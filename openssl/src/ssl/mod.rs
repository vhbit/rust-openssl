use libc::{c_int, c_void, c_long};
use std::ffi::{CString, c_str_to_bytes};
use std::cell::{UnsafeCell};
use std::old_io::{self, IoResult, IoError, IoErrorKind, Stream, Reader, Writer};
use std::mem;
use std::fmt;
use std::num::FromPrimitive;
use std::ptr;
use std::sync::{Arc, Mutex, Once, ONCE_INIT, Semaphore};

use bio::{MemBio};
use ffi;
use ssl::error::{OpenSslErrors, SslError, SslSessionClosed, StreamError};
use x509::{X509StoreContext, X509FileType, X509};

pub mod error;
#[cfg(test)]
mod tests;


static mut VERIFY_IDX: c_int = -1;

fn init() {
    static mut INIT: Once = ONCE_INIT;

    unsafe {
        INIT.call_once(|| {
            ffi::init();

            let verify_idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None,
                                                           None, None);
            assert!(verify_idx >= 0);
            VERIFY_IDX = verify_idx;
        });
    }
}

/// Determines the SSL method supported
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum SslMethod {
    #[cfg(feature = "sslv2")]
    /// Only support the SSLv2 protocol, requires `feature="sslv2"`
    Sslv2,
    /// Support the SSLv2, SSLv3 and TLSv1 protocols
    Sslv23,
    /// Only support the SSLv3 protocol
    Sslv3,
    /// Only support the TLSv1 protocol
    Tlsv1,
    #[cfg(feature = "tlsv1_1")]
    /// Support TLSv1.1 protocol, requires `feature="tlsv1_1"`
    Tlsv1_1,
    #[cfg(feature = "tlsv1_2")]
    /// Support TLSv1.2 protocol, requires `feature="tlsv1_2"`
    Tlsv1_2,
}

impl SslMethod {
    unsafe fn to_raw(&self) -> *const ffi::SSL_METHOD {
        match *self {
            #[cfg(feature = "sslv2")]
            SslMethod::Sslv2 => ffi::SSLv2_method(),
            SslMethod::Sslv3 => ffi::SSLv3_method(),
            SslMethod::Tlsv1 => ffi::TLSv1_method(),
            SslMethod::Sslv23 => ffi::SSLv23_method(),
            #[cfg(feature = "tlsv1_1")]
            SslMethod::Tlsv1_1 => ffi::TLSv1_1_method(),
            #[cfg(feature = "tlsv1_2")]
            SslMethod::Tlsv1_2 => ffi::TLSv1_2_method()
        }
    }
}

/// Determines the type of certificate verification used
#[derive(Copy, Clone, Debug)]
#[repr(i32)]
pub enum SslVerifyMode {
    /// Verify that the server's certificate is trusted
    SslVerifyPeer = ffi::SSL_VERIFY_PEER,
    /// Do not verify the server's certificate
    SslVerifyNone = ffi::SSL_VERIFY_NONE
}

// Creates a static index for user data of type T
// Registers a destructor for the data which will be called
// when context is freed
fn get_verify_data_idx<T>() -> c_int {
    static mut VERIFY_DATA_IDX: c_int = -1;
    static mut INIT: Once = ONCE_INIT;

    extern fn free_data_box<T>(_parent: *mut c_void, ptr: *mut c_void,
                               _ad: *mut ffi::CRYPTO_EX_DATA, _idx: c_int,
                               _argl: c_long, _argp: *mut c_void) {
        let _: Box<T> = unsafe { mem::transmute(ptr) };
    }

    unsafe {
        INIT.call_once(|| {
            let f: ffi::CRYPTO_EX_free = free_data_box::<T>;
            let idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None,
                                                    None, Some(f));
            assert!(idx >= 0);
            VERIFY_DATA_IDX = idx;
        });
        VERIFY_DATA_IDX
    }
}

extern fn raw_verify(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX)
        -> c_int {
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, VERIFY_IDX);
        let verify: Option<VerifyCallback> = mem::transmute(verify);

        let ctx = X509StoreContext::new(x509_ctx);

        match verify {
            None => preverify_ok,
            Some(verify) => verify(preverify_ok != 0, &ctx) as c_int
        }
    }
}

extern fn raw_verify_with_data<T>(preverify_ok: c_int,
                                  x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);

        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, VERIFY_IDX);
        let verify: Option<VerifyCallbackData<T>> = mem::transmute(verify);

        let data = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_verify_data_idx::<T>());
        let data: Box<T> = mem::transmute(data);

        let ctx = X509StoreContext::new(x509_ctx);

        let res = match verify {
            None => preverify_ok,
            Some(verify) => verify(preverify_ok != 0, &ctx, &*data) as c_int
        };

        // Since data might be required on the next verification
        // it is time to forget about it and avoid dropping
        // data will be freed once OpenSSL considers it is time
        // to free all context data
        mem::forget(data);
        res
    }
}

/// The signature of functions that can be used to manually verify certificates
pub type VerifyCallback = fn(preverify_ok: bool,
                             x509_ctx: &X509StoreContext) -> bool;

/// The signature of functions that can be used to manually verify certificates
/// when user-data should be carried for all verification process
pub type VerifyCallbackData<T> = fn(preverify_ok: bool,
                                    x509_ctx: &X509StoreContext,
                                    data: &T) -> bool;

// FIXME: macro may be instead of inlining?
#[inline]
fn wrap_ssl_result(res: c_int) -> Option<SslError> {
    if res == 0 {
        Some(SslError::get())
    } else {
        None
    }
}

/// An SSL context object
pub struct SslContext {
    ctx: ptr::Unique<ffi::SSL_CTX>
}

// TODO: add useful info here
impl fmt::Debug for SslContext {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SslContext")
    }
}

impl Drop for SslContext {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(*self.ctx) }
    }
}

impl SslContext {
    /// Creates a new SSL context.
    pub fn new(method: SslMethod) -> Result<SslContext, SslError> {
        init();

        let ctx = unsafe { ffi::SSL_CTX_new(method.to_raw()) };
        if ctx == ptr::null_mut() {
            return Err(SslError::get());
        }

        Ok(SslContext { ctx: unsafe {ptr::Unique::new(ctx)} })
    }

    /// Configures the certificate verification method for new connections.
    pub fn set_verify(&mut self, mode: SslVerifyMode,
                      verify: Option<VerifyCallback>) {
        unsafe {
            ffi::SSL_CTX_set_ex_data(*self.ctx, VERIFY_IDX,
                                     mem::transmute(verify));
            let f: extern fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int =
                                raw_verify;
            ffi::SSL_CTX_set_verify(*self.ctx, mode as c_int, Some(f));
        }
    }

    /// Configures the certificate verification method for new connections also
    /// carrying supplied data.
    // Note: no option because there is no point to set data without providing
    // a function handling it
    pub fn set_verify_with_data<T>(&mut self, mode: SslVerifyMode,
                                   verify: VerifyCallbackData<T>,
                                   data: T) {
        let data = Box::new(data);
        unsafe {
            ffi::SSL_CTX_set_ex_data(*self.ctx, VERIFY_IDX,
                                     mem::transmute(Some(verify)));
            ffi::SSL_CTX_set_ex_data(*self.ctx, get_verify_data_idx::<T>(),
                                     mem::transmute(data));
            let f: extern fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int =
                                raw_verify_with_data::<T>;
            ffi::SSL_CTX_set_verify(*self.ctx, mode as c_int, Some(f));
        }
    }

    /// Sets verification depth
    pub fn set_verify_depth(&mut self, depth: u32) {
        unsafe {
            ffi::SSL_CTX_set_verify_depth(*self.ctx, depth as c_int);
        }
    }

    #[allow(non_snake_case)]
    /// Specifies the file that contains trusted CA certificates.
    pub fn set_CA_file(&mut self, file: &Path) -> Option<SslError> {
        wrap_ssl_result(
            unsafe {
                let file = CString::from_slice(file.as_vec());
                ffi::SSL_CTX_load_verify_locations(*self.ctx, file.as_ptr(), ptr::null())
            })
    }

    /// Specifies the file that contains certificate
    pub fn set_certificate_file(&mut self, file: &Path,
                                file_type: X509FileType) -> Option<SslError> {
        wrap_ssl_result(
            unsafe {
                let file = CString::from_slice(file.as_vec());
                ffi::SSL_CTX_use_certificate_file(*self.ctx, file.as_ptr(), file_type as c_int)
            })
    }

    /// Specifies the file that contains private key
    pub fn set_private_key_file(&mut self, file: &Path,
                                file_type: X509FileType) -> Option<SslError> {
        wrap_ssl_result(
            unsafe {
                let file = CString::from_slice(file.as_vec());
                ffi::SSL_CTX_use_PrivateKey_file(*self.ctx, file.as_ptr(), file_type as c_int)
            })
    }

    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Option<SslError> {
        wrap_ssl_result(
            unsafe {
                let cipher_list = CString::from_slice(cipher_list.as_bytes());
                ffi::SSL_CTX_set_cipher_list(*self.ctx, cipher_list.as_ptr())
            })
    }
}

#[allow(dead_code)]
struct MemBioRef<'ssl> {
    ssl: &'ssl Ssl,
    bio: MemBio,
}

impl<'ssl> MemBioRef<'ssl> {
    fn read(&mut self, buf: &mut [u8]) -> Option<usize> {
        (&mut self.bio as &mut Reader).read(buf).ok()
    }

    fn write_all(&mut self, buf: &[u8]) {
        let _ = (&mut self.bio as &mut Writer).write_all(buf);
    }
}

pub struct Ssl {
    ssl: ptr::Unique<ffi::SSL>
}

// TODO: put useful information here
impl fmt::Debug for Ssl {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Ssl")
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(*self.ssl) }
    }
}

impl Ssl {
    pub fn new(ctx: &SslContext) -> Result<Ssl, SslError> {
        let ssl = unsafe { ffi::SSL_new(*ctx.ctx) };
        if ssl == ptr::null_mut() {
            return Err(SslError::get());
        }
        let ssl = Ssl { ssl: unsafe {ptr::Unique::new(ssl)}};

        let rbio = try!(MemBio::new());
        let wbio = try!(MemBio::new());

        unsafe { ffi::SSL_set_bio(*ssl.ssl, rbio.unwrap(), wbio.unwrap()) }
        Ok(ssl)
    }

    fn get_rbio<'a>(&'a self) -> MemBioRef<'a> {
        unsafe { self.wrap_bio(ffi::SSL_get_rbio(*self.ssl)) }
    }

    fn get_wbio<'a>(&'a self) -> MemBioRef<'a> {
        unsafe { self.wrap_bio(ffi::SSL_get_wbio(*self.ssl)) }
    }

    fn wrap_bio<'a>(&'a self, bio: *mut ffi::BIO) -> MemBioRef<'a> {
        assert!(bio != ptr::null_mut());
        MemBioRef {
            ssl: self,
            bio: MemBio::borrowed(bio)
        }
    }

    fn connect(&self) -> c_int {
        unsafe {
            ffi::ERR_clear_error();
            ffi::SSL_connect(*self.ssl)
        }
    }

    fn accept(&self) -> c_int {
        unsafe { ffi::SSL_accept(*self.ssl) }
    }

    fn read(&self, buf: &mut [u8]) -> c_int {
        unsafe {
            ffi::ERR_clear_error();
            ffi::SSL_read(*self.ssl, buf.as_ptr() as *mut c_void,
                          buf.len() as c_int)
        }
    }

    fn write_all(&self, buf: &[u8]) -> c_int {
        unsafe {
            ffi::ERR_clear_error();
            ffi::SSL_write(*self.ssl, buf.as_ptr() as *const c_void,
                           buf.len() as c_int)
        }
    }

    fn get_error(&self, ret: c_int) -> LibSslError {
        let err = unsafe { ffi::SSL_get_error(*self.ssl, ret) };
        let res = match FromPrimitive::from_int(err as isize) {
            Some(err) => err,
            None => unreachable!()
        };
        unsafe { ffi::ERR_clear_error() };
        res
    }

    /// Set the host name to be used with SNI (Server Name Indication).
    pub fn set_hostname(&self, hostname: &str) -> Result<(), SslError> {
        let ret = unsafe {
                // This is defined as a macro:
                //      #define SSL_set_tlsext_host_name(s,name) \
                //          SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,(char *)name)

                let hostname = CString::from_slice(hostname.as_bytes());
                ffi::SSL_ctrl(*self.ssl, ffi::SSL_CTRL_SET_TLSEXT_HOSTNAME,
                              ffi::TLSEXT_NAMETYPE_host_name,
                              hostname.as_ptr() as *mut c_void)
        };

        // For this case, 0 indicates failure.
        if ret == 0 {
            Err(SslError::get())
        } else {
            Ok(())
        }
    }

    pub fn get_peer_certificate(&self) -> Option<X509> {
        unsafe {
            let ptr = ffi::SSL_get_peer_certificate(*self.ssl);
            if ptr.is_null() {
                None
            } else {
                Some(X509::new(ptr, true))
            }
        }
    }

}

#[derive(FromPrimitive, Debug)]
#[repr(i32)]
enum LibSslError {
    ErrorNone = ffi::SSL_ERROR_NONE,
    ErrorSsl = ffi::SSL_ERROR_SSL,
    ErrorWantRead = ffi::SSL_ERROR_WANT_READ,
    ErrorWantWrite = ffi::SSL_ERROR_WANT_WRITE,
    ErrorWantX509Lookup = ffi::SSL_ERROR_WANT_X509_LOOKUP,
    ErrorSyscall = ffi::SSL_ERROR_SYSCALL,
    ErrorZeroReturn = ffi::SSL_ERROR_ZERO_RETURN,
    ErrorWantConnect = ffi::SSL_ERROR_WANT_CONNECT,
    ErrorWantAccept = ffi::SSL_ERROR_WANT_ACCEPT,
}


#[inline]
fn default_ssl_buf() -> Vec<u8> {
    // Maximum TLS record size is 16k
    const CAP: usize = 16 * 1024;
    let mut v = Vec::with_capacity(CAP);
    unsafe { v.set_len(CAP); }
    v
}

/// A stream wrapper which handles SSL encryption for an underlying stream.
pub struct SslStream<S> {
    stream: UnsafeCell<S>,
    ssl: Arc<Ssl>,
    buf: Mutex<UnsafeCell<Vec<u8>>>,
    reader_sem: Arc<Semaphore>,
    writer_sem: Arc<Semaphore>,
    slurp_sem: Arc<Semaphore>,
    spit_sem: Arc<Semaphore>,
}

impl<S> fmt::Debug for SslStream<S> where S: fmt::Debug {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SslStream {{ stream: {:?}, }}", self.stream.get())
    }
}

impl<S: Stream> SslStream<S> {
    fn new_base(ssl:Ssl, stream: S) -> SslStream<S> {
        SslStream {
            stream: UnsafeCell::new(stream),
            ssl: Arc::new(ssl),
            buf: Mutex::new(UnsafeCell::new(default_ssl_buf())),
            reader_sem: Arc::new(Semaphore::new(1)),
            writer_sem: Arc::new(Semaphore::new(1)),
            slurp_sem: Arc::new(Semaphore::new(1)),
            spit_sem: Arc::new(Semaphore::new(1))
        }
    }

    pub fn new_server_from(ssl: Ssl, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = SslStream::new_base(ssl, stream);
        ssl.in_retry_wrapper(|ssl| { ssl.accept() }).and(Ok(ssl))
    }

    /// Attempts to create a new SSL stream from a given `Ssl` instance.
    pub fn new_from(ssl: Ssl, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = SslStream::new_base(ssl, stream);
        ssl.in_retry_wrapper(|ssl| { ssl.connect() }).and(Ok(ssl))
    }

    /// Creates a new SSL stream
    pub fn new(ctx: &SslContext, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = try!(Ssl::new(ctx));
        SslStream::new_from(ssl, stream)
    }

    /// Creates a new SSL server stream
    pub fn new_server(ctx: &SslContext, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = try!(Ssl::new(ctx));
        SslStream::new_server_from(ssl, stream)
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// `read`ing or `write`ing directly to the underlying stream will most
    /// likely desynchronize the SSL session.
    #[deprecated="use get_mut instead"]
    pub fn get_inner(&mut self) -> &mut S {
        unsafe {mem::transmute(self.stream.get())}
    }

    pub fn get_mut(&mut self) -> &mut S {
        unsafe {mem::transmute(self.stream.get())}
}

    pub fn get(&self) -> &S {
        unsafe {mem::transmute(self.stream.get())}
    }

    fn in_retry_wrapper<F>(&self, mut blk: F)
            -> Result<c_int, SslError> where F: FnMut(&Ssl) -> c_int {
        loop {
            let ret = blk(&*self.ssl);
            if ret > 0 {
                return Ok(ret);
            }

            match self.ssl.get_error(ret) {
                LibSslError::ErrorWantRead => {
                    try_ssl_stream!(self.do_flush());
                    try_ssl_stream!(self.slurp());
                }

                LibSslError::ErrorWantWrite => { try_ssl_stream!(self.do_flush()) }
                LibSslError::ErrorZeroReturn => return Err(SslSessionClosed),
                LibSslError::ErrorSsl => return Err(SslError::get()),
                LibSslError::ErrorSyscall => {
                    /* According to SSL docs:
                    If ret == 0, an EOF was observed that violates the protocol.
                    If ret == -1, the underlying BIO reported an I/O error

                    BIO errors aren't 100% fatal ones so we can try to loop
                    a little bit longer
                     */
                    match ret {
                        0 => return Err(SslSessionClosed),
                        -1 => (), // debug!("underlying BIO error"),
                        _ => unreachable!()
                    }
                },
                err@_ => panic!("unreachable: {:?}", err)
            }
        }
    }

    fn get_stream<'a>(&'a self) -> &'a mut S {
        // Stream is there while we exist
        unsafe { &mut *self.stream.get() }
    }

    // Can't use `flush` as it requires mutability of self
    fn do_flush(&self) -> IoResult<()> {
        self.write_through()
            .and_then(|_| self.get_stream().flush() )
    }

    fn slurp(&self) -> IoResult<()> {
        // Lock again as reader and writer might want to
        // read data simultaneously. They should wait
        // until data completely copied
        //
        // FIXME: actually, if someone has already read
        // data from stream, may be operation could be
        // retried even without additional reading
        let guard = self.slurp_sem.access();

        let res = match self.buf.lock() {
            Err(_) => Err(IoError{kind: IoErrorKind::ResourceUnavailable, desc: "buf lock error", detail: None}),
            Ok(buf_guard) => {
                let buf = unsafe { &mut *buf_guard.get() };
                let len = try!(self.get_stream().read(buf.as_mut_slice()));
                self.ssl.get_rbio().write_all(&buf[..len]);
                Ok(())
            }
        };
        drop(guard);
        res
    }

    fn write_through(&self) -> IoResult<()> {
        // Lock again as reader and writer might want to
        // read data simultaneously. They should wait
        // until data completely written
        //
        // FIXME: actually, if someone has already read
        // data from stream, may be operation could be
        // retried even without additional writing
        let guard = self.spit_sem.access();

        let res = match self.buf.lock() {
            Err(_) => Err(IoError{kind: IoErrorKind::ResourceUnavailable, desc: "buf lock error", detail: None}),
            Ok(buf_guard) => {
                let buf = unsafe { &mut *buf_guard.get() };
                loop {
                    match self.ssl.get_wbio().read(buf.as_mut_slice()) {
                        Some(len) => try!(self.get_stream().write_all(&buf[..len])),
                        None => break
                    };
                };
                Ok(())
            }
        };
        drop(guard);
        res
    }

    /// Get the compression currently in use.  The result will be
    /// either None, indicating no compression is in use, or a string
    /// with the compression name.
    pub fn get_compression(&self) -> Option<String> {
        let ptr = unsafe { ffi::SSL_get_current_compression(*self.ssl.ssl) };
        if ptr == ptr::null() {
            return None;
        }

        let meth = unsafe { ffi::SSL_COMP_get_name(ptr) };
        let s = unsafe {
            String::from_utf8(c_str_to_bytes(&meth).to_vec()).unwrap()
        };

        Some(s)
    }
}

impl<S: Stream> Reader for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        // Place readers in line
        let guard = self.reader_sem.access();

        let res = match self.in_retry_wrapper(|ssl| { ssl.read(buf) }) {
            Ok(len) => Ok(len as usize),
            Err(SslSessionClosed) =>
                Err(IoError {
                    kind: old_io::EndOfFile, // Should it be changed to ConnectionAborted?
                    desc: "SSL session closed",
                    detail: None
                }),
            Err(StreamError(e)) => Err(e),
            Err(OpenSslErrors(errs)) => {
                Err(IoError {
                    kind: old_io::OtherIoError,
                    desc: "SSL error",
                    detail: Some(format!("SSL stream read: {:?}", errs))
                })
            },
        };
        drop(guard);
        res
    }
}

impl<S: Stream> Writer for SslStream<S> {
    fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        // Ensure SSL_write will never have 0 bytes write
        // as it is undefined behavior
        if buf.len() == 0 { return Ok(())};

        // Place writers in line
        let guard = self.writer_sem.access();

        // SSL_write returns only when complete
        // contents is written, so there is no need
        // in loop (the only exception is a
        // SSL_MODE_ENABLE_PARTIAL_WRITE which is not
        // the case in current impl)
        let ret = self.in_retry_wrapper(|ssl| {
            ssl.write_all(buf)
        });
        let res = match ret {
            Ok(_) => {
                self.write_through()
            },
            Err(SslSessionClosed) => {
                Err(IoError {
                    kind: old_io::ConnectionAborted,
                    desc: "SSL session closed",
                    detail: None
                })
            },
            Err(StreamError(e)) => Err(e),
            Err(e) => panic!("SSL stream write: {:?}", e)
        };

        drop(guard);
        res
    }

    fn flush(&mut self) -> IoResult<()> {
        self.do_flush()
    }
}

impl<S: Stream + Clone> Clone for SslStream<S> {
    // Note: clone should be called only after establishing connection
    // which is the case in current implementation but may be a problem
    // in the future
    fn clone(&self) -> SslStream<S> {
        SslStream {
            stream: UnsafeCell::new(self.get_stream().clone()),
            ssl: self.ssl.clone(),
            buf: Mutex::new(UnsafeCell::new(default_ssl_buf())),
            reader_sem: self.reader_sem.clone(),
            writer_sem: self.writer_sem.clone(),
            slurp_sem: self.slurp_sem.clone(),
            spit_sem: self.spit_sem.clone(),
        }
    }
}

/// A utility type to help in cases where the use of SSL is decided at runtime.
#[derive(Debug)]
pub enum MaybeSslStream<S> where S: Stream {
    /// A connection using SSL
    Ssl(SslStream<S>),
    /// A connection not using SSL
    Normal(S),
}

impl<S> Reader for MaybeSslStream<S> where S: Stream {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.read(buf),
            MaybeSslStream::Normal(ref mut s) => s.read(buf),
        }
    }
}

impl<S> Writer for MaybeSslStream<S> where S: Stream{
    fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.write_all(buf),
            MaybeSslStream::Normal(ref mut s) => s.write_all(buf),
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.flush(),
            MaybeSslStream::Normal(ref mut s) => s.flush(),
        }
    }
}

impl<S> MaybeSslStream<S> where S: Stream {
    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        match *self {
            MaybeSslStream::Ssl(ref s) => s.get(),
            MaybeSslStream::Normal(ref s) => s,
        }
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.get_mut(),
            MaybeSslStream::Normal(ref mut s) => s,
        }
    }
}
