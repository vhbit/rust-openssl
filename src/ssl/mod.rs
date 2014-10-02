use libc::{c_int, c_void, c_long};
use std::cell::{UnsafeCell};
use std::io::{mod, IoResult, IoError, Reader, Stream, Writer};
use std::mem;
use std::ptr;
use std::string;
use std::sync::{Arc, Semaphore};
use sync::one::{Once, ONCE_INIT};

use bio::{MemBio};
use ffi;
use ssl::error::{OpenSslErrors, SslError, SslSessionClosed, StreamError};
use x509::{X509StoreContext, X509FileType};

pub mod error;
#[cfg(test)]
mod tests;


static mut VERIFY_IDX: c_int = -1;

fn init() {
    static mut INIT: Once = ONCE_INIT;

    unsafe {
        INIT.doit(|| {
            ffi::init();

            let verify_idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None,
                                                           None, None);
            assert!(verify_idx >= 0);
            VERIFY_IDX = verify_idx;
        });
    }
}

/// Determines the SSL method supported
#[deriving(Show, Hash, PartialEq, Eq)]
#[allow(non_camel_case_types)]
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
            Sslv2 => ffi::SSLv2_method(),
            Sslv3 => ffi::SSLv3_method(),
            Tlsv1 => ffi::TLSv1_method(),
            Sslv23 => ffi::SSLv23_method(),
            #[cfg(feature = "tlsv1_1")]
            Tlsv1_1 => ffi::TLSv1_1_method(),
            #[cfg(feature = "tlsv1_2")]
            Tlsv1_2 => ffi::TLSv1_2_method()
        }
    }
}

/// Determines the type of certificate verification used
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
        INIT.doit(|| {
            let idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None,
                                                    None, Some(free_data_box::<T>));
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
    ctx: *mut ffi::SSL_CTX
}

impl Drop for SslContext {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.ctx) }
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

        Ok(SslContext { ctx: ctx })
    }

    /// Configures the certificate verification method for new connections.
    pub fn set_verify(&mut self, mode: SslVerifyMode,
                      verify: Option<VerifyCallback>) {
        unsafe {
            ffi::SSL_CTX_set_ex_data(self.ctx, VERIFY_IDX,
                                     mem::transmute(verify));
            ffi::SSL_CTX_set_verify(self.ctx, mode as c_int, Some(raw_verify));
        }
    }

    /// Configures the certificate verification method for new connections also
    /// carrying supplied data.
    // Note: no option because there is no point to set data without providing
    // a function handling it
    pub fn set_verify_with_data<T>(&mut self, mode: SslVerifyMode,
                                   verify: VerifyCallbackData<T>,
                                   data: T) {
        let data = box data;
        unsafe {
            ffi::SSL_CTX_set_ex_data(self.ctx, VERIFY_IDX,
                                     mem::transmute(Some(verify)));
            ffi::SSL_CTX_set_ex_data(self.ctx, get_verify_data_idx::<T>(),
                                     mem::transmute(data));
            ffi::SSL_CTX_set_verify(self.ctx, mode as c_int, Some(raw_verify_with_data::<T>));
        }
    }

    /// Sets verification depth
    pub fn set_verify_depth(&mut self, depth: uint) {
        unsafe {
            ffi::SSL_CTX_set_verify_depth(self.ctx, depth as c_int);
        }
    }

    #[allow(non_snake_case)]
    /// Specifies the file that contains trusted CA certificates.
    pub fn set_CA_file(&mut self, file: &Path) -> Option<SslError> {
        wrap_ssl_result(file.with_c_str(|file| {
            unsafe {
                ffi::SSL_CTX_load_verify_locations(self.ctx, file, ptr::null())
            }
        }))
    }

    /// Specifies the file that contains certificate
    pub fn set_certificate_file(&mut self, file: &Path,
                                file_type: X509FileType) -> Option<SslError> {
        wrap_ssl_result(file.with_c_str(|file| {
            unsafe {
                ffi::SSL_CTX_use_certificate_file(self.ctx, file, file_type as c_int)
            }
        }))
    }

    /// Specifies the file that contains private key
    pub fn set_private_key_file(&mut self, file: &Path,
                                file_type: X509FileType) -> Option<SslError> {
        wrap_ssl_result(file.with_c_str(|file| {
            unsafe {
                ffi::SSL_CTX_use_PrivateKey_file(self.ctx, file, file_type as c_int)
            }
        }))
    }

    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Option<SslError> {
        wrap_ssl_result(cipher_list.with_c_str(|cipher_list| {
            unsafe {
                ffi::SSL_CTX_set_cipher_list(self.ctx, cipher_list)
            }
        }))
    }
}

#[allow(dead_code)]
struct MemBioRef<'ssl> {
    ssl: &'ssl Ssl,
    bio: MemBio,
}

impl<'ssl> MemBioRef<'ssl> {
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
        (&mut self.bio as &mut Reader).read(buf).ok()
    }

    fn write(&mut self, buf: &[u8]) {
        let _ = (&mut self.bio as &mut Writer).write(buf);
    }
}

pub struct Ssl {
    ssl: *mut ffi::SSL
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(self.ssl) }
    }
}

impl Ssl {
    pub fn new(ctx: &SslContext) -> Result<Ssl, SslError> {
        let ssl = unsafe { ffi::SSL_new(ctx.ctx) };
        if ssl == ptr::null_mut() {
            return Err(SslError::get());
        }
        let ssl = Ssl { ssl: ssl };

        let rbio = try!(MemBio::new());
        let wbio = try!(MemBio::new());

        unsafe { ffi::SSL_set_bio(ssl.ssl, rbio.unwrap(), wbio.unwrap()) }
        Ok(ssl)
    }

    fn get_rbio<'a>(&'a self) -> MemBioRef<'a> {
        unsafe { self.wrap_bio(ffi::SSL_get_rbio(self.ssl)) }
    }

    fn get_wbio<'a>(&'a self) -> MemBioRef<'a> {
        unsafe { self.wrap_bio(ffi::SSL_get_wbio(self.ssl)) }
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
            ffi::SSL_connect(self.ssl)
        }
    }

    fn read(&self, buf: &mut [u8]) -> c_int {
        unsafe {
            ffi::ERR_clear_error();
            ffi::SSL_read(self.ssl, buf.as_ptr() as *mut c_void,
                          buf.len() as c_int)
        }
    }

    fn write(&self, buf: &[u8]) -> c_int {
        unsafe {
            ffi::ERR_clear_error();
            ffi::SSL_write(self.ssl, buf.as_ptr() as *const c_void,
                           buf.len() as c_int)
        }
    }

    fn get_error(&self, ret: c_int) -> LibSslError {
        let err = unsafe { ffi::SSL_get_error(self.ssl, ret) };
        let res = match FromPrimitive::from_int(err as int) {
            Some(err) => err,
            None => unreachable!()
        };
        unsafe { ffi::ERR_clear_error() };
        res
    }

    /// Set the host name to be used with SNI (Server Name Indication).
    pub fn set_hostname(&self, hostname: &str) -> Result<(), SslError> {
        let ret = hostname.with_c_str(|hostname| {
            unsafe {
                // This is defined as a macro:
                //      #define SSL_set_tlsext_host_name(s,name) \
                //          SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,(char *)name)

                ffi::SSL_ctrl(self.ssl, ffi::SSL_CTRL_SET_TLSEXT_HOSTNAME,
                              ffi::TLSEXT_NAMETYPE_host_name,
                              hostname as *const c_void as *mut c_void)
            }
        });

        // For this case, 0 indicates failure.
        if ret == 0 {
            Err(SslError::get())
        } else {
            Ok(())
        }
    }

}

#[deriving(FromPrimitive, Show)]
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


fn default_ssl_buf() -> Vec<u8> {
    // Maximum TLS record size is 16k
    Vec::from_elem(16 * 1024, 0)
}

/// A stream wrapper which handles SSL encryption for an underlying stream.
pub struct SslStream<S> {
    stream: UnsafeCell<S>,
    ssl: Arc<Ssl>,
    // Caveat: it is supposed to work like 1 SslStream per thread
    // if there are multiple streams in one thread, buf should be
    // locked too
    buf: UnsafeCell<Vec<u8>>,
    reader_sem: Arc<Semaphore>,
    writer_sem: Arc<Semaphore>,
    slurp_sem: Arc<Semaphore>,
    spit_sem: Arc<Semaphore>,
}

impl<S: Stream> SslStream<S> {
    /// Attempts to create a new SSL stream from a given `Ssl` instance.
    pub fn new_from(ssl: Ssl, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = SslStream {
            stream: UnsafeCell::new(stream),
            ssl: Arc::new(ssl),
            buf: UnsafeCell::new(default_ssl_buf()),
            reader_sem: Arc::new(Semaphore::new(1)),
            writer_sem: Arc::new(Semaphore::new(1)),
            slurp_sem: Arc::new(Semaphore::new(1)),
            spit_sem: Arc::new(Semaphore::new(1))
        };

        ssl.in_retry_wrapper(|ssl| { ssl.connect() }).and(Ok(ssl))
    }

    /// Creates a new SSL stream
    pub fn new(ctx: &SslContext, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = try!(Ssl::new(ctx));

        SslStream::new_from(ssl, stream)
    }

    fn in_retry_wrapper(&self, blk: |&Ssl| -> c_int) -> Result<c_int, SslError> {
        loop {
            let ret = blk(&*self.ssl);
            if ret > 0 {
                return Ok(ret);
            }

            match self.ssl.get_error(ret) {
                ErrorWantRead => {
                    try_ssl_stream!(self.do_flush());
                    try_ssl_stream!(self.slurp());
                }
                ErrorWantWrite => { try_ssl_stream!(self.do_flush()) }
                ErrorZeroReturn => return Err(SslSessionClosed),
                ErrorSsl => return Err(SslError::get()),
                ErrorSyscall => {
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
                err@_ => fail!("unreachable: {}", err)
            }
        }
    }

    fn get_stream<'a>(&'a self) -> &'a mut S {
        // Stream is there while we exist
        unsafe { &mut *self.stream.get() }
    }

    fn get_buf<'a>(&'a self) -> &'a mut Vec<u8> {
        // Buf is there while we exist
        unsafe { &mut *self.buf.get() }
    }

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

        let buf = self.get_buf();
        let len = try!(self.get_stream().read(buf.as_mut_slice()));
        self.ssl.get_rbio().write(buf.slice_to(len));
        drop(guard);
        Ok(())
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

        let buf = self.get_buf();
        loop {
            match self.ssl.get_wbio().read(buf.as_mut_slice()) {
                Some(len) => try!(self.get_stream().write(buf.slice_to(len))),
                None => break
            };
        };
        drop(guard);
        Ok(())
    }

    /// Get the compression currently in use.  The result will be
    /// either None, indicating no compression is in use, or a string
    /// with the compression name.
    pub fn get_compression(&self) -> Option<String> {
        let ptr = unsafe { ffi::SSL_get_current_compression(self.ssl.ssl) };
        if ptr == ptr::null() {
            return None;
        }

        let meth = unsafe { ffi::SSL_COMP_get_name(ptr) };
        let s = unsafe { string::raw::from_buf(meth as *const u8) };

        Some(s)
    }
}

impl<S: Stream> Reader for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        // Place readers in line
        let guard = self.reader_sem.access();

        let res = match self.in_retry_wrapper(|ssl| { ssl.read(buf) }) {
            Ok(len) => Ok(len as uint),
            Err(SslSessionClosed) =>
                Err(IoError {
                    kind: io::EndOfFile, // Should it be changed to ConnectionAborted?
                    desc: "SSL session closed",
                    detail: None
                }),
            Err(StreamError(e)) => Err(e),
            Err(OpenSslErrors(errs)) => {
                Err(IoError {
                    kind: io::OtherIoError,
                    desc: "SSL error",
                    detail: Some(format!("SSL stream read: {}", errs))
                })
            },
        };
        drop(guard);
        res
    }
}

impl<S: Stream> Writer for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<()> {
        // Place writers in line
        let guard = self.writer_sem.access();

        let mut start = 0;
        while start < buf.len() {
            let ret = self.in_retry_wrapper(|ssl| {
                ssl.write(buf.slice_from(start))
            });
            match ret {
                Ok(len) => start += len as uint,
                Err(SslSessionClosed) => {
                    return Err(IoError {
                        kind: io::ConnectionAborted,
                        desc: "SSL session closed",
                        detail: None
                    });
                },
                Err(StreamError(e)) => return Err(e),
                Err(e) => fail!("SSL stream write: {}", e)
            }
            try!(self.write_through());
        }
        drop(guard);
        Ok(())
    }

    fn flush(&mut self) -> IoResult<()> {
        self.do_flush()
    }
}

impl<S: Stream + Clone> Clone for SslStream<S> {
    // Note: clone should be called only after establishing connection
    fn clone(&self) -> SslStream<S> {
        SslStream {
            stream: UnsafeCell::new(self.get_stream().clone()),
            ssl: self.ssl.clone(),
            buf: UnsafeCell::new(default_ssl_buf()),
            reader_sem: self.reader_sem.clone(),
            writer_sem: self.writer_sem.clone(),
            slurp_sem: self.slurp_sem.clone(),
            spit_sem: self.spit_sem.clone(),
        }
    }
}
