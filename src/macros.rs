#![macro_escape]

#[macro_export]
macro_rules! try_ssl_stream {
    ($e:expr) => (
        match $e {
            Ok(ok) => ok,
            Err(err) => return Err(StreamError(err))
        }
    )
}

/// Shortcut return with SSL error if something went wrong
#[macro_export]
macro_rules! try_ssl_if {
    ($e:expr) => (
        if $e {
            return Err(SslError::get())
        }
    )
}

/// Shortcut return with SSL error if last error result is 0
/// (default)
#[macro_export]
macro_rules! try_ssl{
    ($e:expr) => (try_ssl_if!($e == 0))
}

/// Shortcut return with SSL if got a null result
#[macro_export]
macro_rules! try_ssl_null{
    ($e:expr) => (try_ssl_if!($e == ptr::null_mut()))
}


/// Lifts current SSL error code into Result<(), Error>
/// if expression is true
/// Lifting is actually a shortcut of the following form:
///
/// ```ignore
/// let _ = try!(something)
/// Ok(())
/// ```
#[macro_export]
macro_rules! lift_ssl_if{
    ($e:expr) => ( {
        if $e {
            Err(SslError::get())
        } else {
            Ok(())
        }
    })
}

/// Lifts current SSL error code into Result<(), Error>
/// if SSL returned 0 (default error indication)
#[macro_export]
macro_rules! lift_ssl {
    ($e:expr) => (lift_ssl_if!($e == 0))
}
