use std::fmt;
use std::error;//::Error;
use sgx_types::sgx_status_t;

#[derive(Debug)]
pub enum Error {
    SGXError(sgx_status_t),
	Io(::std::io::Error),
	Custom(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            Error::SGXError(ref err) => format!("SGX Error: {}", err),
            Error::Io(ref err) => format!("I/O error: {}", err),
            Error::Custom(ref s) => s.clone()
        };
        f.write_fmt(format_args!("{}", msg))
    }
}

impl error::Error for Error {
	fn description(&self) -> &str {
		"Program Error"
	}
}

impl Into<String> for Error {
	fn into(self) -> String {
		format!("{}", self)
	}
}

impl From<::std::io::Error> for Error {
	fn from(err: ::std::io::Error) -> Error {
		Error::Io(err)
	}
}

impl From<sgx_status_t> for Error {
    fn from(err: sgx_status_t) -> Error {
        Error::SGXError(err)
    }
}