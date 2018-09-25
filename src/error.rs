use std::io;
use std::{fmt, error};
use std::error::Error;
use sgx_types::sgx_status_t;

#[derive(Debug)]
pub enum AppError {
    SGXError(sgx_status_t),
	Io(io::Error),
	Custom(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            AppError::SGXError(ref err) => format!("SGX Error: {}", err),
            AppError::Io(ref err) => format!("I/O error: {}", err),
            AppError::Custom(ref s) => s.clone()
        };
        f.write_fmt(format_args!("{}", msg))
    }
}

impl Error for AppError {
	fn description(&self) -> &str {
		"Program Error"
	}
}

impl Into<String> for AppError {
	fn into(self) -> String {
		format!("{}", self)
	}
}

impl From<io::Error> for AppError {
	fn from(err: io::Error) -> AppError {
		AppError::Io(err)
	}
}

impl From<sgx_status_t> for AppError {
    fn from(err: sgx_status_t) -> AppError {
        AppError::SGXError(err)
    }
}