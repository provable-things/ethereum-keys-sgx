use hex;
use secp256k1;
use std::error::Error;
use std::{io, fmt, num};
use sgx_types::sgx_status_t;
use reqwest;

#[derive(Debug)]
pub enum AppError {
    Io(io::Error),
    Custom(String),
    SGXError(sgx_status_t),
    HexError(hex::FromHexError),
    ReqwestError(reqwest::Error),
    Secp256k1Error(secp256k1::Error),
    ParseINTError(num::ParseIntError)
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            AppError::Custom(ref msg) => msg.clone(),
            AppError::Io(ref e) => format!("I/O error: {}", e),
            AppError::SGXError(ref e) => format!("SGX error: {}", e),
            AppError::HexError(ref e) => format!("Hex error: {}", e),
            AppError::ReqwestError(ref e) => format!("Reqwest error: {}", e),
            AppError::Secp256k1Error(ref e) => format!("Crypto error: {}", e),
            AppError::ParseINTError(ref e) => format!("ParseInt error: {}", e),
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

impl From<num::ParseIntError> for AppError {
    fn from(err: num::ParseIntError) -> AppError {
        AppError::ParseINTError(err)
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

impl From<secp256k1::Error> for AppError {
    fn from(e: secp256k1::Error) -> AppError {
        AppError::Secp256k1Error(e)
    }
}

impl From<hex::FromHexError> for AppError {
    fn from(e: hex::FromHexError) -> AppError {
        AppError::HexError(e)
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> AppError {
        AppError::ReqwestError(e)
    }
}
