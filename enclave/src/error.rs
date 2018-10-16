use std::fmt;
use secp256k1;
use std::error::Error;
use std::string::String;
use sgx_types::sgx_status_t;
use sgx_tservice::sgxtime::SgxTimeError;

#[derive(Debug)]
pub enum EnclaveError {
    SGXTimeError(),
    Custom(String),
    Fmt(fmt::Error),
    SGXError(sgx_status_t),
    Secp256k1Error(secp256k1::Error),
}

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            EnclaveError::Custom(ref msg) => msg.clone(),
            EnclaveError::SGXTimeError() => format!("SGX Time Error!"), // FIXME: error swallowed due to no debug in library!
            EnclaveError::SGXError(ref e) => format!("SGX Error: {}", e),
            EnclaveError::Fmt(ref e) => format!("Formatter error: {}", e),
            EnclaveError::Secp256k1Error(ref e) => format!("Crypto Error: {}", e),
        };
        f.write_fmt(format_args!("{}", msg))
    }
}

impl Error for EnclaveError {
    fn description(&self) -> &str {
        "Program Error"
    }
}

impl Into<String> for EnclaveError {
    fn into(self) -> String {
        format!("{}", self)
    }
}

impl From<fmt::Error> for EnclaveError {
    fn from(err: fmt::Error) -> EnclaveError {
        EnclaveError::Fmt(err)
    }
}

impl From<sgx_status_t> for EnclaveError {
    fn from(err: sgx_status_t) -> EnclaveError {
        EnclaveError::SGXError(err)
    }
}

impl From<secp256k1::Error> for EnclaveError {
    fn from(e: secp256k1::Error) -> EnclaveError {
        EnclaveError::Secp256k1Error(e)
    }
}

impl From<SgxTimeError> for EnclaveError {
    fn from(_e: SgxTimeError) -> EnclaveError {
        EnclaveError::SGXTimeError()
    }
}
