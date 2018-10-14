use std::result;
use error::EnclaveError;
use sgx_tservice::{rsgx_close_pse_session, rsgx_create_pse_session};

type Result<T> = result::Result<T, EnclaveError>;

pub fn create_pse_session() -> Result<()> {
    Ok(rsgx_create_pse_session()?)
}

pub fn close_pse_session<T>(thing: T) -> Result<T> {
    rsgx_close_pse_session()?;
    Ok(thing)
}
