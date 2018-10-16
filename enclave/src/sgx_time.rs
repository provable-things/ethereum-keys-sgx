use std::result;
use error::EnclaveError;
use sgx_types::sgx_status_t;
use sgx_tservice::sgxtime::SgxTime;
use pse_session::{create_pse_session, close_pse_session};

type Result<T> = result::Result<T, EnclaveError>;

pub fn get_sgx_time() -> Result<SgxTime> {
    create_pse_session()
        .and_then(get_sgx_time_struct)
        .and_then(close_pse_session)
}

fn get_sgx_time_struct<T>(_t: T) -> Result<SgxTime> {
     Ok(SgxTime::now()?)
}
