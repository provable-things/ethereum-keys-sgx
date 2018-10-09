use std::result;
use error::EnclaveError;
use sgx_tservice::sgxcounter::SgxMonotonicCounter;
use sgx_tservice::{rsgx_create_pse_session, rsgx_close_pse_session};

type Result<T> = result::Result<T, EnclaveError>;
/*
Type: counter_uuid: sgx_mc_uuid_t
TODO: get something that highlights all instances of a word in vim!
TODO: find a way to move lines around like in vscode!
*/
pub fn generate_zeroed_mc() -> Result<SgxMonotonicCounter> {
    generate_mc(0)
}

pub fn get_mc_count(mc: SgxMonotonicCounter) -> Result<u32> {
    create_pse_session(mc)
        .and_then(read_mc)
        .and_then(close_pse_session)
}

pub fn increment_mc_count(mc: SgxMonotonicCounter) -> Result<u32> {
    create_pse_session(mc)
        .and_then(increment_mc)
        .and_then(close_pse_session)
}

fn increment_mc(mc: SgxMonotonicCounter) -> Result<u32> {
    Ok(mc.increment()?)
}

fn generate_mc(mut count: u32) -> Result<SgxMonotonicCounter> {
    Ok(SgxMonotonicCounter::new(&mut count)?)
}

fn create_pse_session(mc: SgxMonotonicCounter) -> Result<SgxMonotonicCounter> {
    rsgx_create_pse_session()?;
    Ok(mc)
}

fn read_mc(mc: SgxMonotonicCounter) -> Result<u32> {
    Ok(mc.read()?)
}

// TODO: I need a reader monad in Rust to thread state - look into!
fn close_pse_session(count: u32) -> Result<u32> {
    rsgx_close_pse_session()?;
    Ok(count)
}
