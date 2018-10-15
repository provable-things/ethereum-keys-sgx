use std::result;
use sgx_types::*;
use error::EnclaveError;
use sgx_tservice::sgxcounter::SgxMonotonicCounter;
use pse_session::{create_pse_session, close_pse_session};
use sgx_tservice::{rsgx_create_pse_session, rsgx_close_pse_session};

type Result<T> = result::Result<T, EnclaveError>;

pub struct MonotonicCounter {
    pub value: u32,
    pub id: sgx_mc_uuid_t,
}

pub fn create_mc() -> Result<MonotonicCounter> {
    create_pse_session()
        .and_then(generate_zeroed_mc)
        .and_then(close_pse_session)
}

pub fn read_mc(mc: MonotonicCounter) -> Result<u32> {
    create_pse_session()
        .and_then(|_| read_monotonic_counter(mc))
        .and_then(close_pse_session)
}

pub fn increment_mc(mc: MonotonicCounter) -> Result<MonotonicCounter> {
    create_pse_session()
        .and_then(|_| increment_monotonic_counter(mc))
        .and_then(close_pse_session)
}

pub fn destroy_mc(mc: MonotonicCounter) -> Result<()> {
    create_pse_session()
        .and_then(|_| destroy_monotonic_counter(mc))
        .and_then(close_pse_session)
}

fn generate_zeroed_mc<T>(_t: T) -> Result<MonotonicCounter> {
    generate_monotonic_counter(0)
}

fn generate_monotonic_counter(mut init_value: u32) -> Result<MonotonicCounter> {
    let mut counter_uuid = sgx_mc_uuid_t::default();
    let ret_val = unsafe {sgx_create_monotonic_counter(&mut counter_uuid as * mut sgx_mc_uuid_t, init_value as * mut u32)};
    match ret_val {
        sgx_status_t::SGX_SUCCESS => Ok(MonotonicCounter{id: counter_uuid, value: init_value}),
        _ => Err(EnclaveError::SGXError(ret_val))
    }
}

fn read_monotonic_counter(mut mc: MonotonicCounter) -> Result<u32> {
    let mut counter_value: u32 = 0;
    let ret_val = unsafe {sgx_read_monotonic_counter(&mut mc.id as * const sgx_mc_uuid_t, counter_value as * mut u32)};
    match ret_val {
        sgx_status_t::SGX_SUCCESS => Ok(counter_value),
        _ => Err(EnclaveError::SGXError(ret_val))
    }
}

fn increment_monotonic_counter(mut mc: MonotonicCounter) -> Result<MonotonicCounter> { // Don't forget to resave the new returned struct in the keyfile!
    let mut counter_value: u32 = 0;
    let ret_val = unsafe {sgx_increment_monotonic_counter(&mut mc.id as * const sgx_mc_uuid_t, counter_value as * mut u32)};
    match ret_val {
        sgx_status_t::SGX_SUCCESS => Ok(MonotonicCounter{value: counter_value, id: mc.id}),
        _ => Err(EnclaveError::SGXError(ret_val))
    }
}

fn destroy_monotonic_counter(mut mc: MonotonicCounter) -> Result<()> {
    let ret_val = unsafe {sgx_destroy_monotonic_counter(&mut mc.id as * const sgx_mc_uuid_t)};
    match ret_val {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(EnclaveError::SGXError(ret_val))
    }
}
