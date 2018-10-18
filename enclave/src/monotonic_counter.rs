use std::result;
use sgx_types::*;
use keygen::KeyStruct;
use error::EnclaveError;
use std::string::ToString;
use pse_session::{create_pse_session, close_pse_session};

type Result<T> = result::Result<T, EnclaveError>;

#[derive(Copy,Clone)]
pub struct MonotonicCounter {
    pub value: u32,
    pub id: sgx_mc_uuid_t,
}

pub fn create_mc() -> Result<MonotonicCounter> {
    create_pse_session()
        .and_then(generate_zeroed_mc)
        .and_then(close_pse_session)
}

pub fn increment_accesses_mc(kp: KeyStruct) -> Result<KeyStruct> {
    increment_mc(kp.accesses_mc)
        .map(|mc| update_accesses_mc(mc, kp))
}

pub fn increment_signatures_mc(kp: KeyStruct) -> Result<KeyStruct> {
    increment_mc(kp.signatures_mc)
        .map(|mc| update_signatures_mc(mc, kp))
}

pub fn destroy_mc(mc: MonotonicCounter) -> Result<()> {
    create_pse_session()
        .and_then(|_| destroy_monotonic_counter(mc))
        .and_then(close_pse_session)
}
// FIXME: Make generic function for the following two?
pub fn log_keyfile_accesses(kp: KeyStruct) -> Result<KeyStruct> {
    println!("[+] Number of key file accesses: {}", kp.accesses_mc.value);
    Ok(kp)
}

pub fn log_keyfile_signatures(kp: KeyStruct) -> Result<KeyStruct> {
    println!("[+] Number of signatures signed by this key: {}", kp.signatures_mc.value);
    Ok(kp)
}

fn increment_mc(mc: MonotonicCounter) -> Result<MonotonicCounter> {
    create_pse_session()
        .and_then(|_| verify_monotonic_counter(mc))
        .and_then(|_| increment_monotonic_counter(mc))
        .and_then(close_pse_session)
}

fn update_signatures_mc(mc: MonotonicCounter, kp: KeyStruct) -> KeyStruct {
    KeyStruct{sgx_time: kp.sgx_time, secret: kp.secret, public: kp.public, accesses_mc: kp.accesses_mc, signatures_mc: mc}
}

fn update_accesses_mc(mc: MonotonicCounter, kp: KeyStruct) -> KeyStruct {
    KeyStruct{sgx_time: kp.sgx_time, secret: kp.secret, public: kp.public, accesses_mc: mc, signatures_mc: kp.signatures_mc}
}

fn generate_zeroed_mc<T>(_t: T) -> Result<MonotonicCounter> {
    generate_monotonic_counter(0)
}

fn generate_monotonic_counter(mut init_value: u32) -> Result<MonotonicCounter> {
    let mut counter_uuid = sgx_mc_uuid_t::default();
    let ret_val = unsafe {sgx_create_monotonic_counter(&mut counter_uuid, &mut init_value)}; // FIXME: use _ex version to finesse owner policy etc 
    match ret_val {
        sgx_status_t::SGX_SUCCESS => Ok(MonotonicCounter{id: counter_uuid, value: init_value}),
        _ => Err(EnclaveError::SGXError(ret_val))
    }
}

fn verify_monotonic_counter(mut mc: MonotonicCounter) -> Result<u32> {
    let mut counter_value: u32 = 0;
    let ret_val = unsafe {sgx_read_monotonic_counter(&mut mc.id as * const sgx_mc_uuid_t, &mut counter_value as * mut u32)};
    match ret_val {
        sgx_status_t::SGX_SUCCESS => match counter_value == mc.value {
            true  => Ok(counter_value),
            false => Err(EnclaveError::Custom("[!] FATAL! Monotonic counter mismatch - aborting operation!".to_string()))
        },
        _ => Err(EnclaveError::SGXError(ret_val))
    }
}

fn increment_monotonic_counter(mut mc: MonotonicCounter) -> Result<MonotonicCounter> {
    let mut counter_value: u32 = 0;
    let ret_val = unsafe {sgx_increment_monotonic_counter(&mut mc.id as * const sgx_mc_uuid_t, &mut counter_value as * mut u32)};
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
