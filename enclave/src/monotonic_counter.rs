use std::result;
use sgx_types::*;
use keygen::KeyPair;
use error::EnclaveError;
use std::string::ToString;
use sgx_tservice::sgxcounter::SgxMonotonicCounter;  
use pse_session::{create_pse_session, close_pse_session};
use sgx_tservice::{rsgx_create_pse_session, rsgx_close_pse_session};

type Result<T> = result::Result<T, EnclaveError>;

#[derive(Copy,Clone)] // FIXME: Derive debug too and make a way to display it!
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
        .and_then(|_| verify_monotonic_counter(mc))
        .and_then(close_pse_session)
}

pub fn increment_accesses_mc(kp: KeyPair) -> Result<KeyPair> {
    increment_mc(kp.accesses_mc)
        .map(|mc| update_accesses_mc(mc, kp))
}

pub fn increment_signatures_mc(kp: KeyPair) -> Result<KeyPair> {
    increment_mc(kp.signatures_mc)
        .map(|mc| update_signatures_mc(mc, kp))
}

pub fn destroy_mc(mc: MonotonicCounter) -> Result<()> {
    create_pse_session()
        .and_then(|_| destroy_monotonic_counter(mc))
        .and_then(close_pse_session)
}

fn update_signatures_mc(mc: MonotonicCounter, kp: KeyPair) -> KeyPair { // FIXME: Inefficient! But functional...
    KeyPair{secret: kp.secret, public: kp.public, accesses_mc: kp.accesses_mc, signatures_mc: mc}
}

fn update_accesses_mc(mc: MonotonicCounter, kp: KeyPair) -> KeyPair { // FIXME: Inefficient! But functional...
    println!("Here the accesses value mc should be more but it's not: {}", mc.value);
    KeyPair{secret: kp.secret, public: kp.public, accesses_mc: mc, signatures_mc: kp.signatures_mc}
}

fn increment_mc(mc: MonotonicCounter) -> Result<MonotonicCounter> {
    create_pse_session()
        .and_then(|_| verify_monotonic_counter(mc))
        .and_then(|_| increment_monotonic_counter(mc))
        .and_then(close_pse_session)
}

fn generate_zeroed_mc<T>(_t: T) -> Result<MonotonicCounter> {
    generate_monotonic_counter(0)
}

fn generate_monotonic_counter(mut init_value: u32) -> Result<MonotonicCounter> {
    let mut counter_uuid = sgx_mc_uuid_t::default();
    let ret_val = unsafe {sgx_create_monotonic_counter(&mut counter_uuid, &mut init_value)}; // FIXME: use _ex to finesse owner policy etc 
    match ret_val {
        sgx_status_t::SGX_SUCCESS => Ok(MonotonicCounter{id: counter_uuid, value: init_value}),
        _ => Err(EnclaveError::SGXError(ret_val))
    }
}

fn verify_monotonic_counter(mut mc: MonotonicCounter) -> Result<u32> {
    let mut counter_value: u32 = 0;
    let ret_val = unsafe {sgx_read_monotonic_counter(&mut mc.id as * const sgx_mc_uuid_t, &mut counter_value as * mut u32)};
    match ret_val {
        sgx_status_t::SGX_SUCCESS => {
            if counter_value != mc.value {Err(EnclaveError::Custom("[!] FATAL - MONOTONIC COUNTER MISMATCH!\n[-] ABORTING OPERATION!".to_string()))} else {Ok(counter_value)}
        },
        _ => {
            println!("Here?");
            Err(EnclaveError::SGXError(ret_val))
        }
    }
}

fn increment_monotonic_counter(mut mc: MonotonicCounter) -> Result<MonotonicCounter> {
    let mut counter_value: u32 = 0;
    let ret_val = unsafe {sgx_increment_monotonic_counter(&mut mc.id as * const sgx_mc_uuid_t, &mut counter_value as * mut u32)};
    match ret_val {
        sgx_status_t::SGX_SUCCESS => {
            Ok(MonotonicCounter{value: counter_value, id: mc.id})
        },
        _ => {
            println!("Or here?");
            Err(EnclaveError::SGXError(ret_val))
        }
    }
}

fn destroy_monotonic_counter(mut mc: MonotonicCounter) -> Result<()> {
    let ret_val = unsafe {sgx_destroy_monotonic_counter(&mut mc.id as * const sgx_mc_uuid_t)};
    match ret_val {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(EnclaveError::SGXError(ret_val))
    }
}
