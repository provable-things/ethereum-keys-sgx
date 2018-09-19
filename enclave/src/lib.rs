#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate secp256k1;
extern crate sgx_tcrypto;

use std::slice;

use std::string::String;
use sgx_types::*;
use sgx_tcrypto::*;
// use std::backtrace::{self, PrintFormat};

// mod tests;
mod keygen;

/*
 *
 * TODO: Switch to using the crypto crates' sha3 instead of tiny_keccak!! - Done but oops they aren't the same. Dammit.
 * TODO: Seal a pk inside the enc and spit out ONLY the pub key!
 * TODO: Have the ETH address generated OUTSIDE the enc form the pk spat out by the enc. 
 * TODO: Make VANITY keygen & threading work!
 * 
 **/

#[no_mangle]
pub extern "C" fn run_tests() -> sgx_status_t {
    let keypair = keygen::KeySet::new().unwrap(); // Unwrap is not handling error!
    println!("{}", keypair);
    keypair.unsafe_show_secret();
    
    let input_str = String::from("Hash this string please");
    let some_len = input_str.len();
    
    println!("calc_sha256 invoked!");

    // First, build a slice for input_str
    let input_slice = unsafe { slice::from_raw_parts(input_str.as_bytes().as_ptr() as *const u8, some_len) }; // Note: core dumps if not ptr!!

    // slice::from_raw_parts does not guarantee the length, we need a check
    if input_slice.len() != some_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("Input string len = {}, input len = {}", input_slice.len(), some_len);

    // Second, convert the vector to a slice and calculate its SHA256
    let result = rsgx_sha256_slice(&input_slice);

    // Third, copy back the result
    match result {
        Ok(output_hash) => println!("See if this works! {:x?}", output_hash), //*hash = output_hash,
        Err(x) => return x
    }

    sgx_status_t::SGX_SUCCESS
}