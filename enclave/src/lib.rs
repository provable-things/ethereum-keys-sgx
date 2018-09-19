#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate secp256k1;

use sgx_types::*;

use std::backtrace::{self, PrintFormat};

mod tests;
mod keygen;

/*
 *
 * TODO: Keygen INSIDE this enc. ONLY the keygen. Have it spit out the
 * formatted result with the pk redacted. 
 * TODO: Make VANITY keygen & threading work!
 * TODO: Switch to using the crypto crates' sha3 instead of tiny_keccak!!
 * 
 **/

#[no_mangle]
pub extern "C" fn run_tests() -> sgx_status_t {
    let keypair = keygen::KeySet::new().unwrap(); // Unwrap is not handling error!
    println!("{}", keypair);
    keypair.unsafe_show_secret();
    sgx_status_t::SGX_SUCCESS
}