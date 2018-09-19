#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#[cfg(not(target_env = "sgx"))]

extern crate sgx_rand;
extern crate sgx_types;
extern crate secp256k1;
extern crate sgx_tcrypto;
#[macro_use]
extern crate sgx_tstd as std;

mod keygen;
use sgx_types::*;
/*
 *
 * TODO: Switch to using the crypto crates' sha3 instead of tiny_keccak!! - Done but oops they aren't the same. Dammit.
 * TODO: Seal a pkS inside the enc and spit out ONLY the pub key!
 * TODO: Have the ETH address generated OUTSIDE the enc form the pk spat out by the enc. 
 * TODO: Make VANITY keygen & threading work!
 * Can have app call generate, rec. priv key, then call gen again if not vanity. Then have method callable via ocall (add to edl!)
 * that'll seal the priv key and close the enc!
 * 
 **/
#[no_mangle]
pub extern "C" fn generate_keypair() -> sgx_status_t {
    match keygen::KeyPair::new() {
        Ok(_kp) => sgx_status_t::SGX_SUCCESS, // TODO: Copy data to a pointer that's passed in of a public key mem. space!
        Err(_)  => sgx_status_t::SGX_ERROR_UNEXPECTED
    }
}