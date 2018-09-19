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
 * TODO: Seal key struct & re-access after! (Or just priv-key? Do we need to have a struct at all?)
 * TODO: Switch to using the crypto crates' sha3 instead of tiny_keccak!! - Done but oops they aren't the same. Dammit.
 * TODO: Make VANITY keygen & threading work!
 * TODO:Can have app call generate, rec. priv key, then call gen again if not vanity. 
 * Then have method callable via ocall (add to edl!)
 * 
 **/
#[no_mangle]
pub extern "C" fn generate_keypair(pub_key_ptr: &mut secp256k1::PublicKey) -> sgx_status_t {
    match keygen::KeyPair::new() {
        Ok(kp) => *pub_key_ptr = kp.public,
        Err(_) => ()
    }
    sgx_status_t::SGX_SUCCESS
}