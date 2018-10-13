#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#[cfg(not(target_env = "sgx"))]

#[macro_use]
extern crate sgx_tstd as std;

extern crate sgx_rand;
extern crate sgx_tseal;
extern crate sgx_types;
extern crate secp256k1;
extern crate sgx_tcrypto;
extern crate sgx_tservice;

mod mc;
mod error;
mod keygen;
mod signer;
mod sealer;
mod sgx_time;
mod constants;

pub use signer::sign_message;
pub use mc::{generate_zeroed_mc};
pub use sgx_time::sgx_time_sample;
pub use keygen::{generate_keypair, get_public_key, show_private_key};
/*
 * TODO: Change package name & stuff in Cargo.toml
 * TODO: Make VANITY keygen & threading work!
 * TODO: Can have app call generate, rec. priv key, then call gen again if not vanity.
 * TODO: Factor stuff out to a proper app style like the other keygen I made.
 * TODO: Factor out the unsealing!
 * TODO: Create better error handling for custom functions etc.
 * Then have method callable via ocall (add to edl!)
 * Note: MRENCLAVE signed = only THAT enc can unseal.
 * Note: MRSIGNER signed = other encs. by author can unseal.
 **/
