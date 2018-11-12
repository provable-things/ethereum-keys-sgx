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

mod error;
mod signer;
mod sealer;
mod sgx_time;
mod constants;
mod pse_session;
mod destroy_key;
mod import_secret;
mod key_generator;
mod get_public_key;
mod show_private_key;
mod generate_keypair;
mod monotonic_counter;

pub use signer::sign_message;
pub use destroy_key::destroy_key;
pub use import_secret::import_secret;
pub use get_public_key::get_public_key;
pub use generate_keypair::generate_keypair;
pub use show_private_key::show_private_key;
/*
 * TODO: Make VANITY key_generator & threading work!
 * TODO: Can have app call generate, rec. priv key, then call gen again if not vanity.
 * TODO: Factor out the unsealing!
 * TODO: Create better error handling for custom functions etc.
 * Note: MRENCLAVE signed = only THAT enc can unseal.
 * Note: MRSIGNER signed = other encs. by author can unseal.
 **/
