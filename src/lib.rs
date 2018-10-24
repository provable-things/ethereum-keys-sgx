extern crate rlp;
extern crate dirs;
extern crate sgx_urts;
extern crate rustc_hex;
extern crate secp256k1;
extern crate sgx_types;
extern crate tiny_keccak;
extern crate ethereum_types;

pub mod fs;
pub mod types;
pub mod error;
pub mod utils;
pub mod keccak;
pub mod verify;
pub mod constants;
pub mod enclave_api;
pub mod sign_message;
pub mod init_enclave;
pub mod get_public_key;
pub mod destroy_keypair;
pub mod get_eth_address;
pub mod show_private_key;
pub mod sign_transaction;
pub mod generate_keypair;

/*
 * TODO: A wrapper type that means I can wrap single-arity function and now it'll take another
 * thing and return the original return of the function plus whatever I sent to pass through it
 * unscathed. Use it in monadic chains to make multiple-parameter requiring stuff easier. Kinda
 * like the reader monad I guess? Or a state monad without updates?
 * */
