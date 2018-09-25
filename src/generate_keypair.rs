use std::mem::size_of;

use std::result;
use sgx_types::*;
use error::AppError;
use keccak::hash_message;
use sgx_urts::SgxEnclave;
use secp256k1::key::PublicKey;
use init_enclave::init_enclave;
use fs::{read_file_as_vec, write_keyfile};
use enclave_api::{generate_keypair, sign_message};
use types::{KeyPair, EncryptedKeyPair, ENCRYPTED_KEYPAIR_SIZE};

type Result<T> = result::Result<T, AppError>;

static DEFAULT_KEYPAIR_PATH: &'static str = "./encrypted_keypair.txt";

pub fn run() -> Result<()> {
    initialise_enclave()
        .and_then(get_encrypted_keypair)
        .and_then(save_keypair)
}        

// TODO: Check already exists? Or will that happen before this is called?
pub fn get_encrypted_keypair(enc: SgxEnclave) -> Result<EncryptedKeyPair> {
    let mut encrypted_keys: EncryptedKeyPair = vec![0u8; ENCRYPTED_KEYPAIR_SIZE];
    let ptr: *mut u8 = &mut encrypted_keys[0];
    let result = unsafe {
        generate_keypair(enc.geteid(), &mut sgx_status_t::SGX_SUCCESS, ptr, ENCRYPTED_KEYPAIR_SIZE as *const u32)
    };
    enc.destroy();
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] [App] Key pair successfully generated inside enclave");
            Ok(encrypted_keys)
        },
        _ => {
            println!("[-] [App] ECALL to enclave failed {}!", result.as_str());
            Err(AppError::SGXError(result))
        }
    }
}

pub fn save_keypair(data: EncryptedKeyPair) -> Result<()> {
    Ok(write_keyfile(DEFAULT_KEYPAIR_PATH, &data)?)
}

pub fn initialise_enclave() -> Result<SgxEnclave> {
    Ok(init_enclave()?)
}