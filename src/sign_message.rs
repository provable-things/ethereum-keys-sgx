// use keccak::hash_message;
use std::result;
use error::AppError;
use keccak::hash_message;
use sgx_urts::SgxEnclave;
use sgx_types::sgx_status_t;
use enclave_api::sign_message;
use init_enclave::init_enclave;
use fs::read_default_encrypted_keyfile;
use types::{MessageSignature, EncryptedKeyPair, ENCRYPTED_KEYPAIR_SIZE};

type Result<T> = result::Result<T, AppError>;

pub fn run() -> Result<MessageSignature> {
    sign_hashed_message(init_enclave()?, read_default_encrypted_keyfile()?, "Hello Oraclize!") // TODO: Eventually use argv and non-default if passed
}

fn sign_hashed_message(enc: SgxEnclave, mut keypair: EncryptedKeyPair, msg: &str) -> Result<MessageSignature> {
    let mut signature: MessageSignature = [0u8;65];
    let result = unsafe {
        sign_message(
            enc.geteid(), 
            &mut sgx_status_t::SGX_SUCCESS, 
            &mut keypair[0] as *mut u8, 
            ENCRYPTED_KEYPAIR_SIZE as *const u32, 
            &mut hash_message(msg)[0] as *mut u8, // TODO: maybe have a type for this too?
            &mut signature[0] as *mut u8
        )
    };
    enc.destroy();
    match result {
        sgx_status_t::SGX_SUCCESS => Ok(signature),
        _ => Err(AppError::SGXError(result))
    }
}