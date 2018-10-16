use std::result;
use error::AppError;
use sgx_urts::SgxEnclave;
use sgx_types::sgx_status_t;
use enclave_api::sign_message;
use init_enclave::init_enclave;
use keccak::{hash_slice, hash_with_prefix};
use fs::{read_encrypted_keyfile, write_keyfile};
use types::{MessageSignature, EncryptedKeyPair, ENCRYPTED_KEYPAIR_SIZE};

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String, message: String, no_prefix: bool) -> Result<MessageSignature> {
    sign_hashed_message( // FIXME: Make this function better & more functional, urgh!
        read_encrypted_keyfile(&path)?, 
        if no_prefix { hash_slice(&message) } else { hash_with_prefix(&message) }, 
        init_enclave()?,
        path
    )
}

fn sign_hashed_message(mut keypair: EncryptedKeyPair, mut hashed_message: [u8;32], enc: SgxEnclave, path: &String) -> Result<MessageSignature> {
    let mut signature: MessageSignature = [0u8;65];
    let result = unsafe {
        sign_message(
            enc.geteid(), 
            &mut sgx_status_t::SGX_SUCCESS, 
            &mut keypair[0] as *mut u8, 
            ENCRYPTED_KEYPAIR_SIZE as *const u32, 
            &mut hashed_message[0] as *mut u8, // TODO: have a type for this too?
            &mut signature[0] as *mut u8
        )
    };
    enc.destroy();
    match result {
        sgx_status_t::SGX_SUCCESS => {
            write_keyfile(&path, &keypair)?; // FIXME: Factor this out, have this main func return a tuple & go from there?
            Ok(signature)
        },
        _ => Err(AppError::SGXError(result))
    }
}
