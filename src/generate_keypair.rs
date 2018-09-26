use std::result;
use sgx_types::*;
use error::AppError;
use fs::write_keyfile;
use sgx_urts::SgxEnclave;
use init_enclave::init_enclave;
use enclave_api::generate_keypair;
use constants::DEFAULT_KEYPAIR_PATH;
use types::{EncryptedKeyPair, ENCRYPTED_KEYPAIR_SIZE};

type Result<T> = result::Result<T, AppError>;

pub fn run() -> Result<()> {
    init_enclave()
        .and_then(get_encrypted_keypair)
        .and_then(save_keypair)
}        

fn save_keypair(data: EncryptedKeyPair) -> Result<()> {
    Ok(write_keyfile(DEFAULT_KEYPAIR_PATH, &data)?)
}

fn get_encrypted_keypair(enc: SgxEnclave) -> Result<EncryptedKeyPair> { // TODO: check if path exists first, then env. args to act on that info.
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