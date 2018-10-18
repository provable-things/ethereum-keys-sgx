use std::result;
use sgx_types::*;
use error::AppError;
use fs::write_keyfile;
use sgx_urts::SgxEnclave;
use init_enclave::init_enclave;
use enclave_api::generate_keypair;
use types::{EncryptedKeyStruct, ENCRYPTED_KEYPAIR_SIZE};

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String) -> Result<()> {
    init_enclave()
        .and_then(get_encrypted_keypair)
        .and_then(|kp| save_keypair(kp, &path))
}

fn save_keypair(data: EncryptedKeyStruct, path: &String) -> Result<()> {
    Ok(write_keyfile(&path, &data)?)
}

fn get_encrypted_keypair(enc: SgxEnclave) -> Result<EncryptedKeyStruct> {
    let mut encrypted_keys: EncryptedKeyStruct = vec![0u8; ENCRYPTED_KEYPAIR_SIZE];
    let ptr: *mut u8 = &mut encrypted_keys[0];
    let result = unsafe {
        generate_keypair(enc.geteid(), &mut sgx_status_t::SGX_SUCCESS, ptr, ENCRYPTED_KEYPAIR_SIZE as *const u32)
    };
    enc.destroy();
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] Key pair successfully generated inside enclave!");
            Ok(encrypted_keys)
        },
        _ => {
            println!("[-] ECALL to enclave failed {}!", result.as_str());
            Err(AppError::SGXError(result))
        }
    }
}

