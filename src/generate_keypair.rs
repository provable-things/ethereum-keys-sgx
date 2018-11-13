use std::result;
use sgx_types::*;
use error::AppError;
use utils::save_keypair;
use sgx_urts::SgxEnclave;
use init_enclave::init_enclave;
use enclave_api::generate_keypair;
use types::{EncryptedKeyStruct, ENCRYPTED_KEYPAIR_SIZE};

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String) -> Result<()> {
    init_enclave()
        .and_then(get_encrypted_keypair)
        .and_then(|ks| save_keypair(ks, &path))
}

fn get_encrypted_keypair(enc: SgxEnclave) -> Result<EncryptedKeyStruct> {
    let mut encrypted_keys: EncryptedKeyStruct = vec![0u8; ENCRYPTED_KEYPAIR_SIZE];
    let result = unsafe {
        generate_keypair(
            enc.geteid(), 
            &mut sgx_status_t::SGX_SUCCESS, 
            &mut encrypted_keys[0] as * mut u8,
            ENCRYPTED_KEYPAIR_SIZE as *const u32 // FIXME: Do we even need this now we're doing [user_check] ?
        )
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
