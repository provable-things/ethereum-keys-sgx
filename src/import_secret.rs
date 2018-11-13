use std::result;
use sgx_types::*;
use error::AppError;
use sgx_urts::SgxEnclave;
use init_enclave::init_enclave;
use enclave_api::import_secret;
use constants::SECRET_KEY_SIZE_HEX;
use types::{EncryptedKeyStruct, ENCRYPTED_KEYPAIR_SIZE};
use utils::{decode_string_from_hex, save_keypair, is_valid_length};

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String, secret: String) -> Result<()> {
    init_enclave()
        .and_then(|enc| create_keypair_from_secret(enc, secret))
        .and_then(|ks| save_keypair(ks, &path))
}

fn create_keypair_from_secret(enc: SgxEnclave, secret: String) -> Result<EncryptedKeyStruct> { // FIXME: Factor out redundancies here between this and `get_encrypted_keypair` in generate keypair file func!
    let mut encrypted_keys: EncryptedKeyStruct = vec![0u8; ENCRYPTED_KEYPAIR_SIZE];
    let result = unsafe {
        import_secret(
            enc.geteid(),
            &mut sgx_status_t::SGX_SUCCESS,
            &mut encrypted_keys[0] as *mut u8, 
            ENCRYPTED_KEYPAIR_SIZE as *const u32,
            &mut convert_secret_to_bytes(secret)?[0] as * mut u8
        )
    };
    enc.destroy();
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] Key pair successfully generated from secret inside enclave!");
            Ok(encrypted_keys)
        },
        _ => {
            println!("[-] ECALL to enclave failed {}!", result.as_str());
            Err(AppError::SGXError(result))
        }
    }
}

fn convert_secret_to_bytes(secret: String) -> Result<Vec<u8>> {
    is_valid_length(secret, SECRET_KEY_SIZE_HEX)
        .and_then(decode_string_from_hex)
}
