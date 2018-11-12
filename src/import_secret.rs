use std::result;
use sgx_types::*;
use error::AppError;
use constants::SECRET_KEY_SIZE_HEX;
use fs::write_keyfile;
use sgx_urts::SgxEnclave;
use init_enclave::init_enclave;
use secp256k1::{key, Secp256k1};
use enclave_api::import_secret;
use self::key::{SecretKey, PublicKey};
use types::{EncryptedKeyStruct, ENCRYPTED_KEYPAIR_SIZE};
use hex::decode;
type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String, secret: String) -> Result<()> {
    init_enclave()
        .and_then(|enc| create_keypair_from_secret(enc, secret))
        .and_then(|ks| save_keypair(ks, &path))
}

fn create_keypair_from_secret(enc: SgxEnclave, secret: String) -> Result<EncryptedKeyStruct> { // FIXME: Factor out redundancies here between this and `get_encrypted_keypair` func!
    let sec = is_valid_length(secret)?; // FIXME make monadic chain!
    let mut x = decode_secret_from_hex(sec)?;
    let mut encrypted_keys: EncryptedKeyStruct = vec![0u8; ENCRYPTED_KEYPAIR_SIZE];
    let result = unsafe {
        import_secret(
            enc.geteid(),
            &mut sgx_status_t::SGX_SUCCESS,
            &mut encrypted_keys[0] as *mut u8, 
            ENCRYPTED_KEYPAIR_SIZE as *const u32,
            &mut x[0] as * mut u8
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

fn save_keypair(data: EncryptedKeyStruct, path: &String) -> Result<()> {
    Ok(write_keyfile(&path, &data)?)
}

fn decode_secret_from_hex(secret: String) -> Result<Vec<u8>> {
    Ok(decode(&secret)?)
}

fn is_valid_length(secret: String) -> Result<String> {
    match secret.len() == SECRET_KEY_SIZE_HEX {
        true => Ok(secret),
        false => Err(AppError::Custom("Invalid secret key length!".to_string()))
    }
}
