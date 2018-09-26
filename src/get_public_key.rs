use std::result;
use error::AppError;
use self::key::PublicKey;
use sgx_urts::SgxEnclave;
use sgx_types::sgx_status_t;
use init_enclave::init_enclave;
use secp256k1::{key, Secp256k1};
use enclave_api::{get_public_key};
use fs::read_default_encrypted_keyfile;
use types::{ENCRYPTED_KEYPAIR_SIZE, EncryptedKeyPair};

type Result<T> = result::Result<T, AppError>;

pub fn run() -> Result<PublicKey> {
    get_key_from_enc(init_enclave()?, read_default_encrypted_keyfile()?) // TODO: Eventually use argv and non-default if passed
}

fn get_key_from_enc(enc: SgxEnclave, mut keypair: EncryptedKeyPair) -> Result<PublicKey> {
    let mut pub_key = PublicKey::new();
    let result = unsafe {
        get_public_key(enc.geteid(), &mut sgx_status_t::SGX_SUCCESS, &mut pub_key, &mut keypair[0] as *mut u8, ENCRYPTED_KEYPAIR_SIZE as *const u32)
    };
    enc.destroy();
    match result {
        sgx_status_t::SGX_SUCCESS => Ok(pub_key),
        _ => {
            Err(AppError::SGXError(result))
        }
    }
}

#[allow(dead_code)]
fn is_not_valid_key(key: PublicKey) -> Result<bool> { // FIXME: & implement before return pubkey above!
    Ok(key == PublicKey::from_slice(&Secp256k1::new(), &[0u8;64])?)
}