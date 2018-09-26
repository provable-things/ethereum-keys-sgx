use std::result;
use error::AppError;
use sgx_urts::SgxEnclave;
use sgx_types::sgx_status_t;
use init_enclave::init_enclave;
use enclave_api::{show_private_key};
use fs::read_default_encrypted_keyfile;
use types::{ENCRYPTED_KEYPAIR_SIZE, EncryptedKeyPair};

type Result<T> = result::Result<T, AppError>;

pub fn run() -> Result<()> {
    show_key_via_enc(init_enclave()?, read_default_encrypted_keyfile()?) // TODO: use passed in target for path?
}

fn show_key_via_enc(enc: SgxEnclave, mut keypair: EncryptedKeyPair) -> Result<()> {
    let result = unsafe {
        show_private_key(enc.geteid(), &mut sgx_status_t::SGX_SUCCESS, &mut keypair[0] as *mut u8, ENCRYPTED_KEYPAIR_SIZE as *const u32)
    };
    enc.destroy();
    match result {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(AppError::SGXError(result))
    }
}