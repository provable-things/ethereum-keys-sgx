use std::result;
use error::AppError;
use sgx_urts::SgxEnclave;
use sgx_types::sgx_status_t;
use init_enclave::init_enclave;
use enclave_api::{show_private_key};
use fs::{read_encrypted_keyfile, write_keyfile};
use types::{ENCRYPTED_KEYPAIR_SIZE, EncryptedKeyPair};

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String) -> Result<()> {
    show_key_via_enc(read_encrypted_keyfile(&path)?, init_enclave()?, path) // FIXME: make more functional, pass path in only once and read it from inside next func?
}

fn show_key_via_enc(mut keypair: EncryptedKeyPair, enc: SgxEnclave, path: &String) -> Result<()> {
    let ret_val = unsafe {
        show_private_key(enc.geteid(), &mut sgx_status_t::SGX_SUCCESS, &mut keypair[0] as *mut u8, ENCRYPTED_KEYPAIR_SIZE as *const u32)
    };
    enc.destroy();
    match ret_val {
        sgx_status_t::SGX_SUCCESS => {
            write_keyfile(&path, &keypair)?; // FIXME: Factor this out, have this main func return a tuple & go from there?
            Ok(())
        },
        _ => Err(AppError::SGXError(ret_val))
    }
}
