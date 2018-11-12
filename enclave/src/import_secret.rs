use sgx_types::*;
use error::EnclaveError;
use std::{result, string, slice};
use constants::SECRET_LENGTH;
use error::error_to_sgx_status;
use sealer::seal_keypair_no_additional_data;
use key_generator::create_keypair_from_secret;
use secp256k1::Secp256k1;
use secp256k1::key::{SecretKey, PublicKey};

type Result<T> = result::Result<T, EnclaveError>;

#[no_mangle]
pub extern "C" fn import_secret(sealed_log: * mut u8, sealed_log_size: u32, secret_ptr: * const u8) -> sgx_status_t { // FIXME: Refactor!!
    let x = get_passed_in_secret(secret_ptr).expect("Can't get string because I suck!");
    let s = SecretKey::from_slice(&Secp256k1::new(), x).expect("Something");
    let y = create_keypair_from_secret(x).expect("Not a real key dummy!");
    seal_keypair_no_additional_data(sealed_log, sealed_log_size, y).expect("borked it!");
    sgx_status_t::SGX_SUCCESS
}
/*
#[no_mangle]
pub extern "C" fn import_secret(sealed_log: * mut u8, sealed_log_size: u32, secret_ptr: *mut u8) -> sgx_status_t {
    match get_passed_in_secret(secret_ptr) {
        .and_then(create_keypair_from_secret)
        .and_then(|ks| seal_keypair_no_additional_data(sealed_log, sealed_log_size, ks)) {
        Ok(_)  => sgx_status_t::SGX_SUCCESS,
        Err(e) => error_to_sgx_status(e)
    }
}
*/
fn get_passed_in_secret<'a>(secret_ptr: *const u8) -> Result<&'a [u8]> {
    Ok(unsafe {slice::from_raw_parts(secret_ptr, SECRET_LENGTH)})
}
