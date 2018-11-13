use sgx_types::*;
use error::EnclaveError;
use std::{result, slice};
use constants::SECRET_LENGTH;
use error::error_to_sgx_status;
use sealer::seal_keypair_no_additional_data;
use key_generator::create_keypair_from_secret;

type Result<T> = result::Result<T, EnclaveError>;

#[no_mangle]
pub extern "C" fn import_secret(sealed_log: * mut u8, sealed_log_size: u32, secret_ptr: * const u8) -> sgx_status_t {
    match get_passed_in_secret(secret_ptr)
        .and_then(create_keypair_from_secret)
        .and_then(|ks| seal_keypair_no_additional_data(sealed_log, sealed_log_size, ks)) {
        Ok(_)  => sgx_status_t::SGX_SUCCESS,
        Err(e) => error_to_sgx_status(e) 
    }
}

fn get_passed_in_secret<'a>(secret_ptr: *const u8) -> Result<&'a [u8]> { // FIXME: Factor this out with any other raw slicings we do elsewhere!
    Ok(unsafe {slice::from_raw_parts(secret_ptr, SECRET_LENGTH)})
}
