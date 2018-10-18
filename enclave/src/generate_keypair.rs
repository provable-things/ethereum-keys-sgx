use sgx_types::*;
use error::error_to_sgx_status;
use key_generator::create_keypair;
use sealer::seal_keypair_no_additional_data;

#[no_mangle]
pub extern "C" fn generate_keypair(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    match create_keypair()
        .and_then(|ks| seal_keypair_no_additional_data(sealed_log, sealed_log_size, ks)) {
        Ok(_)  => sgx_status_t::SGX_SUCCESS,
        Err(e) => error_to_sgx_status(e)
    }
}
