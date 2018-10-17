use sgx_types::*;
use keygen::create_keypair;
use error::error_to_sgx_status;
use sealer::seal_keypair_no_additional_data;

#[no_mangle]
pub extern "C" fn generate_keypair(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    match create_keypair()
        .and_then(|kp| seal_keypair_no_additional_data(sealed_log, sealed_log_size, kp)) {
        Ok(_)  => sgx_status_t::SGX_SUCCESS,
        Err(e) => error_to_sgx_status(e)
    }
}
