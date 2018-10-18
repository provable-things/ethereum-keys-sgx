use sgx_types::*;
use key_generator::create_keypair;
use sealer::seal_and_return_sgx_status;

#[no_mangle]
pub extern "C" fn generate_keypair(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    create_keypair()
        .map(|kp| seal_and_return_sgx_status(sealed_log, sealed_log_size, kp))
        .unwrap()
}
