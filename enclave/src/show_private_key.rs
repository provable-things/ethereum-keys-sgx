use sgx_types::*;
use error::error_to_sgx_status;
use sealer::seal_keypair_no_additional_data;
use key_generator::{KeyStruct, verify_key_and_update_accesses};

#[no_mangle]
pub extern "C" fn show_private_key(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    match verify_key_and_update_accesses(sealed_log, sealed_log_size) 
        .map(show_secret)
        .and_then(|ks| seal_keypair_no_additional_data(sealed_log, sealed_log_size, ks)) {
        Ok(_)  => sgx_status_t::SGX_SUCCESS,
        Err(e) => error_to_sgx_status(e)
    }
}

fn show_secret(ks: KeyStruct) -> KeyStruct {
    println!("[+] {:?}", ks.secret);
    ks    
}
