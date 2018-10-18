use sgx_types::*;
use sealer::seal_and_return_sgx_status;
use key_generator::{KeyStruct, verify_key_and_update_accesses};

#[no_mangle]
pub extern "C" fn show_private_key(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    verify_key_and_update_accesses(sealed_log, sealed_log_size) 
        .map(show_secret)
        .map(|kp|seal_and_return_sgx_status(sealed_log, sealed_log_size, kp))
        .unwrap()
}

fn show_secret(kp: KeyStruct) -> KeyStruct {
    println!("[+] {:?}", kp.secret);
    kp    
}
