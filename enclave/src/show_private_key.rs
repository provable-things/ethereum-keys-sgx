use sgx_types::*;
use error::error_to_sgx_status;
use keygen::{KeyPair, verify_keypair};
use sgx_time::show_time_since_last_access;
use sealer::{unseal_keypair, seal_keypair_no_additional_data};
use monotonic_counter::{log_keyfile_accesses, increment_accesses_mc};

#[no_mangle]
pub extern "C" fn show_private_key(
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> sgx_status_t {
     match unseal_keypair(sealed_log, sealed_log_size) 
        .and_then(verify_keypair)
        .and_then(show_time_since_last_access)
        .and_then(increment_accesses_mc)
        .and_then(log_keyfile_accesses)
        .map(show_secret)
        .and_then(|kp| seal_keypair_no_additional_data(sealed_log, sealed_log_size, kp)) {
        Ok(_)  => sgx_status_t::SGX_SUCCESS,
        Err(e) => error_to_sgx_status(e)
    }
}

fn show_secret(kp: KeyPair) -> KeyPair {
    println!("[+] {:?}", kp.secret);
    kp    
}
