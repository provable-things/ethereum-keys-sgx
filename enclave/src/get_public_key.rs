use sgx_types::*;
use secp256k1::key::PublicKey;
use error::error_to_sgx_status;
use keygen::{KeyPair, verify_keypair};
use sgx_time::show_time_since_last_access;
use sealer::{seal_keypair_no_additional_data, unseal_keypair};
use monotonic_counter::{increment_accesses_mc, log_keyfile_accesses};

#[no_mangle]
pub extern "C" fn get_public_key(
    pub_key_ptr: &mut PublicKey, 
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> sgx_status_t {
    match unseal_keypair(sealed_log, sealed_log_size) 
        .and_then(verify_keypair)
        .and_then(show_time_since_last_access)
        .and_then(increment_accesses_mc)
        .and_then(log_keyfile_accesses)
        .map(|kp| write_public_key_outside_enclave(kp, pub_key_ptr))
        .and_then(|kp| seal_keypair_no_additional_data(sealed_log, sealed_log_size, kp)) {
        Ok(_)  => sgx_status_t::SGX_SUCCESS,
        Err(e) => error_to_sgx_status(e)
    }
}

fn write_public_key_outside_enclave(kp: KeyPair, pub_key_ptr: &mut PublicKey) -> KeyPair {
    *pub_key_ptr = kp.public;
    kp
}
