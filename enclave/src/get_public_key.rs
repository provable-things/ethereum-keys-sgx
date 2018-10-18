use sgx_types::*;
use secp256k1::key::PublicKey;
use error::error_to_sgx_status;
use sealer::seal_keypair_no_additional_data;
use key_generator::{verify_key_and_update_accesses, KeyStruct};

#[no_mangle]
pub extern "C" fn get_public_key(pub_key_ptr: &mut PublicKey,sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    match verify_key_and_update_accesses(sealed_log, sealed_log_size) 
        .map(|ks| write_public_key_outside_enclave(ks, pub_key_ptr))
        .and_then(|ks| seal_keypair_no_additional_data(sealed_log, sealed_log_size, ks)) {
        Ok(_)  => sgx_status_t::SGX_SUCCESS,
        Err(e) => error_to_sgx_status(e)
    }
}

fn write_public_key_outside_enclave(ks: KeyStruct, pub_key_ptr: &mut PublicKey) -> KeyStruct {
    *pub_key_ptr = ks.public;
    ks
}
