use sgx_types::*;
use secp256k1::key::PublicKey;
use sealer::seal_and_return_sgx_status;
use key_generator::{verify_key_and_update_accesses, KeyStruct};

#[no_mangle]
pub extern "C" fn get_public_key(pub_key_ptr: &mut PublicKey,sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    verify_key_and_update_accesses(sealed_log, sealed_log_size) 
        .map(|kp| write_public_key_outside_enclave(kp, pub_key_ptr))
        .map(|kp| seal_and_return_sgx_status(sealed_log, sealed_log_size, kp)) 
        .unwrap()
}

fn write_public_key_outside_enclave(kp: KeyStruct, pub_key_ptr: &mut PublicKey) -> KeyStruct {
    *pub_key_ptr = kp.public;
    kp
}
