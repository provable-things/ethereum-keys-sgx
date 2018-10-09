use sgx_types::*;
use keygen::KeyPair;
use std::slice;
use constants::HASH_LENGTH;
use sealer::from_sealed_log;
use secp256k1::{Message, Secp256k1};
use sgx_tservice::sgxcounter::SgxMonotonicCounter;

#[no_mangle]
pub extern "C" fn sign_message(
    sealed_log: *mut u8, 
    sealed_log_size: u32,
    hash_msg: *mut u8,
    signature_ptr: &mut [u8;65]
) -> sgx_status_t {
    let opt = from_sealed_log::<KeyPair>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;},
    };
    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {return ret;}, 
    };
    let data: KeyPair = *unsealed_data.get_decrypt_txt();
    let hash = unsafe {slice::from_raw_parts(hash_msg, HASH_LENGTH)};
    let mut x = [0u8;HASH_LENGTH];
    x.copy_from_slice(&hash[..]);// TODO: convert from slice to arr - make func elsewhere!
    let signed_msg = sign_message_hash(x, &data);//.unwrap(); // FIXME: Handle error better!
    *signature_ptr = signed_msg; // FIXME: use a type?
    sgx_status_t::SGX_SUCCESS
}

fn sign_message_hash(hashed_msg: [u8;32], keyset: &KeyPair) -> [u8;65] {
    let message = Message::from_slice(&hashed_msg).expect("32 bytes");
    let secp_context = Secp256k1::new();
    let sig = secp_context.sign_recoverable(&message, &keyset.secret);
    let (rec_id, data) = sig.serialize_compact(&secp_context);
    let mut data_arr = [0; 65];
    data_arr[0..64].copy_from_slice(&data[0..64]);
    data_arr[64] = rec_id.to_i32() as u8;
    data_arr
}
