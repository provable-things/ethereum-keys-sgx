use std::slice;
use sgx_types::*;
use constants::HASH_LENGTH;
use secp256k1::{Message, Secp256k1};
use sealer::seal_and_return_sgx_status;
use key_generator::{KeyStruct, verify_key_and_update_accesses};
use monotonic_counter::{log_keyfile_signatures, increment_signatures_mc};

pub type MessageSignature = [u8;65];

#[no_mangle]
pub extern "C" fn sign_message(sealed_log: *mut u8, sealed_log_size: u32, hash_ptr: *mut u8, signature_ptr: &mut MessageSignature) -> sgx_status_t {
    verify_key_and_update_accesses(sealed_log, sealed_log_size) 
        .map(|kp| get_message_hash(kp, hash_ptr))
        .map(sign_msg_hash_slice)
        .map(|(kp, signed_msg)| write_msg_hash_outside_enclave(kp, signed_msg, signature_ptr))
        .and_then(increment_signatures_mc)
        .and_then(log_keyfile_signatures)
        .map(|kp| seal_and_return_sgx_status(sealed_log, sealed_log_size, kp))
        .unwrap()
}

fn sign_msg_hash_slice<'a>((kp, hashed_msg): (KeyStruct, &'a [u8])) -> (KeyStruct, MessageSignature) { // FIXME: Make less imperative!
    let mut x = [0u8; HASH_LENGTH];
    x.copy_from_slice(&hashed_msg[..]);
    let message = Message::from_slice(&x).expect("32 bytes"); // FIXME: handle better!
    let secp_context = Secp256k1::new();
    let sig = secp_context.sign_recoverable(&message, &kp.secret);
    let (rec_id, data) = sig.serialize_compact(&secp_context);
    let mut data_arr = [0; 65];
    data_arr[0..64].copy_from_slice(&data[0..64]);
    data_arr[64] = rec_id.to_i32() as u8;
    (kp, data_arr)
}

fn write_msg_hash_outside_enclave(kp: KeyStruct, signed_msg: MessageSignature, signature_ptr: &mut MessageSignature) -> KeyStruct {
    *signature_ptr = signed_msg;
    kp
}

fn get_message_hash<'a>(kp: KeyStruct, hash_ptr: *mut u8) -> (KeyStruct, &'a [u8]) {
    (kp, unsafe {slice::from_raw_parts(hash_ptr, HASH_LENGTH)})
}


