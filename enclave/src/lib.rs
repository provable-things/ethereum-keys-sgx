#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#[cfg(not(target_env = "sgx"))]

extern crate sgx_rand;
extern crate sgx_tseal;
extern crate sgx_types;
extern crate secp256k1;
extern crate sgx_tcrypto;
#[macro_use]
extern crate sgx_tstd as std;

mod keygen;
use std::slice;
use sgx_types::*;
use key::PublicKey;
use keygen::KeyPair;
use sgx_tseal::SgxSealedData;
use sgx_types::marker::ContiguousMemory;
use secp256k1::{Secp256k1, Message, key};
/*
 * TODO: Make VANITY keygen & threading work!
 * TODO: Can have app call generate, rec. priv key, then call gen again if not vanity.
 * TODO: Factor stuff out to a proper app style like the other keygen I made.
 * TODO: Create better error handling for custom functions etc.
 * Then have method callable via ocall (add to edl!)
 * Note: MRENCLAVE signed = only THAT enc can unseal.
 * Note: MRSIGNER signed = other encs. by author can unseal.
 * 
 **/
#[no_mangle]
pub extern "C" fn generate_keypair(
    // pub_key_ptr: &mut PublicKey, 
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> sgx_status_t {
    let keypair = match KeyPair::new() {
        Ok(kp) => {
            // *pub_key_ptr = kp.public;
            kp
        },
        Err(_) => {return sgx_status_t::SGX_ERROR_UNEXPECTED;}
    };
    let aad: [u8; 0] = [0_u8; 0]; // Empty additional data...
    let sealed_data = match SgxSealedData::<KeyPair>::seal_data(&aad, &keypair) {
        Ok(x) => x,
        Err(ret) => {return ret;}, 
    };
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn sign_message(
    sealed_log: * mut u8, 
    sealed_log_size: u32,
    hash_msg: * mut u8
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
    let hash = unsafe { slice::from_raw_parts(hash_msg, 32) };// FIXME: Magic number - pass thru!
    let mut x = [0u8;32];
    x.copy_from_slice(&hash[..]);
    println!("[+] [Enclave] From decrypted file : {:?}", data.public);
    println!("[+] [Enclave] From decrypted file : {:?}", data.secret);
    let signed_msg = sign_message_hash(x, &data);//.unwrap(); // FIXME: Handle error better!
    println!("[+] [Enclave] Signed message: {:?}", &signed_msg[..]);
    sgx_status_t::SGX_SUCCESS
}

pub fn sign_message_hash(hashed_msg: [u8;32], keyset: &KeyPair) -> [u8;65] {//Result<[u8;65], SecpError> {
    let message = Message::from_slice(&hashed_msg).expect("32 bytes");
    let secp_context = Secp256k1::new();
    let sig = secp_context.sign_recoverable(&message, &keyset.secret);
    let (rec_id, data) = sig.serialize_compact(&secp_context);
    let mut data_arr = [0; 65];
    data_arr[0..64].copy_from_slice(&data[0..64]);
    data_arr[64] = rec_id.to_i32() as u8;
    data_arr
}

fn to_sealed_log<T: Copy + ContiguousMemory>(
    sealed_data: &SgxSealedData<T>, 
    sealed_log: * mut u8, sealed_log_size: u32
) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
fn from_sealed_log<'a, T: Copy + ContiguousMemory>(
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
