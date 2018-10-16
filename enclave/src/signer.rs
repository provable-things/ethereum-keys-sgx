use std::slice;
use sgx_types::*;
use keygen::KeyPair;
use sgx_time::get_sgx_time;
use constants::HASH_LENGTH;
use sgx_tseal::SgxSealedData;
use secp256k1::{Message, Secp256k1};
use sealer::{to_sealed_log, from_sealed_log};
use monotonic_counter::{increment_signatures_mc, increment_accesses_mc};

#[no_mangle]
pub extern "C" fn sign_message(
    sealed_log: *mut u8, 
    sealed_log_size: u32,
    hash_msg: *mut u8,
    signature_ptr: &mut [u8;65]
) -> sgx_status_t { // FIXME: Can this return a result instead of just the status? If so that would be excellent!
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
    let keys: KeyPair = *unsealed_data.get_decrypt_txt();
    
    
    let sgxt = match get_sgx_time() {
        Ok(x) => x,
        Err(e) => {
            println!("[-] Sgx Time Error: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    match sgxt.duration_since(&keys.sgx_time) {
        Ok(t) => {
            println!("[+] Keyfile last accessed {} seconds ago!", t);
        },
        Err(e) => {
            println!("[-] Sgx Time Error: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let keyfile_time_updated: KeyPair = KeyPair{sgx_time: sgxt, secret: keys.secret, public: keys.public, accesses_mc: keys.accesses_mc, signatures_mc: keys.signatures_mc}; // FIXME: Inefficient but functional...!


    let kp = match increment_accesses_mc(keyfile_time_updated) {
        Ok(kp)   => {
            println!("[+] Number of keyfile accesses: {}", kp.accesses_mc.value);
            kp
        },
        Err(e) => {
            println!("[-] Error incrementing key file accesses: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED; // FIXME: Propagate errors properly!
        }
    };

    let hash = unsafe {slice::from_raw_parts(hash_msg, HASH_LENGTH)};
    let mut x = [0u8;HASH_LENGTH];
    x.copy_from_slice(&hash[..]);// TODO: convert from slice to arr - make func elsewhere!
    let signed_msg = sign_message_hash(x, &kp);//.unwrap(); // FIXME: Handle error better!
    *signature_ptr = signed_msg; // FIXME: use a type?

    let kp2 = match increment_signatures_mc(kp) {
        Ok(kp2)   => {
            println!("[+] Number of signatures signed by key: {}", kp2.signatures_mc.value);
            kp2
        },
        Err(e) => {
            println!("[-] Error incrementing key file accesses: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED; // FIXME: Propagate errors properly!
        }
    };


    let aad: [u8; 0] = [0_u8; 0]; // Empty additional data...
    let sealed_data = match SgxSealedData::<KeyPair>::seal_data(&aad, &kp2) { // Seals the data
        Ok(x) => x, 
        Err(ret) => {return ret;}, 
    };
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size); // Writes the data
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };


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
