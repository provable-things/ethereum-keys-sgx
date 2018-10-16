use std::result;
use std::vec::Vec;
use sgx_types::*;
use error::EnclaveError;
use secp256k1::Secp256k1;
use sgx_tseal::SgxSealedData;
use sgx_rand::{Rng, thread_rng};
use sgx_types::marker::ContiguousMemory;
use secp256k1::key::{SecretKey, PublicKey};
use sealer::{to_sealed_log, from_sealed_log};
use monotonic_counter::{MonotonicCounter, destroy_mc, create_mc, increment_accesses_mc, increment_signatures_mc};

type Result<T> = result::Result<T, EnclaveError>;

// FIXME: This file is getting a bit unweildly. Factor stuff out & make better!

#[derive(Copy, Clone)]
pub struct KeyPair { // FIXME: Rename this to reflect what it is better! And instead of public everything, add some impls for reads!
    pub public: PublicKey,
    pub(crate) secret: SecretKey,
    pub accesses_mc: MonotonicCounter,
    pub signatures_mc: MonotonicCounter
}

unsafe impl ContiguousMemory for KeyPair{}

#[no_mangle]
pub extern "C" fn generate_keypair(
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> sgx_status_t {
    let keypair = match KeyPair::new() {
        Ok(kp) => kp,
        Err(e) => {
            println!("[-] Error creating new key pair: {}", e); //Err(e) => {return e;} // FIXME: Propagate SGX errors to app properly! Or will this do?
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    let aad: [u8; 0] = [0_u8; 0]; // Empty additional data...
    let sealed_data = match SgxSealedData::<KeyPair>::seal_data(&aad, &keypair) { // Seals the data
        Ok(x) => x,
        Err(ret) => {return ret;}, 
    };
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size); // Writes the data
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn destroy_key(
    sealed_log: * mut u8, 
    sealed_log_size: u32
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
    let kp: KeyPair = *unsealed_data.get_decrypt_txt();


    // Delete the mcs
    match destroy_mc(kp.accesses_mc) { // Inefficient - sort out!
        Ok(_)   => {
            println!("[+] Accesses monontonic counter successfully destroyed!");
        },
        Err(e) => {
            println!("[-] Error destroying accesses monotonic counter: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }
    match destroy_mc(kp.signatures_mc) { // Inefficient - sort out!
        Ok(_)   => {
            println!("[+] Signatures monontonic counter successfully destroyed!");
        },
        Err(e) => {
            println!("[-] Error destroying signatures monotonic counter: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }

    // Seal and overwrite outside enc.
    let aad: [u8; 0] = [0_u8; 0]; // Empty additional data...
    let sealed_data = match SgxSealedData::<KeyPair>::seal_data(&aad, &kp) { // Seals the data
        Ok(x) => x, 
        Err(ret) => {return ret;}, 
    };
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size); // Writes the data
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn get_public_key(
    pub_key_ptr: &mut PublicKey, 
    sealed_log: * mut u8, 
    sealed_log_size: u32
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
    let keys: KeyPair = *unsealed_data.get_decrypt_txt();
    let kp = match increment_accesses_mc(keys) {
        Ok(kp)   => {
            println!("[+] Keyfile accesses successfully incremented!\n[+] Number of key file accesses: {}", kp.accesses_mc.value);
            kp
        },
        Err(e) => {
            println!("Shouldn't be here! {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED; // FIXME: Propagate errors properly!
        }
    };
    if verify_pair(kp) {
        *pub_key_ptr = kp.public; // write the key to front end
    } else {
        println!("[-] Public key not derivable from secret in unencrypted key file!"); // FIXME: Handle errors better in the enc.
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    let aad: [u8; 0] = [0_u8; 0]; // Empty additional data...
    let sealed_data = match SgxSealedData::<KeyPair>::seal_data(&aad, &kp) { // Seals the data
        Ok(x) => x, 
        Err(ret) => {return ret;}, 
    };
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size); // Writes the data
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn show_private_key(
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> sgx_status_t {
    let opt = from_sealed_log::<KeyPair>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;},
    };
    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {println!("[-] Error unsealing data: {}", ret);return ret;} 
    };
    let keys: KeyPair = *unsealed_data.get_decrypt_txt();
    if verify_pair(keys) {
        println!("[+] {:?}", keys.secret);
        sgx_status_t::SGX_SUCCESS
    } else {
        println!("[-] Public key not derivable from secret in unencrypted key file!"); // FIXME: Handle errors better in the enc.
        sgx_status_t::SGX_ERROR_UNEXPECTED
    }
}

impl KeyPair {
    pub fn new() -> Result<KeyPair> {
        let s   = generate_random_priv_key()?;
        let p   = get_public_key_from_secret(s);
        let mc1 = create_mc()?;
        let mc2 = create_mc()?;
        Ok(KeyPair{secret: s, public: p, accesses_mc: mc1, signatures_mc: mc2})
    }
}

pub fn verify_pair(keys: KeyPair) -> bool { // NOTE: Can't impl. since decryption loses methods on structs obvs.
    keys.public == get_public_key_from_secret(keys.secret)
}

fn generate_random_priv_key() -> Result<SecretKey> {
    Ok(SecretKey::from_slice(&Secp256k1::new(), &get_32_random_bytes_arr())?)
}

fn get_32_random_bytes_arr() -> [u8;32] {
    let mut arr = [0; 32];
    arr.copy_from_slice(&get_x_random_bytes_vec(32));
    arr
}

fn get_public_key_from_secret(secret_key: SecretKey) -> PublicKey {
    PublicKey::from_secret_key(&Secp256k1::new(), &secret_key)
}

fn get_x_random_bytes_vec(len: usize) -> Vec<u8> { // FIXME: Ugly func, imperative, make better!
    let mut x = vec![0u8; len]; 
    thread_rng().fill_bytes(&mut x);
    x
}
