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
use sgx_types::*;
use sgx_tseal::SgxSealedData;
use sgx_types::marker::ContiguousMemory;
use secp256k1::key::{SecretKey, PublicKey};

// #[derive(Copy, Clone, Debug)]
// struct Secret {
//     key: u8,
//     secret: SecretKey
// }

// unsafe impl ContiguousMemory for Secret {}
/*
 *
 * TODO: Seal key struct & re-access after! (Or just priv-key? Do we need to have a struct at all?)
 * TODO: Switch to using the crypto crates' sha3 instead of tiny_keccak!! - Done but oops they aren't the same. Dammit.
 * TODO: Make VANITY keygen & threading work!
 * TODO:Can have app call generate, rec. priv key, then call gen again if not vanity. 
 * Then have method callable via ocall (add to edl!)
 * 
 **/
#[no_mangle]
pub extern "C" fn generate_keypair(
    pub_key_ptr: &mut PublicKey, 
    // sealed_log: *mut u8, 
    // log_size: *const u32
) -> sgx_status_t {

    let keypair = match keygen::KeyPair::new() {
        Ok(kp) => *pub_key_ptr = kp.public,
        Err(_) => {return sgx_status_t::SGX_ERROR_UNEXPECTED;}
    };

    // let keypair = match keygen::KeyPair::new() {
    //     Ok(kp) => {
    //         *pub_key_ptr = kp.public;
    //         kp
    //     },
    //     Err(_) => {return sgx_status_t::SGX_ERROR_UNEXPECTED;}
    // };

    // let secret_struct = Secret{key: 1, secret: keypair.secret}; // Kinda messy really
    // let aad: [u8; 0] = [0_u8; 0];
    // let result = SgxSealedData::<Secret>::seal_data(&aad, &secret_struct);
    // let sealed_data = match result {
    //     Ok(x) => x,
    //     Err(ret) => { return ret; }, 
    // };

    // let opt = to_sealed_log(&sealed_data, sealed_log, log_size);
    // if opt.is_none() {
    //     return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    // }


    sgx_status_t::SGX_SUCCESS
}

// So same story, we pass in a ptr to correct sized allocd. mem then write to it.
fn to_sealed_log<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
// fn from_sealed_log<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, T>> {
//     unsafe {
//         SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
//     }
// }
//MRENCLAVE signed = only THAT enc can unseal.
//MRSIGNER signed = other encs. by author can unseal.