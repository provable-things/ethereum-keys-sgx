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
use sgx_rand::{Rng, StdRng};
use sgx_tseal::SgxSealedData;
use sgx_types::marker::ContiguousMemory;
use secp256k1::key::{SecretKey, PublicKey};
/*
 *
 * TODO: Seal key struct & re-access after! (Or just priv-key? Do we need to have a struct at all?)
 * TODO: Switch to using the crypto crates' sha3 instead of tiny_keccak!! - Done but oops they aren't the same. Dammit.
 * TODO: Make VANITY keygen & threading work!
 * TODO:Can have app call generate, rec. priv key, then call gen again if not vanity. 
 * Then have method callable via ocall (add to edl!)
 * Note: MRENCLAVE signed = only THAT enc can unseal.
 * Note: MRSIGNER signed = other encs. by author can unseal.
 * 
 **/
#[no_mangle]
pub extern "C" fn generate_keypair(
    pub_key_ptr: &mut PublicKey, 
) -> sgx_status_t {
    println!("Do we even see stuff from inside the enc?");
    let keypair = match keygen::KeyPair::new() {
        Ok(kp) => *pub_key_ptr = kp.public,
        Err(_) => {return sgx_status_t::SGX_ERROR_UNEXPECTED;}
    };
    sgx_status_t::SGX_SUCCESS
}

#[derive(Copy, Clone, Default, Debug)]
struct RandData {
    rand: [u8; 16],
}

unsafe impl ContiguousMemory for RandData {}

#[no_mangle]
pub extern "C" fn create_sealeddata(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    let mut data = RandData::default();
    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(&mut data.rand);
    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<RandData>::seal_data(&aad, &data);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => {return ret;}, 
    };
    let raw_size = sgx_tseal::SgxSealedData::<'_,RandData>::calc_raw_sealed_data_size(0, 16);
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };
    println!("Random data that's been encrypted: {:?}", data);
    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn verify_sealeddata(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    let opt = from_sealed_log::<RandData>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;},
    };
    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {return ret;}, 
    };
    let data = unsealed_data.get_decrypt_txt();
    println!("Data that's been unencrypted {:?}", data);
    sgx_status_t::SGX_SUCCESS
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