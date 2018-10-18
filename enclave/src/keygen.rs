use std::result;
use std::vec::Vec;
use error::EnclaveError;
use secp256k1::Secp256k1;
use std::string::ToString;
use sgx_time::get_sgx_time;
use sgx_rand::{Rng, thread_rng};
use sgx_tservice::sgxtime::SgxTime;
use sgx_types::marker::ContiguousMemory;
use secp256k1::key::{SecretKey, PublicKey};
use monotonic_counter::{MonotonicCounter, create_mc};

type Result<T> = result::Result<T, EnclaveError>;

#[derive(Copy, Clone)]
pub struct KeyPair { // FIXME: Rename this to reflect what it is better! And instead of public everything, add some impls for reads!
    pub sgx_time: SgxTime,   
    pub public: PublicKey,
    pub(crate) secret: SecretKey,
    pub accesses_mc: MonotonicCounter,
    pub signatures_mc: MonotonicCounter
}

unsafe impl ContiguousMemory for KeyPair{}

impl KeyPair {
    pub fn new() -> Result<KeyPair> {
        let s   = generate_random_priv_key()?;
        let p   = get_public_key_from_secret(s); // FIXME: Are errors handled here?
        let t   = get_sgx_time()?;
        let mc1 = create_mc()?;
        let mc2 = create_mc()?;
        Ok(KeyPair{sgx_time: t, secret: s, public: p, accesses_mc: mc1, signatures_mc: mc2})
    }
}

pub fn create_keypair() -> Result<KeyPair> {
    Ok(KeyPair::new()?)
}

pub fn verify_keypair(kp: KeyPair) -> Result<KeyPair> {
    match kp.public == get_public_key_from_secret(kp.secret) {
        true => Ok(kp),
        false => Err(EnclaveError::Custom("[-] Public key not derivable from secret in unencrypted keyfile!".to_string()))
    }
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
