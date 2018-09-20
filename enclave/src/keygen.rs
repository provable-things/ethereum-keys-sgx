use std::fmt;
use std::vec::Vec;
use secp256k1::Secp256k1;
use sgx_rand::{Rng, thread_rng};
use secp256k1::Error as SecpError;
use secp256k1::key::{SecretKey, PublicKey};

pub struct KeyPair {
    pub public: PublicKey,
    pub(crate) secret: SecretKey, // FIXME: Make private getter for it instead?
}

impl fmt::Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		writeln!(f, "Private key: [redacted - please use `unsafe_show_secret` to view]")?;
		write!(f, "{:?}", self.public)
	}
}

impl KeyPair {
    pub fn new() -> Result<KeyPair, SecpError> {
        let s = generate_random_priv_key()?;
        let p = get_public_key_from_secret(s);
        Ok(KeyPair{secret: s, public: p})
    }
}

fn generate_random_priv_key() -> Result<SecretKey, SecpError> {
    SecretKey::from_slice(&Secp256k1::new(), &get_32_random_bytes_arr())
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