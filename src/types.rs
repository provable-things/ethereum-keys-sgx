use std::fmt;
use std::mem::size_of;
use constants::SECRET_KEY_SIZE;
use sgx_types::sgx_sealed_data_t;
use secp256k1::key::{PublicKey, SecretKey};

#[allow(dead_code)]

pub struct KeyPair {
    public: PublicKey,
    secret: SecretKey
}
pub type MessageSignature = [u8;65];
pub type EncryptedKeyPair = Vec<u8>;
pub static ENCRYPTED_KEYPAIR_SIZE: usize = size_of::<sgx_sealed_data_t>() + size_of::<KeyPair>();