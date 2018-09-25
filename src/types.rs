use std::mem::size_of;
use sgx_types::sgx_sealed_data_t;
use secp256k1::key::{PublicKey, SecretKey};

#[allow(dead_code)]

pub struct KeyPair {
    public: PublicKey,
    secret: SecretKey
}

pub type EncryptedKeyPair = Vec<u8>;
pub static ENCRYPTED_KEYPAIR_SIZE: usize = size_of::<sgx_sealed_data_t>() + size_of::<KeyPair>();