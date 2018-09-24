use secp256k1::key::{PublicKey, SecretKey};

#[allow(dead_code)] // We only use the struct to measure it's size for enc. copying.
pub struct KeyPair {
    public: PublicKey,
    secret: SecretKey
}