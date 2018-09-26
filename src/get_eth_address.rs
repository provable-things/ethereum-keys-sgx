use std::result;
use get_public_key;
use error::AppError;
use keccak::Keccak256;
use self::key::PublicKey;
use secp256k1::{Secp256k1, key};

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String) -> Result<Vec<u8>> {
    get_public_key::run(&path.to_string())
        .map(serialize)
        .map(hash)
        .map(truncate)
}

fn serialize(public: PublicKey) -> Vec<u8> {
    public.serialize_vec(&Secp256k1::new(), false).to_vec()//[1..65]
}

fn hash(serialized_key: Vec<u8>) -> [u8;32] {
    serialized_key[1..65].keccak256()
}

fn truncate(hashed_key: [u8;32]) -> Vec<u8> {
    hashed_key[12..].to_vec()
}