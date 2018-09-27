use std::result;
use get_public_key;
use error::AppError;
use keccak::Keccak256;
use self::key::PublicKey;
use ethereum_types::Address;
use secp256k1::{Secp256k1, key};

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String) -> Result<Address> {
    get_public_key::run(&path.to_string())
        .and_then(public_to_address)
}

pub fn public_to_address(public: PublicKey) -> Result<Address> {
    serialize(public)
        .map(hash)
        .map(convert_to_address_type)
}

fn serialize(public: PublicKey) -> Result<Vec<u8>> {
    Ok(public.serialize_vec(&Secp256k1::new(), false).to_vec())
}

fn hash(serialized_key: Vec<u8>) -> [u8;32] {
    serialized_key[1..65].keccak256()
}

fn convert_to_address_type(hashed_key: [u8;32]) -> Address { // TODO: Make more functional & less gross.
    let mut addr = Address::default();
    addr.copy_from_slice(&hashed_key[12..]);
    addr
}