use std::path::Path;
use std::io::{stdin, stdout, Write};
use std::result;
use error::AppError;
use keccak::Keccak256;
use self::key::PublicKey;
use ethereum_types::Address;
use secp256k1::{Secp256k1, key};

type Result<T> = result::Result<T, AppError>;

pub fn keyfile_exists(path: &String) -> bool {
    Path::new(path).exists()
}

pub fn get_affirmation(warn_msg: String) -> bool {
    let mut s = String::new();
    print!("[!] WARNING! {} Proceed? y/n\n", warn_msg);
    let _ = stdout().flush();
    stdin().read_line(&mut s).expect("[-] You did not enter a correct string");
    if s.trim() == "y" || s.trim() == "yes" || s.trim() == "Y" || s.trim() == "YES" || s.trim() == "Yes" { true } else { false }
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
