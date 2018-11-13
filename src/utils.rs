use std::result;
use hex::decode;
use error::AppError;
use std::path::Path;
use keccak::Keccak256;
use fs::write_keyfile;
use self::key::PublicKey;
use ethereum_types::Address;
use types::EncryptedKeyStruct;
use secp256k1::{Secp256k1, key};
use std::io::{stdin, stdout, Write};
use constants::{HEX_PREFIX, URL_PREFIX, URL_SUFFIX};

type Result<T> = result::Result<T, AppError>;

pub fn get_network_name(network_id: u8) -> String {
     match network_id {
        3  => "ropsten",
        4  => "rinkeby",
        42 => "kovan",
        _  => "mainnet"
    }.to_string()
}

pub fn save_keypair(data: EncryptedKeyStruct, path: &String) -> Result<()> {
    Ok(write_keyfile(&path, &data)?)
}

pub fn get_infura_url(network_id: u8) -> String {
   format!("{prefix}{network}{suffix}", prefix=URL_PREFIX, network=get_network_name(network_id), suffix=URL_SUFFIX)
}

pub fn keyfile_exists(path: &String) -> bool {
    Path::new(path).exists()
}

pub fn get_affirmation(warn_msg: String) -> bool {
    let mut s = String::new();
    print!("[!] WARNING! {} Proceed? y/n", warn_msg);
    let _ = stdout().flush();
    stdin().read_line(&mut s).expect("[-] You did not enter a correct string");
    if s.trim() == "y" || s.trim() == "yes" || s.trim() == "Y" || s.trim() == "YES" || s.trim() == "Yes" { true } else { false }
}

pub fn public_to_address(public: PublicKey) -> Result<Address> {
    serialize(public)
        .map(hash)
        .map(convert_to_address_type)
}

pub fn trim_hex_prefix(hex_string: String) -> Result<String> {
    Ok(hex_string.trim_left_matches(HEX_PREFIX).to_string())
}

pub fn trimmed_hex_to_i64(hex_no_prefix: String) -> Result<i64> {
    Ok(i64::from_str_radix(hex_no_prefix.as_str(), 16)?)
}

pub fn decode_string_from_hex(thing: String) -> Result<Vec<u8>> {
    Ok(decode(&thing)?)
}

pub fn is_valid_length(thing: String, length: usize) -> Result<String> {
    match thing.len() == length {
        true => Ok(thing),
        false => Err(AppError::Custom("Supplied string is invalid length!".to_string()))
    }
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
