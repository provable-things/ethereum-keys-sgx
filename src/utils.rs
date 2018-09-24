use std::{fs, path};
use tiny_keccak::Keccak;
use secp256k1::key::{PublicKey, SecretKey};

//TODO: Sort this stuff into correct places once it compiles

pub struct KeyPair {
    public: PublicKey,
    secret: SecretKey
}

pub fn hash_message(msg: &str) -> [u8;32] { // ISSUE: Need to make work with vectors/any size msg
    msg.as_bytes().keccak256()
}

pub fn write_file(path: &String, data: &Vec<u8>) {
    fs::write(path, data).expect("Unable to write file!")
}

pub fn read_file_as_vec(path: &String) -> Vec<u8> {
    fs::read(path).expect("Unable to read file")
}

pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
}

impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(&mut result);
        result
    }
}