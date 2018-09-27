use std::result;
use error::AppError;
use keccak::hash_slice;
use rustc_hex::FromHex;
use self::key::PublicKey;
use get_eth_address::public_to_address;
use secp256k1::{key, Secp256k1, Message as SecpMessage, RecoverableSignature, RecoveryId};

type Result<T> = result::Result<T, AppError>;

pub fn run(address: String, message: String, signature: String) -> Result<Vec<u8>> { // TODO: Make a type!
    let public = recover_public_key(message, signature)?;
    println!("Pub key: {:?}", &public);
    Ok(public_to_address(public)?)
}

pub fn recover_public_key(message: String, signature: String) -> Result<PublicKey> {
    let bytes: Vec<u8> = signature.from_hex()?;
    println!("rec id {}", &bytes[64]);
    let rsig = RecoverableSignature::from_compact(&Secp256k1::new(), &bytes[0..64], RecoveryId::from_i32(bytes[64] as i32)?)?;
	Ok(Secp256k1::new().recover(&SecpMessage::from_slice(&hash_slice(&message)[..])?, &rsig)?)
}