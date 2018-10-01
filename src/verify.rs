use std::result;
use error::AppError;
use rustc_hex::FromHex;
use self::key::PublicKey;
use ethereum_types::Address;
use get_eth_address::{public_to_address};
use keccak::{hash_slice, hash_with_prefix};
use secp256k1::{key, Secp256k1, Message as SecpMessage, RecoverableSignature, RecoveryId};

type Result<T> = result::Result<T, AppError>;

// FIXME: This whole file is ugly!
pub fn run(address: &Address, message: String, signature: String, no_prefix: bool) -> Result<bool> {
    Ok(&public_to_address(recover_public_key(
        if no_prefix { hash_slice(&message) } else { hash_with_prefix(&message) }, //match?
        signature)?
    )? == address) 
}

fn recover_public_key(hashed_message: [u8;32], signature: String) -> Result<PublicKey> {
    let bytes: Vec<u8> = signature.from_hex()?;
    let rsig = RecoverableSignature::from_compact(&Secp256k1::new(), &bytes[0..64], RecoveryId::from_i32(bytes[64] as i32)?)?;
	Ok(Secp256k1::new().recover(&SecpMessage::from_slice(&hashed_message[..])?, &rsig)?)
}
