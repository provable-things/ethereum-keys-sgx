use std::result;
use types::Hash;
use rlp::RlpStream;
use error::AppError;
use types::Signature;
use ethereum_types::*;
use keccak::Keccak256;
use fs::read_encrypted_keyfile;
use init_enclave::init_enclave;
use sign_message::sign_hashed_message as sign_transaction;

type Result<T> = result::Result<T, AppError>;

#[derive(Default,Debug,Clone,PartialEq,Eq)] // FIXME: Sort to which are necessary!
pub struct Transaction {
    pub to: Address,
    pub nonce: U256,
    pub value: U256,
    pub data: Vec<u8>,
    pub gas_limit: U256,
    pub gas_price: U256,
}

pub fn run(path: String, chain_id: u64, tx: Transaction) -> Result<Signature> {
    encode_signing_data(chain_id, tx)
        .map(hash_signing_data)
        .and_then(|(hash, _encoded_data)| get_signature(path, hash, _encoded_data))
        .and_then(|(sig, _encoded_data)| Ok(sig)) // FIXME: HERE is where we will append the sig to the data!
}

fn get_signature(path: String, hash: Hash, data: RlpStream) -> Result<(Signature, RlpStream)> {
    read_encrypted_keyfile(&path)
        .and_then(|keyfile| sign_transaction(keyfile, hash, init_enclave()?, &path))
        .and_then(|sig| Ok((sig, data)))
}

fn encode_signing_data(chain_id: u64, tx: Transaction) -> Result<RlpStream> {
    let mut stream = RlpStream::new();
    stream.append(&tx.nonce);
    stream.append(&tx.gas_price);
    stream.append(&tx.gas_limit);
    stream.append(&tx.value); // Something I saw has the value & to switched. TODO: Investigate!
    stream.append(&tx.to);
    stream.append(&tx.data);
    stream.append(&chain_id);
    stream.append(&0u8);
    stream.append(&0u8);
    Ok(stream)
}

fn hash_signing_data(data: RlpStream) -> (Hash, RlpStream) {
    (data.as_raw().keccak256(), data)
}
