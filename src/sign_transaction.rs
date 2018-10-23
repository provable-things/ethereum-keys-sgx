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
    encode_tx(chain_id, tx)
        .and_then(|encoded_tx| sign_transaction( // FIXME: Make neater!
            read_encrypted_keyfile(&path)?, 
            encoded_tx, 
            init_enclave()?,
            &path
        )) 
}

fn encode_tx(chain_id: u64, tx: Transaction) -> Result<Hash> {
    let mut stream = RlpStream::new();
    stream.append(&tx.nonce);
    stream.append(&tx.gas_price);
    stream.append(&tx.gas_limit);
    stream.append(&tx.value);
    stream.append(&tx.to);
    stream.append(&tx.data);
    stream.append(&chain_id);
    stream.append(&0u8);
    stream.append(&0u8);
    Ok(stream.as_raw().keccak256())
}
