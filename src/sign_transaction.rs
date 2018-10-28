use get_nonce;
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

pub struct Transaction {
    v: u64, 
    r: U256,
    s: U256,
    to: Address,
    nonce: U256,
    value: U256,
    chain_id: u8, 
    data: Vec<u8>,
    gas_limit: U256,
    gas_price: U256,
}

impl Transaction {
    pub fn new(chain_id: u8, data: Vec<u8>, nonce: U256, value: U256, gas_limit: U256, gas_price: U256, to: Address) -> Transaction {
        Transaction {
            to: to,
            data: data,
            nonce: nonce,
            value: value,
            r: U256::zero(),
            s: U256::zero(),
            v: chain_id.into(), // Per EIP155 
            chain_id: chain_id, 
            gas_limit: gas_limit,
            gas_price: gas_price 
        }
    }

    fn add_v_r_s_to_tx(mut self, sig: Signature) -> Self {
        self.r = sig[0..32].into();
        self.s = sig[32..64].into();
        self.v = calculate_v(&sig[64], &self.chain_id);
        self
    }

    fn update_nonce(mut self, nonce: i64) -> Self {
        self.nonce = U256::from(nonce);
        self
    }
}

pub fn run(path: String, query_nonce: bool, tx: Transaction) -> Result<RlpStream> {
    match query_nonce {
        false => encode_tx(path, tx),
        true  => get_nonce::run(&path, tx.chain_id) // FIXME: Double logs the enclave init - should fix? Maybe pull the actual funcs we need?
            .map(|n| tx.update_nonce(n))
            .and_then(|tx| encode_tx(path, tx))
    }
}

fn encode_tx(path: String, tx: Transaction) -> Result<RlpStream> {
    encode_tx_data(&tx)
        .map(hash_encoded_data)
        .and_then(|hash| get_signature(path, hash))
        .map(|sig| tx.add_v_r_s_to_tx(sig))
        .and_then(|tx| encode_tx_data(&tx))
}

fn get_signature(path: String, hash: Hash) -> Result<Signature> {
    read_encrypted_keyfile(&path)
        .and_then(|keyfile| Ok(sign_transaction(keyfile, hash, init_enclave()?, &path)?)) 
}

fn calculate_v(sig_v: &u8, chain_id: &u8) -> u64 {
    ((chain_id * 2) + (*sig_v + 35)).into() // Per EIP155
}

fn encode_tx_data(tx: &Transaction) -> Result<RlpStream> {
    let mut stream = RlpStream::new();
    stream.begin_list(9);
    stream.append(&tx.nonce);
    stream.append(&tx.gas_price);
    stream.append(&tx.gas_limit);
    stream.append(&tx.to);
    stream.append(&tx.value);
    stream.append(&tx.data);
    stream.append(&tx.v);
    stream.append(&tx.r); 
    stream.append(&tx.s); 
    Ok(stream)
}

fn hash_encoded_data(data: RlpStream) -> Hash {
    data.as_raw().keccak256()
}
