use types::Signature;
use ethereum_types::{Address, U256};

pub struct Transaction {
    pub v: u64, 
    pub r: U256,
    pub s: U256,
    pub to: Address,
    pub nonce: U256,
    pub value: U256,
    pub chain_id: u8, 
    pub data: Vec<u8>,
    pub gas_limit: U256,
    pub gas_price: U256,
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

    pub fn add_v_r_s_to_tx(mut self, sig: Signature) -> Self {
        self.r = sig[0..32].into();
        self.s = sig[32..64].into();
        self.v = calculate_v(&sig[64], &self.chain_id);
        self
    }

    pub fn update_nonce(mut self, nonce: i64) -> Self {
        self.nonce = U256::from(nonce);
        self
    }
}

fn calculate_v(sig_v: &u8, chain_id: &u8) -> u64 {
    ((chain_id * 2) + (*sig_v + 35)).into() // Per EIP155
}
