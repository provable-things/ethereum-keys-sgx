use get_public_key;
use error::AppError;
use serde_json::Value;
use std::{result, i64};
use ethereum_types::Address;
use reqwest::{Client, Response};
use send_transaction::parse_response_as_json; // FIXME: Factor this json stuff out!
use utils::{get_infura_url, public_to_address, trim_hex_prefix, trimmed_hex_to_i64};

type Result<T> = result::Result<T, AppError>;

#[derive(Serialize, Deserialize, Debug)]
pub struct InfuraResponse {
    id: u64,
    result: String,
    jsonrpc: String
}

pub fn run<'a>(path: &String, network_id: u8) -> Result<i64> {
    get_address_from_keyfile(path)
        .and_then(|addr| make_api_call(addr, network_id))
        .and_then(parse_response_as_json)
        .map(get_result_from_json)
        .and_then(convert_nonce_to_i64)
}

fn get_address_from_keyfile(path: &String) -> Result<Address> {
    get_public_key::run(&path.to_string())
        .and_then(public_to_address)
}

fn make_api_call(addr: Address, network_id: u8) -> Result<Response> {
    Ok(Client::new()
        .post(get_infura_url(network_id).as_str())
        .json(&get_infura_json(addr))
        .send()?)
}

fn get_infura_json(addr: Address) -> Value {
    json!({
        "id":1,
        "params": [
            addr,
            "latest"
        ],
        "jsonrpc":"2.0",
        "method":"eth_getTransactionCount",
    })
}

fn convert_nonce_to_i64(hex_nonce: String) -> Result<i64> {
    trim_hex_prefix(hex_nonce)
        .and_then(trimmed_hex_to_i64)
}

pub fn get_result_from_json(res: InfuraResponse) -> String {
    res.result
}
