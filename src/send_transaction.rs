use std::result;
use rlp::RlpStream;
use error::AppError;
use serde_json::Value;
use itertools::Itertools;
use utils::{get_infura_url};
use transaction::Transaction;
use reqwest::{Client, Response};
use sign_transaction::run as sign_transaction;
use get_nonce::{InfuraResponse, get_result_from_json};

type Result<T> = result::Result<T, AppError>;

pub fn run(path: String, query_nonce: bool, network_id: u8, tx: Transaction) -> Result<String> { 
    sign_transaction(path, query_nonce, tx)
        .and_then(|signed_tx| send_transaction(signed_tx, network_id)) 
        .and_then(parse_response_as_json)
        .map(get_result_from_json)
}

fn send_transaction(signed_tx: RlpStream, network_id: u8) -> Result<Response> {
    Ok(Client::new()
        .post(get_infura_url(network_id).as_str())
        .json(&get_infura_json(signed_tx))
        .send()?)
}

pub fn parse_response_as_json(mut res: Response) -> Result<InfuraResponse> {
    Ok(res.json()?) // FIXME: Need to handle the errors better, we swallow the acutal response here. Below doesn't work!
}

fn get_infura_json(signed_tx: RlpStream) -> Value {
    json!({
        "id": 1,
        "jsonrpc":"2.0",
        "method":"eth_sendRawTransaction",
        "params":[
            format!("0x{:02x}", signed_tx.as_raw().iter().format("")) 
        ],
    })
}
