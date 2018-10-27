use std::result;
use get_public_key;
use hex::decode;
use error::AppError;
use serde_json::Value;
use utils::public_to_address;
use reqwest::{Client, header};
use self::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

pub static NONCE_URL: &'static str = "https://mainnet.infura.io/"; // FIXME: Need to make network a variable!

type Result<T> = result::Result<T, AppError>;

#[derive(Serialize, Deserialize, Debug)]
pub struct Res {
    id: u64,
    result: String,
    jsonrpc: String
}
/*
TODO: Pass in an arbritary address if needs be?
TODO: Use state monad and build up the state with address, client, params etc?
*/
use std::i64;
pub fn run<'a>(path: &String) -> Result<i64> {
    // if address ? get nonce : open keyfile get nonce ... 
    let addr = get_public_key::run(&path.to_string()).and_then(public_to_address)?;
    let mut y = Client::new().post(NONCE_URL).headers(get_headers()).json(&get_json()).send()?; // can use build instead of send to build the req and send it later.
    let json: Res = y.json()?;
    let raw = json.result; // FIXME: Make this whole piece more functional!
    let without_prefix = raw.trim_left_matches("0x");
    let z = i64::from_str_radix(without_prefix, 16)?;
    Ok(z)
}

fn get_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers
}

fn get_json() -> Value {
    json!({"jsonrpc":"2.0","method":"eth_getTransactionCount","params": ["0xc94770007dda54cF92009BFF0dE90c06F603a09f","latest"],"id":1})
}
/*
enum {
 // get from EIP155
}

fn get_url() -> Url {
    // make url here!
}
*/
