use std::result;
use get_public_key;
use error::AppError;
use ethereum_types::Address;
use utils::public_to_address;

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String) -> Result<Address> {
    get_public_key::run(&path.to_string())
        .and_then(public_to_address)
}
