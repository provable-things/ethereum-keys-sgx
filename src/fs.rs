use std::fs;
use std::result;
use error::AppError;
use types::EncryptedKeyPair;

type Result<T> = result::Result<T, AppError>;

pub fn write_keyfile(path: &str, data: &EncryptedKeyPair) -> Result<()> {
    Ok(fs::write(path, data)?)
}

pub fn read_file_as_vec(path: &String) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}