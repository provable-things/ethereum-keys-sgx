use std::fs;
use std::result;
use error::AppError;
use types::EncryptedKeyPair;
use constants::DEFAULT_KEYPAIR_PATH;

type Result<T> = result::Result<T, AppError>;

pub fn keyfile_exists() -> bool {
    Path::new(DEFAULT_KEYPAIR_PATH).exists()
}

pub fn read_file_as_vec(path: &String) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

pub fn write_keyfile(path: &str, data: &EncryptedKeyPair) -> Result<()> {
    Ok(fs::write(path, data)?)
}