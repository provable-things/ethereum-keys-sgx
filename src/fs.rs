use std::fs;
use std::result;
use std::path::Path;
use error::AppError;
use types::EncryptedKeyPair;
use constants::DEFAULT_KEYPAIR_PATH;

type Result<T> = result::Result<T, AppError>;

pub fn default_keyfile_exists() -> bool {
    keyfile_exists(DEFAULT_KEYPAIR_PATH)
}

pub fn keyfile_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn read_default_encrypted_keyfile() -> Result<EncryptedKeyPair> {
    Ok(fs::read(DEFAULT_KEYPAIR_PATH)?)
}

pub fn read_encrypted_keyfile(path: &String) -> Result<EncryptedKeyPair> {
    Ok(fs::read(path)?) // Make this error if given path doesn't exist?
}

pub fn write_keyfile(path: &str, data: &EncryptedKeyPair) -> Result<()> {
    Ok(fs::write(path, data)?)
}