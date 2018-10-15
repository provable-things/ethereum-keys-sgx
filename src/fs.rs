use std::fs;
use std::result;
use std::path::Path;
use error::AppError;
use types::EncryptedKeyPair;

type Result<T> = result::Result<T, AppError>;

pub fn keyfile_exists(path: &String) -> bool {
    Path::new(path).exists()
}

pub fn delete_keyfile(path: &String) -> Result<()> {
    Ok(fs::remove_file(path)?) 
}

pub fn write_keyfile(path: &str, data: &EncryptedKeyPair) -> Result<()> {
    Ok(fs::write(path, data)?)
}

pub fn read_encrypted_keyfile(path: &String) -> Result<EncryptedKeyPair> {
    Ok(fs::read(path)?)
}

