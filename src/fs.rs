use std::fs;
use std::result;
use error::AppError;

type Result<T> = result::Result<T, AppError>;

pub fn write_file(path: &str, data: &Vec<u8>) -> Result<()> {
    Ok(fs::write(path, data)?)
}

pub fn read_file_as_vec(path: &String) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}