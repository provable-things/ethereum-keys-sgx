use std::fs;
use std::io::Error;
// use error::Error as AppError;

pub fn write_file(path: &String, data: &Vec<u8>) -> Result<(), Error> {
    fs::write(path, data)
}

pub fn read_file_as_vec(path: &String) -> Result<Vec<u8>, Error> {
    fs::read(path)
}