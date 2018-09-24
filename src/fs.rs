use std::fs;

pub fn write_file(path: &String, data: &Vec<u8>) {
    fs::write(path, data).expect("Unable to write file!")  // FIXME: Return a result to handle
}

pub fn read_file_as_vec(path: &String) -> Vec<u8> {
    fs::read(path).expect("Unable to read file") // FIXME: Return a result to handle
}