use std::path::Path;
use std::io::{stdin, stdout, Write};

pub fn keyfile_exists(path: &String) -> bool {
    Path::new(path).exists()
}

pub fn print_hex(vec: Vec<u8>) -> () { // TODO: impl on a type or something
    print!("0x");
    for ch in vec {
        print!("{:02x}", ch); // TODO: Handle errors - MAKE LESS CRAP!
    }
    println!("");
}

pub fn get_affirmation(warn_msg: String) -> bool {
    let mut s = String::new();
    print!("[!] WARNING! {} Proceed? y/n\n", warn_msg);
    let _ = stdout().flush();
    stdin().read_line(&mut s).expect("[-] You did not enter a correct string");
    if s.trim() == "y" || s.trim() == "yes" || s.trim() == "Y" || s.trim() == "YES" || s.trim() == "Yes" { true } else { false }
}