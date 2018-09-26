extern crate serde;
extern crate docopt;
#[macro_use]
extern crate serde_derive;
extern crate secp256k1_enclave_rust;

use docopt::Docopt;
use std::path::Path;
use std::io::{stdin, stdout, Write};
use secp256k1_enclave_rust::{generate_keypair, get_public_key, show_private_key, sign_message};

pub static DEFAULT_KEYPAIR_PATH: &'static str = "./encrypted_keypair.txt";

static USAGE: &'static str = "
Intel SGX Ethereum Key Management CLI.
    Copyright 2018 Oraclize.it

Usage:  ethkeysgx generate       [--keyfile=<path>]
        ethkeysgx show public    [--keyfile=<path>]
        ethkeysgx show secret    [--keyfile=<path>]
        ethkeysgx sign <message> [--keyfile=<path>]
        ethkeysgx [-h | --help]

Options:
    -h, --help          Show this usage message & quits.
    --keyfile=<path>    Path to desired encrypted keyfile. [default: ./encrypted_keypair]

Commands:
    generate            Generates an secp256k1 keypair inside an SGX enclave,
                        encrypts them & saves to disk at either the given path or as
                        encrypted_keypair.txt in the current directory.
    show public         Log the public key from the encrypted keypair to the console.
    show secret         Log the private key from the encrypted keypair to the console.
    sign                Signs a passed in message using key pair provided, otherwise 
                        uses default keypair if it exists.
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_sign: bool,
    cmd_show: bool,
    cmd_public: bool,
    cmd_secret: bool,
    cmd_generate: bool,
    flag_keyfile: String
}
/*
 * TODO: Factor out this a bit since it's getting a bit unweildy.
 * */
fn main() {
    Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .map(execute)
        .unwrap_or_else(|e| e.exit());
}

fn execute(args: Args) -> () {
    match args {
        Args {cmd_generate: true, ..} => generate(args.flag_keyfile),    
        Args {cmd_sign: true, ..}     => sign(args.flag_keyfile),
        Args {cmd_show: true, ..}     => {
            match args {
                Args {cmd_public: true, ..} => show_pub(args.flag_keyfile),
                Args {cmd_secret: true, ..} => show_priv(args.flag_keyfile),
                _ => println!("{}", USAGE)
            }
        },
        _ => println!("{}", USAGE)
    };
}

fn generate(path: String) -> () {
    if keyfile_exists(&path) {
        let mut s = String::new();
        print!("[!] WARNING! Keyfile already exists at {} and will be overwritten. This cannot be undone. Overwrite? y/n\n", &path);
        let _ = stdout().flush();
        stdin().read_line(&mut s).expect("[-] You did not enter a correct string");
        if s.trim() == "y" || s.trim() == "yes" {
            match generate_keypair::run(&path) {
                Ok(_)  => println!("[+] Keypair successfully generated & saved to {}", path),
                Err(e) => println!("[-] Error generating keypair: {:?}", e)
            };
        } else {
            println!("[-] Affirmation not received, exiting.")
        }
    }
}

fn sign(path: String) -> () { // TODO: Pass in Message too!
    match sign_message::run(path) {
        Ok(k)  => println!("[+] Message signature: {:?}", &k[..]),
        Err(e) => println!("[-] Error signing message: {:?}", e)
    }
}

fn show_pub(path: String) -> () { // TODO: Show as eth addr.
    match get_public_key::run(path) {
        Ok(k)  => println!("[+] {:?}", k),
        Err(e) => println!("[-] Error retreiving plaintext public key: {:?}", e)
    }
}
fn show_priv(path: String) -> () {
    let mut s = String::new();
    print!("[!] WARNING! You are about to log your private key to the console! Proceed? y/n\n");
    let _ = stdout().flush();
    stdin().read_line(&mut s).expect("[-] You did not enter a correct string");
    if s.trim() == "y" || s.trim() == "yes" {
        match show_private_key::run(path) {
            Ok(_)  => (),
            Err(e) => println!("[-] Error retreiving plaintext private key: {:?}", e)
        }
    } else {
        println!("[-] Affirmation not received, exiting.")
    }
}

pub fn keyfile_exists(path: &String) -> bool {
    Path::new(path).exists()
}
