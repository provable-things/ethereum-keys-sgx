extern crate serde;
extern crate docopt;
#[macro_use]
extern crate serde_derive;
extern crate secp256k1_enclave_rust;

use docopt::Docopt;
use std::io::{stdin, stdout, Write};
use secp256k1_enclave_rust::{generate_keypair, get_public_key, get_private_key, sign_message};

pub static DEFAULT_KEYPAIR_PATH: &'static str = "./encrypted_keypair.txt";

static USAGE: &'static str = "
Intel SGX Ethereum Key Management CLI.
    Copyright 2018 Oraclize.it

Usage:  ethkeysgx generate
        ethkeysgx show public [--keyfile=<path>]
        ethkeysgx show secret [--keyfile=<path>]
        ethkeysgx sign <message> [--keyfile=<path>]
        ethkeysgx [-h | --help]

Options:
    -h, --help          Show this usage message & quits.
    --keyfile=<path>    Path to desired encrypted keyfile. [default: ./encrypted_keypair.txt]

Commands:
    generate            Generates an secp256k1 keypair inside an SGX enclave,
                        encrypts them & saves to disk to ./encrypted_keypair.txt
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

fn main() {
    Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .map(execute)
        .unwrap_or_else(|e| e.exit());
}

fn execute(args: Args) -> () {
    match args {
        Args {cmd_generate: true, ..} => generate(),
        Args {cmd_sign: true, ..} => sign(),
        Args {cmd_show: true, ..} => {
            match args {
                Args {cmd_public: true, ..} => show_pub(),
                Args {cmd_secret: true, ..} => show_priv(),
                _ => println!("{}", USAGE)
            }
        },
        _ => println!("{}", USAGE)
    };
}

fn generate() -> () {// TODO: Check key exists!
    match generate_keypair::run() {
        Ok(_)  => println!("[+] Keypair successfully generated & saved to {}", DEFAULT_KEYPAIR_PATH),
        Err(e) => println!("[-] Error generating keypair: {:?}", e)
    };
}

fn sign() -> () { // TODO: Check key exists! Pass in Message too!
    match sign_message::run() {//args.get_str("<message>")) {
        Ok(k)  => println!("[+] Message signature: {:?}", &k[..]),
        Err(e) => println!("[-] Error signing message: {:?}", e)
    }
}

fn show_pub() -> () { // TODO: Take path as param TODO: Show as eth addr.
    match get_public_key::run() {
        Ok(k)  => println!("[+] {:?}", k),
        Err(e) => println!("[-] Error retreiving plaintext public key: {:?}", e)
    }
}
fn show_priv() -> () { //TODO: Take path as param
    let mut s = String::new();
    print!("[!] WARNING - you are about to log your private key to the console! Proceed? y/n\n");
    let _=stdout().flush();
    stdin().read_line(&mut s).expect("[-] You did not enter a correct string");
    if s.trim() == "y" || s.trim() == "yes" {
        match get_private_key::run() {
            Ok(_)  => (),
            Err(e) => println!("[-] Error retreiving plaintext private key: {:?}", e)
        }
    } else {
        println!("[-] Affirmation not given, exiting.")
    }
}
