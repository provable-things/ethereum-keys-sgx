extern crate serde;
extern crate docopt;
#[macro_use]
extern crate serde_derive;
extern crate secp256k1_enclave_rust;

use docopt::Docopt;
use std::path::Path;
use std::io::{stdin, stdout, Write};
use secp256k1_enclave_rust::{generate_keypair, get_eth_address, get_public_key, show_private_key, sign_message};

pub static DEFAULT_KEYPAIR_PATH: &'static str = "./encrypted_keypair.txt";

static USAGE: &'static str = "
Intel SGX Ethereum Key Management CLI.
    Copyright: 2018 Oraclize.it
    Questions: greg@oraclize.it

Usage:  ethkeysgx generate                                  [--keyfile=<path>]
        ethkeysgx show public                               [--keyfile=<path>]
        ethkeysgx show secret                               [--keyfile=<path>]
        ethkeysgx show address                              [--keyfile=<path>]
        ethkeysgx sign <message>                            [--keyfile=<path>]
        ethkeysgx verify <address> <message> <signature>    [--keyfile=<path>]
        ethkeysgx [-h | --help]

Options:
    -h, --help          ❍ Show this usage message & quits.
    --keyfile=<path>    ❍ Path to desired encrypted keyfile. [default: ./encrypted_keypair]


Commands:
    generate            ❍ Generates an secp256k1 keypair inside an SGX enclave, encrypts
                        them & saves to disk as either ./encrypted_keypair.txt in the
                        current directory, or at the passed in path.
    show public         ❍ Log the public key from the given encrypted keypair to the console.
    show secret         ❍ Log the private key from the given encrypted keypair to the console.
    sign                ❍ Signs a passed in message using key pair provided, otherwise 
                        uses default keypair if it exists.
    verify              ❍ Verify a given address signed a given message with a given signature. 
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_sign: bool,
    cmd_show: bool,
    cmd_public: bool,
    cmd_secret: bool,
    cmd_verify: bool,
    cmd_address: bool,
    cmd_generate: bool,
    arg_message: String,
    arg_address: String,
    flag_keyfile: String,
    arg_signature: String
}
/*
 * TODO: Factor this out a bit since it's getting a bit unweildy.
 * TODO: How to tie a sealed thingy to a specific enclave?!
 * TODO: Add a flag for a non-prefixed sig type?
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
        Args {cmd_sign: true, ..}     => sign(args.flag_keyfile, args.arg_message),
        Args {cmd_verify: true, ..}   => verify(args.arg_address, args.arg_message, args.arg_signature),
        Args {cmd_show: true, ..}     => {
            match args {
                Args {cmd_public: true, ..}  => show_pub(args.flag_keyfile),
                Args {cmd_secret: true, ..}  => show_priv(args.flag_keyfile),
                Args {cmd_address: true, ..} => show_addr(args.flag_keyfile),
                _ => println!("{}", USAGE)
            }
        },
        _ => println!("{}", USAGE)
    };
}

fn generate(path: String) -> () { // TODO: Factor out some of this repeated logic.
    if keyfile_exists(&path) {
        let mut s = String::new();
        print!("[!] WARNING! Something already exists at {} and will be overwritten.\n[!] WARNING! This cannot be undone. Overwrite? y/n\n", &path);
        let _ = stdout().flush();
        stdin().read_line(&mut s).expect("[-] You did not enter a correct string");
        if s.trim() == "y" || s.trim() == "yes" {
            create_keypair(&path)
        } else {
            return println!("[-] Affirmation not received, exiting.");
        }
    } else {
        create_keypair(&path)
    }
}

fn show_priv(path: String) -> () {
    let mut s = String::new();
    print!("[!] WARNING! You are about to log your private key to the console! Proceed? y/n\n");
    let _ = stdout().flush();
    stdin().read_line(&mut s).expect("[-] You did not enter a correct string");
    if s.trim() == "y" || s.trim() == "yes" {
        match show_private_key::run(&path) {
            Ok(_)  => (),
            Err(e) => println!("[-] Error retreiving plaintext private key from {}:\n\t{:?}", &path, e)
        }
    } else {
        println!("[-] Affirmation not received, exiting.")
    }
}

fn create_keypair(path: &String) -> (){
    match generate_keypair::run(&path) {
        Ok(_)  => println!("[+] Keypair successfully generated & saved to {}", path),
        Err(e) => println!("[-] Error generating keypair:\n\t{:?}", e)
    };
}

fn sign(path: String, message: String) -> () { // TODO: Show pub key signed with! TODO: Take argv flag re prefix!
    match sign_message::run(&path, message) {
        Ok(k)  => {println!("[+] Message signature: ");print_hex(k.to_vec())},
        Err(e) => println!("[-] Error signing message with key from {}:\n\t{:?}", &path, e)
    }
}

fn show_pub(path: String) -> () {
    match get_public_key::run(&path) {
        Ok(k)  => println!("[+] {:?}", k),
        Err(e) => println!("[-] Error retreiving plaintext public key from {}:\n\t{:?}", &path, e)
    }
}

fn show_addr(path: String) -> () { // TODO: Use eth types?
    match get_eth_address::run(&path) {
        Ok(k)  => {print!("[+] Ethereum Address: ");print_hex(k)},
        Err(e) => println!("[-] Error retreiving Ethereum Address from: {}:\n\t{:?}", &path, e)
    }
}

fn verify(path: String, message: String, address: String) -> () {
    println!("false"); // FIXME: Implement!
}

fn keyfile_exists(path: &String) -> bool {
    Path::new(path).exists()
}

fn print_hex(vec: Vec<u8>) -> () { // TODO: impl on a type or something
    print!("0x");
    for ch in vec {
        print!("{:02x}", ch); // TODO: Handle errors - MAKE LESS CRAP!
    }
    println!("");
}