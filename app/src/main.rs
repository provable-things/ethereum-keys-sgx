extern crate docopt;
extern crate secp256k1_enclave_rust;

use docopt::Docopt;
use std::io::{stdin, stdout, Write};
use secp256k1_enclave_rust::{generate_keypair, get_public_key, sign_message};
/*
 *
 * TODO: Have a way we can use a specific key if passed as an arg, and it'll attempt to find a file called that and decrpy it.
 * TODO: Have a way we can pass in a message and have it sign it. Hash the message outside as it currently does.
 * 
 **/

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

fn main() {
    Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .map(execute);
}

fn execute(args: docopt::ArgvMap) {
    if args.get_bool("generate") { // TODO: Check exists!
        match generate_keypair::run() {
            Ok(_)  => println!("Yay!"),
            Err(e) => println!("Error generating key set: {:?}", e)
        };
    } else if args.get_bool("sign") {
        println!("Asked to sign this message: {}", args.get_str("<message>"));
    } else if args.get_bool("show") && args.get_bool("public") {
        println!("Asked to show public key");  
    } else if args.get_bool("show") && args.get_bool("secret") {
        let mut s = String::new();
        print!("[!] Caution - you are about to log your private key to the console. Proceed? y/n\n");
        let _=stdout().flush();
        stdin().read_line(&mut s).expect("You did not enter a correct string");
        if s.trim() == "y" || s.trim() == "yes" {
            println!("User asked to show private key");  
        } else {
            println!("[-] Incorrect input received, exiting. Goodbye!")
        }
    }else {
        println!("{}", USAGE)
    }

    // match get_public_key::run() {
    //     Ok(k)  => println!("{:?}",k),
    //     Err(e) => println!("Error getting public key: {:?}", e)
    // }
    // match sign_message::run() {
    //     Ok(k)  => println!("Message signature: {:?}", &k[..]),
    //     Err(e) => println!("Error signing message: {:?}", e)
    // }
}