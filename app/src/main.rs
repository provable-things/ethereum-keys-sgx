extern crate serde;
extern crate docopt;
#[macro_use]
extern crate serde_derive;
extern crate ethereum_types;
extern crate secp256k1_enclave_rust;

use docopt::Docopt;
use ethereum_types::Address;
use self::utils::{keyfile_exists, print_hex, get_affirmation};
use secp256k1_enclave_rust::{
    show_private_key, 
    generate_keypair, 
    get_public_key, 
    get_eth_address, 
    sign_message, 
    verify,
    utils
};

pub static DEFAULT_KEYPAIR_PATH: &'static str = "./encrypted_keypair.txt";

static USAGE: &'static str = "
Intel SGX Ethereum Key Management CLI.
    Copyright: 2018 Oraclize.it
    Questions: greg@oraclize.it

Usage:  ethkeysgx generate                                  [--keyfile=<path>]
        ethkeysgx show public                               [--keyfile=<path>]
        ethkeysgx show secret                               [--keyfile=<path>]
        ethkeysgx show address                              [--keyfile=<path>] 
        ethkeysgx sign <message>                            [--keyfile=<path>] [-n | --noprefix]
        ethkeysgx verify <address> <message> <signature>    [--keyfile=<path>] [-n | --noprefix]
        ethkeysgx [-h | --help]

Options:
    -h, --help          ❍ Show this usage message.
    --keyfile=<path>    ❍ Path to desired encrypted keyfile. [default: ./encrypted_keypair]
    -n, --noprefix      ❍ Does not add the ethereum message prefix when signing or verifying 
                        a signed message. Messages signed with no prefix are NOT ECRecoverable!

Commands:
    generate            ❍ Generates an secp256k1 keypair inside an SGX enclave, encrypts
                        them & saves to disk as either ./encrypted_keypair.txt in the
                        current directory, or at the passed in path.
    show public         ❍ Log the public key from the given encrypted keypair to the console.
    show secret         ❍ Log the private key from the given encrypted keypair to the console.
    sign                ❍ Signs a passed in message using key pair provided, otherwise uses
                        default keypair if it exists. Defaults to using the ethereum message
                        prefix and ∴ signatures are ECRecoverable.
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
    flag_noprefix: bool,
    arg_message: String,
    arg_address: String,
    flag_keyfile: String,
    arg_signature: String
}
/*
 * NOTE: tseal internal.rs has good info in it.
 * TODO: Use a monotonic counter attached to a tx signer to count number of signed txs.
 * TODO: Store the uuid of the MCs in the keyfile struct as well.
 * NOTE: Initial version of MC will be MRSIGNER not MRENCLAVE.
 * TODO: Could use the first MC to just count how many unseal events there have been?
 * TODO: OR just the number of times the private key has been shown?
 * TODO: Use SGX time to log the last time key file was accessed. (This & above need bigger key struc!)
 * TODO: Store address in hex in keyfile!
 * TODO: Show full ethereum address!
 * TODO: Add option to verify via the hash too?
 * TODO: Use MRENCLAVE to tie a sealed thingy to this specific enclave!
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
        Args {cmd_sign: true, ..}     => sign(args.flag_keyfile, args.arg_message, args.flag_noprefix),
        Args {cmd_verify: true, ..}   => verify(&args.arg_address.parse().unwrap(), args.arg_message, args.arg_signature, args.flag_noprefix), // FIXME: Unwrap! Plus rm 0x?
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

fn generate(path: String) -> () {
    match keyfile_exists(&path) {
        false => create_keypair(&path),
        true  => {
            println!("[!] WARNING! Something already exists at {} and will be overwritten.\n", &path); 
            match get_affirmation("This cannot be undone!".to_string()) {
                false => println!("[-] Affirmation not received, exiting."),
                true  => create_keypair(&path)
            }
        }
    }
}

fn show_priv(path: String) -> () {
    match get_affirmation("You are about to log your private key to the console!".to_string()) {
        false => println!("[-] Affirmation not received, exiting."),
        true  => {
            match show_private_key::run(&path) {
                Ok(_)  => (),
                Err(e) => println!("[-] Error retreiving plaintext private key from {}:\n\t{:?}", &path, e)
            }
        }
    }
}

fn create_keypair(path: &String) -> (){
    match generate_keypair::run(&path) {
        Ok(_)  => println!("[+] Keypair successfully generated & saved to {}", path),
        Err(e) => println!("[-] Error generating keypair:\n\t{:?}", e)
    };
}

fn sign(path: String, message: String, no_prefix: bool) -> () {
    match sign_message::run(&path, message, no_prefix) {
        Err(e) => println!("[-] Error signing message with key from {}:\n\t{:?}", &path, e),
        Ok(k)  => {
            match no_prefix { // TODO: Print better
                true  => {println!("[+] Message signature (no prefix): ");print_hex(k.to_vec())},
                false => {println!("[+] Message signature (with prefix): ");print_hex(k.to_vec())}
            }
        }
    }
}

fn show_pub(path: String) -> () {
    match get_public_key::run(&path) {
        Ok(k)  => println!("[+] {:?}", k),
        Err(e) => println!("[-] Error retreiving plaintext public key from {}:\n\t{:?}", &path, e)
    }
}

fn show_addr(path: String) -> () {
    match get_eth_address::run(&path) {
        Ok(a)  => println!("[+] Ethereum Address: {}", a),
        Err(e) => println!("[-] Error retreiving Ethereum Address from: {}:\n\t{:?}", &path, e)
    }
}

fn verify(address: &Address, message: String, signature: String, no_prefix: bool) -> () {
    match verify::run(address, message, signature, no_prefix) {
        Err(e) => println!("[-] Error verifying signature: {}", e),
        Ok(b)  => {
            match b {
                true  => println!("[+] Signature verified! Message was signed with Ethereum Address: {}", address),
                false => println!("[!] Signature verification failed. Message was NOT signed with Ethereum Address: {}", address)
            }
        }
    }
}
