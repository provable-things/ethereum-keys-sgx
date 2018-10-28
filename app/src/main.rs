extern crate serde;
extern crate docopt;
extern crate itertools;
extern crate ethereum_types;
extern crate ethkey_sgx_app;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;
use itertools::Itertools;
use self::utils::get_network_name;
use ethereum_types::{Address, U256, H160};

use self::utils::{keyfile_exists, get_affirmation};
use ethkey_sgx_app::{
    transaction::Transaction,
    show_private_key,
    sign_transaction,
    generate_keypair, 
    destroy_keypair,
    get_eth_address, 
    get_public_key, 
    sign_message, 
    get_nonce,
    verify,
    utils
};

pub static DEFAULT_KEYPAIR_PATH: &'static str = "./encrypted_keypair.txt";

static USAGE: &'static str = "
Intel SGX Ethereum Key Management CLI.
    Copyright: 2018 Oraclize.it
    Questions: greg@oraclize.it

Usage:  ethkey_sgx                                              [-h | --help]
        ethkey_sgx generate                                     [--keyfile=<path>]
        ethkey_sgx show public                                  [--keyfile=<path>]
        ethkey_sgx show secret                                  [--keyfile=<path>]
        ethkey_sgx show address                                 [--keyfile=<path>] 
        ethkey_sgx sign msg <message>                           [--keyfile=<path>] [-n | --noprefix]
        ethkey_sgx show nonce                                   [--keyfile=<path>] [--chainid=<uint>] 
        ethkey_sgx verify <address> <message> <signature>       [--keyfile=<path>] [-n | --noprefix]
        ethkey_sgx destroy                                      [--keyfile=<path>]
        ethkey_sgx sign tx     [--to=<address>] [--value=<Wei>] [--keyfile=<path>] [--gaslimit=<uint>] [--gasprice=<Wei>] [--nonce=<uint>] [--data=<string>] [--chainid=<uint>]

Commands:
    generate            ❍ Generates an secp256k1 keypair inside an SGX enclave, encrypts
                        them & saves to disk as either ./encrypted_keypair.txt in the
                        current directory, or at the passed in path.
    show secret         ❍ Log the private key from the given encrypted keypair to the console.
    show nonce          ❍ Retrieves the current nonce of the keypair in a given keyfile, for
                        the network specified via the chain ID parameter:
                            1  = Ethereum Main-Net (default)
                            3  = Ropsten Test-Net
                            4  = Rinkeby Test-Net
                            42 = Kovan Test-Net
    sign tx             ❍ Signs a transaction with the given parameters and returns the raw 
                        data ready for broadcasting to the ethereum network. If no nonce is
                        supplied, the tool will attempt to discover the nonce of the given
                        keypair for the network the transaction is destined for. See below
                        for the parameter defaults.
    sign msg            ❍ Signs a passed in message using key pair provided, otherwise uses
                        default keypair if it exists. Defaults to using the ethereum message
                        prefix and ∴ signatures are ECRecoverable.
   verify               ❍ Verify a given address signed a given message with a given signature. 
   destroy              ❍ Destroys a given key file's monotonic counters, rendering the keyfile
                        unusable, before erasing the encrypted keyfile itself. Use with caution!

Options:
    -h, --help          ❍ Show this usage message.

    --keyfile=<path>    ❍ Path to desired encrypted keyfile [default: ./encrypted_keypair]

    --to=<address>      ❍ Destination address of transaction [default: ]

    --value=<Wei>       ❍ Amount of ether to send with transaction in Wei [default: 0]

    --gaslimit=<uint>   ❍ Amount of gas to send with transaction [default: 210000]

    --gasprice=<Wei>    ❍ Gas price for transaction in Wei [default: 20000000000]

    --chainid=<uint>    ❍ ID of desired chain for transaction [default: 1]

    --nonce=<uint>      ❍ Nonce of transaction in Wei [default:  -1]

    --data=<string>     ❍ Additional data to send with transaction [default:  ]

    --value=<Wei>       ❍ Amount of ether to send with transaction in Wei [default: 0]

    -n, --noprefix      ❍ Does not add the ethereum message prefix when signing or verifying 
                        a signed message. Messages signed with no prefix are NOT ECRecoverable!
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_tx: bool,
    cmd_msg: bool,
    cmd_sign: bool,
    cmd_show: bool,
    cmd_nonce: bool,
    flag_value: u64,
    flag_nonce: i64,
    flag_to: String,
    cmd_public: bool,
    cmd_secret: bool,
    cmd_verify: bool,
    flag_chainid: u8,
    cmd_address: bool,
    cmd_destroy: bool,
    flag_data: String,
    cmd_generate: bool,
    flag_gasprice: u64,
    flag_gaslimit: u64,
    flag_noprefix: bool,
    arg_message: String,
    arg_address: String,
    flag_keyfile: String,
    arg_signature: String
}
/*
 * NOTE: Initial version of MC will be MRSIGNER not MRENCLAVE.
 * TODO: Use SGX time to log the last time key file was accessed. (This & above need bigger key struc!)
 * TODO: Store address in hex in keyfile!
 * TODO: Add option to verify via the hash too?
 * TODO: Use MRENCLAVE to tie a sealed thingy to this specific enclave!
 * TODO: Have a method to view the values of the mcs (should still increment the accesses obvs!)
 * */
fn main() {
    Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .map(execute)
        .unwrap_or_else(|e| e.exit());
}

fn execute(args: Args) -> () {
    match args {
        Args {cmd_show: true, ..}     => match_show(args),
        Args {cmd_sign: true, ..}     => match_sign(args), 
        Args {cmd_destroy: true, ..}  => destroy(args.flag_keyfile),
        Args {cmd_generate: true, ..} => generate(args.flag_keyfile),    
        Args {cmd_verify: true, ..}   => verify(&args.arg_address.parse().expect("Invalid ethereum address!"), args.arg_message, args.arg_signature, args.flag_noprefix),  
        _ => println!("{}", USAGE)
    }
}

fn match_show(args: Args) -> () {
    match args {
        Args {cmd_public: true, ..}  => show_pub(args.flag_keyfile),
        Args {cmd_secret: true, ..}  => show_priv(args.flag_keyfile),
        Args {cmd_address: true, ..} => show_addr(args.flag_keyfile),
        Args {cmd_nonce: true, ..}   => show_nonce(args.flag_keyfile, args.flag_chainid),
        _ => println!("{}", USAGE)
    }
}

fn match_sign(args: Args) -> () {
    match args {
        Args {cmd_msg: true, ..} => sign_msg(args.flag_keyfile, args.arg_message, args.flag_noprefix),
        Args {cmd_tx: true, ..}  => sign_tx(args.flag_keyfile, args.flag_nonce == -1, Transaction::new(
            args.flag_chainid,
            args.flag_data.into(),
            if args.flag_nonce != -1 {U256::from(args.flag_nonce)} else {U256::from(0)},
            U256::from(args.flag_value), 
            U256::from(args.flag_gaslimit), 
            U256::from(args.flag_gasprice),
            if args.flag_to.len() == 0 {H160::zero()} else {args.flag_to.parse().expect("Invalid ethereum address!")},
        )),
        _ => println!("{}", USAGE)
    }
}

fn generate(path: String) -> () {
    match keyfile_exists(&path) {
        false => create_keypair(&path),
        true  => {
            println!("[!] WARNING! Something already exists at {} and will be overwritten!", &path); 
            match get_affirmation("This cannot be undone!".to_string()) {
                false => println!("[-] Affirmation not received, exiting."),
                true  => create_keypair(&path)
            }
        }
    }
}

fn destroy(path: String) -> () {
    match keyfile_exists(&path) {
        false => println!("[-] Cannot destroy key, no keyfile found at {}", &path),
        true  => {
            println!("[!] WARNING! Key file at {} will be destroyed!", &path); 
            match get_affirmation("This cannot be undone!".to_string()) {
                false => println!("[-] Affirmation not received, exiting."),
                true  => match destroy_keypair::run(&path) {
                    Ok(_)  => (),
                    Err(e) => println!("[-] Error destroying key pair: {}", e)
                }
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
        Ok(_)  => println!("[+] Key pair successfully saved to {}!", path),
        Err(e) => println!("[-] Error generating keypair:\n\t{:?}", e)
    };
}

fn sign_tx(path: String, query_nonce: bool, tx: Transaction) -> () {
    match sign_transaction::run(path, query_nonce, tx) { // do something with the query nonce in "run"
        Ok(sig) => println!("[+] Raw transaction signature: 0x{:02x}", sig.as_raw().iter().format("")), 
        Err(e)  => println!("[-] Error signing transaction:\n\t{:?}", e)
    }
}

fn sign_msg(path: String, message: String, no_prefix: bool) -> () {
    match sign_message::run(&path, message, no_prefix) {
        Err(e) => println!("[-] Error signing message with key from {}:\n\t{:?}", &path, e),
        Ok(k)  => {
            match no_prefix { 
                true  => println!("[+] Message signature (no prefix): 0x{:02x}", k.iter().format("")),
                false => println!("[+] Message signature (with prefix): 0x{:02x}", k.iter().format(""))
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
        Ok(a)  => println!("[+] Ethereum Address: {:#x}", a),
        Err(e) => println!("[-] Error retreiving Ethereum Address from: {}:\n\t{:?}", &path, e)
    }
}

fn show_nonce(path: String, network_id: u8) -> () {
    match get_nonce::run(&path, network_id) {
        Ok(n)  => println!("[+] Encrypted keyfile's last confirmed nonce on {network} is {nonce}", nonce = n, network = get_network_name(network_id)),
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
