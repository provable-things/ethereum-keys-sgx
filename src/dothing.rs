use std::fs;
use std::path;
use sgx_types::*;
use std::mem::size_of;
use tiny_keccak::Keccak;
use sgx_urts::SgxEnclave;
use std::io::{Read, Write};
use init_enclave::init_enclave;
use secp256k1::key::{PublicKey, SecretKey};
use enclave_api::{generate_keypair, sign_message};
use utils::{KeyPair, read_file_as_vec, write_file, hash_message};

pub fn dothing() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] [App] Enclave Initialised. ID: {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] [App] Enclave Init Failed: {}!", x.as_str());
            return;
        },
    };
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut pub_key = PublicKey::new();
    let sgx_struct_size = size_of::<sgx_sealed_data_t>();
    let alloc_size = size_of::<KeyPair>();
    let mut sealed_log_size: usize = alloc_size + sgx_struct_size;
    let mut seal_alloc = vec![0u8; sealed_log_size];
    let ptr: *mut u8 = &mut seal_alloc[0];
    let result = unsafe {
        generate_keypair(enclave.geteid(), &mut retval, &mut pub_key, ptr, sealed_log_size as *const u32)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] [App] Key pair successfully generated inside enclave");
            println!("[+] [App] Keypair successfully sealed outside of enclave");
            println!("[+] [App] Retrievd from enclave: {:?}", pub_key);
        },
        _ => {
            println!("[-] [App] ECALL to enclave failed {}!", result.as_str());
            return;
        }
    };
    let path = String::from("./encrypted_keypair.txt");
    write_file(&path, &seal_alloc);
    println!("[+] [App] Encrypted key pair successfully written to disk!");
    let mut contents = read_file_as_vec(&path);
    println!("[+] [App] File successfully read from disk!");
    let ptr2: *mut u8 = &mut contents[0]; 
    let msg = "Hello Oraclize!";
    println!("[+] [App] Message to sign: {}", msg);
    let mut msg_hash = hash_message(msg);
    println!("[+] [App] Hashed message {:?}", msg_hash);
    let hash_ptr: *mut u8 = &mut msg_hash[0]; 
    let result2 = unsafe {
        sign_message(enclave.geteid(), &mut retval, ptr2, sealed_log_size as *const u32, hash_ptr)
    };
    match result2 {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] [App] Sign message function call was successful! It returned: {}", result2.as_str());
        },
        _ => {
            println!("[-] [App] ECALL to enclave failed! {}", result2.as_str());
            return;
        }
    };
    enclave.destroy();
}