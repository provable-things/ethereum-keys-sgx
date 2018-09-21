// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

extern crate dirs;
extern crate sgx_urts;
extern crate secp256k1;
extern crate sgx_types;
extern crate tiny_keccak;

use std::fs;
use std::path;
use sgx_types::*;
use std::mem::size_of;
use tiny_keccak::Keccak;
use sgx_urts::SgxEnclave;
use std::io::{Read, Write};
use secp256k1::key::{PublicKey, SecretKey};

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
static ENCLAVE_TOKEN: &'static str = "enclave.token";

extern {
    fn generate_keypair(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t, 
        pub_key: *mut PublicKey, 
        sealed_log: *mut u8,
        sealed_log_size: *const u32
    ) -> sgx_status_t;

    fn sign_message(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t, 
        sealed_log: *mut u8,
        sealed_log_size: *const u32,
        hashed_message: *mut u8
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {

    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // Step 1: try to retrieve the launch token saved by last transaction
    //         if there is no token, then create a new one.
    //
    // try to get the token saved in $HOME */
    let mut home_dir = path::PathBuf::new();
    let use_token = match dirs::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            home_dir = path;
            true
        },
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };

    let token_file: path::PathBuf = home_dir.join(ENCLAVE_TOKEN);;
    if use_token == true {
        match fs::File::open(&token_file) {
            Err(_) => {
                println!("[-] Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                println!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(1024) => {
                        println!("[+] Token file valid!");
                    },
                    _ => println!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let enclave = try!(SgxEnclave::create(ENCLAVE_FILE,
                                          debug,
                                          &mut launch_token,
                                          &mut launch_token_updated,
                                          &mut misc_attr));

    // Step 3: save the launch token if it is updated
    if use_token == true && launch_token_updated != 0 {
        // reopen the file with write capablity
        match fs::File::create(&token_file) {
            Ok(mut f) => {
                match f.write_all(&launch_token) {
                    Ok(()) => println!("[+] Saved updated launch token!"),
                    Err(_) => println!("[-] Failed to save updated launch token!"),
                }
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            },
        }
    }

    Ok(enclave)
}
/*
 *
 * TODO: Factor out to a lib crate eventually!
 * TODO: Have the first call the enc. do an ::new, which spits out the PublicKey
 * and a sealed privkey.
 * TODO: Make it a CLI with an -init option and a -sign option. Have the second used 
 * to hash & sign the supplied message usig the sealed priv key.
 * 
 **/
fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] [App] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] [App] Init Enclave Failed {}!", x.as_str());
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

pub struct KeyPair {
    public: PublicKey,
    secret: SecretKey
}

fn hash_message(msg: &str) -> [u8;32] { // ISSUE: Need to make work with vectors!!
    msg.as_bytes().keccak256()
}

fn write_file(path: &String, data: &Vec<u8>) {
    fs::write(path, data).expect("Unable to write file!")
}

fn read_file_as_vec(path: &String) -> Vec<u8> {
    fs::read(path).expect("Unable to read file")
}

pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
}

impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(&mut result);
        result
    }
}


