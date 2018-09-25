use sgx_types::*;
use utils::KeyPair;
use std::mem::size_of;
use error as AppError;
use keccak::hash_message;
use secp256k1::key::PublicKey;
use init_enclave::init_enclave;
use fs::{read_file_as_vec, write_file};
use enclave_api::{generate_keypair, sign_message};

static DEFAULT_KEYPAIR_PATH: &'static str = "./encrypted_keypair.txt";

// TODO: pull out the multiple repeatedlogic with the returns
// TODO: Separate error handling fully
// TODO: See if this file can be separated like a lib crate too to factor out functions etc.
// Copy signature out from enc. to front end.

pub fn run() {
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
    // get_keypair(enclave.geteid())
    //     .and_then(save_keypair);
    let mut return_value = sgx_status_t::SGX_SUCCESS;
    let mut pub_key = PublicKey::new();
    let sgx_struct_size = size_of::<sgx_sealed_data_t>();
    let alloc_size = size_of::<KeyPair>();
    let sealed_log_size: usize = alloc_size + sgx_struct_size;
    let mut seal_alloc = vec![0u8; sealed_log_size];
    let ptr: *mut u8 = &mut seal_alloc[0];
    let result = unsafe {
        generate_keypair(enclave.geteid(), &mut return_value, &mut pub_key, ptr, sealed_log_size as *const u32)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] [App] Key pair successfully generated inside enclave");
            println!("[+] [App] Keypair successfully sealed outside of enclave");
            println!("[+] [App] Retrieved from enclave: {:?}", pub_key);
        },
        _ => {
            println!("[-] [App] ECALL to enclave failed {}!", result.as_str());
            return;
        }
    };
    let path = String::from("./encrypted_keypair.txt");
    write_file(&path, &seal_alloc);
    println!("[+] [App] Encrypted key pair successfully written to disk!");
    let mut contents = read_file_as_vec(&path).expect("should work"); // FIXME: error handling!
    println!("[+] [App] File successfully read from disk!");
    let ptr2: *mut u8 = &mut contents[0]; //erros now since it returns a result!
    let msg = "Hello Oraclize!";
    println!("[+] [App] Message to sign: {}", msg);
    let mut msg_hash = hash_message(msg);
    println!("[+] [App] Hashed message {:?}", msg_hash);
    let hash_ptr: *mut u8 = &mut msg_hash[0]; 
    let result2 = unsafe {
        sign_message(enclave.geteid(), &mut return_value, ptr2, sealed_log_size as *const u32, hash_ptr)
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

// // TODO: Check already exists
// // Type of enc_id ???
// pub fn get_keypair(enc_id: u32) -> Result<KeyPair, AppError> {
//     let mut return_value = sgx_status_t::SGX_SUCCESS;
//     let pub_key = PublicKey::new(); // TODO: Pass this into this function so the main can show the pub key? Have this func return res<keypair, err>
//     let sgx_struct_size = size_of::<sgx_sealed_data_t>();
//     let alloc_size = size_of::<KeyPair>();
//     let sealed_log_size: usize = alloc_size + sgx_struct_size;
//     let mut seal_alloc = vec![0u8; sealed_log_size];
//     let ptr: *mut u8 = &mut seal_alloc[0];
//     let result = unsafe {
//         generate_keypair(enc_id, &mut return_value, &mut pub_key, ptr, sealed_log_size as *const u32)
//     }
//     match result {
//         sgx_status_t::SGX_SUCCESS => {
//             println!("[+] [App] Key pair successfully generated inside enclave");
//             println!("[+] [App] Keypair successfully sealed outside of enclave");
//             println!("[+] [App] Retrieved from enclave: {:?}", pub_key);
//         },
//         _ => {
//             println!("[-] [App] ECALL to enclave failed {}!", result.as_str());
//             return;
//         }
//     }
//     seal_alloc
// }

// pub fn save_keypair(data: Vec<u8>) -> Result<(), AppError> {
//     write_file(DEFAULT_KEYPAIR_PATH, &data)
// }

// // pub fn init_enclave() -> SgxResult<SgxEnclave> {
// //     let enclave = match init_enclave() {
// //         Ok(r) => {
// //             println!("[+] [App] Enclave Initialised. ID: {}!", r.geteid());
// //             r
// //         },
// //         Err(x) => {
// //             println!("[-] [App] Enclave Init Failed: {}!", x.as_str());
// //             return;
// //         },
// //     };
// // }