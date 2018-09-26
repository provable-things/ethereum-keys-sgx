

// use std::result;
// use sgx_types::*;
// use error::AppError;
// use std::mem::size_of;
// use keccak::hash_message;
// use sgx_urts::SgxEnclave;
// use secp256k1::key::PublicKey;

// use fs::{read_file_as_vec, write_keyfile};
// use enclave_api::{generate_keypair, sign_message};
// use types::{KeyPair, EncryptedKeyPair, ENCRYPTED_KEYPAIR_SIZE};

// type Result<T> = result::Result<T, AppError>;

// static DEFAULT_KEYPAIR_PATH: &'static str = "./encrypted_keypair.txt";

// // TODO: pull out the multiple repeatedlogic with the returns
// // TODO: See if this file can be separated like a lib crate too to factor out functions etc.
// // Copy signature out from enc. to front end.

// pub fn run() {
//     // let enclave = match init_enclave() {
//     //     Ok(r) => {
//     //         println!("[+] [App] Enclave Initialised. ID: {}!", r.geteid());
//     //         r
//     //     },
//     //     Err(x) => {
//     //         println!("[-] [App] Enclave Init Failed: {}!", x.as_str());
//     //         return;
//     //     },
//     // };
//     match initialise_enclave()
//         .and_then(get_encrypted_keypair)
//         .and_then(save_keypair) {
//             Ok(_) => {
//                 println!("Success!");
//                 return;
//             },
//             Err(_) => {
//                 println!("Fail :(");
//                 return;
//             }
//         };
        
//     // get_keypair(enclave.geteid())
//     //     .and_then(save_keypair);
//     // let mut return_value = sgx_status_t::SGX_SUCCESS;
//     // let mut pub_key = PublicKey::new();
//     // let sgx_struct_size = size_of::<sgx_sealed_data_t>();
//     // let alloc_size = size_of::<KeyPair>();
//     // let sealed_log_size: usize = alloc_size + sgx_struct_size;
//     // let mut seal_alloc = vec![0u8; sealed_log_size];
//     // let ptr: *mut u8 = &mut seal_alloc[0];
//     // let result = unsafe {
//     //     generate_keypair(enclave.geteid(), &mut return_value, &mut pub_key, ptr, sealed_log_size as *const u32)
//     // };
//     // match result {
//     //     sgx_status_t::SGX_SUCCESS => {
//     //         println!("[+] [App] Key pair successfully generated inside enclave");
//     //         println!("[+] [App] Keypair successfully sealed outside of enclave");
//     //         println!("[+] [App] Retrieved from enclave: {:?}", pub_key);
//     //     },
//     //     _ => {
//     //         println!("[-] [App] ECALL to enclave failed {}!", result.as_str());
//     //         return;
//     //     }
//     // };


//     // let path = String::from("./encrypted_keypair.txt");
//     // write_file(&path, &seal_alloc);
//     // println!("[+] [App] Encrypted key pair successfully written to disk!");
//     // let mut contents = read_file_as_vec(&path).expect("should work"); // FIXME: error handling!
//     // println!("[+] [App] File successfully read from disk!");
//     // let ptr2: *mut u8 = &mut contents[0]; //erros now since it returns a result!
//     // let msg = "Hello Oraclize!";
//     // println!("[+] [App] Message to sign: {}", msg);
//     // let mut msg_hash = hash_message(msg);
//     // println!("[+] [App] Hashed message {:?}", msg_hash);
//     // let hash_ptr: *mut u8 = &mut msg_hash[0]; 
//     // let result2 = unsafe {
//     //     sign_message(enclave.geteid(), &mut return_value, ptr2, sealed_log_size as *const u32, hash_ptr)
//     // };
//     // match result2 {
//     //     sgx_status_t::SGX_SUCCESS => {
//     //         println!("[+] [App] Sign message function call was successful! It returned: {}", result2.as_str());
//     //     },
//     //     _ => {
//     //         println!("[-] [App] ECALL to enclave failed! {}", result2.as_str());
//     //         return;
//     //     }
//     // };
//     // enclave.destroy();
// }

// // TODO: Check already exists? Or will that happen before this is called?
// pub fn get_encrypted_keypair(enc: SgxEnclave) -> Result<EncryptedKeyPair> {
//     // let mut return_value = sgx_status_t::SGX_SUCCESS;
//     // let pub_key = PublicKey::new(); // TODO: Pass this into this function so the main can show the pub key? Have this func return res<keypair, err>
//     // let sgx_struct_size = size_of::<sgx_sealed_data_t>();
//     // let alloc_size = size_of::<KeyPair>();
//     // let sealed_log_size: usize = alloc_size + sgx_struct_size;
//     // let mut seal_alloc = vec![0u8; sealed_log_size];
//     let mut encrypted_keys: EncryptedKeyPair = vec![0u8; ENCRYPTED_KEYPAIR_SIZE];
//     let ptr: *mut u8 = &mut encrypted_keys[0];
//     let result = unsafe {
//         generate_keypair(enc.geteid(), &mut sgx_status_t::SGX_SUCCESS, ptr, ENCRYPTED_KEYPAIR_SIZE as *const u32)
//     };
//     enc.destroy();
//     match result {
//         sgx_status_t::SGX_SUCCESS => {
//             println!("[+] [App] Key pair successfully generated inside enclave");
//             Ok(encrypted_keys)
//         },
//         _ => {
//             println!("[-] [App] ECALL to enclave failed {}!", result.as_str());
//             Err(AppError::SGXError(result))
//         }
//     }
// }

// pub fn save_keypair(data: EncryptedKeyPair) -> Result<()> {
//     Ok(write_keyfile(DEFAULT_KEYPAIR_PATH, &data)?)
// }

// pub fn initialise_enclave() -> Result<SgxEnclave> {
//     // let enclave = match init_enclave() {
//     //     Ok(enclave) => {
//     //         println!("[+] [App] Enclave Initialised. ID: {}!", enclave.geteid());
//     //         Ok(enclave)
//     //     },
//     //     Err(x) => {
//     //         // println!("[-] [App] Enclave Init Failed: {}!", x.as_str());
//     //         Err(AppError::SGXError(x))
//     //     },
//     // };
//     Ok(init_enclave()?)
// }



// // pub fn get_pub_key(enc_id: u32w) -> Result<PublicKey> {
// //     let mut return_value = sgx_status_t::SGX_SUCCESS;
// //     let pub_key = PublicKey::new();
// //     let pub_key_size = size_of(pub_key);
// //     let result = unsafe {
// //         get_public_key(enc_id, &mut return_value, &mut pub_key, pub_key_size as *const u32) // TODO: Define this in EDL & enc.
// //     }
// //     match result {
// //         sgx_status_t::SGX_SUCCESS => {
// //             println!("[+] [App] Public key successfully retrieved!");
// //             Ok(pub_key)
// //         },
// //         _ => {
// //             println!("[-] [App] ECALL to enclave failed {}!", result.as_str());
// //             Err(AppError::SGXError(result))
// //         }
// //     }
// // }