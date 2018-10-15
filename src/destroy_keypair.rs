use std::result;
use sgx_types::*;
use error::AppError;
use fs::{delete_keyfile, read_encrypted_keyfile};
use sgx_urts::SgxEnclave;
use enclave_api::destroy_key;
use init_enclave::init_enclave;
use types::{EncryptedKeyPair, ENCRYPTED_KEYPAIR_SIZE};

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String) -> Result<()> {
    init_enclave()
        .and_then(|enc| destroy_key_mcs(enc, &path))
        .and_then(rm_keypair)
}

fn rm_keypair(path: &String) -> Result<()> {
    Ok(delete_keyfile(&path)?) 
}

fn destroy_key_mcs<'a>(enc: SgxEnclave, path: &'a String) -> Result<&'a String> { // use better lifetime!
    let mut kp: EncryptedKeyPair = read_encrypted_keyfile(&path)?;
    let ret_val = unsafe {
        destroy_key(enc.geteid(), &mut sgx_status_t::SGX_SUCCESS, &mut kp[0] as *mut u8, ENCRYPTED_KEYPAIR_SIZE as *const u32)
    };
    enc.destroy();
    match ret_val {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] Keypair successfully destroyed!");
            Ok(&path)
        },
        _ => {
            println!("[-] ECALL to enclave failed: {}", ret_val.as_str());
            Err(AppError::SGXError(ret_val))
        }
    }
}
/*
fn get_encrypted_keypair(enc: SgxEnclave) -> Result<EncryptedKeyPair> {
    let mut encrypted_keys: EncryptedKeyPair = vec![0u8; ENCRYPTED_KEYPAIR_SIZE];
    let ptr: *mut u8 = &mut encrypted_keys[0];
    let result = unsafe {
        generate_keypair(enc.geteid(), &mut sgx_status_t::SGX_SUCCESS, ptr, ENCRYPTED_KEYPAIR_SIZE as *const u32)
    };
    enc.destroy();
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] Key pair successfully generated inside enclave!");
            Ok(encrypted_keys)
        },
        _ => {
            println!("[-] ECALL to enclave failed {}!", result.as_str());
            Err(AppError::SGXError(result))
        }
    }
}

fn get_key_from_enc(mut keypair: EncryptedKeyPair, enc: SgxEnclave, path: &String) -> Result<PublicKey> {
    let mut pub_key = PublicKey::new();
    let result = unsafe {
        get_public_key(enc.geteid(), &mut sgx_status_t::SGX_SUCCESS, &mut pub_key, &mut keypair[0] as *mut u8, ENCRYPTED_KEYPAIR_SIZE as *const u32)
    };
    enc.destroy();
    
    
    // SO at the this point the keypair passed in have been overwritten by the new updated mc
    // version! So can write it here if I want?
    write_keyfile(&path, &keypair)?; // FIXME, function this out! 
    // FIXME: Second access errors :/ Should test see if 2nd access also gets secret because if so,
    // it's an MC error, if not, it's a overwrite-the-keyfile error. 
    // Also should implement the destroy functionality to not use up the mcs!! Do that first!

    match result {
        sgx_status_t::SGX_SUCCESS => Ok(pub_key),
        _ => Err(AppError::SGXError(result))
    }
}
*/
