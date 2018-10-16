use sgx_types::*;
use sgx_time::get_sgx_time;
use sgx_tseal::SgxSealedData;
use keygen::{KeyPair, verify_pair};
use sealer::{to_sealed_log, from_sealed_log};
use monotonic_counter::increment_accesses_mc;

#[no_mangle]
pub extern "C" fn show_private_key(
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> sgx_status_t {
    let opt = from_sealed_log::<KeyPair>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;},
    };
    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {println!("[-] Error unsealing data: {}", ret);return ret;} 
    };
    let keys: KeyPair = *unsealed_data.get_decrypt_txt();

    let sgxt = match get_sgx_time() {
        Ok(x) => x,
        Err(e) => {
            println!("[-] Sgx Time Error: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    match sgxt.duration_since(&keys.sgx_time) {
        Ok(t) => {
            println!("[+] Keyfile last accessed {} seconds ago!", t);
        },
        Err(e) => {
            println!("[-] Sgx Time Error: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let keyfile_time_updated: KeyPair = KeyPair{sgx_time: sgxt, secret: keys.secret, public: keys.public, accesses_mc: keys.accesses_mc, signatures_mc: keys.signatures_mc}; // FIXME: Inefficient but functional...!


    let kp = match increment_accesses_mc(keyfile_time_updated) {
        Ok(kp)   => {
            println!("[+] Number of keyfile accesses: {}", kp.accesses_mc.value);
            kp
        },
        Err(e) => {
            println!("[-] Error incrementing key file accesses: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED; // FIXME: Propagate errors properly!
        }
    };
    
    let aad: [u8; 0] = [0_u8; 0]; // Empty additional data...
    let sealed_data = match SgxSealedData::<KeyPair>::seal_data(&aad, &kp) { // Seals the data
        Ok(x) => x, 
        Err(ret) => {return ret;}, 
    };
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size); // Writes the data
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };

    if verify_pair(kp) {
        println!("[+] {:?}", kp.secret);
        sgx_status_t::SGX_SUCCESS
    } else {
        println!("[-] Public key not derivable from secret in unencrypted key file!"); // FIXME: Handle errors better in the enc.
        sgx_status_t::SGX_ERROR_UNEXPECTED
    }
}

