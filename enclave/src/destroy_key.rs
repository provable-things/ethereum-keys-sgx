use sgx_types::*;
use keygen::KeyStruct;
use sgx_tseal::SgxSealedData;
use monotonic_counter::destroy_mc;
use sealer::{to_sealed_log, from_sealed_log};

#[no_mangle]
pub extern "C" fn destroy_key(
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> sgx_status_t {
    let opt = from_sealed_log::<KeyStruct>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;},
    };
    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {return ret;}, 
    };
    let kp: KeyStruct = *unsealed_data.get_decrypt_txt();


    // Delete the mcs
    match destroy_mc(kp.accesses_mc) { // Inefficient - sort out!
        Ok(_)   => {
            println!("[+] Accesses monontonic counter successfully destroyed!");
        },
        Err(e) => {
            println!("[-] Error destroying accesses monotonic counter: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }
    match destroy_mc(kp.signatures_mc) { // Inefficient - sort out!
        Ok(_)   => {
            println!("[+] Signatures monontonic counter successfully destroyed!");
        },
        Err(e) => {
            println!("[-] Error destroying signatures monotonic counter: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }

    // Seal and overwrite outside enc.
    let aad: [u8; 0] = [0_u8; 0]; // Empty additional data...
    let sealed_data = match SgxSealedData::<KeyStruct>::seal_data(&aad, &kp) { // Seals the data
        Ok(x) => x, 
        Err(ret) => {return ret;}, 
    };
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size); // Writes the data
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };

    sgx_status_t::SGX_SUCCESS
}


