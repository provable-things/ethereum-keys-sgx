use sgx_types::*;
use keygen::KeyPair;
use sealer::to_sealed_log;
use sgx_tseal::SgxSealedData;

#[no_mangle]
pub extern "C" fn generate_keypair(
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> sgx_status_t {
    let keypair = match KeyPair::new() {
        Ok(kp) => kp,
        Err(e) => {
            println!("[-] Error creating new key pair: {}", e); //Err(e) => {return e;} // FIXME: Propagate SGX errors to app properly! Or will this do?
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    let aad: [u8; 0] = [0_u8; 0]; // Empty additional data...
    let sealed_data = match SgxSealedData::<KeyPair>::seal_data(&aad, &keypair) { // Seals the data
        Ok(x) => x,
        Err(ret) => {return ret;}, 
    };
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size); // Writes the data
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };
    sgx_status_t::SGX_SUCCESS
}
