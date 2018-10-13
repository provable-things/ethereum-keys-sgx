use sgx_types::sgx_status_t;
use sgx_tservice::{rsgx_close_pse_session, rsgx_create_pse_session, sgxtime};

#[no_mangle]
pub extern "C" fn sgx_time_sample() -> sgx_status_t {

    match rsgx_create_pse_session() {
        Ok(_) => println!("Create PSE session done"),
        _ => {
            println!("Cannot create PSE session");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }
    let ttime = sgxtime::SgxTime::now();
    match ttime {
        Ok(st) => println!("Ok with {:?}", st),
        Err(x) => {
            println!("Err with {}", x);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }
    match rsgx_close_pse_session() {
        Ok(_) => println!("close PSE session done"),
        _ => {
            println!("Cannot close PSE session");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }
    
    sgx_status_t::SGX_SUCCESS
}
