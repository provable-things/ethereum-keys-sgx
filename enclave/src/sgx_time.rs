use std::result;
use key_generator::KeyStruct;
use error::EnclaveError;
use sgx_tservice::sgxtime::SgxTime;
use pse_session::{create_pse_session, close_pse_session};

type Result<T> = result::Result<T, EnclaveError>;

pub fn show_time_since_last_access(kp: KeyStruct) -> Result<KeyStruct> {
    get_sgx_time()
        .and_then(|t| show_duration_since(t, kp))
        .and_then(update_time_in_keypair)
}

fn show_duration_since(sgxt: SgxTime, kp: KeyStruct) -> Result<(KeyStruct, SgxTime)> {
     match sgxt.duration_since(&kp.sgx_time) {
        Err(_) => Err(EnclaveError::SGXTimeError()), // FIXME: Error swalled, make `From` in error.rs!
        Ok(t)  => {
            println!("[+] Keyfile last accessed {} seconds ago!", t);
            Ok((kp, sgxt))
        }
    }
}

fn update_time_in_keypair((kp, t): (KeyStruct, SgxTime)) -> Result<KeyStruct> {
    Ok(KeyStruct{sgx_time: t, secret: kp.secret, public: kp.public, accesses_mc: kp.accesses_mc, signatures_mc: kp.signatures_mc})
}

pub fn get_sgx_time() -> Result<SgxTime> {
    create_pse_session()
        .and_then(get_sgx_time_struct)
        .and_then(close_pse_session)
}

fn get_sgx_time_struct<T>(_t: T) -> Result<SgxTime> {
     Ok(SgxTime::now()?)
}
