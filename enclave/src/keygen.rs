use std::result;
use std::vec::Vec;
use sgx_types::*;
use error::EnclaveError;
use secp256k1::Secp256k1;
use sgx_tseal::SgxSealedData;
use sgx_rand::{Rng, thread_rng};
use sgx_types::marker::ContiguousMemory;
use secp256k1::key::{SecretKey, PublicKey};
use sealer::{to_sealed_log, from_sealed_log};
use sgx_tservice::sgxcounter::SgxMonotonicCounter;

type Result<T> = result::Result<T, EnclaveError>;

#[derive(Copy, Clone)]//, Debug)] <-- Can't derive debug due to no display. Implement & sort the errors!
pub struct KeyPair<'a> {
    pub public: PublicKey,
    pub(crate) secret: SecretKey,
    pub private_key_accesses_mc: &'a SgxMonotonicCounter
}

#[no_mangle]
pub extern "C" fn generate_keypair(
    sealed_log: * mut u8, 
    sealed_log_size: u32
) -> sgx_status_t {
    let keypair = match KeyPair::new() {
        Ok(kp) => kp,
        Err(_) => {return sgx_status_t::SGX_ERROR_UNEXPECTED;}
    };
    let aad: [u8; 0] = [0_u8; 0]; // Empty additional data...
    let sealed_data = match SgxSealedData::<KeyPair>::seal_data(&aad, &keypair) {
        Ok(x) => x,
        Err(ret) => {return ret;}, 
    };
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    };
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn get_public_key(
    pub_key_ptr: &mut PublicKey, 
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
        Err(ret) => {return ret;}, 
    };
    let keys: KeyPair = *unsealed_data.get_decrypt_txt();
    if verify_pair(keys) {
        *pub_key_ptr = keys.public;
        sgx_status_t::SGX_SUCCESS
    } else {
        println!("[-] Public key not derivable from secret in unencrypted key file!"); // FIXME: Handle errors better in the enc.
        sgx_status_t::SGX_ERROR_UNEXPECTED
    }
}

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
        Err(ret) => {return ret;}, 
    };
    let keys: KeyPair = *unsealed_data.get_decrypt_txt();
    if verify_pair(keys) {
        println!("[+] {:?}", keys.secret);
        sgx_status_t::SGX_SUCCESS
    } else {
        println!("[-] Public key not derivable from secret in unencrypted key file!"); // FIXME: Handle errors better in the enc.
        sgx_status_t::SGX_ERROR_UNEXPECTED
    }
}
/*
 *
 * TODO: Need to call destroy on MC (note spelling mistake in sdk!) when getting affirmation to overwrite keyfile!
 * 
 * */
// #[derive(Serialize, Deserialize)]
// #[serde(remote = "SgxMonotonicCounter")]
// struct SgxMonotonicCounterDef {
//     // #[serde(getter = "Duration::seconds")]
//     // secs: i64,
//     // #[serde(getter = "Duration::subsec_nanos")]
//     // nanos: i32,
//     #[serde(getter = "SgxMonotonicCounter::counter_uuid")]
//     counter_uuid: sgx_mc_uuid_t,
//     #[serde(getter = "SgxMonotonicCounter::initflag")]
//     initflag: Cell<bool>,
// }

// // Provide a conversion to construct the remote type.
// impl From<SgxMonotonicCounterDef> for SgxMonotonicCounter {
//     fn from(def: SgxMonotonicCounterDef) -> SgxMonotonicCounter {
//         SgxMonotonicCounter::new(def.counter_uuid, def.initflag)
//     }
// }

// #[derive(Serialize, Deserialize)]
// struct Process {
//     command_line: String,

//     #[serde(with = "DurationDef")]
//     wall_time: Duration,
// }

unsafe impl<'a> ContiguousMemory for KeyPair<'a>{}

// impl fmt::Display for KeyPair {
//     fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
// 		writeln!(f, "Private key: [redacted - please use `unsafe_show_secret` to view]")?;
// 		writeln!(f, "{:?}", self.public)?;
//         // write!(f, "Number of private key accesses: {:?}", self.private_key_accesses_mc)
// 	}
// }

impl<'a> KeyPair<'a> {
    pub fn new() -> Result<KeyPair<'a>> {
        let s = generate_random_priv_key()?;
        let p = get_public_key_from_secret(s);
        let mc = SgxMonotonicCounter::new(&mut 0)?;
        Ok(KeyPair{secret: s, public: p, private_key_accesses_mc: &mc})
    }
}

pub fn verify_pair(keys: KeyPair) -> bool { // Note: Can't impl. since decryption loses methods on structs obvs.
    keys.public == get_public_key_from_secret(keys.secret)
}

fn generate_random_priv_key() -> Result<SecretKey> {
    Ok(SecretKey::from_slice(&Secp256k1::new(), &get_32_random_bytes_arr())?)
}

fn get_32_random_bytes_arr() -> [u8;32] {
    let mut arr = [0; 32];
    arr.copy_from_slice(&get_x_random_bytes_vec(32));
    arr
}

fn get_public_key_from_secret(secret_key: SecretKey) -> PublicKey {
    PublicKey::from_secret_key(&Secp256k1::new(), &secret_key)
}

fn get_x_random_bytes_vec(len: usize) -> Vec<u8> { // FIXME: Ugly func, imperative, make better!
    let mut x = vec![0u8; len]; 
    thread_rng().fill_bytes(&mut x);
    x
}