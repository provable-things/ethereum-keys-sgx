#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#[cfg(not(target_env = "sgx"))]

extern crate sgx_rand;
extern crate sgx_types;
extern crate secp256k1;
extern crate sgx_tcrypto;
#[macro_use]
extern crate sgx_tstd as std;

mod keygen;
use sgx_types::*;
/*
 *
 * TODO: Switch to using the crypto crates' sha3 instead of tiny_keccak!! - Done but oops they aren't the same. Dammit.
 * TODO: Seal a pkS inside the enc and spit out ONLY the pub key!
 * TODO: Have the ETH address generated OUTSIDE the enc form the pk spat out by the enc. 
 * TODO: Make VANITY keygen & threading work!
 * Can have app call generate, rec. priv key, then call gen again if not vanity. Then have method callable via ocall (add to edl!)
 * that'll seal the priv key and close the enc!
 * 
 **/
#[no_mangle]
pub extern "C" fn generate_keypair(pub_key_ptr: &mut secp256k1::PublicKey) -> sgx_status_t {

    // println!("Pub key ptr before gen. key pair: {:?}", pub_key_ptr);
    match keygen::KeyPair::new() { // TODO: Try in, out in the EDL, and try the above println! with the :? now.
        Ok(kp) => {
            println!("Public key from ok arm: {}", kp.public); // Hex version
            *pub_key_ptr = kp.public
        },
        Err(_e) => {
            println!("We're in the erorr arm here :(");
            ()
        }
    }
    println!("Public key pointer after the match: {:?}", pub_key_ptr);
    sgx_status_t::SGX_SUCCESS


    // // Second, convert the vector to a slice and calculate its SHA256
    // let result = rsgx_sha256_slice(&input_slice);

    // // Third, copy back the result
    // match result {
    //     Ok(output_hash) => *hash = output_hash,
    //     Err(x) => return x
    // }
}