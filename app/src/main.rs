extern crate secp256k1_enclave_rust;
use secp256k1_enclave_rust::dothing::run;
/*
 *
 * TODO: Make into CLI with docopt - init to create new key (can only do once? Store state?)
 * TODO: add messsage to get back the signed hash of it.
 * TODO: Have the first call the enc. do an ::new, which spits out the PublicKey
 * and a sealed privkey.
 * 
 **/
fn main() {
   run();
}