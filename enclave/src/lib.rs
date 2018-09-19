#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;

extern crate secp256k1;

use sgx_types::*;

use std::backtrace::{self, PrintFormat};

mod tests;

#[no_mangle]
pub extern "C" fn run_tests() -> sgx_status_t {
    println!("starting test");

    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

    tests::capabilities();
    tests::recid_sanity_check();
    tests::sign();
    tests::signature_serialize_roundtrip();
    tests::signature_lax_der();
    tests::sign_and_verify();
    tests::sign_and_verify_extreme();
    tests::sign_and_verify_fail();
    tests::sign_with_recovery();
    tests::bad_recovery();
    tests::test_bad_slice();
    tests::test_debug_output();
    tests::test_recov_sig_serialize_compact();
    tests::test_recov_id_conversion_between_i32();
    tests::test_low_s();

    println!("test finished!");
    sgx_status_t::SGX_SUCCESS
}