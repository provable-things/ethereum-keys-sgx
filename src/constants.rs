pub const SECRET_KEY_SIZE: usize = 32;
pub static ENCLAVE_TOKEN: &'static str = "enclave.token";
pub static ENCLAVE_FILE: &'static str = "enclave.signed.so";
pub static ETH_PREFIX: &'static str = "\x19Ethereum Signed Message:\n32";
// see here https://ethereum.stackexchange.com/questions/19582/does-ecrecover-in-solidity-expects-the-x19ethereum-signed-message-n-prefix/21037
// Can get the above string as bytes, then add it to the keccak hasher? (Look into how to make a longer style keccak hasher)