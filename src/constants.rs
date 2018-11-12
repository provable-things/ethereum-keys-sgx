pub const SECRET_KEY_SIZE_HEX: usize = 64;
pub static HEX_PREFIX: &'static str = "0x"; 
pub static URL_PREFIX: &'static str = "https://";
pub static URL_SUFFIX: &'static str = ".infura.io/";
pub static ENCLAVE_TOKEN: &'static str = "enclave.token";
pub static ENCLAVE_FILE: &'static str = "enclave.signed.so";
pub static ETH_PREFIX: &'static str = "\x19Ethereum Signed Message:\n32";
pub static NETWORK_REGEX: &'static str = r"(ropsten)|(rinkeby)|(mainnet)|(kovan)";
