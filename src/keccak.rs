use tiny_keccak::Keccak;
use constants::ETH_PREFIX;

pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
}

impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(&mut result);
        result
    }
}

pub fn hash_slice(slice: &str) -> [u8;32] { // FIXME: use a type?
    slice.as_bytes().keccak256()
}

fn hash_hashed_msg_with_prefix(hashed_msg: [u8;32]) -> [u8;32] {
    let mut keccak = Keccak::new_keccak256();
    let mut result: [u8; 32] = [0; 32];
    keccak.update(&ETH_PREFIX.as_bytes());
    keccak.update(&hashed_msg);
    keccak.finalize(&mut result);
    result
}

pub fn hash_with_prefix(slice: &str) -> [u8;32] {
    hash_hashed_msg_with_prefix(hash_slice(slice))
}

// pub fn hash_with_prefix(msg_slice: &str) -> [u8;32] { // For second version of const. str.
//     let mut keccak = Keccak::new_keccak256();
//     let mut result: [u8; 32] = [0; 32];
//     keccak.update(&ETH_PREFIX.as_bytes());
//     keccak.update(&msg_slice.len().to_string().as_bytes());
//     keccak.update(&msg_slice);
//     keccak.finalize(&mut result);
//     result
// }

