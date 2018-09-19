use sgx_rand::{Rng, thread_rng};
use std::prelude::v1::Vec;

use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::constants;
use secp256k1::{Secp256k1, Signature, RecoverableSignature, Message, RecoveryId};
use secp256k1::Error::{InvalidMessage, IncorrectSignature, InvalidSignature};


macro_rules! hex {
    ($hex:expr) => {
        {
            let mut vec = Vec::new();
            let mut b = 0;
            for (idx, c) in $hex.as_bytes().iter().enumerate() {
                b <<= 4;
                match *c {
                    b'A'...b'F' => b |= c - b'A' + 10,
                    b'a'...b'f' => b |= c - b'a' + 10,
                    b'0'...b'9' => b |= c - b'0',
                    _ => panic!("Bad hex"),
                }
                if (idx & 1) == 1 {
                    vec.push(b);
                    b = 0;
                }
            }
            vec
        }
    }
}

pub fn capabilities() {
    let none = Secp256k1::without_caps();
    let sign = Secp256k1::signing_only();
    let vrfy = Secp256k1::verification_only();
    let full = Secp256k1::new();

    let mut msg = [0u8; 32];
    thread_rng().fill_bytes(&mut msg);
    let msg = Message::from_slice(&msg).unwrap();

    // Try key generation
    let (sk, pk) = full.generate_keypair(&mut thread_rng());

    // Try signing
    assert_eq!(sign.sign(&msg, &sk), full.sign(&msg, &sk));
    assert_eq!(sign.sign_recoverable(&msg, &sk), full.sign_recoverable(&msg, &sk));
    let sig = full.sign(&msg, &sk);
    let sigr = full.sign_recoverable(&msg, &sk);

    // Try verifying
    assert!(vrfy.verify(&msg, &sig, &pk).is_ok());
    assert!(full.verify(&msg, &sig, &pk).is_ok());

    // Try pk recovery
    assert!(vrfy.recover(&msg, &sigr).is_ok());
    assert!(full.recover(&msg, &sigr).is_ok());

    assert_eq!(vrfy.recover(&msg, &sigr),
               full.recover(&msg, &sigr));
    assert_eq!(full.recover(&msg, &sigr), Ok(pk));

    // Check that we can produce keys from slices with no precomputation
    let (pk_slice, sk_slice) = (&pk.serialize(), &sk[..]);
    let new_pk = PublicKey::from_slice(&none, pk_slice).unwrap();
    let new_sk = SecretKey::from_slice(&none, sk_slice).unwrap();
    assert_eq!(sk, new_sk);
    assert_eq!(pk, new_pk);
}

pub fn recid_sanity_check() {
    let one = RecoveryId::from_i32(1);
    assert_eq!(one, one.clone());
}

pub fn sign() {
    let mut s = Secp256k1::new();
    s.randomize(&mut thread_rng());
    let one = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    let sk = SecretKey::from_slice(&s, &one).unwrap();
    let msg = Message::from_slice(&one).unwrap();

    let sig = s.sign_recoverable(&msg, &sk);
    assert_eq!(Ok(sig), RecoverableSignature::from_compact(&s, &[
        0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
        0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
        0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
        0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
        0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
        0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
        0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
        0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
                                                           RecoveryId::from_i32(1).unwrap()))
}

pub fn signature_serialize_roundtrip() {
    let mut s = Secp256k1::new();
    s.randomize(&mut thread_rng());

    let mut msg = [0; 32];
    for _ in 0..100 {
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let (sk, _) = s.generate_keypair(&mut thread_rng());
        let sig1 = s.sign(&msg, &sk);
        let der = sig1.serialize_der(&s);
        let sig2 = Signature::from_der(&s, &der[..]).unwrap();
        assert_eq!(sig1, sig2);

        let compact = sig1.serialize_compact(&s);
        let sig2 = Signature::from_compact(&s, &compact[..]).unwrap();
        assert_eq!(sig1, sig2);

        assert!(Signature::from_compact(&s, &der[..]).is_err());
        assert!(Signature::from_compact(&s, &compact[0..4]).is_err());
        assert!(Signature::from_der(&s, &compact[..]).is_err());
        assert!(Signature::from_der(&s, &der[0..4]).is_err());
    }
}

pub fn signature_lax_der() {
    macro_rules! check_lax_sig(
        ($hex:expr) => ({
            let secp = Secp256k1::without_caps();
            let sig = hex!($hex);
            assert!(Signature::from_der_lax(&secp, &sig[..]).is_ok());
        })
    );

    check_lax_sig!("304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c");
    check_lax_sig!("304402202ea9d51c7173b1d96d331bd41b3d1b4e78e66148e64ed5992abd6ca66290321c0220628c47517e049b3e41509e9d71e480a0cdc766f8cdec265ef0017711c1b5336f");
    check_lax_sig!("3045022100bf8e050c85ffa1c313108ad8c482c4849027937916374617af3f2e9a881861c9022023f65814222cab09d5ec41032ce9c72ca96a5676020736614de7b78a4e55325a");
    check_lax_sig!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
    check_lax_sig!("3046022100eaa5f90483eb20224616775891397d47efa64c68b969db1dacb1c30acdfc50aa022100cf9903bbefb1c8000cf482b0aeeb5af19287af20bd794de11d82716f9bae3db1");
    check_lax_sig!("3045022047d512bc85842ac463ca3b669b62666ab8672ee60725b6c06759e476cebdc6c102210083805e93bd941770109bcc797784a71db9e48913f702c56e60b1c3e2ff379a60");
    check_lax_sig!("3044022023ee4e95151b2fbbb08a72f35babe02830d14d54bd7ed1320e4751751d1baa4802206235245254f58fd1be6ff19ca291817da76da65c2f6d81d654b5185dd86b8acf");
}

pub fn sign_and_verify() {
    let mut s = Secp256k1::new();
    s.randomize(&mut thread_rng());

    let mut msg = [0; 32];
    for _ in 0..100 {
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut thread_rng());
        let sig = s.sign(&msg, &sk);
        assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
    }
}

pub fn sign_and_verify_extreme() {
    let mut s = Secp256k1::new();
    s.randomize(&mut thread_rng());

    // Wild keys: 1, CURVE_ORDER - 1
    // Wild msgs: 0, 1, CURVE_ORDER - 1, CURVE_ORDER
    let mut wild_keys = [[0; 32]; 2];
    let mut wild_msgs = [[0; 32]; 4];

    wild_keys[0][0] = 1;
    wild_msgs[1][0] = 1;

    wild_keys[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);
    wild_msgs[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);
    wild_msgs[2][..].copy_from_slice(&constants::CURVE_ORDER[..]);

    wild_keys[1][0] -= 1;
    wild_msgs[1][0] -= 1;

    for key in wild_keys.iter().map(|k| SecretKey::from_slice(&s, &k[..]).unwrap()) {
        for msg in wild_msgs.iter().map(|m| Message::from_slice(&m[..]).unwrap()) {
            let sig = s.sign(&msg, &key);
            let pk = PublicKey::from_secret_key(&s, &key);
            assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
        }
    }
}

pub fn sign_and_verify_fail() {
    let mut s = Secp256k1::new();
    s.randomize(&mut thread_rng());

    let mut msg = [0u8; 32];
    thread_rng().fill_bytes(&mut msg);
    let msg = Message::from_slice(&msg).unwrap();

    let (sk, pk) = s.generate_keypair(&mut thread_rng());

    let sigr = s.sign_recoverable(&msg, &sk);
    let sig = sigr.to_standard(&s);

    let mut msg = [0u8; 32];
    thread_rng().fill_bytes(&mut msg);
    let msg = Message::from_slice(&msg).unwrap();
    assert_eq!(s.verify(&msg, &sig, &pk), Err(IncorrectSignature));

    let recovered_key = s.recover(&msg, &sigr).unwrap();
    assert!(recovered_key != pk);
}

pub fn sign_with_recovery() {
    let mut s = Secp256k1::new();
    s.randomize(&mut thread_rng());

    let mut msg = [0u8; 32];
    thread_rng().fill_bytes(&mut msg);
    let msg = Message::from_slice(&msg).unwrap();

    let (sk, pk) = s.generate_keypair(&mut thread_rng());

    let sig = s.sign_recoverable(&msg, &sk);

    assert_eq!(s.recover(&msg, &sig), Ok(pk));
}

pub fn bad_recovery() {
    let mut s = Secp256k1::new();
    s.randomize(&mut thread_rng());

    let msg = Message::from_slice(&[0x55; 32]).unwrap();

    // Zero is not a valid sig
    let sig = RecoverableSignature::from_compact(&s, &[0; 64], RecoveryId::from_i32(0).unwrap()).unwrap();
    assert_eq!(s.recover(&msg, &sig), Err(InvalidSignature));
    // ...but 111..111 is
    let sig = RecoverableSignature::from_compact(&s, &[1; 64], RecoveryId::from_i32(0).unwrap()).unwrap();
    assert!(s.recover(&msg, &sig).is_ok());
}

pub fn test_bad_slice() {
    let s = Secp256k1::new();
    assert_eq!(Signature::from_der(&s, &[0; constants::MAX_SIGNATURE_SIZE + 1]),
               Err(InvalidSignature));
    assert_eq!(Signature::from_der(&s, &[0; constants::MAX_SIGNATURE_SIZE]),
               Err(InvalidSignature));

    assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE - 1]),
               Err(InvalidMessage));
    assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE + 1]),
               Err(InvalidMessage));
    assert!(Message::from_slice(&[0; constants::MESSAGE_SIZE]).is_ok());
}

pub fn test_debug_output() {
    let s = Secp256k1::new();
    let sig = RecoverableSignature::from_compact(&s, &[
        0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
        0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
        0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
        0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
        0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
        0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
        0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
        0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
                                                 RecoveryId::from_i32(1).unwrap()).unwrap();
    assert_eq!(&format!("{:?}", sig), "RecoverableSignature(98882e09f4ed6dc3659e43fc771e0cafa60b1f926f2b77041f744721adff7366898cb609d0ee128d06ae9aa3c48020ff9f705e02f80e1280a8ade05216971a4c01)");

    let msg = Message::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 255]).unwrap();
    assert_eq!(&format!("{:?}", msg), "Message(0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff)");
}

pub fn test_recov_sig_serialize_compact() {
    let s = Secp256k1::new();

    let recid_in = RecoveryId::from_i32(1).unwrap();
    let bytes_in = &[
        0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
        0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
        0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
        0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
        0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
        0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
        0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
        0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89];
    let sig = RecoverableSignature::from_compact(
        &s, bytes_in, recid_in).unwrap();
    let (recid_out, bytes_out) = sig.serialize_compact(&s);
    assert_eq!(recid_in, recid_out);
    assert_eq!(&bytes_in[..], &bytes_out[..]);
}

pub fn test_recov_id_conversion_between_i32() {
    assert!(RecoveryId::from_i32(-1).is_err());
    assert!(RecoveryId::from_i32(0).is_ok());
    assert!(RecoveryId::from_i32(1).is_ok());
    assert!(RecoveryId::from_i32(2).is_ok());
    assert!(RecoveryId::from_i32(3).is_ok());
    assert!(RecoveryId::from_i32(4).is_err());
    let id0 = RecoveryId::from_i32(0).unwrap();
    assert_eq!(id0.to_i32(), 0);
    let id1 = RecoveryId::from_i32(1).unwrap();
    assert_eq!(id1.to_i32(), 1);
}

pub fn test_low_s() {
    // nb this is a transaction on testnet
    // txid 8ccc87b72d766ab3128f03176bb1c98293f2d1f85ebfaf07b82cc81ea6891fa9
    //      input number 3
    let sig = hex!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
    let pk = hex!("031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43");
    let msg = hex!("a4965ca63b7d8562736ceec36dfa5a11bf426eb65be8ea3f7a49ae363032da0d");

    let secp = Secp256k1::new();
    let mut sig = Signature::from_der(&secp, &sig[..]).unwrap();
    let pk = PublicKey::from_slice(&secp, &pk[..]).unwrap();
    let msg = Message::from_slice(&msg[..]).unwrap();

    // without normalization we expect this will fail
    assert_eq!(secp.verify(&msg, &sig, &pk), Err(IncorrectSignature));
    // after normalization it should pass
    sig.normalize_s(&secp);
    assert_eq!(secp.verify(&msg, &sig, &pk), Ok(()));
}

#[cfg(feature = "serde")]
#[test]
fn test_signature_serde() {
    use serde_test::{Token, assert_tokens};

    let s = Secp256k1::new();

    let msg = Message::from_slice(&[1; 32]).unwrap();
    let sk = SecretKey::from_slice(&s, &[2; 32]).unwrap();
    let sig = s.sign(&msg, &sk);
    static SIG_BYTES: [u8; 71] = [
        48, 69, 2, 33, 0, 157, 11, 173, 87, 103, 25, 211, 42, 231, 107, 237,
        179, 76, 119, 72, 102, 103, 60, 189, 227, 244, 225, 41, 81, 85, 92, 148,
        8, 230, 206, 119, 75, 2, 32, 40, 118, 231, 16, 47, 32, 79, 107, 254,
        226, 108, 150, 124, 57, 38, 206, 112, 44, 249, 125, 75, 1, 0, 98, 225,
        147, 247, 99, 25, 15, 103, 118
    ];

    assert_tokens(&sig, &[Token::BorrowedBytes(&SIG_BYTES[..])]);
}
