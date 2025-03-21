use alloy_sol_types::sol;

use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bool is_valid;
    }
}

pub fn verify_ecdsa_signature(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    let sec1_pubkey: Vec<u8> = if public_key.len() == 64 {
        let mut buf = Vec::with_capacity(65);
        buf.push(0x04);
        buf.extend_from_slice(public_key.as_slice());
        buf
    } else {
        public_key.to_vec()
    };

    let verifying_key = VerifyingKey::from_sec1_bytes(sec1_pubkey.as_slice()).unwrap();
    let sig = Signature::try_from(signature.as_slice()).unwrap();

    // try catch verify

    let is_valid = verifying_key.verify(message.as_ref(), &sig).is_ok();

    is_valid
}
