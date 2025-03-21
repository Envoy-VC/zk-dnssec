#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use zkdnssec_lib::{verify_ecdsa_signature, PublicValuesStruct};

pub fn main() {
    let public_key = sp1_zkvm::io::read_vec();
    let signature = sp1_zkvm::io::read_vec();
    let message = sp1_zkvm::io::read_vec();

    // Verify the signature.
    let is_valid = verify_ecdsa_signature(public_key, signature, message);

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { is_valid });

    sp1_zkvm::io::commit_slice(&bytes);
}
