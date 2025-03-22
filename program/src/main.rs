#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use zkdnssec_lib::{
    rr::{dns_class::DNSClass, dnssec::rdata::sig::SIG, domain::name::Name, resource::Record},
    verify_rrsig, PublicValuesStruct,
};

pub fn main() {
    let public_key = sp1_zkvm::io::read_vec();
    let name = sp1_zkvm::io::read::<Name>();
    let dns_class = sp1_zkvm::io::read::<DNSClass>();
    let sig = sp1_zkvm::io::read::<SIG>();
    let records = sp1_zkvm::io::read::<Vec<Record>>();
    let signature = sp1_zkvm::io::read_vec();

    let is_valid = verify_rrsig(public_key, &name, dns_class, &sig, &records, signature);
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { is_valid });

    sp1_zkvm::io::commit_slice(&bytes);
}
