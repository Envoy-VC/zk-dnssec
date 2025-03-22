use serde::{Deserialize, Serialize};

use dns_key::DNSKEY;
use rrsig::RRSIG;
use sig::SIG;

use crate::serialize::binary::{BinEncodable, BinEncoder};

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub enum DNSSECRData {
    DNSKEY(DNSKEY),
    RRSIG(RRSIG),
    SIG(SIG),
}

impl DNSSECRData {
    pub(crate) fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String> {
        match *self {
            Self::DNSKEY(ref dnskey) => {
                encoder.with_canonical_names(|encoder| dnskey.emit(encoder))
            }
            Self::RRSIG(ref rrsig) => encoder.with_canonical_names(|encoder| rrsig.emit(encoder)),
            Self::SIG(ref sig) => encoder.with_canonical_names(|encoder| sig.emit(encoder)),
        }
    }
}

pub mod dns_key;
pub mod rrsig;
pub mod sig;
