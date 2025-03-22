use serde::{Deserialize, Serialize};

use crate::rr::dnssec::algorithm::Algorithm;
use crate::rr::domain::name::Name;
use crate::rr::record_type::RecordType;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Deserialize, Serialize)]
pub struct SIG {
    type_covered: RecordType,
    algorithm: Algorithm,
    num_labels: u8,
    original_ttl: u32,
    sig_expiration: u32,
    sig_inception: u32,
    key_tag: u16,
    signer_name: Name,
    sig: Vec<u8>,
}
