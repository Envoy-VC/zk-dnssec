use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Deserialize, Serialize)]
pub enum RecordType {
    TXT,
    DNSKEY,
    RRSIG,
    DS,
}
