use serde::{Deserialize, Serialize};

use crate::serialize::binary::{BinEncodable, BinEncoder};

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub enum DNSClass {
    /// Internet
    IN,
    /// Chaos
    CH,
    /// Hesiod
    HS,
    /// QCLASS NONE
    NONE,
    /// QCLASS * (ANY)
    ANY,
    /// Special class for OPT Version, it was overloaded for EDNS - RFC 6891
    /// From the RFC: `Values lower than 512 MUST be treated as equal to 512`
    OPT(u16),
}

impl BinEncodable for DNSClass {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String> {
        encoder.emit_u16((*self).into())
    }
}

impl From<DNSClass> for u16 {
    fn from(rt: DNSClass) -> Self {
        match rt {
            DNSClass::IN => 1,
            DNSClass::CH => 3,
            DNSClass::HS => 4,
            DNSClass::NONE => 254,
            DNSClass::ANY => 255,
            DNSClass::OPT(max_payload_len) => max_payload_len.max(512),
        }
    }
}
