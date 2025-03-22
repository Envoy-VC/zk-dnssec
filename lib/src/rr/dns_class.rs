use serde::{Deserialize, Serialize};

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
