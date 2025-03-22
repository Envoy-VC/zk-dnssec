use serde::{Deserialize, Serialize};

use crate::rr::dnssec::rdata::DNSSECRData;
use crate::rr::rdata::txt::TXT;
use crate::serialize::binary::{BinEncodable, BinEncoder};

#[derive(Debug, PartialEq, Clone, Eq, Deserialize, Serialize)]
pub enum RData {
    /// ```text
    /// 3.3.14. TXT RDATA format
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   TXT-DATA                    /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// where:
    ///
    /// TXT-DATA        One or more <character-string>s.
    ///
    /// TXT RRs are used to hold descriptive text.  The semantics of the text
    /// depends on the domain where it is found.
    /// ```
    TXT(TXT),
    DNSSEC(DNSSECRData),
}

impl BinEncodable for RData {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String> {
        match *self {
            Self::TXT(ref txt) => txt.emit(encoder),
            Self::DNSSEC(ref sig) => sig.emit(encoder),
        }
    }
}
