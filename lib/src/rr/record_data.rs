use serde::{Deserialize, Serialize};

use crate::serialize::binary::{BinEncodable, BinEncoder};

use super::rdata::rrsig::RRSIG;
use super::rdata::txt::TXT;

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
    /// ```text
    /// RFC 2535 & 2931   DNS Security Extensions               March 1999
    /// RFC 4034          DNSSEC Resource Records               March 2005
    ///
    /// 3.1.  RRSIG RDATA Wire Format
    ///
    ///    The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
    ///    1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
    ///    TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
    ///    Inception field, a 2 octet Key tag, the Signer's Name field, and the
    ///    Signature field.
    ///
    ///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    ///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |        Type Covered           |  Algorithm    |     Labels    |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |                         Original TTL                          |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |                      Signature Expiration                     |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |                      Signature Inception                      |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |            Key Tag            |                               /
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
    ///    /                                                               /
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    /                                                               /
    ///    /                            Signature                          /
    ///    /                                                               /
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    RRSIG(RRSIG),
}

impl BinEncodable for RData {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String> {
        match *self {
            Self::TXT(ref txt) => txt.emit(encoder), // TODO: Implement
            Self::RRSIG(ref sig) => sig.emit(encoder), // TODO: Implement
        }
    }
}
