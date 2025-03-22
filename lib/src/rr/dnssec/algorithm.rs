use serde::{Deserialize, Serialize};

use crate::serialize::binary::{BinEncodable, BinEncoder};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum Algorithm {
    /// For now only support ECDSA P-256 with SHA-256 & RSA with SHA-256
    ECDSAP256SHA256,
    RSASHA256,
}

impl From<Algorithm> for u8 {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::RSASHA256 => 8,
            Algorithm::ECDSAP256SHA256 => 13,
        }
    }
}

impl BinEncodable for Algorithm {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String> {
        encoder.emit(u8::from(*self))
    }
}
