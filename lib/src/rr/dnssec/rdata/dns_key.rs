use serde::{Deserialize, Serialize};

use crate::{
    rr::dnssec::algorithm::Algorithm,
    serialize::binary::{BinEncodable, BinEncoder},
};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct DNSKEY {
    zone_key: bool,
    secure_entry_point: bool,
    revoke: bool,
    algorithm: Algorithm,
    public_key: Vec<u8>,
}

impl DNSKEY {
    pub fn zone_key(&self) -> bool {
        self.zone_key
    }

    pub fn secure_entry_point(&self) -> bool {
        self.secure_entry_point
    }

    pub fn revoke(&self) -> bool {
        self.revoke
    }

    pub fn flags(&self) -> u16 {
        let mut flags: u16 = 0;
        if self.zone_key() {
            flags |= 0b0000_0001_0000_0000
        }
        if self.secure_entry_point() {
            flags |= 0b0000_0000_0000_0001
        }
        if self.revoke() {
            flags |= 0b0000_0000_1000_0000
        }

        flags
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl BinEncodable for DNSKEY {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String> {
        encoder.emit_u16(self.flags())?;
        encoder.emit(3)?; // always 3 for now
        self.algorithm().emit(encoder)?;
        encoder.emit_vec(self.public_key())?;

        Ok(())
    }
}
