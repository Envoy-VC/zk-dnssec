use serde::{Deserialize, Serialize};

use crate::{rr::record_data::RData, serialize::binary::{BinEncodable, BinEncoder}};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct TXT {
    pub txt_data: Box<[Box<[u8]>]>,
}

impl TXT {
    pub fn txt_data(&self) -> &[Box<[u8]>] {
        &self.txt_data
    }

    pub fn into_rdata(self) -> RData {
        RData::TXT(self)
    }
}

impl BinEncodable for TXT {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String> {
        for s in self.txt_data() {
            encoder.emit_character_data(s)?;
        }

        Ok(())
    }
}
