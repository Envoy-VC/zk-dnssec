use serde::{Deserialize, Serialize};

use crate::serialize::binary::{BinEncodable, BinEncoder};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct TXT {
    txt_data: Box<[Box<[u8]>]>,
}

impl TXT {
    pub fn txt_data(&self) -> &[Box<[u8]>] {
        &self.txt_data
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
