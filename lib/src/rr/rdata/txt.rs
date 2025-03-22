use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct TXT {
    txt_data: Vec<u8>,
}

impl TXT {
    pub fn new(txt_data: Vec<u8>) -> Self {
        Self { txt_data }
    }
}
