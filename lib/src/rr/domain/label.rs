use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::hash::{Hash, Hasher};

#[derive(Clone, Eq, Serialize, Deserialize, Debug)]
pub struct Label(Vec<u8>);

impl PartialEq<Self> for Label {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

impl Label {
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Label, String> {
        // Check for label validity.
        // RFC 2181, Section 11 "Name Syntax".
        // > The length of any one label is limited to between 1 and 63 octets.
        if bytes.is_empty() {
            return Err("Label requires a minimum length of 1".into());
        }
        if bytes.len() > 63 {
            return Err("Label exceeds maximum length of 63 octets".into());
        };

        Ok(Self(bytes.to_vec()))
    }

    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }

    pub fn to_lowercase(&self) -> Self {
        Self(self.0.to_ascii_lowercase())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for Label {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl Hash for Label {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        for b in self.borrow() as &[u8] {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}
