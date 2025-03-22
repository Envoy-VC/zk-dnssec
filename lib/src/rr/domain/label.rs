use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::fmt::{self, Write};
use std::hash::{Hash, Hasher};

const WILDCARD: &[u8] = b"*";

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

    pub fn from_ascii(s: &str) -> Result<Self, String> {
        if s.len() > 63 {
            return Err("Label exceeds maximum length of 63 octets".into());
        }

        if s.as_bytes() == WILDCARD {
            return Ok(Self::wildcard());
        }

        if !s.is_empty()
            && s.is_ascii()
            && s.chars().take(1).all(|c| is_safe_ascii(c, true, false))
            && s.chars().skip(1).all(|c| is_safe_ascii(c, false, false))
        {
            Self::from_raw_bytes(s.as_bytes())
        } else {
            Err("Malformed Label".into())
        }
    }

    /// Returns a new Label of the Wildcard, i.e. "*"
    pub fn wildcard() -> Self {
        Self(Vec::from(WILDCARD))
    }

    pub fn write_ascii<W: Write>(&self, f: &mut W) -> Result<(), fmt::Error> {
        // We can't guarantee that the same input will always translate to the same output
        fn escape_non_ascii<W: Write>(
            byte: u8,
            f: &mut W,
            is_first: bool,
        ) -> Result<(), fmt::Error> {
            let to_triple_escape = |ch: u8| format!("\\{ch:03o}");
            let to_single_escape = |ch: char| format!("\\{ch}");

            match char::from(byte) {
                c if is_safe_ascii(c, is_first, true) => f.write_char(c)?,
                // it's not a control and is printable as well as inside the standard ascii range
                c if byte > b'\x20' && byte < b'\x7f' => f.write_str(&to_single_escape(c))?,
                _ => f.write_str(&to_triple_escape(byte))?,
            }

            Ok(())
        }

        // traditional ascii case...
        let mut chars = self.as_bytes().iter();
        if let Some(ch) = chars.next() {
            escape_non_ascii(*ch, f, true)?;
        }

        for ch in chars {
            escape_non_ascii(*ch, f, false)?;
        }

        Ok(())
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

fn is_safe_ascii(c: char, is_first: bool, for_encoding: bool) -> bool {
    match c {
        c if !c.is_ascii() => false,
        c if c.is_alphanumeric() => true,
        '-' if !is_first => true,     // dash is allowed
        '_' => true,                  // SRV like labels
        '*' if is_first => true,      // wildcard
        '.' if !for_encoding => true, // needed to allow dots, for things like email addresses
        _ => false,
    }
}
