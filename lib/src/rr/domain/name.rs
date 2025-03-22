use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Write},
    hash::{Hash, Hasher},
    str::FromStr,
};

use crate::{rr::domain::label::Label, serialize::binary::BinEncoder};

#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct Name {
    pub is_fqdn: bool,
    pub label_data: Vec<u8>, // 24 Length,
    pub label_ends: Vec<u8>, // 32 Length
}

#[derive(Eq, Debug, Clone, PartialEq, Serialize, Deserialize)]
enum ParseState {
    Label,
    Escape1,
    Escape2(u32),
    Escape3(u32, u32),
}

pub struct LabelIter<'a> {
    name: &'a Name,
    start: u8,
    end: u8,
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.start >= self.end {
            return None;
        }

        let end: u8 = *self.name.label_ends.get(self.start as usize)?;
        let start = match self.start {
            0 => 0,
            _ => self.name.label_ends[(self.start - 1) as usize],
        };
        self.start += 1;
        Some(&self.name.label_data[start as usize..end as usize])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.end.saturating_sub(self.start) as usize;
        (len, Some(len))
    }
}

impl Name {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the name is a fully qualified domain name.
    pub fn is_fqdn(&self) -> bool {
        self.is_fqdn
    }

    pub fn set_fqdn(&mut self, val: bool) {
        self.is_fqdn = val
    }

    /// Returns the root label, i.e. no labels.
    pub fn is_root(&self) -> bool {
        self.label_ends.is_empty() && self.is_fqdn()
    }

    /// Returns an iterator over the labels
    pub fn iter(&self) -> LabelIter<'_> {
        LabelIter {
            name: self,
            start: 0,
            end: self.label_ends.len() as u8,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.label_ends.is_empty()
    }

    pub fn len(&self) -> usize {
        let dots = if !self.label_ends.is_empty() {
            self.label_ends.len()
        } else {
            1
        };
        dots + self.label_data.len()
    }

    fn extend_name(&mut self, label: &[u8]) -> Result<(), String> {
        self.label_data.extend_from_slice(label);
        self.label_ends.push(self.label_data.len() as u8);
        if self.len() > 255 {
            return Err("Domain name too long".into());
        };
        Ok(())
    }

    pub fn append_label(mut self, label: Label) -> Result<Self, String> {
        self.extend_name(label.as_bytes())?;
        Ok(self)
    }

    pub fn append_domain(self, domain: &Self) -> Result<Self, String> {
        let mut this = self.append_name(domain)?;
        this.set_fqdn(true);
        Ok(this)
    }

    pub fn num_labels(&self) -> u8 {
        // it is illegal to have more than 256 labels.

        let num = self.label_ends.len() as u8;

        self.iter()
            .next()
            .map(|l| if l == b"*" { num - 1 } else { num })
            .unwrap_or(num)
    }

    pub fn to_lowercase(&self) -> Self {
        let new_label_data = self
            .label_data
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect();
        Self {
            is_fqdn: self.is_fqdn,
            label_data: new_label_data,
            label_ends: self.label_ends.clone(),
        }
    }

    pub fn emit_with_lowercase(
        &self,
        encoder: &mut BinEncoder<'_>,
        lowercase: bool,
    ) -> Result<(), String> {
        let is_canonical_names = encoder.is_canonical_names();
        if lowercase {
            self.to_lowercase()
                .emit_as_canonical(encoder, is_canonical_names)
        } else {
            self.emit_as_canonical(encoder, is_canonical_names)
        }
    }

    pub fn trim_to(&self, num_labels: usize) -> Self {
        if num_labels > self.label_ends.len() {
            self.clone()
        } else {
            let labels: Vec<&[u8]> = self
                .iter()
                .skip(self.label_ends.len() - num_labels)
                .collect();
            Self::from_labels(labels).unwrap()
        }
    }

    pub fn append_name(mut self, other: &Self) -> Result<Self, String> {
        for label in other.iter() {
            self.extend_name(label)?;
        }

        self.is_fqdn = other.is_fqdn;
        Ok(self)
    }

    pub fn from_labels(labels: Vec<&[u8]>) -> Result<Self, String> {
        let (labels, errors): (Vec<_>, Vec<_>) = labels
            .into_iter()
            .map(Label::from_raw_bytes)
            .partition(Result::is_ok);

        let labels: Vec<_> = labels.into_iter().map(Result::unwrap).collect();
        let errors: Vec<_> = errors.into_iter().map(Result::unwrap_err).collect();

        if labels.len() > 255 {
            return Err("Domain name too long".into());
        };
        if !errors.is_empty() {
            return Err("Error converting some labels".into());
        };

        let mut name = Self {
            is_fqdn: true,
            ..Self::default()
        };

        for label in labels {
            name = name.append_label(label)?;
        }

        Ok(name)
    }

    pub fn emit_as_canonical(
        &self,
        encoder: &mut BinEncoder<'_>,
        canonical: bool,
    ) -> Result<(), String> {
        let buf_len = encoder.len();
        let labels = self.iter();

        // start index of each label
        let mut labels_written = Vec::with_capacity(self.label_ends.len());
        // we're going to write out each label, tracking the indexes of the start to each label
        //   then we'll look to see if we can remove them and recapture the capacity in the buffer...
        for label in labels {
            if label.len() > 63 {
                return Err("Label Bytes too long".into());
            }

            labels_written.push(encoder.offset());
            encoder.emit_character_data(label)?;
        }
        let last_index = encoder.offset();
        // now search for other labels already stored matching from the beginning label, strip then to the end
        //   if it's not found, then store this as a new label
        for label_idx in &labels_written {
            match encoder.get_label_pointer(*label_idx, last_index) {
                // if writing canonical and already found, continue
                Some(_) if canonical => continue,
                Some(loc) if !canonical => {
                    // reset back to the beginning of this label, and then write the pointer...
                    encoder.set_offset(*label_idx);
                    encoder.trim();

                    // write out the pointer marker
                    //  or'd with the location which shouldn't be larger than this 2^14 or 16k
                    encoder.emit_u16(0xC000u16 | (loc & 0x3FFFu16))?;

                    // we found a pointer don't write more, break
                    return Ok(());
                }
                _ => {
                    // no existing label exists, store this new one.
                    encoder.store_label_pointer(*label_idx, last_index);
                }
            }
        }

        // if we're getting here, then we didn't write out a pointer and are ending the name
        // the end of the list of names
        encoder.emit(0)?;

        // the entire name needs to be less than 256.
        let length = encoder.len() - buf_len;
        if length > 255 {
            return Err("Domain name too long".into());
        }

        Ok(())
    }

    fn from_encoded_str<E: LabelEnc>(local: &str, origin: Option<&Self>) -> Result<Self, String> {
        let mut name = Self::new();
        let mut label = String::new();

        let mut state = ParseState::Label;

        // short circuit root parse
        if local == "." {
            name.set_fqdn(true);
            return Ok(name);
        }

        // TODO: it would be nice to relocate this to Label, but that is hard because the label boundary can only be detected after processing escapes...
        // evaluate all characters
        for ch in local.chars() {
            match state {
                ParseState::Label => match ch {
                    '.' => {
                        name = name.append_label(E::to_label(&label)?)?;
                        label.clear();
                    }
                    '\\' => state = ParseState::Escape1,
                    ch if !ch.is_control() && !ch.is_whitespace() => label.push(ch),
                    _ => return Err("unrecognized char".into()),
                },
                ParseState::Escape1 => {
                    if ch.is_numeric() {
                        state = ParseState::Escape2(ch.to_digit(8).unwrap());
                    } else {
                        // it's a single escaped char
                        label.push(ch);
                        state = ParseState::Label;
                    }
                }
                ParseState::Escape2(i) => {
                    if ch.is_numeric() {
                        state = ParseState::Escape3(i, ch.to_digit(8).unwrap());
                    } else {
                        return Err("Unrecognized label code".into());
                    }
                }
                ParseState::Escape3(i, ii) => {
                    if ch.is_numeric() {
                        // octal conversion
                        let val: u32 = (i * 8 * 8) + (ii * 8) + ch.to_digit(8).unwrap();
                        let new: char = char::from_u32(val).unwrap();
                        label.push(new);
                        state = ParseState::Label;
                    } else {
                        return Err("unrecognized char".into());
                    }
                }
            }
        }

        if !label.is_empty() {
            name = name.append_label(E::to_label(&label)?)?;
        }

        if local.ends_with('.') {
            name.set_fqdn(true);
        } else if let Some(other) = origin {
            return name.append_domain(other);
        }

        Ok(name)
    }

    pub fn from_ascii<S: AsRef<str>>(name: S) -> Result<Self, String> {
        Self::from_encoded_str::<LabelEncAscii>(name.as_ref(), None)
    }

    fn write_labels<W: Write, E: LabelEnc>(&self, f: &mut W) -> Result<(), fmt::Error> {
        let mut iter = self.iter().map(|b| Label::from_raw_bytes(b).unwrap());
        if let Some(label) = iter.next() {
            E::write_label(f, &label)?;
        }

        for label in iter {
            write!(f, ".")?;
            E::write_label(f, &label)?;
        }

        // if it was the root name
        if self.is_root() || self.is_fqdn() {
            write!(f, ".")?;
        }
        Ok(())
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.is_fqdn.hash(state);

        // this needs to be CaseInsensitive like PartialEq
        for l in self
            .iter()
            .map(|l| Label::from_raw_bytes(l).unwrap().to_lowercase())
        {
            l.hash(state);
        }
    }
}

trait LabelEnc {
    fn to_label(name: &str) -> Result<Label, String>;
    fn write_label<W: Write>(f: &mut W, label: &Label) -> Result<(), fmt::Error>;
}

struct LabelEncAscii;
impl LabelEnc for LabelEncAscii {
    fn to_label(name: &str) -> Result<Label, String> {
        Label::from_ascii(name)
    }
    fn write_label<W: Write>(f: &mut W, label: &Label) -> Result<(), fmt::Error> {
        label.write_ascii(f)
    }
}

impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl FromStr for Name {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_ascii(s)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_labels::<fmt::Formatter<'_>, LabelEncAscii>(f)
    }
}
