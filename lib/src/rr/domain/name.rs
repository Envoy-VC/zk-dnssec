use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

use crate::{rr::domain::label::Label, serialize::binary::BinEncoder};

#[derive(Clone, Default, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Name {
    is_fqdn: bool,
    label_data: Vec<u8>, // 24 Length,
    label_ends: Vec<u8>, // 32 Length
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
            .map(|l| Label::from_raw_bytes(l))
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
