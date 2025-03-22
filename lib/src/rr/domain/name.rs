use serde::{Deserialize, Serialize};

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

    pub fn num_labels(&self) -> u8 {
        // it is illegal to have more than 256 labels.

        let num = self.label_ends.len() as u8;

        self.iter()
            .next()
            .map(|l| if l == b"*" { num - 1 } else { num })
            .unwrap_or(num)
    }
}
