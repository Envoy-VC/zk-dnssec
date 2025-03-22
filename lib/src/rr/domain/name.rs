use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

use crate::rr::domain::label::Label;

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
