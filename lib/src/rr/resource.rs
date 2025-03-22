use serde::{Deserialize, Serialize};

use crate::rr::dns_class::DNSClass;
use crate::rr::domain::name::Name;
use crate::rr::record_data::RData;
use crate::rr::record_type::RecordType;

#[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
pub struct Record {
    pub name_labels: Name,
    pub rr_type: RecordType,
    pub dns_class: DNSClass,
    pub ttl: u32,
    pub rdata: Option<RData>,
}

impl Record {
    #[inline]
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    #[inline]
    pub fn record_type(&self) -> RecordType {
        self.rr_type
    }

    #[inline]
    pub fn name(&self) -> &Name {
        &self.name_labels
    }

    #[inline]
    pub fn data(&self) -> Option<&RData> {
        self.rdata.as_ref()
    }
}
