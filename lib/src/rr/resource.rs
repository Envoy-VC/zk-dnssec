use serde::{Deserialize, Serialize};

use crate::rr::dns_class::DNSClass;
use crate::rr::domain::name::Name;
use crate::rr::record_data::RData;
use crate::rr::record_type::RecordType;

#[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
pub struct Record {
    name_labels: Name,
    rr_type: RecordType,
    dns_class: DNSClass,
    ttl: u32,
    rdata: RData,
}
