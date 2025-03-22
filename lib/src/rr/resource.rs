#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Eq, Debug, Clone)]
pub struct Record<R: RecordData = RData> {
    name_labels: Name,
    rr_type: RecordType,
    dns_class: DNSClass,
    ttl: u32,
    rdata: Option<R>,
}