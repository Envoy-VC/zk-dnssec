use serde::{Deserialize, Serialize};

use crate::serialize::binary::{BinEncodable, BinEncoder};

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Deserialize, Serialize)]
pub enum RecordType {
    A,
    AAAA,
    ANAME,
    ANY,
    AXFR,
    CAA,
    CDS,
    CDNSKEY,
    CNAME,
    CSYNC,
    DNSKEY,
    DS,
    HINFO,
    HTTPS,
    IXFR,
    KEY,
    MX,
    NAPTR,
    NS,
    NSEC,
    NSEC3,
    NSEC3PARAM,
    NULL,
    OPENPGPKEY,
    OPT,
    PTR,
    RRSIG,
    SIG,
    SOA,
    SRV,
    SSHFP,
    SVCB,
    TLSA,
    TSIG,
    TXT,
    Unknown(u16),
    ZERO,
}

impl RecordType {}

impl From<u16> for RecordType {
    /// Convert from `u16` to `RecordType`
    ///
    /// ```
    /// use trust_dns_proto::rr::record_type::RecordType;
    ///
    /// let var = RecordType::from(1);
    /// assert_eq!(RecordType::A, var);
    /// ```
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::AAAA,
            65305 => Self::ANAME,
            255 => Self::ANY,
            251 => Self::IXFR,
            252 => Self::AXFR,
            257 => Self::CAA,
            59 => Self::CDS,
            60 => Self::CDNSKEY,
            5 => Self::CNAME,
            62 => Self::CSYNC,
            48 => Self::DNSKEY,
            43 => Self::DS,
            13 => Self::HINFO,
            65 => Self::HTTPS,
            25 => Self::KEY,
            15 => Self::MX,
            35 => Self::NAPTR,
            2 => Self::NS,
            47 => Self::NSEC,
            50 => Self::NSEC3,
            51 => Self::NSEC3PARAM,
            10 => Self::NULL,
            61 => Self::OPENPGPKEY,
            41 => Self::OPT,
            12 => Self::PTR,
            46 => Self::RRSIG,
            24 => Self::SIG,
            6 => Self::SOA,
            33 => Self::SRV,
            44 => Self::SSHFP,
            64 => Self::SVCB,
            52 => Self::TLSA,
            250 => Self::TSIG,
            16 => Self::TXT,
            0 => Self::ZERO,
            // all unknown record types
            _ => Self::Unknown(value),
        }
    }
}

impl From<RecordType> for u16 {
    fn from(rt: RecordType) -> Self {
        match rt {
            RecordType::A => 1,
            RecordType::AAAA => 28,
            RecordType::ANAME => 65305,
            RecordType::ANY => 255,
            RecordType::AXFR => 252,
            RecordType::CAA => 257,
            RecordType::CDNSKEY => 60,
            RecordType::CDS => 59,
            RecordType::CNAME => 5,
            RecordType::CSYNC => 62,
            RecordType::DNSKEY => 48,
            RecordType::DS => 43,
            RecordType::HINFO => 13,
            RecordType::HTTPS => 65,
            RecordType::KEY => 25,
            RecordType::IXFR => 251,
            RecordType::MX => 15,
            RecordType::NAPTR => 35,
            RecordType::NS => 2,
            RecordType::NSEC => 47,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::NULL => 10,
            RecordType::OPENPGPKEY => 61,
            RecordType::OPT => 41,
            RecordType::PTR => 12,
            RecordType::RRSIG => 46,
            RecordType::SIG => 24,
            RecordType::SOA => 6,
            RecordType::SRV => 33,
            RecordType::SSHFP => 44,
            RecordType::SVCB => 64,
            RecordType::TLSA => 52,
            RecordType::TSIG => 250,
            RecordType::TXT => 16,
            RecordType::ZERO => 0,
            RecordType::Unknown(code) => code,
        }
    }
}

impl BinEncodable for RecordType {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String> {
        encoder.emit_u16((*self).into())
    }
}
