use trust_dns_client::rr::rdata::DNSKEY;
use trust_dns_client::rr::rdata::RRSIG;
use trust_dns_client::rr::Record;
use trust_dns_client::rr::RecordData;
use trust_dns_client::rr::RecordType;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

use zkdnssec_lib::rr::dns_class::DNSClass as ZKDNSClass;
use zkdnssec_lib::rr::dnssec::algorithm::Algorithm as ZKAlgorithm;
use zkdnssec_lib::rr::dnssec::rdata::sig::SIG as ZKSIG;
use zkdnssec_lib::rr::domain::name::Name as ZKName;
use zkdnssec_lib::rr::rdata::txt::TXT as ZKTXT;
use zkdnssec_lib::rr::record_type::RecordType as ZKRecordType;
use zkdnssec_lib::rr::resource::Record as ZKRecord;

fn create_resolver() -> Result<Resolver, Box<dyn std::error::Error>> {
    let resolver_config = ResolverConfig::google();
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.validate = false;
    resolver_opts.edns0 = true;
    let resolver = Resolver::new(resolver_config, resolver_opts)?;
    Ok(resolver)
}

fn get_txt_records(domain: &str) -> Result<(Record, Record), Box<dyn std::error::Error>> {
    let resolver = create_resolver()?;

    let txt_response = resolver.lookup(domain, RecordType::TXT)?;

    let rrsig_response = resolver.lookup(domain, RecordType::RRSIG)?;

    let txt_records = txt_response.records().first().unwrap();
    let rrsig_records = rrsig_response
        .records()
        .iter()
        .find(|r| {
            let data = RRSIG::try_from_rdata(r.data().unwrap().clone()).unwrap();
            data.type_covered() == RecordType::TXT
        })
        .unwrap();

    Ok((txt_records.clone(), rrsig_records.clone()))
}

fn get_dnskey(domain: &str) -> Result<Record, Box<dyn std::error::Error>> {
    let resolver = create_resolver()?;

    let dns_key_response = resolver.lookup(domain, RecordType::DNSKEY)?;

    let dns_key_records = dns_key_response
        .records()
        .iter()
        .find(|r| {
            let data = match r.data() {
                Some(data) => data.clone(),
                None => panic!("No data found"),
            };

            DNSKEY::try_from_rdata(data.clone()).is_ok()
        })
        .unwrap();

    Ok(dns_key_records.clone())
}

pub struct Inputs {
    pub pub_key: Vec<u8>,
    pub name: ZKName,
    pub dns_class: ZKDNSClass,
    pub rrsig: ZKSIG,
    pub record: ZKRecord,
    pub signature: Vec<u8>,
}

pub fn generate_inputs(domain: &str) -> Result<Inputs, Box<dyn std::error::Error>> {
    let (txt_record, rrsig_record) = get_txt_records(domain)?;
    let dns_key_record = get_dnskey(domain)?;

    let rrsig = match RRSIG::try_from_rdata(rrsig_record.data().unwrap().clone()) {
        Ok(rrsig) => rrsig,
        Err(e) => panic!(
            "Failed to convert RRSIG record into structured form: {:?}",
            e
        ),
    };

    let dns_key = match DNSKEY::try_from_rdata(dns_key_record.data().unwrap().clone()) {
        Ok(key) => key,
        Err(e) => panic!(
            "Failed to convert DNSKEY record into structured form: {:?}",
            e
        ),
    };

    let pub_key = dns_key.public_key();

    let sec1_pubkey = if pub_key.len() == 64 {
        let mut buf = Vec::with_capacity(65);
        buf.push(0x04);
        buf.extend_from_slice(pub_key);
        buf
    } else {
        pub_key.to_vec()
    };

    let signature = rrsig.sig().to_vec();

    let zk_name = ZKName::from_ascii("envoy1084.xyz").unwrap();
    let zk_dns_class: ZKDNSClass = ZKDNSClass::IN;
    let zk_type_covered = ZKRecordType::TXT;
    let zk_algorithm = ZKAlgorithm::ECDSAP256SHA256;
    let zk_signer_name = ZKName::from_ascii(rrsig.signer_name().to_ascii()).unwrap();

    let zk_rrsig = ZKSIG {
        type_covered: zk_type_covered,
        algorithm: zk_algorithm,
        num_labels: rrsig.num_labels(),
        original_ttl: rrsig.original_ttl(),
        sig_expiration: rrsig.sig_expiration(),
        sig_inception: rrsig.sig_inception(),
        key_tag: rrsig.key_tag(),
        signer_name: zk_signer_name,
        sig: signature.clone(),
    };

    let data: Box<[Box<[u8]>]> = txt_record
        .data()
        .unwrap()
        .clone()
        .into_txt()
        .unwrap()
        .txt_data()
        .iter()
        .cloned()
        .collect();

    let zk_rdata = ZKTXT { txt_data: data };
    let zk_record = ZKRecord {
        name_labels: ZKName::from_ascii(txt_record.name().to_ascii()).unwrap(),
        rr_type: ZKRecordType::TXT,
        dns_class: ZKDNSClass::IN,
        ttl: rrsig.original_ttl(),
        rdata: Some(zk_rdata.into_rdata()),
    };

    let inputs = Inputs {
        pub_key: sec1_pubkey,
        name: zk_name,
        dns_class: zk_dns_class,
        rrsig: zk_rrsig,
        record: zk_record,
        signature: signature.clone(),
    };

    Ok(inputs)
}
