use hex::encode;

use trust_dns_client::rr::rdata::DNSKEY;
use trust_dns_client::rr::rdata::RRSIG;
use trust_dns_client::rr::rdata::TXT;
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

fn convert_to_ascii(data: &[Box<[u8]>]) -> Vec<String> {
    data.iter()
        .map(|boxed_slice| {
            match std::str::from_utf8(boxed_slice) {
                Ok(s) => s.to_string(),
                Err(_) => format!("{:?}", boxed_slice), // Handle non-ASCII data gracefully
            }
        })
        .collect()
}

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

            data.type_covered() == RecordType::TXT && data.signer_name() == txt_records.name()
        })
        .unwrap();

    Ok((txt_records.clone(), rrsig_records.clone()))
}

fn get_dnskey(domain: &str, key_tag: u16) -> Result<DNSKEY, Box<dyn std::error::Error>> {
    let resolver = create_resolver()?;

    let dns_key_response = resolver.lookup(domain, RecordType::DNSKEY)?;

    let dns_keys: Vec<DNSKEY> = dns_key_response
        .records()
        .iter()
        .map(|r| {
            let r_data = r.data().unwrap();
            DNSKEY::try_from_rdata(r_data.clone()).unwrap()
        })
        .collect(); // Store in a variable first

    let dns_key = dns_keys
        .iter()
        .find(|k| {
            let calculated = k.calculate_key_tag().unwrap();
            calculated == key_tag
        })
        .unwrap();

    Ok(dns_key.clone())
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
    let txt: TXT = txt_record.data().unwrap().clone().into_txt().unwrap();
    let rrsig = match RRSIG::try_from_rdata(rrsig_record.data().unwrap().clone()) {
        Ok(rrsig) => rrsig,
        Err(e) => panic!(
            "Failed to convert RRSIG record into structured form: {:?}",
            e
        ),
    };

    let dns_key = get_dnskey(domain, rrsig.key_tag())?;

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

    println!("\n\nDomain: {:?}", domain);

    println!("\n======================== Record Details ========================\n");
    println!("Name Labels: {:?}", txt_record.name().clone());
    println!("Record Type: {:?}", txt_record.record_type().clone());
    println!("DNS Class: {:?}", txt_record.dns_class().clone());
    println!("TTL: {:?}", txt_record.ttl().clone());
    println!("RDATA: {:?}", convert_to_ascii(txt.txt_data()));

    println!("\n======================== Record Details ========================\n");
    println!(
        "Secure Entry Point: {:?}",
        dns_key.secure_entry_point().clone()
    );
    println!("Revoke: {:?}", dns_key.revoke().clone());
    println!("Key Tag: {:?}", dns_key.calculate_key_tag().clone());
    println!("Algorithm: {:?}", dns_key.algorithm().clone());
    println!("Zone Key: {:?}", dns_key.zone_key().clone());
    println!("Public Key: {:?}", encode(dns_key.public_key()));

    println!("\n======================== Record Details ========================\n");
    println!("Name Labels: {:?}", rrsig_record.name().clone());
    println!("Record Type: {:?}", rrsig_record.record_type().clone());
    println!("DNS Class: {:?}", rrsig_record.dns_class().clone());
    println!("TTL: {:?}", rrsig_record.ttl().clone());
    println!("Type Covered: {:?}", rrsig.type_covered().clone());
    println!("Algorithm: {:?}", rrsig.algorithm().clone());
    println!("No. of Labels: {:?}", rrsig.num_labels().clone());
    println!("Original TTL: {:?}", rrsig.original_ttl().clone());
    println!("Signature Expiration: {:?}", rrsig.sig_expiration().clone());
    println!("Signature Inception: {:?}", rrsig.sig_inception().clone());
    println!("Key Tag: {:?}", rrsig.key_tag().clone());
    println!("Signer Name: {:?}", rrsig.signer_name().clone());
    println!("Signature: {:?}\n", encode(signature.clone()));

    let zk_name = ZKName::from_ascii(domain).unwrap();
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
