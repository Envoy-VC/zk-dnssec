use crate::rr::dns_class::DNSClass;
use crate::rr::dnssec::rdata::sig::SIG;
use crate::rr::domain::name::Name;
use crate::rr::resource::Record;

//                      Reconstructing the Signed Data
//
//          signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
//
//             "|" denotes concatenation
//
//             RRSIG_RDATA is the wire format of the RRSIG RDATA fields
//                with the Signature field excluded and the Signer's Name
//                in canonical form.
//
//             RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
//
//                name is calculated according to the function below
//
//                class is the RRset's class
//
//                type is the RRset type and all RRs in the class
//
//                OrigTTL is the value from the RRSIG Original TTL field
//
//                All names in the RDATA field are in canonical form
//
//                The set of all RR(i) is sorted into canonical order.
//
//             To calculate the name:
//                let rrsig_labels = the value of the RRSIG Labels field
//
//                let fqdn = RRset's fully qualified domain name in
//                                canonical form
//
//                let fqdn_labels = Label count of the fqdn above.
//
//                if rrsig_labels = fqdn_labels,
//                    name = fqdn
//
//                if rrsig_labels < fqdn_labels,
//                   name = "*." | the rightmost rrsig_label labels of the
//                                 fqdn
//
//                if rrsig_labels > fqdn_labels
//                   the RRSIG RR did not pass the necessary validation
//                   checks and MUST NOT be used to authenticate this
//                   RRset.

/// Returns the to-be-signed serialization of the given record set using the information
/// provided from the SIG record.
///
/// # Arguments
///
/// * `name` - labels of the record to sign
/// * `dns_class` - DNSClass of the RRSet, i.e. IN
/// * `sig` - SIG or RRSIG record, which was produced from the RRSet
/// * `records` - RRSet records to sign with the information in the `rrsig`
///
/// # Return
///
/// * `Vec<u8>` - the to-be-signed serialization of the given record set
pub fn construct_rrset_message_with_sig(
    name: &Name,
    dns_class: DNSClass,
    sig: &SIG,
    records: &[Record],
) -> Vec<u8> {
    // TODO: Implement

    // 1. Sort the records

    let num_labels = sig.num_labels();
    let type_covered = sig.type_covered();
    let algorithm = sig.algorithm();
    let original_ttl = sig.original_ttl();
    let sig_expiration = sig.sig_expiration();
    let sig_inception = sig.sig_inception();
    let key_tag = sig.key_tag();
    let signer_name = sig.signer_name();

    Vec::new()
}

pub fn determine_name(name: &Name, num_labels: u8) -> Result<Name, String> {
    //             To calculate the name:
    //                let rrsig_labels = the value of the RRSIG Labels field
    //
    //                let fqdn = RRset's fully qualified domain name in
    //                                canonical form
    //
    //                let fqdn_labels = Label count of the fqdn above.
    let fqdn_labels = name.num_labels();
    //                if rrsig_labels = fqdn_labels,
    //                    name = fqdn

    if fqdn_labels == num_labels {
        return Ok(name.clone());
    }
    //                if rrsig_labels < fqdn_labels,
    //                   name = "*." | the rightmost rrsig_label labels of the
    //                                 fqdn
    if num_labels < fqdn_labels {
        let mut star_name: Name = Name::from_labels(vec![b"*" as &[u8]]).unwrap();
        let rightmost = name.trim_to(num_labels as usize);
        if !rightmost.is_root() {
            star_name = star_name.append_name(&rightmost)?;
            return Ok(star_name);
        }
        return Ok(star_name);
    }
    //
    //                if rrsig_labels > fqdn_labels
    //                   the RRSIG RR did not pass the necessary validation
    //                   checks and MUST NOT be used to authenticate this
    //                   RRset.

    Err("could not determine name".into())
}
