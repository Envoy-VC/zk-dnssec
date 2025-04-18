use serde::{Deserialize, Serialize};

use crate::rr::dnssec::algorithm::Algorithm;
use crate::rr::domain::name::Name;
use crate::rr::record_type::RecordType;
use crate::serialize::binary::{BinEncodable, BinEncoder};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Deserialize, Serialize)]
pub struct SIG {
    pub type_covered: RecordType,
    pub algorithm: Algorithm,
    pub num_labels: u8,
    pub original_ttl: u32,
    pub sig_expiration: u32,
    pub sig_inception: u32,
    pub key_tag: u16,
    pub signer_name: Name,
    pub sig: Vec<u8>,
}

impl SIG {
    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.3), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.3 Labels Field
    ///
    ///  The "labels" octet is an unsigned count of how many labels there are
    ///  in the original SIG RR owner name not counting the null label for
    ///  root and not counting any initial "*" for a wildcard.  If a secured
    ///  retrieval is the result of wild card substitution, it is necessary
    ///  for the resolver to use the original form of the name in verifying
    ///  the digital signature.  This field makes it easy to determine the
    ///  original form.
    ///
    ///  If, on retrieval, the RR appears to have a longer name than indicated
    ///  by "labels", the resolver can tell it is the result of wildcard
    ///  substitution.  If the RR owner name appears to be shorter than the
    ///  labels count, the SIG RR must be considered corrupt and ignored.  The
    ///  maximum number of labels allowed in the current DNS is 127 but the
    ///  entire octet is reserved and would be required should DNS names ever
    ///  be expanded to 255 labels.  The following table gives some examples.
    ///  The value of "labels" is at the top, the retrieved owner name on the
    ///  left, and the table entry is the name to use in signature
    ///  verification except that "bad" means the RR is corrupt.
    ///
    ///  labels= |  0  |   1  |    2   |      3   |      4   |
    ///  --------+-----+------+--------+----------+----------+
    ///         .|   . | bad  |  bad   |    bad   |    bad   |
    ///        d.|  *. |   d. |  bad   |    bad   |    bad   |
    ///      c.d.|  *. | *.d. |   c.d. |    bad   |    bad   |
    ///    b.c.d.|  *. | *.d. | *.c.d. |   b.c.d. |    bad   |
    ///  a.b.c.d.|  *. | *.d. | *.c.d. | *.b.c.d. | a.b.c.d. |
    /// ```
    pub fn num_labels(&self) -> u8 {
        self.num_labels
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.1), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.1 Type Covered Field
    ///
    ///  The "type covered" is the type of the other RRs covered by this SIG.
    /// ```
    pub fn type_covered(&self) -> RecordType {
        self.type_covered
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.2), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.2 Algorithm Number Field
    ///
    ///  This octet is as described in section 3.2.
    /// ```
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.4), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.4 Original TTL Field
    ///
    ///  The "original TTL" field is included in the RDATA portion to avoid
    ///  (1) authentication problems that caching servers would otherwise
    ///  cause by decrementing the real TTL field and (2) security problems
    ///  that unscrupulous servers could otherwise cause by manipulating the
    ///  real TTL field.  This original TTL is protected by the signature
    ///  while the current TTL field is not.
    ///
    ///  NOTE:  The "original TTL" must be restored into the covered RRs when
    ///  the signature is verified (see Section 8).  This generally implies
    ///  that all RRs for a particular type, name, and class, that is, all the
    ///  RRs in any particular RRset, must have the same TTL to start with.
    /// ```
    pub fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.5), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.5 Signature Expiration and Inception Fields
    ///
    ///  The SIG is valid from the "signature inception" time until the
    ///  "signature expiration" time.  Both are unsigned numbers of seconds
    ///  since the start of 1 January 1970, GMT, ignoring leap seconds.  (See
    ///  also Section 4.4.)  Ring arithmetic is used as for DNS SOA serial
    ///  numbers [RFC 1982] which means that these times can never be more
    ///  than about 68 years in the past or the future.  This means that these
    ///  times are ambiguous modulo ~136.09 years.  However there is no
    ///  security flaw because keys are required to be changed to new random
    ///  keys by [RFC 2541] at least every five years.  This means that the
    ///  probability that the same key is in use N*136.09 years later should
    ///  be the same as the probability that a random guess will work.
    ///
    ///  A SIG RR may have an expiration time numerically less than the
    ///  inception time if the expiration time is near the 32 bit wrap around
    ///  point and/or the signature is long lived.
    ///
    ///  (To prevent misordering of network requests to update a zone
    ///  dynamically, monotonically increasing "signature inception" times may
    ///  be necessary.)
    ///
    ///  A secure zone must be considered changed for SOA serial number
    ///  purposes not only when its data is updated but also when new SIG RRs
    ///  are inserted (ie, the zone or any part of it is re-signed).
    /// ```
    pub fn sig_expiration(&self) -> u32 {
        self.sig_expiration
    }

    /// See [`SIG::sig_expiration`]
    pub fn sig_inception(&self) -> u32 {
        self.sig_inception
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.6), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.6 Key Tag Field
    ///
    ///  The "key Tag" is a two octet quantity that is used to efficiently
    ///  select between multiple keys which may be applicable and thus check
    ///  that a public key about to be used for the computationally expensive
    ///  effort to check the signature is possibly valid.  For algorithm 1
    ///  (MD5/RSA) as defined in [RFC 2537], it is the next to the bottom two
    ///  octets of the public key modulus needed to decode the signature
    ///  field.  That is to say, the most significant 16 of the least
    ///  significant 24 bits of the modulus in network (big endian) order. For
    ///  all other algorithms, including private algorithms, it is calculated
    ///  as a simple checksum of the KEY RR as described in Appendix C.
    /// ```
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.7), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.7 Signer's Name Field
    ///
    ///  The "signer's name" field is the domain name of the signer generating
    ///  the SIG RR.  This is the owner name of the public KEY RR that can be
    ///  used to verify the signature.  It is frequently the zone which
    ///  contained the RRset being authenticated.  Which signers should be
    ///  authorized to sign what is a significant resolver policy question as
    ///  discussed in Section 6. The signer's name may be compressed with
    ///  standard DNS name compression when being transmitted over the
    ///  network.
    /// ```
    pub fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
}

impl BinEncodable for SIG {
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034#section-6), DNSSEC Resource Records, March 2005
    ///
    /// This is accurate for all currently known name records.
    ///
    /// ```text
    /// 6.2.  Canonical RR Form
    ///
    ///    For the purposes of DNS security, the canonical form of an RR is the
    ///    wire format of the RR where:
    ///
    ///    ...
    ///
    ///    3.  if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
    ///        HINFO, MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
    ///        SRV, DNAME, A6, RRSIG, or (rfc6840 removes NSEC), all uppercase
    ///        US-ASCII letters in the DNS names contained within the RDATA are replaced
    ///        by the corresponding lowercase US-ASCII letters;
    /// ```
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String> {
        let is_canonical_names = encoder.is_canonical_names();

        self.type_covered().emit(encoder)?;
        self.algorithm().emit(encoder)?;
        encoder.emit(self.num_labels())?;
        encoder.emit_u32(self.original_ttl())?;
        encoder.emit_u32(self.sig_expiration())?;
        encoder.emit_u32(self.sig_inception())?;
        encoder.emit_u16(self.key_tag())?;
        self.signer_name()
            .emit_with_lowercase(encoder, is_canonical_names)?;
        encoder.emit_vec(self.sig())?;
        Ok(())
    }
}
