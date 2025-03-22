use serde::{Deserialize, Serialize};

use crate::rr::dnssec::rdata::sig::SIG;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Deserialize, Serialize)]
pub struct RRSIG(SIG);
