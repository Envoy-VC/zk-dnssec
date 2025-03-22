use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum Algorithm {
    /// For now only support ECDSA P-256 with SHA-256
    ECDSAP256SHA256,
}
