use std::{fmt::Display, sync::Arc};

use bitcoin_hashes::{hash160, sha256, Hash};
use hex_conservative::FromHex;
use hex_conservative::{DisplayHex, HexToArrayError};
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HtlcPreimage([u8; 32]);


impl HtlcPreimage {
    pub fn new(datum: [u8; 32]) -> Self {
        HtlcPreimage(datum)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.to_lower_hex_string()
    }

    pub fn to_hash(&self) -> HtlcHash {
        HtlcHash::from_preimage(&self)
    }
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HtlcHash([u8; 20]);

impl HtlcHash {
    pub fn new(datum: [u8; 20]) -> Self {
        HtlcHash(datum)
    }

    pub fn from_preimage(preimage: &HtlcPreimage) -> Self {
        HtlcHash::new(hash160::Hash::hash(preimage.as_bytes()).to_byte_array())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; 20] {
        self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.to_lower_hex_string()
    }

    pub fn raw_hash(&self) -> hash160::Hash {
        Hash::from_byte_array(self.0)
    }

    pub fn from_hex(value: &str) -> Result<Self, HexToArrayError> {
        <[u8; 20]>::from_hex(value).map(HtlcHash)
    }
}

impl Display for HtlcHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
