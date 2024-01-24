use crate::crypto::okamoto_uchiyama::PublicKey;
use crate::pem::{Asn1Encode, PemEncodable};
use base64::{engine::general_purpose, Engine as _};
use num_bigint_dig::BigUint;
use std::fmt;

/// PrivateKey represents an Okamoto-Uchiyama private key.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct PrivateKey {
    // The public key corresponding to this private key
    pub public_key: PublicKey,
    // gd = g^(p-1) mod p^2, not mandatory, here to ease calculations
    pub gd: BigUint,
    // A large prime p,
    pub p: BigUint,
    // A large prime q
    pub q: BigUint,
    // p_squared = p^2,  not mandatory, here to ease calculations
    pub p_squared: BigUint,
}

impl PrivateKey {
    /// Generate a new private key from p, q, and a public key
    pub fn new(public_key: &PublicKey, p: &BigUint, q: &BigUint) -> PrivateKey {
        let public_key = public_key.clone();
        let p = p.clone();
        let q = q.clone();

        // Generate p^2
        let p_squared = &p * &p;
        // Generate gd
        let gd = public_key.g.modpow(&(&p - &1u32), &p_squared) % &p_squared;

        PrivateKey {
            public_key,
            gd,
            p,
            q,
            p_squared,
        }
    }

    /// Convert the private key to ASN.1 DER format
    pub fn to_der(&self) -> Vec<u8> {
        let mut der = Vec::new();
        der.extend_from_slice(&self.public_key.to_der());
        der.extend_from_slice(&self.gd.to_asn1_der());
        der.extend_from_slice(&self.p.to_asn1_der());
        der.extend_from_slice(&self.q.to_asn1_der());
        der.extend_from_slice(&self.p_squared.to_asn1_der());
        der
    }
}

// Implementation of the Display trait for the PrivateKey struct
impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivateKey {{
  public_key: {},
  gd: {},
  p: {},
  q: {},
  p_squared: {}
}}",
            self.public_key, self.gd, self.p, self.q, self.p_squared
        )
    }
}

/// Implements the PemEncodable trait for PrivateKey struct
impl PemEncodable for PrivateKey {
    fn to_pem(&self) -> String {
        let mut pem = String::new();
        pem.push_str("-----BEGIN PRIVATE KEY-----\n");
        pem.push_str(&general_purpose::STANDARD.encode(&self.to_der()));
        pem.push_str("\n-----END PRIVATE KEY-----\n");
        pem
    }
}
