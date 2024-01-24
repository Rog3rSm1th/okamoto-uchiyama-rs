use crate::error::OkamotoUchiyamaError;
use crate::pem::{Asn1Encode, PemEncodable};

use base64::engine::general_purpose;
use base64::Engine;
use num::One;
use num_bigint_dig::BigUint;
use std::fmt;

pub use crate::crypto::private_key::PrivateKey;

/// Represents an Okamoto-Uchiyama public key.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    // modulus: p^2 * q
    pub n: BigUint,
    // Random integer in the range [2, n - 1]
    pub g: BigUint,
    // g^n mod n
    pub h: BigUint,
}

impl PublicKey {
    /// Generate a public key from n, g, and h
    pub fn new(n: &BigUint, g: &BigUint, h: &BigUint) -> PublicKey {
        PublicKey {
            n: n.clone(),
            g: g.clone(),
            h: h.clone(),
        }
    }

    /// Performs homomorphic operation over two passed ciphers.
    /// Okamoto-Uchiyama has additive homomorphic property, so resultant cipher
    /// contains the sum of two numbers.
    pub fn homomorphic_encrypt_two(
        self,
        c1: &BigUint,
        c2: &BigUint,
    ) -> Result<BigUint, OkamotoUchiyamaError> {
        if c1 == &self.n || c2 == &self.n {
            return Err(OkamotoUchiyamaError::CipherTooLarge);
        }

        // Calculate the product of the two ciphers and take the modulus by the public key n.
        Ok((c1 * c2) % &self.n)
    }

    /// Performs homomorphic operation over multiple passed ciphers.
    /// Okamoto-Uchiyama has additive homomorphic property, so resultant cipher
    /// contains the sum of multiple numbers.
    pub fn homomorphic_encrypt_multiple(
        self,
        ciphers: Vec<&BigUint>,
    ) -> Result<BigUint, OkamotoUchiyamaError> {
        // Check if any cipher in the vector is equal to the public key n.
        if ciphers.contains(&&self.n) {
            return Err(OkamotoUchiyamaError::CipherTooLarge);
        }

        // Calculate the product of all ciphers in the vector and return it.
        let mut c = BigUint::one();
        for cipher in ciphers {
            c = &c * cipher;
        }
        Ok(c)
    }

    /// Convert the public key to ASN.1 DER format
    pub fn to_der(&self) -> Vec<u8> {
        let mut der = Vec::new();
        der.extend_from_slice(&self.n.to_asn1_der());
        der.extend_from_slice(&self.g.to_asn1_der());
        der.extend_from_slice(&self.h.to_asn1_der());
        der
    }
}

// Implements Display trait for the PublicKey struct
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey {{\n  n: {},\n  g: {},\n  h: {}\n}}",
            self.n, self.g, self.h
        )
    }
}

/// Implements the PemEncodable trait for PublicKey struct
impl PemEncodable for PublicKey {
    fn to_pem(&self) -> String {
        let mut pem = String::new();
        pem.push_str("-----BEGIN PUBLIC KEY-----\n");
        pem.push_str(&general_purpose::STANDARD.encode(&self.to_der()));
        pem.push_str("\n-----END PUBLIC KEY-----\n");
        pem
    }
}
