use crate::crypto::ciphertext::Ciphertext;
use crate::error::OkamotoUchiyamaError;
use crate::pem::PemEncodable;

use asn1::BigUint as Asn1BigUint;
use asn1::ParseError;
use base64::engine::general_purpose;
use base64::engine::general_purpose::STANDARD;
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

    /// Decode a PEM-encoded public key string into a PublicKey instance
    pub fn from_pem(pem: &str) -> Result<Self, OkamotoUchiyamaError> {
        // Trim the starting and ending spaces/newlines
        let pem = pem.trim();

        // Check if the PEM string starts and ends with the correct tags
        if !pem.starts_with("-----BEGIN PUBLIC KEY-----")
            || !pem.ends_with("-----END PUBLIC KEY-----")
        {
            return Err(OkamotoUchiyamaError::PemDecodingError);
        }

        // Extract the base64-encoded ASN.1 sequence between the tags
        let base64_encoded = pem
            .trim_start_matches("-----BEGIN PUBLIC KEY-----")
            .trim_end_matches("-----END PUBLIC KEY-----")
            .trim();

        // Decode the base64-encoded ASN.1 sequence using Engine::decode
        let asn1_decoded = STANDARD
            .decode(base64_encoded)
            .map_err(|_| OkamotoUchiyamaError::PemDecodingError)?;

        // Parse the ASN.1 sequence into the PublicKey struct
        let (n, g, h) =
            asn1::parse::<_, ParseError, _>(&asn1_decoded, |d: &mut asn1::Parser<'_>| {
                d.read_element::<asn1::Sequence>()?
                    .parse::<_, ParseError, _>(|d| {
                        // Parse ASN.1 BigUint elements
                        let n_asn1 = d.read_element::<Asn1BigUint>()?;
                        let g_asn1 = d.read_element::<Asn1BigUint>()?;
                        let h_asn1 = d.read_element::<Asn1BigUint>()?;

                        // Convert ASN.1 BigUint to BigUint
                        let n_bytes = n_asn1.as_bytes();
                        let g_bytes = g_asn1.as_bytes();
                        let h_bytes = h_asn1.as_bytes();

                        // Convert bytes back to BigUint
                        let n = BigUint::from_bytes_be(&n_bytes);
                        let g = BigUint::from_bytes_be(&g_bytes);
                        let h = BigUint::from_bytes_be(&h_bytes);

                        Ok((n, g, h))
                    })
            })
            .map_err(|_| OkamotoUchiyamaError::PemDecodingError)?;

        // Create and return PublicKey instance
        Ok(PublicKey::new(&n, &g, &h))
    }

    /// Performs homomorphic operation over two passed ciphertexts.
    /// Okamoto-Uchiyama has additive homomorphic property, so the resultant ciphertext
    /// contains the sum of two numbers.
    pub fn homomorphic_encrypt_two(
        &self,
        c1: &Ciphertext,
        c2: &Ciphertext,
    ) -> Result<Ciphertext, OkamotoUchiyamaError> {
        if c1.value() == &self.n || c2.value() == &self.n {
            return Err(OkamotoUchiyamaError::CipherTooLarge);
        }

        // Calculate the product of the two ciphertexts and take the modulus by the public key n.
        let result_value = (c1.value() * c2.value()) % &self.n;
        Ok(Ciphertext::new(result_value))
    }

    /// Performs homomorphic operation over multiple passed ciphertexts.
    /// Okamoto-Uchiyama has additive homomorphic property, so the resultant ciphertext
    /// contains the sum of multiple numbers.
    pub fn homomorphic_encrypt_multiple(
        &self,
        ciphers: Vec<&Ciphertext>,
    ) -> Result<Ciphertext, OkamotoUchiyamaError> {
        // Check if any ciphertext in the vector has the same value as the public key n.
        if ciphers.iter().any(|&cipher| cipher.value() == &self.n) {
            return Err(OkamotoUchiyamaError::CipherTooLarge);
        }

        // Calculate the product of all ciphertexts in the vector and return it.
        let mut result = BigUint::one();
        for cipher in ciphers {
            result = &result * cipher.value();
        }
        let result_value = result % &self.n;
        Ok(Ciphertext::new(result_value))
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

        // Convert public key components to ASN.1
        let n_bytes = self.n.clone().to_bytes_be();
        let n_asn1 = Asn1BigUint::new(&n_bytes);

        let g_bytes = self.g.clone().to_bytes_be();
        let g_asn1 = Asn1BigUint::new(&g_bytes);

        let h_bytes = self.h.clone().to_bytes_be();
        let h_asn1 = Asn1BigUint::new(&h_bytes);

        // Write all elements to ASN.1 Sequence
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&n_asn1)?; // Add n to the sequence
                w.write_element(&g_asn1)?; // Add g to the sequence
                w.write_element(&h_asn1)?; // Add h to the sequence
                Ok(())
            }))
        });

        // Encode the ASN.1 sequence using Base64
        pem.push_str("-----BEGIN PUBLIC KEY-----\n");
        pem.push_str(&general_purpose::STANDARD.encode(result.unwrap_or_else(|_| vec![])));
        pem.push_str("\n-----END PUBLIC KEY-----\n");

        pem
    }
}
