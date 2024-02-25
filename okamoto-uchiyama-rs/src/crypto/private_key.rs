use crate::crypto::okamoto_uchiyama::PublicKey;
use crate::error::OkamotoUchiyamaError;
use crate::pem::PemEncodable;

use asn1::BigUint as Asn1BigUint;
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

    /// Decode a PEM-encoded private key string into a PrivateKey instance
    pub fn from_pem(pem: &str) -> Result<Self, OkamotoUchiyamaError> {
        // Trim the starting and ending spaces/newlines
        let pem = pem.trim();

        // Check if the PEM string starts and ends with the correct tags
        if !pem.starts_with("-----BEGIN PRIVATE KEY-----")
            || !pem.ends_with("-----END PRIVATE KEY-----")
        {
            return Err(OkamotoUchiyamaError::PemDecodingError);
        }

        // Extract the base64-encoded ASN.1 sequence between the tags
        let base64_encoded = pem
            .trim_start_matches("-----BEGIN PRIVATE KEY-----")
            .trim_end_matches("-----END PRIVATE KEY-----")
            .trim();

        // Decode the base64-encoded ASN.1 sequence using Engine::decode
        let asn1_decoded = general_purpose::STANDARD
            .decode(base64_encoded)
            .map_err(|_| OkamotoUchiyamaError::PemDecodingError)?;

        // Parse the ASN.1 sequence into the PrivateKey struct
        let (n, g, h, gd, p, q, p_squared) =
            asn1::parse::<_, asn1::ParseError, _>(&asn1_decoded, |d: &mut asn1::Parser<'_>| {
                d.read_element::<asn1::Sequence>()?
                    .parse::<_, asn1::ParseError, _>(|d| {
                        // Parse ASN.1 BigUint elements
                        let n_asn1 = d.read_element::<Asn1BigUint>()?;
                        let g_asn1 = d.read_element::<Asn1BigUint>()?;
                        let h_asn1 = d.read_element::<Asn1BigUint>()?;
                        let gd_asn1 = d.read_element::<Asn1BigUint>()?;
                        let p_asn1 = d.read_element::<Asn1BigUint>()?;
                        let q_asn1 = d.read_element::<Asn1BigUint>()?;
                        let p_squared_asn1 = d.read_element::<Asn1BigUint>()?;

                        // Convert ASN.1 BigUint to BigUint
                        let n_bytes = n_asn1.as_bytes();
                        let g_bytes = g_asn1.as_bytes();
                        let h_bytes = h_asn1.as_bytes();
                        let gd_bytes = gd_asn1.as_bytes();
                        let p_bytes = p_asn1.as_bytes();
                        let q_bytes = q_asn1.as_bytes();
                        let p_squared_bytes = p_squared_asn1.as_bytes();

                        // Convert bytes back to BigUint
                        let n = BigUint::from_bytes_be(&n_bytes);
                        let g = BigUint::from_bytes_be(&g_bytes);
                        let h = BigUint::from_bytes_be(&h_bytes);
                        let gd = BigUint::from_bytes_be(&gd_bytes);
                        let p = BigUint::from_bytes_be(&p_bytes);
                        let q = BigUint::from_bytes_be(&q_bytes);
                        let p_squared = BigUint::from_bytes_be(&p_squared_bytes);

                        Ok((n, g, h, gd, p, q, p_squared))
                    })
            })
            .map_err(|_| OkamotoUchiyamaError::PemDecodingError)?;

        // Create and return PrivateKey instance
        let public_key = PublicKey::new(&n, &g, &h);
        Ok(PrivateKey {
            public_key,
            gd,
            p,
            q,
            p_squared,
        })
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

        // Convert public key components to ASN.1
        let n_bytes = self.public_key.n.clone().to_bytes_be();
        let n_asn1 = Asn1BigUint::new(&n_bytes);

        let g_bytes = self.public_key.g.clone().to_bytes_be();
        let g_asn1 = Asn1BigUint::new(&g_bytes);

        let h_bytes = self.public_key.h.clone().to_bytes_be();
        let h_asn1 = Asn1BigUint::new(&h_bytes);

        // Convert private key components to ASN.1
        let gd_bytes = self.gd.clone().to_bytes_be();
        let gd_asn1 = Asn1BigUint::new(&gd_bytes);

        let p_bytes = self.p.clone().to_bytes_be();
        let p_asn1 = Asn1BigUint::new(&p_bytes);

        let q_bytes = self.q.clone().to_bytes_be();
        let q_asn1 = Asn1BigUint::new(&q_bytes);

        let p_squared_bytes = self.p_squared.clone().to_bytes_be();
        let p_squared_bytes_asn1 = Asn1BigUint::new(&p_squared_bytes);

        // Write all elements to ASN.1 Sequence
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&n_asn1)?; // Add n to the sequence
                w.write_element(&g_asn1)?; // Add g to the sequence
                w.write_element(&h_asn1)?; // Add h to the sequence
                w.write_element(&gd_asn1)?; // Add gd to the sequence
                w.write_element(&p_asn1)?; // Add p to the sequence
                w.write_element(&q_asn1)?; // Add q to the sequence
                w.write_element(&p_squared_bytes_asn1)?; // Add p_squared to the sequence
                Ok(())
            }))
        });

        // Encode the ASN.1 sequence using Base64
        pem.push_str("-----BEGIN PRIVATE KEY-----\n");
        pem.push_str(&general_purpose::STANDARD.encode(result.unwrap_or_else(|_| vec![])));
        pem.push_str("\n-----END PRIVATE KEY-----\n");

        pem
    }
}
