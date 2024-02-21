use crate::error::OkamotoUchiyamaError;

use crate::pem::PemEncodable;
use asn1::BigUint as Asn1BigUint;
use base64::engine::general_purpose;
use base64::Engine;
use num_bigint_dig::BigUint;

// Define a Ciphertext struct to encapsulate a ciphertext value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    value: BigUint,
}

impl Ciphertext {
    // Constructor function to create a new Ciphertext instance
    pub fn new(value: BigUint) -> Self {
        Ciphertext { value }
    }

    /// Attempt to create a `Ciphertext` from a PEM-encoded string
    pub fn from_pem(pem: &str) -> Result<Self, OkamotoUchiyamaError> {
        // Trim the starting and ending spaces/newlines
        let pem = pem.trim();

        // Check if the PEM string starts and ends with the correct tags
        if !pem.starts_with("-----BEGIN CIPHERTEXT-----")
            || !pem.ends_with("-----END CIPHERTEXT-----")
        {
            return Err(OkamotoUchiyamaError::PemDecodingError);
        }

        // Extract the base64-encoded ASN.1 sequence between the tags
        let base64_encoded = pem
            .trim_start_matches("-----BEGIN CIPHERTEXT-----")
            .trim_end_matches("-----END CIPHERTEXT-----")
            .trim();

        // Decode the base64-encoded ASN.1 sequence using Engine::decode
        let asn1_decoded = general_purpose::STANDARD
            .decode(base64_encoded.as_bytes())
            .map_err(|_| OkamotoUchiyamaError::PemDecodingError)?;

        // Parse the ASN.1 sequence into a BigUint
        let value_asn1 = asn1::parse_single::<Asn1BigUint>(&asn1_decoded)
            .map_err(|_| OkamotoUchiyamaError::PemDecodingError)?;

        // Convert the ASN.1 BigUint to a BigUint
        let value_bytes = value_asn1.as_bytes();
        let value = BigUint::from_bytes_be(&value_bytes);

        // Return a new `Ciphertext` instance
        Ok(Ciphertext::new(value))
    }

    // Getter method to retrieve the value of the ciphertext
    pub fn value(&self) -> &BigUint {
        &self.value
    }
}

/// Implement the PemEncodable trait for the Ciphertext struct
impl PemEncodable for Ciphertext {
    fn to_pem(&self) -> String {
        let mut pem = String::new();

        // Convert the ciphertext value to ASN.1
        let value_bytes = self.value.to_bytes_be();
        let value_asn1 = Asn1BigUint::new(&value_bytes);

        // Write the value to ASN.1 Sequence
        let result = asn1::write(|w| w.write_element(&value_asn1));

        // Encode the ASN.1 sequence using Base64
        pem.push_str("-----BEGIN CIPHERTEXT-----\n");
        pem.push_str(&general_purpose::STANDARD.encode(result.unwrap_or_else(|_| vec![])));
        pem.push_str("\n-----END CIPHERTEXT-----\n");

        pem
    }
}
