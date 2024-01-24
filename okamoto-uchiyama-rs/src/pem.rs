use num_bigint_dig::BigUint;

/// A trait for types that can be encoded into PEM (Privacy Enhanced Mail) format.
pub trait PemEncodable {
    /// Converts the implementor into a PEM-encoded string
    fn to_pem(&self) -> String;
}

/// A trait for types that can be encoded in ASN.1 DER (Distinguished Encoding Rules) format.
pub trait Asn1Encode {
    /// Converts the implementor into an ASN.1 DER-encoded byte vector.
    fn to_asn1_der(&self) -> Vec<u8>;
}

/// Implementation of the Asn1Encode trait for the BigUint type.
impl Asn1Encode for BigUint {
    /// Converts a BigUint into an ASN.1 DER-encoded byte vector.
    fn to_asn1_der(&self) -> Vec<u8> {
        // Create a new vector to store the ASN.1 DER encoding
        let mut der = Vec::new();

        // Encode Type
        der.push(0x02);

        // Encode Length
        let value_bytes = self.to_bytes_be();
        let length_byte_count = value_bytes
            .iter()
            .position(|&b| b != 0)
            .map_or(0, |pos| value_bytes.len() - pos);

        // Always use long form for the length representation
        let length_bytes = length_byte_count.to_be_bytes();
        der.push((0x80 | length_bytes.len()) as u8); // Set the most significant bit to indicate long form
        der.extend_from_slice(&length_bytes);

        // Encode Value
        der.extend_from_slice(&value_bytes);

        der
    }
}
