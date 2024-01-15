use crate::error::OkamotoUchiyamaError;

use num::One;
use num_bigint_dig::BigUint;

pub use crate::crypto::private_key::PrivateKey;

/// Represents a Okamoto-Uchiyama public key.
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
    /// Generate a public key from n, g and h
    pub fn new(n: &BigUint, g: &BigUint, h: &BigUint) -> PublicKey {
        PublicKey {
            n: n.clone(),
            g: g.clone(),
            h: h.clone(),
        }
    }

    /// Performs homomorphic operation over two passed chiphers.
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

    /// Performs homomorphic operation over multiple passed chiphers.
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
}
