use crate::crypto::okamoto_uchiyama::PublicKey;

use num_bigint_dig::BigUint;
use std::fmt;

/// PrivateKey represents a Okamoto-Uchiyama private key.
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
    /// Generate a new private key from p, q and a public key
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
