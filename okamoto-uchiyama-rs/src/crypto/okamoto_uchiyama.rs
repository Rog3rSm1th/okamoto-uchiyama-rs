use crate::key::KeySize;

use num::One;
use num_bigint_dig::algorithms::mod_inverse;
use num_bigint_dig::{BigUint, RandBigInt};
use num_primes::Generator;
use rand::thread_rng;

pub use crate::crypto::private_key::PrivateKey;
pub use crate::crypto::public_key::PublicKey;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Default)]
pub struct OkamotoUchiyama {
    // A large prime p,
    pub p: BigUint,
    // p_squared = p^2
    pub p_squared: BigUint,
    // A large prime q
    pub q: BigUint,
    // Modulus: p^2 * q
    pub n: BigUint,
    // A random integer in the range [2, n - 1]
    pub g: BigUint,
    // g^(p-1) mod p^2
    pub gpminuse1: BigUint,
    // h = g^n mod n
    pub h: BigUint,
    // The length in bits of the Okamoto-Uchiyama public key modulus.
    pub length: u32,
}

impl OkamotoUchiyama {
    #[allow(unused)]
    // Init the cryptosystem by generating the constants used for key-pair creation
    pub fn init(key_size: KeySize) -> Self {
        // Select the key size
        let length = match key_size {
            KeySize::Bits512 => 512,
            KeySize::Bits1024 => 1024,
            KeySize::Bits2048 => 2048,
            KeySize::Bits4096 => 4096,
        };

        // Calculate a large prime number with `length / 3` bit length
        let p_prime = Generator::new_prime((&length / 3) as usize);
        // Convert the prime number to BigUint
        let p = BigUint::from_bytes_be(&p_prime.clone().to_bytes_be());

        // Calculate another large prime number with `length / 2` bit length
        let q_prime = Generator::new_prime((&length / 2) as usize);
        // Convert the prime number to BigUint
        let q = BigUint::from_bytes_be(&q_prime.clone().to_bytes_be());

        // Calculate n = p^2 * q
        let p_squared = &p * &p;
        let n = &p_squared * &q;

        // Find an integer `g` in the range [2, n - 1] such that g^(p-1) mod p^2 != 1
        let p_minus_1 = &p - 1u32;
        let mut rng = thread_rng();
        let mut g = BigUint::default();

        let mut gpminuse1: BigUint;
        loop {
            // Generate a random integer in the range [2, n - 1]
            g = rng.gen_biguint_range(&2u32.into(), &(&n - &1u32));
            // Check if g^(p-1) mod p^2 != 1
            gpminuse1 = g.modpow(&p_minus_1, &p_squared) % &p_squared;
            if gpminuse1 != 0u32.into() {
                break;
            }
        }

        // Calculate h = g^n mod n
        let h = g.modpow(&n, &n) % &n;

        // Return a new instance of the OkamotoUchiyama struct with the calculated values
        OkamotoUchiyama {
            p,
            p_squared,
            q,
            n,
            g,
            gpminuse1,
            h,
            length,
        }
    }

    /// Generates the public key
    pub fn generate_public_key(&self) -> PublicKey {
        PublicKey {
            // Public key components
            n: self.n.clone(),
            g: self.g.clone(),
            h: self.h.clone(),
        }
    }

    /// Generates the private key
    pub fn generate_private_key(&self) -> PrivateKey {
        PrivateKey {
            // Private key contains the public key
            public_key: self.generate_public_key().clone(),

            // Private key components
            gd: self.gpminuse1.clone(),
            p: self.p.clone(),
            q: self.q.clone(),
            p_squared: self.p_squared.clone(),
        }
    }

    /// Encrypt a message using the public key.
    pub fn encrypt(message: &BigUint, public_key: &PublicKey) -> BigUint {
        // Choose a random integer r from {1...n-1}.
        let mut rng = thread_rng();
        let n_minus_1 = &public_key.n - &BigUint::one();
        let r = rng.gen_biguint_range(&BigUint::one(), &n_minus_1);

        // Compute the ciphertext as c = (g^m * h^r) mod n.
        (public_key.g.modpow(&message, &public_key.n) * public_key.h.modpow(&r, &public_key.n))
            % &public_key.n
    }

    /// Decrypts a ciphertext using the provided private key.
    pub fn decrypt(ciphertext: &BigUint, private_key: &PrivateKey) -> BigUint {
        let pminus1 = &private_key.p - 1u32;

        // c^(p-1) mod p^2
        let a = ciphertext.modpow(&pminus1, &private_key.p_squared);

        // L1(a) = (a - 1) / p
        let l1 = (a - 1u32) / &private_key.p.clone();

        // L2(b) = (b - 1) / p
        let l2 = (&private_key.gd.clone() - 1u32) / &private_key.p.clone();

        // b^(-1) mod p
        let binverse = mod_inverse(
            std::borrow::Cow::Borrowed(&l2),
            std::borrow::Cow::Borrowed(&private_key.p.clone()),
        )
        .unwrap()
        .to_biguint()
        .unwrap();

        (l1 * binverse) % &private_key.p.clone()
    }
}
