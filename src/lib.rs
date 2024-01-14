// This is a pure Rust implementation of the Okamoto-Uchiyama cryptosystem.
// The code was written by Rog3rSm1th and is licensed under
// the MIT license.
//
// The implementation provides the following functionalities:
// - Key pair generation
// - Encryption and decryption of messages
// - Homomorphic operation over two ciphers
// - Homomorphic operation over multiple ciphers

pub mod crypto;
pub mod error;
pub mod key;

// Re-exporting types from the 'crypto' module for external use
pub use crypto::crypto::{OkamotoUchiyama, PrivateKey, PublicKey};
