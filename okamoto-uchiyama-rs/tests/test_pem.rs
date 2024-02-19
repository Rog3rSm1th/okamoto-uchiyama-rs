use num_bigint_dig::BigUint;
use okamoto_uchiyama::pem::PemEncodable;
use okamoto_uchiyama::{PrivateKey, PublicKey};

#[test]
fn test_public_key_pem_encoding() {
    // Create a sample public key
    let public_key = PublicKey::new(
        &BigUint::from(9432233159u64),
        &BigUint::from(8083706871u64),
        &BigUint::from(7988052977u64),
    );

    // Encode to PEM
    let pem_str = public_key.to_pem();

    // Expected PEM-encoded string
    let expected_pem = "-----BEGIN PUBLIC KEY-----\n\
                        MBUCBQIyNHTHAgUB4dOT9wIFAdwgA/E=\n\
                        -----END PUBLIC KEY-----\n";

    // Assert equality
    assert_eq!(pem_str, expected_pem);
}

#[test]
fn test_private_key_pem_encoding() {
    // Create a sample private key
    let public_key = PublicKey::new(
        &BigUint::from(9432233159u64),
        &BigUint::from(8083706871u64),
        &BigUint::from(7988052977u64),
    );
    let private_key = PrivateKey::new(
        &public_key,
        &BigUint::from(2003u64),
        &BigUint::from(2351u64),
    );

    // Encode to PEM
    let pem_str = private_key.to_pem();

    // Expected PEM-encoded string
    let expected_pem = "-----BEGIN PRIVATE KEY-----\n\
                        MCcCBQIyNHTHAgUB4dOT9wIFAdwgA/ECAx9jegICB9MCAgkvAgM9N+k=\n\
                        -----END PRIVATE KEY-----\n";

    // Assert equality
    assert_eq!(pem_str, expected_pem);
}

#[test]
fn test_parse_public_key_from_pem() {
    // Define the PEM-encoded public key string
    let pem_str = "-----BEGIN PUBLIC KEY-----\n\
                    MBUCBQIyNHTHAgUB4dOT9wIFAdwgA/E=\n\
                    -----END PUBLIC KEY-----\n";

    // Parse the PEM-encoded string into a PublicKey instance
    let parsed_public_key = PublicKey::from_pem(pem_str).unwrap();

    let expected_public_key = PublicKey::new(
        &BigUint::from(9432233159u64),
        &BigUint::from(8083706871u64),
        &BigUint::from(7988052977u64),
    );

    // // Assert equality between the parsed and expected public keys
    assert_eq!(parsed_public_key, expected_public_key);
}

#[test]
fn test_parse_private_key_from_pem() {
    // Define the PEM-encoded private key string
    let pem_str = "-----BEGIN PRIVATE KEY-----\n\
                    MCcCBQIyNHTHAgUB4dOT9wIFAdwgA/ECAx9jegICB9MCAgkvAgM9N+k=\n\
                    -----END PRIVATE KEY-----\n";

    // Parse the PEM-encoded string into a PrivateKey instance
    let parsed_private_key = PrivateKey::from_pem(pem_str).unwrap();

    let public_key = PublicKey::new(
        &BigUint::from(9432233159u64),
        &BigUint::from(8083706871u64),
        &BigUint::from(7988052977u64),
    );
    let expected_private_key = PrivateKey::new(
        &public_key,
        &BigUint::from(2003u64),
        &BigUint::from(2351u64),
    );

    // Assert equality between the parsed and expected private keys
    assert_eq!(parsed_private_key, expected_private_key);
}
