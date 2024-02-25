use num_bigint_dig::BigUint;
use okamoto_uchiyama::{OkamotoUchiyama, PrivateKey, PublicKey};

#[test]
fn test_encryption_decryption() {
    let message = BigUint::from(1337u64);

    // Initialization
    let length = okamoto_uchiyama::key::KeySize::Bits1024;
    let okamoto_uchiyama = OkamotoUchiyama::init(length);

    // Generate the key pair
    let private_key = okamoto_uchiyama.generate_private_key();
    let public_key = private_key.public_key.clone();

    let ciphertext = OkamotoUchiyama::encrypt(&message, &public_key);
    let plaintext: BigUint = OkamotoUchiyama::decrypt(&ciphertext, &private_key);

    assert_eq!(message, plaintext);
}

#[test]
fn test_encryption_decryption_from_public_key() {
    let message = BigUint::from(1337u64);

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

    let ciphertext = OkamotoUchiyama::encrypt(&message, &public_key);
    let plaintext: BigUint = OkamotoUchiyama::decrypt(&ciphertext, &private_key);

    assert_eq!(message, plaintext);
}
