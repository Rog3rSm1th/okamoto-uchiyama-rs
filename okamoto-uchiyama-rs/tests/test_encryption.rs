use num_bigint_dig::BigUint;
use okamoto_uchiyama::OkamotoUchiyama;

#[test]
fn test_homomorphic_encrypt_two() {
    let m1 = BigUint::from(6u64);
    let m2 = BigUint::from(7u64);

    // Initialization
    let length = okamoto_uchiyama::key::KeySize::Bits1024;
    let okamoto_uchiyama = OkamotoUchiyama::init(length);

    // Generate the key pair
    let private_key = okamoto_uchiyama.generate_private_key();
    let public_key = private_key.public_key.clone();

    let c1 = OkamotoUchiyama::encrypt(&m1, &public_key);
    let c2 = OkamotoUchiyama::encrypt(&m2, &public_key);

    let c1_c2 = public_key.homomorphic_encrypt_two(&c1, &c2).unwrap();

    let decrypted_c1_c2 = OkamotoUchiyama::decrypt(&c1_c2, &private_key);
    assert_eq!(decrypted_c1_c2, BigUint::from(13u64))
}

#[test]
fn test_homomorphic_encrypt_multiple() {
    let m1 = BigUint::from(6u64);
    let m2 = BigUint::from(7u64);
    let m3 = BigUint::from(8u64);

    // Initialization
    let length = okamoto_uchiyama::key::KeySize::Bits1024;
    let okamoto_uchiyama = OkamotoUchiyama::init(length);

    // Generate the key pair
    let private_key = okamoto_uchiyama.generate_private_key();
    let public_key = private_key.public_key.clone();

    let c1 = OkamotoUchiyama::encrypt(&m1, &public_key);
    let c2 = OkamotoUchiyama::encrypt(&m2, &public_key);
    let c3 = OkamotoUchiyama::encrypt(&m3, &public_key);

    let c1_c2_c3 = public_key
        .homomorphic_encrypt_multiple(vec![&c1, &c2, &c3])
        .unwrap();

    let decrypted_c1_c2_c3 = OkamotoUchiyama::decrypt(&c1_c2_c3, &private_key);
    assert_eq!(decrypted_c1_c2_c3, BigUint::from(21u64))
}
