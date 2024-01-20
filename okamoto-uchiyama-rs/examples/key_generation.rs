use num_bigint_dig::BigUint;
use okamoto_uchiyama::{PrivateKey, PublicKey};

fn main() {
    // Creating a public key with three large integers as parameters
    let public_key = PublicKey::new(
        &BigUint::from(9432233159u64),
        &BigUint::from(8083706871u64),
        &BigUint::from(7988052977u64),
    );

    // Creating a private key with the corresponding public key and two additional parameters
    let private_key = PrivateKey::new(
        &public_key,
        &BigUint::from(2003u64),
        &BigUint::from(2351u64),
    );

    // Printing the public and private keys
    println!("{:#?}", public_key);
    println!("{:#?}", private_key);
}