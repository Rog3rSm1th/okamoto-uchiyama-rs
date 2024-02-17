use okamoto_uchiyama::PublicKey;

fn main() {
    // Define the PEM-encoded public key string
    let pem_encoded_key = "
    -----BEGIN PUBLIC KEY-----\n\
   MBUCBQIyNHTHAgUB4dOT9wIFAdwgA/E=\n\
   -----END PUBLIC KEY-----\n";

    // Attempt to parse the PEM-encoded key into a PublicKey instance
    let public_key = PublicKey::from_pem(pem_encoded_key).unwrap();

    // Print the public key
    println!("{}", public_key);
}
