use okamoto_uchiyama::PrivateKey;

fn main() {
    // Define the PEM-encoded private key string
    let pem_encoded_key = "
    -----BEGIN PRIVATE KEY-----\n\
    MCcCBQIyNHTHAgUB4dOT9wIFAdwgA/ECAx9jegICB9MCAgkvAgM9N+k=\n\
    -----END PRIVATE KEY-----\n";

    // Attempt to parse the PEM-encoded key into a PrivateKey instance
    let private_key = PrivateKey::from_pem(pem_encoded_key).unwrap();

    // Print the private key
    println!("{}", private_key);
}
