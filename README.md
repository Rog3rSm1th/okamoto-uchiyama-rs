# okamoto-uchiyama-rust

The Okamoto–Uchiyama cryptosystem is a public key cryptosystem proposed in 1998 by Tatsuaki Okamoto and Shigenori Uchiyama. The scheme is an additive homomorphic cryptosystem; this means that, given only the public key and the encryption of **`m_1`** and **`m_2`**, one can compute the encryption of **`m_1 + m_2`**.

This Rust implementation of this cryptosystem includes the following features: 
   - Key pair generation
   - Encryption and decryption of messages
   - Homomorphic operation over two ciphers
   - Homomorphic operation over multiple ciphers

### Generate a key pair

```rust
use num_bigint_dig::BigUint;
use okamoto_uchiyama::{OkamotoUchiyama, PrivateKey, PublicKey};

// Initialization
// In this exemple we use a 1024 bits key
let length = okamoto_uchiyama::key::KeySize::Bits1024;
let okamoto_uchiyama = OkamotoUchiyama::init(length);

// Generate the key pair
let private_key = okamoto_uchiyama.generate_private_key();
let public_key = private_key.public_key.clone();
```
It is possible to generate keys of *512*, *1024*, *2048* or *4096* bits using `okamoto_uchiyama::key::KeySize::Bits512`, `okamoto_uchiyama::key::KeySize::Bits1024`, `okamoto_uchiyama::key::KeySize::Bits2048`, `okamoto_uchiyama::key::KeySize::Bits4096`. 

### Load existing keys

You can load existing privates and publics keys 

```rust
use num_bigint_dig::BigUint;
use okamoto_uchiyama::{OkamotoUchiyama, PrivateKey, PublicKey};

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
```

### Partial homomorphic encryption

#### Add two encrypted ciphertexts

A notable feature of the Okamoto-Uchiyama cryptosystem is its homomorphic properties.

Since this scheme makes possible Homomorphic addition of plaintexts, the product of two ciphertexts will decrypt to the sum of their corresponding plaintexts: **`E(m1) * E(m2) = E(m1 + m2)`**

```rust
use num_bigint_dig::BigUint;
use okamoto_uchiyama::{OkamotoUchiyama, PrivateKey, PublicKey};

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

// Result is c1 + c2 = 6 + 7 = 13
let decrypted_c1_c2 = OkamotoUchiyama::decrypt(&c1_c2, &private_key);
```

#### Add multiple encrypted ciphertexts

```rust
use num_bigint_dig::BigUint;
use okamoto_uchiyama::{OkamotoUchiyama, PrivateKey, PublicKey};

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

// Result is c1 + c2 + c2 = 6 + 7 + 8 = 21
let decrypted_c1_c2_c3 = OkamotoUchiyama::decrypt(&c1_c2_c3, &private_key);
```

### TODO

- [ ] Faster primes generation
- [ ]  Improve security
