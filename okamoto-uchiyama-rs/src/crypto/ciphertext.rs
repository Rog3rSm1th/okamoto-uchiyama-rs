use num_bigint_dig::BigUint;

// Define a Ciphertext struct to encapsulate a ciphertext value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    value: BigUint,
}

impl Ciphertext {
    // Constructor function to create a new Ciphertext instance
    pub fn new(value: BigUint) -> Self {
        Ciphertext { value }
    }

    // Getter method to retrieve the value of the ciphertext
    pub fn value(&self) -> &BigUint {
        &self.value
    }
}
