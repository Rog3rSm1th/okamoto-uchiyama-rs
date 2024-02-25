use thiserror::Error;

#[derive(Debug, Error)]
pub enum OkamotoUchiyamaError {
    // When the message is too large for the public key size.
    #[error("Message is larger than public key size")]
    MessageTooLarge,

    // When the ciphertext is too large for the public key size
    #[error("Message is larger than public key size")]
    CipherTooLarge,

    // When the PEM key decoding fails
    #[error("Error when decoding the PEM encoded key")]
    PemDecodingError,

    // Generic error message
    #[error("Okamoto-Uchiyama failed with the following stdout: {stdout} stderr: {stderr}")]
    OkamotoUchiyamaError { stdout: String, stderr: String },
}
