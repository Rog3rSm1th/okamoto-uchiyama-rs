/// A trait for types that can be encoded into PEM (Privacy Enhanced Mail) format.
pub trait PemEncodable {
    /// Converts the implementor into a PEM-encoded string
    fn to_pem(&self) -> String;
}
