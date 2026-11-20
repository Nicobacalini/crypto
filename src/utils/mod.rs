pub mod error;
pub use error::CryptoError;

/// Trait polimorfico object-safe para motores criptograficos simetricos.
pub trait Encryptor: Send + Sync {
    /// Cifra un buffer en memoria.
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Descifra un buffer en memoria validando la integridad del contenido.
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Identificador canonico del algoritmo (ej. "aes", "caesar", "xor", "vigenere").
    fn name(&self) -> &'static str;
}
