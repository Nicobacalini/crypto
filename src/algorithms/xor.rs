use crate::utils::{CryptoError, Encryptor};
use zeroize::{Zeroize, ZeroizeOnDrop};

// cifrador por combinacion XOR ciclica con clave repetida

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct XorCipher {
    key: Vec<u8>,
}

impl XorCipher {
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.is_empty() {
            return Err(CryptoError::EmptyKey);
        }

        Ok(Self { key: key.to_vec() })
    }

    // cifrar y desifrar son identicos
    fn process(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, byte)| byte ^ self.key[i % self.key.len()])
            .collect()
    }
}

impl Encryptor for XorCipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.process(data))
    }
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.process(data))
    }
    fn name(&self) -> &'static str {
        "xor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_accepted_vectors() {
        // Clave vacia debe retornar error EmptyKey
        assert!(matches!(XorCipher::new(b""), Err(CryptoError::EmptyKey)));

        // Vector concreto: evita falsos positivos de cifrador identidad
        let concrete = XorCipher::new(&[0x01, 0x02]).unwrap();
        assert_eq!(concrete.encrypt(b"AB").unwrap(), vec![0x40, 0x40]);
        assert_eq!(concrete.decrypt(&[0x40, 0x40]).unwrap(), b"AB");

        // Entrada vacia
        assert_eq!(concrete.encrypt(b"").unwrap(), b"");
        assert_eq!(concrete.decrypt(b"").unwrap(), b"");

        // Involucion con repeticion de clave (data.len() > key.len())
        let cipher = XorCipher::new(b"secret_key").unwrap();
        let data = b"Rust Cryptography Server 2026";
        let encrypted = cipher.encrypt(data).unwrap();
        assert_ne!(encrypted, data);
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, data);
    }
}
