use crate::utils::{CryptoError, Encryptor};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CaesarCipher {
    shift: u8,
}

impl CaesarCipher {
    /// Normaliza el desplazamiento módulo 26.
    pub fn new(shift: u8) -> Self {
        Self { shift: shift % 26 }
    }

    fn transform_byte(b: u8, shift: u8) -> u8 {
        match b {
            b'A'..=b'Z' => (b - b'A' + shift) % 26 + b'A',
            b'a'..=b'z' => (b - b'a' + shift) % 26 + b'a',
            _ => b,
        }
    }
}

impl Encryptor for CaesarCipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let result = data
            .iter()
            .map(|&b| Self::transform_byte(b, self.shift))
            .collect();
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let inv_shift = (26 - self.shift) % 26;
        let result = data
            .iter()
            .map(|&b| Self::transform_byte(b, inv_shift))
            .collect();
        Ok(result)
    }

    fn name(&self) -> &'static str {
        "caesar"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_caesar_official_vectors() {
        let cipher = CaesarCipher::new(3);
        let encrypted = cipher.encrypt(b"Hello World").unwrap();
        assert_eq!(encrypted, b"Khoor Zruog");
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"Hello World");
        let cipher_26 = CaesarCipher::new(26);
        assert_eq!(cipher_26.encrypt(b"Rust").unwrap(), b"Rust");
        assert_eq!(cipher_26.decrypt(b"Rust").unwrap(), b"Rust");

        let cipher_0 = CaesarCipher::new(0);
        assert_eq!(cipher_0.encrypt(b"Rust").unwrap(), b"Rust");
        assert_eq!(cipher_0.decrypt(b"Rust").unwrap(), b"Rust");
    }

    #[test]
    fn test_caesar_wraparound_empty_and_utf8_preservation() {
        let cipher = CaesarCipher::new(5);
        let wrapped = cipher.encrypt(b"XYZ xyz").unwrap();
        assert_eq!(wrapped, b"CDE cde");
        assert_eq!(cipher.decrypt(&wrapped).unwrap(), b"XYZ xyz");

        assert_eq!(cipher.encrypt(b"").unwrap(), b"");
        assert_eq!(cipher.decrypt(b"").unwrap(), b"");

        let utf8_msg = "¡Hola, Ñandú 123!".as_bytes();
        let enc_utf8 = cipher.encrypt(utf8_msg).unwrap();
        assert_eq!(enc_utf8, "¡Mtqf, Ñfsiú 123!".as_bytes());
        assert_eq!(cipher.decrypt(&enc_utf8).unwrap(), utf8_msg);
    }
}
