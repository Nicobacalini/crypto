use crate::utils::{CryptoError, Encryptor};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VigenereCipher {
    key_shifts: Vec<u8>,
}

impl VigenereCipher {
    // contruye la instrucia validando que la clave sea alfabetica
    pub fn new(key: &str) -> Result<Self, CryptoError> {
        if key.is_empty() {
            return Err(CryptoError::EmptyKey);
        }

        if !key.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(CryptoError::InvalidKey(
                "La clave de Vigenère solo puede contener letras ASCII (A-Z, a-z)".into(),
            ));
        }

        let key_shifts: Vec<u8> = key
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a',
                _ => unreachable!(),
            })
            .collect();

        Ok(Self { key_shifts })
    }

    /// Aplica el desplazamiento segun el modo (cifrar/descifrar).
    fn transform(&self, data: &[u8], decrypt: bool) -> Vec<u8> {
        let mut key_idx = 0;
        data.iter()
            .map(|&b| {
                if b.is_ascii_alphabetic() {
                    let shift = self.key_shifts[key_idx % self.key_shifts.len()];
                    key_idx += 1;
                    let effective_shift = if decrypt { (26 - shift) % 26 } else { shift };
                    match b {
                        b'A'..=b'Z' => (b - b'A' + effective_shift) % 26 + b'A',
                        b'a'..=b'z' => (b - b'a' + effective_shift) % 26 + b'a',
                        _ => b,
                    }
                } else {
                    b
                }
            })
            .collect()
    }
}

impl Encryptor for VigenereCipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.transform(data, false))
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.transform(data, true))
    }

    fn name(&self) -> &'static str {
        "vigenere"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vigenere_accepted_vectors() {
        // Vector de prueba oficial: "HELLO" + "KEY" -> "RIJVS"
        let cipher = VigenereCipher::new("KEY").unwrap();
        let encrypted = cipher.encrypt(b"HELLO").unwrap();
        assert_eq!(encrypted, b"RIJVS");

        let decrypted = cipher.decrypt(b"RIJVS").unwrap();
        assert_eq!(decrypted, b"HELLO");

        // Claves no validas con caracteres numericos o simbolos deben rechazarse
        assert!(VigenereCipher::new("KEY123").is_err());
        assert!(VigenereCipher::new("KEY!").is_err());
    }

    #[test]
    fn test_vigenere_official_vectors() {
        let cipher = VigenereCipher::new("LEMON").unwrap();
        let encrypted = cipher.encrypt(b"ATTACK AT DAWN").unwrap();
        assert_eq!(encrypted, b"LXFOPV EF RNHR");
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"ATTACK AT DAWN");
    }

    #[test]
    fn test_vigenere_case_preservation() {
        let cipher = VigenereCipher::new("lemon").unwrap();
        let encrypted = cipher.encrypt(b"Attack at Dawn! 123").unwrap();
        assert_eq!(encrypted, b"Lxfopv ef Rnhr! 123");
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"Attack at Dawn! 123");
    }

    #[test]
    fn test_vigenere_invalid_keys() {
        assert!(matches!(
            VigenereCipher::new(""),
            Err(CryptoError::EmptyKey)
        ));
        assert!(matches!(
            VigenereCipher::new("lemon123"),
            Err(CryptoError::InvalidKey(_))
        ));
        assert!(matches!(
            VigenereCipher::new("le mon"),
            Err(CryptoError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_vigenere_invalid_key_does_not_leak_secret() {
        let err = VigenereCipher::new("SuperSecret123!").err().unwrap();
        match err {
            CryptoError::InvalidKey(msg) => {
                assert!(
                    !msg.contains("SuperSecret123!"),
                    "el error filtró la clave en texto claro: {msg}"
                );
            }
            other => panic!("se esperaba InvalidKey, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn test_vigenere_empty_and_utf8_preservation() {
        let cipher = VigenereCipher::new("KEY").unwrap();
        assert_eq!(cipher.encrypt(b"").unwrap(), b"");
        assert_eq!(cipher.decrypt(b"").unwrap(), b"");

        let msg = "Café ñ 2026".as_bytes();
        let enc = cipher.encrypt(msg).unwrap();
        assert_ne!(enc, msg);
        assert_eq!(cipher.decrypt(&enc).unwrap(), msg);
    }

    #[test]
    fn test_vigenere_name() {
        let cipher = VigenereCipher::new("KEY").unwrap();
        assert_eq!(cipher.name(), "vigenere");
    }
}
