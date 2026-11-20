use crate::algorithms::{AesCipher, CaesarCipher, VigenereCipher, XorCipher};
use crate::utils::{CryptoError, Encryptor};

/// Factoría encargada de instanciar cifradores polimórficos de forma dinámica.
pub struct EncryptorFactory;

impl EncryptorFactory {
    /// Crea un objeto `Box<dyn Encryptor>` a partir del identificador del algoritmo y su clave.
    pub fn create(name: &str, key: &[u8]) -> Result<Box<dyn Encryptor>, CryptoError> {
        match name.to_lowercase().trim() {
            "caesar" => {
                if key.is_empty() {
                    return Err(CryptoError::EmptyKey);
                }
                // Parsea el desplazamiento expresado como cadena de texto UTF-8 (ej. "3")
                let shift_str = std::str::from_utf8(key).map_err(|_| {
                    CryptoError::InvalidKey(
                        "El desplazamiento de César debe ser un texto o número UTF-8 válido".into(),
                    )
                })?;
                let trimmed = shift_str.trim();
                if trimmed.is_empty() {
                    return Err(CryptoError::EmptyKey);
                }
                let shift: u8 = trimmed.parse().map_err(|_| {
                    CryptoError::InvalidKey(
                        "El desplazamiento de César debe ser un entero entre 0 y 255".into(),
                    )
                })?;
                Ok(Box::new(CaesarCipher::new(shift)))
            }
            "xor" => {
                if key.is_empty() {
                    return Err(CryptoError::EmptyKey);
                }
                let cipher = XorCipher::new(key)?;
                Ok(Box::new(cipher))
            }
            "vigenere" => {
                if key.is_empty() {
                    return Err(CryptoError::EmptyKey);
                }
                let key_str = std::str::from_utf8(key).map_err(|_| {
                    CryptoError::InvalidKey("La clave de Vigenère debe ser UTF-8 válido".into())
                })?;
                let cipher = VigenereCipher::new(key_str)?;
                Ok(Box::new(cipher))
            }
            "aes" => {
                if key.is_empty() {
                    return Err(CryptoError::EmptyKey);
                }
                let cipher = AesCipher::new(key)?;
                Ok(Box::new(cipher))
            }
            unknown => Err(CryptoError::UnknownAlgorithm(unknown.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_caesar() {
        let encryptor = EncryptorFactory::create("caesar", b"3").unwrap();
        assert_eq!(encryptor.name(), "caesar");
        let encrypted = encryptor.encrypt(b"Hello World").unwrap();
        assert_eq!(encrypted, b"Khoor Zruog");
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"Hello World");
    }

    #[test]
    fn test_create_caesar_errors() {
        assert!(matches!(
            EncryptorFactory::create("caesar", b""),
            Err(CryptoError::EmptyKey)
        ));
        assert!(matches!(
            EncryptorFactory::create("caesar", b"invalido"),
            Err(CryptoError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_create_xor() {
        let encryptor = EncryptorFactory::create("xor", b"secret").unwrap();
        assert_eq!(encryptor.name(), "xor");
        let data = b"Test XOR string";
        let encrypted = encryptor.encrypt(data).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_create_xor_empty_key() {
        assert!(matches!(
            EncryptorFactory::create("xor", b""),
            Err(CryptoError::EmptyKey)
        ));
    }

    #[test]
    fn test_create_vigenere() {
        let encryptor = EncryptorFactory::create("vigenere", b"LEMON").unwrap();
        assert_eq!(encryptor.name(), "vigenere");
        let encrypted = encryptor.encrypt(b"ATTACKATDAWN").unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"ATTACKATDAWN");
    }

    #[test]
    fn test_create_vigenere_errors() {
        assert!(matches!(
            EncryptorFactory::create("vigenere", b""),
            Err(CryptoError::EmptyKey)
        ));
        assert!(matches!(
            EncryptorFactory::create("vigenere", b"123!"),
            Err(CryptoError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_create_aes() {
        let key = b"0123456789abcdef";
        let encryptor = EncryptorFactory::create("aes", key).unwrap();
        assert_eq!(encryptor.name(), "aes");
    }

    #[test]
    fn test_create_aes_errors() {
        assert!(matches!(
            EncryptorFactory::create("aes", b""),
            Err(CryptoError::EmptyKey)
        ));
        assert!(matches!(
            EncryptorFactory::create("aes", b"short_key"),
            Err(CryptoError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_case_insensitivity_and_trim() {
        assert!(EncryptorFactory::create("  CAESAR  ", b"3").is_ok());
        assert!(EncryptorFactory::create("XoR", b"key").is_ok());
        assert!(EncryptorFactory::create("  AES ", b"0123456789abcdef").is_ok());
        assert!(EncryptorFactory::create("ViGeNeRe", b"KEY").is_ok());
    }

    #[test]
    fn test_unknown_algorithm() {
        let result = EncryptorFactory::create("unknown", b"key");
        assert!(matches!(result, Err(CryptoError::UnknownAlgorithm(_))));
    }

    #[test]
    fn test_create_caesar_edge_cases_and_no_secret_leak() {
        assert!(matches!(
            EncryptorFactory::create("caesar", b"   "),
            Err(CryptoError::EmptyKey)
        ));
        assert!(matches!(
            EncryptorFactory::create("caesar", &[0xFF, 0xFE]),
            Err(CryptoError::InvalidKey(_))
        ));

        for bad in [
            b"256".as_slice(),
            b"-1".as_slice(),
            b"clave_secreta".as_slice(),
        ] {
            let bad_str = std::str::from_utf8(bad).unwrap();
            match EncryptorFactory::create("caesar", bad) {
                Err(CryptoError::InvalidKey(msg)) => {
                    assert!(
                        !msg.contains(bad_str),
                        "el error de factory filtró la entrada '{bad_str}': {msg}"
                    );
                }
                other => panic!(
                    "se esperaba InvalidKey para '{bad_str}', se obtuvo {:?}",
                    other.err()
                ),
            }
        }
    }

    #[test]
    fn test_create_vigenere_non_utf8() {
        assert!(matches!(
            EncryptorFactory::create("vigenere", &[0xFF]),
            Err(CryptoError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_create_aes_roundtrip_via_trait_object() {
        let key = b"0123456789abcdef";
        let encryptor = EncryptorFactory::create("aes", key).unwrap();
        let plain = b"Texto polimorfico con AES-128";
        let ct = encryptor.encrypt(plain).unwrap();
        assert_ne!(ct, plain);
        assert_eq!(encryptor.decrypt(&ct).unwrap(), plain);
    }
}
