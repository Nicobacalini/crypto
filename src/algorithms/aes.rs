use crate::utils::{CryptoError, Encryptor};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Tabla de sustitucion oficial S-BOX (NIST FIPS-197)
pub const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const fn build_inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

/// Tabla inversa oficial InvSubBytes derivada en tiempo de compilación desde `SBOX`.
pub const INV_SBOX: [u8; 256] = build_inv_sbox();

/// Multiplicacion por 2 en GF(2^8) con reduccion por x^8 + x^4 + x^3 + x + 1 sin ramas.
pub fn xtime(x: u8) -> u8 {
    let high_bit_mask = (x >> 7).wrapping_neg();
    (x << 1) ^ (0x1b & high_bit_mask)
}

fn mul2(b: u8) -> u8 {
    xtime(b)
}
fn mul3(b: u8) -> u8 {
    xtime(b) ^ b
}
fn mul9(b: u8) -> u8 {
    xtime(xtime(xtime(b))) ^ b
}
fn mul11(b: u8) -> u8 {
    xtime(xtime(xtime(b))) ^ xtime(b) ^ b
}
fn mul13(b: u8) -> u8 {
    xtime(xtime(xtime(b))) ^ xtime(xtime(b)) ^ b
}
fn mul14(b: u8) -> u8 {
    xtime(xtime(xtime(b))) ^ xtime(xtime(b)) ^ xtime(b)
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Motor AES-128 de bloque con relleno PKCS#7 en modo ECB.
///
/// Advertencia: el modo ECB sin autenticación no oculta patrones entre bloques ni
/// valida integridad; esta implementación sirve como primitiva base para modos
/// encadenados con IV y autenticación (HMAC/AEAD) en capas superiores.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AesCipher {
    round_keys: [[u8; 16]; 11],
}

impl AesCipher {
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.is_empty() {
            return Err(CryptoError::EmptyKey);
        }
        if key.len() != 16 {
            return Err(CryptoError::InvalidKey(
                "AES-128 requiere una clave de exactamente 16 bytes".into(),
            ));
        }

        // Crear las 11 claves de ronda (la primera es la clave original)
        let mut round_keys = [[0u8; 16]; 11];
        round_keys[0].copy_from_slice(key);

        for r in 1..=10 {
            // Ultima palabra (columna) de la clave de ronda anterior
            let mut w = [
                round_keys[r - 1][12],
                round_keys[r - 1][13],
                round_keys[r - 1][14],
                round_keys[r - 1][15],
            ];

            // RotWord + SubWord + Rcon
            w.rotate_left(1);
            for b in w.iter_mut() {
                *b = SBOX[*b as usize];
            }
            w[0] ^= RCON[r - 1];

            // Generar las 4 columnas de la subclave
            for col in 0..4 {
                let mut prev = if col == 0 {
                    w
                } else {
                    let o = (col - 1) * 4;
                    [
                        round_keys[r][o],
                        round_keys[r][o + 1],
                        round_keys[r][o + 2],
                        round_keys[r][o + 3],
                    ]
                };

                let offset = col * 4;
                for i in 0..4 {
                    round_keys[r][offset + i] = round_keys[r - 1][offset + i] ^ prev[i];
                }
                prev.zeroize();
            }
            w.zeroize();
        }

        Ok(Self { round_keys })
    }

    /// Cifra un único bloque de 16 bytes en memoria
    pub fn encrypt_block(&self, state: &mut [u8; 16]) {
        self.add_round_key(state, 0);
        for r in 1..10 {
            self.sub_bytes(state);
            self.shift_rows(state);
            self.mix_columns(state);
            self.add_round_key(state, r);
        }
        // Ronda 10 final (sin MixColumns)
        self.sub_bytes(state);
        self.shift_rows(state);
        self.add_round_key(state, 10);
    }

    /// Descifra un único bloque de 16 bytes en memoria
    pub fn decrypt_block(&self, state: &mut [u8; 16]) {
        self.add_round_key(state, 10);
        for r in (1..10).rev() {
            self.inv_shift_rows(state);
            self.inv_sub_bytes(state);
            self.add_round_key(state, r);
            self.inv_mix_columns(state);
        }
        // Ronda 0 final (sin InvMixColumns)
        self.inv_shift_rows(state);
        self.inv_sub_bytes(state);
        self.add_round_key(state, 0);
    }

    fn add_round_key(&self, state: &mut [u8; 16], r: usize) {
        for (s, k) in state.iter_mut().zip(&self.round_keys[r]) {
            *s ^= *k;
        }
    }

    fn sub_bytes(&self, state: &mut [u8; 16]) {
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
    }

    fn inv_sub_bytes(&self, state: &mut [u8; 16]) {
        for b in state.iter_mut() {
            *b = INV_SBOX[*b as usize];
        }
    }

    /// El estado es column-major: indice = fila + 4 * columna
    fn shift_rows(&self, s: &mut [u8; 16]) {
        // Fila 1: rota 1 a la izquierda (1 <- 5 <- 9 <- 13 <- 1)
        let tmp = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = tmp;

        // Fila 2: rota 2
        s.swap(2, 10);
        s.swap(6, 14);

        // Fila 3: rota 3 a la izquierda (equivale a 1 a la derecha)
        let tmp = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = tmp;
    }

    fn inv_shift_rows(&self, s: &mut [u8; 16]) {
        // Fila 1: rota 1 a la derecha
        let tmp = s[13];
        s[13] = s[9];
        s[9] = s[5];
        s[5] = s[1];
        s[1] = tmp;

        // Fila 2: rota 2
        s.swap(2, 10);
        s.swap(6, 14);

        // Fila 3: rota 3 a la derecha (equivale a 1 a la izquierda)
        let tmp = s[3];
        s[3] = s[7];
        s[7] = s[11];
        s[11] = s[15];
        s[15] = tmp;
    }

    fn mix_columns(&self, s: &mut [u8; 16]) {
        for c in 0..4 {
            let offset = c * 4;
            let a0 = s[offset];
            let a1 = s[offset + 1];
            let a2 = s[offset + 2];
            let a3 = s[offset + 3];

            s[offset] = mul2(a0) ^ mul3(a1) ^ a2 ^ a3;
            s[offset + 1] = a0 ^ mul2(a1) ^ mul3(a2) ^ a3;
            s[offset + 2] = a0 ^ a1 ^ mul2(a2) ^ mul3(a3);
            s[offset + 3] = mul3(a0) ^ a1 ^ a2 ^ mul2(a3);
        }
    }

    fn inv_mix_columns(&self, s: &mut [u8; 16]) {
        for c in 0..4 {
            let offset = c * 4;
            let a0 = s[offset];
            let a1 = s[offset + 1];
            let a2 = s[offset + 2];
            let a3 = s[offset + 3];

            s[offset] = mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3);
            s[offset + 1] = mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3);
            s[offset + 2] = mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3);
            s[offset + 3] = mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3);
        }
    }
}

impl Encryptor for AesCipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Aplicar relleno PKCS#7
        let pad = 16 - (data.len() % 16);
        let mut padded = Vec::with_capacity(data.len() + pad);
        padded.extend_from_slice(data);
        padded.extend(std::iter::repeat(pad as u8).take(pad));

        // Cifrar bloque por bloque (Modo ECB)
        for chunk in padded.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = chunk.try_into().unwrap();
            self.encrypt_block(block);
        }

        Ok(padded)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.is_empty() || data.len() % 16 != 0 {
            return Err(CryptoError::InvalidCiphertextLength);
        }

        let mut decrypted = data.to_vec();

        // Descifrar bloque por bloque
        for chunk in decrypted.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = chunk.try_into().unwrap();
            self.decrypt_block(block);
        }

        // Validar y remover relleno PKCS#7 en tiempo constante
        let last_block = &decrypted[decrypted.len() - 16..];
        let pad = last_block[15];

        // Validar 1 <= pad <= 16 en tiempo constante
        let ge_one = !pad.ct_eq(&0);
        let le_sixteen = (pad & 0xF0).ct_eq(&0) | pad.ct_eq(&16);
        let mut valid = ge_one & le_sixteen;

        // Verificar los 16 bytes del último bloque sin cortes tempranos
        for (i, &byte) in last_block.iter().enumerate() {
            let pos_from_end = (16 - i) as u8;
            let diff = (pad as u16).wrapping_sub(pos_from_end as u16);
            let in_pad = Choice::from(((diff >> 15) as u8) ^ 1);
            let byte_ok = byte.ct_eq(&pad);
            valid &= !in_pad | byte_ok;
        }

        if bool::from(valid) {
            decrypted.truncate(decrypted.len() - pad as usize);
            Ok(decrypted)
        } else {
            decrypted.zeroize();
            Err(CryptoError::InvalidPadding)
        }
    }

    fn name(&self) -> &'static str {
        "aes"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector oficial FIPS-197, Apendice C.1
    #[test]
    fn fips197_vector() {
        let key: Vec<u8> = (0u8..16).collect();
        let cipher = AesCipher::new(&key).unwrap();

        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let plain = block;
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        cipher.encrypt_block(&mut block);
        assert_eq!(block, expected);

        cipher.decrypt_block(&mut block);
        assert_eq!(block, plain);
    }

    #[test]
    fn roundtrip_con_padding() {
        let cipher = AesCipher::new(b"clave_de_16_byte").unwrap();
        for len in [0usize, 1, 15, 16, 17, 100] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = cipher.encrypt(&data).unwrap();
            assert_eq!(ct.len() % 16, 0);
            assert!(ct.len() > data.len());
            assert_eq!(cipher.decrypt(&ct).unwrap(), data);
        }
    }

    #[test]
    fn errores() {
        assert!(AesCipher::new(b"corta").is_err());
        let cipher = AesCipher::new(&[0u8; 16]).unwrap();
        assert!(matches!(
            cipher.decrypt(&[0u8; 15]),
            Err(CryptoError::InvalidCiphertextLength)
        ));
        assert!(matches!(
            cipher.decrypt(&[]),
            Err(CryptoError::InvalidCiphertextLength)
        ));
    }

    #[test]
    fn xtime_branchless_matches_reference_all_256() {
        for x in 0u8..=255 {
            let expected = if x & 0x80 != 0 {
                (x << 1) ^ 0x1b
            } else {
                x << 1
            };
            assert_eq!(xtime(x), expected, "fallo en xtime({x})");
        }
    }

    #[test]
    fn inv_sbox_is_exact_inverse_of_sbox() {
        for i in 0u8..=255 {
            let s = SBOX[i as usize];
            assert_eq!(INV_SBOX[s as usize], i);
            let inv = INV_SBOX[i as usize];
            assert_eq!(SBOX[inv as usize], i);
        }
    }

    #[test]
    fn key_validation_contracts() {
        assert!(matches!(AesCipher::new(b""), Err(CryptoError::EmptyKey)));

        let secret = b"clave_secreta_larga_no_filtrar";
        for len in [1usize, 15, 17, 30] {
            let err = AesCipher::new(&secret[..len]).err().unwrap();
            match err {
                CryptoError::InvalidKey(msg) => {
                    assert!(
                        !msg.contains("clave_secreta"),
                        "el mensaje de error filtró material de clave: {msg}"
                    );
                }
                other => panic!("se esperaba InvalidKey, se obtuvo {other:?}"),
            }
        }
    }

    #[test]
    fn invalid_padding_rejected_deterministically() {
        let cipher = AesCipher::new(b"clave_de_16_byte").unwrap();

        let mut bad_blocks = [
            [0u8; 16],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 3, 4],
            [
                0x00, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                0x10, 0x10,
            ],
        ];

        for block in &mut bad_blocks {
            cipher.encrypt_block(block);
            assert!(
                matches!(cipher.decrypt(block), Err(CryptoError::InvalidPadding)),
                "se esperaba InvalidPadding para bloque manipulado"
            );
        }

        // Ciphertext corrupto en el último bloque
        let mut ct = cipher.encrypt(b"mensaje de prueba").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(
            cipher.decrypt(&ct),
            Err(CryptoError::InvalidPadding)
        ));

        // Descifrado con clave errónea
        let valid_ct = cipher.encrypt(b"mensaje de prueba").unwrap();
        let wrong_cipher = AesCipher::new(b"otra_clave_16_by").unwrap();
        assert!(matches!(
            wrong_cipher.decrypt(&valid_ct),
            Err(CryptoError::InvalidPadding)
        ));
    }
}
