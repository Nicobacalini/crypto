use cryptoserver::algorithms::{
    AesCipher, CaesarCipher, EncryptorFactory, VigenereCipher, XorCipher,
};
use cryptoserver::utils::{CryptoError, Encryptor};
use std::process::{Command, Stdio};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn ciphers_and_trait_object_are_send_and_sync() {
    assert_send_sync::<Box<dyn Encryptor>>();
    assert_send_sync::<AesCipher>();
    assert_send_sync::<CaesarCipher>();
    assert_send_sync::<VigenereCipher>();
    assert_send_sync::<XorCipher>();
}

#[test]
fn polymorphic_dispatch_roundtrips_all_algorithms() {
    let casos: &[(&str, &[u8], &[u8])] = &[
        ("caesar", b"3", b"Hello World!"),
        ("xor", b"clave_secreta", b"Datos binarios \x00\x01\xff"),
        ("vigenere", b"LEMON", b"ATTACK AT DAWN"),
        ("aes", b"0123456789abcdef", b"Mensaje confidencial AES-128"),
    ];

    for &(algo, key, plaintext) in casos {
        let cipher = EncryptorFactory::create(algo, key).unwrap();
        assert_eq!(cipher.name(), algo);
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

#[test]
fn error_contracts_and_no_secret_leakage() {
    let secret = "MiClaveUltraSecreta123!";

    assert!(matches!(
        EncryptorFactory::create("unknown", b"key"),
        Err(CryptoError::UnknownAlgorithm(_))
    ));
    assert!(matches!(
        EncryptorFactory::create("aes", b""),
        Err(CryptoError::EmptyKey)
    ));
    assert!(matches!(
        EncryptorFactory::create("xor", b""),
        Err(CryptoError::EmptyKey)
    ));

    let aes_err = EncryptorFactory::create("aes", secret.as_bytes())
        .err()
        .unwrap();
    assert!(matches!(aes_err, CryptoError::InvalidKey(_)));
    assert!(!aes_err.to_string().contains(secret));

    let vig_err = EncryptorFactory::create("vigenere", secret.as_bytes())
        .err()
        .unwrap();
    assert!(matches!(vig_err, CryptoError::InvalidKey(_)));
    assert!(!vig_err.to_string().contains(secret));

    let cae_err = EncryptorFactory::create("caesar", secret.as_bytes())
        .err()
        .unwrap();
    assert!(matches!(cae_err, CryptoError::InvalidKey(_)));
    assert!(!cae_err.to_string().contains(secret));

    let aes = EncryptorFactory::create("aes", b"0123456789abcdef").unwrap();
    assert!(matches!(
        aes.decrypt(&[0u8; 7]),
        Err(CryptoError::InvalidCiphertextLength)
    ));

    let mut ct = aes.encrypt(b"Prueba de padding").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert!(matches!(aes.decrypt(&ct), Err(CryptoError::InvalidPadding)));
}

#[test]
fn cli_binary_help_version_and_early_validation() {
    let bin = env!("CARGO_BIN_EXE_cryptoserver");

    let help = Command::new(bin)
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(help.status.success());
    let help_stdout = String::from_utf8_lossy(&help.stdout);
    assert!(help_stdout.contains("encrypt"));
    assert!(help_stdout.contains("decrypt"));

    let version = Command::new(bin)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(version.status.success());
    let ver_stdout = String::from_utf8_lossy(&version.stdout);
    assert!(ver_stdout.contains(env!("CARGO_PKG_VERSION")));

    let bad_algo = Command::new(bin)
        .args([
            "encrypt", "--algo", "rot13", "-i", "in.txt", "-o", "out.enc",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!bad_algo.status.success());

    let nonexistent = std::env::temp_dir().join(format!(
        "cryptoserver_inexistente_{}.bin",
        std::process::id()
    ));
    let out_dummy =
        std::env::temp_dir().join(format!("cryptoserver_out_dummy_{}.enc", std::process::id()));
    let missing_input = Command::new(bin)
        .args([
            "encrypt",
            "-a",
            "aes",
            "-i",
            nonexistent.to_str().unwrap(),
            "-o",
            out_dummy.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!missing_input.status.success());
    let stderr = String::from_utf8_lossy(&missing_input.stderr);
    assert!(
        !stderr.contains("Ingrese la clave"),
        "el CLI solicitó clave antes de verificar el archivo de entrada: {stderr}"
    );
}
