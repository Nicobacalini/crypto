mod cli;

use clap::Parser;
use cli::{Algorithm, Cli, Commands};
use cryptoserver::algorithms::EncryptorFactory;
use cryptoserver::utils::CryptoError;
use rpassword::prompt_password;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

fn main() {
    if let Err(err) = run() {
        eprintln!("❌ Error en la operación: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CryptoError> {
    let args = Cli::parse();
    let (algo, input, output, decrypt) = match args.command {
        Commands::Encrypt {
            algo,
            input,
            output,
        } => (algo, input, output, false),
        Commands::Decrypt {
            algo,
            input,
            output,
        } => (algo, input, output, true),
    };

    // Validar y leer el archivo de entrada antes de solicitar la clave al usuario.
    let data = Zeroizing::new(fs::read(&input)?);
    let key = ask_key(algo.as_str())?;
    let algo_name = transform_and_write(algo, &data, key.as_bytes(), &output, decrypt)?;

    let action = if decrypt { "descifrado" } else { "cifrado" };
    println!(
        "✅ Archivo '{}' {action} exitosamente con {algo_name} -> '{}'",
        input.display(),
        output.display()
    );
    Ok(())
}

/// Solicita de forma segura la clave por la terminal sin eco.
fn ask_key(algo: &str) -> Result<Zeroizing<String>, CryptoError> {
    let key = prompt_password(format!("🔑 Ingrese la clave para '{algo}': "))?;
    Ok(Zeroizing::new(key))
}

fn transform_and_write(
    algo: Algorithm,
    data: &[u8],
    key: &[u8],
    output: &Path,
    decrypt: bool,
) -> Result<&'static str, CryptoError> {
    let encryptor = EncryptorFactory::create(algo.as_str(), key)?;
    let result = if decrypt {
        Zeroizing::new(encryptor.decrypt(data)?)
    } else {
        Zeroizing::new(encryptor.encrypt(data)?)
    };
    write_file_secure(output, &result)?;
    Ok(encryptor.name())
}

fn resolve_parent_dir(output: &Path) -> &Path {
    match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Escribe un archivo de forma atómica con permisos restrictivos (`0o600` en Unix).
fn write_file_secure(output: &Path, content: &[u8]) -> Result<(), CryptoError> {
    let parent = resolve_parent_dir(output);

    let mut random_bytes = [0u8; 8];
    getrandom::getrandom(&mut random_bytes)?;
    let mut hex = String::with_capacity(16);
    for byte in random_bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    let tmp_path = parent.join(format!(".cryptoserver.tmp.{}.{hex}", std::process::id()));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(&tmp_path)?;
    let write_res = (|| -> std::io::Result<()> {
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, output)?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(prefix: &str) -> Self {
            let mut rnd = [0u8; 8];
            getrandom::getrandom(&mut rnd).unwrap();
            let mut hex = String::with_capacity(16);
            for b in rnd {
                let _ = write!(hex, "{b:02x}");
            }
            let path = std::env::temp_dir().join(format!(
                "cryptoserver_{prefix}_{}_{hex}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn resolve_parent_dir_handles_bare_filenames() {
        assert_eq!(resolve_parent_dir(Path::new("salida.enc")), Path::new("."));
        assert_eq!(
            resolve_parent_dir(Path::new("/tmp/sub/salida.enc")),
            Path::new("/tmp/sub")
        );
    }

    #[test]
    fn write_file_secure_creates_atomic_private_file_and_overwrites_cleanly() {
        let dir = TempDirGuard::new("secure_write");
        let target = dir.path.join("secreto.txt");

        write_file_secure(&target, b"primer contenido").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"primer contenido");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Sobrescritura atómica y sin residuos temporales
        write_file_secure(&target, b"segundo contenido").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"segundo contenido");

        let entries: Vec<_> = fs::read_dir(&dir.path)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["secreto.txt".to_string()]);
    }

    #[test]
    fn write_file_secure_fails_cleanly_on_missing_parent_dir() {
        let dir = TempDirGuard::new("missing_parent");
        let missing = dir.path.join("no_existe").join("archivo.enc");
        let res = write_file_secure(&missing, b"datos");
        assert!(matches!(res, Err(CryptoError::Io(_))));
    }

    #[test]
    fn transform_and_write_roundtrips_all_algorithms_and_in_place_overwrite() {
        let dir = TempDirGuard::new("roundtrip");
        let cases: &[(Algorithm, &[u8], &[u8])] = &[
            (Algorithm::Caesar, b"3", b"Mensaje secreto 123!"),
            (Algorithm::Xor, b"clave_xor", b"Binario \x00\xff secreto"),
            (Algorithm::Vigenere, b"LEMON", b"Attack at Dawn!"),
            (
                Algorithm::Aes,
                b"clave_de_16_byte",
                b"Bloque AES-128 exacto y seguro",
            ),
        ];

        for (idx, &(algo, key, plaintext)) in cases.iter().enumerate() {
            let plain_path = dir.path.join(format!("plain_{idx}.bin"));
            let enc_path = dir.path.join(format!("enc_{idx}.enc"));
            let dec_path = dir.path.join(format!("dec_{idx}.bin"));

            fs::write(&plain_path, plaintext).unwrap();
            let plain_bytes = fs::read(&plain_path).unwrap();
            let used_name = transform_and_write(algo, &plain_bytes, key, &enc_path, false).unwrap();
            assert_eq!(used_name, algo.as_str());

            let cipher_bytes = fs::read(&enc_path).unwrap();
            assert_ne!(cipher_bytes, plaintext);

            transform_and_write(algo, &cipher_bytes, key, &dec_path, true).unwrap();
            assert_eq!(fs::read(&dec_path).unwrap(), plaintext);
        }

        // Sobrescritura in-place (input == output)
        let inplace_path = dir.path.join("inplace.dat");
        let original = b"Contenido in-place AES-128";
        fs::write(&inplace_path, original).unwrap();
        let data_enc = fs::read(&inplace_path).unwrap();
        transform_and_write(
            Algorithm::Aes,
            &data_enc,
            b"0123456789abcdef",
            &inplace_path,
            false,
        )
        .unwrap();
        let data_dec = fs::read(&inplace_path).unwrap();
        transform_and_write(
            Algorithm::Aes,
            &data_dec,
            b"0123456789abcdef",
            &inplace_path,
            true,
        )
        .unwrap();
        assert_eq!(fs::read(&inplace_path).unwrap(), original);
    }
}
