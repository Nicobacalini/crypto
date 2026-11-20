use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Caesar,
    Xor,
    Vigenere,
    Aes,
}

impl Algorithm {
    /// Identificador canónico esperado por `EncryptorFactory::create`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Caesar => "caesar",
            Self::Xor => "xor",
            Self::Vigenere => "vigenere",
            Self::Aes => "aes",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "cryptoserver",
    author = "CryptoServer Team",
    version,
    about = "Motor Criptográfico y Servidor Seguro en Rust"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Cifra un archivo de entrada usando el algoritmo especificado
    Encrypt {
        /// Algoritmo a utilizar
        #[arg(short, long, value_enum, ignore_case = true)]
        algo: Algorithm,
        /// Ruta del archivo de entrada
        #[arg(short, long)]
        input: PathBuf,
        /// Ruta del archivo cifrado de salida
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Descifra un archivo de entrada usando el algoritmo especificado
    Decrypt {
        /// Algoritmo a utilizar
        #[arg(short, long, value_enum, ignore_case = true)]
        algo: Algorithm,
        /// Ruta del archivo cifrado de entrada
        #[arg(short, long)]
        input: PathBuf,
        /// Ruta del archivo de salida descifrado
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_version_matches_cargo_manifest() {
        assert_eq!(
            Cli::command().get_version(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn cli_parses_encrypt_and_decrypt_short_and_long_flags() {
        let enc = Cli::try_parse_from([
            "cryptoserver",
            "encrypt",
            "-a",
            "aes",
            "-i",
            "in.txt",
            "-o",
            "out.enc",
        ])
        .unwrap();
        assert_eq!(
            match enc.command {
                Commands::Encrypt {
                    algo,
                    input,
                    output,
                } => (algo, input, output),
                Commands::Decrypt { .. } => panic!("se esperaba Encrypt"),
            },
            (
                Algorithm::Aes,
                PathBuf::from("in.txt"),
                PathBuf::from("out.enc")
            )
        );

        let dec = Cli::try_parse_from([
            "cryptoserver",
            "decrypt",
            "--algo",
            "vigenere",
            "--input",
            "out.enc",
            "--output",
            "restored.txt",
        ])
        .unwrap();
        assert_eq!(
            match dec.command {
                Commands::Decrypt {
                    algo,
                    input,
                    output,
                } => (algo, input, output),
                Commands::Encrypt { .. } => panic!("se esperaba Decrypt"),
            },
            (
                Algorithm::Vigenere,
                PathBuf::from("out.enc"),
                PathBuf::from("restored.txt")
            )
        );
    }

    #[test]
    fn cli_parses_algo_case_insensitively() {
        let aes = Cli::try_parse_from([
            "cryptoserver",
            "encrypt",
            "--algo",
            "AES",
            "-i",
            "a",
            "-o",
            "b",
        ])
        .unwrap();
        assert!(matches!(
            aes.command,
            Commands::Encrypt {
                algo: Algorithm::Aes,
                ..
            }
        ));

        let caesar = Cli::try_parse_from([
            "cryptoserver",
            "decrypt",
            "--algo",
            "Caesar",
            "-i",
            "a",
            "-o",
            "b",
        ])
        .unwrap();
        assert!(matches!(
            caesar.command,
            Commands::Decrypt {
                algo: Algorithm::Caesar,
                ..
            }
        ));
    }

    #[test]
    fn cli_rejects_unknown_algorithm_at_parse_time() {
        let res = Cli::try_parse_from([
            "cryptoserver",
            "encrypt",
            "--algo",
            "rot13",
            "-i",
            "a",
            "-o",
            "b",
        ]);
        assert!(res.is_err());
    }
}
