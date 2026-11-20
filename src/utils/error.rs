use thiserror::Error;

/// Modelo de error unico del sistema: en Rust los fallos son valores tipados, no excepciones.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("La clave o contraseña no puede estar vacia")]
    EmptyKey,

    #[error("Clave con formato o caracteres invalidos: {0}")]
    InvalidKey(String),

    #[error("Longitud de ciphertext invalida (debe ser multiplo del bloque)")]
    InvalidCiphertextLength,

    #[error("Padding PKCS#7 invalido o corrupto")]
    InvalidPadding,

    #[error("Algoritmo desconocido o no soportado: {0}")]
    UnknownAlgorithm(String),

    #[error("¡ALERTA! Integridad comprometida (archivo manipulado o clave erronea)")]
    IntegrityCompromised,

    #[error("Formato binario o numero magico invalido: {0}")]
    InvalidFormat(String),

    /// Respuesta homogenea y generica que preserva la Negacion Plausible (Ext 6)
    #[error("Acceso denegado al contenedor")]
    VaultAccessDenied,

    #[error("Entrada no encontrada en el vault: {0}")]
    EntryNotFound(String),

    #[error("Error de entrada/salida en disco: {0}")]
    Io(#[from] std::io::Error),

    #[error("Fallo del generador aleatorio del sistema operativo: {0}")]
    Random(#[from] getrandom::Error),

    #[error("Error al serializar telemetria de sesion")]
    ReportSerialization,
}
