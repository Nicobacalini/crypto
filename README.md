# CryptoServer

Motor criptográfico simétrico modular y herramienta CLI en Rust. Implementa despacho dinámico polimórfico (`Encryptor` + `EncryptorFactory`), cifradores clásicos (`caesar`, `xor`, `vigenere`) y AES-128 implementado desde cero según NIST FIPS-197, con limpieza segura de memoria (`zeroize`), validación PKCS#7 en tiempo constante (`subtle`) y escritura atómica de archivos con permisos restrictivos.

---

## Inicio rápido (CLI)

```bash
# Cifrar un archivo con AES-128 (clave de 16 bytes solicitada sin eco por terminal)
cargo run -- encrypt -a aes -i mensaje.txt -o mensaje.enc

# Descifrar el archivo generado
cargo run -- decrypt -a aes -i mensaje.enc -o mensaje_restaurado.txt

# Consultar ayuda y versión del manifiesto
cargo run -- --help
cargo run -- --version
```

Comportamiento operativo de la CLI:
1. El argumento `-a`/`--algo` se valida al parsear comandos mediante `clap::ValueEnum` (sin distinguir mayúsculas/minúsculas).
2. El archivo de entrada (`-i`/`--input`) se lee y valida **antes** de solicitar la clave por terminal (`rpassword` sin eco).
3. El archivo de salida (`-o`/`--output`) se escribe mediante un temporal exclusivo con entropía `getrandom`, `sync_all`, permisos `0600` en Unix y `rename` atómico.

### Algoritmos soportados

| Identificador | Motor | Requisito de clave | Alcance / Propósito |
|---|---|---|---|
| `caesar` | `CaesarCipher` | Entero `0..=255` en UTF-8 | Sustitución monoalfabética ASCII ($Z_{26}$), uso pedagógico |
| `xor` | `XorCipher` | Bytes no vacíos | Flujo involutivo con clave repetida, ofuscación liviana |
| `vigenere` | `VigenereCipher` | Letras ASCII (`A-Z`, `a-z`) | Sustitución polialfabética ASCII, estudio histórico |
| `aes` | `AesCipher` | Exactamente 16 bytes (128 bits) | Bloque SPN FIPS-197 + PKCS#7 en modo ECB (primitiva base) |

---

## Estado del proyecto y Roadmap

| Estado | Componentes |
|---|---|
| **Implementado** | Trait `Encryptor` (`Send + Sync`), `CryptoError`, `EncryptorFactory`, `CaesarCipher`, `XorCipher`, `VigenereCipher`, `AesCipher`, CLI (`encrypt` / `decrypt`), escritura atómica `0600`, 38 pruebas unitarias + 4 de aceptación, pipeline de CI |
| **Pendiente (stubs)** | `src/container.rs` (formato `.enc v3`), `src/utils/crypto_utils.rs` (KDF, IV y salts CSPRNG), `src/utils/hmac_utils.rs` (HMAC en tiempo constante), `src/vault.rs` (negación plausible), `src/server/*` (cola productor-consumidor, logger, reportes JSON, watch 24/7) |

---

## Garantías de seguridad y límites actuales

| Control | Mecanismo aplicado |
|---|---|
| Ausencia de `unsafe` | `[lints.rust] unsafe_code = "forbid"` en `Cargo.toml` |
| Chequeo de desbordes | `[profile.release] overflow-checks = true` activo también en compilación optimizada |
| Limpieza de memoria | `ZeroizeOnDrop` en los 4 cifradores, limpieza de temporales `w`/`prev` en el key schedule de AES, limpieza de búfer ante fallo de relleno y `Zeroizing` para lectura/clave/salida en la CLI |
| Sin oráculo de padding | Validación PKCS#7 en tiempo constante sobre el último bloque con `subtle::{Choice, ConstantTimeEq}` y `xtime` sin ramas |
| Sin fuga en errores | Los mensajes de `CryptoError` nunca reflejan claves o contraseñas ingresadas |
| Escritura atómica privada | Archivo temporal exclusivo con sufijo aleatorio (`getrandom`), modo `0o600` en Unix, `sync_all()`, `fs::rename` y limpieza ante fallos |

> [!WARNING]
> **Límite de confidencialidad e integridad actual:** Los cifradores clásicos y `AesCipher` en modo ECB crudo sin KDF, IV único ni MAC/AEAD no protegen contra ataques de patrón, reordenamiento o manipulación activa en producción. El cifrado autenticado con derivación de claves corresponde a la capa del contenedor `.enc v3` pendiente.

---

## Arquitectura del proyecto

### Capas y flujo de ejecución actual

```text
  Usuario (CLI)
       │
       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Binario: src/main.rs + src/cli.rs (clap)                                   │
│  1. Cli::parse() valida comando y algoritmo (Algorithm: clap::ValueEnum)   │
│  2. fs::read(&input) previo al prompt -> Zeroizing<Vec<u8>>                │
│  3. ask_key() via rpassword (sin eco) -> Zeroizing<String>                 │
│  4. transform_and_write() -> EncryptorFactory::create(...)                 │
│  5. write_file_secure(): temp (getrandom) + 0o600 + sync_all + fs::rename  │
└───────────────────────────────────────┬────────────────────────────────────┘
                                        │ usa la API pública (sin clap)
                                        ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Biblioteca: src/lib.rs  (pub mod algorithms; pub mod utils;)               │
│                                                                            │
│  ┌──────────────────────────────────┐   ┌───────────────────────────────┐  │
│  │ algorithms/ (motores simétricos) │   │ utils/ (contratos y errores)  │  │
│  │  • EncryptorFactory::create      │──▶│  • trait Encryptor: Send+Sync │  │
│  │  • CaesarCipher   (ZeroizeOnDrop)│   │  • enum CryptoError           │  │
│  │  • XorCipher      (ZeroizeOnDrop)│   │    (thiserror, sin secretos)  │  │
│  │  • VigenereCipher (ZeroizeOnDrop)│   └───────────────────────────────┘  │
│  │  • AesCipher      (FIPS-197, CT) │                                      │
│  └──────────────────────────────────┘                                      │
└────────────────────────────────────────────────────────────────────────────┘
                                        ▲
                                        │ pruebas unitarias (38) + integración (4)
┌───────────────────────────────────────┴────────────────────────────────────┐
│ Verificación: tests unitarios en src/ + tests/aceptacion.rs (lib y binario)│
└────────────────────────────────────────────────────────────────────────────┘
```

### Estructura actual del repositorio

```text
cryptoserver/
├── .github/workflows/ci.yml    ← Pipeline de CI (fmt, clippy -D warnings, tests, doctests, release)
├── .gitignore                  ← Reglas de exclusión (target/, claves, *.vault, *.enc)
├── Cargo.toml                  ← Manifiesto, dependencias, profile.release y lint unsafe_code = "forbid"
├── Cargo.lock                  ← Resolución exacta de dependencias
├── README.md                   ← Documentación del proyecto
├── src/
│   ├── lib.rs                  ← API pública de la biblioteca (expone únicamente algorithms y utils)
│   ├── main.rs                 ← Punto de entrada binario, lectura previa, Zeroizing y write_file_secure
│   ├── cli.rs                  ← Definición privada al binario de comandos y clap::ValueEnum
│   ├── algorithms/             ← Motores criptográficos activos
│   │   ├── mod.rs              ← Re-exportaciones de algoritmos y del trait Encryptor
│   │   ├── factory.rs          ← EncryptorFactory (desacoplamiento dinámico)
│   │   ├── caesar.rs           ← Cifrado César (aritmética Z_26)
│   │   ├── xor.rs              ← XOR con repetición de clave
│   │   ├── vigenere.rs         ← Vigenère polialfabético
│   │   └── aes.rs              ← AES-128 (FIPS-197, INV_SBOX const fn, PKCS#7 en tiempo constante)
│   ├── utils/                  ← Contratos y modelo de errores activos
│   │   ├── mod.rs              ← Trait Encryptor (object-safe, Send + Sync) y re-exportación de CryptoError
│   │   └── error.rs            ← Enum CryptoError modelado con thiserror
│   │
│   │   # Stubs vacíos (0 bytes, aún no declarados en src/lib.rs ni src/utils/mod.rs):
│   ├── container.rs            ← Reservado: empaquetador y parser del formato .enc v3
│   ├── vault.rs                ← Reservado: contenedor VaultHeader / VaultEntry y negación plausible
│   ├── utils/crypto_utils.rs   ← Reservado: KDF (folding / PBKDF2), IV y salts CSPRNG
│   ├── utils/hmac_utils.rs     ← Reservado: HMAC incremental y verificación en tiempo constante
│   └── server/                 ← Reservado: servidor concurrente y observabilidad
│       ├── mod.rs
│       ├── logger.rs
│       ├── job_queue.rs
│       ├── report.rs
│       └── watch.rs
└── tests/
    └── aceptacion.rs           ← Suite de pruebas de integración y aceptación de biblioteca y binario
```

### ¿Por qué Rust?

En lenguajes tradicionales como C o C++, el programador debe invocar destructores manualmente, evitar punteros colgantes (*dangling pointers*), cuidar alineaciones en estructuras binarias y vigilar carreras de datos con herramientas externas. En Rust, el sistema de *ownership*, el *borrow checker* y los *lifetimes* previenen estas fallas en tiempo de compilación, complementados por `cargo` para dependencias, pruebas y análisis estático.

### Contrato polimórfico (`Encryptor` y `EncryptorFactory`)

`Encryptor` (`src/utils/mod.rs`, re-exportado en `src/algorithms/mod.rs`) es el contrato central del motor:
- **Object-safe (`dyn Encryptor`):** Sus métodos no tienen genéricos ni retornan `Self` por valor, permitiendo despacho dinámico mediante `Box<dyn Encryptor>` o `Arc<dyn Encryptor>`.
- **Concurrencia (`Send + Sync`):** Garantiza que cualquier motor instanciado por `EncryptorFactory::create` pueda compartirse entre hilos en futuras capas concurrentes.
- **Desacoplamiento:** `src/lib.rs` expone únicamente `algorithms` y `utils`; `src/cli.rs` pertenece exclusivamente al binario (`src/main.rs`) para no filtrar tipos de `clap` en la API pública de la biblioteca.

### Modelo de errores (`CryptoError`)

En Rust los fallos son valores tipados. El enum `CryptoError` (`src/utils/error.rs`), modelado con `thiserror`, centraliza tanto las variantes activas hoy (`EmptyKey`, `InvalidKey`, `InvalidCiphertextLength`, `InvalidPadding`, `UnknownAlgorithm`, `Io`, `Random`) como las reservadas para las próximas capas (`IntegrityCompromised`, `InvalidFormat`, `VaultAccessDenied`, `EntryNotFound`, `ReportSerialization`).

---

## Verificación y CI

Comandos ejecutados automáticamente en cada `push` y `pull_request` sobre `main`/`master` (`.github/workflows/ci.yml`):

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc
cargo build --release
```

---

## Referencia técnica de algoritmos

### CaesarCipher (`src/algorithms/caesar.rs`)

- **Fundamentos matemáticos:** Sustitución monoalfabética basada en aritmética modular sobre el alfabeto latino de $26$ letras. La transformación de un carácter $p$ mediante un desplazamiento $k$ se calcula mediante:
  $$C = ((p - \text{base} + k) \pmod{26}) + \text{base}$$
  donde $\text{base}$ corresponde a `b'A'` ($65$) para mayúsculas o `b'a'` ($97$) para minúsculas.

- **Relación de descifrado (Inversa):** Descifrar con un desplazamiento $k$ es matemáticamente equivalente a cifrar utilizando el desplazamiento complementario:
  $$k_{\text{descifrado}} = (26 - (k \pmod{26})) \pmod{26}$$

- **Tratamiento de caracteres y preservación:**
  - Se aplican transformaciones exclusivamente a los bytes que se encuentran en los rangos alfabéticos ASCII (`b'A'..=b'Z'` y `b'a'..=b'z'`).
  - **Preservación:** Cualquier byte fuera de estos rangos (números, espacios, signos de puntuación o secuencias UTF-8 multi-byte) se transmite intacto sin sufrir modificaciones.
  - **Normalización de claves:** Desplazamientos que superen el tamaño del alfabeto ($k \ge 26$) se reducen mediante la operación módulo ($k \pmod{26}$) para prevenir desbordamientos aritméticos (al ser de tipo `u8`, los valores negativos quedan prevenidos por el sistema de tipos en tiempo de compilación).

- **Complejidad:**
  - **Tiempo:** $\mathcal{O}(n)$, donde $n$ representa la cantidad de bytes o caracteres a procesar.
  - **Espacio:** $\mathcal{O}(n)$ debido a la asignación del búfer `Vec<u8>` resultante requerida por la firma del trait (sería $\mathcal{O}(1)$ si operase *in-place* sobre un búfer mutable).

- **Vulnerabilidades y Seguridad:**
  - **Espacio de claves reducido:** Solo existen $25$ claves posibles no triviales ($1 \le k \le 25$). Resulta totalmente vulnerable a ataques de fuerza bruta de ejecución instantánea y al análisis estadístico de frecuencias.

- **Uso ideal:** Fines educativos y pedagógicos, demostración de aritmética modular en tipos primitivos, ofuscación trivial de texto para evitar spoilers o respuestas (como ROT13) y pruebas unitarias de interfaces polimórficas.

---

### XorCipher (`src/algorithms/xor.rs`)

- **Fundamentos matemáticos:** Se fundamenta en la propiedad involutiva del operador binario XOR:
  $$(A \oplus K) \oplus K = A$$
  La clave se aplica de forma cíclica sobre la secuencia de bytes de entrada mediante la expresión:
  $$\text{data}[i] \oplus \text{key}[i \pmod{\text{key.len()}}]$$

- **Manejo de bordes (Caso crítico):** Si la clave está vacía ($\text{key.len()} = 0$), la evaluación de $i \pmod 0$ provocaría una división por cero no definida. El constructor `XorCipher::new` valida esta precondición y retorna de forma segura un error tipado `Err(CryptoError::EmptyKey)`, evitando *panics* o comportamientos indeterminados en tiempo de ejecución.

- **Complejidad:**
  - **Tiempo:** $\mathcal{O}(n)$, donde $n$ es la longitud total del mensaje en bytes.
  - **Espacio:** $\mathcal{O}(n)$ al retornar una nueva estructura `Vec<u8>` con los datos procesados.

- **Debilidades y Limitaciones:**
  - **Ataque de clave repetida:** Cuando la longitud del mensaje supera el tamaño de la clave, el patrón periódico expone los datos al análisis de frecuencias de bytes.
  - **Ataque de texto plano conocido (KPA):** Si un atacante obtiene una porción del texto plano original y su correspondiente texto cifrado, puede reconstruir la clave aplicando:
    $$K = P \oplus C$$

- **Uso ideal:** Cifrado simétrico de alta velocidad para datos temporales, manipulación de streams de datos, ofuscación liviana de recursos o propósitos pedagógicos.

---

### VigenereCipher (`src/algorithms/vigenere.rs`)

- **Fundamentos matemáticos:** Cifrado polialfabético que extiende el principio de César aplicando una secuencia periódica de desplazamientos basada en una clave alfabética de longitud $m$:
  - **Cifrado:** $C_i = (P_i + K_{i \pmod m}) \pmod{26}$
  - **Descifrado:** $P_i = (C_i - K_{i \pmod m} + 26) \pmod{26}$

- **Implementación y validación:**
  - La clave no puede estar vacía (retorna `Err(CryptoError::EmptyKey)`) y debe estar constituida exclusivamente por caracteres alfabéticos ASCII (`A-Z` / `a-z`), retornando `Err(CryptoError::InvalidKey)` sin exponer el valor ingresado en caso contrario.
  - Mantiene intacta la estructura del mensaje original: los caracteres no alfabéticos (espacios, signos de puntuación y dígitos) se preservan y no consumen caracteres de la clave (el índice de progresión de la clave no avanza).

- **Complejidad:**
  - **Tiempo:** $\mathcal{O}(n)$, procesando los caracteres secuencialmente.
  - **Espacio:** $\mathcal{O}(n)$ para almacenar el resultado del procesamiento.

- **Vulnerabilidades Criptográficas:**
  - **Análisis de Kasiski y prueba de Friedman:** Susceptible al análisis de frecuencias multivariado. Una vez identificada la longitud de la clave ($m$) mediante la búsqueda de repeticiones periódicas de n-gramas, el criptograma se reduce a $m$ cifrados César independientes.

- **Uso ideal:** Introducción académica a la criptografía polialfabética, estudio histórico de técnicas de criptoanálisis (método de Kasiski y test de Friedman) y ofuscación clásica de texto con mayor complejidad que la sustitución simple.

---

### AesCipher (`src/algorithms/aes.rs`)

- **Fundamentos matemáticos:** El algoritmo AES-128 es un cifrado por bloques simétrico basado en una Red de Sustitución y Permutación (SPN). Procesa la información en bloques fijos de 128 bits (16 bytes) utilizando una clave secreta de 128 bits (16 bytes) a lo largo de 10 rondas de transformación.
  Para lograr las propiedades de **confusión** (eliminar correlaciones entre la clave y el texto cifrado) y **difusión** (disipar los patrones del texto plano a lo largo de todo el texto cifrado), AES aplica transformaciones algebraicas sobre una estructura interna bidimensional llamada **Matriz de Estado** (*State Matrix*).

  1. **La matriz de Estado (State Matrix):**
     - Los 16 bytes que forman un bloque de datos se representan en una matriz bidimensional de 4x4 bytes organizada por columnas.
     Para la fila $r \in [0..3]$ y columna $c \in [0..3]$, la relación viene dada por:
     $$\text{índice} = r + 4 \times c$$

  2. **Las 4 transformaciones Criptográficas:**
     - **SubBytes:**
       - **Objetivo:** Reemplaza cada byte del estado por otro byte de forma independiente mediante una función de sustitución no lineal.
       - **Fundamento Matemático:** Se obtiene calculando la inversa multiplicativa en el Cuerpo de Galois $GF(2^8)$ respecto al polinomio irreducible binario:
         $$m(x) = x^8 + x^4 + x^3 + x + 1 \quad (\text{representación hexadecimal: } 0x11B)$$
         Posteriormente, sobre dicho valor inverso se aplica una transformación afín sobre $\mathbb{F}_2^8$.
       - **S-BOX:** Para evitar ejecutar estas operaciones algebraicas complejas en tiempo de ejecución, los 256 resultados posibles se precalculan en una tabla de búsqueda llamada S-BOX (`SBOX[byte]`).
       - **Descifrado:** Se emplea la tabla inversa InvSubBytes (`INV_SBOX`), donde se satisface la relación `INV_SBOX[SBOX[x]] == x`.

     - **ShiftRows:**
       - **Objetivo:** Permuta cíclicamente las filas de la matriz de estado hacia la izquierda para entrelazar las columnas entre sí.
       - **Regla de rotación por fila:**
         - **Fila 0:** No rota (desplazamiento de 0 bytes).
         - **Fila 1:** Desplaza 1 byte hacia la izquierda.
         - **Fila 2:** Desplaza 2 bytes hacia la izquierda.
         - **Fila 3:** Desplaza 3 bytes hacia la izquierda.
       - **Descifrado (InvShiftRows):** Rota exactamente las mismas posiciones pero en sentido inverso (hacia la derecha).

     - **MixColumns:**
       - **Objetivo:** Mezcla linealmente cada columna del estado interpretándola como un polinomio de grado menor a 4 sobre el cuerpo finito $GF(2^8)$.
       - **Multiplicación Matricial:** Cada columna $(a_0, a_1, a_2, a_3)^T$ se multiplica por una matriz circular fija.
       - **Álgebra en el Cuerpo de Galois $GF(2^8)$:**
         - La adición en $GF(2^8)$ se realiza mediante la operación lógica XOR ($\oplus$).
         - La multiplicación por 02 se denomina `xtime(b)`: consiste en desplazar el byte $b$ un bit a la izquierda; si el bit más significativo (MSB) previo al desplazamiento era 1, se aplica una reducción modular mediante un XOR con la constante $0x1B$ (implementada sin ramas en `aes.rs`).
         - Multiplicaciones por otros coeficientes se derivan combinando `xtime` y XOR (por ejemplo, $\text{mul3}(b) = \text{xtime}(b) \oplus b$).
       - **Descifrado (InvMixColumns):** Multiplica cada columna por la matriz circular inversa con los coeficientes $\{0E, 0B, 0D, 09\}$ ($14, 11, 13 \text{ y } 9$ en decimal).

     - **AddRoundKey (Inyección de Clave):**
       - **Objetivo:** Aplica una operación XOR bit a bit entre los 16 bytes de la matriz de estado y los 16 bytes de la Subclave de Ronda correspondiente.
       - **Propiedad Involutiva:** Al ser la operación XOR su propia inversa ($(S \oplus K) \oplus K = S$), la transformación de descifrado utiliza la misma operación lógica.

3. **Expansión de Claves (Key Schedule)**
    - Para abastecer a las 10 rondas de procesamiento, la clave secreta inicial de 16 bytes (128 bits) se expande hasta obtener 11 subclaves de ronda ($11 \times 16 = 176$ bytes en total):
        - **Subclave 0:** Corresponde exactamente a la clave original de entrada.
        - **Generación de Subclaves 1 a 10:** Para cada ronda $r \in [1..10]$, la columna inicial de la subclave se calcula a partir de la última columna $W$ de la subclave anterior pasando por:
            - **RotWord:** Rotación circular de 1 byte a la izquierda ($[w_0, w_1, w_2, w_3] \to [w_1, w_2, w_3, w_0]$).
            - **SubWord:** Sustitución de cada byte mediante la S-BOX.
            - **Constante de Ronda ($Rcon[r]$):** Operación XOR del primer byte con el elemento $Rcon[r]$ derivado en $GF(2^8)$ ($[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]$).
            - **Encadenamiento XOR:** Con la columna equivalente de la subclave previa.

4. **Flujo Algorítmico y Secuencia de Rondas**
    - El orden en el que se aplican las transformaciones difiere ligeramente entre el cifrado y el descifrado:
        - **Secuencia de Cifrado:**
            - AddRoundKey (con Subclave 0).
            - **Rondas 1 a 9 (Rondas intermedias):** SubBytes $\to$ ShiftRows $\to$ MixColumns $\to$ AddRoundKey.
            - **Ronda 10 (Ronda final):** SubBytes $\to$ ShiftRows $\to$ AddRoundKey (se omite MixColumns en la última ronda).
        - **Secuencia de Descifrado:**
            - AddRoundKey (con Subclave 10).
            - **Rondas 9 a 1 (Rondas intermedias en orden descendente):** InvShiftRows $\to$ InvSubBytes $\to$ AddRoundKey $\to$ InvMixColumns (InvMixColumns se ejecuta después de AddRoundKey).
            - **Ronda Final:** InvShiftRows $\to$ InvSubBytes $\to$ AddRoundKey (con Subclave 0).

5. **Relleno de Bloques (Padding PKCS#7)**
    - Puesto que AES trabaja estrictamente sobre bloques múltiplos de 16 bytes, los mensajes cuyo tamaño no coincida con este requisito se adaptan mediante la norma PKCS#7:
        - Se calcula el número de bytes faltantes $pad = 16 - (\text{longitud} \pmod{16})$.
        - Se concatenan $pad$ bytes, conteniendo cada uno el valor numérico $pad$.
        - **Regla de borde:** Si los datos originales ya miden un múltiplo exacto de 16 bytes, se añade obligatoriamente un bloque completo adicional de 16 bytes con el valor 16 ($0x10$) para impedir ambigüedades durante la remoción del relleno.

- **Implementación y validación:**
  - Validación estricta de clave: `CryptoError::EmptyKey` para claves vacías y `CryptoError::InvalidKey` (sin filtrar el valor ingresado) para longitudes distintas de 16 bytes (128 bits).
  - Derivación de `INV_SBOX` en tiempo de compilación mediante `const fn` (`build_inv_sbox`), evitando almacenamiento y cómputo redundante por instancia.
  - Limpieza automática en memoria de subclaves y temporales (`zeroize::ZeroizeOnDrop`), operación `xtime` sin ramas y validación PKCS#7 en tiempo constante (`subtle`) para mitigar oráculos de relleno.
  - Manejo de bordes en el descifrado: validación de tamaño múltiplo de 16 y rechazo determinista de rellenos corruptos (`CryptoError::InvalidPadding`).
  - Verificación unitaria contra el vector de prueba oficial NIST FIPS-197 (Apéndice C.1).

- **Complejidad:**
  - **Tiempo:** $\mathcal{O}(1)$ para `new` (expansión de 11 subclaves) y $\mathcal{O}(n)$ para `encrypt` / `decrypt` procesando bloques de 16 bytes a lo largo de 10 rondas.
  - **Espacio:** $\mathcal{O}(1)$ en memoria interna (176 bytes de subclaves por instancia y tabla `INV_SBOX` estática de 256 bytes en tiempo de compilación) y $\mathcal{O}(n)$ para el búfer `Vec<u8>` de salida.

- **Vulnerabilidades Criptográficas:**
  - Fuga de patrones estructurales por el modo ECB (*Electronic Codebook*).
  - Ausencia de autenticación de integridad (vulnerable a manipulación activa de bloques sin un esquema HMAC/AEAD).
  - Ataques de canal lateral (*cache-timing*) por búsquedas en tablas `SBOX`/`INV_SBOX` basadas en claves/datos.

- **Uso ideal:**
  - Cifrado simétrico de nivel estándar para bloques fijos de datos.
  - Demostración académica y pedagógica de redes SPN y aritmética $GF(2^8)$ sin librerías externas.
  - Base para modos encadenados (CBC con IV, CTR) o cifrado autenticado.
