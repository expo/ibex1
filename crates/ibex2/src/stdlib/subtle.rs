//! Engine-free WebCrypto algorithms and owned secret keys.
//!
//! The JavaScript binding stores these values behind runtime-owned handles;
//! only an explicit export of an extractable key exposes its material.
//!
//! @ref LLP 0059.000#314-cryptosubtle--pure-ungated-author-required — opaque keys and the L2a algorithm set

#[cfg(feature = "crypto")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::fmt;

/// PBKDF2 remains a synchronous pure operation under LLP 0059.000 §1.1, so
/// bound the work admitted by one host call instead of allowing an unbounded
/// iteration count to monopolize the runtime thread.
pub const MAX_PBKDF2_ITERATIONS: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorName {
    NotSupportedError,
    InvalidAccessError,
    DataError,
    OperationError,
    SyntaxError,
}

impl ErrorName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotSupportedError => "NotSupportedError",
            Self::InvalidAccessError => "InvalidAccessError",
            Self::DataError => "DataError",
            Self::OperationError => "OperationError",
            Self::SyntaxError => "SyntaxError",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub name: ErrorName,
    pub message: String,
}

impl Error {
    fn new(name: ErrorName, message: impl Into<String>) -> Self {
        Self {
            name,
            message: message.into(),
        }
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorName::NotSupportedError, message)
    }

    #[cfg(feature = "crypto")]
    fn invalid_access(message: impl Into<String>) -> Self {
        Self::new(ErrorName::InvalidAccessError, message)
    }

    #[cfg(feature = "crypto")]
    fn data(message: impl Into<String>) -> Self {
        Self::new(ErrorName::DataError, message)
    }

    #[cfg(feature = "crypto")]
    fn operation(message: impl Into<String>) -> Self {
        Self::new(ErrorName::OperationError, message)
    }

    fn syntax(message: impl Into<String>) -> Self {
        Self::new(ErrorName::SyntaxError, message)
    }

    pub fn feature_unavailable() -> Self {
        Self::unsupported("crypto.subtle was omitted from this build")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name.as_str(), self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    pub const fn output_bits(self) -> usize {
        match self {
            Self::Sha256 => 256,
            Self::Sha384 => 384,
            Self::Sha512 => 512,
        }
    }

    #[cfg(feature = "crypto")]
    const fn hmac_default_bits(self) -> usize {
        match self {
            Self::Sha256 => 512,
            Self::Sha384 | Self::Sha512 => 1024,
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        match name.to_ascii_uppercase().as_str() {
            "SHA-256" => Ok(Self::Sha256),
            "SHA-384" => Ok(Self::Sha384),
            "SHA-512" => Ok(Self::Sha512),
            _ => Err(Error::unsupported(format!(
                "digest algorithm {name} is not supported"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyUsage {
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    Sign,
    Verify,
    DeriveKey,
    DeriveBits,
}

impl KeyUsage {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::WrapKey => "wrapKey",
            Self::UnwrapKey => "unwrapKey",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::DeriveKey => "deriveKey",
            Self::DeriveBits => "deriveBits",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "encrypt" => Ok(Self::Encrypt),
            "decrypt" => Ok(Self::Decrypt),
            "wrapKey" => Ok(Self::WrapKey),
            "unwrapKey" => Ok(Self::UnwrapKey),
            "sign" => Ok(Self::Sign),
            "verify" => Ok(Self::Verify),
            "deriveKey" => Ok(Self::DeriveKey),
            "deriveBits" => Ok(Self::DeriveBits),
            _ => Err(Error::syntax(format!("unknown key usage {value}"))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyAlgorithm {
    Hmac {
        hash: HashAlgorithm,
        length_bits: usize,
    },
    AesGcm {
        length_bits: usize,
    },
    Hkdf,
    Pbkdf2,
}

impl KeyAlgorithm {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Hmac { .. } => "HMAC",
            Self::AesGcm { .. } => "AES-GCM",
            Self::Hkdf => "HKDF",
            Self::Pbkdf2 => "PBKDF2",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportAlgorithm {
    Hmac {
        hash: HashAlgorithm,
        length_bits: Option<usize>,
    },
    AesGcm,
    Hkdf,
    Pbkdf2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerateAlgorithm {
    Hmac {
        hash: HashAlgorithm,
        length_bits: Option<usize>,
    },
    AesGcm {
        length_bits: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivedKeyAlgorithm {
    Hmac {
        hash: HashAlgorithm,
        length_bits: Option<usize>,
    },
    AesGcm {
        length_bits: usize,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum DeriveAlgorithm<'a> {
    Hkdf {
        hash: HashAlgorithm,
        salt: &'a [u8],
        info: &'a [u8],
    },
    Pbkdf2 {
        hash: HashAlgorithm,
        salt: &'a [u8],
        iterations: u32,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct AesGcmParams<'a> {
    pub iv: &'a [u8],
    pub additional_data: &'a [u8],
    pub tag_length_bits: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFormat {
    Raw,
    Jwk,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonWebKey {
    pub kty: String,
    pub k: String,
    pub alg: Option<String>,
    pub key_use: Option<String>,
    pub key_ops: Option<Vec<String>>,
    pub ext: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportedKey {
    Raw(Vec<u8>),
    Jwk(JsonWebKey),
}

/// An owned secret key. Debug output deliberately excludes material.
pub struct CryptoKey {
    material: Vec<u8>,
    algorithm: KeyAlgorithm,
    extractable: bool,
    usages: Vec<KeyUsage>,
}

impl fmt::Debug for CryptoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoKey")
            .field("type", &"secret")
            .field("algorithm", &self.algorithm)
            .field("extractable", &self.extractable)
            .field("usages", &self.usages)
            .finish_non_exhaustive()
    }
}

impl Drop for CryptoKey {
    fn drop(&mut self) {
        self.material.fill(0);
    }
}

impl CryptoKey {
    pub const fn key_type(&self) -> &'static str {
        "secret"
    }

    pub const fn extractable(&self) -> bool {
        self.extractable
    }

    pub const fn algorithm(&self) -> &KeyAlgorithm {
        &self.algorithm
    }

    pub fn usages(&self) -> &[KeyUsage] {
        &self.usages
    }

    #[cfg(feature = "crypto")]
    fn permits(&self, usage: KeyUsage) -> bool {
        self.usages.contains(&usage)
    }
}

#[cfg(feature = "crypto")]
fn validate_usages(usages: &[KeyUsage], allowed: &[KeyUsage]) -> Result<Vec<KeyUsage>> {
    let mut normalized = Vec::with_capacity(usages.len());
    for usage in usages {
        if !allowed.contains(usage) {
            return Err(Error::syntax(format!(
                "{} is not a valid usage for this key",
                usage.name()
            )));
        }
        if !normalized.contains(usage) {
            normalized.push(*usage);
        }
    }
    Ok(normalized)
}

#[cfg(feature = "crypto")]
fn require_usage(key: &CryptoKey, usage: KeyUsage) -> Result<()> {
    if key.permits(usage) {
        Ok(())
    } else {
        Err(Error::invalid_access(format!(
            "key does not allow {}",
            usage.name()
        )))
    }
}

#[cfg(feature = "crypto")]
fn jwk_algorithm(algorithm: &KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Hmac {
            hash: HashAlgorithm::Sha256,
            ..
        } => "HS256",
        KeyAlgorithm::Hmac {
            hash: HashAlgorithm::Sha384,
            ..
        } => "HS384",
        KeyAlgorithm::Hmac {
            hash: HashAlgorithm::Sha512,
            ..
        } => "HS512",
        KeyAlgorithm::AesGcm { length_bits: 128 } => "A128GCM",
        KeyAlgorithm::AesGcm { length_bits: 256 } => "A256GCM",
        _ => "",
    }
}

#[cfg(feature = "crypto")]
fn validate_jwk(
    jwk: &JsonWebKey,
    expected_alg: &str,
    extractable: bool,
    usages: &[KeyUsage],
) -> Result<()> {
    if jwk.kty != "oct" {
        return Err(Error::data("JWK kty must be oct"));
    }
    if let Some(alg) = &jwk.alg {
        if alg != expected_alg {
            return Err(Error::data(
                "JWK alg does not match the requested algorithm",
            ));
        }
    }
    if extractable && jwk.ext == Some(false) {
        return Err(Error::data(
            "a non-extractable JWK cannot be imported as extractable",
        ));
    }
    if let Some(ops) = &jwk.key_ops {
        for usage in usages {
            if !ops.iter().any(|op| op == usage.name()) {
                return Err(Error::data(
                    "JWK key_ops does not contain every requested usage",
                ));
            }
        }
    }
    if let Some(key_use) = &jwk.key_use {
        let expected = if expected_alg.starts_with("HS") {
            "sig"
        } else {
            "enc"
        };
        if key_use != expected {
            return Err(Error::data(
                "JWK use is inconsistent with the requested algorithm",
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "crypto")]
fn validate_aes_length(length_bits: usize) -> Result<()> {
    match length_bits {
        128 | 256 => Ok(()),
        192 => Err(Error::unsupported("AES-GCM-192 is not supported by ring")),
        _ => Err(Error::data("AES-GCM keys must be 128 or 256 bits")),
    }
}

#[cfg(feature = "crypto")]
fn import_material(
    material: Vec<u8>,
    algorithm: ImportAlgorithm,
    extractable: bool,
    usages: &[KeyUsage],
) -> Result<CryptoKey> {
    let (algorithm, usages) = match algorithm {
        ImportAlgorithm::Hmac { hash, length_bits } => {
            if material.is_empty() {
                return Err(Error::data("HMAC key data must not be empty"));
            }
            let available = material.len() * 8;
            let length_bits = length_bits.unwrap_or(available);
            if length_bits == 0 || length_bits > available || length_bits <= available - 8 {
                return Err(Error::data(
                    "HMAC length does not describe the supplied key data",
                ));
            }
            (
                KeyAlgorithm::Hmac { hash, length_bits },
                validate_usages(usages, &[KeyUsage::Sign, KeyUsage::Verify])?,
            )
        }
        ImportAlgorithm::AesGcm => {
            let length_bits = material.len() * 8;
            validate_aes_length(length_bits)?;
            (
                KeyAlgorithm::AesGcm { length_bits },
                validate_usages(
                    usages,
                    &[
                        KeyUsage::Encrypt,
                        KeyUsage::Decrypt,
                        KeyUsage::WrapKey,
                        KeyUsage::UnwrapKey,
                    ],
                )?,
            )
        }
        ImportAlgorithm::Hkdf => {
            if extractable {
                return Err(Error::syntax("HKDF base keys must be non-extractable"));
            }
            (
                KeyAlgorithm::Hkdf,
                validate_usages(usages, &[KeyUsage::DeriveKey, KeyUsage::DeriveBits])?,
            )
        }
        ImportAlgorithm::Pbkdf2 => {
            if extractable {
                return Err(Error::syntax("PBKDF2 base keys must be non-extractable"));
            }
            (
                KeyAlgorithm::Pbkdf2,
                validate_usages(usages, &[KeyUsage::DeriveKey, KeyUsage::DeriveBits])?,
            )
        }
    };
    if usages.is_empty() {
        return Err(Error::syntax(
            "secret keys must have at least one permitted usage",
        ));
    }
    Ok(CryptoKey {
        material,
        algorithm,
        extractable,
        usages,
    })
}

pub fn import_raw_key(
    material: &[u8],
    algorithm: ImportAlgorithm,
    extractable: bool,
    usages: &[KeyUsage],
) -> Result<CryptoKey> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (material, algorithm, extractable, usages);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    import_material(material.to_vec(), algorithm, extractable, usages)
}

pub fn import_jwk_key(
    jwk: &JsonWebKey,
    algorithm: ImportAlgorithm,
    extractable: bool,
    usages: &[KeyUsage],
) -> Result<CryptoKey> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (jwk, algorithm, extractable, usages);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    {
        if matches!(algorithm, ImportAlgorithm::Hkdf | ImportAlgorithm::Pbkdf2) {
            return Err(Error::unsupported("HKDF and PBKDF2 accept raw keys only"));
        }
        let material = URL_SAFE_NO_PAD
            .decode(jwk.k.as_bytes())
            .map_err(|_| Error::data("JWK k is not unpadded base64url"))?;
        let expected = match algorithm {
            ImportAlgorithm::Hmac { hash, .. } => match hash {
                HashAlgorithm::Sha256 => "HS256",
                HashAlgorithm::Sha384 => "HS384",
                HashAlgorithm::Sha512 => "HS512",
            },
            ImportAlgorithm::AesGcm => match material.len() * 8 {
                128 => "A128GCM",
                192 => return Err(Error::unsupported("AES-GCM-192 is not supported by ring")),
                256 => "A256GCM",
                _ => return Err(Error::data("AES-GCM JWK has an invalid key length")),
            },
            _ => unreachable!(),
        };
        validate_jwk(jwk, expected, extractable, usages)?;
        import_material(material, algorithm, extractable, usages)
    }
}

pub fn export_key(format: KeyFormat, key: &CryptoKey) -> Result<ExportedKey> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (format, key);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    {
        if !key.extractable {
            return Err(Error::invalid_access("key is not extractable"));
        }
        if matches!(key.algorithm, KeyAlgorithm::Hkdf | KeyAlgorithm::Pbkdf2) {
            return Err(Error::unsupported(
                "derivation base keys cannot be exported",
            ));
        }
        Ok(match format {
            KeyFormat::Raw => ExportedKey::Raw(key.material.clone()),
            KeyFormat::Jwk => ExportedKey::Jwk(JsonWebKey {
                kty: "oct".into(),
                k: URL_SAFE_NO_PAD.encode(&key.material),
                alg: Some(jwk_algorithm(&key.algorithm).into()),
                key_use: None,
                key_ops: Some(key.usages.iter().map(|usage| usage.name().into()).collect()),
                ext: Some(key.extractable),
            }),
        })
    }
}

pub fn generate_key(
    algorithm: GenerateAlgorithm,
    extractable: bool,
    usages: &[KeyUsage],
) -> Result<CryptoKey> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (algorithm, extractable, usages);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    {
        if usages.is_empty() {
            return Err(Error::syntax(
                "generated secret keys need at least one usage",
            ));
        }
        let (import, length_bits) = match algorithm {
            GenerateAlgorithm::Hmac { hash, length_bits } => {
                let length = length_bits.unwrap_or_else(|| hash.hmac_default_bits());
                if length == 0 || !length.is_multiple_of(8) {
                    return Err(Error::operation(
                        "HMAC key length must be a positive multiple of 8",
                    ));
                }
                (
                    ImportAlgorithm::Hmac {
                        hash,
                        length_bits: Some(length),
                    },
                    length,
                )
            }
            GenerateAlgorithm::AesGcm { length_bits } => {
                validate_aes_length(length_bits)?;
                (ImportAlgorithm::AesGcm, length_bits)
            }
        };
        let mut material = vec![0; length_bits / 8];
        super::crypto::get_random_values(&mut material)
            .map_err(|error| Error::operation(error.to_string()))?;
        import_material(material, import, extractable, usages)
    }
}

pub fn digest(hash: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (hash, data);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    {
        let algorithm = match hash {
            HashAlgorithm::Sha256 => &ring::digest::SHA256,
            HashAlgorithm::Sha384 => &ring::digest::SHA384,
            HashAlgorithm::Sha512 => &ring::digest::SHA512,
        };
        Ok(ring::digest::digest(algorithm, data).as_ref().to_vec())
    }
}

#[cfg(feature = "crypto")]
fn hmac_algorithm(hash: HashAlgorithm) -> ring::hmac::Algorithm {
    match hash {
        HashAlgorithm::Sha256 => ring::hmac::HMAC_SHA256,
        HashAlgorithm::Sha384 => ring::hmac::HMAC_SHA384,
        HashAlgorithm::Sha512 => ring::hmac::HMAC_SHA512,
    }
}

pub fn sign(key: &CryptoKey, data: &[u8]) -> Result<Vec<u8>> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (key, data);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    {
        require_usage(key, KeyUsage::Sign)?;
        let KeyAlgorithm::Hmac { hash, .. } = key.algorithm else {
            return Err(Error::invalid_access("sign requires an HMAC key"));
        };
        let key = ring::hmac::Key::new(hmac_algorithm(hash), &key.material);
        Ok(ring::hmac::sign(&key, data).as_ref().to_vec())
    }
}

pub fn verify(key: &CryptoKey, signature: &[u8], data: &[u8]) -> Result<bool> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (key, signature, data);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    {
        require_usage(key, KeyUsage::Verify)?;
        let KeyAlgorithm::Hmac { hash, .. } = key.algorithm else {
            return Err(Error::invalid_access("verify requires an HMAC key"));
        };
        let key = ring::hmac::Key::new(hmac_algorithm(hash), &key.material);
        Ok(ring::hmac::verify(&key, data, signature).is_ok())
    }
}

#[cfg(feature = "crypto")]
fn aes_key(key: &CryptoKey) -> Result<ring::aead::LessSafeKey> {
    let KeyAlgorithm::AesGcm { length_bits } = key.algorithm else {
        return Err(Error::invalid_access("AES-GCM requires an AES-GCM key"));
    };
    let algorithm = match length_bits {
        128 => &ring::aead::AES_128_GCM,
        256 => &ring::aead::AES_256_GCM,
        _ => return Err(Error::invalid_access("unsupported AES-GCM key length")),
    };
    ring::aead::UnboundKey::new(algorithm, &key.material)
        .map(ring::aead::LessSafeKey::new)
        .map_err(|_| Error::operation("AES-GCM key setup failed"))
}

#[cfg(feature = "crypto")]
fn aes_nonce(params: AesGcmParams<'_>) -> Result<ring::aead::Nonce> {
    if params.tag_length_bits != 128 {
        return Err(Error::operation("ring supports only 128-bit AES-GCM tags"));
    }
    ring::aead::Nonce::try_assume_unique_for_key(params.iv)
        .map_err(|_| Error::operation("ring supports only 96-bit AES-GCM IVs"))
}

pub fn encrypt(key: &CryptoKey, params: AesGcmParams<'_>, plaintext: &[u8]) -> Result<Vec<u8>> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (key, params, plaintext);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    {
        require_usage(key, KeyUsage::Encrypt)?;
        let key = aes_key(key)?;
        let nonce = aes_nonce(params)?;
        let mut output = plaintext.to_vec();
        key.seal_in_place_append_tag(
            nonce,
            ring::aead::Aad::from(params.additional_data),
            &mut output,
        )
        .map_err(|_| Error::operation("AES-GCM encryption failed"))?;
        Ok(output)
    }
}

pub fn decrypt(key: &CryptoKey, params: AesGcmParams<'_>, ciphertext: &[u8]) -> Result<Vec<u8>> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (key, params, ciphertext);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    {
        require_usage(key, KeyUsage::Decrypt)?;
        let key = aes_key(key)?;
        let nonce = aes_nonce(params)?;
        let mut output = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(
                nonce,
                ring::aead::Aad::from(params.additional_data),
                &mut output,
            )
            .map_err(|_| Error::operation("AES-GCM authentication failed"))?;
        let length = plaintext.len();
        output.truncate(length);
        Ok(output)
    }
}

#[cfg(feature = "crypto")]
fn derive_material(
    algorithm: DeriveAlgorithm<'_>,
    base_key: &CryptoKey,
    usage: KeyUsage,
    length_bits: usize,
) -> Result<Vec<u8>> {
    require_usage(base_key, usage)?;
    if !length_bits.is_multiple_of(8) {
        return Err(Error::operation("derived length must be a multiple of 8"));
    }
    let mut output = vec![0; length_bits / 8];
    match algorithm {
        DeriveAlgorithm::Hkdf { hash, salt, info } => {
            if base_key.algorithm != KeyAlgorithm::Hkdf {
                return Err(Error::invalid_access("HKDF requires an HKDF base key"));
            }
            let algorithm = match hash {
                HashAlgorithm::Sha256 => ring::hkdf::HKDF_SHA256,
                HashAlgorithm::Sha384 => ring::hkdf::HKDF_SHA384,
                HashAlgorithm::Sha512 => ring::hkdf::HKDF_SHA512,
            };
            struct Length(usize);
            impl ring::hkdf::KeyType for Length {
                fn len(&self) -> usize {
                    self.0
                }
            }
            let salt = ring::hkdf::Salt::new(algorithm, salt);
            let prk = salt.extract(&base_key.material);
            let info = [info];
            prk.expand(&info, Length(output.len()))
                .and_then(|okm| okm.fill(&mut output))
                .map_err(|_| Error::operation("HKDF requested too much output"))?;
        }
        DeriveAlgorithm::Pbkdf2 {
            hash,
            salt,
            iterations,
        } => {
            if base_key.algorithm != KeyAlgorithm::Pbkdf2 {
                return Err(Error::invalid_access("PBKDF2 requires a PBKDF2 base key"));
            }
            let iterations = std::num::NonZeroU32::new(iterations)
                .ok_or_else(|| Error::operation("PBKDF2 iterations must be non-zero"))?;
            if iterations.get() > MAX_PBKDF2_ITERATIONS {
                return Err(Error::operation(format!(
                    "PBKDF2 iterations exceed the per-call limit of {MAX_PBKDF2_ITERATIONS}"
                )));
            }
            let algorithm = match hash {
                HashAlgorithm::Sha256 => ring::pbkdf2::PBKDF2_HMAC_SHA256,
                HashAlgorithm::Sha384 => ring::pbkdf2::PBKDF2_HMAC_SHA384,
                HashAlgorithm::Sha512 => ring::pbkdf2::PBKDF2_HMAC_SHA512,
            };
            ring::pbkdf2::derive(algorithm, iterations, salt, &base_key.material, &mut output);
        }
    }
    Ok(output)
}

pub fn derive_bits(
    algorithm: DeriveAlgorithm<'_>,
    base_key: &CryptoKey,
    length_bits: usize,
) -> Result<Vec<u8>> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (algorithm, base_key, length_bits);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    derive_material(algorithm, base_key, KeyUsage::DeriveBits, length_bits)
}

pub fn derive_key(
    algorithm: DeriveAlgorithm<'_>,
    base_key: &CryptoKey,
    derived: DerivedKeyAlgorithm,
    extractable: bool,
    usages: &[KeyUsage],
) -> Result<CryptoKey> {
    #[cfg(not(feature = "crypto"))]
    {
        let _ = (algorithm, base_key, derived, extractable, usages);
        Err(Error::feature_unavailable())
    }
    #[cfg(feature = "crypto")]
    {
        let (import, length_bits) = match derived {
            DerivedKeyAlgorithm::Hmac { hash, length_bits } => {
                let length_bits = length_bits.unwrap_or_else(|| hash.hmac_default_bits());
                (
                    ImportAlgorithm::Hmac {
                        hash,
                        length_bits: Some(length_bits),
                    },
                    length_bits,
                )
            }
            DerivedKeyAlgorithm::AesGcm { length_bits } => {
                validate_aes_length(length_bits)?;
                (ImportAlgorithm::AesGcm, length_bits)
            }
        };
        let material = derive_material(algorithm, base_key, KeyUsage::DeriveKey, length_bits)?;
        import_material(material, import, extractable, usages)
    }
}

#[cfg(test)]
#[cfg(feature = "crypto")]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn fips_180_4_digests() {
        assert_eq!(
            digest(HashAlgorithm::Sha256, b"abc").unwrap(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(digest(HashAlgorithm::Sha384, b"abc").unwrap(), hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
        assert_eq!(digest(HashAlgorithm::Sha512, b"abc").unwrap(), hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
    }

    #[test]
    fn rfc_4231_hmac_sha256_case_one() {
        let key = import_raw_key(
            &[0x0b; 20],
            ImportAlgorithm::Hmac {
                hash: HashAlgorithm::Sha256,
                length_bits: None,
            },
            false,
            &[KeyUsage::Sign, KeyUsage::Verify],
        )
        .unwrap();
        let signature = sign(&key, b"Hi There").unwrap();
        assert_eq!(
            signature,
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        assert!(verify(&key, &signature, b"Hi There").unwrap());
        assert!(!verify(&key, &signature, b"not it").unwrap());
    }

    #[test]
    fn rfc_4231_hmac_sha384_and_sha512_case_one() {
        for (hash, expected) in [
            (
                HashAlgorithm::Sha384,
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            ),
            (
                HashAlgorithm::Sha512,
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
        ] {
            let key = import_raw_key(
                &[0x0b; 20],
                ImportAlgorithm::Hmac {
                    hash,
                    length_bits: None,
                },
                false,
                &[KeyUsage::Sign],
            )
            .unwrap();
            assert_eq!(sign(&key, b"Hi There").unwrap(), hex(expected));
        }
    }

    #[test]
    fn nist_gcm_empty_plaintext_case() {
        let key = import_raw_key(
            &[0; 16],
            ImportAlgorithm::AesGcm,
            false,
            &[KeyUsage::Encrypt, KeyUsage::Decrypt],
        )
        .unwrap();
        let params = AesGcmParams {
            iv: &[0; 12],
            additional_data: &[],
            tag_length_bits: 128,
        };
        let encrypted = encrypt(&key, params, &[]).unwrap();
        assert_eq!(encrypted, hex("58e2fccefa7e3061367f1d57a4e7455a"));
        assert_eq!(decrypt(&key, params, &encrypted).unwrap(), b"");

        let key = import_raw_key(
            &[0; 32],
            ImportAlgorithm::AesGcm,
            false,
            &[KeyUsage::Encrypt],
        )
        .unwrap();
        assert_eq!(
            encrypt(&key, params, &[]).unwrap(),
            hex("530f8afbc74536b9a963b4f1c4cb738b")
        );
        assert_eq!(
            import_raw_key(&[0; 24], ImportAlgorithm::AesGcm, false, &[])
                .unwrap_err()
                .name,
            ErrorName::NotSupportedError
        );
    }

    #[test]
    fn rfc_5869_hkdf_sha256_case_one() {
        let key = import_raw_key(
            &[0x0b; 22],
            ImportAlgorithm::Hkdf,
            false,
            &[KeyUsage::DeriveBits],
        )
        .unwrap();
        let output = derive_bits(
            DeriveAlgorithm::Hkdf {
                hash: HashAlgorithm::Sha256,
                salt: &hex("000102030405060708090a0b0c"),
                info: &hex("f0f1f2f3f4f5f6f7f8f9"),
            },
            &key,
            42 * 8,
        )
        .unwrap();
        assert_eq!(output, hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    }

    #[test]
    fn pbkdf2_hmac_sha256_vector() {
        let key = import_raw_key(
            b"password",
            ImportAlgorithm::Pbkdf2,
            false,
            &[KeyUsage::DeriveBits],
        )
        .unwrap();
        let output = derive_bits(
            DeriveAlgorithm::Pbkdf2 {
                hash: HashAlgorithm::Sha256,
                salt: b"salt",
                iterations: 1,
            },
            &key,
            256,
        )
        .unwrap();
        assert_eq!(
            output,
            hex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        );
    }

    #[test]
    fn jwk_round_trip_and_nonextractable_rules() {
        let key = import_raw_key(
            &[7; 32],
            ImportAlgorithm::Hmac {
                hash: HashAlgorithm::Sha256,
                length_bits: None,
            },
            true,
            &[KeyUsage::Sign],
        )
        .unwrap();
        let ExportedKey::Jwk(jwk) = export_key(KeyFormat::Jwk, &key).unwrap() else {
            panic!()
        };
        let again = import_jwk_key(
            &jwk,
            ImportAlgorithm::Hmac {
                hash: HashAlgorithm::Sha256,
                length_bits: None,
            },
            true,
            &[KeyUsage::Sign],
        )
        .unwrap();
        assert_eq!(
            export_key(KeyFormat::Raw, &again).unwrap(),
            ExportedKey::Raw(vec![7; 32])
        );
        let base = import_raw_key(
            b"password",
            ImportAlgorithm::Pbkdf2,
            false,
            &[KeyUsage::DeriveBits],
        )
        .unwrap();
        assert_eq!(
            export_key(KeyFormat::Raw, &base).unwrap_err().name,
            ErrorName::InvalidAccessError
        );
        assert_eq!(
            import_raw_key(
                b"password",
                ImportAlgorithm::Pbkdf2,
                true,
                &[KeyUsage::DeriveBits]
            )
            .unwrap_err()
            .name,
            ErrorName::SyntaxError
        );
    }
}
