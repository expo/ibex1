//! Native TLS bridge engine for the `tls` builtin (ENG-23492).
//!
//! One sans-IO rustls `ClientConnection` per bridged `tls.connect` socket,
//! exposed to the C++ JSI shims (`src/engine/hermes_runtime_tls.cc`) through
//! the `ibex_tls_*` extern "C" surface. The JS side owns ALL I/O: it shovels
//! ciphertext between the existing `net.Socket` and this engine, and plaintext
//! between the engine and the `TLSSocket` wrapper. The engine therefore spawns
//! no threads and installs no static destructors — the exit()-deadlock class
//! that byte-value static pools cause (ENG-23471/ENG-23498) cannot occur here.
//! @ref LLP 0004#the-tls-builtin — sans-IO bridge design, rejected alternatives
//!
//! Trust evaluation deliberately lives HERE, not in tls.js: the JS
//! `_validatePeerAuthorization` is a fingerprint-list comparator that cannot
//! verify signatures. A recording verifier wraps rustls's WebPKI verifier so
//! the handshake always completes and the real verdict is reported to JS,
//! which maps it onto Node's OpenSSL-style codes (`rejectUnauthorized:false`
//! semantics, oracle-pinned against Node v25.9.0). Hostname/identity checking
//! stays in JS (`checkServerIdentity` is user-overridable in Node).
//! @ref LLP 0004#the-tls-builtin — trust-evaluation split native/JS

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::{Cursor, IoSlice, Read, Write};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError,
    RootCertStore, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;

/// Outcome of the (recorded, non-aborting) server certificate verification.
#[derive(Clone, Debug, Default)]
struct VerifyOutcome {
    /// The verifier ran (a certificate was presented).
    checked: bool,
    /// Chain is trusted (signatures + validity window + issuer chain to a
    /// root). `NotValidForName` counts as chain-ok: webpki verifies the path
    /// before the name, and Node checks hostnames separately in JS.
    chain_ok: bool,
    /// Coarse native classification; the JS side refines `UNKNOWN_ISSUER`
    /// into Node's DEPTH_ZERO_SELF_SIGNED_CERT / SELF_SIGNED_CERT_IN_CHAIN /
    /// UNABLE_TO_VERIFY_LEAF_SIGNATURE using the presented chain shape.
    code: Option<String>,
    reason: Option<String>,
}

struct Engine {
    conn: ClientConnection,
    verify: Arc<Mutex<VerifyOutcome>>,
    /// Fatal TLS error from `process_new_packets` (alert sent/received,
    /// garbage record, ...). Once set the connection is unusable; JS drains
    /// any pending alert bytes via `read_tls` and destroys the socket.
    error: Option<String>,
    /// Node-shaped error code accompanying `error` (oracle: a plaintext peer
    /// yields ERR_SSL_WRONG_VERSION_NUMBER in Node v25.9.0).
    error_code: Option<String>,
}

/// Counts the bytes rustls would offer to its next `write_tls` call without
/// consuming them. `ChunkVecBuffer::write_to` only removes the byte count
/// reported by the writer, so returning `Ok(0)` makes this a non-destructive
/// pending-length probe while retaining rustls's public `Write` contract.
#[derive(Default)]
struct PendingWriteCounter {
    bytes: usize,
}

impl Write for PendingWriteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes = buf.len();
        Ok(0)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.bytes = bufs
            .iter()
            .fold(0, |total, buf| total.saturating_add(buf.len()));
        Ok(0)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct OwnedEngine {
    /// Unforgeable identity of the Hermes runtime that created this engine.
    /// Engine ids cross the JS/native boundary as numbers, so principal ids
    /// alone are not an ownership boundary: two runtimes can assign the same
    /// principal number. The runtime nonce is checked before every lookup.
    runtime_nonce: u64,
    /// Principal that minted the numeric handle. Permissive policy does not
    /// make native handles ambient across package compartments.
    owner: u64,
    // Engine operations can perform certificate parsing and rustls record
    // processing. Keep that work off the process-global registry mutex so an
    // unrelated runtime's TLS connection cannot serialize behind it.
    // Reads temporarily move the engine into an opaque C++-owned lease while
    // the exact-size JSI buffer is allocated. `None` therefore means "busy",
    // not "missing"; the registry entry remains present so ownership checks
    // cannot be bypassed or confused with an unknown selector.
    engine: Arc<Mutex<Option<Engine>>>,
}

type EngineSlot = Arc<Mutex<Option<Engine>>>;

const TLS_READ_EMPTY: i64 = 0;
const TLS_READ_EOF: i64 = -1;
const TLS_READ_TLS_ERROR: i64 = -2;
const TLS_READ_UNKNOWN_ENGINE: i64 = -3;
const TLS_READ_WRONG_OWNER: i64 = -4;
const TLS_READ_PROBE_ERROR: i64 = -5;
const TLS_READ_BUSY: i64 = -6;
const TLS_READ_INVALID_ARGUMENT: i64 = -7;
const TLS_READ_INTERNAL_ERROR: i64 = -8;
const MAX_TLS_READ_BYTES: usize = 65_536;

/// A poisoned synchronization primitive must not unwind through an `extern
/// "C"` entry point and abort the process. TLS state is already guarded by its
/// own fatal-error fields, so preserve availability and let the operation
/// report a normal bridge error if the recovered state is unusable.
fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadKind {
    Ciphertext,
    Plaintext,
}

/// Exclusive engine reservation spanning the exact-size JSI allocation.
///
/// Keeping the engine here rather than a `MutexGuard` avoids holding any Rust
/// lock while Hermes allocates the native backing store or collects. Dropping
/// or cancelling the lease restores the engine without consuming bytes;
/// finishing reads directly into the JSI ArrayBuffer and then restores it. The
/// tradeoff is a second short slot-mutex acquisition solely to put the engine
/// back; there is still one ownership/registry lookup and no second locked
/// engine operation or payload copy per chunk. The opaque pointer never crosses
/// into JavaScript.
struct ReadLease {
    slot: EngineSlot,
    engine: Option<Engine>,
    kind: ReadKind,
    reserved: usize,
    runtime_nonce: u64,
    owner: u64,
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        let Some(engine) = self.engine.take() else {
            return;
        };
        let mut slot = lock_recover(&self.slot);
        if slot.is_none() {
            *slot = Some(engine);
        }
    }
}

#[derive(Clone, Copy)]
struct OwnerToken {
    runtime_nonce: u64,
    owner: u64,
}

fn engines() -> &'static Mutex<HashMap<u64, OwnedEngine>> {
    // Rust statics are never destroyed, so this is an immortal singleton by
    // construction (no C++-style static-destructor teardown to deadlock on).
    static ENGINES: OnceLock<Mutex<HashMap<u64, OwnedEngine>>> = OnceLock::new();
    ENGINES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn owner_tokens() -> &'static Mutex<HashMap<u64, OwnerToken>> {
    static TOKENS: OnceLock<Mutex<HashMap<u64, OwnerToken>>> = OnceLock::new();
    TOKENS.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_OWNER_TOKEN: AtomicU64 = AtomicU64::new(1);
const MAX_JS_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

unsafe extern "C" {
    fn ex_hermes_current_runtime_nonce() -> u64;
    fn ex_hermes_current_principal_id() -> u64;
}

fn current_runtime_nonce() -> u64 {
    // SAFETY: this function reads the runtime-thread's current security
    // context and has no pointer arguments or lifetime requirements.
    unsafe { ex_hermes_current_runtime_nonce() }
}

fn current_principal_id() -> u64 {
    // SAFETY: like the nonce accessor, this reads runtime-thread-local
    // security context and has no pointer/lifetime preconditions.
    unsafe { ex_hermes_current_principal_id() }
}

fn allocate_engine_id(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            if next == 0 || next > MAX_JS_SAFE_INTEGER {
                None
            } else {
                next.checked_add(1)
            }
        })
        .ok()
}

#[no_mangle]
pub extern "C" fn ibex_tls_owner_token_new() -> u64 {
    let runtime_nonce = current_runtime_nonce();
    if runtime_nonce == 0 {
        return 0;
    }
    let Some(id) = allocate_engine_id(&NEXT_OWNER_TOKEN) else {
        return 0;
    };
    lock_recover(owner_tokens()).insert(
        id,
        OwnerToken {
            runtime_nonce,
            owner: current_principal_id(),
        },
    );
    id
}

#[no_mangle]
pub extern "C" fn ibex_tls_owner_token_check(id: u64) -> i32 {
    let runtime_nonce = current_runtime_nonce();
    let principal = current_principal_id();
    let map = lock_recover(owner_tokens());
    let Some(token) = map.get(&id) else {
        return 0;
    };
    if token.runtime_nonce != runtime_nonce || token.owner != principal {
        return -1;
    }
    1
}

#[no_mangle]
pub extern "C" fn ibex_tls_owner_token_free(id: u64) -> i32 {
    let ownership = ibex_tls_owner_token_check(id);
    if ownership != 1 {
        return ownership;
    }
    lock_recover(owner_tokens()).remove(&id);
    1
}

thread_local! {
    // Construction errors are consumed synchronously by the C++ bridge on
    // the same runtime thread. A process-global slot let one runtime steal or
    // overwrite another runtime's error during concurrent construction.
    static LAST_ERROR: RefCell<Option<(u64, u64, String)>> = const { RefCell::new(None) };
}

fn set_last_error(message: String) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some((current_runtime_nonce(), current_principal_id(), message))
    });
}

/// A `ServerCertVerifier` that runs the real WebPKI verification, records the
/// verdict, and then reports success so the handshake always completes. This
/// is what lets `rejectUnauthorized:false` observe `authorized:false` plus the
/// real error code over a *completed* connection, matching Node.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    outcome: Arc<Mutex<VerifyOutcome>>,
    abort_on_invalid: bool,
}

fn default_crypto_provider() -> &'static Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
}

fn default_root_store() -> &'static Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(roots)
    })
}

fn default_server_verifier() -> &'static Arc<WebPkiServerVerifier> {
    static VERIFIER: OnceLock<Arc<WebPkiServerVerifier>> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        WebPkiServerVerifier::builder_with_provider(
            default_root_store().clone(),
            default_crypto_provider().clone(),
        )
        .build()
        .expect("the compiled webpki root store must build a verifier")
    })
}

fn classify_verify_error(err: &TlsError) -> (bool, String, String) {
    // (chain_ok, code, reason)
    match err {
        TlsError::InvalidCertificate(cert_err) => match cert_err {
            CertificateError::Expired => (
                false,
                "CERT_HAS_EXPIRED".into(),
                "certificate has expired".into(),
            ),
            CertificateError::ExpiredContext { .. } => (
                false,
                "CERT_HAS_EXPIRED".into(),
                "certificate has expired".into(),
            ),
            CertificateError::NotValidYet => (
                false,
                "CERT_NOT_YET_VALID".into(),
                "certificate is not yet valid".into(),
            ),
            CertificateError::NotValidYetContext { .. } => (
                false,
                "CERT_NOT_YET_VALID".into(),
                "certificate is not yet valid".into(),
            ),
            CertificateError::UnknownIssuer => (
                false,
                "UNKNOWN_ISSUER".into(),
                "unable to verify certificate issuer".into(),
            ),
            CertificateError::Revoked => {
                (false, "CERT_REVOKED".into(), "certificate revoked".into())
            }
            CertificateError::BadSignature => (
                false,
                "CERT_SIGNATURE_FAILURE".into(),
                "certificate signature failure".into(),
            ),
            CertificateError::InvalidPurpose => (
                false,
                "INVALID_PURPOSE".into(),
                "unsupported certificate purpose".into(),
            ),
            // webpki validates the path before the server name, so a name
            // mismatch means the chain itself was trusted. Node performs the
            // hostname check in JS (checkServerIdentity); report chain-ok and
            // let tls.js produce ERR_TLS_CERT_ALTNAME_INVALID Node-shaped.
            CertificateError::NotValidForName => (
                true,
                "HOSTNAME_MISMATCH".into(),
                "certificate is not valid for the server name".into(),
            ),
            CertificateError::NotValidForNameContext { .. } => (
                true,
                "HOSTNAME_MISMATCH".into(),
                "certificate is not valid for the server name".into(),
            ),
            other => (
                false,
                "UNABLE_TO_VERIFY_CERT".into(),
                format!("certificate verification failed: {other:?}"),
            ),
        },
        other => (
            false,
            "UNABLE_TO_VERIFY_CERT".into(),
            format!("certificate verification failed: {other}"),
        ),
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let mut outcome = lock_recover(&self.outcome);
        outcome.checked = true;
        match result {
            Ok(verified) => {
                outcome.chain_ok = true;
                outcome.code = None;
                outcome.reason = None;
                Ok(verified)
            }
            Err(err) => {
                let (chain_ok, code, reason) = classify_verify_error(&err);
                outcome.chain_ok = chain_ok;
                outcome.code = Some(code);
                outcome.reason = Some(reason);
                if self.abort_on_invalid {
                    Err(err)
                } else {
                    Ok(ServerCertVerified::assertion())
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(serde::Deserialize)]
struct BridgeConfig {
    /// SNI name; only sent when the caller supplied `servername` (measured
    /// Node v25.9.0: bare `tls.connect({host})` sends NO SNI — example.com
    /// rejects such handshakes with alert 40, and badssl serves its fallback
    /// cert; ibex https.js sets servername explicitly).
    servername: Option<String>,
    /// Destination host; used as the verification name when no servername is
    /// given (Node verifies against `servername || host` in JS; the native
    /// record for the name check is advisory only).
    host: Option<String>,
    #[serde(default)]
    alpn: Vec<String>,
    /// Concatenated PEM certificates replacing the bundled webpki roots
    /// (Node `ca` option semantics: replaces, not extends).
    ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    passphrase: Option<String>,
    /// Base64-encoded DER PKCS#12 identity supplied through Node's `pfx`
    /// option. Binary transport is explicit because this configuration
    /// crosses a JSON-only JSI boundary.
    pfx: Option<String>,
    #[serde(default = "default_reject_unauthorized", rename = "rejectUnauthorized")]
    reject_unauthorized: bool,
    #[serde(default, rename = "hasSession")]
    has_session: bool,
    #[serde(default, rename = "cipherSuites")]
    cipher_suites: Vec<String>,
    #[serde(rename = "minVersion")]
    min_version: Option<String>,
    #[serde(rename = "maxVersion")]
    max_version: Option<String>,
}

const MAX_CLIENT_IDENTITY_BYTES: usize = 16 * 1024 * 1024;

fn default_reject_unauthorized() -> bool {
    true
}

#[cfg(all(
    not(any(target_os = "ios", target_os = "tvos")),
    feature = "tls-client-identity-openssl"
))]
fn client_identity_from_pfx(
    encoded: &str,
    passphrase: Option<&str>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    use base64::Engine as _;
    use openssl::pkcs12::Pkcs12;

    if encoded.len() > MAX_CLIENT_IDENTITY_BYTES.saturating_mul(4).div_ceil(3) + 4 {
        return Err("pfx client identity exceeds the 16 MiB limit".into());
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "pfx client identity is not canonical base64".to_string())?;
    if der.len() > MAX_CLIENT_IDENTITY_BYTES {
        return Err("pfx client identity exceeds the 16 MiB limit".into());
    }
    let password = passphrase.unwrap_or("");
    if password.as_bytes().contains(&0) {
        return Err("pfx passphrase must not contain NUL".into());
    }
    let archive =
        Pkcs12::from_der(&der).map_err(|error| format!("invalid pfx client identity: {error}"))?;
    if archive
        .to_der()
        .map_err(|error| format!("invalid pfx client identity: {error}"))?
        != der
    {
        return Err("pfx client identity contains trailing or noncanonical DER".into());
    }
    let parsed = archive
        .parse2(password)
        .map_err(|error| format!("invalid pfx client identity or passphrase: {error}"))?;
    let key = parsed
        .pkey
        .ok_or_else(|| "pfx client identity contains no private key".to_string())?;
    let leaf = parsed
        .cert
        .ok_or_else(|| "pfx client identity contains no certificate".to_string())?;
    let mut certs =
        vec![CertificateDer::from(leaf.to_der().map_err(|error| {
            format!("invalid pfx client certificate: {error}")
        })?)];
    if let Some(chain) = parsed.ca {
        for certificate in chain {
            certs.push(CertificateDer::from(certificate.to_der().map_err(
                |error| format!("invalid pfx client certificate chain: {error}"),
            )?));
        }
    }
    let key_pem = key
        .private_key_to_pem_pkcs8()
        .map_err(|error| format!("invalid pfx client private key: {error}"))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|error| format!("invalid pfx client private key: {error}"))?;
    Ok((certs, key))
}

#[cfg(all(
    not(any(target_os = "ios", target_os = "tvos")),
    feature = "tls-client-identity-openssl"
))]
fn encrypted_client_key(key_pem: &str, passphrase: &str) -> Result<PrivateKeyDer<'static>, String> {
    use openssl::pkey::PKey;

    if passphrase.as_bytes().contains(&0) {
        return Err("client private-key passphrase must not contain NUL".into());
    }
    if key_pem.len() > MAX_CLIENT_IDENTITY_BYTES {
        return Err("client private key exceeds the 16 MiB limit".into());
    }
    let key = PKey::private_key_from_pem_passphrase(key_pem.as_bytes(), passphrase.as_bytes())
        .map_err(|error| format!("invalid encrypted client private key or passphrase: {error}"))?;
    let decrypted_pem = key
        .private_key_to_pem_pkcs8()
        .map_err(|error| format!("invalid encrypted client private key: {error}"))?;
    PrivateKeyDer::from_pem_slice(&decrypted_pem)
        .map_err(|error| format!("invalid encrypted client private key: {error}"))
}

fn client_identity(
    config: &BridgeConfig,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, String> {
    if let Some(encoded) = config.pfx.as_deref() {
        if config.cert.is_some() || config.key.is_some() {
            return Err("pfx cannot be combined with cert or key client identity options".into());
        }
        #[cfg(all(
            not(any(target_os = "ios", target_os = "tvos")),
            feature = "tls-client-identity-openssl"
        ))]
        {
            return client_identity_from_pfx(encoded, config.passphrase.as_deref()).map(Some);
        }
        #[cfg(all(
            not(any(target_os = "ios", target_os = "tvos")),
            not(feature = "tls-client-identity-openssl")
        ))]
        {
            let _ = encoded;
            return Err("pfx client identities are unavailable in this reduced TLS profile".into());
        }
        #[cfg(any(target_os = "ios", target_os = "tvos"))]
        {
            let _ = encoded;
            return Err(
                "pfx client identities are unavailable in the iOS reduced TLS profile".into(),
            );
        }
    }

    match (config.cert.as_deref(), config.key.as_deref()) {
        (None, None) => {
            if config.passphrase.is_some() {
                return Err("passphrase requires a pfx or client private key".into());
            }
            Ok(None)
        }
        (Some(cert_pem), Some(key_pem)) => {
            if cert_pem.len() > MAX_CLIENT_IDENTITY_BYTES {
                return Err("client certificate chain exceeds the 16 MiB limit".into());
            }
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(|error| format!("invalid client certificate: {error}"))?;
            if certs.is_empty() {
                return Err("cert option contained no certificates".into());
            }
            let key = if let Some(passphrase) = config.passphrase.as_deref() {
                #[cfg(all(
                    not(any(target_os = "ios", target_os = "tvos")),
                    feature = "tls-client-identity-openssl"
                ))]
                {
                    encrypted_client_key(key_pem, passphrase)?
                }
                #[cfg(all(
                    not(any(target_os = "ios", target_os = "tvos")),
                    not(feature = "tls-client-identity-openssl")
                ))]
                {
                    let _ = passphrase;
                    return Err(
                        "encrypted client private keys are unavailable in this reduced TLS profile"
                            .into(),
                    );
                }
                #[cfg(any(target_os = "ios", target_os = "tvos"))]
                {
                    let _ = passphrase;
                    return Err(
                        "encrypted client private keys are unavailable in the iOS reduced TLS profile"
                            .into(),
                    );
                }
            } else {
                PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                    .map_err(|error| format!("invalid client private key: {error}"))?
            };
            Ok(Some((certs, key)))
        }
        _ => Err("both cert and key are required for mutual TLS".into()),
    }
}

fn build_engine(config_json: &str) -> Result<Engine, String> {
    let config: BridgeConfig =
        serde_json::from_str(config_json).map_err(|e| format!("invalid tls bridge config: {e}"))?;

    if config.has_session {
        return Err("TLS session resumption input is not supported by the rustls bridge".into());
    }

    let provider = if config.cipher_suites.is_empty() {
        default_crypto_provider().clone()
    } else {
        let mut provider_value = default_crypto_provider().as_ref().clone();
        provider_value.cipher_suites.retain(|suite| {
            let (openssl, standard) = cipher_names(suite.suite());
            config.cipher_suites.iter().any(|requested| {
                openssl
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(requested))
                    || standard
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case(requested))
            })
        });
        if provider_value.cipher_suites.is_empty() {
            return Err(format!(
                "none of the requested cipher suites are supported by the rustls bridge: {:?}",
                config.cipher_suites
            ));
        }
        Arc::new(provider_value)
    };

    let custom_roots = if let Some(ca_pem) = config.ca.as_deref() {
        let mut roots = RootCertStore::empty();
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            let cert = cert.map_err(|e| format!("invalid certificate in ca option: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("invalid certificate in ca option: {e}"))?;
            added += 1;
        }
        if added == 0 {
            return Err("ca option contained no certificates".into());
        }
        Some(Arc::new(roots))
    } else {
        None
    };

    let identity = client_identity(&config)?;
    let outcome = Arc::new(Mutex::new(VerifyOutcome::default()));
    let webpki_verifier = if let Some(roots) = custom_roots {
        WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
            .build()
            .map_err(|e| format!("failed to build certificate verifier: {e}"))?
    } else if config.cipher_suites.is_empty() {
        default_server_verifier().clone()
    } else {
        WebPkiServerVerifier::builder_with_provider(default_root_store().clone(), provider.clone())
            .build()
            .map_err(|e| format!("failed to build certificate verifier: {e}"))?
    };
    let verifier = Arc::new(RecordingVerifier {
        inner: webpki_verifier,
        outcome: outcome.clone(),
        // A permissive client must complete an invalid-chain handshake to
        // expose Node's authorized:false state. A strict client identity must
        // instead abort natively before rustls can answer CertificateRequest
        // with the client's certificate/proof.
        abort_on_invalid: config.reject_unauthorized && identity.is_some(),
    });

    // Protocol versions: rustls supports TLS 1.2/1.3. Node's defaults are
    // minVersion TLSv1.2 / maxVersion TLSv1.3; lower requested minimums clamp
    // to TLS 1.2 (the connection still negotiates >= 1.2, which satisfies a
    // lower minimum).
    if matches!(config.max_version.as_deref(), Some("TLSv1" | "TLSv1.1")) {
        return Err(format!(
            "unsupported maxVersion {:?}: rustls supports TLSv1.2 and TLSv1.3",
            config.max_version
        ));
    }
    if matches!(config.min_version.as_deref(), Some(v) if !matches!(v, "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3"))
        || matches!(config.max_version.as_deref(), Some(v) if !matches!(v, "TLSv1.2" | "TLSv1.3"))
    {
        return Err(format!(
            "unsupported TLS version range: min={:?} max={:?}",
            config.min_version, config.max_version
        ));
    }
    let min_is_13 = config.min_version.as_deref() == Some("TLSv1.3");
    let max_below_13 = config.max_version.as_deref() == Some("TLSv1.2");
    let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = Vec::new();
    if !min_is_13 {
        versions.push(&rustls::version::TLS12);
    }
    if !max_below_13 {
        versions.push(&rustls::version::TLS13);
    }
    if versions.is_empty() {
        return Err(format!(
            "unsupported TLS version range: min={:?} max={:?}",
            config.min_version, config.max_version
        ));
    }

    let client_builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| format!("failed to configure TLS versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut client_config = match identity {
        None => client_builder.with_no_client_auth(),
        Some((certs, key)) => client_builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| format!("client certificate/key mismatch: {e}"))?,
    };

    client_config.alpn_protocols = config
        .alpn
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect();
    // Match measured Node v25.9.0: SNI is only sent when servername was
    // explicitly provided.
    client_config.enable_sni = config.servername.is_some();

    let name_source = config
        .servername
        .clone()
        .or_else(|| config.host.clone())
        .unwrap_or_else(|| "localhost".to_string());
    let server_name = ServerName::try_from(name_source.clone())
        .map_err(|e| format!("invalid servername {name_source:?}: {e}"))?;

    let conn = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|e| format!("failed to create TLS client connection: {e}"))?;

    Ok(Engine {
        conn,
        verify: outcome,
        error: None,
        error_code: None,
    })
}

fn record_process_error(engine: &mut Engine, err: &TlsError) {
    if engine.error.is_some() {
        return;
    }
    // Oracle (Node v25.9.0): a peer speaking plaintext instead of TLS yields
    // ERR_SSL_WRONG_VERSION_NUMBER; use it for malformed-record errors and a
    // generic handshake code otherwise (only certificate codes are pinned).
    let code = match err {
        TlsError::InvalidMessage(_) => "ERR_SSL_WRONG_VERSION_NUMBER",
        TlsError::AlertReceived(_) => "ERR_SSL_TLSV1_ALERT",
        _ => "ERR_TLS_HANDSHAKE_FAILURE",
    };
    engine.error_code = Some(code.to_string());
    engine.error = Some(format!("{err}"));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EngineLookupError {
    Missing,
    WrongOwner,
}

struct OwnedEngineAccess {
    slot: EngineSlot,
    runtime_nonce: u64,
    owner: u64,
}

fn lookup_owned_engine(id: u64) -> Result<OwnedEngineAccess, EngineLookupError> {
    let runtime_nonce = current_runtime_nonce();
    let principal = current_principal_id();
    if runtime_nonce == 0 {
        return Err(EngineLookupError::WrongOwner);
    }
    {
        let map = lock_recover(engines());
        let owned = map.get(&id).ok_or(EngineLookupError::Missing)?;
        if owned.runtime_nonce != runtime_nonce || owned.owner != principal {
            return Err(EngineLookupError::WrongOwner);
        }
        Ok(OwnedEngineAccess {
            slot: Arc::clone(&owned.engine),
            runtime_nonce,
            owner: principal,
        })
    }
}

fn with_engine<R>(id: u64, f: impl FnOnce(&mut Engine) -> R) -> Option<R> {
    let access = lookup_owned_engine(id).ok()?;
    let mut engine = lock_recover(&access.slot);
    Some(f(engine.as_mut()?))
}

fn to_owned_cstring(value: String) -> *mut c_char {
    match std::ffi::CString::new(value) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create a new TLS client engine from a JSON config. Returns an engine id
/// (> 0) or 0 on failure (message retrievable via `ibex_tls_last_error`).
///
/// # Safety
/// `config_json` must be a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_client_new(config_json: *const c_char) -> u64 {
    let runtime_nonce = current_runtime_nonce();
    let owner = current_principal_id();
    if runtime_nonce == 0 {
        set_last_error("TLS engine creation requires an active runtime".into());
        return 0;
    }
    if config_json.is_null() {
        set_last_error("config required".into());
        return 0;
    }
    let config = match unsafe { std::ffi::CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("config must be UTF-8".into());
            return 0;
        }
    };
    match build_engine(config) {
        Ok(engine) => {
            let Some(id) = allocate_engine_id(&NEXT_ID) else {
                set_last_error("TLS engine id space exhausted".into());
                return 0;
            };
            let replaced = lock_recover(engines()).insert(
                id,
                OwnedEngine {
                    runtime_nonce,
                    owner,
                    engine: Arc::new(Mutex::new(Some(engine))),
                },
            );
            debug_assert!(
                replaced.is_none(),
                "monotonic TLS id collided with live engine"
            );
            id
        }
        Err(message) => {
            set_last_error(message);
            0
        }
    }
}

/// Take the last `ibex_tls_client_new` error. Caller frees the returned
/// string with `ibex_tls_string_free`; returns null when no error is stored.
#[no_mangle]
pub extern "C" fn ibex_tls_last_error() -> *mut c_char {
    let runtime_nonce = current_runtime_nonce();
    let principal = current_principal_id();
    match LAST_ERROR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(nonce, owner, _)| *nonce == runtime_nonce && *owner == principal)
        {
            slot.take().map(|(_, _, message)| message)
        } else {
            None
        }
    }) {
        Some(message) => to_owned_cstring(message),
        None => std::ptr::null_mut(),
    }
}

/// Feed ciphertext received from the socket into the engine. Returns bytes
/// consumed (>= 0) or -1 on a fatal TLS error (JS should drain `read_tls`
/// once more to flush any alert, then destroy).
///
/// # Safety
/// `data` must point to `len` readable bytes (or be null with `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_write_tls(id: u64, data: *const u8, len: usize) -> i64 {
    let slice: &[u8] = if data.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    with_engine(id, |engine| {
        if engine.error.is_some() {
            return -1;
        }
        let mut cursor = Cursor::new(slice);
        loop {
            let position = cursor.position() as usize;
            if position >= slice.len() {
                break;
            }
            match engine.conn.read_tls(&mut cursor) {
                Ok(0) => break,
                Ok(_) => {}
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::Other
                        && err.to_string().contains("plaintext buffer full")
                    {
                        // Normal rustls receive backpressure. Return the exact
                        // consumed prefix; JS drains plaintext and re-offers
                        // the untouched ciphertext remainder.
                        break;
                    }
                    engine.error_code = Some("ERR_TLS_HANDSHAKE_FAILURE".into());
                    engine.error = Some(format!("{err}"));
                    return -1;
                }
            }
            if let Err(err) = engine.conn.process_new_packets() {
                record_process_error(engine, &err);
                return -1;
            }
        }
        cursor.position() as i64
    })
    .unwrap_or(-1)
}

fn tls_bytes_pending(conn: &mut ClientConnection) -> Result<usize, ()> {
    if !conn.wants_write() {
        return Ok(0);
    }
    let mut counter = PendingWriteCounter::default();
    match conn.write_tls(&mut counter) {
        Ok(0) if counter.bytes > 0 => Ok(counter.bytes),
        Ok(_) | Err(_) => Err(()),
    }
}

/// Queue plaintext for encryption. Returns bytes accepted (rustls buffers
/// pre-handshake writes and enforces an internal buffer limit, so this can be
/// a short count; JS re-offers the remainder after pumping ciphertext out) or
/// -1 on error / unknown id.
///
/// # Safety
/// `data` must point to `len` readable bytes (or be null with `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_write_plain(id: u64, data: *const u8, len: usize) -> i64 {
    let slice: &[u8] = if data.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    with_engine(id, |engine| {
        if engine.error.is_some() {
            return -1;
        }
        match engine.conn.writer().write(slice) {
            Ok(n) => n as i64,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(err) => {
                engine.error_code = Some("ERR_TLS_WRITE_FAILED".into());
                engine.error = Some(err.to_string());
                -1
            }
        }
    })
    .unwrap_or(-1)
}

fn plain_read_result(engine: &mut Engine, result: std::io::Result<usize>) -> i64 {
    match result {
        Ok(0) => TLS_READ_EOF,
        Ok(n) => i64::try_from(n).unwrap_or(i64::MAX),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
            if engine.error.is_some() {
                TLS_READ_TLS_ERROR
            } else {
                TLS_READ_EMPTY
            }
        }
        // An unauthenticated transport EOF is truncation, not a clean TLS end.
        // Treating it as close_notify lets an on-path peer cut a response at a
        // record boundary and have consumers accept the prefix as complete.
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            engine.error_code = Some("ECONNRESET".into());
            engine.error = Some("TLS connection closed without close_notify".into());
            TLS_READ_TLS_ERROR
        }
        Err(_) => TLS_READ_TLS_ERROR,
    }
}

fn plaintext_bytes_pending(engine: &mut Engine) -> i64 {
    let result = engine
        .conn
        .reader()
        .into_first_chunk()
        .map(|chunk| chunk.len());
    plain_read_result(engine, result)
}

fn pending_read_length(engine: &mut Engine, kind: ReadKind) -> i64 {
    match kind {
        ReadKind::Ciphertext => match tls_bytes_pending(&mut engine.conn) {
            Ok(bytes) => i64::try_from(bytes).unwrap_or(TLS_READ_PROBE_ERROR),
            Err(()) => TLS_READ_PROBE_ERROR,
        },
        ReadKind::Plaintext => plaintext_bytes_pending(engine),
    }
}

fn reserve_read_lease(
    access: OwnedEngineAccess,
    kind: ReadKind,
    max_bytes: usize,
) -> Result<(usize, Box<ReadLease>), i64> {
    let mut slot = lock_recover(&access.slot);
    let Some(engine) = slot.as_mut() else {
        return Err(TLS_READ_BUSY);
    };
    let pending = pending_read_length(engine, kind);
    if pending <= 0 {
        return Err(pending);
    }
    let pending = usize::try_from(pending).map_err(|_| TLS_READ_PROBE_ERROR)?;
    let reserved = pending.min(max_bytes);
    if reserved == 0 {
        return Err(TLS_READ_INVALID_ARGUMENT);
    }
    let Some(engine) = slot.take() else {
        return Err(TLS_READ_BUSY);
    };
    drop(slot);
    Ok((
        reserved,
        Box::new(ReadLease {
            slot: access.slot,
            engine: Some(engine),
            kind,
            reserved,
            runtime_nonce: access.runtime_nonce,
            owner: access.owner,
        }),
    ))
}

unsafe fn begin_read(
    id: u64,
    max_bytes: usize,
    kind: ReadKind,
    lease_out: *mut *mut c_void,
) -> i64 {
    if lease_out.is_null() {
        return TLS_READ_INVALID_ARGUMENT;
    }
    // SAFETY: the caller supplied a non-null out pointer for one opaque lease.
    unsafe { *lease_out = std::ptr::null_mut() };
    if !(1..=MAX_TLS_READ_BYTES).contains(&max_bytes) {
        return TLS_READ_INVALID_ARGUMENT;
    }
    let access = match lookup_owned_engine(id) {
        Ok(access) => access,
        Err(EngineLookupError::Missing) => return TLS_READ_UNKNOWN_ENGINE,
        Err(EngineLookupError::WrongOwner) => return TLS_READ_WRONG_OWNER,
    };
    match reserve_read_lease(access, kind, max_bytes) {
        Ok((reserved, lease)) => {
            // SAFETY: ownership transfers to C++; exactly one of finish/cancel
            // reconstructs this Box, and the pointer never enters JavaScript.
            unsafe { *lease_out = Box::into_raw(lease).cast::<c_void>() };
            i64::try_from(reserved).unwrap_or(TLS_READ_INVALID_ARGUMENT)
        }
        Err(status) => status,
    }
}

/// Reserve the exact next ciphertext read (capped by `max_bytes`) and return an
/// opaque lease through `lease_out`. Positive results are the required buffer
/// length; zero means no output. Negative statuses distinguish TLS failure,
/// missing/wrong-owner handles, probe failure, reentrancy, and bad arguments.
/// No ciphertext is consumed until `ibex_tls_read_finish` receives the JSI
/// buffer, and cancellation restores the engine untouched.
///
/// # Safety
/// `lease_out` must point to writable storage for one opaque pointer.
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_tls_read_begin(
    id: u64,
    max_bytes: usize,
    lease_out: *mut *mut c_void,
) -> i64 {
    // SAFETY: forwarded unchanged under this function's caller contract.
    unsafe { begin_read(id, max_bytes, ReadKind::Ciphertext, lease_out) }
}

/// Reserve the exact next contiguous plaintext read. Return conventions match
/// `ibex_tls_tls_read_begin`, with -1 additionally representing authenticated
/// end-of-stream and -2 a fatal TLS/truncation error.
///
/// # Safety
/// `lease_out` must point to writable storage for one opaque pointer.
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_plaintext_read_begin(
    id: u64,
    max_bytes: usize,
    lease_out: *mut *mut c_void,
) -> i64 {
    // SAFETY: forwarded unchanged under this function's caller contract.
    unsafe { begin_read(id, max_bytes, ReadKind::Plaintext, lease_out) }
}

fn finish_read(lease: &mut ReadLease, out: &mut [u8]) -> i64 {
    let Some(engine) = lease.engine.as_mut() else {
        return TLS_READ_INVALID_ARGUMENT;
    };
    match lease.kind {
        ReadKind::Ciphertext => {
            if !engine.conn.wants_write() {
                return TLS_READ_INTERNAL_ERROR;
            }
            let mut cursor = Cursor::new(out);
            match engine.conn.write_tls(&mut cursor) {
                Ok(_) => {
                    let written =
                        i64::try_from(cursor.position()).unwrap_or(TLS_READ_INTERNAL_ERROR);
                    if written == i64::try_from(lease.reserved).unwrap_or(-1) {
                        written
                    } else {
                        engine.error_code = Some("ERR_TLS_READ_FAILED".into());
                        engine.error = Some("TLS ciphertext lease produced a short read".into());
                        TLS_READ_INTERNAL_ERROR
                    }
                }
                Err(err) => {
                    engine.error_code = Some("ERR_TLS_READ_FAILED".into());
                    engine.error = Some(format!("failed to drain TLS ciphertext: {err}"));
                    TLS_READ_INTERNAL_ERROR
                }
            }
        }
        ReadKind::Plaintext => {
            let result = engine.conn.reader().read(out);
            let read = plain_read_result(engine, result);
            if read == i64::try_from(lease.reserved).unwrap_or(-1) {
                read
            } else {
                if read >= 0 {
                    engine.error_code = Some("ERR_TLS_READ_FAILED".into());
                    engine.error = Some("TLS plaintext lease produced a short read".into());
                }
                TLS_READ_INTERNAL_ERROR
            }
        }
    }
}

/// Fill an exact-size JSI buffer from a lease and restore the engine. This does
/// not consult the engine registry: ownership was authenticated by begin and is
/// rechecked directly against the captured runtime/principal after allocation.
/// The lease is consumed on every return path.
///
/// # Safety
/// `lease_ptr` must be returned by one successful begin call and not previously
/// finished/cancelled. `buf` must point to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_read_finish(
    lease_ptr: *mut c_void,
    buf: *mut u8,
    cap: usize,
) -> i64 {
    if lease_ptr.is_null() {
        return TLS_READ_INVALID_ARGUMENT;
    }
    // SAFETY: the caller transfers back the unique Box created by begin.
    let mut lease = unsafe { Box::from_raw(lease_ptr.cast::<ReadLease>()) };
    if lease.runtime_nonce != current_runtime_nonce() || lease.owner != current_principal_id() {
        return TLS_READ_WRONG_OWNER;
    }
    if buf.is_null() || cap != lease.reserved {
        return TLS_READ_INVALID_ARGUMENT;
    }
    // SAFETY: the caller guarantees `buf` is writable for the exact reserved
    // capacity and the lease excludes concurrent engine mutation.
    let out = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
    finish_read(&mut lease, out)
}

/// Cancel an unfilled read reservation. Dropping the reconstructed lease puts
/// the untouched engine back into its registry slot.
///
/// # Safety
/// `lease_ptr` must be null or a unique, unfinished lease pointer.
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_read_cancel(lease_ptr: *mut c_void) {
    if !lease_ptr.is_null() {
        // SAFETY: ownership returns exactly once from the C++ RAII guard.
        drop(unsafe { Box::from_raw(lease_ptr.cast::<ReadLease>()) });
    }
}

/// Signal that the underlying transport reached EOF (raw socket 'end').
#[no_mangle]
pub extern "C" fn ibex_tls_transport_eof(id: u64) {
    with_engine(id, |engine| {
        let mut empty: &[u8] = &[];
        // read_tls from an empty reader registers EOF with rustls.
        let _ = engine.conn.read_tls(&mut empty);
        if let Err(err) = engine.conn.process_new_packets() {
            record_process_error(engine, &err);
        }
    });
}

/// Queue a close_notify alert (JS then drains `read_tls` and forwards it).
#[no_mangle]
pub extern "C" fn ibex_tls_shutdown(id: u64) {
    with_engine(id, |engine| engine.conn.send_close_notify());
}

/// Engine status as JSON:
/// `{handshaking, wantsWrite, protocol, alpn, cipher, cipherStandard,
///   error, errorCode, verify: {checked, chainOk, code, reason}}`.
/// Caller frees with `ibex_tls_string_free`; null for an unknown id.
#[no_mangle]
pub extern "C" fn ibex_tls_status_json(id: u64) -> *mut c_char {
    let json = with_engine(id, |engine| {
        let protocol = engine.conn.protocol_version().map(|v| match v {
            rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
            rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
            other => format!("{other:?}"),
        });
        let alpn = engine
            .conn
            .alpn_protocol()
            .map(|proto| String::from_utf8_lossy(proto).to_string());
        let (cipher, cipher_standard) = engine
            .conn
            .negotiated_cipher_suite()
            .map(|suite| cipher_names(suite.suite()))
            .unwrap_or((None, None));
        let verify = lock_recover(&engine.verify).clone();
        serde_json::json!({
            "handshaking": engine.conn.is_handshaking(),
            "wantsWrite": engine.conn.wants_write(),
            "protocol": protocol,
            "alpn": alpn,
            "cipher": cipher,
            "cipherStandard": cipher_standard,
            "error": engine.error,
            "errorCode": engine.error_code,
            "verify": {
                "checked": verify.checked,
                "chainOk": verify.chain_ok,
                "code": verify.code,
                "reason": verify.reason,
            },
        })
        .to_string()
    });
    match json {
        Some(json) => to_owned_cstring(json),
        None => std::ptr::null_mut(),
    }
}

/// The peer certificate chain exactly as presented on the wire, as a JSON
/// array of base64 DER strings (leaf first). Caller frees with
/// `ibex_tls_string_free`; null for an unknown id.
#[no_mangle]
pub extern "C" fn ibex_tls_peer_certs_json(id: u64) -> *mut c_char {
    use base64::Engine as _;
    let json = with_engine(id, |engine| {
        let certs: Vec<String> = engine
            .conn
            .peer_certificates()
            .unwrap_or(&[])
            .iter()
            .map(|cert| base64::engine::general_purpose::STANDARD.encode(cert.as_ref()))
            .collect();
        serde_json::to_string(&certs).unwrap_or_else(|_| "[]".to_string())
    });
    match json {
        Some(json) => to_owned_cstring(json),
        None => std::ptr::null_mut(),
    }
}

/// Check engine ownership without mutating it. Returns 1 for the owner, 0 for
/// a missing id, and -1 for another runtime or principal.
#[no_mangle]
pub extern "C" fn ibex_tls_check_owner(id: u64) -> i32 {
    let runtime_nonce = current_runtime_nonce();
    let principal = current_principal_id();
    let map = lock_recover(engines());
    let Some(owned) = map.get(&id) else {
        return 0;
    };
    if owned.runtime_nonce != runtime_nonce || owned.owner != principal {
        return -1;
    }
    1
}

/// Release an engine. Returns 1 when removed, 0 when already absent, -1 when
/// owned by another runtime/principal, and -2 while an exact-size read lease is
/// allocating its JSI buffer. A reentrant close must not detach the registry
/// entry from the lease that will restore it.
#[no_mangle]
pub extern "C" fn ibex_tls_free(id: u64) -> i32 {
    let runtime_nonce = current_runtime_nonce();
    let principal = current_principal_id();
    let mut map = lock_recover(engines());
    let Some(owned) = map.get(&id) else {
        return 0;
    };
    if owned.runtime_nonce != runtime_nonce || owned.owner != principal {
        return -1;
    }
    if lock_recover(&owned.engine).is_none() {
        return -2;
    }
    map.remove(&id);
    1
}

/// Release every TLS engine owned by a runtime during runtime destruction.
/// The explicit nonce is required because teardown clears the thread-local
/// current-runtime context after invoking native cleanup hooks.
#[no_mangle]
pub extern "C" fn ibex_tls_cleanup_runtime(runtime_nonce: u64) {
    if runtime_nonce == 0 {
        return;
    }
    lock_recover(engines()).retain(|_, owned| owned.runtime_nonce != runtime_nonce);
    lock_recover(owner_tokens()).retain(|_, token| token.runtime_nonce != runtime_nonce);
}

/// Free a string returned by the `*_json` / last-error functions.
///
/// # Safety
/// `s` must be a pointer previously returned by this module (or null).
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(s) });
    }
}

/// Map a negotiated suite to Node's `getCipher()` names:
/// (`name` — OpenSSL style, `standardName` — IANA style). Oracle: Node
/// v25.9.0 reports e.g. `{name:'TLS_AES_256_GCM_SHA384', standardName:
/// 'TLS_AES_256_GCM_SHA384'}` for TLS 1.3 and `{name:
/// 'ECDHE-RSA-AES128-GCM-SHA256', standardName:
/// 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'}` for TLS 1.2.
fn cipher_names(suite: rustls::CipherSuite) -> (Option<String>, Option<String>) {
    use rustls::CipherSuite::*;
    let (name, standard) = match suite {
        TLS13_AES_256_GCM_SHA384 => ("TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"),
        TLS13_AES_128_GCM_SHA256 => ("TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"),
        TLS13_CHACHA20_POLY1305_SHA256 => (
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => (
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => (
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => (
            "ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => (
            "ECDHE-RSA-AES256-GCM-SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => (
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => (
            "ECDHE-RSA-CHACHA20-POLY1305",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        other => {
            let debug = format!("{other:?}");
            return (Some(debug.clone()), Some(debug));
        }
    };
    (Some(name.to_string()), Some(standard.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        allocate_engine_id, begin_read, build_engine, finish_read, reserve_read_lease,
        tls_bytes_pending, OwnedEngineAccess, PendingWriteCounter, ReadKind, MAX_JS_SAFE_INTEGER,
        MAX_TLS_READ_BYTES, TLS_READ_INVALID_ARGUMENT,
    };
    use std::ffi::c_void;
    use std::io::{Cursor, IoSlice, Write};
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};

    #[test]
    fn tls_engine_ids_stop_before_javascript_number_aliasing() {
        let counter = AtomicU64::new(MAX_JS_SAFE_INTEGER - 1);
        assert_eq!(allocate_engine_id(&counter), Some(MAX_JS_SAFE_INTEGER - 1));
        assert_eq!(allocate_engine_id(&counter), Some(MAX_JS_SAFE_INTEGER));
        assert_eq!(allocate_engine_id(&counter), None);
        assert_eq!(allocate_engine_id(&counter), None);
    }

    #[test]
    fn tls_engine_id_zero_is_never_allocated() {
        let counter = AtomicU64::new(0);
        assert_eq!(allocate_engine_id(&counter), None);
    }

    #[test]
    fn pending_write_counter_counts_without_consuming() {
        let mut counter = PendingWriteCounter::default();
        assert_eq!(counter.write(b"ciphertext").unwrap(), 0);
        assert_eq!(counter.bytes, 10);

        let chunks = [IoSlice::new(b"handshake"), IoSlice::new(b"alert")];
        assert_eq!(counter.write_vectored(&chunks).unwrap(), 0);
        assert_eq!(counter.bytes, 14);
    }

    #[test]
    fn native_read_begin_rejects_out_of_range_limits_before_lookup() {
        for max_bytes in [0, MAX_TLS_READ_BYTES + 1, usize::MAX] {
            let mut lease = std::ptr::dangling_mut::<c_void>();
            let status = unsafe {
                begin_read(
                    1,
                    max_bytes,
                    ReadKind::Ciphertext,
                    std::ptr::addr_of_mut!(lease),
                )
            };
            assert_eq!(status, TLS_READ_INVALID_ARGUMENT);
            assert!(lease.is_null(), "invalid begin must clear its out pointer");
        }
    }

    #[test]
    fn ciphertext_pending_probe_is_exact_and_non_consuming() {
        let mut engine = build_engine("{}").expect("minimal TLS client config");
        let pending = tls_bytes_pending(&mut engine.conn).expect("ciphertext probe");
        assert!(pending > 0, "a new client has a ClientHello pending");
        assert!(engine.conn.wants_write(), "the probe must not drain bytes");

        let mut ciphertext = vec![0_u8; pending];
        let mut cursor = Cursor::new(ciphertext.as_mut_slice());
        assert_eq!(engine.conn.write_tls(&mut cursor).unwrap(), pending);
        assert_eq!(cursor.position() as usize, pending);
    }

    #[test]
    fn cancelled_read_lease_restores_engine_without_consuming_ciphertext() {
        let mut engine = build_engine("{}").expect("minimal TLS client config");
        let pending = tls_bytes_pending(&mut engine.conn).expect("ciphertext probe");
        let slot = Arc::new(Mutex::new(Some(engine)));
        let access = OwnedEngineAccess {
            slot: Arc::clone(&slot),
            runtime_nonce: 11,
            owner: 22,
        };

        let (reserved, lease) =
            reserve_read_lease(access, ReadKind::Ciphertext, 1).expect("read lease");
        assert_eq!(reserved, 1);
        assert!(slot.lock().unwrap().is_none(), "lease must be exclusive");
        drop(lease);

        let mut restored = slot.lock().unwrap();
        let restored = restored.as_mut().expect("cancelled lease restores engine");
        assert_eq!(
            tls_bytes_pending(&mut restored.conn).expect("restored probe"),
            pending,
            "allocation cancellation must not consume the ClientHello"
        );
    }

    #[test]
    fn finished_read_lease_fills_only_the_reserved_prefix() {
        let mut engine = build_engine("{}").expect("minimal TLS client config");
        let pending = tls_bytes_pending(&mut engine.conn).expect("ciphertext probe");
        let slot = Arc::new(Mutex::new(Some(engine)));
        let access = OwnedEngineAccess {
            slot: Arc::clone(&slot),
            runtime_nonce: 11,
            owner: 22,
        };
        let (reserved, mut lease) =
            reserve_read_lease(access, ReadKind::Ciphertext, 1).expect("read lease");
        let mut byte = vec![0_u8; reserved];
        assert_eq!(finish_read(&mut lease, &mut byte), reserved as i64);
        drop(lease);

        let mut restored = slot.lock().unwrap();
        let restored = restored.as_mut().expect("finished lease restores engine");
        assert_eq!(
            tls_bytes_pending(&mut restored.conn).expect("remaining probe"),
            pending - reserved
        );
    }
}
