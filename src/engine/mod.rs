//! Engine support utilities
//!
//! The C++ Hermes adapter (`hermes_runtime.cc`) is compiled by build.rs and
//! linked into this crate. It exposes C functions (`ex_hermes_create`,
//! `ex_hermes_eval`, `ex_hermes_poll`, etc.) that can be called from both
//! Rust (via the CLI's hermes.rs wrapper) and Swift (via the bridging header).
//!
//! This module provides supporting utilities like source map handling.

pub mod evaluation;
pub mod hermes_structured;
mod import_grants;
pub mod module_runner;
pub mod portable_identity;
pub mod session_lowering;
pub mod session_syntax;
pub mod sourcemap;
// Native TLS bridge engine for the `tls` builtin (ENG-23492/ENG-23526).
// Platform-specific TCP host functions provide the transport; the Rust engine
// itself is sans-I/O and shared across Unix and Windows.
pub mod tls_bridge;

#[cfg(all(test, feature = "runtime-extension-conformance"))]
mod runtime_extension_conformance_tests;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

extern "C" {
    fn ex_hermes_bytecode_version() -> u32;
    fn ex_hermes_engine_binary_path(out: *mut std::ffi::c_char, out_len: usize) -> i32;
    #[cfg(any(
        target_os = "tvos",
        all(
            target_os = "ios",
            not(feature = "capsec-simulator-performance-observer")
        )
    ))]
    fn ibex_private_hermes_ios_verify_mapped_file_v1(
        fd: std::os::fd::RawFd,
        error: *mut std::ffi::c_char,
        error_len: usize,
    ) -> i32;
    #[cfg(any(unix, windows))]
    fn ex_open_pinned_self_image(error: *mut std::ffi::c_char, error_len: usize) -> isize;
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        all(target_os = "ios", feature = "capsec-simulator-performance-observer"),
        windows
    ))]
    fn ex_hermes_engine_mapped_object(out_device: *mut u64, out_inode: *mut u64) -> i32;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    fn ibex_private_apple_sha256_fd_v1(
        fd: std::os::fd::RawFd,
        expected_size: u64,
        output: *mut u8,
    ) -> i32;
}

/// Open the running executable once and prove that the descriptor names the
/// object backing its mapped code. Callers must perform every subsequent
/// executable read through the returned descriptor.
// @ref LLP 0029#3-identity-separated-digest-domains — a pathname lookup cannot
// safely authenticate an envelope after the running image has been replaced.
#[cfg(unix)]
pub fn open_pinned_self_image() -> Result<std::fs::File, String> {
    use std::os::fd::FromRawFd;

    let mut error = [0i8; 512];
    let fd = unsafe { ex_open_pinned_self_image(error.as_mut_ptr(), error.len()) };
    if fd < 0 {
        let message = unsafe { std::ffi::CStr::from_ptr(error.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        return Err(if message.is_empty() {
            "failed to pin the running executable image".into()
        } else {
            message
        });
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd as i32) })
}

#[cfg(windows)]
pub fn open_pinned_self_image() -> Result<std::fs::File, String> {
    use std::os::windows::io::FromRawHandle;

    let mut error = [0i8; 512];
    let handle = unsafe { ex_open_pinned_self_image(error.as_mut_ptr(), error.len()) };
    if handle < 0 {
        let message = unsafe { std::ffi::CStr::from_ptr(error.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        return Err(if message.is_empty() {
            "failed to pin the running executable image".into()
        } else {
            message
        });
    }
    Ok(unsafe { std::fs::File::from_raw_handle(handle as *mut std::ffi::c_void) })
}

#[cfg(not(any(unix, windows)))]
pub fn open_pinned_self_image() -> Result<std::fs::File, String> {
    Err("pinned self-image acquisition is unsupported on this target".into())
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadedEngineBinaryIdentity {
    pub engine_artifact_path: std::path::PathBuf,
    pub kind: String,
    pub binary_digest: String,
    pub object: capsec_semantics::model::ObjectIdentity,
    pub target_architecture: String,
    pub structural_features: Vec<String>,
}

const EMBEDDED_HERMES_PROFILE_PROVENANCE: &str =
    include_str!(concat!(env!("OUT_DIR"), "/hermes_profile_provenance.json"));

// These are `null` for every legacy build. Portable mode writes all four from
// one revalidated selected-input closure before native compilation begins, so
// a later runtime/post-link consumer need not reconstruct authority from paths.
// They are compile-time build evidence only: unused `include_str!` constants do
// not establish final-link byte retention, which remains a post-link/runtime
// responsibility.
// @ref LLP 0035#build-consumption-and-post-link-contracts — expose the canonical
// portable inputs and exact build-consumption binding from OUT_DIR.
pub const EMBEDDED_PORTABLE_ENGINE_MANIFEST: &str =
    include_str!(concat!(env!("OUT_DIR"), "/portable_engine_manifest.json"));
pub const EMBEDDED_PORTABLE_ENGINE_INSTALLATION_RECEIPT: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/portable_engine_installation_receipt.json"
));
pub const EMBEDDED_PORTABLE_ENGINE_BUILD_CONSUMPTION: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/portable_engine_build_consumption.json"
));
pub const EMBEDDED_PORTABLE_ENGINE_PROMOTION_ADMISSION: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/portable_engine_promotion_admission.json"
));
pub const EMBEDDED_PORTABLE_ENGINE_PROMOTION_REPORT: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/portable_engine_promotion_report.json"
));

fn expected_loaded_engine_identity(
) -> &'static std::result::Result<LoadedEngineBinaryIdentity, String> {
    static IDENTITY: OnceLock<std::result::Result<LoadedEngineBinaryIdentity, String>> =
        OnceLock::new();
    IDENTITY.get_or_init(capture_loaded_engine_identity)
}

fn capture_loaded_engine_identity() -> Result<LoadedEngineBinaryIdentity, String> {
    let path = loaded_engine_artifact_path()?;
    capture_engine_artifact_identity(&path, verify_loaded_mapping_object)
}

fn loaded_engine_artifact_path() -> Result<std::path::PathBuf, String> {
    let mut buffer = vec![0u8; 32 * 1024];
    let length = unsafe { ex_hermes_engine_binary_path(buffer.as_mut_ptr().cast(), buffer.len()) };
    if length <= 0 {
        return Err("failed to identify the loaded Hermes engine artifact".into());
    }
    buffer.truncate(length as usize);
    let text =
        std::str::from_utf8(&buffer).map_err(|_| "loaded Hermes path is not UTF-8".to_owned())?;
    Ok(std::path::PathBuf::from(text))
}

fn capture_engine_artifact_identity(
    candidate_path: &std::path::Path,
    verify_mapping: impl FnOnce(
        &std::fs::File,
        &std::fs::Metadata,
        &capsec_semantics::model::ObjectIdentity,
    ) -> Result<(), String>,
) -> Result<LoadedEngineBinaryIdentity, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let path = std::fs::canonicalize(candidate_path).map_err(|error| {
        format!(
            "failed to authenticate loaded Hermes artifact {}: {error}",
            candidate_path.display()
        )
    })?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut file = options.open(&path).map_err(|error| {
        format!(
            "failed to pin loaded Hermes artifact {}: {error}",
            path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect loaded Hermes artifact: {error}"))?;
    if !metadata.is_file() {
        return Err("loaded Hermes artifact is not a regular file".into());
    }
    let object = engine_object_identity(&file, &metadata)?;
    verify_mapping(&file, &metadata, &object)?;
    let hash = hash_open_file_sha256(&mut file, metadata.len())?;
    let after = file
        .metadata()
        .map_err(|error| format!("failed to revalidate loaded Hermes artifact: {error}"))?;
    let mut changed =
        engine_object_identity(&file, &after)? != object || after.len() != metadata.len();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        changed |= after.mtime() != metadata.mtime()
            || after.mtime_nsec() != metadata.mtime_nsec()
            || after.ctime() != metadata.ctime()
            || after.ctime_nsec() != metadata.ctime_nsec();
    }
    if changed {
        return Err("loaded Hermes artifact changed while it was authenticated".into());
    }
    let digest = format!("sha256-{}", URL_SAFE_NO_PAD.encode(hash));
    Ok(LoadedEngineBinaryIdentity {
        engine_artifact_path: path,
        kind: "hermes".into(),
        binary_digest: digest,
        object,
        target_architecture: std::env::consts::ARCH.to_owned(),
        structural_features: loaded_engine_structural_features(),
    })
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
pub(crate) fn hash_open_file_sha256(
    file: &mut std::fs::File,
    expected_size: u64,
) -> Result<[u8; 32], String> {
    use std::os::fd::AsRawFd as _;

    let mut digest = [0u8; 32];
    if unsafe {
        ibex_private_apple_sha256_fd_v1(file.as_raw_fd(), expected_size, digest.as_mut_ptr())
    } != 1
    {
        return Err("failed to hash the complete pinned file".into());
    }
    Ok(digest)
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
pub(crate) fn hash_open_file_sha256(
    file: &mut std::fs::File,
    _expected_size: u64,
) -> Result<[u8; 32], String> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    let mut hash = Sha256::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|error| format!("failed to hash loaded Hermes artifact: {error}"))?;
        if read == 0 {
            break;
        }
        hash.update(&chunk[..read]);
    }
    Ok(hash.finalize().into())
}

pub fn loaded_engine_structural_features() -> Vec<String> {
    if cfg!(exact_frame_attribution) {
        vec![
            "hermes-frame-attribution".into(),
            "native-compartments".into(),
            "native-lockdown".into(),
        ]
    } else {
        Vec::new()
    }
}

fn engine_object_identity(
    file: &std::fs::File,
    metadata: &std::fs::Metadata,
) -> Result<capsec_semantics::model::ObjectIdentity, String> {
    #[cfg(unix)]
    {
        let _ = file;
        use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
        use std::os::unix::fs::MetadataExt;
        Ok(ObjectIdentity {
            platform: if cfg!(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos"
            )) {
                ObjectPlatform::Apple
            } else if cfg!(target_os = "android") {
                ObjectPlatform::Android
            } else {
                ObjectPlatform::Unix
            },
            volume: NonEmptyString::new(format!("dev:{}", metadata.dev()))?,
            file: NonEmptyString::new(format!("ino:{}", metadata.ino()))?,
        })
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
        // — bind the report to the pinned file handle, never just its path.
        crate::host::object_identity_for_open_file(file)
            .map_err(|error| format!("failed to identify pinned Windows Hermes artifact: {error}"))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn verify_loaded_mapping_object(
    _file: &std::fs::File,
    metadata: &std::fs::Metadata,
    _object: &capsec_semantics::model::ObjectIdentity,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let mut device = 0u64;
    let mut inode = 0u64;
    if unsafe { ex_hermes_engine_mapped_object(&mut device, &mut inode) } != 1 {
        return Err("failed to identify the mapped Hermes ELF image".into());
    }
    if inode != metadata.ino() || device != metadata.dev() {
        return Err("loaded Hermes path names a different object than the mapped ELF image".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_loaded_mapping_object(
    _file: &std::fs::File,
    metadata: &std::fs::Metadata,
    _object: &capsec_semantics::model::ObjectIdentity,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let mut device = 0u64;
    let mut inode = 0u64;
    if unsafe { ex_hermes_engine_mapped_object(&mut device, &mut inode) } != 1 {
        return Err("failed to identify the mapped Hermes factory object".into());
    }
    if device != metadata.dev() || inode != metadata.ino() {
        return Err(
            "loaded Hermes path names a different object than the mapped factory image".into(),
        );
    }
    Ok(())
}

#[cfg(all(target_os = "ios", feature = "capsec-simulator-performance-observer"))]
fn verify_loaded_mapping_object(
    _file: &std::fs::File,
    metadata: &std::fs::Metadata,
    _object: &capsec_semantics::model::ObjectIdentity,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let mut device = 0u64;
    let mut inode = 0u64;
    if unsafe { ex_hermes_engine_mapped_object(&mut device, &mut inode) } != 1 {
        return Err("failed to authenticate the mapped Hermes simulator __text image".into());
    }
    if device != metadata.dev() || inode != metadata.ino() {
        return Err(
            "loaded Hermes path names a different object than the authenticated simulator image"
                .into(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn verify_loaded_mapping_object(
    _file: &std::fs::File,
    _metadata: &std::fs::Metadata,
    object: &capsec_semantics::model::ObjectIdentity,
) -> Result<(), String> {
    use capsec_semantics::model::ObjectPlatform;

    // Windows exposes only the loader-reported module pathname here. The
    // native helper reopens that pathname, so this is a diagnostic
    // current-file consistency check, not identity for the image section that
    // supplied already mapped code. CapSec promotion retains a separate
    // Windows mapped-image blocker.
    let mut volume = 0u64;
    let mut file = 0u64;
    if unsafe { ex_hermes_engine_mapped_object(&mut volume, &mut file) } != 1 {
        return Err("failed to identify the current Windows Hermes pathname object".into());
    }
    if object.platform != ObjectPlatform::Windows
        || object.volume.as_str() != format!("volume:{volume}")
        || object.file.as_str() != format!("file:{file}")
    {
        return Err("loaded Hermes path names a different current Windows file object".into());
    }
    Ok(())
}

#[cfg(any(
    target_os = "tvos",
    all(
        target_os = "ios",
        not(feature = "capsec-simulator-performance-observer")
    )
))]
fn verify_loaded_mapping_object(
    file: &std::fs::File,
    _metadata: &std::fs::Metadata,
    _object: &capsec_semantics::model::ObjectIdentity,
) -> Result<(), String> {
    use std::os::fd::AsRawFd as _;

    let mut error = [0i8; 1024];
    let status = unsafe {
        ibex_private_hermes_ios_verify_mapped_file_v1(
            file.as_raw_fd(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    if status == 1 {
        return Ok(());
    }
    let message = unsafe { std::ffi::CStr::from_ptr(error.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Err(if message.is_empty() {
        "failed to bind the pinned Hermes file to its mapped iOS executable bytes".into()
    } else {
        format!("failed to attest mapped iOS Hermes executable bytes: {message}")
    })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    windows
)))]
fn verify_loaded_mapping_object(
    _file: &std::fs::File,
    _metadata: &std::fs::Metadata,
    _object: &capsec_semantics::model::ObjectIdentity,
) -> Result<(), String> {
    Err("this target cannot attest the loaded Hermes image object".into())
}

/// Initial identity of the artifact that supplied the linked Hermes runtime
/// factory. This expected build identity is immutable for the process; callers
/// that need a post-probe recheck use `verify_loaded_engine_binary_identity`,
/// which reopens and re-hashes the current named file instead of consulting
/// this cache. Supported Unix targets additionally bind that file to the
/// mapped object; Windows retains pathname-reopen identity only.
pub fn loaded_engine_binary_path() -> Result<std::path::PathBuf, String> {
    expected_loaded_engine_identity()
        .as_ref()
        .map(|identity| identity.engine_artifact_path.clone())
        .map_err(Clone::clone)
}

pub fn loaded_engine_binary_digest() -> Result<String, String> {
    expected_loaded_engine_identity()
        .as_ref()
        .map(|identity| identity.binary_digest.clone())
        .map_err(Clone::clone)
}

pub fn loaded_engine_binary_identity() -> Result<LoadedEngineBinaryIdentity, String> {
    expected_loaded_engine_identity()
        .as_ref()
        .cloned()
        .map_err(Clone::clone)
}

/// Capture the mapped engine's path/object identity while taking its content
/// digest from the build-time Hermes receipt. This exists only in an
/// `insecure` build, which makes no code-integrity or sandbox claim; secure
/// profiles always hash the complete current artifact through
/// [`loaded_engine_binary_identity`].
/// @ref LLP 0038#fully-open-mode-insecure
#[cfg(feature = "insecure")]
pub fn loaded_engine_binary_identity_insecure() -> Result<LoadedEngineBinaryIdentity, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let receipt: serde_json::Value = serde_json::from_str(EMBEDDED_HERMES_PROFILE_PROVENANCE)
        .map_err(|error| format!("embedded Hermes provenance is not JSON: {error}"))?;
    let Some(hex_digest) = receipt
        .get("artifact")
        .and_then(|artifact| artifact.get("binaryDigest"))
        .and_then(serde_json::Value::as_str)
        .and_then(|digest| digest.strip_prefix("sha256-"))
    else {
        return loaded_engine_binary_identity();
    };
    if hex_digest.len() != 64 || !hex_digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("embedded Hermes provenance has a malformed binary digest".into());
    }
    let mut raw_digest = [0u8; 32];
    for (index, byte) in raw_digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex_digest[index * 2..index * 2 + 2], 16)
            .map_err(|_| "embedded Hermes provenance has a malformed binary digest")?;
    }

    let path = std::fs::canonicalize(loaded_engine_artifact_path()?)
        .map_err(|error| format!("failed to identify loaded Hermes artifact: {error}"))?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(&path)
        .map_err(|error| format!("failed to open loaded Hermes artifact: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect loaded Hermes artifact: {error}"))?;
    if !metadata.is_file() {
        return Err("loaded Hermes artifact is not a regular file".into());
    }
    let object = engine_object_identity(&file, &metadata)?;
    verify_loaded_mapping_object(&file, &metadata, &object)?;

    Ok(LoadedEngineBinaryIdentity {
        engine_artifact_path: path,
        kind: "hermes".into(),
        binary_digest: format!("sha256-{}", URL_SAFE_NO_PAD.encode(raw_digest)),
        object,
        target_architecture: std::env::consts::ARCH.to_owned(),
        structural_features: loaded_engine_structural_features(),
    })
}

/// Installer-origin assertion embedded only after build.rs independently
/// matches it to the exact Hermes artifact selected for linking. Returning it
/// rechecks the current named file bytes against that receipt. Supported Unix
/// targets additionally bind that file to the mapping containing the Hermes
/// factory; Windows only reopens the loader-reported pathname.
///
/// This does not hash the executable pages already mapped by the loader. It is
/// therefore a mechanical file/object binding, not a complete loaded-code
/// attestation; promotion still requires an independent sealed/signed package
/// or equivalent mapping trust anchor.
///
/// `None` is an explicit unverified state for ordinary builds made without a
/// receipt. CapSec conformance builds set
/// `IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE=1`, so they fail at build time
/// instead of reaching this state.
// @ref LLP 0013#upstream-tracking-and-re-derivation — a pin/coordinate only
// identifies the candidate loaded profile after link-time selection and the
// platform-specific mapping/current-file check described above. Windows keeps
// an explicit mapped-image promotion blocker because its check is path-based.
pub fn loaded_engine_profile_provenance() -> Result<Option<serde_json::Value>, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use std::fmt::Write as _;

    let receipt: serde_json::Value = serde_json::from_str(EMBEDDED_HERMES_PROFILE_PROVENANCE)
        .map_err(|error| format!("embedded Hermes provenance is not JSON: {error}"))?;
    if receipt.is_null() {
        return Ok(None);
    }
    let expected = receipt
        .get("artifact")
        .and_then(|artifact| artifact.get("binaryDigest"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "embedded Hermes provenance has no artifact binary digest".to_owned())?;
    // This is deliberately fresh on every call: conformance invokes it again
    // after probes, when the initial expected identity cache is no longer
    // evidence about the current object bytes.
    let identity = capture_loaded_engine_identity()?;
    let encoded = identity
        .binary_digest
        .strip_prefix("sha256-")
        .ok_or_else(|| "loaded Hermes identity has a malformed digest".to_owned())?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "loaded Hermes identity digest is not base64url".to_owned())?;
    let mut loaded_hex = String::with_capacity(71);
    loaded_hex.push_str("sha256-");
    for byte in raw {
        write!(&mut loaded_hex, "{byte:02x}").expect("writing a digest to String cannot fail");
    }
    if expected != loaded_hex {
        return Err(
            "embedded Hermes profile receipt does not match the current Hermes artifact bytes"
                .to_owned(),
        );
    }
    Ok(Some(receipt))
}

/// HBC version accepted by the mapped Hermes engine. This deliberately does
/// not consult a separately discovered CLI binary.
pub fn loaded_engine_bytecode_version() -> Result<u32, String> {
    let version = unsafe { ex_hermes_bytecode_version() };
    (version != 0)
        .then_some(version)
        .ok_or_else(|| "loaded Hermes engine did not expose its bytecode version".into())
}

pub fn verify_loaded_engine_binary_identity(
    expected: &LoadedEngineBinaryIdentity,
) -> Result<LoadedEngineBinaryIdentity, String> {
    // Re-open and hash on every verification. The cached identity is the
    // immutable pre-probe expectation, never the post-probe observation.
    verify_engine_binary_identity_with(expected, capture_loaded_engine_identity)
}

fn verify_engine_binary_identity_with(
    expected: &LoadedEngineBinaryIdentity,
    capture: impl FnOnce() -> Result<LoadedEngineBinaryIdentity, String>,
) -> Result<LoadedEngineBinaryIdentity, String> {
    let actual = capture()?;
    if &actual != expected {
        return Err("loaded Hermes identity differs from the expected artifact".into());
    }
    Ok(actual)
}

/// Flag set when a background callback is pushed.
/// iOS polls this to know when to wake up the event loop.
static CALLBACK_PENDING: AtomicBool = AtomicBool::new(false);

/// Host wake hook (exact LLP 0297 W4b/B8): a wake-driven host executor
/// parks its runtime thread on a condition variable instead of polling the
/// pending flag, so it needs a push notification when a cross-thread
/// callback lands. Stored as raw words so invocation from arbitrary
/// threads is lock-free. Registration is expected once at host boot;
/// re-registration is not synchronized against a concurrent notify (a
/// racing reader may pair the new fn with the old context).
static HOST_WAKE_HOOK_FN: AtomicUsize = AtomicUsize::new(0);
static HOST_WAKE_HOOK_CTX: AtomicUsize = AtomicUsize::new(0);

/// Register (or clear, with `None`) the host wake hook invoked whenever a
/// background thread pushes a runtime callback. The hook runs on the
/// pushing thread and must only do cheap, bounded work (enqueue + signal a
/// condvar). The one library-owned notify symbol always invokes this hook;
/// CLI profiles register their tokio wake function through it at runtime.
#[no_mangle]
pub extern "C" fn ex_hermes_set_host_wake_hook(
    hook: Option<extern "C" fn(*mut std::ffi::c_void)>,
    context: *mut std::ffi::c_void,
) {
    HOST_WAKE_HOOK_CTX.store(context as usize, Ordering::Release);
    HOST_WAKE_HOOK_FN.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

fn invoke_host_wake_hook() {
    let raw_fn = HOST_WAKE_HOOK_FN.load(Ordering::Acquire);
    if raw_fn == 0 {
        return;
    }
    let context = HOST_WAKE_HOOK_CTX.load(Ordering::Acquire) as *mut std::ffi::c_void;
    // SAFETY: raw_fn was stored from a valid `extern "C" fn(*mut c_void)`
    // in ex_hermes_set_host_wake_hook and is only transmuted back to that
    // exact type.
    let hook: extern "C" fn(*mut std::ffi::c_void) = unsafe { std::mem::transmute(raw_fn) };
    hook(context);
}

/// Default implementation of ex_hermes_notify_callback for iOS/standalone use.
/// This is called from C++ (hermes_runtime.cc) when async callbacks are pushed
/// from background threads.
///
/// This symbol is deliberately owned by the library in every feature profile.
/// A binary that needs a specialized wake mechanism registers it through
/// `ex_hermes_set_host_wake_hook`; defining a replacement global symbol made
/// `cli-notify` integration-test link units fail when the CLI object was absent
/// (ENG-24265).
#[no_mangle]
pub extern "C" fn ex_hermes_notify_callback() {
    CALLBACK_PENDING.store(true, Ordering::Release);
    invoke_host_wake_hook();
}

/// Check and clear the callback pending flag.
/// Called from the event loop polling code.
pub fn take_callback_pending() -> bool {
    CALLBACK_PENDING.swap(false, Ordering::Acquire)
}

#[cfg(test)]
#[allow(clashing_extern_declarations)]
mod tests {
    use std::ffi::{c_void, CStr, CString};
    use std::os::raw::c_char;

    /// Scoped delay injection for cross-thread runtime-callback producers.
    /// Typed in-process state, not an environment variable: env-var
    /// injection rode a process-global channel that unrelated tests capture,
    /// restore, and clear, silently dropping another test's delay while its
    /// producer thread was between publish and read (see
    /// issues/closed/20260727-test-delay-injection-is-a-global-env-var.md).
    #[cfg(feature = "capsec-conformance-observer")]
    struct RuntimeCallbackDelayGuard;

    #[cfg(feature = "capsec-conformance-observer")]
    impl RuntimeCallbackDelayGuard {
        fn new(milliseconds: u64) -> Self {
            unsafe { ibex_test_set_runtime_callback_delay_ms(milliseconds) };
            Self
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    impl Drop for RuntimeCallbackDelayGuard {
        fn drop(&mut self) {
            unsafe { ibex_test_set_runtime_callback_delay_ms(0) };
        }
    }

    /// Scoped producer-hold injection; counterpart of
    /// [`RuntimeCallbackDelayGuard`], parking a foreign producer inside
    /// `pushRuntimeCallback` after publish+notify.
    #[cfg(feature = "capsec-conformance-observer")]
    struct RuntimeProducerHoldGuard;

    #[cfg(feature = "capsec-conformance-observer")]
    impl RuntimeProducerHoldGuard {
        fn new(milliseconds: u64) -> Self {
            unsafe { ibex_test_set_runtime_producer_hold_ms(milliseconds) };
            Self
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    impl Drop for RuntimeProducerHoldGuard {
        fn drop(&mut self) {
            unsafe { ibex_test_set_runtime_producer_hold_ms(0) };
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[test]
    fn apple_open_file_sha256_matches_portable_digest() {
        use sha2::{Digest as _, Sha256};
        use std::io::Write as _;

        for bytes in [
            Vec::new(),
            (0u8..=255).cycle().take(1_000_123).collect::<Vec<_>>(),
        ] {
            let mut file = tempfile::tempfile().expect("digest fixture");
            file.write_all(&bytes).expect("write digest fixture");
            let observed = super::hash_open_file_sha256(&mut file, bytes.len() as u64)
                .expect("hash open file");
            assert_eq!(observed.as_slice(), Sha256::digest(&bytes).as_slice());
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn pinned_self_image_survives_path_replacement() {
        use sha2::{Digest as _, Sha256};
        use std::io::{Read as _, Write as _};
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::process::Command;
        use std::time::{Duration, Instant};

        const CHILD: &str = "IBEX_PINNED_SELF_IMAGE_REPLACEMENT_CHILD";
        const SOCKET: &str = "IBEX_PINNED_SELF_IMAGE_REPLACEMENT_SOCKET";
        const EXPECTED: &str = "IBEX_PINNED_SELF_IMAGE_REPLACEMENT_DIGEST";

        if std::env::var_os(CHILD).is_some() {
            let mut image = super::open_pinned_self_image().expect("pin mapped test executable");
            let mut stream = UnixStream::connect(std::env::var_os(SOCKET).expect("socket path"))
                .expect("connect replacement controller");
            stream
                .write_all(b"ready")
                .expect("report pinned descriptor");
            let mut release = [0u8; 1];
            stream
                .read_exact(&mut release)
                .expect("await pathname replacement");
            let mut bytes = Vec::new();
            image
                .read_to_end(&mut bytes)
                .expect("read pinned descriptor");
            let actual = format!("{:x}", Sha256::digest(&bytes));
            assert_eq!(actual, std::env::var(EXPECTED).expect("expected digest"));
            return;
        }

        let temp = tempfile::tempdir().expect("replacement test directory");
        let probe = temp.path().join("mapped-probe");
        std::fs::copy(std::env::current_exe().expect("test executable"), &probe)
            .expect("copy test executable");
        let original = std::fs::read(&probe).expect("read copied executable");
        let expected = format!("{:x}", Sha256::digest(&original));
        let socket_path = temp.path().join("controller.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind replacement controller");
        listener
            .set_nonblocking(true)
            .expect("make replacement controller nonblocking");
        let mut child = Command::new(&probe)
            .arg("--exact")
            .arg("engine::tests::pinned_self_image_survives_path_replacement")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env(SOCKET, &socket_path)
            .env(EXPECTED, expected)
            .spawn()
            .expect("spawn copied test executable");

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Some(status) = child.try_wait().expect("poll child") {
                        panic!("replacement child exited before pinning: {status}");
                    }
                    assert!(
                        Instant::now() < deadline,
                        "replacement child did not pin in time"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept replacement child: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set replacement controller timeout");
        let mut ready = [0u8; 5];
        stream
            .read_exact(&mut ready)
            .expect("await pinned descriptor");
        assert_eq!(&ready, b"ready");

        std::fs::rename(&probe, temp.path().join("mapped-original"))
            .expect("move running executable pathname");
        std::fs::write(&probe, b"replacement object").expect("replace executable pathname");
        stream.write_all(b"g").expect("release replacement child");
        let status = child.wait().expect("wait for replacement child");
        assert!(status.success(), "replacement child failed: {status}");
    }

    #[test]
    fn loaded_engine_identity_binds_factory_object_to_current_file_snapshot() {
        let identity = super::loaded_engine_binary_identity().unwrap();
        assert_eq!(identity.kind, "hermes");
        assert!(identity.engine_artifact_path.is_absolute());
        assert!(identity.binary_digest.starts_with("sha256-"));
        assert_eq!(identity.target_architecture, std::env::consts::ARCH);
        assert!(super::loaded_engine_bytecode_version().unwrap() > 0);
        assert_eq!(
            super::verify_loaded_engine_binary_identity(&identity).unwrap(),
            identity
        );
    }

    #[cfg(feature = "insecure")]
    #[test]
    fn insecure_engine_identity_matches_the_verified_build_artifact() {
        assert_eq!(
            super::loaded_engine_binary_identity_insecure().unwrap(),
            super::loaded_engine_binary_identity().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn post_probe_identity_verification_reopens_and_rehashes_the_object() {
        let directory = tempfile::tempdir().unwrap();
        let artifact = directory.path().join("libhermesvm-test.so");
        std::fs::write(&artifact, b"before-probe").unwrap();
        let expected =
            super::capture_engine_artifact_identity(&artifact, |_, _, _| Ok(())).unwrap();

        assert_eq!(
            super::verify_engine_binary_identity_with(&expected, || {
                super::capture_engine_artifact_identity(&artifact, |_, _, _| Ok(()))
            })
            .unwrap(),
            expected
        );

        // Change bytes in place and preserve the length/object identity. A
        // cached path, digest, or pre-probe Metadata snapshot would accept it;
        // a required post-probe recheck must reopen and hash it again.
        std::fs::write(&artifact, b"after--probe").unwrap();
        let changed = super::capture_engine_artifact_identity(&artifact, |_, _, _| Ok(())).unwrap();
        assert_eq!(changed.object, expected.object);
        assert_ne!(changed.binary_digest, expected.binary_digest);
        assert!(super::verify_engine_binary_identity_with(&expected, || {
            super::capture_engine_artifact_identity(&artifact, |_, _, _| Ok(()))
        })
        .is_err());

        // Replacing the pathname with the original bytes must also fail: a
        // stale cached digest alone would match, but fresh metadata identifies
        // a different object (and production's mapped-object check rejects it
        // before the comparison).
        let replacement = directory.path().join("replacement.so");
        std::fs::write(&replacement, b"before-probe").unwrap();
        std::fs::rename(&replacement, &artifact).unwrap();
        let replaced =
            super::capture_engine_artifact_identity(&artifact, |_, _, _| Ok(())).unwrap();
        assert_eq!(replaced.binary_digest, expected.binary_digest);
        assert_ne!(replaced.object, expected.object);
        assert!(super::verify_engine_binary_identity_with(&expected, || {
            super::capture_engine_artifact_identity(&artifact, |_, _, _| Ok(()))
        })
        .is_err());
    }

    #[test]
    fn embedded_engine_profile_receipt_rechecks_factory_object_file_bytes() {
        let receipt = match super::loaded_engine_profile_provenance() {
            Ok(Some(receipt)) => receipt,
            Ok(None) => {
                // Ordinary developer builds may intentionally omit a receipt.
                // Required CapSec builds fail instead of reaching this state.
                return;
            }
            Err(error) => panic!("embedded Hermes provenance did not revalidate: {error}"),
        };
        assert_eq!(
            receipt["schema"],
            "ibex/hermes-profile-provenance-receipt/2"
        );
        let expected_profile = match std::env::consts::OS {
            "android" => "android-maven",
            "windows" => "windows-source-patched",
            _ => "source-patched",
        };
        assert_eq!(receipt["profileId"], expected_profile);
        assert!(receipt["origin"]["reviewedProfileIdentity"].is_object());
        assert!(super::loaded_engine_binary_identity().is_ok());
    }

    #[repr(C)]
    struct HermesRuntimeOpaque {
        _private: [u8; 0],
    }

    #[repr(C)]
    struct StructuredOwnedBytes {
        data: *mut u8,
        length: usize,
    }

    #[repr(C)]
    struct StructuredSourcePosition {
        source_label: StructuredOwnedBytes,
        line: u32,
        column: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct StructuredValueHandle {
        runtime_nonce: u64,
        handle_id: u64,
    }

    #[repr(C)]
    struct StructuredEvaluationResult {
        abi_version: u32,
        struct_size: u32,
        outcome_tag: u32,
        fault: u32,
        work_target_id: u64,
        value: StructuredValueHandle,
        throw_metadata_status: u32,
        throw_metadata_fields: u32,
        throw_error_class: u32,
        lifecycle_exit_code: i32,
        capability_flags: u32,
        message: StructuredOwnedBytes,
        stack: StructuredOwnedBytes,
        positions: *mut StructuredSourcePosition,
        position_count: usize,
    }

    #[repr(C)]
    struct StructuredAsyncFailureEvent {
        abi_version: u32,
        struct_size: u32,
        kind: u32,
        principal_status: u32,
        value: StructuredValueHandle,
        host_context_id: u64,
        owning_principal_id: u64,
        event_id: u64,
        associated_evaluation: u64,
        dropped_count: u64,
    }

    const STRUCTURED_VALUE: u32 = 2;
    const STRUCTURED_THROW: u32 = 3;
    const STRUCTURED_ENGINE_FAULT: u32 = 6;
    const STRUCTURED_ABI_VERSION: u32 = 2;
    const VALUE_INVALID: u32 = 0;
    const VALUE_UNDEFINED: u32 = 1;
    const VALUE_STRING: u32 = 5;
    const VALUE_OBJECT: u32 = 9;
    const FAULT_NONE: u32 = 0;
    const FAULT_STALE_HANDLE: u32 = 7;
    const FAULT_RAW_THROW_UNAVAILABLE: u32 = 8;
    const FAULT_EVALUATION_IN_FLIGHT: u32 = 14;
    const THROW_METADATA_UNAVAILABLE: u32 = 0;
    const ERROR_CLASS_UNCLASSIFIED: u32 = 0;
    const CAPABILITY_SAFE_THROW: u32 = 1 << 1;
    const CAPABILITY_SOURCE_POSITIONS: u32 = 1 << 2;
    const ASYNC_FAILURE_ABI_VERSION: u32 = 1;
    const ASYNC_FAILURE_AVAILABLE: u32 = 1;
    const ASYNC_FAILURE_EMPTY: u32 = 0;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(C)]
    struct WorkletSharedValueHandle {
        slot: u32,
        generation: u32,
        epoch: u32,
    }

    const WORKLET_CAPTURE_F32: u32 = 1;
    const WORKLET_CAPTURE_BOOL: u32 = 2;
    const WORKLET_CAPTURE_SHARED_VALUE: u32 = 3;
    const WORKLET_INSTALL_SOURCE_UTF8: u32 = 1;
    const WORKLET_RUN_ON_JS_SLOTS: usize = 8;

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct WorkletCapture {
        kind: u32,
        scalar: f32,
        shared_value: WorkletSharedValueHandle,
    }

    #[derive(Clone, Copy, Debug)]
    #[repr(C)]
    struct WorkletScheduledCall {
        source_identity: u64,
        source_sequence: u64,
        generation: u64,
        callback_identity: u32,
        argument_count: u32,
        arguments: [f32; WORKLET_RUN_ON_JS_SLOTS],
    }

    impl Default for WorkletScheduledCall {
        fn default() -> Self {
            Self {
                source_identity: 0,
                source_sequence: 0,
                generation: 0,
                callback_identity: 0,
                argument_count: 0,
                arguments: [0.0; WORKLET_RUN_ON_JS_SLOTS],
            }
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    #[repr(C)]
    struct WorkletInstallMetrics {
        source_install_count: u64,
        reused_install_count: u64,
        source_install_total_ns: u64,
        source_install_max_ns: u64,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6EvidenceSource {
        path: String,
        sha256: String,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6Transaction {
        epoch: u32,
        motion_seq: String,
        root_instance: u32,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6CaptureEvidence {
        kind: String,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        descriptor_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation: Option<u32>,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6CallbackEvidence {
        identity: u32,
        action: String,
        payload_keys: Vec<String>,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6ArtifactEvidence {
        schema_version: u32,
        descriptor_id: String,
        node_id: u32,
        phase: String,
        generation: u64,
        compiler_id: String,
        install_format: String,
        source: String,
        source_identity: String,
        callback_identity: String,
        captures: Vec<MotionM6CaptureEvidence>,
        input_slots: Vec<String>,
        output_slots: Vec<String>,
        callbacks: Vec<MotionM6CallbackEvidence>,
        source_sha256: String,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6TierEvidence {
        tier: String,
        root_id: u32,
        transaction: MotionM6Transaction,
        artifacts: Vec<MotionM6ArtifactEvidence>,
    }

    #[derive(Clone, Debug, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct MotionM6GeneratedEvidence {
        schema_version: u32,
        generated_at_unix_ms: u64,
        generator: String,
        sources: Vec<MotionM6EvidenceSource>,
        tiers: Vec<MotionM6TierEvidence>,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6EvidenceFile {
        schema_version: u32,
        generated_at_unix_ms: u64,
        generator: String,
        sources: Vec<MotionM6EvidenceSource>,
        tiers: Vec<MotionM6TierEvidence>,
        evidence_sha256: String,
    }

    #[derive(Clone, Copy, Debug)]
    #[repr(C)]
    struct MotionRatedPublishSample {
        channel_identity: u64,
        dirty_generation: u64,
        sample_time_ns: u64,
        value_count: u32,
        flags: u32,
        values: [f32; WORKLET_RUN_ON_JS_SLOTS],
    }

    type WorkletSharedValueReadCallback =
        extern "C" fn(WorkletSharedValueHandle, *mut f32, *mut c_void) -> u32;
    type WorkletSharedValueWriteCallback =
        extern "C" fn(WorkletSharedValueHandle, f32, *mut c_void) -> u32;

    extern "C" {
        fn ex_hermes_create() -> *mut HermesRuntimeOpaque;
        fn ex_hermes_create_no_eval() -> *mut HermesRuntimeOpaque;
        fn ex_hermes_create_diagnostic() -> *mut HermesRuntimeOpaque;
        fn ex_hermes_destroy(runtime: *mut HermesRuntimeOpaque);
        fn ex_hermes_try_destroy(runtime: *mut HermesRuntimeOpaque, runtime_nonce: u64) -> i32;
        fn ex_hermes_eval(
            runtime: *mut HermesRuntimeOpaque,
            data: *const u8,
            len: usize,
            source_url: *const c_char,
            is_bytecode: i32,
            out_value: *mut *mut c_char,
        ) -> i32;
        fn ex_hermes_watch_time_limit(runtime: *mut HermesRuntimeOpaque, timeout_ms: u32) -> i32;
        fn ex_hermes_unwatch_time_limit(runtime: *mut HermesRuntimeOpaque);
        fn ex_hermes_interrupt_eval(runtime: *mut HermesRuntimeOpaque, runtime_nonce: u64) -> i32;
        fn ex_hermes_evaluation_result_init(result: *mut StructuredEvaluationResult);
        fn ex_hermes_evaluation_result_dispose(result: *mut StructuredEvaluationResult);
        fn ex_hermes_eval_structured_diagnostic(
            runtime: *mut HermesRuntimeOpaque,
            source: *const u8,
            source_length: usize,
            source_label: *const u8,
            source_label_length: usize,
            result: *mut StructuredEvaluationResult,
        ) -> i32;
        fn ex_hermes_value_kind(
            runtime: *mut HermesRuntimeOpaque,
            handle: StructuredValueHandle,
        ) -> u32;
        fn ex_hermes_value_release(
            runtime: *mut HermesRuntimeOpaque,
            handle: StructuredValueHandle,
        ) -> u32;
        fn ex_hermes_take_async_failure_event(
            runtime: *mut HermesRuntimeOpaque,
            event: *mut StructuredAsyncFailureEvent,
        ) -> u32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_exact_runtime_c_abi_probe_prepare(out_context: *mut *mut c_void) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_exact_runtime_c_abi_probe_wrong_thread(context: *mut c_void) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_exact_runtime_c_abi_probe_finish(context: *mut c_void) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_with_principal_tls_scope(
            module_id: u64,
            native_principal: u64,
            typed_principals: *const u64,
            typed_principal_count: usize,
            body: extern "C" fn(*mut c_void) -> i32,
            context: *mut c_void,
        ) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_forbidden_principal_tls_mask(
            module_id: u64,
            native_principal: u64,
            typed_principals: *const u64,
            typed_principal_count: usize,
        ) -> u32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_runtime_security_context_boundary(
            runtime: *mut HermesRuntimeOpaque,
            outer_runtime_nonce: u64,
            module_id: u64,
            native_principal: u64,
            typed_principals: *const u64,
            typed_principal_count: usize,
        ) -> u32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ex_hermes_current_runtime_nonce() -> u64;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_set_runtime_callback_delay_ms(milliseconds: u64);
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_set_runtime_producer_hold_ms(milliseconds: u64);
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_reset_jsi_owner_release_observer();
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_jsi_owner_final_releases_on_owner_thread() -> u64;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_jsi_owner_final_releases_off_owner_thread() -> u64;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_reset_runtime_finalizer_observer();
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_capture_runtime_finalizer_target(runtime: *mut HermesRuntimeOpaque) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_push_captured_runtime_finalizer(mode: u32) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_runtime_finalizer_run_count() -> u64;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_runtime_finalizer_good_run_count() -> u64;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_runtime_finalizer_destroyed_without_run_count() -> u64;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_runtime_finalizer_logged_failure_count() -> u64;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_runtime_finalizer_ran_on_owner_thread() -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_runtime_finalizer_refusal_destroyed_on_producer_thread() -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ex_hermes_set_host_call_async(
            runtime: *mut HermesRuntimeOpaque,
            callback: extern "C" fn(
                runtime: *mut HermesRuntimeOpaque,
                call_id: u64,
                op: *const c_char,
                args_json: *const c_char,
            ),
        );
        #[cfg(feature = "capsec-conformance-observer")]
        fn ex_hermes_resolve_host_call(
            runtime: *mut HermesRuntimeOpaque,
            call_id: u64,
            payload: *const c_char,
        );
        #[cfg(target_os = "windows")]
        fn ex_host_install();
        fn ex_hermes_free_string(value: *mut c_char);
        fn ex_hermes_gc(runtime: *mut HermesRuntimeOpaque);
        fn ex_hermes_get_heap_info(
            runtime: *mut HermesRuntimeOpaque,
            include_expensive: i32,
        ) -> *mut c_char;
        fn ex_hermes_get_gc_stats(runtime: *mut HermesRuntimeOpaque) -> *mut c_char;
        fn ex_hermes_poll(runtime: *mut HermesRuntimeOpaque, now_ms: u64) -> i32;
        fn ex_hermes_poll_with_external_keep_alive(
            runtime: *mut HermesRuntimeOpaque,
            now_ms: u64,
        ) -> i32;
        fn ex_hermes_set_keep_alive_on_async_error(runtime: *mut HermesRuntimeOpaque, enabled: i32);
        fn ex_hermes_has_pending_tasks(runtime: *mut HermesRuntimeOpaque) -> i32;
        fn ex_hermes_next_timer(runtime: *mut HermesRuntimeOpaque) -> i64;
        fn ex_hermes_now_ms() -> u64;
        fn ex_hermes_callback_backlog(runtime: *mut HermesRuntimeOpaque) -> u32;
        fn ex_hermes_runtime_nonce(runtime: *mut HermesRuntimeOpaque) -> u64;
        fn ex_hermes_set_host_call(
            runtime: *mut HermesRuntimeOpaque,
            callback: extern "C" fn(*const c_char, *const c_char) -> *mut c_char,
        );
        fn ex_hermes_schedule_watchdog_heartbeat(
            runtime: *mut HermesRuntimeOpaque,
            callback: extern "C" fn(*mut std::ffi::c_void),
            context: *mut std::ffi::c_void,
        );
        fn ex_hermes_schedule_watchdog_heartbeat_for_generation(
            runtime: *mut HermesRuntimeOpaque,
            runtime_nonce: u64,
            callback: extern "C" fn(*mut std::ffi::c_void),
            context: *mut std::ffi::c_void,
        );
        fn ex_worklet_create() -> *mut HermesRuntimeOpaque;
        fn ex_worklet_destroy(runtime: *mut HermesRuntimeOpaque);
        fn ex_worklet_set_generation(runtime: *mut HermesRuntimeOpaque, generation: u64);
        fn ex_worklet_install(
            runtime: *mut HermesRuntimeOpaque,
            worklet_id: *const c_char,
            source: *const u8,
            source_len: usize,
            generation: u64,
            out_error: *mut *mut c_char,
        ) -> i32;
        fn ex_worklet_invoke(
            runtime: *mut HermesRuntimeOpaque,
            worklet_id: *const c_char,
            args_json: *const c_char,
            out_result_json: *mut *mut c_char,
        ) -> i32;
        fn ex_worklet_install_typed(
            runtime: *mut HermesRuntimeOpaque,
            install_format: u32,
            artifact: *const u8,
            artifact_len: usize,
            captures: *const WorkletCapture,
            capture_count: u32,
            generation: u64,
            out_identity: *mut u64,
            out_error: *mut *mut c_char,
        ) -> i32;
        fn ex_worklet_invoke_typed(
            runtime: *mut HermesRuntimeOpaque,
            identity: u64,
            inputs: *const f32,
            input_count: u32,
            outputs: *mut f32,
            output_capacity: u32,
            out_output_count: *mut u32,
        ) -> i32;
        fn ex_worklet_install_metrics(
            runtime: *mut HermesRuntimeOpaque,
            out_metrics: *mut WorkletInstallMetrics,
        ) -> i32;
        fn ex_worklet_drain_scheduled_typed(
            runtime: *mut HermesRuntimeOpaque,
            out_calls: *mut WorkletScheduledCall,
            capacity: u32,
        ) -> u32;
        fn ex_worklet_take_scheduled_drop_count(runtime: *mut HermesRuntimeOpaque) -> u64;
        fn ex_hermes_dispatch_worklet_calls(
            runtime: *mut HermesRuntimeOpaque,
            calls: *const WorkletScheduledCall,
            count: u32,
            out_delivered: *mut u32,
        ) -> i32;
        fn ex_hermes_dispatch_worklet_json_batch(
            runtime: *mut HermesRuntimeOpaque,
            batch_json: *const u8,
            batch_len: usize,
            generation: u64,
        ) -> i32;
        fn ex_hermes_dispatch_motion_rated_publish(
            runtime: *mut HermesRuntimeOpaque,
            sample: *const MotionRatedPublishSample,
        ) -> i32;
        fn ex_worklet_bind_shared_value_accessors(
            runtime: *mut HermesRuntimeOpaque,
            read_callback: Option<WorkletSharedValueReadCallback>,
            write_callback: Option<WorkletSharedValueWriteCallback>,
            context: *mut c_void,
        ) -> i32;
    }

    #[derive(Debug)]
    struct SharedValueHost {
        expected: WorkletSharedValueHandle,
        value: f32,
        reads: u32,
        writes: u32,
        rejected_reads: u32,
        rejected_writes: u32,
    }

    extern "C" fn read_shared_value(
        handle: WorkletSharedValueHandle,
        out_value: *mut f32,
        context: *mut c_void,
    ) -> u32 {
        if context.is_null() || out_value.is_null() {
            return 2;
        }
        // SAFETY: the test keeps the boxed host alive until after it unbinds
        // the callbacks and destroys the single-owner worklet runtime.
        let host = unsafe { &mut *context.cast::<SharedValueHost>() };
        if handle != host.expected {
            host.rejected_reads += 1;
            return 1;
        }
        host.reads += 1;
        // SAFETY: the C++ bridge supplies a non-null pointer to one float.
        unsafe { *out_value = host.value };
        0
    }

    extern "C" fn write_shared_value(
        handle: WorkletSharedValueHandle,
        value: f32,
        context: *mut c_void,
    ) -> u32 {
        if context.is_null() {
            return 2;
        }
        // SAFETY: see read_shared_value; callback invocation is synchronous.
        let host = unsafe { &mut *context.cast::<SharedValueHost>() };
        if handle != host.expected {
            host.rejected_writes += 1;
            return 1;
        }
        host.writes += 1;
        host.value = value;
        0
    }

    fn install_worklet(
        runtime: *mut HermesRuntimeOpaque,
        id: &CString,
        source: &str,
        generation: u64,
    ) {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_worklet_install(
                runtime,
                id.as_ptr(),
                source.as_ptr(),
                source.len(),
                generation,
                &mut error,
            )
        };
        let message = if error.is_null() {
            None
        } else {
            let text = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { ex_hermes_free_string(error) };
            Some(text)
        };
        assert_eq!(status, 0, "worklet install failed: {message:?}");
    }

    fn invoke_worklet(runtime: *mut HermesRuntimeOpaque, id: &CString) -> String {
        let mut result = std::ptr::null_mut();
        let status =
            unsafe { ex_worklet_invoke(runtime, id.as_ptr(), std::ptr::null(), &mut result) };
        assert_eq!(status, 0, "worklet invoke failed");
        assert!(!result.is_null(), "worklet result must be JSON encoded");
        let text = unsafe { CStr::from_ptr(result) }
            .to_string_lossy()
            .into_owned();
        unsafe { ex_hermes_free_string(result) };
        text
    }

    unsafe fn install_typed_worklet(
        runtime: *mut HermesRuntimeOpaque,
        source: &str,
        captures: &[WorkletCapture],
        generation: u64,
    ) -> u64 {
        let mut identity = 0;
        let mut error = std::ptr::null_mut();
        let status = ex_worklet_install_typed(
            runtime,
            WORKLET_INSTALL_SOURCE_UTF8,
            source.as_ptr(),
            source.len(),
            captures.as_ptr(),
            captures.len() as u32,
            generation,
            &mut identity,
            &mut error,
        );
        let message = if error.is_null() {
            None
        } else {
            let text = CStr::from_ptr(error).to_string_lossy().into_owned();
            ex_hermes_free_string(error);
            Some(text)
        };
        assert_eq!(status, 0, "typed worklet install failed: {message:?}");
        assert_ne!(identity, 0);
        identity
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        format!("{:x}", Sha256::digest(bytes))
    }

    fn load_motion_m6_evidence() -> Option<MotionM6GeneratedEvidence> {
        let evidence_path = std::env::var_os("EXACT_MOTION_M6_ARTIFACTS")?;
        let bytes = std::fs::read(&evidence_path).unwrap_or_else(|error| {
            panic!(
                "failed to read EXACT_MOTION_M6_ARTIFACTS {}: {error}",
                std::path::Path::new(&evidence_path).display(),
            )
        });
        let evidence: MotionM6EvidenceFile =
            serde_json::from_slice(&bytes).expect("Motion M6 evidence must be strict JSON");
        let generated = MotionM6GeneratedEvidence {
            schema_version: evidence.schema_version,
            generated_at_unix_ms: evidence.generated_at_unix_ms,
            generator: evidence.generator,
            sources: evidence.sources,
            tiers: evidence.tiers,
        };
        assert_eq!(
            generated.schema_version, 1,
            "unsupported Motion M6 evidence schema"
        );
        assert_eq!(
            generated.generator, "scripts/check-motion-m6-authoring.ts",
            "Motion M6 evidence must come from the registered authoring twin",
        );
        let canonical_bytes =
            serde_json::to_vec(&generated).expect("Motion M6 evidence must reserialize");
        assert_eq!(
            sha256_hex(&canonical_bytes),
            evidence.evidence_sha256,
            "Motion M6 evidence digest does not authenticate the generated payload",
        );

        let max_age_ms = std::env::var("EXACT_MOTION_M6_ARTIFACT_MAX_AGE_MS")
            .unwrap_or_else(|_| "300000".to_owned())
            .parse::<u64>()
            .expect("EXACT_MOTION_M6_ARTIFACT_MAX_AGE_MS must be a u64");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_millis() as u64;
        assert!(
            generated.generated_at_unix_ms <= now_ms.saturating_add(10_000),
            "Motion M6 evidence timestamp is implausibly in the future",
        );
        assert!(
            now_ms.saturating_sub(generated.generated_at_unix_ms) <= max_age_ms,
            "Motion M6 evidence is stale (generated={}, now={}, maxAgeMs={})",
            generated.generated_at_unix_ms,
            now_ms,
            max_age_ms,
        );

        const EXPECTED_SOURCES: [&str; 5] = [
            "scripts/check-motion-m6-authoring.ts",
            "tests/motion/m6-authoring-twin.contract",
            "tests/motion/m6-authoring-twin.react.ts",
            "packages/exact-contract/src/compiler/motion-worklet-source.ts",
            "packages/exact-devtools/src/worklet-source-plugin.ts",
        ];
        assert_eq!(
            generated
                .sources
                .iter()
                .map(|source| source.path.as_str())
                .collect::<Vec<_>>(),
            EXPECTED_SOURCES,
            "Motion M6 provenance source set drifted",
        );
        let exact_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("Ibex must be vendored under Exact/vendor");
        for source in &generated.sources {
            let source_bytes =
                std::fs::read(exact_root.join(&source.path)).unwrap_or_else(|error| {
                    panic!("failed to read provenance source {}: {error}", source.path)
                });
            assert_eq!(
                sha256_hex(&source_bytes),
                source.sha256,
                "Motion M6 provenance source {} changed after evidence generation",
                source.path,
            );
        }

        assert_eq!(
            generated.tiers.len(),
            2,
            "expected Contract and React evidence"
        );
        assert_eq!(generated.tiers[0].tier, "contract");
        assert_eq!(generated.tiers[0].root_id, 2_470_401);
        assert_eq!(generated.tiers[1].tier, "react");
        assert_eq!(generated.tiers[1].root_id, 2_470_402);
        for tier in &generated.tiers {
            assert!(tier.transaction.epoch > 0);
            assert!(tier.transaction.root_instance > 0);
            assert!(
                tier.transaction
                    .motion_seq
                    .parse::<u64>()
                    .is_ok_and(|sequence| sequence > 0),
                "{} Motion transaction sequence must be positive",
                tier.tier,
            );
            assert_eq!(
                tier.artifacts.len(),
                4,
                "{} must emit four artifacts",
                tier.tier
            );
            let phase_count = |phase: &str| {
                tier.artifacts
                    .iter()
                    .filter(|artifact| artifact.phase == phase)
                    .count()
            };
            assert_eq!(
                phase_count("derive"),
                2,
                "{} must emit two projections",
                tier.tier
            );
            assert_eq!(
                phase_count("update"),
                1,
                "{} must emit one update",
                tier.tier
            );
            assert_eq!(
                phase_count("end"),
                1,
                "{} must emit one terminal callback",
                tier.tier
            );
            for artifact in &tier.artifacts {
                assert_eq!(artifact.schema_version, 2);
                assert_eq!(artifact.install_format, "source-utf8");
                assert!(artifact.node_id > 0);
                assert!(artifact.generation > 0);
                assert!(!artifact.compiler_id.is_empty());
                assert!(
                    artifact
                        .descriptor_id
                        .parse::<u64>()
                        .is_ok_and(|identity| identity > 0),
                    "{} descriptor identity must be a positive u64",
                    artifact.compiler_id,
                );
                assert!(artifact.source_identity.parse::<u64>().is_ok());
                assert!(artifact.callback_identity.parse::<u64>().is_ok());
                assert_eq!(
                    sha256_hex(artifact.source.as_bytes()),
                    artifact.source_sha256,
                    "{} artifact source digest mismatch",
                    artifact.compiler_id,
                );
                assert!(artifact.input_slots.len() <= 16);
                assert!(artifact.output_slots.len() <= 16);
                match artifact.phase.as_str() {
                    "derive" => {
                        assert!(artifact.input_slots.is_empty());
                        assert_eq!(artifact.output_slots, ["return.value"]);
                        assert_eq!(artifact.captures.len(), 1);
                        assert!(artifact.callbacks.is_empty());
                    }
                    "update" => {
                        assert_eq!(artifact.input_slots.len(), 1);
                        assert!(artifact.output_slots.is_empty());
                        assert_eq!(artifact.captures.len(), 1);
                        assert!(artifact.callbacks.is_empty());
                    }
                    "end" => {
                        assert_eq!(artifact.input_slots.len(), 2);
                        assert!(artifact.output_slots.is_empty());
                        assert!(artifact.captures.is_empty());
                        assert_eq!(artifact.callbacks.len(), 1);
                        assert_eq!(artifact.callbacks[0].action, "observe");
                        assert_eq!(artifact.callbacks[0].payload_keys, ["x", "velocity"]);
                    }
                    other => panic!("unexpected Motion M6 artifact phase {other}"),
                }
            }
        }
        Some(generated)
    }

    unsafe fn worklet_total_allocated_bytes(runtime: *mut HermesRuntimeOpaque) -> u64 {
        let stats = ex_hermes_get_gc_stats(runtime);
        assert!(!stats.is_null(), "Hermes GC stats must be available");
        let text = CStr::from_ptr(stats).to_string_lossy().into_owned();
        ex_hermes_free_string(stats);
        let marker = "\"totalAllocatedBytes\":";
        let cursor = text
            .find(marker)
            .map(|offset| offset + marker.len())
            .expect("Hermes GC stats must include totalAllocatedBytes");
        let digits = text[cursor..]
            .trim_start()
            .bytes()
            .take_while(u8::is_ascii_digit)
            .collect::<Vec<_>>();
        assert!(!digits.is_empty(), "totalAllocatedBytes must be an integer");
        std::str::from_utf8(&digits)
            .expect("allocation counter digits must be UTF-8")
            .parse::<u64>()
            .expect("totalAllocatedBytes must fit in u64")
    }

    unsafe fn invoke_typed_repeatedly(
        runtime: *mut HermesRuntimeOpaque,
        identity: u64,
        input_count: usize,
        output_capacity: usize,
        expected_output_count: u32,
        sample_count: u64,
    ) {
        let inputs = vec![2.0_f32; input_count];
        let mut outputs = vec![0.0_f32; output_capacity];
        let input_ptr = if inputs.is_empty() {
            std::ptr::null()
        } else {
            inputs.as_ptr()
        };
        let output_ptr = if outputs.is_empty() {
            std::ptr::null_mut()
        } else {
            outputs.as_mut_ptr()
        };
        for _ in 0..sample_count {
            let mut output_count = 0;
            assert_eq!(
                ex_worklet_invoke_typed(
                    runtime,
                    identity,
                    input_ptr,
                    input_count as u32,
                    output_ptr,
                    output_capacity as u32,
                    &mut output_count,
                ),
                0,
            );
            assert_eq!(output_count, expected_output_count);
        }
    }

    unsafe fn typed_allocation_slope(
        runtime: *mut HermesRuntimeOpaque,
        identity: u64,
        input_count: usize,
        output_capacity: usize,
        expected_output_count: u32,
        sample_count: u64,
    ) -> u64 {
        let before = worklet_total_allocated_bytes(runtime);
        invoke_typed_repeatedly(
            runtime,
            identity,
            input_count,
            output_capacity,
            expected_output_count,
            sample_count,
        );
        let after = worklet_total_allocated_bytes(runtime);
        assert!(
            after >= before,
            "Hermes' cumulative allocation counter must be monotonic"
        );
        after - before
    }

    fn motion_m6_worklet_captures(
        artifact: &MotionM6ArtifactEvidence,
        epoch: u32,
    ) -> Vec<WorkletCapture> {
        artifact
            .captures
            .iter()
            .map(|capture| match capture.kind.as_str() {
                "f32" => {
                    assert!(capture.descriptor_id.is_none());
                    assert!(capture.generation.is_none());
                    let value = capture
                        .value
                        .as_ref()
                        .and_then(serde_json::Value::as_f64)
                        .expect("f32 capture must carry a numeric value");
                    assert!(value.is_finite());
                    assert!(value >= f32::MIN as f64 && value <= f32::MAX as f64);
                    WorkletCapture {
                        kind: WORKLET_CAPTURE_F32,
                        scalar: value as f32,
                        shared_value: WorkletSharedValueHandle {
                            slot: 0,
                            generation: 0,
                            epoch: 0,
                        },
                    }
                }
                "bool" => {
                    assert!(capture.descriptor_id.is_none());
                    assert!(capture.generation.is_none());
                    WorkletCapture {
                        kind: WORKLET_CAPTURE_BOOL,
                        scalar: if capture
                            .value
                            .as_ref()
                            .and_then(serde_json::Value::as_bool)
                            .expect("bool capture must carry a boolean value")
                        {
                            1.0
                        } else {
                            0.0
                        },
                        shared_value: WorkletSharedValueHandle {
                            slot: 0,
                            generation: 0,
                            epoch: 0,
                        },
                    }
                }
                "sharedValue" => {
                    assert!(capture.value.is_none());
                    let descriptor_id = capture
                        .descriptor_id
                        .as_deref()
                        .expect("SharedValue capture must carry descriptorId")
                        .parse::<u64>()
                        .expect("SharedValue descriptorId must fit u64");
                    assert!(descriptor_id > 0);
                    let folded_slot = (descriptor_id ^ (descriptor_id >> 32)) as u32;
                    WorkletCapture {
                        kind: WORKLET_CAPTURE_SHARED_VALUE,
                        scalar: 0.0,
                        shared_value: WorkletSharedValueHandle {
                            slot: folded_slot.max(1),
                            generation: capture
                                .generation
                                .expect("SharedValue capture must carry generation"),
                            epoch,
                        },
                    }
                }
                other => panic!("unsupported Motion M6 capture kind {other}"),
            })
            .collect()
    }

    fn motion_m6_matched_control(artifact: &MotionM6ArtifactEvidence) -> String {
        match artifact.phase.as_str() {
            "derive" if artifact.source.contains("worklet.clamp") => {
                "(function(){worklet.output(0,worklet.clamp((Math.abs(worklet.captureGet(0))/320),0,1));})".to_owned()
            }
            "derive" if artifact.source.contains("Math.max") => {
                "()=>{worklet.output(0,Math.max(0,Math.min(1,Math.abs(worklet.captureGet(0))/320)));return;}".to_owned()
            }
            "derive" if artifact.source.starts_with("()=>") => {
                "()=>{worklet.output(0,worklet.captureGet(0)+0);return;}".to_owned()
            }
            "derive" => {
                "(function(){worklet.output(0,worklet.captureGet(0)+0);})".to_owned()
            }
            "update" if artifact.source.contains("=>") => {
                "__exactInput0=>{worklet.captureSet(0,__exactInput0+0);}".to_owned()
            }
            "update" => {
                "(function(__exactInput0){worklet.captureSet(0,__exactInput0+0);})".to_owned()
            }
            "end" if artifact.source.contains("=>") => {
                "(__exactInput0,__exactInput1)=>{worklet.runOnJS(1,__exactInput0,__exactInput1);}".to_owned()
            }
            "end" => {
                "(function(__exactInput0,__exactInput1){worklet.runOnJS(1,__exactInput0,__exactInput1);})".to_owned()
            }
            other => panic!("unsupported Motion M6 artifact phase {other}"),
        }
    }

    unsafe fn measure_motion_m6_tier(tier: &MotionM6TierEvidence) {
        const WARMUP: u64 = 128;
        const SAMPLES: u64 = 2_048;
        let generation = tier.artifacts[0].generation;
        assert!(tier
            .artifacts
            .iter()
            .all(|artifact| artifact.generation == generation));

        let captures = tier
            .artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact,
                    motion_m6_worklet_captures(artifact, tier.transaction.epoch),
                )
            })
            .collect::<Vec<_>>();
        let mut shared_handles = captures
            .iter()
            .flat_map(|(_, captures)| captures)
            .filter(|capture| capture.kind == WORKLET_CAPTURE_SHARED_VALUE)
            .map(|capture| capture.shared_value)
            .collect::<Vec<_>>();
        shared_handles.dedup();
        assert_eq!(
            shared_handles.len(),
            1,
            "{} fixture must project one SharedValue identity",
            tier.tier,
        );

        let runtime = ex_worklet_create();
        assert!(!runtime.is_null());
        let mut host = Box::new(SharedValueHost {
            expected: shared_handles[0],
            value: 80.0,
            reads: 0,
            writes: 0,
            rejected_reads: 0,
            rejected_writes: 0,
        });
        let context = (&mut *host as *mut SharedValueHost).cast::<c_void>();
        assert_eq!(
            ex_worklet_bind_shared_value_accessors(
                runtime,
                Some(read_shared_value),
                Some(write_shared_value),
                context,
            ),
            0,
        );
        ex_worklet_set_generation(runtime, generation);

        for (artifact, captures) in &captures {
            let candidate =
                install_typed_worklet(runtime, &artifact.source, captures, artifact.generation);
            let control = install_typed_worklet(
                runtime,
                &motion_m6_matched_control(artifact),
                captures,
                artifact.generation,
            );
            invoke_typed_repeatedly(
                runtime,
                candidate,
                artifact.input_slots.len(),
                artifact.output_slots.len(),
                artifact.output_slots.len() as u32,
                WARMUP,
            );
            invoke_typed_repeatedly(
                runtime,
                control,
                artifact.input_slots.len(),
                artifact.output_slots.len(),
                artifact.output_slots.len() as u32,
                WARMUP,
            );
            let candidate_bytes = typed_allocation_slope(
                runtime,
                candidate,
                artifact.input_slots.len(),
                artifact.output_slots.len(),
                artifact.output_slots.len() as u32,
                SAMPLES,
            );
            let control_bytes = typed_allocation_slope(
                runtime,
                control,
                artifact.input_slots.len(),
                artifact.output_slots.len(),
                artifact.output_slots.len() as u32,
                SAMPLES,
            );
            eprintln!(
                concat!(
                    "motion-worklet-generated-artifact: tier={} compiler={} phase={} ",
                    "samples={} raw-control={} raw-candidate={} semantic-excess={}",
                ),
                tier.tier,
                artifact.compiler_id,
                artifact.phase,
                SAMPLES,
                control_bytes,
                candidate_bytes,
                candidate_bytes.saturating_sub(control_bytes),
            );
            assert!(control_bytes > 0, "retain raw Hermes ABI allocation truth");
            assert_eq!(
                candidate_bytes, control_bytes,
                "{} {} generated artifact must have zero semantic/excess allocation bytes",
                tier.tier, artifact.compiler_id,
            );
        }

        let (derive, derive_captures) = captures
            .iter()
            .find(|(artifact, _)| {
                artifact.phase == "derive"
                    && !artifact.source.contains("worklet.clamp")
                    && !artifact.source.contains("Math.max")
            })
            .expect("Motion M6 evidence must include the direct scalar projection");
        let negative = install_typed_worklet(
            runtime,
            "(function(){var box={value:worklet.captureGet(0)};worklet.output(0,box.value);})",
            derive_captures,
            derive.generation,
        );
        let control = install_typed_worklet(
            runtime,
            &motion_m6_matched_control(derive),
            derive_captures,
            derive.generation,
        );
        invoke_typed_repeatedly(runtime, negative, 0, 1, 1, WARMUP);
        invoke_typed_repeatedly(runtime, control, 0, 1, 1, WARMUP);
        let negative_bytes = typed_allocation_slope(runtime, negative, 0, 1, 1, SAMPLES);
        let control_bytes = typed_allocation_slope(runtime, control, 0, 1, 1, SAMPLES);
        assert!(
            negative_bytes > control_bytes,
            "{} negative object-allocation control must exceed its matched control",
            tier.tier,
        );
        eprintln!(
            "motion-worklet-generated-negative: tier={} samples={} raw-control={} raw-negative={} semantic-excess={}",
            tier.tier,
            SAMPLES,
            control_bytes,
            negative_bytes,
            negative_bytes.saturating_sub(control_bytes),
        );

        assert_eq!(host.rejected_reads, 0);
        assert_eq!(host.rejected_writes, 0);
        assert_eq!(
            ex_worklet_bind_shared_value_accessors(runtime, None, None, std::ptr::null_mut()),
            0,
        );
        ex_worklet_destroy(runtime);
    }

    /// LLP 0099 M6 forbids object/string allocation in the hot math path; it
    /// does not pretend Hermes' fixed JSI call cells disappear. Compare raw
    /// cumulative slopes in one warmed runtime with identical input/output
    /// host-call shapes, and require zero candidate excess. The allocating
    /// control proves that this counter detects the object-literal regression
    /// the compiler is required to exclude.
    #[test]
    fn motion_worklet_semantic_allocation_slope_is_flat() {
        if let Some(evidence) = load_motion_m6_evidence() {
            unsafe {
                for tier in &evidence.tiers {
                    measure_motion_m6_tier(tier);
                }
            }
            return;
        }

        // The standalone Ibex suite has no Exact authoring toolchain. Retain
        // one local source-shape sentinel there; the registered Exact M6
        // acceptance wrapper always supplies authenticated generated evidence
        // and therefore takes the branch above.
        unsafe {
            const WARMUP: u64 = 128;
            const SAMPLES: u64 = 2_048;
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());
            ex_worklet_set_generation(runtime, 1);

            let control = install_typed_worklet(
                runtime,
                "(function (input) { worklet.output(0, input); })",
                &[],
                1,
            );
            let candidate = install_typed_worklet(
                runtime,
                "(function (input) { worklet.output(0, input * 2 + 1); })",
                &[],
                1,
            );
            let allocating_control = install_typed_worklet(
                runtime,
                "(function (input) { var box = { value: input * 2 + 1 }; worklet.output(0, box.value); })",
                &[],
                1,
            );

            for identity in [control, candidate, allocating_control] {
                invoke_typed_repeatedly(runtime, identity, 1, 1, 1, WARMUP);
            }

            let control_bytes = typed_allocation_slope(runtime, control, 1, 1, 1, SAMPLES);
            let candidate_bytes = typed_allocation_slope(runtime, candidate, 1, 1, 1, SAMPLES);
            let allocating_bytes =
                typed_allocation_slope(runtime, allocating_control, 1, 1, 1, SAMPLES);

            eprintln!(
                concat!(
                    "motion-worklet-allocation: samples={} raw-control={} ",
                    "raw-candidate={} semantic-excess={} allocating-control={}",
                ),
                SAMPLES,
                control_bytes,
                candidate_bytes,
                candidate_bytes.saturating_sub(control_bytes),
                allocating_bytes,
            );

            assert!(control_bytes > 0, "retain raw Hermes ABI allocation truth");
            assert_eq!(
                candidate_bytes, control_bytes,
                "scalar math must have zero semantic/excess allocation bytes"
            );
            assert!(
                allocating_bytes > control_bytes,
                "the paired counter must detect an object-literal allocation"
            );
            ex_worklet_destroy(runtime);
        }
    }

    #[test]
    fn restricted_worklet_supports_common_guarded_runtime_drives() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());
            assert_ne!(ex_hermes_runtime_nonce(runtime), 0);
            assert_eq!(eval(runtime, "21 * 2"), (0, Some("42".into())));

            ex_hermes_gc(runtime);
            let heap_info = ex_hermes_get_heap_info(runtime, 0);
            assert!(!heap_info.is_null());
            ex_hermes_free_string(heap_info);
            let gc_stats = ex_hermes_get_gc_stats(runtime);
            assert!(!gc_stats.is_null());
            ex_hermes_free_string(gc_stats);
            ex_worklet_destroy(runtime);

            // The private restricted context must not consume the app
            // runtime's install-to-constructor handoff.
            let app = ex_hermes_create_diagnostic();
            assert!(!app.is_null());
            ex_hermes_destroy(app);
        }
    }

    fn eval(runtime: *mut HermesRuntimeOpaque, source: &str) -> (i32, Option<String>) {
        let url = std::ffi::CString::new("r1-test.js").expect("source url");
        let mut out: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_eval(
                runtime,
                source.as_ptr(),
                source.len(),
                url.as_ptr(),
                0,
                &mut out,
            )
        };
        let value = if out.is_null() {
            None
        } else {
            let text = unsafe { std::ffi::CStr::from_ptr(out) }
                .to_string_lossy()
                .into_owned();
            unsafe { ex_hermes_free_string(out) };
            Some(text)
        };
        (status, value)
    }

    fn finalization_primitives_available(runtime: *mut HermesRuntimeOpaque) -> bool {
        let (status, kinds) = eval(
            runtime,
            "typeof FinalizationRegistry + ',' + typeof WeakRef",
        );
        assert_eq!(status, 0, "finalization capability probe failed: {kinds:?}");
        if kinds.as_deref() == Some("function,function") {
            return true;
        }

        #[cfg(ibex_hermes_finalization_capable)]
        panic!(
            "authenticated finalization-capable Hermes profile lacks FinalizationRegistry/WeakRef: {kinds:?}"
        );
        #[cfg(not(ibex_hermes_finalization_capable))]
        false
    }

    fn poll_finalization_until(runtime: *mut HermesRuntimeOpaque, predicate: &str, failure: &str) {
        for _ in 0..64 {
            unsafe {
                ex_hermes_gc(runtime);
                assert!(
                    ex_hermes_poll(runtime, ex_hermes_now_ms()) >= 0,
                    "FinalizationRegistry cleanup must not make polling fatal"
                );
            }
            if eval(runtime, predicate).1.as_deref() == Some("true") {
                return;
            }
        }
        panic!("{failure}");
    }

    fn heap_allocated_bytes(runtime: *mut HermesRuntimeOpaque) -> Option<u64> {
        let raw = unsafe { ex_hermes_get_heap_info(runtime, 0) };
        if raw.is_null() {
            return None;
        }
        let text = unsafe { CStr::from_ptr(raw) }
            .to_string_lossy()
            .into_owned();
        unsafe { ex_hermes_free_string(raw) };
        let info: serde_json::Value = serde_json::from_str(&text).ok()?;
        info.get("allocatedBytes")
            .or_else(|| info.get("hermes_allocatedBytes"))
            .and_then(serde_json::Value::as_u64)
    }

    /// The restricted consumer constructor keeps host-selected evaluation
    /// available while closing every JavaScript-reachable string compiler,
    /// including Hermes's cached Function("return this") fast path.
    /// @ref LLP 0013#embedding-dynamic-code-policy-patch-0014
    #[test]
    fn no_eval_consumer_runtime_closes_dynamic_code_paths() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let runtime = ex_hermes_create_no_eval();
            assert!(
                !runtime.is_null(),
                "the linked Hermes artifact must carry the dynamic-code latch"
            );

            let (status, value) = eval(
                runtime,
                r#"
                (function () {
                  var probes = [
                    function () { return eval('1'); },
                    function () { return (0, eval)('1'); },
                    function () { return Function('return 1'); },
                    function () { return Function('return this'); },
                    function () { return Function('  return this;  '); },
                    function () { return ({}).constructor.constructor('return this'); },
                    function () { return Reflect.apply(Function, undefined, ['return this']); },
                    function () { return Reflect.construct(Function, ['return this']); },
                    function () { return (async function () {}).constructor('return 1'); },
                    function () { return (function* () {}).constructor('return 1'); }
                  ];
                  var survivors = [];
                  for (var i = 0; i < probes.length; i++) {
                    try { probes[i](); survivors.push(i); } catch (_) {}
                  }
                  return JSON.stringify(survivors);
                })()
                "#,
            );
            assert_eq!(status, 0, "host-selected evaluation failed: {value:?}");
            assert_eq!(value.as_deref(), Some("[]"));

            let (status, value) = eval(
                runtime,
                r#"
                JSON.stringify({
                  mathFrozen: Object.isFrozen(Math),
                  randomConfigurable:
                    Object.getOwnPropertyDescriptor(Math, "random").configurable,
                  dateFrozen: Object.isFrozen(Date),
                  dateConfigurable:
                    Object.getOwnPropertyDescriptor(globalThis, "Date").configurable
                })
                "#,
            );
            assert_eq!(status, 0, "consumer policy probe failed: {value:?}");
            assert_eq!(
                value.as_deref(),
                Some(
                    "{\"mathFrozen\":false,\"randomConfigurable\":true,\"dateFrozen\":false,\"dateConfigurable\":true}"
                )
            );
            ex_hermes_destroy(runtime);
        }
    }

    /// Restricted consumers receive detached Promise failures through the
    /// native owner-thread queue, without a handler-reachable observer hook.
    /// @ref LLP 0002#the-narrow-consumer-contract-semver-major
    #[test]
    fn no_eval_consumer_runtime_reports_detached_promise_rejections() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let runtime = ex_hermes_create_no_eval();
            assert!(!runtime.is_null());
            let (status, value) = eval(runtime, "Promise.reject('detached'); 'scheduled'");
            assert_eq!(status, 0, "rejection scheduling failed: {value:?}");

            let mut event = StructuredAsyncFailureEvent {
                abi_version: ASYNC_FAILURE_ABI_VERSION,
                struct_size: std::mem::size_of::<StructuredAsyncFailureEvent>() as u32,
                kind: 0,
                principal_status: 0,
                value: StructuredValueHandle {
                    runtime_nonce: 0,
                    handle_id: 0,
                },
                host_context_id: 0,
                owning_principal_id: 0,
                event_id: 0,
                associated_evaluation: 0,
                dropped_count: 0,
            };
            assert_eq!(
                ex_hermes_take_async_failure_event(runtime, &mut event),
                ASYNC_FAILURE_AVAILABLE
            );
            assert_ne!(event.value.runtime_nonce, 0);
            assert_ne!(event.value.handle_id, 0);
            assert_eq!(ex_hermes_value_release(runtime, event.value), FAULT_NONE);
            assert_eq!(
                ex_hermes_take_async_failure_event(runtime, &mut event),
                ASYNC_FAILURE_EMPTY
            );
            ex_hermes_destroy(runtime);
        }
    }

    /// Return the exact JavaScript source installed by the production
    /// `kFsHandleJS` bootstrap. Keeping this extraction test-only avoids a
    /// production test hook while ensuring the absence test cannot drift into
    /// a hand-written imitation of FsHandle ownership.
    fn authored_fs_handle_install_source() -> &'static str {
        const HERMES_RUNTIME_SOURCE: &str = include_str!("hermes_runtime.cc");
        const START: &str = "static const char* kFsHandleJS = R\"JS(";
        const END: &str = "\n)JS\";";

        let (_, after_start) = HERMES_RUNTIME_SOURCE
            .split_once(START)
            .expect("hermes_runtime.cc must retain the kFsHandleJS source marker");
        let (source, _) = after_start
            .split_once(END)
            .expect("kFsHandleJS must retain its raw-string terminator");
        assert!(source.starts_with("(function () {"));
        assert!(source.contains("function FsHandle(id)"));
        assert!(source.contains("FsHandle.prototype.revoke = function ()"));
        source
    }

    /// A classified artifact must execute ordinary user registrations with the
    /// standard unregister and weak-target behavior after forced collection and
    /// bounded owner-thread checkpoints.
    #[test]
    fn js_finalization_registry_fires_for_user_registrations_after_gc() {
        let _host_guard = crate::host::abi::host_test_lock();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );

        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            if !finalization_primitives_available(runtime) {
                ex_hermes_destroy(runtime);
                return;
            }

            let (status, value) = eval(
                runtime,
                r#"(function () {
                  globalThis.__userFinalized = Object.create(null);
                  globalThis.__userFinalizedTotal = 0;
                  globalThis.__userRegistry = new FinalizationRegistry(function (held) {
                    __userFinalized[held] = (__userFinalized[held] || 0) + 1;
                    __userFinalizedTotal++;
                  });
                  (function () {
                    var targets = [];
                    var tokens = [];
                    for (var i = 0; i < 1000; i++) {
                      var target = { index: i };
                      var token = {};
                      targets.push(target);
                      tokens.push(token);
                      __userRegistry.register(target, i, token);
                      if (i === 1) globalThis.__userWeakSample = new WeakRef(target);
                    }
                    for (var j = 0; j < 1000; j += 2) {
                      if (!__userRegistry.unregister(tokens[j])) {
                        throw new Error('failed to unregister token ' + j);
                      }
                    }
                  })();
                  globalThis.__userFinalizationPressure = new Uint8Array(8 * 1024 * 1024);
                  globalThis.__userFinalizationPressure = null;
                  return 'registered';
                })()"#,
            );
            assert_eq!(status, 0, "user registration setup failed: {value:?}");
            assert_eq!(value.as_deref(), Some("registered"));

            poll_finalization_until(
                runtime,
                "String(__userFinalizedTotal === 500)",
                "user FinalizationRegistry population did not stabilize within 64 GC/checkpoints",
            );
            // Additional bounded checkpoints make duplicate delivery visible.
            for _ in 0..4 {
                ex_hermes_gc(runtime);
                assert!(ex_hermes_poll(runtime, ex_hermes_now_ms()) >= 0);
            }

            let (status, summary) = eval(
                runtime,
                r#"JSON.stringify({
                  counts: (function () {
                    var result = [];
                    for (var i = 0; i < 1000; i++) result.push(__userFinalized[i] || 0);
                    return result;
                  })(),
                  weakCleared: __userWeakSample.deref() === undefined,
                  total: __userFinalizedTotal
                })"#,
            );
            assert_eq!(status, 0, "user finalization summary failed: {summary:?}");
            let summary: serde_json::Value =
                serde_json::from_str(summary.as_deref().expect("user finalization summary JSON"))
                    .expect("valid user finalization summary JSON");
            assert_eq!(summary["total"].as_u64(), Some(500));
            assert_eq!(summary["weakCleared"].as_bool(), Some(true));
            let counts = summary["counts"].as_array().expect("per-held-value counts");
            assert_eq!(counts.len(), 1000);
            for (index, count) in counts.iter().enumerate() {
                assert_eq!(
                    count.as_u64(),
                    Some(if index % 2 == 0 { 0 } else { 1 }),
                    "held value {index} had the wrong cleanup count"
                );
            }
            ex_hermes_destroy(runtime);
        }
    }

    /// Repeated wrapper waves gate both synthetic native-handle count and
    /// declared native byte weight, including mixed retention and deterministic
    /// explicit disposal.
    #[test]
    fn js_finalization_registry_reclaims_webgpu_shaped_wrappers_under_sustained_load() {
        let _host_guard = crate::host::abi::host_test_lock();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );

        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            if !finalization_primitives_available(runtime) {
                ex_hermes_destroy(runtime);
                return;
            }

            let (status, value) = eval(
                runtime,
                r#"(function () {
                  globalThis.__syntheticGpu = (function () {
                    var nextId = 1;
                    var live = Object.create(null);
                    var liveCount = 0;
                    var liveBytes = 0;
                    var created = 0;
                    var released = [];
                    var releaseCounts = Object.create(null);
                    function release(record) {
                      if (!live[record.id]) return;
                      delete live[record.id];
                      liveCount--;
                      liveBytes -= record.bytes;
                      released.push(record.id);
                      releaseCounts[record.id] = (releaseCounts[record.id] || 0) + 1;
                    }
                    var registry = new FinalizationRegistry(release);
                    function wrap(bytes) {
                      var record = { id: nextId++, bytes: bytes };
                      var token = {};
                      var disposed = false;
                      live[record.id] = record;
                      liveCount++;
                      liveBytes += bytes;
                      created++;
                      var wrapper = {
                        id: record.id,
                        bytes: bytes,
                        dispose: function () {
                          if (disposed) return;
                          disposed = true;
                          registry.unregister(token);
                          release(record);
                        }
                      };
                      registry.register(wrapper, record, token);
                      return wrapper;
                    }
                    return {
                      wrap: wrap,
                      allReleased: function (ids) {
                        for (var i = 0; i < ids.length; i++) {
                          if (!releaseCounts[ids[i]]) return false;
                        }
                        return true;
                      },
                      summary: function () {
                        return {
                          created: created,
                          released: released.length,
                          liveCount: liveCount,
                          liveBytes: liveBytes
                        };
                      },
                      releaseCount: function (id) { return releaseCounts[id] || 0; }
                    };
                  })();
                  return 'installed';
                })()"#,
            );
            assert_eq!(status, 0, "synthetic GPU library failed: {value:?}");
            assert_eq!(value.as_deref(), Some("installed"));

            const BATCH_SIZE: u64 = 500;
            const BATCH_WEIGHT: u64 = 9_183_232;
            let mut heap_samples = Vec::new();
            for batch in 0..10 {
                let (status, ids) = eval(
                    runtime,
                    r#"(function () {
                      var ids = [];
                      (function () {
                        var wrappers = [];
                        for (var i = 0; i < 500; i++) {
                          var wrapper = __syntheticGpu.wrap(((i % 8) + 1) * 4096);
                          ids.push(wrapper.id);
                          wrappers.push(wrapper);
                        }
                      })();
                      globalThis.__syntheticGpuPressure = new Uint8Array(8 * 1024 * 1024);
                      globalThis.__syntheticGpuPressure = null;
                      return JSON.stringify(ids);
                    })()"#,
                );
                assert_eq!(status, 0, "synthetic GPU batch {batch} failed: {ids:?}");
                let ids = ids.expect("synthetic GPU batch ids");
                let predicate = format!("String(__syntheticGpu.allReleased({ids}))");
                poll_finalization_until(
                    runtime,
                    &predicate,
                    &format!("synthetic GPU batch {batch} did not drain within 64 GC/checkpoints"),
                );
                let summary = eval(runtime, "JSON.stringify(__syntheticGpu.summary())")
                    .1
                    .expect("synthetic GPU batch summary");
                let summary: serde_json::Value =
                    serde_json::from_str(&summary).expect("valid synthetic GPU summary");
                assert!(summary["liveCount"].as_u64().unwrap() <= BATCH_SIZE);
                assert!(summary["liveBytes"].as_u64().unwrap() <= BATCH_WEIGHT);
                if let Some(bytes) = heap_allocated_bytes(runtime) {
                    heap_samples.push(bytes);
                }
            }

            let (status, mixed) = eval(
                runtime,
                r#"(function () {
                  var all = [];
                  var dropped = [];
                  var retained = [];
                  (function () {
                    for (var i = 0; i < 500; i++) {
                      var wrapper = __syntheticGpu.wrap(((i % 8) + 1) * 4096);
                      all.push(wrapper.id);
                      if (i % 2 === 0) retained.push(wrapper);
                      else dropped.push(wrapper.id);
                    }
                  })();
                  globalThis.__syntheticGpuRetained = retained;
                  globalThis.__syntheticGpuMixedAll = all;
                  return JSON.stringify(dropped);
                })()"#,
            );
            assert_eq!(status, 0, "mixed synthetic GPU batch failed: {mixed:?}");
            let dropped = mixed.expect("mixed dropped ids");
            poll_finalization_until(
                runtime,
                &format!("String(__syntheticGpu.allReleased({dropped}))"),
                "dropped half of mixed synthetic GPU batch did not drain",
            );
            let mixed_summary = eval(
                runtime,
                r#"JSON.stringify({
                  retainedReleased: __syntheticGpuRetained.some(function (w) {
                    return __syntheticGpu.releaseCount(w.id) !== 0;
                  }),
                  state: __syntheticGpu.summary()
                })"#,
            )
            .1
            .expect("mixed synthetic GPU summary");
            let mixed_summary: serde_json::Value =
                serde_json::from_str(&mixed_summary).expect("valid mixed GPU summary");
            assert_eq!(mixed_summary["retainedReleased"].as_bool(), Some(false));
            assert!(mixed_summary["state"]["liveCount"].as_u64().unwrap() <= BATCH_SIZE);
            assert!(mixed_summary["state"]["liveBytes"].as_u64().unwrap() <= BATCH_WEIGHT);

            assert_eq!(
                eval(runtime, "__syntheticGpuRetained = null; 'dropped-retained'")
                    .1
                    .as_deref(),
                Some("dropped-retained")
            );
            poll_finalization_until(
                runtime,
                "String(__syntheticGpu.allReleased(__syntheticGpuMixedAll))",
                "retained half of mixed synthetic GPU batch did not drain after release",
            );

            let explicit_id: u64 = eval(
                runtime,
                r#"(function () {
                  var wrapper = __syntheticGpu.wrap(65536);
                  var id = wrapper.id;
                  wrapper.dispose();
                  wrapper = null;
                  return String(id);
                })()"#,
            )
            .1
            .expect("explicitly disposed wrapper id")
            .parse()
            .expect("numeric explicitly disposed wrapper id");
            for _ in 0..8 {
                ex_hermes_gc(runtime);
                assert!(ex_hermes_poll(runtime, ex_hermes_now_ms()) >= 0);
            }
            assert_eq!(
                eval(
                    runtime,
                    &format!("String(__syntheticGpu.releaseCount({explicit_id}))"),
                )
                .1
                .as_deref(),
                Some("1"),
                "explicit dispose followed by GC must release exactly once"
            );

            let total = eval(runtime, "JSON.stringify(__syntheticGpu.summary())")
                .1
                .expect("final synthetic GPU summary");
            let total: serde_json::Value =
                serde_json::from_str(&total).expect("valid final synthetic GPU summary");
            assert_eq!(total["created"].as_u64(), Some(5_501));
            assert_eq!(total["released"], total["created"]);
            assert_eq!(total["liveCount"].as_u64(), Some(0));
            assert_eq!(total["liveBytes"].as_u64(), Some(0));

            // Secondary, deliberately non-gating evidence: the exposed Hermes
            // allocatedBytes series should settle after repeated drained waves,
            // while synthetic native count/weight above remain the hard gates.
            let _allocated_bytes_plateau_observed = heap_samples
                .windows(3)
                .any(|window| window[2] <= window[0].saturating_add(BATCH_WEIGHT));
            ex_hermes_destroy(runtime);
        }
    }

    /// Collection without a following checkpoint leaves JS cleanup pending;
    /// destroy discards it without running user code. FsHandle grants expose the
    /// currently documented host-global retained-authority residual.
    #[test]
    fn pending_js_cleanup_is_dropped_at_destroy_without_fault() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::default_legacy();
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);

        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let capable = finalization_primitives_available(runtime);
            if capable {
                let (status, value) = eval(
                    runtime,
                    r#"(function () {
                      globalThis.__destroyCleanupRan = 0;
                      globalThis.__destroyRegistry = new FinalizationRegistry(function () {
                        __destroyCleanupRan++;
                        throw new Error('cleanup must not run during destroy');
                      });
                      (function () {
                        for (var i = 0; i < 256; i++) __destroyRegistry.register({}, i);
                      })();
                      return 'registered';
                    })()"#,
                );
                assert_eq!(status, 0, "pending cleanup setup failed: {value:?}");
            }

            let (status, ids_json) = eval(
                runtime,
                r#"(function () {
                  var ids = [];
                  (function () {
                    for (var i = 0; i < 256; i++) {
                      var handle = Ibex.fs.readHandle('/tmp');
                      ids.push(handle._id);
                    }
                  })();
                  return JSON.stringify(ids);
                })()"#,
            );
            assert_eq!(status, 0, "pending FsHandle setup failed: {ids_json:?}");
            let ids: Vec<u64> =
                serde_json::from_str(ids_json.as_deref().expect("pending FsHandle ids JSON"))
                    .expect("valid pending FsHandle ids JSON");
            ex_hermes_gc(runtime);
            // Intentionally no ex_hermes_poll/eval checkpoint after collection.
            ex_hermes_destroy(runtime);

            // @ref LLP 0050#5-decision-d4--honest-teardown-contract — the
            // host-global registry has no runtime key or destroy-time sweep.
            assert!(ids
                .iter()
                .all(|id| host.handles().check(*id, "fs:read:/tmp/finalization-probe")));
        }
    }

    /// Accepted entries transfer to the owner queue; stale/invalid refusals do
    /// not. The observer uses an RAII-bearing capture so its destruction thread
    /// and whether it ever ran are executable facts.
    /// @ref LLP 0050#4-decision-d3--native-tier-contract-and-the-staleness-story
    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn push_runtime_finalizer_refusal_transfers_nothing() {
        const ACCEPTED: i32 = 0;
        const STALE: i32 = 1;
        const INVALID: i32 = 2;
        const GOOD: u32 = 0;
        const THROWING: u32 = 1;
        const EMPTY: u32 = 2;

        let _host_guard = crate::host::abi::host_test_lock();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        unsafe {
            ibex_test_reset_runtime_finalizer_observer();
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            assert_eq!(ibex_test_capture_runtime_finalizer_target(runtime), 1);

            assert_eq!(ibex_test_push_captured_runtime_finalizer(GOOD), ACCEPTED);
            assert_eq!(ibex_test_runtime_finalizer_run_count(), 0);
            assert!(ex_hermes_poll(runtime, ex_hermes_now_ms()) >= 0);
            assert_eq!(ibex_test_runtime_finalizer_run_count(), 1);
            assert_eq!(ibex_test_runtime_finalizer_good_run_count(), 1);
            assert_eq!(ibex_test_runtime_finalizer_ran_on_owner_thread(), 1);

            assert_eq!(
                ibex_test_push_captured_runtime_finalizer(THROWING),
                ACCEPTED
            );
            assert_eq!(ibex_test_push_captured_runtime_finalizer(GOOD), ACCEPTED);
            assert!(ex_hermes_poll(runtime, ex_hermes_now_ms()) >= 0);
            assert_eq!(ibex_test_runtime_finalizer_run_count(), 3);
            assert_eq!(
                ibex_test_runtime_finalizer_good_run_count(),
                2,
                "a throwing finalizer must not strand the following good entry"
            );
            assert_eq!(
                ibex_test_runtime_finalizer_logged_failure_count(),
                1,
                "the throwing finalizer must be logged exactly once"
            );

            assert_eq!(
                ibex_test_push_captured_runtime_finalizer(EMPTY),
                INVALID,
                "an empty finalizer is malformed, not stale"
            );
            assert_eq!(ibex_test_runtime_finalizer_destroyed_without_run_count(), 0);
            ex_hermes_destroy(runtime);
        }

        let stale_result =
            std::thread::spawn(|| unsafe { ibex_test_push_captured_runtime_finalizer(GOOD) })
                .join()
                .expect("stale finalizer producer thread");
        assert_eq!(stale_result, STALE);
        unsafe {
            assert_eq!(ibex_test_runtime_finalizer_run_count(), 3);
            assert_eq!(ibex_test_runtime_finalizer_destroyed_without_run_count(), 1);
            assert_eq!(
                ibex_test_runtime_finalizer_refusal_destroyed_on_producer_thread(),
                1,
                "stale refusal must leave capture destruction with its producer"
            );
        }
    }

    /// Weak intrinsic identities are shared by package compartments, so the
    /// lockdown root walk must freeze both constructors and prototypes.
    #[test]
    fn lockdown_freezes_weak_intrinsics_and_blocks_cross_package_mutation() {
        let _host_guard = crate::host::abi::host_test_lock();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );

        unsafe {
            let previous_compartments = std::env::var_os("IBEX_COMPARTMENTS");
            std::env::set_var("IBEX_COMPARTMENTS", "1");
            let runtime = ex_hermes_create_diagnostic();
            match previous_compartments {
                Some(value) => std::env::set_var("IBEX_COMPARTMENTS", value),
                None => std::env::remove_var("IBEX_COMPARTMENTS"),
            }
            assert!(!runtime.is_null());
            if !finalization_primitives_available(runtime) {
                ex_hermes_destroy(runtime);
                return;
            }
            let (status, value) = eval(
                runtime,
                r#"(function () {
                  var packageA = __compartments['finalization-package-a'];
                  var packageB = __compartments['finalization-package-b'];
                  function mutationBlocked(owner, observer, key) {
                    var threw = false;
                    try {
                      (function () { 'use strict'; owner.prototype[key] = 1; })();
                    } catch (_) {
                      threw = true;
                    }
                    return threw && !Object.prototype.hasOwnProperty.call(observer.prototype, key);
                  }
                  return JSON.stringify({
                    weakRefConstructorFrozen: Object.isFrozen(WeakRef),
                    weakRefPrototypeFrozen: Object.isFrozen(WeakRef.prototype),
                    registryConstructorFrozen: Object.isFrozen(FinalizationRegistry),
                    registryPrototypeFrozen: Object.isFrozen(FinalizationRegistry.prototype),
                    weakRefShared: packageA.WeakRef === packageB.WeakRef,
                    registryShared: packageA.FinalizationRegistry === packageB.FinalizationRegistry,
                    weakRefMutationBlocked: mutationBlocked(
                      packageA.WeakRef, packageB.WeakRef, '__ibexCrossPackageWeakRefMutation'),
                    registryMutationBlocked: mutationBlocked(
                      packageA.FinalizationRegistry,
                      packageB.FinalizationRegistry,
                      '__ibexCrossPackageFinalizationRegistryMutation')
                  });
                })()"#,
            );
            assert_eq!(status, 0, "weak intrinsic lockdown probe failed: {value:?}");
            let value: serde_json::Value =
                serde_json::from_str(value.as_deref().expect("weak intrinsic lockdown JSON"))
                    .expect("valid weak intrinsic lockdown JSON");
            for key in [
                "weakRefConstructorFrozen",
                "weakRefPrototypeFrozen",
                "registryConstructorFrozen",
                "registryPrototypeFrozen",
                "weakRefShared",
                "registryShared",
                "weakRefMutationBlocked",
                "registryMutationBlocked",
            ] {
                assert_eq!(
                    value[key].as_bool(),
                    Some(true),
                    "failed lockdown check {key}"
                );
            }
            ex_hermes_destroy(runtime);
        }
    }

    /// The pinned Hermes runtime owns the weak reachability semantics. Dropping
    /// wrappers must reclaim their native HandleRegistry entries while the
    /// realm remains alive; destroying the realm would only prove teardown.
    #[test]
    fn native_finalization_registry_reclaims_dropped_fs_handles_in_a_persistent_runtime() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::default_legacy();
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);

        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let (status, registry_kind) = eval(runtime, "typeof FinalizationRegistry");
            assert_eq!(status, 0, "FinalizationRegistry capability probe failed");
            if registry_kind.as_deref() != Some("function") {
                #[cfg(ibex_hermes_finalization_capable)]
                panic!(
                    "authenticated finalization-capable Hermes profile lacks FinalizationRegistry"
                );
                #[cfg(not(ibex_hermes_finalization_capable))]
                {
                    assert_eq!(
                        eval(runtime, "'persistent-runtime-without-finalization'")
                            .1
                            .as_deref(),
                        Some("persistent-runtime-without-finalization")
                    );
                    ex_hermes_destroy(runtime);
                    return;
                }
            }

            let (status, ids_json) = eval(
                runtime,
                r#"(function () {
                  globalThis.__nativeRevokeHandle = __exactRevokeHandle;
                  globalThis.__finalizationRevokeCount = 0;
                  globalThis.__exactRevokeHandle = function (id) {
                    globalThis.__finalizationRevokeCount++;
                    return globalThis.__nativeRevokeHandle(id);
                  };
                  var ids = [];
                  for (var i = 0; i < 2000; i++) {
                    var handle = Ibex.fs.readHandle('/tmp');
                    ids.push(handle._id);
                  }
                  handle = null;
                  globalThis.__finalizationProbeIds = ids;
                  globalThis.__finalizationPressure = new Uint8Array(8 * 1024 * 1024);
                  globalThis.__finalizationPressure = null;
                  return JSON.stringify(ids);
                })()"#,
            );
            assert_eq!(status, 0, "handle allocation failed: {ids_json:?}");
            let ids: Vec<u64> = serde_json::from_str(
                ids_json
                    .as_deref()
                    .expect("handle allocation must return its numeric ids"),
            )
            .expect("handle ids must be valid JSON integers");
            assert_eq!(ids.len(), 2000);

            for _ in 0..64 {
                ex_hermes_gc(runtime);
                assert!(
                    ex_hermes_poll(runtime, ex_hermes_now_ms()) >= 0,
                    "FinalizationRegistry cleanup must not make polling fatal"
                );
                if ids
                    .iter()
                    .all(|id| !host.handles().check(*id, "fs:read:/tmp/finalization-probe"))
                {
                    break;
                }
            }

            let unreclaimed = ids
                .iter()
                .filter(|id| {
                    host.handles()
                        .check(**id, "fs:read:/tmp/finalization-probe")
                })
                .count();
            assert_eq!(
                unreclaimed, 0,
                "native finalization left {unreclaimed} of 2000 HandleRegistry entries live"
            );
            let finalized: usize = eval(runtime, "String(__finalizationRevokeCount)")
                .1
                .expect("finalizer count")
                .parse()
                .expect("finalizer count must be numeric");
            assert_eq!(
                finalized, 2000,
                "every dropped wrapper must reach the native cleanup callback exactly once"
            );
            assert_eq!(
                eval(
                    runtime,
                    "globalThis.__exactRevokeHandle = globalThis.__nativeRevokeHandle; 'restored'",
                )
                .1
                .as_deref(),
                Some("restored")
            );
            assert_eq!(
                eval(runtime, "'persistent-runtime-still-live'")
                    .1
                    .as_deref(),
                Some("persistent-runtime-still-live"),
                "reclamation must complete before runtime teardown"
            );
            ex_hermes_destroy(runtime);
        }
    }

    /// Engines without the primitive stay honest: evaluating the authored
    /// compatibility source must not manufacture a strong-retaining registry.
    /// Cleanup in that profile is deterministic explicit disposal, not a fake
    /// garbage-collection signal.
    #[test]
    fn compat_and_fs_handle_sources_leave_finalization_absent_and_explicit_revoke_reclaims() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::default_legacy();
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);

        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let (status, forced) = eval(
                runtime,
                r#"Object.defineProperty(globalThis, 'FinalizationRegistry', {
                  value: undefined,
                  writable: true,
                  enumerable: false,
                  configurable: true
                });
                typeof FinalizationRegistry"#,
            );
            assert_eq!((status, forced.as_deref()), (0, Some("undefined")));

            let compat_source = include_str!("bootstrap/compat-polyfills.js");
            let (status, error) = eval(runtime, compat_source);
            assert_eq!(status, 0, "actual compatibility source failed: {error:?}");
            assert_eq!(
                eval(runtime, "typeof FinalizationRegistry").1.as_deref(),
                Some("undefined"),
                "compatibility bootstrap must leave FinalizationRegistry absent"
            );

            let fs_handle_source = authored_fs_handle_install_source();
            let (status, error) = eval(runtime, fs_handle_source);
            assert_eq!(
                status, 0,
                "actual kFsHandleJS source failed with the intrinsic absent: {error:?}"
            );
            assert_eq!(
                eval(runtime, "typeof FinalizationRegistry").1.as_deref(),
                Some("undefined"),
                "actual FsHandle installation must not synthesize a finalizer"
            );

            let (status, handle_id) = eval(
                runtime,
                "globalThis.__absentFsHandle = Ibex.fs.readHandle('/tmp'); String(__absentFsHandle._id)",
            );
            assert_eq!(
                status, 0,
                "actual FsHandle construction failed: {handle_id:?}"
            );
            let id: u64 = handle_id
                .expect("actual FsHandle must expose its numeric native id")
                .parse()
                .expect("actual FsHandle id must be numeric");
            assert!(
                host.handles().check(id, "fs:read:/tmp/finalization-probe"),
                "actual FsHandle construction must mint a live native grant"
            );
            assert_eq!(
                eval(
                    runtime,
                    "__absentFsHandle.revoke(); __absentFsHandle = null; 'revoked'",
                )
                .1
                .as_deref(),
                Some("revoked"),
                "actual FsHandle.prototype.revoke must remain the absence fallback"
            );
            assert!(
                !host.handles().check(id, "fs:read:/tmp/finalization-probe"),
                "explicit revoke must reclaim the native HandleRegistry entry"
            );
            assert_eq!(
                eval(runtime, "'absence-runtime-still-live'").1.as_deref(),
                Some("absence-runtime-still-live")
            );
            ex_hermes_destroy(runtime);
        }
    }

    fn legacy_hermes_block_scoping_requested() -> bool {
        std::env::var("IBEX_LEGACY_HERMES_BLOCK_SCOPING")
            .ok()
            .is_some_and(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
    }

    /// @ref LLP 0034#verification-gates — app-runtime source evaluation uses
    /// the default per-iteration lexical semantics. Structural lockdown tames
    /// both eval and the Function constructor separately, so neither is a
    /// production compilation surface to gate.
    #[test]
    fn main_runtime_enables_es6_block_scoping_for_source_compilation() {
        if legacy_hermes_block_scoping_requested() {
            return;
        }
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let collect = r#"
function collect() {
  const callbacks = [];
  for (const item of ["a", "b"]) callbacks.push(() => item);
  return callbacks.map(callback => callback());
}
"#;
            let source = format!("{collect} JSON.stringify(collect())");
            let (status, value) = eval(runtime, &source);
            assert_eq!(status, 0, "runtime evaluation failed: {value:?}");
            assert_eq!(value.as_deref(), Some(r#"["a","b"]"#));
            ex_hermes_destroy(runtime);
        }
    }

    /// @ref LLP 0034#verification-gates — the persistent UI worklet runtime
    /// compiles installed source with the same lexical mode as the app runtime.
    #[test]
    fn worklet_runtime_enables_es6_block_scoping_for_source_compilation() {
        if legacy_hermes_block_scoping_requested() {
            return;
        }
        unsafe {
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());
            ex_worklet_set_generation(runtime, 1);
            let id = CString::new("block-scoping").expect("worklet id");
            install_worklet(
                runtime,
                &id,
                r#"(function () {
  const callbacks = [];
  for (const item of ["a", "b"]) callbacks.push(() => item);
  return function () { return callbacks.map(callback => callback()).join(","); };
})()"#,
                1,
            );
            assert_eq!(invoke_worklet(runtime, &id), r#""a,b""#);
            ex_worklet_destroy(runtime);
        }
    }

    unsafe fn structured_eval(
        runtime: *mut HermesRuntimeOpaque,
        source: &[u8],
    ) -> StructuredEvaluationResult {
        let mut result = std::mem::MaybeUninit::<StructuredEvaluationResult>::uninit();
        ex_hermes_evaluation_result_init(result.as_mut_ptr());
        let mut result = result.assume_init();
        let label = b"ibex:structured-test";
        let source_pointer = if source.is_empty() {
            std::ptr::null()
        } else {
            source.as_ptr()
        };
        assert_eq!(
            ex_hermes_eval_structured_diagnostic(
                runtime,
                source_pointer,
                source.len(),
                label.as_ptr(),
                label.len(),
                &mut result,
            ),
            0
        );
        result
    }

    #[test]
    fn structured_diagnostic_result_mirror_matches_v2_error_class_layout() {
        assert_eq!(
            std::mem::offset_of!(StructuredEvaluationResult, throw_error_class),
            48
        );
        assert_eq!(
            std::mem::offset_of!(StructuredEvaluationResult, lifecycle_exit_code),
            52
        );
        assert_eq!(
            std::mem::offset_of!(StructuredEvaluationResult, capability_flags),
            56
        );
        if cfg!(target_pointer_width = "64") {
            assert_eq!(std::mem::size_of::<StructuredEvaluationResult>(), 112);
        }
    }

    /// Restricted worklets must cross the SharedValue boundary with the full
    /// typed identity. Stale identities are host-rejected no-ops, and values
    /// that cannot be represented as finite f32 never reach the host callback.
    #[test]
    fn worklet_shared_values_use_validating_typed_accessors() {
        unsafe {
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());

            let mut host = Box::new(SharedValueHost {
                expected: WorkletSharedValueHandle {
                    slot: 2,
                    generation: 7,
                    epoch: 3,
                },
                value: 41.0,
                reads: 0,
                writes: 0,
                rejected_reads: 0,
                rejected_writes: 0,
            });
            let context = (&mut *host as *mut SharedValueHost).cast::<c_void>();
            assert_eq!(
                ex_worklet_bind_shared_value_accessors(
                    runtime,
                    Some(read_shared_value),
                    Some(write_shared_value),
                    context,
                ),
                0
            );
            ex_worklet_set_generation(runtime, 1);

            let live_id = CString::new("typed-live").expect("worklet id");
            install_worklet(
                runtime,
                &live_id,
                "(function () { var s = worklet.sharedValue(2, 7, 3); s.set(s.get() + 1); return s.get(); })",
                1,
            );
            assert_eq!(invoke_worklet(runtime, &live_id), "42");
            assert_eq!(host.value, 42.0);
            assert_eq!((host.reads, host.writes), (2, 1));

            let stale_id = CString::new("typed-stale").expect("worklet id");
            install_worklet(
                runtime,
                &stale_id,
                "(function () { var s = worklet.sharedValue(2, 8, 3); s.set(99); return s.get() === undefined; })",
                1,
            );
            assert_eq!(invoke_worklet(runtime, &stale_id), "true");
            assert_eq!(host.value, 42.0, "stale write must be a no-op");
            assert_eq!((host.rejected_reads, host.rejected_writes), (1, 1));

            // A durable handle keeps its last successfully observed value
            // when the host later rejects that same typed identity. The raw
            // accessor still fails closed; only the language handle owns the
            // stale shadow required by LLP 0099 M1.
            let shadow_id = CString::new("typed-stale-shadow").expect("worklet id");
            install_worklet(
                runtime,
                &shadow_id,
                "(function () { var s = worklet.sharedValue(2, 7, 3); return function () { return s.get(); }; })()",
                1,
            );
            assert_eq!(invoke_worklet(runtime, &shadow_id), "42");
            host.expected.generation = 8;
            assert_eq!(invoke_worklet(runtime, &shadow_id), "42");
            assert_eq!(host.rejected_reads, 2);
            host.expected.generation = 7;

            let non_finite_id = CString::new("typed-non-finite").expect("worklet id");
            install_worklet(
                runtime,
                &non_finite_id,
                "(function () { worklet.sharedValue(2, 7, 3).set(Infinity); return 1; })",
                1,
            );
            assert_eq!(invoke_worklet(runtime, &non_finite_id), "1");
            assert_eq!(host.writes, 1, "non-finite value must not reach the host");
            assert_eq!(host.value, 42.0);

            assert_eq!(
                ex_worklet_bind_shared_value_accessors(runtime, None, None, std::ptr::null_mut(),),
                0
            );
            ex_worklet_destroy(runtime);
        }
    }

    /// LLP 0099 M6: the hot Motion worklet ABI is fixed f32 slots, captures
    /// are install-time scalars or full SharedValue identities, unchanged
    /// artifacts retain a stable callback identity, and runOnJS uses a
    /// bounded drop-oldest ring drained on the app runtime.
    #[test]
    fn motion_worklet_typed_abi_captures_and_run_on_js_are_bounded() {
        unsafe {
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());
            let mut host = Box::new(SharedValueHost {
                expected: WorkletSharedValueHandle {
                    slot: 3,
                    generation: 9,
                    epoch: 4,
                },
                value: 41.0,
                reads: 0,
                writes: 0,
                rejected_reads: 0,
                rejected_writes: 0,
            });
            let context = (&mut *host as *mut SharedValueHost).cast::<c_void>();
            assert_eq!(
                ex_worklet_bind_shared_value_accessors(
                    runtime,
                    Some(read_shared_value),
                    Some(write_shared_value),
                    context,
                ),
                0
            );
            ex_worklet_set_generation(runtime, 7);
            let captures = [
                WorkletCapture {
                    kind: WORKLET_CAPTURE_F32,
                    scalar: 2.0,
                    shared_value: WorkletSharedValueHandle {
                        slot: 0,
                        generation: 0,
                        epoch: 0,
                    },
                },
                WorkletCapture {
                    kind: WORKLET_CAPTURE_BOOL,
                    scalar: 1.0,
                    shared_value: WorkletSharedValueHandle {
                        slot: 0,
                        generation: 0,
                        epoch: 0,
                    },
                },
                WorkletCapture {
                    kind: WORKLET_CAPTURE_SHARED_VALUE,
                    scalar: 0.0,
                    shared_value: host.expected,
                },
            ];
            let source = r#"(function (input) {
              var shared = worklet.captureGet(2);
              worklet.output(0, input * worklet.capture(0));
              worklet.output(1, shared);
              worklet.output(2, worklet.capture(1) ? 1 : 0);
              worklet.captureSet(2, shared + 1);
              worklet.runOnJS(77, input, shared);
            })"#;
            let identity = install_typed_worklet(runtime, source, &captures, 7);
            assert_eq!(
                install_typed_worklet(runtime, source, &captures, 7),
                identity,
                "content + capture identity must be stable across re-renders"
            );

            let mut output = [f32::NAN; 3];
            let input = [3.0_f32];
            let mut output_count = 0;
            assert_eq!(
                ex_worklet_invoke_typed(
                    runtime,
                    identity,
                    input.as_ptr(),
                    input.len() as u32,
                    output.as_mut_ptr(),
                    output.len() as u32,
                    &mut output_count,
                ),
                0
            );
            assert_eq!(output_count, 3);
            assert_eq!(output, [6.0, 41.0, 1.0]);
            assert_eq!(host.value, 42.0);

            // The install-time SharedValue capture owns the same stale shadow
            // contract as worklet.sharedValue(...). A host-rejected handle
            // reads its last observed value and rejects the write.
            host.expected.generation = 10;
            assert_eq!(
                ex_worklet_invoke_typed(
                    runtime,
                    identity,
                    input.as_ptr(),
                    1,
                    output.as_mut_ptr(),
                    3,
                    &mut output_count,
                ),
                0
            );
            assert_eq!(output[1], 42.0);
            assert_eq!(host.rejected_reads, 1);
            assert_eq!(host.rejected_writes, 1);
            host.expected.generation = 9;

            // Fill past the fixed ring. The oldest four calls are evicted;
            // per-source sequence remains monotonic and makes the gap clear.
            for _ in 0..254 {
                assert_eq!(
                    ex_worklet_invoke_typed(
                        runtime,
                        identity,
                        input.as_ptr(),
                        1,
                        output.as_mut_ptr(),
                        3,
                        &mut output_count,
                    ),
                    0
                );
            }
            let mut calls = [WorkletScheduledCall::default(); 256];
            assert_eq!(
                ex_worklet_drain_scheduled_typed(runtime, calls.as_mut_ptr(), 256),
                256
            );
            assert_eq!(ex_worklet_take_scheduled_drop_count(runtime), 0);
            // Two calls occurred before the 254-fill loop: the stale-shadow
            // invocation is still a valid runOnJS enqueue, so capacity is
            // reached exactly without a drop.
            assert_eq!(calls[0].source_sequence, 1);
            assert_eq!(calls[255].source_sequence, 256);
            assert!(calls.iter().all(|call| {
                call.source_identity == identity
                    && call.generation == 7
                    && call.callback_identity == 77
                    && call.argument_count == 2
            }));
            for _ in 0..260 {
                assert_eq!(
                    ex_worklet_invoke_typed(
                        runtime,
                        identity,
                        input.as_ptr(),
                        1,
                        output.as_mut_ptr(),
                        3,
                        &mut output_count,
                    ),
                    0
                );
            }
            assert_eq!(
                ex_worklet_drain_scheduled_typed(runtime, calls.as_mut_ptr(), 256),
                256
            );
            assert_eq!(ex_worklet_take_scheduled_drop_count(runtime), 4);
            assert_eq!(calls[0].source_sequence, 261);
            assert_eq!(calls[255].source_sequence, 516);

            let app = ex_hermes_create_diagnostic();
            assert!(!app.is_null());
            assert_eq!(
                eval(
                    app,
                    "globalThis.__runOnJSSeen=[]; globalThis.__exactRunOnJS=function(id,meta,a,b){ __runOnJSSeen.push([id,meta.sourceSequence,a,b]); }; 'ready'",
                )
                .0,
                0
            );
            let mut delivered = 0;
            assert_eq!(
                ex_hermes_dispatch_worklet_calls(
                    app,
                    calls.as_ptr(),
                    calls.len() as u32,
                    &mut delivered,
                ),
                0
            );
            assert_eq!(delivered, 256);
            assert_eq!(
                eval(
                    app,
                    "JSON.stringify([__runOnJSSeen.length,__runOnJSSeen[0],__runOnJSSeen[255]])",
                )
                .1
                .as_deref(),
                Some("[256,[77,\"261\",3,300],[77,\"516\",3,555]]")
            );

            let mut metrics = WorkletInstallMetrics::default();
            assert_eq!(ex_worklet_install_metrics(runtime, &mut metrics), 0);
            assert_eq!(metrics.source_install_count, 1);
            assert_eq!(metrics.reused_install_count, 1);
            assert!(metrics.source_install_total_ns > 0);
            assert!(metrics.source_install_max_ns > 0);

            ex_hermes_destroy(app);
            assert_eq!(
                ex_worklet_bind_shared_value_accessors(runtime, None, None, std::ptr::null_mut(),),
                0
            );
            ex_worklet_destroy(runtime);
        }
    }

    /// The source-install choice is deliberate for M6: the shipped build
    /// plugin already emits function-expression source, and warm installs
    /// must remain immaterial beside the 1ms per-frame execution budget.
    #[test]
    fn motion_worklet_source_install_p95_is_measured() {
        unsafe {
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());
            ex_worklet_set_generation(runtime, 1);
            let mut samples = Vec::new();
            for index in 0..64_u32 {
                let source =
                    format!("(function (value) {{ worklet.output(0, value + {index}); }})");
                let started = std::time::Instant::now();
                let _ = install_typed_worklet(runtime, &source, &[], 1);
                samples.push(started.elapsed().as_nanos() as u64);
            }
            samples.sort_unstable();
            let p50 = samples[samples.len() / 2];
            let p95 = samples[(samples.len() * 95 / 100).min(samples.len() - 1)];
            eprintln!(
                "M6 source install: p50={:.3}ms p95={:.3}ms",
                p50 as f64 / 1_000_000.0,
                p95 as f64 / 1_000_000.0,
            );
            assert!(
                p95 < 5_000_000,
                "warm source install p95 must stay below the 5ms mount-time ceiling"
            );
            ex_worklet_destroy(runtime);
        }
    }

    #[test]
    fn legacy_unarmed_constructor_is_non_executable() {
        unsafe {
            assert!(ex_hermes_create().is_null());
        }
    }

    #[test]
    fn runtime_drive_gate_refuses_off_owner_and_preserves_the_generation() {
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let nonce = ex_hermes_runtime_nonce(runtime);
            assert_ne!(nonce, 0);
            let address = runtime as usize;
            let (poll_status, destroy_status) = std::thread::spawn(move || {
                let runtime = address as *mut HermesRuntimeOpaque;
                (
                    ex_hermes_poll(runtime, 0),
                    ex_hermes_try_destroy(runtime, nonce),
                )
            })
            .join()
            .unwrap();
            assert_eq!(poll_status, -3);
            assert_eq!(destroy_status, -3);
            assert_eq!(ex_hermes_runtime_nonce(runtime), nonce);
            assert_eq!(ex_hermes_poll(runtime, ex_hermes_now_ms()), 0);
            assert_eq!(ex_hermes_try_destroy(runtime, nonce), 0);
        }
    }

    #[test]
    fn runtime_drive_gate_returns_stale_eval_contract_after_destroy() {
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let nonce = ex_hermes_runtime_nonce(runtime);
            assert_ne!(nonce, 0);
            assert_eq!(ex_hermes_try_destroy(runtime, nonce), 0);

            let (status, message) = eval(runtime, "'must-not-run'");
            assert_eq!(status, -2);
            assert_eq!(
                message.as_deref(),
                Some("Hermes eval refused by the runtime drive gate")
            );
        }
    }

    #[test]
    fn public_eval_gate_has_no_pre_guard_runtime_dereference() {
        let source = include_str!("hermes_runtime.cc");
        let public_eval = source
            .split_once("extern \"C\" int ex_hermes_eval(")
            .expect("public eval definition")
            .1
            .split_once("int exactHermesBootstrapEval(")
            .expect("private bootstrap evaluator follows public eval")
            .0;
        let guard = public_eval
            .find("ExactRuntimeDriveGuard drive(runtime);")
            .expect("public eval drive guard");
        let dispatch = public_eval
            .find("return evalRuntimeUnchecked(")
            .expect("guarded eval implementation dispatch");
        assert!(guard < dispatch);
        assert!(
            !public_eval.contains("runtime->"),
            "the public wrapper must not inspect a caller runtime pointer before or after refusal"
        );
        assert!(
            !public_eval.contains("bootstrap_in_progress"),
            "the unpublished bootstrap exception belongs only to the private construction helper"
        );
    }

    static REENTRANT_RUNTIME: std::sync::atomic::AtomicPtr<HermesRuntimeOpaque> =
        std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
    static REENTRANT_STATUS: std::sync::atomic::AtomicI32 =
        std::sync::atomic::AtomicI32::new(i32::MIN);
    static REENTRANT_STRUCTURED_FAULT: std::sync::atomic::AtomicU32 =
        std::sync::atomic::AtomicU32::new(u32::MAX);
    static REENTRANT_GC_STATS_NULL: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static NESTED_OTHER_RUNTIME: std::sync::atomic::AtomicPtr<HermesRuntimeOpaque> =
        std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
    static NESTED_OTHER_STATUS: std::sync::atomic::AtomicI32 =
        std::sync::atomic::AtomicI32::new(i32::MIN);

    extern "C" fn poll_from_host_call(
        _operation: *const c_char,
        _arguments_json: *const c_char,
    ) -> *mut c_char {
        let runtime = REENTRANT_RUNTIME.load(std::sync::atomic::Ordering::Acquire);
        let status = unsafe { ex_hermes_poll(runtime, 0) };
        REENTRANT_STATUS.store(status, std::sync::atomic::Ordering::Release);
        let mut structured = std::mem::MaybeUninit::<StructuredEvaluationResult>::uninit();
        unsafe { ex_hermes_evaluation_result_init(structured.as_mut_ptr()) };
        let mut structured = unsafe { structured.assume_init() };
        let source = b"'nested'";
        let label = b"ibex:reentrant-test";
        assert_eq!(
            unsafe {
                ex_hermes_eval_structured_diagnostic(
                    runtime,
                    source.as_ptr(),
                    source.len(),
                    label.as_ptr(),
                    label.len(),
                    &mut structured,
                )
            },
            0
        );
        REENTRANT_STRUCTURED_FAULT.store(structured.fault, std::sync::atomic::Ordering::Release);
        unsafe { ex_hermes_evaluation_result_dispose(&mut structured) };
        let gc_stats = unsafe { ex_hermes_get_gc_stats(runtime) };
        REENTRANT_GC_STATS_NULL.store(gc_stats.is_null(), std::sync::atomic::Ordering::Release);
        if !gc_stats.is_null() {
            unsafe { ex_hermes_free_string(gc_stats) };
        }
        let payload = b"+null\0";
        let result = unsafe { libc::malloc(payload.len()).cast::<u8>() };
        assert!(!result.is_null());
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), result, payload.len()) };
        result.cast()
    }

    extern "C" fn poll_other_runtime_from_host_call(
        _operation: *const c_char,
        _arguments_json: *const c_char,
    ) -> *mut c_char {
        let runtime = NESTED_OTHER_RUNTIME.load(std::sync::atomic::Ordering::Acquire);
        let status = unsafe { ex_hermes_poll(runtime, ex_hermes_now_ms()) };
        NESTED_OTHER_STATUS.store(status, std::sync::atomic::Ordering::Release);
        let payload = b"+null\0";
        let result = unsafe { libc::malloc(payload.len()).cast::<u8>() };
        assert!(!result.is_null());
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), result, payload.len()) };
        result.cast()
    }

    #[cfg(feature = "capsec-conformance-observer")]
    const OUTER_MODULE_SENTINEL: u64 = 4_242;
    #[cfg(feature = "capsec-conformance-observer")]
    const OUTER_NATIVE_SENTINEL: u64 = 4_343;
    #[cfg(feature = "capsec-conformance-observer")]
    const OUTER_TYPED_SENTINELS: [u64; 2] = [4_444, 4_545];
    #[cfg(feature = "capsec-conformance-observer")]
    static NESTED_INNER_TLS_MASK: std::sync::atomic::AtomicU32 =
        std::sync::atomic::AtomicU32::new(u32::MAX);
    #[cfg(feature = "capsec-conformance-observer")]
    static NESTED_INNER_ACTIVE_NONCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    #[cfg(feature = "capsec-conformance-observer")]
    extern "C" fn observe_nested_inner_principal_scope(
        _operation: *const c_char,
        _arguments_json: *const c_char,
    ) -> *mut c_char {
        let mask = unsafe {
            ibex_test_forbidden_principal_tls_mask(
                OUTER_MODULE_SENTINEL,
                OUTER_NATIVE_SENTINEL,
                OUTER_TYPED_SENTINELS.as_ptr(),
                OUTER_TYPED_SENTINELS.len(),
            )
        };
        NESTED_INNER_TLS_MASK.store(mask, std::sync::atomic::Ordering::Release);
        NESTED_INNER_ACTIVE_NONCE.store(
            unsafe { ex_hermes_current_runtime_nonce() },
            std::sync::atomic::Ordering::Release,
        );
        let payload = b"+null\0";
        let result = unsafe { libc::malloc(payload.len()).cast::<u8>() };
        if result.is_null() {
            return std::ptr::null_mut();
        }
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), result, payload.len()) };
        result.cast()
    }

    #[cfg(feature = "capsec-conformance-observer")]
    extern "C" fn evaluate_nested_inner_runtime(_context: *mut c_void) -> i32 {
        let runtime = NESTED_OTHER_RUNTIME.load(std::sync::atomic::Ordering::Acquire);
        let (status, value) = eval(
            runtime,
            "__hostCall('observe-inner-principal-scope', null); 'inner-survived'",
        );
        if status == 0 && value.as_deref() == Some("inner-survived") {
            0
        } else {
            status.checked_sub(100).unwrap_or(i32::MIN + 1)
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    extern "C" fn drive_other_runtime_with_foreign_principal_scope(
        _operation: *const c_char,
        _arguments_json: *const c_char,
    ) -> *mut c_char {
        let status = unsafe {
            ibex_test_with_principal_tls_scope(
                OUTER_MODULE_SENTINEL,
                OUTER_NATIVE_SENTINEL,
                OUTER_TYPED_SENTINELS.as_ptr(),
                OUTER_TYPED_SENTINELS.len(),
                evaluate_nested_inner_runtime,
                std::ptr::null_mut(),
            )
        };
        NESTED_OTHER_STATUS.store(status, std::sync::atomic::Ordering::Release);
        let payload = b"+null\0";
        let result = unsafe { libc::malloc(payload.len()).cast::<u8>() };
        if result.is_null() {
            return std::ptr::null_mut();
        }
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), result, payload.len()) };
        result.cast()
    }

    #[test]
    fn runtime_drive_gate_refuses_same_runtime_reentry() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            REENTRANT_RUNTIME.store(runtime, std::sync::atomic::Ordering::Release);
            REENTRANT_STATUS.store(i32::MIN, std::sync::atomic::Ordering::Release);
            REENTRANT_STRUCTURED_FAULT.store(u32::MAX, std::sync::atomic::Ordering::Release);
            REENTRANT_GC_STATS_NULL.store(false, std::sync::atomic::Ordering::Release);
            ex_hermes_set_host_call(runtime, poll_from_host_call);

            let (status, value) = eval(runtime, "__hostCall('reenter', null); 'survived'");
            assert_eq!(status, 0, "outer eval failed: {value:?}");
            assert_eq!(value.as_deref(), Some("survived"));
            assert_eq!(
                REENTRANT_STATUS.load(std::sync::atomic::Ordering::Acquire),
                -4,
                "the nested drive must be refused as reentrant"
            );
            assert_eq!(
                REENTRANT_STRUCTURED_FAULT.load(std::sync::atomic::Ordering::Acquire),
                FAULT_EVALUATION_IN_FLIGHT,
                "nested structured evaluation must report the typed reentrancy fault"
            );
            assert!(
                REENTRANT_GC_STATS_NULL.load(std::sync::atomic::Ordering::Acquire),
                "nested GC inspection must fail closed without touching JSI"
            );
            assert_eq!(ex_hermes_poll(runtime, ex_hermes_now_ms()), 0);

            REENTRANT_RUNTIME.store(std::ptr::null_mut(), std::sync::atomic::Ordering::Release);
            ex_hermes_destroy(runtime);
        }
    }

    #[test]
    fn runtime_drive_gate_allows_same_thread_different_runtime_nesting() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let outer = ex_hermes_create_diagnostic();
            let inner = ex_hermes_create_diagnostic();
            assert!(!outer.is_null());
            assert!(!inner.is_null());
            NESTED_OTHER_RUNTIME.store(inner, std::sync::atomic::Ordering::Release);
            NESTED_OTHER_STATUS.store(i32::MIN, std::sync::atomic::Ordering::Release);
            ex_hermes_set_host_call(outer, poll_other_runtime_from_host_call);

            let (status, value) = eval(outer, "__hostCall('nested-other', null); 'outer-survived'");
            assert_eq!(status, 0, "outer eval failed: {value:?}");
            assert_eq!(value.as_deref(), Some("outer-survived"));
            assert_eq!(
                NESTED_OTHER_STATUS.load(std::sync::atomic::Ordering::Acquire),
                0,
                "a different runtime owned by this thread may be driven while the outer runtime is active"
            );
            assert_eq!(ex_hermes_poll(outer, ex_hermes_now_ms()), 0);
            assert_eq!(ex_hermes_poll(inner, ex_hermes_now_ms()), 0);

            NESTED_OTHER_RUNTIME.store(std::ptr::null_mut(), std::sync::atomic::Ordering::Release);
            ex_hermes_destroy(inner);
            ex_hermes_destroy(outer);
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn nested_runtime_drive_isolates_and_restores_principal_tls() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let outer = ex_hermes_create_diagnostic();
            let inner = ex_hermes_create_diagnostic();
            assert!(!outer.is_null());
            assert!(!inner.is_null());
            let inner_nonce = ex_hermes_runtime_nonce(inner);
            assert_ne!(inner_nonce, 0);

            NESTED_OTHER_RUNTIME.store(inner, std::sync::atomic::Ordering::Release);
            NESTED_OTHER_STATUS.store(i32::MIN, std::sync::atomic::Ordering::Release);
            NESTED_INNER_TLS_MASK.store(u32::MAX, std::sync::atomic::Ordering::Release);
            NESTED_INNER_ACTIVE_NONCE.store(0, std::sync::atomic::Ordering::Release);
            ex_hermes_set_host_call(inner, observe_nested_inner_principal_scope);
            ex_hermes_set_host_call(outer, drive_other_runtime_with_foreign_principal_scope);

            let (status, value) = eval(
                outer,
                "__hostCall('nested-principal-isolation', null); 'outer-survived'",
            );
            assert_eq!(status, 0, "outer eval failed: {value:?}");
            assert_eq!(value.as_deref(), Some("outer-survived"));
            assert_eq!(
                NESTED_OTHER_STATUS.load(std::sync::atomic::Ordering::Acquire),
                0,
                "the inner public eval must succeed and restore the outer TLS scope"
            );
            assert_eq!(
                NESTED_INNER_TLS_MASK.load(std::sync::atomic::Ordering::Acquire),
                0,
                "runtime B observed a legacy, native-callback, or typed-FS principal from runtime A"
            );
            assert_eq!(
                NESTED_INNER_ACTIVE_NONCE.load(std::sync::atomic::Ordering::Acquire),
                inner_nonce,
                "the inner callback must execute under runtime B's generation"
            );

            NESTED_OTHER_RUNTIME.store(std::ptr::null_mut(), std::sync::atomic::Ordering::Release);
            ex_hermes_destroy(inner);
            ex_hermes_destroy(outer);
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn construction_and_teardown_context_isolate_and_restore_principal_tls() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let nonce = ex_hermes_runtime_nonce(runtime);
            assert_ne!(nonce, 0);
            let outer_nonce = nonce
                .checked_add(1)
                .filter(|value| *value != 0)
                .unwrap_or(1);
            assert_ne!(outer_nonce, nonce);
            assert_eq!(
                ibex_test_runtime_security_context_boundary(
                    runtime,
                    outer_nonce,
                    OUTER_MODULE_SENTINEL,
                    OUTER_NATIVE_SENTINEL,
                    OUTER_TYPED_SENTINELS.as_ptr(),
                    OUTER_TYPED_SENTINELS.len(),
                ),
                0,
                "the construction/Closing cleanup context leaked or failed to restore outer authority TLS"
            );
            ex_hermes_destroy(runtime);
        }
    }

    /// AC18 is a consumer-language contract, so the assertions and public ABI
    /// calls live in exact_runtime_c_abi_check.c. Rust supplies only the
    /// foreign thread needed to prove owner-thread rejection.
    /// @ref LLP 0024#6-evaluation-outcomes-and-the-abi
    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn independent_c11_consumer_executes_structured_value_abi() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let mut context = std::ptr::null_mut();
            assert_eq!(
                ibex_exact_runtime_c_abi_probe_prepare(&mut context),
                0,
                "C11 ABI prepare probe failed"
            );
            assert!(!context.is_null());

            let context_address = context as usize;
            let wrong_thread = std::thread::spawn(move || {
                ibex_exact_runtime_c_abi_probe_wrong_thread(context_address as *mut c_void)
            })
            .join();
            // Always return ownership to the C harness before interpreting
            // the foreign-thread result, so a failing assertion cannot leak
            // its live Hermes runtime.
            let finish = ibex_exact_runtime_c_abi_probe_finish(context);
            let wrong_thread = wrong_thread.expect("C11 ABI foreign thread panicked");
            assert_eq!(wrong_thread, 0, "C11 ABI wrong-thread probe failed");
            assert_eq!(finish, 0, "C11 ABI owner-thread finish probe failed");
        }
    }

    #[test]
    fn structured_diagnostic_eval_preserves_values_without_thenable_assimilation() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let mut empty = structured_eval(runtime, b"");
            if empty.outcome_tag == STRUCTURED_ENGINE_FAULT {
                assert_eq!(empty.fault, FAULT_RAW_THROW_UNAVAILABLE);
                ex_hermes_evaluation_result_dispose(&mut empty);
                ex_hermes_destroy(runtime);
                return;
            }
            assert_eq!(empty.outcome_tag, STRUCTURED_VALUE);
            assert_eq!(empty.fault, FAULT_NONE);
            assert_ne!(empty.work_target_id, 0);
            assert_eq!(ex_hermes_value_kind(runtime, empty.value), VALUE_UNDEFINED);
            assert_eq!(ex_hermes_value_release(runtime, empty.value), FAULT_NONE);
            ex_hermes_evaluation_result_dispose(&mut empty);

            let mut thenable = structured_eval(
                runtime,
                b"globalThis.__structuredThenCalls = 0; ({ then: function(){ globalThis.__structuredThenCalls++; } })",
            );
            assert_eq!(thenable.outcome_tag, STRUCTURED_VALUE);
            assert_eq!(ex_hermes_value_kind(runtime, thenable.value), VALUE_OBJECT);
            assert_eq!(
                eval(runtime, "globalThis.__structuredThenCalls"),
                (0, Some("0".into()))
            );
            assert_eq!(ex_hermes_value_release(runtime, thenable.value), FAULT_NONE);
            assert_eq!(
                ex_hermes_value_release(runtime, thenable.value),
                FAULT_STALE_HANDLE
            );
            assert_eq!(ex_hermes_value_kind(runtime, thenable.value), VALUE_INVALID);
            ex_hermes_evaluation_result_dispose(&mut thenable);

            let mut revoked_proxy = structured_eval(
                runtime,
                b"const pair = Proxy.revocable([], {}); pair.revoke(); pair.proxy",
            );
            assert_eq!(revoked_proxy.outcome_tag, STRUCTURED_VALUE);
            assert_eq!(
                ex_hermes_value_kind(runtime, revoked_proxy.value),
                VALUE_OBJECT
            );
            assert_eq!(
                ex_hermes_value_release(runtime, revoked_proxy.value),
                FAULT_NONE
            );
            ex_hermes_evaluation_result_dispose(&mut revoked_proxy);
            ex_hermes_destroy(runtime);
        }
    }

    #[test]
    fn structured_diagnostic_eval_keeps_original_throw_without_reading_properties() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let mut thrown = structured_eval(
                runtime,
                br#"globalThis.__structuredGetterCalls = 0;
                    throw {
                      get message(){ globalThis.__structuredGetterCalls++; return "message"; },
                      get stack(){ globalThis.__structuredGetterCalls++; return "stack"; }
                    };"#,
            );
            if thrown.outcome_tag == STRUCTURED_ENGINE_FAULT {
                assert_eq!(thrown.fault, FAULT_RAW_THROW_UNAVAILABLE);
                ex_hermes_evaluation_result_dispose(&mut thrown);
                ex_hermes_destroy(runtime);
                return;
            }
            assert_eq!(thrown.abi_version, STRUCTURED_ABI_VERSION);
            assert_eq!(thrown.struct_size as usize, std::mem::size_of_val(&thrown));
            assert_eq!(thrown.outcome_tag, STRUCTURED_THROW);
            // This diagnostic seam advertises no SafeThrow capability, so
            // its metadata discriminator must remain unavailable even when
            // the linked engine has the trap-free native primitive.
            assert_eq!(thrown.throw_metadata_status, THROW_METADATA_UNAVAILABLE);
            assert_eq!(thrown.throw_metadata_fields, 0);
            assert_eq!(thrown.throw_error_class, ERROR_CLASS_UNCLASSIFIED);
            assert_eq!(
                thrown.capability_flags & (CAPABILITY_SAFE_THROW | CAPABILITY_SOURCE_POSITIONS),
                0
            );
            assert!(thrown.positions.is_null());
            assert_eq!(thrown.position_count, 0);
            assert_eq!(ex_hermes_value_kind(runtime, thrown.value), VALUE_OBJECT);
            assert_eq!(
                eval(runtime, "globalThis.__structuredGetterCalls"),
                (0, Some("0".into()))
            );
            assert_eq!(ex_hermes_value_release(runtime, thrown.value), FAULT_NONE);
            ex_hermes_evaluation_result_dispose(&mut thrown);

            // The same capability/metadata invariant applies to an ordinary
            // Error: diagnostic evaluation cannot expose profile metadata.
            let mut ordinary_error = structured_eval(runtime, b"throw new Error('boom')");
            assert_eq!(ordinary_error.outcome_tag, STRUCTURED_THROW);
            assert_eq!(
                ordinary_error.throw_metadata_status,
                THROW_METADATA_UNAVAILABLE
            );
            assert_eq!(ordinary_error.throw_metadata_fields, 0);
            assert_eq!(ordinary_error.throw_error_class, ERROR_CLASS_UNCLASSIFIED);
            assert!(ordinary_error.message.data.is_null());
            assert_eq!(ordinary_error.message.length, 0);
            assert!(ordinary_error.stack.data.is_null());
            assert_eq!(ordinary_error.stack.length, 0);
            assert_eq!(
                ordinary_error.capability_flags
                    & (CAPABILITY_SAFE_THROW | CAPABILITY_SOURCE_POSITIONS),
                0
            );
            assert!(ordinary_error.positions.is_null());
            assert_eq!(ordinary_error.position_count, 0);
            assert_eq!(
                ex_hermes_value_release(runtime, ordinary_error.value),
                FAULT_NONE
            );
            ex_hermes_evaluation_result_dispose(&mut ordinary_error);
            assert_eq!(ordinary_error.abi_version, STRUCTURED_ABI_VERSION);
            assert!(ordinary_error.positions.is_null());
            assert_eq!(ordinary_error.position_count, 0);

            let mut revoked_proxy = structured_eval(
                runtime,
                b"const pair = Proxy.revocable([], {}); pair.revoke(); throw pair.proxy",
            );
            assert_eq!(revoked_proxy.outcome_tag, STRUCTURED_THROW);
            assert_eq!(
                revoked_proxy.throw_metadata_status,
                THROW_METADATA_UNAVAILABLE
            );
            assert_eq!(
                ex_hermes_value_kind(runtime, revoked_proxy.value),
                VALUE_OBJECT
            );
            assert_eq!(
                ex_hermes_value_release(runtime, revoked_proxy.value),
                FAULT_NONE
            );
            ex_hermes_evaluation_result_dispose(&mut revoked_proxy);

            let mut nul_string = structured_eval(runtime, b"throw 'left\\0right'");
            assert_eq!(nul_string.outcome_tag, STRUCTURED_THROW);
            assert_eq!(
                ex_hermes_value_kind(runtime, nul_string.value),
                VALUE_STRING
            );
            assert_eq!(
                ex_hermes_value_release(runtime, nul_string.value),
                FAULT_NONE
            );
            ex_hermes_evaluation_result_dispose(&mut nul_string);
            ex_hermes_destroy(runtime);
        }
    }

    extern "C" fn count_watchdog_heartbeat(context: *mut std::ffi::c_void) {
        let count = unsafe { &*(context.cast::<std::sync::atomic::AtomicUsize>()) };
        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// A watchdog executor retains its runtime identity across threads. If the
    /// handle address is recycled, an old heartbeat must not be relabelled with
    /// the new runtime's nonce and admitted into that runtime.
    #[test]
    fn watchdog_heartbeat_rejects_a_stale_generation_at_a_reused_address() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());

        unsafe {
            let stale_runtime = ex_hermes_create_diagnostic();
            assert!(!stale_runtime.is_null());
            let stale_nonce = ex_hermes_runtime_nonce(stale_runtime);
            assert_ne!(stale_nonce, 0);
            ex_hermes_destroy(stale_runtime);

            let replacement = ex_hermes_create_diagnostic();
            assert!(!replacement.is_null());

            let replacement_nonce = ex_hermes_runtime_nonce(replacement);
            assert_ne!(replacement_nonce, 0);
            assert_ne!(replacement_nonce, stale_nonce);
            let count = std::sync::atomic::AtomicUsize::new(0);
            let context = (&count as *const std::sync::atomic::AtomicUsize)
                .cast_mut()
                .cast::<std::ffi::c_void>();

            ex_hermes_schedule_watchdog_heartbeat(replacement, count_watchdog_heartbeat, context);
            assert_eq!(ex_hermes_callback_backlog(replacement), 0);
            assert_eq!(ex_hermes_poll(replacement, ex_hermes_now_ms()), 0);
            assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 0);

            // Force the exact identity pair seen after address reuse: the
            // address now names B, while the producer still carries A's
            // captured nonce. Physical allocator reuse is irrelevant to the
            // registry operation and would make this test nondeterministic.
            ex_hermes_schedule_watchdog_heartbeat_for_generation(
                replacement,
                stale_nonce,
                count_watchdog_heartbeat,
                context,
            );
            assert_eq!(ex_hermes_callback_backlog(replacement), 0);
            assert_eq!(ex_hermes_poll(replacement, ex_hermes_now_ms()), 0);
            assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 0);

            ex_hermes_schedule_watchdog_heartbeat_for_generation(
                replacement,
                replacement_nonce,
                count_watchdog_heartbeat,
                context,
            );
            assert_eq!(ex_hermes_callback_backlog(replacement), 1);
            assert_eq!(ex_hermes_poll(replacement, ex_hermes_now_ms()), 1);
            assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
            ex_hermes_destroy(replacement);
        }
    }

    /// A CPU-bound eval must be interruptible. Hermes compiles async-break
    /// checks by default, so an armed time limit terminates the loop and
    /// surfaces its stable error rather than hanging the owner thread.
    /// @ref LLP 0002#runtime-driving-thread-contract
    #[test]
    fn time_limit_interrupts_cpu_bound_eval() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            assert_eq!(ex_hermes_watch_time_limit(runtime, 50), 0);
            let started = std::time::Instant::now();
            let (status, value) = eval(runtime, "while (true) {};");
            let elapsed = started.elapsed();
            ex_hermes_unwatch_time_limit(runtime);
            ex_hermes_destroy(runtime);
            let _ = sender.send((status, value, elapsed));
        });

        let (status, value, elapsed) = receiver
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("Hermes async-break time limit must terminate the eval");
        worker.join().expect("time-limited eval worker");
        assert_ne!(status, 0, "a timed-out eval cannot report success");
        assert!(
            value
                .as_deref()
                .unwrap_or_default()
                .contains("Javascript execution has timed out"),
            "timeout must carry Hermes' stable error: {value:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "a 50ms limit must interrupt promptly, took {elapsed:?}"
        );
    }

    /// A zero timeout is refused rather than silently arming nothing, and
    /// unwatch is safe when no limit is armed.
    #[test]
    fn time_limit_rejects_zero_and_tolerates_idle_unwatch() {
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            assert_ne!(ex_hermes_watch_time_limit(runtime, 0), 0);
            ex_hermes_unwatch_time_limit(runtime);
            assert_eq!(ex_hermes_watch_time_limit(runtime, 50), 0);
            // Re-arming replaces the previous registration rather than
            // stacking a second monitor entry.
            assert_eq!(ex_hermes_watch_time_limit(runtime, 75), 0);
            ex_hermes_unwatch_time_limit(runtime);
            ex_hermes_unwatch_time_limit(runtime);
            ex_hermes_destroy(runtime);
        }
    }

    /// The any-thread interrupt stops a running eval from a foreign thread
    /// (what an embedder's cancellation hook needs), and refuses a stale
    /// nonce so it cannot interrupt a runtime that reused the address.
    #[test]
    fn interrupt_eval_stops_a_foreign_threads_runaway_and_checks_the_nonce() {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let nonce = ex_hermes_runtime_nonce(runtime);
            assert_ne!(nonce, 0);
            // A stale nonce must be refused before any eval is running.
            assert_ne!(
                ex_hermes_interrupt_eval(runtime, nonce.wrapping_add(1)),
                0,
                "a stale nonce must not interrupt this runtime"
            );
            ready_tx.send((runtime as usize, nonce)).unwrap();
            let (status, value) = eval(runtime, "while (true) {};");
            ex_hermes_destroy(runtime);
            let _ = done_tx.send((status, value));
        });

        let (runtime_addr, nonce) = ready_rx.recv().expect("worker published its runtime");
        // Give the worker time to enter the loop, then interrupt off-thread.
        std::thread::sleep(std::time::Duration::from_millis(150));
        let interrupted =
            unsafe { ex_hermes_interrupt_eval(runtime_addr as *mut HermesRuntimeOpaque, nonce) };

        let settled = done_rx.recv_timeout(std::time::Duration::from_secs(30));
        worker.join().expect("interrupted eval worker");
        if interrupted != 0 {
            // The linked Hermes lacks async-break support; the eval then never
            // returns on its own, which the recv_timeout above would surface.
            // Skip rather than assert a capability this engine does not have.
            return;
        }
        let (status, value) = settled.expect("an interrupted eval must settle");
        assert_ne!(status, 0, "an interrupted eval cannot report success");
        assert!(
            value
                .as_deref()
                .unwrap_or_default()
                .contains("Javascript execution has timed out"),
            "interrupt must surface Hermes' stable timeout error: {value:?}"
        );
    }

    /// Frame attribution must inspect the runtime being evaluated, not merely
    /// the last runtime created on this thread. Snapback nests a mutation
    /// runtime inside an action runtime; the stale thread-local used to make
    /// the outer continuation look like it had no user principal and falsely
    /// deny its explicitly granted fetch capability (ENG-24219).
    #[test]
    fn capability_attribution_tracks_the_eval_target_across_two_runtimes() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::strict();
        host.capabilities().grant("*", "network:fetch", None);
        crate::host::abi::install_host(host);

        unsafe {
            let outer = ex_hermes_create_diagnostic();
            let nested = ex_hermes_create_diagnostic();
            assert!(!outer.is_null());
            assert!(!nested.is_null());

            let (status, value) = eval(
                outer,
                "__exactCapabilityCheck('network:fetch:127.0.0.1') ? 'allowed' : 'denied'",
            );
            assert_eq!(status, 0, "outer eval failed: {value:?}");
            assert_eq!(value.as_deref(), Some("allowed"));

            ex_hermes_destroy(nested);
            ex_hermes_destroy(outer);
        }
    }

    #[test]
    fn native_owner_hosts_reject_non_integral_or_unsafe_numeric_selectors() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());

        unsafe {
            #[cfg(target_os = "windows")]
            ex_host_install();
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            let (status, value) = eval(
                runtime,
                r#"
                (function() {
                  var invalid = [
                    NaN, Infinity, -Infinity, 0, -1, 1.5,
                    9007199254740992, undefined, '1'
                  ];
                  var httpRejected = invalid.every(function(value) {
                    return __exactHttpOwner(value) === false;
                  });
                  var stamp = __exactNetOwner('new');
                  __exactNetOwner('assert', stamp);
                  var stampsRejected = invalid.every(function(value) {
                    try {
                      __exactNetOwner('assert', value);
                      return false;
                    } catch (_) {
                      return true;
                    }
                  });
                  var invalidHandles = [
                    NaN, Infinity, -Infinity, 0, -1, 1.5,
                    9007199254740992, '1'
                  ];
                  var handlesRejected = invalidHandles.every(function(value) {
                    try {
                      __exactNetOwner('assert', stamp, value);
                      return false;
                    } catch (_) {
                      return true;
                    }
                  });
                  return String(httpRejected) + ':' +
                    String(stampsRejected) + ':' + String(handlesRejected);
                })()
                "#,
            );
            assert_eq!(status, 0, "owner-host selector probe failed: {value:?}");
            assert_eq!(value.as_deref(), Some("true:true:true"));
            ex_hermes_destroy(runtime);
        }
    }

    #[test]
    fn native_owner_hooks_resist_replacement_before_first_net_require() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());

        unsafe {
            #[cfg(target_os = "windows")]
            ex_host_install();
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            let (status, value) = eval(
                runtime,
                r#"
                (function() {
                  var netDescriptor = Object.getOwnPropertyDescriptor(
                    globalThis, '__exactNetOwner'
                  );
                  var httpDescriptor = Object.getOwnPropertyDescriptor(
                    globalThis, '__exactHttpOwner'
                  );
                  var realNetOwner = globalThis.__exactNetOwner;
                  var realHttpOwner = globalThis.__exactHttpOwner;
                  var sentinelCalls = 0;
                  function sentinel() { sentinelCalls += 1; return -1; }

                  globalThis.__exactNetOwner = sentinel;
                  globalThis.__exactHttpOwner = sentinel;
                  var netDeleteRefused = delete globalThis.__exactNetOwner;
                  var httpDeleteRefused = delete globalThis.__exactHttpOwner;
                  var netRedefinitionRefused = false;
                  var httpRedefinitionRefused = false;
                  try {
                    Object.defineProperty(globalThis, '__exactNetOwner', {
                      value: sentinel
                    });
                  } catch (_) {
                    netRedefinitionRefused = true;
                  }
                  try {
                    Object.defineProperty(globalThis, '__exactHttpOwner', {
                      value: sentinel
                    });
                  } catch (_) {
                    httpRedefinitionRefused = true;
                  }

                  var stamp = globalThis.__exactNetOwner('new');
                  globalThis.__exactNetOwner('assert', stamp);
                  var httpOwnerResult = globalThis.__exactHttpOwner(0);

                  var checks = [
                    netDescriptor && netDescriptor.writable === false &&
                      netDescriptor.configurable === false,
                    httpDescriptor && httpDescriptor.writable === false &&
                      httpDescriptor.configurable === false,
                    globalThis.__exactNetOwner === realNetOwner,
                    globalThis.__exactHttpOwner === realHttpOwner,
                    netDeleteRefused === false,
                    httpDeleteRefused === false,
                    netRedefinitionRefused,
                    httpRedefinitionRefused,
                    sentinelCalls === 0,
                    typeof stamp === 'number' && stamp > 0,
                    httpOwnerResult === false
                  ];
                  return checks.every(function(check) { return check; })
                    ? 'sealed'
                    : JSON.stringify(checks);
                })()
                "#,
            );
            assert_eq!(status, 0, "owner-hook replacement probe failed: {value:?}");
            assert_eq!(value.as_deref(), Some("sealed"));
            ex_hermes_destroy(runtime);
        }
    }

    #[test]
    fn schedule_on_app_runtime_json_dispatches_on_app_runtime() {
        unsafe {
            let app = ex_hermes_create_diagnostic();
            assert!(!app.is_null());
            assert_eq!(
                eval(
                    app,
                    "globalThis.__scheduled=null; globalThis.__exactScheduleOnAppRuntime=function(batch,generation){ __scheduled=[batch,generation]; }; 'ready'",
                )
                .0,
                0
            );
            let batch = br#"[{"name":"refreshBadge","args":{"count":3}}]"#;
            assert_eq!(
                ex_hermes_dispatch_worklet_json_batch(app, batch.as_ptr(), batch.len(), 11,),
                0
            );
            assert_eq!(
                eval(app, "JSON.stringify(__scheduled)").1.as_deref(),
                Some("[[{\"name\":\"refreshBadge\",\"args\":{\"count\":3}}],11]")
            );
            ex_hermes_destroy(app);
        }
    }

    #[test]
    fn motion_rated_publish_dispatches_fixed_sample_on_app_runtime() {
        unsafe {
            let app = ex_hermes_create_diagnostic();
            assert!(!app.is_null());
            assert_eq!(
                eval(
                    app,
                    "globalThis.__rated=null; globalThis.__exactMotionRatedPublish=function(id,values,metadata){ __rated=[id,values,metadata]; }; 'ready'",
                )
                .0,
                0
            );
            let sample = MotionRatedPublishSample {
                channel_identity: 91,
                dirty_generation: 7,
                sample_time_ns: 123_456,
                value_count: 2,
                flags: 3,
                values: [4.5, -2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            };
            assert_eq!(ex_hermes_dispatch_motion_rated_publish(app, &sample), 0);
            assert_eq!(
                eval(app, "JSON.stringify(__rated)").1.as_deref(),
                Some(
                    "[\"91\",[4.5,-2],{\"dirtyGeneration\":\"7\",\"sampleTimeNs\":\"123456\",\"heartbeat\":true,\"programmatic\":true}]"
                )
            );

            let mut invalid = sample;
            invalid.values[0] = f32::NAN;
            assert_eq!(ex_hermes_dispatch_motion_rated_publish(app, &invalid), 1);
            ex_hermes_destroy(app);
        }
    }

    // Asserts armed-refusal semantics, which an `insecure` build
    // deliberately does not have. @ref LLP 0039#secure-mode-must-stay-exercised
    #[cfg(not(feature = "insecure"))]
    #[test]
    fn host_policy_is_pinned_to_each_runtime_context() {
        let _host_guard = crate::host::abi::host_test_lock();
        let allow = crate::host::Host::strict();
        allow.capabilities().grant("*", "network:fetch", None);
        crate::host::abi::install_host(allow);
        let first = unsafe { ex_hermes_create_diagnostic() };
        assert!(!first.is_null());

        let deny = crate::host::Host::strict();
        deny.capabilities().deny("*", "network:fetch", None);
        crate::host::abi::install_host(deny);
        let second = unsafe { ex_hermes_create_diagnostic() };
        assert!(!second.is_null());

        let source = "__exactCapabilityCheck('network:fetch:example.com') ? 'allowed' : 'denied'";
        let (first_status, first_value) = eval(first, source);
        let (second_status, second_value) = eval(second, source);
        assert_eq!((first_status, first_value.as_deref()), (0, Some("allowed")));
        assert_eq!(
            (second_status, second_value.as_deref()),
            (0, Some("denied"))
        );

        unsafe {
            ex_hermes_destroy(second);
            ex_hermes_destroy(first);
        }
    }

    /// Native TLS engine handles are process-global numbers at the JS ABI, but
    /// authority must remain scoped to the creating runtime. Two runtimes can
    /// use the same principal ids, so principal-only ownership lets one guess,
    /// inspect, or close the other's TLS session. Runtime destruction must also
    /// retire only that runtime's engines.
    #[test]
    fn tls_engine_handles_are_isolated_and_cleaned_per_runtime() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::strict();
        crate::host::abi::install_host(host);

        unsafe {
            let first = ex_hermes_create_diagnostic();
            let second = ex_hermes_create_diagnostic();
            assert!(!first.is_null());
            assert!(!second.is_null());

            let (status, first_id_text) =
                eval(first, "__exactTlsEngineNew('{\"host\":\"localhost\"}')");
            assert_eq!(
                status, 0,
                "first TLS engine creation failed: {first_id_text:?}"
            );
            let first_id: u64 = first_id_text
                .expect("first engine id")
                .parse()
                .expect("numeric first engine id");

            let (status, second_id_text) =
                eval(second, "__exactTlsEngineNew('{\"host\":\"localhost\"}')");
            assert_eq!(
                status, 0,
                "second TLS engine creation failed: {second_id_text:?}"
            );
            let second_id: u64 = second_id_text
                .expect("second engine id")
                .parse()
                .expect("numeric second engine id");

            let (status, value) = eval(
                second,
                &format!(
                    "try {{ __exactTlsEngineStatus({first_id}); 'leaked' }} \
                     catch (error) {{ String(error).includes('belongs to another runtime or principal') ? 'isolated' : String(error) }}"
                ),
            );
            assert_eq!(status, 0, "cross-runtime probe failed: {value:?}");
            assert_eq!(value.as_deref(), Some("isolated"));

            ex_hermes_destroy(first);

            let (status, value) = eval(
                second,
                &format!(
                    "try {{ __exactTlsEngineStatus({first_id}); 'retained' }} \
                     catch (error) {{ String(error).includes('unknown engine handle') ? 'cleaned' : String(error) }}"
                ),
            );
            assert_eq!(
                status, 0,
                "destroyed-runtime cleanup probe failed: {value:?}"
            );
            assert_eq!(value.as_deref(), Some("cleaned"));

            let (status, value) = eval(
                second,
                &format!(
                    "JSON.parse(__exactTlsEngineStatus({second_id})).handshaking ? 'alive' : 'alive'"
                ),
            );
            assert_eq!(
                status, 0,
                "surviving runtime lost its TLS engine: {value:?}"
            );
            assert_eq!(value.as_deref(), Some("alive"));

            ex_hermes_destroy(second);
        }
    }

    /// A one-shot timer whose callback throws must be retired before the
    /// error propagates out of `ex_hermes_poll`; before the fix it stayed
    /// due and refired on every subsequent poll. @ref LLP 0006#degrade-diagnostics-never-the-caller
    #[test]
    fn throwing_one_shot_timer_does_not_refire() {
        unsafe {
            std::env::set_var("IBEX_SUPPRESS_CONSOLE_MIRROR", "1");
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            let (status, value) = eval(
                runtime,
                "globalThis.__r1Count = 0;\n\
                 setTimeout(function () { globalThis.__r1Count++; throw new Error('boom'); }, 0);\n\
                 'armed';",
            );
            assert_eq!(status, 0, "arming eval failed: {value:?}");

            // Timer due_ms is monotonic-ms since process start; a huge `now`
            // guarantees the timer is due on the first poll.
            let now = u64::MAX / 2;
            let first = ex_hermes_poll(runtime, now);
            assert_eq!(first, -1, "throwing timer should surface a poll error");

            let second = ex_hermes_poll(runtime, now + 1_000);
            assert_eq!(second, 0, "retired one-shot timer must not refire");
            let third = ex_hermes_poll(runtime, now + 2_000);
            assert_eq!(third, 0, "retired one-shot timer must not refire");

            let (status, value) = eval(runtime, "String(globalThis.__r1Count)");
            assert_eq!(status, 0);
            assert_eq!(value.as_deref(), Some("1"));

            ex_hermes_destroy(runtime);
        }
    }

    /// An unreferenced timer is not runtime liveness, but it remains eligible
    /// while an embedding host independently keeps the owner loop alive. The
    /// external-ready poll expresses that distinction without mutating
    /// `Timeout.hasRef()` or the ordinary pending-work query.
    /// @ref LLP 0003#the-event-loop
    /// @ref LLP 0024#1-the-in-memory-source-api
    #[test]
    fn external_keep_alive_poll_runs_due_unref_timer_without_refing_it() {
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            let (status, value) = eval(
                runtime,
                "globalThis.__externalKeepAliveCount = 0;\n\
                 const timer = setTimeout(function () {\n\
                   globalThis.__externalKeepAliveCount++;\n\
                 }, 0);\n\
                 __exactTimerUnref(timer);\n\
                 'armed';",
            );
            assert_eq!(status, 0, "timer arming failed: {value:?}");
            assert_eq!(value.as_deref(), Some("armed"));
            assert_eq!(
                ex_hermes_has_pending_tasks(runtime),
                0,
                "an unref'd timer must not become runtime liveness"
            );

            let now = u64::MAX / 2;
            assert_eq!(
                ex_hermes_poll(runtime, now),
                0,
                "ordinary poll must preserve unref exit semantics"
            );
            assert_eq!(
                ex_hermes_poll_with_external_keep_alive(runtime, now),
                1,
                "host-held liveness must make the due timer eligible"
            );
            assert_eq!(
                ex_hermes_poll(runtime, now + 1),
                0,
                "the external turn must retire the one-shot exactly once"
            );

            let (status, value) = eval(runtime, "String(globalThis.__externalKeepAliveCount)");
            assert_eq!(status, 0);
            assert_eq!(value.as_deref(), Some("1"));
            ex_hermes_destroy(runtime);
        }
    }

    /// Embedded hosts opt into report-and-continue behavior for errors escaping
    /// async callbacks. A `nextTick` queued by a timer is drained from
    /// `ex_hermes_poll`, not the arming eval, so this directly pins the
    /// keep-alive policy at the poll-time nextTick drain. @ref LLP 0003#the-event-loop
    #[test]
    fn keep_alive_policy_continues_after_poll_time_next_tick_throw() {
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            ex_hermes_set_keep_alive_on_async_error(runtime, 1);

            let (status, value) = eval(
                runtime,
                "globalThis.__r1TickOrder = [];\n\
                 setTimeout(function () {\n\
                   process.nextTick(function () {\n\
                     globalThis.__r1TickOrder.push('threw');\n\
                     throw new Error('keep-alive-next-tick');\n\
                   });\n\
                   process.nextTick(function () {\n\
                     globalThis.__r1TickOrder.push('continued');\n\
                   });\n\
                 }, 0);\n\
                 'armed';",
            );
            assert_eq!(status, 0, "arming eval failed: {value:?}");

            let poll_status = ex_hermes_poll(runtime, u64::MAX / 2);
            let (state_status, state) = eval(runtime, "globalThis.__r1TickOrder.join(',')");
            ex_hermes_destroy(runtime);

            assert_eq!(
                poll_status, 1,
                "keep-alive nextTick throw must not make the observing poll fatal"
            );
            assert_eq!(
                state_status, 0,
                "runtime must remain evaluable after the throw"
            );
            assert_eq!(
                state.as_deref(),
                Some("threw,continued"),
                "the nextTick drain must continue after the throwing callback"
            );
        }
    }

    /// The native signal watcher delivers through `pushRuntimeCallback`, the
    /// same cross-thread callback queue used by HTTP, WebSocket, DNS, and fs.
    /// Replacing its JS dispatcher with a throwing function makes the throw
    /// escape the queued callback itself, exercising `drainCallbackQueue`
    /// without a network race or a test-only production hook. @ref LLP 0003#the-event-loop
    #[cfg(unix)]
    #[test]
    fn keep_alive_policy_continues_after_cross_thread_callback_throw() {
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            ex_hermes_set_keep_alive_on_async_error(runtime, 1);

            let signal = libc::SIGUSR2;
            let (status, value) = eval(
                runtime,
                &format!(
                    "globalThis.__r1CrossThreadRuns = 0;\n\
                     globalThis.__exactDispatchPendingSignals = function () {{\n\
                       globalThis.__r1CrossThreadRuns++;\n\
                       throw new Error('keep-alive-cross-thread');\n\
                     }};\n\
                     __exactTrapSignal({signal});\n\
                     'armed';"
                ),
            );
            assert_eq!(status, 0, "signal callback setup failed: {value:?}");
            assert_eq!(
                libc::raise(signal),
                0,
                "failed to raise trapped test signal"
            );

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let mut backlog = ex_hermes_callback_backlog(runtime);
            while backlog == 0 && std::time::Instant::now() < deadline {
                std::thread::yield_now();
                backlog = ex_hermes_callback_backlog(runtime);
            }

            let poll_status = if backlog == 0 {
                None
            } else {
                Some(ex_hermes_poll(runtime, ex_hermes_now_ms()))
            };
            let (state_status, state) = eval(runtime, "String(globalThis.__r1CrossThreadRuns)");
            // Restore the process-wide disposition before assertions can panic.
            let _ = eval(runtime, &format!("__exactResetSignal({signal}); 'reset'"));
            ex_hermes_destroy(runtime);

            assert!(
                backlog > 0,
                "signal watcher did not enqueue its runtime callback"
            );
            assert_eq!(
                poll_status,
                Some(0),
                "keep-alive cross-thread throw must not make the observing poll fatal"
            );
            assert_eq!(
                state_status, 0,
                "runtime must remain evaluable after the throw"
            );
            assert_eq!(state.as_deref(), Some("1"));
        }
    }

    #[test]
    fn self_clearing_interval_keeps_captured_principals_alive_through_callback() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", "network:fetch:self-clear.invalid", None);
        assert_ne!(crate::host::abi::install_host(host), 0);

        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let (status, value) = eval(
                runtime,
                "globalThis.__selfClearCount = 0;\n\
                 globalThis.__selfClearAllowed = false;\n\
                 var interval = setInterval(function () {\n\
                   clearInterval(interval);\n\
                   globalThis.__selfClearCount++;\n\
                   globalThis.__selfClearAllowed =\n\
                     __exactCapabilityCheck('network:fetch:self-clear.invalid');\n\
                 }, 0);\n\
                 'armed';",
            );
            assert_eq!(status, 0, "interval setup failed: {value:?}");

            assert_eq!(
                ex_hermes_poll(runtime, u64::MAX / 2),
                1,
                "self-clearing callback should complete after erasing its timer record"
            );
            assert_eq!(ex_hermes_poll(runtime, u64::MAX / 2 + 1), 0);
            let (status, value) = eval(
                runtime,
                "String(globalThis.__selfClearCount) + ':' + \
                 String(globalThis.__selfClearAllowed)",
            );
            assert_eq!((status, value.as_deref()), (0, Some("1:true")));
            ex_hermes_destroy(runtime);
        }
    }

    /// setTimeout/setInterval store `due_ms = nowMs() + delay` on a MONOTONIC
    /// clock, and the Rust event loop reads that same clock via
    /// `ex_hermes_now_ms()` for the `now` it feeds to `ex_hermes_poll`. A large
    /// numeric delay lets us confirm both sides share one clock domain: due_ms
    /// minus a freshly-read now must be ~= the delay (not wildly off, as it
    /// would be if the two used different clock epochs).
    #[test]
    fn timer_due_time_shares_monotonic_clock_domain() {
        unsafe {
            std::env::set_var("IBEX_SUPPRESS_CONSOLE_MIRROR", "1");
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            let t0 = ex_hermes_now_ms();
            let (status, _) = eval(
                runtime,
                "globalThis.__c = 0; setTimeout(function () { globalThis.__c++; }, 100000); 'ok';",
            );
            assert_eq!(status, 0);

            let due = ex_hermes_next_timer(runtime);
            assert!(
                due >= 0,
                "an armed timer must report a non-negative due time"
            );
            let rel = (due as u64).saturating_sub(t0);
            assert!(
                (90_000..=110_000).contains(&rel),
                "due_ms - ex_hermes_now_ms() = {rel}ms, expected ~100000ms; \
                 the Rust loop clock and the C++ timer clock must be the same domain",
            );

            // Passing that due time straight to poll fires the timer.
            let fired = ex_hermes_poll(runtime, due as u64);
            assert!(fired >= 1, "timer should fire once its due time is reached");
            let (_, value) = eval(runtime, "String(globalThis.__c)");
            assert_eq!(value.as_deref(), Some("1"));

            ex_hermes_destroy(runtime);
        }
    }

    /// setTimeout/setInterval must (a) ToNumber-coerce a non-number delay like
    /// `'100000'` instead of silently treating it as 0, and (b) clamp negative
    /// and NaN delays to 0. Before the fix the delay went through
    /// `static_cast<uint64_t>(asNumber())`: strings became 0, and negative/NaN
    /// were UB — on x86_64 they cast to 0x8000000000000000, so `nowMs() + delay`
    /// landed ~292M years out and the callback NEVER fired.
    #[test]
    fn timer_delay_is_coerced_and_clamped() {
        unsafe {
            std::env::set_var("IBEX_SUPPRESS_CONSOLE_MIRROR", "1");
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            // (a) A string delay is coerced via ToNumber, so a '100000' timer is
            // due ~100s out — not immediately (which is what treating it as 0
            // would produce).
            let t0 = ex_hermes_now_ms();
            let (status, _) = eval(
                runtime,
                "globalThis.__s = 0; setTimeout(function () { globalThis.__s++; }, '100000'); 'ok';",
            );
            assert_eq!(status, 0);
            let due = ex_hermes_next_timer(runtime);
            assert!(due >= 0);
            let rel = (due as u64).saturating_sub(t0);
            assert!(
                rel >= 90_000,
                "string delay '100000' must coerce to ~100000ms, got {rel}ms \
                 (a non-coerced delay would be ~0)",
            );
            // Retire it so it doesn't interfere with the clamp cases below.
            ex_hermes_poll(runtime, due as u64);
            let (_, value) = eval(runtime, "String(globalThis.__s)");
            assert_eq!(value.as_deref(), Some("1"));
            assert_eq!(ex_hermes_next_timer(runtime), -1);

            // (b) Negative, NaN, non-coercible-object, and missing delays all
            // clamp to 0: each timer is due ~immediately (a small offset, NOT a
            // ~292M-year deadline) and fires on the next poll.
            let cases = [
                ("neg", "setTimeout(function () { globalThis.__f++; }, -1);"),
                ("nan", "setTimeout(function () { globalThis.__f++; }, NaN);"),
                ("obj", "setTimeout(function () { globalThis.__f++; }, {});"),
                ("none", "setTimeout(function () { globalThis.__f++; });"),
            ];
            for (label, arm) in cases {
                let base = ex_hermes_now_ms();
                let (status, _) = eval(runtime, &format!("globalThis.__f = 0; {arm} 'ok';"));
                assert_eq!(status, 0, "{label}: setTimeout must not throw");
                let due = ex_hermes_next_timer(runtime);
                assert!(
                    due >= 0,
                    "{label}: delay must not become a far-future deadline"
                );
                let rel = (due as u64).saturating_sub(base);
                assert!(
                    rel <= 1_000,
                    "{label}: delay must clamp to ~0ms, got {rel}ms (bogus deadline?)",
                );
                // now >= due, so the timer is due and fires.
                let fired = ex_hermes_poll(runtime, ex_hermes_now_ms());
                assert!(fired >= 1, "{label}: clamped-to-0 timer must fire");
                let (_, value) = eval(runtime, "String(globalThis.__f)");
                assert_eq!(
                    value.as_deref(),
                    Some("1"),
                    "{label}: callback should run once"
                );
                assert_eq!(
                    ex_hermes_next_timer(runtime),
                    -1,
                    "{label}: one-shot retired"
                );
            }

            ex_hermes_destroy(runtime);
        }
    }

    /// DNS and filesystem pool jobs retain JSI promise callbacks off-thread.
    /// Destroy must enter Closing, wait for those producers to publish their
    /// callbacks, and discard the captures on this owner thread before Hermes
    /// is deleted. Recreating immediately exercises allocator address reuse.
    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn destroy_drains_delayed_dns_and_fs_producers_before_recreate() {
        let _host_guard = crate::host::abi::host_test_lock();
        let temp = std::env::temp_dir().join(format!(
            "ibex-runtime-lifetime-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&temp, b"lifetime").expect("write async lifetime fixture");

        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", &format!("fs:read:{}", temp.display()), None);
        host.capabilities()
            .grant("*", "network:resolve:localhost", None);
        crate::host::abi::install_host(host);
        let _delay_guard = RuntimeCallbackDelayGuard::new(100);

        unsafe {
            let first = ex_hermes_create_diagnostic();
            assert!(!first.is_null());
            let path = serde_json::to_string(&temp.to_string_lossy()).unwrap();
            let (status, value) = eval(
                first,
                &format!("require('fs'); __exactFsReadFileAsync({path}); 'fs-queued'"),
            );
            // Measure from job submission, not from destroy: the worker holds
            // ~100ms after this eval, so a draining destroy cannot return
            // earlier than submission + hold regardless of how long the test
            // scheduler stalls between eval and destroy. Measuring from
            // destroy false-fails under parallel-load contention once the
            // hold has already expired.
            let submitted = std::time::Instant::now();
            assert_eq!((status, value.as_deref()), (0, Some("fs-queued")));
            ex_hermes_destroy(first);
            assert!(
                submitted.elapsed() >= std::time::Duration::from_millis(60),
                "destroy returned before the pinned filesystem worker drained"
            );

            let second = ex_hermes_create_diagnostic();
            assert!(!second.is_null());
            let (status, value) = eval(
                second,
                "require('dns'); __exactDnsLookupAsync('localhost', 4); 'dns-queued'",
            );
            // Submission-anchored for the same reason as the fs block above.
            let submitted = std::time::Instant::now();
            assert_eq!((status, value.as_deref()), (0, Some("dns-queued")));
            ex_hermes_destroy(second);
            assert!(
                submitted.elapsed() >= std::time::Duration::from_millis(60),
                "destroy returned before the pinned DNS worker drained"
            );

            let third = ex_hermes_create_diagnostic();
            assert!(!third.is_null());
            assert_eq!(
                eval(third, "'fresh-runtime'").1.as_deref(),
                Some("fresh-runtime")
            );
            ex_hermes_destroy(third);
        }
        let _ = std::fs::remove_file(temp);
    }

    /// Fetch backends may complete after cancellation. The native callback
    /// takes its nonce-bearing target before this injected delay; destroy and
    /// immediate recreate must make the later pin fail instead of delivering
    /// old-runtime JSI handles into a reused address.
    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn delayed_fetch_completion_cannot_enter_recreated_runtime() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let _host_guard = crate::host::abi::host_test_lock();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fetch lifetime server");
        let port = listener.local_addr().unwrap().port();
        let (responded_tx, responded_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fetch lifetime request");
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write fetch lifetime response");
            let _ = stream.flush();
            responded_tx.send(()).unwrap();
        });

        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", "network:fetch:127.0.0.1", None);
        crate::host::abi::install_host(host);
        let _delay_guard = RuntimeCallbackDelayGuard::new(150);

        unsafe {
            let first = ex_hermes_create_diagnostic();
            assert!(!first.is_null());
            let source = format!(
                "__nativeFetch('http://127.0.0.1:{port}/', {{method:'GET'}}, null); 'fetch-queued'"
            );
            assert_eq!(eval(first, &source).1.as_deref(), Some("fetch-queued"));
            responded_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("native fetch reached local server");
            std::thread::sleep(std::time::Duration::from_millis(25));
            ex_hermes_destroy(first);

            let second = ex_hermes_create_diagnostic();
            assert!(!second.is_null());
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert_eq!(
                eval(second, "'fresh-after-fetch'").1.as_deref(),
                Some("fresh-after-fetch")
            );
            ex_hermes_destroy(second);
        }

        server.join().expect("fetch lifetime server thread");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    static HOST_CALL_ASYNC_LAST_ID: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    #[cfg(feature = "capsec-conformance-observer")]
    extern "C" fn capture_host_call_async_id(
        _runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        _op: *const c_char,
        _args_json: *const c_char,
    ) {
        HOST_CALL_ASYNC_LAST_ID.store(call_id, std::sync::atomic::Ordering::SeqCst);
    }

    /// A fetch completion enqueues its resolve/reject closures from the
    /// network thread, and the runtime thread may run AND release that queued
    /// callback before the network worker's frame unwinds. The queued
    /// callback must therefore be the sole owner: both final releases must
    /// land on the runtime thread while the producer is still parked in the
    /// post-enqueue hold. (issues/20260726-native-fetch-jsi-last-owner-race.md)
    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn fetch_completion_releases_jsi_owners_on_runtime_thread_only() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let _host_guard = crate::host::abi::host_test_lock();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fetch owner server");
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fetch owner request");
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write fetch owner response");
            let _ = stream.flush();
        });

        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", "network:fetch:127.0.0.1", None);
        crate::host::abi::install_host(host);
        let _hold_guard = RuntimeProducerHoldGuard::new(1500);

        unsafe {
            ibex_test_reset_jsi_owner_release_observer();
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let source = format!(
                "globalThis.__settled = 0; __nativeFetch('http://127.0.0.1:{port}/', {{method:'GET'}}, null).then(function () {{ globalThis.__settled = 1; }}, function () {{ globalThis.__settled = 2; }}); 'queued'"
            );
            assert_eq!(eval(runtime, &source).1.as_deref(), Some("queued"));

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                ex_hermes_poll(runtime, ex_hermes_now_ms());
                let (_, settled) = eval(runtime, "String(globalThis.__settled)");
                match settled.as_deref() {
                    Some("1") => break,
                    Some("2") => panic!("native fetch rejected in owner-release test"),
                    _ => {}
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "fetch completion never settled"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }

            // The completion ran to the end of the poll drain, so its queued
            // entry is already released — on the runtime thread — while the
            // network worker is still parked. A copy-capture regression leaves
            // the final owners with the parked worker and this reads 0.
            assert_eq!(ibex_test_jsi_owner_final_releases_on_owner_thread(), 2);
            assert_eq!(ibex_test_jsi_owner_final_releases_off_owner_thread(), 0);

            // Destroy waits out the parked producer's native pin, proving the
            // runtime callback finished before the producer returned.
            let started = std::time::Instant::now();
            ex_hermes_destroy(runtime);
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(100),
                "destroy returned before the held fetch producer drained"
            );
        }
        // The producer frame unwinds just after releasing its pin; give those
        // last locals a beat, then require that nothing released off-thread.
        std::thread::sleep(std::time::Duration::from_millis(100));
        unsafe {
            assert_eq!(ibex_test_jsi_owner_final_releases_off_owner_thread(), 0);
        }

        server.join().expect("fetch owner server thread");
    }

    /// Sibling coverage for ex_hermes_resolve_host_call: an any-thread
    /// host-call completion must also leave the queued callback as the sole
    /// JSI owner, with both final releases on the runtime thread. Joining the
    /// resolver thread makes the producer-side check fully deterministic.
    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn host_call_completion_releases_jsi_owners_on_runtime_thread_only() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::strict();
        crate::host::abi::install_host(host);
        let _hold_guard = RuntimeProducerHoldGuard::new(1500);

        unsafe {
            ibex_test_reset_jsi_owner_release_observer();
            HOST_CALL_ASYNC_LAST_ID.store(0, std::sync::atomic::Ordering::SeqCst);
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            ex_hermes_set_host_call_async(runtime, capture_host_call_async_id);
            let (status, value) = eval(
                runtime,
                "globalThis.__settled = 0; __hostCallAsync('ping', {}).then(function () { globalThis.__settled = 1; }, function () { globalThis.__settled = 2; }); 'queued'",
            );
            assert_eq!((status, value.as_deref()), (0, Some("queued")));
            let call_id = HOST_CALL_ASYNC_LAST_ID.load(std::sync::atomic::Ordering::SeqCst);
            assert_ne!(call_id, 0, "__hostCallAsync must register a call id");

            let runtime_addr = runtime as usize;
            let resolver = std::thread::spawn(move || {
                let payload = std::ffi::CString::new("+{\"ok\":true}").unwrap();
                unsafe {
                    ex_hermes_resolve_host_call(
                        runtime_addr as *mut HermesRuntimeOpaque,
                        call_id,
                        payload.as_ptr(),
                    );
                }
            });

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                ex_hermes_poll(runtime, ex_hermes_now_ms());
                let (_, settled) = eval(runtime, "String(globalThis.__settled)");
                match settled.as_deref() {
                    Some("1") => break,
                    Some("2") => panic!("__hostCallAsync rejected in owner-release test"),
                    _ => {}
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "host-call completion never settled"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }

            // The resolver thread is still parked in the post-enqueue hold and
            // the runtime thread has already released both closures.
            assert_eq!(ibex_test_jsi_owner_final_releases_on_owner_thread(), 2);
            assert_eq!(ibex_test_jsi_owner_final_releases_off_owner_thread(), 0);

            // Joining unwinds the producer frame completely; any owner it
            // still held would now show up as an off-thread final release.
            resolver.join().expect("host-call resolver thread");
            assert_eq!(ibex_test_jsi_owner_final_releases_off_owner_thread(), 0);
            ex_hermes_destroy(runtime);
        }
    }

    /// Stress the real NSURLSession completion path: many concurrent fetch
    /// completions racing the runtime thread must never finally release a JSI
    /// owner off the owner thread and must not crash the delegate thread.
    /// (issues/20260726-native-fetch-jsi-last-owner-race.md)
    #[cfg(all(target_os = "macos", feature = "capsec-conformance-observer"))]
    #[test]
    fn native_fetch_nsurlsession_stress_releases_owners_on_runtime_thread() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        const TOTAL_FETCHES: usize = 48;

        let _host_guard = crate::host::abi::host_test_lock();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fetch stress server");
        let port = listener.local_addr().unwrap().port();
        listener
            .set_nonblocking(true)
            .expect("nonblocking fetch stress listener");
        let stop = Arc::new(AtomicBool::new(false));
        let accept_stop = stop.clone();
        let server = std::thread::spawn(move || {
            let mut handlers = Vec::new();
            while !accept_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        handlers.push(std::thread::spawn(move || {
                            let _ = stream.set_nonblocking(false);
                            let mut request = [0u8; 2048];
                            let _ = stream.read(&mut request);
                            let _ = stream.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                            );
                            let _ = stream.flush();
                        }));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
            for handler in handlers {
                let _ = handler.join();
            }
        });

        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", "network:fetch:127.0.0.1", None);
        crate::host::abi::install_host(host);

        unsafe {
            ibex_test_reset_jsi_owner_release_observer();
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let total = TOTAL_FETCHES;
            let source = format!(
                "globalThis.__done = 0; globalThis.__fail = 0; for (var i = 0; i < {total}; i++) {{ __nativeFetch('http://127.0.0.1:{port}/', {{method:'GET'}}, null).then(function () {{ globalThis.__done++; }}, function () {{ globalThis.__fail++; }}); }} 'stress-queued'"
            );
            assert_eq!(eval(runtime, &source).1.as_deref(), Some("stress-queued"));

            let want = TOTAL_FETCHES.to_string();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                ex_hermes_poll(runtime, ex_hermes_now_ms());
                let (_, settled) = eval(runtime, "String(globalThis.__done + globalThis.__fail)");
                if settled.as_deref() == Some(want.as_str()) {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "stress fetches never settled: {settled:?}"
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let (_, failed) = eval(runtime, "String(globalThis.__fail)");
            assert_eq!(
                failed.as_deref(),
                Some("0"),
                "stress fetches must all resolve"
            );
            ex_hermes_destroy(runtime);
        }
        // Give the last NSURLSession workers a beat to unwind, then require
        // every tracked release to have happened on the owner thread.
        std::thread::sleep(std::time::Duration::from_millis(150));
        unsafe {
            assert_eq!(
                ibex_test_jsi_owner_final_releases_on_owner_thread(),
                (TOTAL_FETCHES as u64) * 2
            );
            assert_eq!(ibex_test_jsi_owner_final_releases_off_owner_thread(), 0);
        }

        stop.store(true, Ordering::SeqCst);
        server.join().expect("fetch stress server thread");
    }

    #[cfg(all(feature = "host-http-server", feature = "capsec-conformance-observer"))]
    #[test]
    fn destroy_cancels_and_drains_delayed_http_wait_before_recreate() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", "network:listen:127.0.0.1:0", None);
        crate::host::abi::install_host(host);
        let _delay_guard = RuntimeCallbackDelayGuard::new(100);

        unsafe {
            let first = ex_hermes_create_diagnostic();
            assert!(!first.is_null());
            let (status, value) = eval(
                first,
                "require('http'); var __lifeServer = JSON.parse(__exactHttpServe(0, '127.0.0.1')); __exactHttpWait(__lifeServer.id, 5000); 'http-queued'",
            );
            assert_eq!((status, value.as_deref()), (0, Some("http-queued")));
            let started = std::time::Instant::now();
            ex_hermes_destroy(first);
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(60),
                "destroy returned before the pinned HTTP waiter drained"
            );

            let second = ex_hermes_create_diagnostic();
            assert!(!second.is_null());
            assert_eq!(
                eval(second, "'fresh-after-http'").1.as_deref(),
                Some("fresh-after-http")
            );
            ex_hermes_destroy(second);
        }
    }

    #[cfg(target_os = "windows")]
    mod windows_native_smoke {
        use super::*;
        use base64::{engine::general_purpose, Engine as _};
        use sha1::{Digest, Sha1};
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::{Duration, Instant};

        struct RuntimeGuard(*mut HermesRuntimeOpaque);

        impl RuntimeGuard {
            fn new() -> Self {
                crate::host::abi::install_host(crate::host::Host::default_legacy());
                unsafe {
                    let runtime = ex_hermes_create_diagnostic();
                    assert!(!runtime.is_null());
                    Self(runtime)
                }
            }

            fn as_ptr(&self) -> *mut HermesRuntimeOpaque {
                self.0
            }
        }

        impl Drop for RuntimeGuard {
            fn drop(&mut self) {
                unsafe { ex_hermes_destroy(self.0) };
            }
        }

        fn eval_ok(runtime: *mut HermesRuntimeOpaque, source: &str) -> Option<String> {
            let (status, value) = eval(runtime, source);
            assert_eq!(status, 0, "eval failed: {value:?}");
            value
        }

        fn eval_ok_with_permissive_host(
            runtime: *mut HermesRuntimeOpaque,
            source: &str,
        ) -> Option<String> {
            crate::host::abi::install_host(crate::host::Host::default_legacy());
            let (mut status, mut value) = eval(runtime, source);
            if status != 0
                && value
                    .as_deref()
                    .is_some_and(|message| message.contains("Permission denied"))
            {
                crate::host::abi::install_host(crate::host::Host::default_legacy());
                (status, value) = eval(runtime, source);
            }
            assert_eq!(status, 0, "eval failed: {value:?}");
            value
        }

        fn json_string(value: &str) -> String {
            serde_json::to_string(value).expect("JSON string")
        }

        fn install_ascii_text_encoder(runtime: *mut HermesRuntimeOpaque) {
            let value = eval_ok(
                runtime,
                r#"
                if (typeof TextEncoder === 'undefined') {
                  globalThis.TextEncoder = function TextEncoder() {};
                  TextEncoder.prototype.encode = function(value) {
                    var text = String(value);
                    var out = new Uint8Array(text.length);
                    for (var i = 0; i < text.length; i++) {
                      out[i] = text.charCodeAt(i) & 255;
                    }
                    return out;
                  };
                }
                'text-encoder-ready';
                "#,
            );
            assert_eq!(value.as_deref(), Some("text-encoder-ready"));
        }

        fn wait_for_js_result(runtime: *mut HermesRuntimeOpaque, expression: &str) -> String {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut tick = u64::MAX / 4;
            while Instant::now() < deadline {
                let poll_status = unsafe { ex_hermes_poll(runtime, tick) };
                assert!(
                    poll_status >= 0,
                    "Hermes poll failed while waiting for {expression}"
                );
                tick = tick.saturating_add(20);

                let value = eval_ok(runtime, expression).unwrap_or_default();
                if !value.is_empty() {
                    return value;
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("timed out waiting for {expression}");
        }

        fn read_http_headers(stream: &mut TcpStream) -> String {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let read = stream.read(&mut buf).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            String::from_utf8_lossy(&request).into_owned()
        }

        fn spawn_http_server() -> (String, thread::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind HTTP server");
            let port = listener.local_addr().expect("HTTP local addr").port();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept HTTP client");
                let request = read_http_headers(&mut stream);
                assert!(request.starts_with("GET /native-fetch "));
                let body = b"ibex-winhttp-fetch";
                let response = format!(
                    "HTTP/1.1 203 Non-Authoritative Information\r\n\
                     Content-Length: {}\r\n\
                     Content-Type: text/plain\r\n\
                     X-Ibex-Backend: winhttp\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write HTTP headers");
                stream.write_all(body).expect("write HTTP body");
            });
            (format!("http://127.0.0.1:{port}/native-fetch"), handle)
        }

        fn websocket_accept_key(client_key: &str) -> String {
            let mut sha = Sha1::new();
            sha.update(client_key.as_bytes());
            sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            general_purpose::STANDARD.encode(sha.finalize())
        }

        fn read_websocket_text_frame(stream: &mut TcpStream) -> String {
            let mut header = [0u8; 2];
            stream
                .read_exact(&mut header)
                .expect("read WebSocket frame header");
            assert_eq!(header[0] & 0x0f, 0x1, "expected text frame");
            let masked = (header[1] & 0x80) != 0;
            assert!(masked, "client WebSocket frames must be masked");
            let mut len = (header[1] & 0x7f) as usize;
            if len == 126 {
                let mut ext = [0u8; 2];
                stream
                    .read_exact(&mut ext)
                    .expect("read extended frame length");
                len = u16::from_be_bytes(ext) as usize;
            } else if len == 127 {
                let mut ext = [0u8; 8];
                stream
                    .read_exact(&mut ext)
                    .expect("read extended frame length");
                len = u64::from_be_bytes(ext) as usize;
            }
            let mut mask = [0u8; 4];
            stream.read_exact(&mut mask).expect("read frame mask");
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).expect("read frame payload");
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
            String::from_utf8(payload).expect("text frame utf8")
        }

        fn write_websocket_text_frame(stream: &mut TcpStream, text: &str) {
            let payload = text.as_bytes();
            let mut frame = vec![0x81];
            if payload.len() < 126 {
                frame.push(payload.len() as u8);
            } else {
                frame.push(126);
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            frame.extend_from_slice(payload);
            stream
                .write_all(&frame)
                .expect("write WebSocket text frame");
        }

        fn spawn_websocket_echo_server() -> (String, thread::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind WebSocket server");
            let port = listener.local_addr().expect("WebSocket local addr").port();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept WebSocket client");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set WebSocket timeout");
                let request = read_http_headers(&mut stream);
                let key = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.eq_ignore_ascii_case("sec-websocket-key") {
                            Some(value.trim().to_string())
                        } else {
                            None
                        }
                    })
                    .expect("Sec-WebSocket-Key header");
                let accept = websocket_accept_key(&key);
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write WebSocket handshake");
                let message = read_websocket_text_frame(&mut stream);
                assert_eq!(message, "ibex-winhttp-websocket");
                write_websocket_text_frame(&mut stream, "winhttp-websocket-echo");
                thread::sleep(Duration::from_millis(250));
                let _ = stream.write_all(&[0x88, 0x02, 0x03, 0xe8]);
            });
            (format!("ws://127.0.0.1:{port}/native-websocket"), handle)
        }

        fn spawn_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind TCP server");
            let port = listener.local_addr().expect("TCP local addr").port();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept TCP client");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set TCP timeout");
                let mut buf = [0u8; 64];
                let read = stream.read(&mut buf).expect("read TCP payload");
                assert_eq!(&buf[..read], b"ibex-winsock-tcp");
                stream
                    .write_all(b"winsock-tcp-echo")
                    .expect("write TCP echo");
            });
            (port, handle)
        }

        #[test]
        fn windows_runtime_uses_native_platform_backends() {
            let _host_guard = crate::host::abi::host_test_lock();
            let runtime = RuntimeGuard::new();
            install_ascii_text_encoder(runtime.as_ptr());

            let tempdir = tempfile::tempdir().expect("tempdir");
            let file = tempdir.path().join("native-fs.txt");
            let file_js = json_string(file.to_str().expect("utf8 temp path"));
            let sync_source = format!(
                r#"(function() {{
                  var crypto = require('crypto');
                  var fs = require('fs');
                  var os = require('os');
                  var cp = require('child_process');
                  var file = {file_js};
                  fs.writeFileSync(file, 'ibex-windows-fs');
                  var fsText = fs.readFileSync(file, 'utf8');
                  var hash = crypto.createHash('sha256').update('abc').digest('hex');
                  var hmac = crypto.createHmac('sha256', 'key').update('abc').digest('hex');
                  var spawn = cp.spawnSync('cmd.exe', ['/d', '/c', 'echo ibex-windows-spawn']);
                  var stdout = spawn.stdout && typeof spawn.stdout.toString === 'function'
                    ? spawn.stdout.toString()
                    : String(spawn.stdout || '');
                  return [
                    process.platform,
                    os.platform(),
                    String(os.totalmem() > 0),
                    hash,
                    hmac,
                    fsText,
                    String(fs.statSync(file).isFile()),
                    String(spawn.status),
                    stdout.replace(/\s+$/, '')
                  ].join('|');
                }})()"#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &sync_source).as_deref(),
                Some(
                    "win32|win32|true|\
                     ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad|\
                     9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab|\
                     ibex-windows-fs|true|0|ibex-windows-spawn"
                )
            );

            let (fetch_url, fetch_server) = spawn_http_server();
            let fetch_url_js = json_string(&fetch_url);
            let fetch_source = format!(
                r#"
                globalThis.__windowsNativeFetch = {{ done: false, result: '' }};
                fetch({fetch_url_js}).then(function(response) {{
                  return response.text().then(function(text) {{
                    globalThis.__windowsNativeFetch.result =
                      String(response.status) + ':' + response.headers.get('x-ibex-backend') + ':' + text;
                    globalThis.__windowsNativeFetch.done = true;
                  }});
                }}, function(error) {{
                  globalThis.__windowsNativeFetch.result = 'ERR:' + (error && error.message || String(error));
                  globalThis.__windowsNativeFetch.done = true;
                }});
                'armed';
                "#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &fetch_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeFetch.done ? globalThis.__windowsNativeFetch.result : ''",
                ),
                "203:winhttp:ibex-winhttp-fetch"
            );
            fetch_server.join().expect("HTTP server thread");

            let (ws_url, ws_server) = spawn_websocket_echo_server();
            let ws_url_js = json_string(&ws_url);
            let ws_source = format!(
                r#"
                globalThis.__windowsNativeWs = {{ done: false, result: '' }};
                var ws = new WebSocket({ws_url_js});
                ws.onopen = function() {{
                  ws.send('ibex-winhttp-websocket');
                }};
                ws.onmessage = function(event) {{
                  globalThis.__windowsNativeWs.result = 'ws:' + event.data;
                  globalThis.__windowsNativeWs.done = true;
                  ws.close(1000, 'done');
                }};
                ws.onerror = function(event) {{
                  globalThis.__windowsNativeWs.result = 'ERR:' + (event && event.message || 'websocket error');
                  globalThis.__windowsNativeWs.done = true;
                }};
                'armed';
                "#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &ws_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeWs.done ? globalThis.__windowsNativeWs.result : ''",
                ),
                "ws:winhttp-websocket-echo"
            );
            ws_server.join().expect("WebSocket server thread");

            let dns_source = r#"
              globalThis.__windowsNativeDns = { done: false, result: '' };
              require('dns').lookup('localhost', { family: 4 }, function(error, address, family) {
                var normalizedFamily = family === 'IPv4' ? 4 : family;
                globalThis.__windowsNativeDns.result = error
                  ? 'ERR:' + (error.code || error.message)
                  : 'dns:' + String(normalizedFamily) + ':' + String(!!address);
                globalThis.__windowsNativeDns.done = true;
              });
              'armed';
            "#;
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), dns_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeDns.done ? globalThis.__windowsNativeDns.result : ''",
                ),
                "dns:4:true"
            );

            let (tcp_port, tcp_server) = spawn_tcp_echo_server();
            let tcp_source = format!(
                r#"
                globalThis.__windowsNativeTcp = {{ done: false, result: '' }};
                // Structural lockdown eagerly runs and then seals the private
                // lazy installer; the installed TCP bridge is what this smoke
                // exercises. @ref LLP 0013#phase-1
                var tcpHandle = __exactTcpConnect('127.0.0.1', {tcp_port}, null, null);
                __exactTcpWrite(tcpHandle, 'ibex-winsock-tcp');
                function __tcpBytesToText(bytes) {{
                  if (bytes === null || bytes === '') return '';
                  var out = '';
                  for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
                  return out;
                }}
                function __pollTcp() {{
                  try {{
                    var chunk = __exactTcpRead(tcpHandle, 65536);
                    if (chunk === '') {{
                      setTimeout(__pollTcp, 5);
                      return;
                    }}
                    if (chunk === null) {{
                      globalThis.__windowsNativeTcp.result = 'ERR:closed';
                      globalThis.__windowsNativeTcp.done = true;
                      return;
                    }}
                    globalThis.__windowsNativeTcp.result = 'tcp:' + __tcpBytesToText(chunk);
                    globalThis.__windowsNativeTcp.done = true;
                    __exactTcpClose(tcpHandle);
                  }} catch (error) {{
                    globalThis.__windowsNativeTcp.result = 'ERR:' + (error && error.message || String(error));
                    globalThis.__windowsNativeTcp.done = true;
                  }}
                }}
                __pollTcp();
                'armed';
                "#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &tcp_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeTcp.done ? globalThis.__windowsNativeTcp.result : ''",
                ),
                "tcp:winsock-tcp-echo"
            );
            tcp_server.join().expect("TCP server thread");
        }
    }
}
