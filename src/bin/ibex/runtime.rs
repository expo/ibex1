//! Runtime orchestration for the `ibex` CLI.
//!
//! This module wires together the engine, host configuration, security policy,
//! and build/transpile helpers used by the CLI entrypoints.

use crate::agent_logs;
use crate::cli::{BundleFormat, Cli};
use crate::engine::{self, Engine, EngineFeature};
use crate::host::{Host, HostConfig};
use crate::subprocess::{output_with_timeout, timeout_from_env, DEFAULT_BUNDLER_TIMEOUT_MS};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Set when bytecode loading fails (e.g. version mismatch between hermesc
/// and the embedded Hermes runtime). Once set, we skip further bytecode
/// compilation attempts for the rest of the process lifetime.
static BYTECODE_INCOMPATIBLE: AtomicBool = AtomicBool::new(false);

const RELEASE_POLICY_TOOLCHAIN_DIGEST: Option<&str> =
    option_env!("IBEX_RELEASE_POLICY_TOOLCHAIN_DIGEST");

#[cfg(feature = "module-runner")]
const LEGACY_MODULE_LOADER_LAST_SUPPORTED_MINOR: &str = "0.1";

#[cfg(all(test, feature = "module-runner"))]
static PREPARED_ACTIVATION_LOCATOR_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(feature = "module-runner")]
fn legacy_module_loader_window_is_open() -> bool {
    let version = env!("CARGO_PKG_VERSION");
    let in_bounded_release = version == LEGACY_MODULE_LOADER_LAST_SUPPORTED_MINOR
        || version.starts_with(&format!("{LEGACY_MODULE_LOADER_LAST_SUPPORTED_MINOR}."));
    let explicitly_disabled = std::env::var("IBEX_LEGACY_MODULE_LOADER")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "0" | "false" | "FALSE" | "no" | "NO"));
    in_bounded_release && !explicitly_disabled
}

#[cfg(feature = "module-runner")]
// @ref LLP 0026#performance-and-platform-gates — native admission is exact
// to the target tuples carrying matching evaluator and compartment artifacts.
fn native_module_runner_target_is_advertised(os: &str, arch: &str) -> bool {
    matches!((os, arch), ("macos", "aarch64") | ("linux", "x86_64"))
}

/// Test-only selector for preserving the bounded compatibility loader instead
/// of preparing an entry through the ordinary producer/bundler path. Fixture
/// fidelity remains independently selected by `EXACT_COMPAT_TEST` inside the
/// compat harness and runtime shims.
/// @ref LLP 0028#4-reachability-inventory-and-retirement-matrix
fn compat_loader_fixture_mode() -> bool {
    std::env::var_os("IBEX_COMPAT_LOADER_TEST").is_some()
}

#[cfg(feature = "module-runner")]
fn current_native_module_runner_target_is_advertised() -> bool {
    native_module_runner_target_is_advertised(std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(feature = "module-runner")]
static MODULE_PRODUCER_BINARY_DIGEST: OnceLock<
    std::result::Result<capsec_semantics::model::Digest, String>,
> = OnceLock::new();

#[cfg(feature = "module-runner")]
fn cached_module_producer_binary_digest(
    cache: &OnceLock<std::result::Result<capsec_semantics::model::Digest, String>>,
    capture: impl FnOnce() -> Result<capsec_semantics::model::Digest>,
) -> Result<capsec_semantics::model::Digest> {
    // Inline artifacts are admitted against the one producer executing in
    // this process. Capture that identity once: rebuilding the complete graph
    // during request admission must not re-read and re-hash a large executable
    // after an identical authenticated preflight. A failed capture is cached
    // too, so one process cannot change producer identity after admission has
    // begun. Capture itself authenticates the mapped file object below.
    // @ref LLP 0027#canonical-encoding-and-validation
    // @ref LLP 0026#performance-and-platform-gates
    match cache.get_or_init(|| {
        let result = capture();
        result.map_err(|error: anyhow::Error| format!("{error:#}"))
    }) {
        Ok(digest) => Ok(digest.clone()),
        Err(error) => anyhow::bail!("capture module producer binary identity: {error}"),
    }
}

#[cfg(all(feature = "module-runner", unix, any(not(feature = "insecure"), test)))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModuleProducerObject {
    device: u64,
    inode: u64,
}

#[cfg(all(feature = "module-runner", unix, any(not(feature = "insecure"), test)))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModuleProducerFileState {
    object: ModuleProducerObject,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(all(feature = "module-runner", unix, any(not(feature = "insecure"), test)))]
fn module_producer_file_state(metadata: &std::fs::Metadata) -> ModuleProducerFileState {
    use std::os::unix::fs::MetadataExt as _;

    ModuleProducerFileState {
        object: ModuleProducerObject {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(all(feature = "module-runner", unix, any(not(feature = "insecure"), test)))]
fn capture_module_producer_binary_digest_from_path(
    path: &Path,
    expected_object: ModuleProducerObject,
    no_follow: bool,
) -> Result<capsec_semantics::model::Digest> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | if no_follow { libc::O_NOFOLLOW } else { 0 });
    let mut file = options
        .open(path)
        .with_context(|| format!("pin mapped module producer {}", path.display()))?;
    let before_metadata = file.metadata().context("inspect mapped module producer")?;
    anyhow::ensure!(
        before_metadata.is_file(),
        "mapped module producer is not a regular file"
    );
    let before = module_producer_file_state(&before_metadata);
    anyhow::ensure!(
        before.object == expected_object,
        "module producer path names a different object than the running image"
    );
    let digest = ibex_runtime::module_loader::artifact::digest_reader(
        "ibex/module-producer-binary/1",
        &mut file,
    )?;
    let after = module_producer_file_state(
        &file
            .metadata()
            .context("revalidate mapped module producer")?,
    );
    anyhow::ensure!(
        after == before,
        "mapped module producer changed while it was authenticated"
    );
    Ok(digest)
}

#[cfg(all(
    feature = "module-runner",
    not(feature = "insecure"),
    target_os = "macos"
))]
fn mapped_module_producer_object() -> Result<ModuleProducerObject> {
    #[repr(C)]
    struct ProcRegionInfo {
        protection: u32,
        maximum_protection: u32,
        inheritance: u32,
        flags: u32,
        offset: u64,
        behavior: u32,
        user_wired_count: u32,
        user_tag: u32,
        pages_resident: u32,
        pages_shared_now_private: u32,
        pages_swapped_out: u32,
        pages_dirtied: u32,
        reference_count: u32,
        shadow_depth: u32,
        share_mode: u32,
        private_pages_resident: u32,
        shared_pages_resident: u32,
        object_id: u32,
        depth: u32,
        address: u64,
        size: u64,
    }

    #[repr(C)]
    struct ProcRegionWithPathInfo {
        region: ProcRegionInfo,
        vnode: libc::vnode_info_path,
    }

    const PROC_PIDREGIONPATHINFO: libc::c_int = 8;
    let mut region = std::mem::MaybeUninit::<ProcRegionWithPathInfo>::zeroed();
    let address = module_producer_mapping_anchor as *const () as usize as u64;
    let expected_size = std::mem::size_of::<ProcRegionWithPathInfo>();
    let bytes = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            PROC_PIDREGIONPATHINFO,
            address,
            region.as_mut_ptr().cast(),
            expected_size
                .try_into()
                .context("module producer region record is too large")?,
        )
    };
    anyhow::ensure!(
        bytes >= 0 && bytes as usize == expected_size,
        "identify the mapped module producer object"
    );
    let region = unsafe { region.assume_init() };
    let object = ModuleProducerObject {
        device: u64::from(region.vnode.vip_vi.vi_stat.vst_dev),
        inode: region.vnode.vip_vi.vi_stat.vst_ino,
    };
    anyhow::ensure!(object.inode != 0, "mapped module producer has no inode");
    Ok(object)
}

#[cfg(all(
    feature = "module-runner",
    not(feature = "insecure"),
    target_os = "linux"
))]
fn mapped_module_producer_object() -> Result<ModuleProducerObject> {
    let metadata = std::fs::metadata("/proc/self/exe")
        .context("identify the kernel-bound module producer object")?;
    Ok(module_producer_file_state(&metadata).object)
}

#[cfg(all(
    feature = "module-runner",
    not(feature = "insecure"),
    not(any(target_os = "macos", target_os = "linux", windows))
))]
fn capture_module_producer_binary_digest() -> Result<capsec_semantics::model::Digest> {
    anyhow::bail!("this target cannot authenticate its mapped module producer image")
}

#[cfg(all(
    feature = "module-runner",
    not(feature = "insecure"),
    any(target_os = "macos", target_os = "linux", windows)
))]
#[inline(never)]
fn module_producer_mapping_anchor() {}

#[cfg(all(feature = "module-runner", windows))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsModuleProducerFileState {
    object: capsec_semantics::model::ObjectIdentity,
    length: u64,
    creation_time: u64,
    last_write_time: u64,
}

#[cfg(all(feature = "module-runner", windows))]
fn windows_module_producer_file_state(
    file: &std::fs::File,
) -> Result<WindowsModuleProducerFileState> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = file.metadata().context("inspect mapped module producer")?;
    anyhow::ensure!(
        metadata.is_file(),
        "mapped module producer is not a regular file"
    );
    anyhow::ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "mapped module producer is a reparse point"
    );
    Ok(WindowsModuleProducerFileState {
        object: ibex_runtime::host::object_identity_for_open_file(file)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .context("identify mapped Windows module producer")?,
        length: metadata.len(),
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
    })
}

#[cfg(all(feature = "module-runner", windows))]
fn open_windows_module_producer(path: &Path) -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        // Retain the exact object while hashing and deny a later writer,
        // rename, or delete from invalidating the loader-path observation.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options
        .open(path)
        .with_context(|| format!("pin mapped module producer {}", path.display()))
}

#[cfg(all(feature = "module-runner", windows))]
fn mapped_windows_module_producer() -> Result<(windows_sys::Win32::Foundation::HMODULE, PathBuf)> {
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    };

    let mut module = std::ptr::null_mut();
    let anchor = module_producer_mapping_anchor as *const () as *const u16;
    let located = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            anchor,
            &mut module,
        )
    };
    anyhow::ensure!(
        located != 0 && !module.is_null(),
        "identify the Windows module containing the producer"
    );

    // Windows' extended-length pathname ceiling is 32,767 UTF-16 code units.
    // A fixed ceiling avoids accepting a silently truncated loader report.
    let mut path = vec![0u16; 32_768];
    let written = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) };
    anyhow::ensure!(
        written > 0 && (written as usize) < path.len(),
        "locate the mapped Windows module producer"
    );
    path.truncate(written as usize);
    let path = PathBuf::from(std::ffi::OsString::from_wide(&path));
    anyhow::ensure!(
        path.is_absolute(),
        "mapped Windows module producer path is not absolute"
    );
    Ok((module, path))
}

#[cfg(all(feature = "module-runner", windows))]
fn capture_windows_module_producer_digest_from_path(
    path: &Path,
    expected_object: &capsec_semantics::model::ObjectIdentity,
) -> Result<capsec_semantics::model::Digest> {
    let mut file = open_windows_module_producer(path)?;
    let before = windows_module_producer_file_state(&file)?;
    anyhow::ensure!(
        &before.object == expected_object,
        "module producer path names a different object than the running image"
    );
    let digest = ibex_runtime::module_loader::artifact::digest_reader(
        "ibex/module-producer-binary/1",
        &mut file,
    )?;
    let after = windows_module_producer_file_state(&file)?;
    anyhow::ensure!(
        after == before,
        "mapped module producer changed while it was authenticated"
    );

    // Reopen while the retained handle still denies writes and replacement.
    // This detects a parent reparse/pathname race without releasing the bytes
    // that supplied the accepted digest.
    let reopened = open_windows_module_producer(path)?;
    anyhow::ensure!(
        windows_module_producer_file_state(&reopened)?.object == before.object,
        "module producer path changed object while it was authenticated"
    );
    Ok(digest)
}

#[cfg(all(feature = "module-runner", windows))]
fn capture_module_producer_binary_digest() -> Result<capsec_semantics::model::Digest> {
    let (module, path) = mapped_windows_module_producer()?;
    let file = open_windows_module_producer(&path)?;
    let expected = windows_module_producer_file_state(&file)?.object;

    // GetModuleHandleEx(FROM_ADDRESS) attributes a code address in this Rust
    // module to the loader's exact executable mapping. Windows retains loaded
    // image names against replacement; our no-reparse, non-write-sharing
    // handle then pins that named file object while its exact bytes are hashed.
    // Re-query before and after capture so a loader/path transition cannot be
    // relabeled as the in-process Oxc producer.
    let (confirmed_module, confirmed_path) = mapped_windows_module_producer()?;
    anyhow::ensure!(
        confirmed_module == module && confirmed_path == path,
        "mapped Windows module producer changed before authentication"
    );
    let digest = capture_windows_module_producer_digest_from_path(&path, &expected)?;
    let (revalidated_module, revalidated_path) = mapped_windows_module_producer()?;
    anyhow::ensure!(
        revalidated_module == module && revalidated_path == path,
        "mapped Windows module producer changed during authentication"
    );
    let revalidated = open_windows_module_producer(&revalidated_path)?;
    anyhow::ensure!(
        windows_module_producer_file_state(&revalidated)?.object == expected,
        "mapped Windows module producer path changed object after authentication"
    );
    drop(file);
    Ok(digest)
}

#[cfg(all(
    feature = "module-runner",
    not(feature = "insecure"),
    any(target_os = "macos", target_os = "linux")
))]
fn capture_module_producer_binary_digest() -> Result<capsec_semantics::model::Digest> {
    let object = mapped_module_producer_object()?;
    #[cfg(target_os = "macos")]
    let (path, no_follow) = (
        std::env::current_exe().context("locate module producer executable")?,
        true,
    );
    #[cfg(target_os = "linux")]
    let (path, no_follow) = (PathBuf::from("/proc/self/exe"), false);
    capture_module_producer_binary_digest_from_path(&path, object, no_follow)
}

/// Insecure builds make no binary-authentication claim, so their inline
/// producer identity is the canonical transform contract rather than a hash of
/// the complete running executable. This preserves exact cache invalidation
/// for output-affecting producer changes without reading a large binary on
/// every one-shot process launch.
/// @ref LLP 0039#decision — insecure behavior is selected at compile time;
/// secure builds retain mapped-executable authentication above.
#[cfg(all(feature = "module-runner", feature = "insecure"))]
fn capture_module_producer_binary_digest() -> Result<capsec_semantics::model::Digest> {
    ibex_runtime::module_loader::producer_spike::module_artifact_transform_fingerprint_v1()?
        .digest()
}

#[cfg(feature = "module-runner")]
/// Select the identity of the in-process Oxc module producer. Secure builds
/// authenticate the mapped Ibex executable; insecure builds use the canonical
/// transform contract documented above.
/// @ref LLP 0027#canonical-encoding-and-validation — secure inline artifacts
/// bind the expected in-process producer binary.
pub(crate) fn module_producer_binary_digest() -> Result<capsec_semantics::model::Digest> {
    cached_module_producer_binary_digest(
        &MODULE_PRODUCER_BINARY_DIGEST,
        capture_module_producer_binary_digest,
    )
}

#[cfg(feature = "module-runner")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeRunnerTestProfile {
    Source,
    Prepared,
}

#[cfg(feature = "module-runner")]
impl NativeRunnerTestProfile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Prepared => "prepared",
        }
    }
}

/// Select the real-binary source/prepared conformance profile. This test seam
/// is deliberately absent from release execution even if an environment value
/// is supplied.
/// @ref LLP 0019#tier-3-the-rustoxc-module-artifact-producer
#[cfg(feature = "module-runner")]
pub(crate) fn native_runner_test_profile() -> Result<Option<NativeRunnerTestProfile>> {
    let Some(value) = std::env::var_os("IBEX_TEST_NATIVE_RUNNER_PROFILE") else {
        return Ok(None);
    };
    #[cfg(not(debug_assertions))]
    {
        let _ = value;
        anyhow::bail!("IBEX_TEST_NATIVE_RUNNER_PROFILE is unavailable in release builds");
    }
    #[cfg(debug_assertions)]
    match value.to_str() {
        Some("source") => Ok(Some(NativeRunnerTestProfile::Source)),
        Some("prepared") => Ok(Some(NativeRunnerTestProfile::Prepared)),
        _ => anyhow::bail!("IBEX_TEST_NATIVE_RUNNER_PROFILE must be source or prepared"),
    }
}

#[cfg(feature = "module-runner")]
fn native_runner_test_deployment_digest(
    graph: &ibex_runtime::module_loader::runner_pipeline::SourceModuleGraphV1,
) -> Result<capsec_semantics::model::Digest> {
    let records = graph
        .records()
        .map(|(source_id, _, verified)| {
            let artifact = verified.artifact();
            Ok(serde_json::json!({
                "sourceId": source_id.encode()?,
                "semanticDigest": artifact.semantic_digest,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let value = serde_json::json!({
        "schema": "ibex/native-runner-test-deployment/1",
        "entrySourceId": graph.entry().encode()?,
        "records": records,
    });
    let digest = capsec_semantics::digest::compute_domain_digest(
        "ibex:native-runner-test-deployment:1",
        &value,
        &[],
    )?;
    capsec_semantics::model::Digest::new(digest).map_err(anyhow::Error::msg)
}

/// Emit a receipt only after the engine has successfully executed the exact
/// graph. The engine calls this while it still owns any records added by
/// invocation-time activation, so the carrier inventory reflects what ran.
/// @ref LLP 0028#5-conformance-gates-telemetry-and-rollout
#[cfg(feature = "module-runner")]
pub(crate) fn emit_native_runner_execution_receipt(
    graph: &ibex_runtime::module_loader::runner_pipeline::SourceModuleGraphV1,
    profile: NativeRunnerTestProfile,
) -> Result<()> {
    use ibex_runtime::module_loader::artifact::{ModulePayloadV1, ProducerIdentityV1};

    let records = graph
        .records()
        .map(|(source_id, _, verified)| {
            let artifact = verified.artifact();
            let producer_binary_digest = match &artifact.producer {
                ProducerIdentityV1::InProcess {
                    producer_binary_digest,
                    ..
                }
                | ProducerIdentityV1::Prepared {
                    producer_binary_digest,
                    ..
                }
                | ProducerIdentityV1::PreparedPackage {
                    producer_binary_digest,
                    ..
                } => producer_binary_digest,
            };
            Ok(serde_json::json!({
                "sourceId": source_id.encode()?,
                "semanticDigest": artifact.semantic_digest,
                "transformFingerprintDigest": artifact.semantics.transform_fingerprint.digest()?,
                "carrierKind": match &artifact.payload {
                    ModulePayloadV1::Inline { .. } => "inline-source",
                    ModulePayloadV1::Carrier { .. } => "prepared-carrier",
                },
                "producerBinaryDigest": producer_binary_digest,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let hermes = crate::engine::hermes::HermesEngine::loaded_engine_identity()?;
    let receipt = serde_json::json!({
        "schema": "ibex/native-module-execution-receipt/1",
        "profile": profile.as_str(),
        "entrySourceId": graph.entry().encode()?,
        "loadedHermesDigest": hermes.binary_digest,
        "records": records,
    });
    let bytes = capsec_semantics::canonical::to_jcs_bytes(&receipt)?;
    eprintln!(
        "IBEX_NATIVE_MODULE_EXECUTION_RECEIPT {}",
        std::str::from_utf8(&bytes).expect("canonical JSON is UTF-8")
    );
    Ok(())
}

const WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP: &str = r#"(function(g) {
  if (g.__exactRuntimeLoaded === true) return;

  if (typeof g.TextEncoder !== 'function') {
    g.TextEncoder = function TextEncoder() {};
    g.TextEncoder.prototype.encode = function(value) {
      var str = String(value == null ? '' : value);
      var out = [];
      for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        if (code < 0x80) {
          out.push(code);
        } else if (code < 0x800) {
          out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
          var next = str.charCodeAt(++i);
          var cp = 0x10000 + (((code & 0x3ff) << 10) | (next & 0x3ff));
          out.push(
            0xf0 | (cp >> 18),
            0x80 | ((cp >> 12) & 0x3f),
            0x80 | ((cp >> 6) & 0x3f),
            0x80 | (cp & 0x3f)
          );
        } else {
          out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
      }
      return new Uint8Array(out);
    };
  }

  if (typeof g.TextDecoder !== 'function') {
    g.TextDecoder = function TextDecoder() {};
    g.TextDecoder.prototype.decode = function(input) {
      var bytes;
      if (input == null) {
        bytes = new Uint8Array(0);
      } else if (input instanceof ArrayBuffer) {
        bytes = new Uint8Array(input);
      } else if (ArrayBuffer.isView(input)) {
        bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
      } else {
        bytes = new Uint8Array(input);
      }
      var out = '';
      for (var i = 0; i < bytes.length;) {
        var b0 = bytes[i++];
        if (b0 < 0x80) {
          out += String.fromCharCode(b0);
        } else if ((b0 & 0xe0) === 0xc0) {
          var b1 = bytes[i++] || 0;
          out += String.fromCharCode(((b0 & 0x1f) << 6) | (b1 & 0x3f));
        } else if ((b0 & 0xf0) === 0xe0) {
          var b2 = bytes[i++] || 0;
          var b3 = bytes[i++] || 0;
          out += String.fromCharCode(((b0 & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f));
        } else {
          var b4 = bytes[i++] || 0;
          var b5 = bytes[i++] || 0;
          var b6 = bytes[i++] || 0;
          var cp = ((b0 & 0x07) << 18) | ((b4 & 0x3f) << 12) | ((b5 & 0x3f) << 6) | (b6 & 0x3f);
          cp -= 0x10000;
          out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
        }
      }
      return out;
    };
  }

  g.process = (typeof g.process === 'object' && g.process !== null) ? g.process : {};
  g.process.platform = g.process.platform || 'win32';
  g.process.env = g.process.env || {};
  g.process.cwd = typeof g.process.cwd === 'function' ? g.process.cwd : function cwd() {
    if (typeof g.__exactGetCwd === 'function') {
      var value = g.__exactGetCwd();
      if (typeof value === 'string' && value.length) return value;
    }
    return '.';
  };
  g.process.chdir = typeof g.process.chdir === 'function' ? g.process.chdir : function chdir(path) {
    if (typeof g.__exactSetCwd === 'function') {
      g.__exactSetCwd(String(path));
      return;
    }
    throw new Error('process.chdir is not available');
  };
  g.process.nextTick = typeof g.process.nextTick === 'function' ? g.process.nextTick : function nextTick(callback) {
    return queueMicrotask(callback);
  };
  g.process.exitCode = typeof g.process.exitCode === 'number' ? g.process.exitCode : 0;
  g.process.exit = typeof g.process.exit === 'function' ? g.process.exit : function exit(code) {
    var status = code == null ? g.process.exitCode || 0 : Number(code) || 0;
    g.process.exitCode = status;
    if (typeof g.__exactExit === 'function') {
      g.__exactExit(status);
    }
  };

  if (typeof g.Buffer !== 'function' && typeof require === 'function') {
    try {
      var bufferModule = require('buffer');
      if (bufferModule && typeof bufferModule.Buffer === 'function') {
        g.Buffer = bufferModule.Buffer;
      }
    } catch (_) {}
  }
  if (typeof g.crypto !== 'object' || g.crypto === null) {
    var exactRandomBytes = function(size) {
      size = Number(size) || 0;
      if (size < 0) size = 0;
      if (typeof g.__exactRandomBytes === 'function') {
        return g.__exactRandomBytes(size);
      }
      var fallback = new Uint8Array(size);
      for (var i = 0; i < fallback.length; i++) fallback[i] = Math.floor(Math.random() * 256) & 255;
      return fallback;
    };
    g.crypto = {
      getRandomValues: function(arr) {
        if (!arr || !ArrayBuffer.isView(arr)) {
          throw new TypeError('Expected an integer TypedArray');
        }
        var bytes = exactRandomBytes(arr.byteLength);
        var view = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
        for (var i = 0; i < view.length; i++) view[i] = bytes[i] || 0;
        return arr;
      },
      randomUUID: function() {
        var b = exactRandomBytes(16);
        b[6] = (b[6] & 15) | 64;
        b[8] = (b[8] & 63) | 128;
        var hex = '0123456789abcdef';
        var out = '';
        for (var i = 0; i < 16; i++) {
          if (i === 4 || i === 6 || i === 8 || i === 10) out += '-';
          out += hex[(b[i] >> 4) & 15] + hex[b[i] & 15];
        }
        return out;
      }
    };
  }

  function Headers(init) {
    this._entries = [];
    if (init instanceof Headers) {
      var source = init.entries();
      for (var s = 0; s < source.length; s++) this.append(source[s][0], source[s][1]);
    } else if (Array.isArray(init)) {
      for (var i = 0; i < init.length; i++) this.append(init[i][0], init[i][1]);
    } else if (init && typeof init === 'object') {
      for (var key in init) this.append(key, init[key]);
    }
  }
  Headers.prototype.append = function(name, value) {
    this._entries.push([String(name).toLowerCase(), String(value)]);
  };
  Headers.prototype.delete = function(name) {
    name = String(name).toLowerCase();
    this._entries = this._entries.filter(function(entry) { return entry[0] !== name; });
  };
  Headers.prototype.get = function(name) {
    name = String(name).toLowerCase();
    for (var i = this._entries.length - 1; i >= 0; i--) {
      if (this._entries[i][0] === name) return this._entries[i][1];
    }
    return null;
  };
  Headers.prototype.has = function(name) {
    return this.get(name) !== null;
  };
  Headers.prototype.set = function(name, value) {
    this.delete(name);
    this.append(name, value);
  };
  Headers.prototype.entries = function() {
    return this._entries.slice();
  };
  Headers.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this._entries.length; i++) callback.call(thisArg, this._entries[i][1], this._entries[i][0], this);
  };

  function URLSearchParams(init) {
    this._pairs = [];
    if (typeof init === 'string') {
      var value = init.charAt(0) === '?' ? init.slice(1) : init;
      if (value.length) {
        var parts = value.split('&');
        for (var i = 0; i < parts.length; i++) {
          if (!parts[i]) continue;
          var eq = parts[i].indexOf('=');
          var key = eq === -1 ? parts[i] : parts[i].slice(0, eq);
          var val = eq === -1 ? '' : parts[i].slice(eq + 1);
          this.append(decodeURIComponent(key.replace(/\+/g, ' ')), decodeURIComponent(val.replace(/\+/g, ' ')));
        }
      }
    } else if (Array.isArray(init)) {
      for (var a = 0; a < init.length; a++) this.append(init[a][0], init[a][1]);
    } else if (init && typeof init === 'object') {
      if (typeof init.entries === 'function') {
        var entries = init.entries();
        for (var next = entries.next(); !next.done; next = entries.next()) this.append(next.value[0], next.value[1]);
      } else {
        for (var name in init) this.append(name, init[name]);
      }
    }
  }
  URLSearchParams.prototype.append = function(name, value) { this._pairs.push([String(name), String(value)]); };
  URLSearchParams.prototype.delete = function(name) {
    name = String(name);
    this._pairs = this._pairs.filter(function(pair) { return pair[0] !== name; });
  };
  URLSearchParams.prototype.get = function(name) {
    name = String(name);
    for (var i = 0; i < this._pairs.length; i++) if (this._pairs[i][0] === name) return this._pairs[i][1];
    return null;
  };
  URLSearchParams.prototype.getAll = function(name) {
    name = String(name);
    var out = [];
    for (var i = 0; i < this._pairs.length; i++) if (this._pairs[i][0] === name) out.push(this._pairs[i][1]);
    return out;
  };
  URLSearchParams.prototype.has = function(name) {
    return this.get(name) !== null;
  };
  URLSearchParams.prototype.set = function(name, value) {
    this.delete(name);
    this.append(name, value);
  };
  URLSearchParams.prototype.entries = function() {
    var pairs = this._pairs.slice();
    var index = 0;
    return { next: function() { return index < pairs.length ? { value: pairs[index++], done: false } : { value: undefined, done: true }; } };
  };
  URLSearchParams.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this._pairs.length; i++) callback.call(thisArg, this._pairs[i][1], this._pairs[i][0], this);
  };
  URLSearchParams.prototype.toString = function() {
    return this._pairs.map(function(pair) {
      return encodeURIComponent(pair[0]).replace(/%20/g, '+') + '=' + encodeURIComponent(pair[1]).replace(/%20/g, '+');
    }).join('&');
  };

  function parseUrl(value, base) {
    var input = String(value);
    if (!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(input) && base) {
      var baseUrl = new URL(base);
      if (input.charAt(0) === '/') {
        input = baseUrl.origin + input;
      } else {
        var dir = baseUrl.pathname.replace(/\/[^\/]*$/, '/');
        input = baseUrl.origin + dir + input;
      }
    }
    var match = input.match(/^([A-Za-z][A-Za-z0-9+.-]*:)(?:\/\/([^\/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/);
    if (!match) throw new TypeError('Invalid URL');
    var authority = match[2] || '';
    var hostname = authority;
    var port = '';
    if (authority.charAt(0) === '[') {
      var close = authority.indexOf(']');
      hostname = close === -1 ? authority : authority.slice(0, close + 1);
      if (close !== -1 && authority.charAt(close + 1) === ':') port = authority.slice(close + 2);
    } else {
      var colon = authority.lastIndexOf(':');
      if (colon !== -1) {
        hostname = authority.slice(0, colon);
        port = authority.slice(colon + 1);
      }
    }
    var pathname = match[3] || (authority ? '/' : '');
    return {
      protocol: match[1],
      host: authority,
      hostname: hostname,
      port: port,
      pathname: pathname,
      search: match[4] !== undefined ? '?' + match[4] : '',
      hash: match[5] !== undefined ? '#' + match[5] : ''
    };
  }
  function URL(value, base) {
    if (!(this instanceof URL)) return new URL(value, base);
    var parsed = parseUrl(value, base);
    this.protocol = parsed.protocol;
    this.hostname = parsed.hostname;
    this.port = parsed.port;
    this.pathname = parsed.pathname;
    this.search = parsed.search;
    this.hash = parsed.hash;
    this.searchParams = new URLSearchParams(this.search);
    this._sync();
  }
  URL.prototype._sync = function() {
    this.host = this.hostname + (this.port ? ':' + this.port : '');
    this.origin = this.protocol + '//' + this.host;
    this.href = this.origin + (this.pathname || '/') + (this.searchParams.toString() ? '?' + this.searchParams.toString() : this.search) + this.hash;
  };
  URL.prototype.toString = function() { this._sync(); return this.href; };
  URL.prototype.toJSON = URL.prototype.toString;

  function Blob(parts, options) {
    parts = parts || [];
    options = options || {};
    var chunks = [];
    var size = 0;
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      var bytes;
      if (typeof part === 'string') bytes = new TextEncoder().encode(part);
      else if (part instanceof ArrayBuffer) bytes = new Uint8Array(part);
      else if (ArrayBuffer.isView(part)) bytes = new Uint8Array(part.buffer, part.byteOffset, part.byteLength);
      else bytes = new TextEncoder().encode(String(part));
      chunks.push(bytes);
      size += bytes.byteLength;
    }
    this._chunks = chunks;
    this.size = size;
    this.type = options.type ? String(options.type).toLowerCase() : '';
  }
  Blob.prototype.arrayBuffer = function() {
    var out = new Uint8Array(this.size);
    var offset = 0;
    for (var i = 0; i < this._chunks.length; i++) {
      out.set(this._chunks[i], offset);
      offset += this._chunks[i].byteLength;
    }
    return Promise.resolve(out.buffer);
  };
  Blob.prototype.text = function() {
    return this.arrayBuffer().then(function(buffer) { return new TextDecoder().decode(buffer); });
  };
  Blob.prototype.slice = function(start, end, type) {
    var out = new Uint8Array(this.size);
    var offset = 0;
    for (var i = 0; i < this._chunks.length; i++) {
      out.set(this._chunks[i], offset);
      offset += this._chunks[i].byteLength;
    }
    return new Blob([out.slice(start || 0, end === undefined ? this.size : end)], { type: type || '' });
  };

  function FormData() { this._entries = []; }
  FormData.prototype.append = function(name, value, filename) { this._entries.push([String(name), value, filename]); };
  FormData.prototype.delete = function(name) {
    name = String(name);
    this._entries = this._entries.filter(function(entry) { return entry[0] !== name; });
  };
  FormData.prototype.get = function(name) {
    name = String(name);
    for (var i = 0; i < this._entries.length; i++) if (this._entries[i][0] === name) return this._entries[i][1];
    return null;
  };
  FormData.prototype.getAll = function(name) {
    name = String(name);
    var out = [];
    for (var i = 0; i < this._entries.length; i++) if (this._entries[i][0] === name) out.push(this._entries[i][1]);
    return out;
  };
  FormData.prototype.has = function(name) { return this.get(name) !== null; };
  FormData.prototype.set = function(name, value, filename) { this.delete(name); this.append(name, value, filename); };
  FormData.prototype.entries = function() {
    var entries = this._entries.map(function(entry) { return [entry[0], entry[1]]; });
    var index = 0;
    return { next: function() { return index < entries.length ? { value: entries[index++], done: false } : { value: undefined, done: true }; } };
  };
  FormData.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this._entries.length; i++) callback.call(thisArg, this._entries[i][1], this._entries[i][0], this);
  };

  function Request(input, init) {
    init = init || {};
    var source = input && typeof input === 'object' ? input : null;
    this.url = source && source.url ? String(source.url) : String(input);
    this.method = String(init.method || (source && source.method) || 'GET').toUpperCase();
    this.headers = new Headers(init.headers || (source && source.headers) || []);
    this._body = init.body !== undefined ? init.body : (source && source._body !== undefined ? source._body : null);
    this.signal = init.signal || (source && source.signal) || null;
  }

  function Response(body, init) {
    init = init || {};
    this.status = init.status == null ? 200 : init.status;
    this.statusText = init.statusText || '';
    this.url = init.url || '';
    this.redirected = !!init.redirected;
    this.ok = this.status >= 200 && this.status <= 299;
    this.headers = new Headers(init.headers || []);
    if (body == null) {
      this._body = new Uint8Array(0);
    } else if (typeof body === 'string') {
      this._body = new TextEncoder().encode(body);
    } else if (body instanceof Uint8Array) {
      this._body = body;
    } else if (body instanceof ArrayBuffer) {
      this._body = new Uint8Array(body);
    } else if (ArrayBuffer.isView(body)) {
      this._body = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    } else {
      this._body = new TextEncoder().encode(String(body));
    }
    this.bodyUsed = false;
  }
  Response.prototype.arrayBuffer = function() {
    this.bodyUsed = true;
    var copy = new Uint8Array(this._body.length);
    copy.set(this._body);
    return Promise.resolve(copy.buffer);
  };
  Response.prototype.text = function() {
    this.bodyUsed = true;
    return Promise.resolve(new TextDecoder().decode(this._body));
  };
  Response.prototype.json = function() {
    return this.text().then(function(text) { return JSON.parse(text); });
  };

  function responseFromNative(nativeResponse) {
    return new Response(nativeResponse.body, {
      status: nativeResponse.status,
      statusText: nativeResponse.statusText,
      headers: nativeResponse.headers,
      url: nativeResponse.url,
      redirected: nativeResponse.redirected
    });
  }

  var exactEventTargetStates = new WeakMap();
  function ExactEventTarget(ownerAssert) {
    exactEventTargetStates.set(this, {
      listeners: {},
      ownerAssert: typeof ownerAssert === 'function' ? ownerAssert : null
    });
  }
  function exactEventTargetState(target) {
    var state = target && exactEventTargetStates.get(target);
    if (!state) throw new TypeError('Illegal invocation');
    if (state.ownerAssert) state.ownerAssert();
    return state;
  }
  ExactEventTarget.prototype.addEventListener = function(type, listener) {
    var state = exactEventTargetState(this);
    if (typeof listener !== 'function') return;
    type = String(type);
    (state.listeners[type] || (state.listeners[type] = [])).push(listener);
  };
  ExactEventTarget.prototype.removeEventListener = function(type, listener) {
    var state = exactEventTargetState(this);
    type = String(type);
    var list = state.listeners[type];
    if (!list) return;
    for (var i = 0; i < list.length; i++) {
      if (list[i] === listener) {
        list.splice(i, 1);
        return;
      }
    }
  };
  ExactEventTarget.prototype.dispatchEvent = function(event) {
    var state = exactEventTargetState(this);
    event.target = event.target || this;
    event.currentTarget = this;
    var handler = this['on' + event.type];
    if (typeof handler === 'function') {
      handler.call(this, event);
    }
    var list = state.listeners[event.type];
    if (list) {
      list = list.slice();
      for (var i = 0; i < list.length; i++) {
        list[i].call(this, event);
      }
    }
    return true;
  };

  if (typeof g.WebSocket !== 'function' &&
      typeof g.__exactWsConnect === 'function' &&
      typeof g.__exactWsSend === 'function' &&
      typeof g.__exactWsClose === 'function' &&
      typeof g.__exactNetOwner === 'function') {
    var exactWebSocketStates = new WeakMap();
    var exactWsConnect = g.__exactWsConnect;
    var exactWsSend = g.__exactWsSend;
    var exactWsClose = g.__exactWsClose;
    var exactNetOwner = g.__exactNetOwner;
    var exactEventTargetDispatch = ExactEventTarget.prototype.dispatchEvent;

    function exactWebSocketState(socket) {
      var state = socket && exactWebSocketStates.get(socket);
      if (!state) throw new TypeError('Illegal invocation');
      return state;
    }

    function exactOwnedWebSocketState(socket) {
      var state = exactWebSocketState(socket);
      exactNetOwner('assert', state.ownerStamp);
      return state;
    }

    function exactWebSocketHandleOpen(socket, protocol, extensions) {
      var state = exactOwnedWebSocketState(socket);
      if (state.readyState !== ExactWebSocket.CONNECTING) return;
      state.protocol = protocol || '';
      state.extensions = extensions || '';
      state.readyState = ExactWebSocket.OPEN;
      exactEventTargetDispatch.call(socket, { type: 'open' });
    }

    function exactWebSocketHandleMessage(socket, data) {
      if (exactOwnedWebSocketState(socket).readyState !== ExactWebSocket.OPEN) return;
      exactEventTargetDispatch.call(socket, { type: 'message', data: data });
    }

    function exactWebSocketHandleError(socket, message) {
      var state = exactOwnedWebSocketState(socket);
      exactEventTargetDispatch.call(socket, { type: 'error', message: message || 'WebSocket error' });
      if (state.readyState !== ExactWebSocket.CLOSED) {
        state.readyState = ExactWebSocket.CLOSED;
        exactEventTargetDispatch.call(socket, { type: 'close', code: 1006, reason: message || '', wasClean: false });
      }
    }

    function exactWebSocketHandleClose(socket, code, reason, wasClean) {
      exactOwnedWebSocketState(socket).readyState = ExactWebSocket.CLOSED;
      exactEventTargetDispatch.call(socket, { type: 'close', code: code, reason: reason || '', wasClean: !!wasClean });
    }

    function exactWebSocketHandleBytesSent(socket, bytes) {
      var state = exactOwnedWebSocketState(socket);
      state.bufferedAmount = Math.max(0, state.bufferedAmount - (bytes || 0));
    }

    function ExactWebSocket(url, protocols) {
      if (!(this instanceof ExactWebSocket)) {
        throw new TypeError("Failed to construct 'WebSocket': Please use the 'new' operator");
      }
      var ownerStamp = exactNetOwner('new');
      ExactEventTarget.call(this, function() {
        exactNetOwner('assert', ownerStamp);
      });
      var state = {
        url: String(url),
        protocol: '',
        extensions: '',
        readyState: ExactWebSocket.CONNECTING,
        bufferedAmount: 0,
        binaryType: 'blob',
        id: 0,
        ownerStamp: ownerStamp,
        onopen: null,
        onmessage: null,
        onerror: null,
        onclose: null
      };
      // @ref LLP 0013#delegation-and-authority-flow — a wrapper may cross a
      // principal boundary, but its native selector remains closure-private.
      exactWebSocketStates.set(this, state);
      var socket = this;
      var bridge = {
        _handleOpen: function(protocol, extensions) {
          exactWebSocketHandleOpen(socket, protocol, extensions);
        },
        _handleMessage: function(data) {
          exactWebSocketHandleMessage(socket, data);
        },
        _handleError: function(message) {
          exactWebSocketHandleError(socket, message);
        },
        _handleClose: function(code, reason, wasClean) {
          exactWebSocketHandleClose(socket, code, reason, wasClean);
        },
        _handleBytesSent: function(bytes) {
          exactWebSocketHandleBytesSent(socket, bytes);
        }
      };
      var protocolList = [];
      if (Array.isArray(protocols)) {
        protocolList = protocols.map(String);
      } else if (protocols !== undefined) {
        protocolList = [String(protocols)];
      }
      var id = exactWsConnect(state.url, protocolList.join(','), bridge);
      state.id = typeof id === 'number' ? id : 0;
    }
    ExactWebSocket.CONNECTING = 0;
    ExactWebSocket.OPEN = 1;
    ExactWebSocket.CLOSING = 2;
    ExactWebSocket.CLOSED = 3;
    ExactWebSocket.prototype = Object.create(ExactEventTarget.prototype);
    ExactWebSocket.prototype.constructor = ExactWebSocket;
    ExactWebSocket.prototype.CONNECTING = ExactWebSocket.CONNECTING;
    ExactWebSocket.prototype.OPEN = ExactWebSocket.OPEN;
    ExactWebSocket.prototype.CLOSING = ExactWebSocket.CLOSING;
    ExactWebSocket.prototype.CLOSED = ExactWebSocket.CLOSED;
    Object.defineProperties(ExactWebSocket.prototype, {
      url: {
        get: function() { return exactOwnedWebSocketState(this).url; },
        enumerable: true,
        configurable: true
      },
      protocol: {
        get: function() { return exactOwnedWebSocketState(this).protocol; },
        enumerable: true,
        configurable: true
      },
      extensions: {
        get: function() { return exactOwnedWebSocketState(this).extensions; },
        enumerable: true,
        configurable: true
      },
      readyState: {
        get: function() { return exactOwnedWebSocketState(this).readyState; },
        enumerable: true,
        configurable: true
      },
      bufferedAmount: {
        get: function() { return exactOwnedWebSocketState(this).bufferedAmount; },
        enumerable: true,
        configurable: true
      },
      binaryType: {
        get: function() { return exactOwnedWebSocketState(this).binaryType; },
        set: function(value) {
          if (value === 'blob' || value === 'arraybuffer') {
            exactOwnedWebSocketState(this).binaryType = value;
          }
        },
        enumerable: true,
        configurable: true
      },
      onopen: {
        get: function() { return exactOwnedWebSocketState(this).onopen; },
        set: function(value) { exactOwnedWebSocketState(this).onopen = typeof value === 'function' ? value : null; },
        enumerable: true,
        configurable: true
      },
      onmessage: {
        get: function() { return exactOwnedWebSocketState(this).onmessage; },
        set: function(value) { exactOwnedWebSocketState(this).onmessage = typeof value === 'function' ? value : null; },
        enumerable: true,
        configurable: true
      },
      onerror: {
        get: function() { return exactOwnedWebSocketState(this).onerror; },
        set: function(value) { exactOwnedWebSocketState(this).onerror = typeof value === 'function' ? value : null; },
        enumerable: true,
        configurable: true
      },
      onclose: {
        get: function() { return exactOwnedWebSocketState(this).onclose; },
        set: function(value) { exactOwnedWebSocketState(this).onclose = typeof value === 'function' ? value : null; },
        enumerable: true,
        configurable: true
      }
    });
    ExactWebSocket.prototype.send = function(data) {
      var state = exactOwnedWebSocketState(this);
      if (state.readyState !== ExactWebSocket.OPEN) {
        throw new Error('WebSocket is not open');
      }
      // Authenticate before caller-controlled conversion or bufferedAmount
      // mutation. The native send boundary ignores this unsupported payload
      // after performing its strict owner/capability check.
      exactWsSend(state.id, undefined);
      var payload = data;
      var bytes = 0;
      if (typeof data === 'string') {
        bytes = new TextEncoder().encode(data).byteLength;
      } else if (data instanceof ArrayBuffer) {
        payload = new Uint8Array(data);
        bytes = payload.byteLength;
      } else if (ArrayBuffer.isView(data)) {
        payload = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        bytes = payload.byteLength;
      } else {
        payload = String(data);
        bytes = new TextEncoder().encode(payload).byteLength;
      }
      state.bufferedAmount += bytes;
      try {
        exactWsSend(state.id, payload);
      } catch (error) {
        state.bufferedAmount = Math.max(0, state.bufferedAmount - bytes);
        throw error;
      }
    };
    ExactWebSocket.prototype.close = function(code, reason) {
      var state = exactOwnedWebSocketState(this);
      if (state.readyState === ExactWebSocket.CLOSED || state.readyState === ExactWebSocket.CLOSING) return;
      if (state.id) {
        // __exactWsClose performs the strict native owner check. Only commit
        // CLOSING after it succeeds so a denied retained-wrapper call cannot
        // poison the owner's retry.
        exactWsClose(state.id, code == null ? 1005 : code, reason == null ? '' : String(reason));
      }
      if (state.readyState !== ExactWebSocket.CLOSED) {
        state.readyState = ExactWebSocket.CLOSING;
      }
    };
    g.WebSocket = ExactWebSocket;
  }

  if (typeof g.AbortController !== 'function') {
    function AbortSignal() {
      ExactEventTarget.call(this);
      this.aborted = false;
      this.reason = undefined;
    }
    AbortSignal.prototype = Object.create(ExactEventTarget.prototype);
    AbortSignal.prototype.constructor = AbortSignal;
    AbortSignal.prototype.throwIfAborted = function() {
      if (this.aborted) throw this.reason || new Error('The operation was aborted');
    };
    function AbortController() {
      this.signal = new AbortSignal();
    }
    AbortController.prototype.abort = function(reason) {
      if (this.signal.aborted) return;
      this.signal.aborted = true;
      this.signal.reason = reason || new Error('The operation was aborted');
      this.signal.dispatchEvent({ type: 'abort' });
    };
    g.AbortController = AbortController;
    g.AbortSignal = AbortSignal;
  }

  if (typeof g.__nativeFetchSync === 'function') {
    g.fetch = function fetch(input, init) {
      var request = input instanceof Request ? new Request(input, init) : new Request(input, init || {});
      return Promise.resolve().then(function() {
        if (request.signal && request.signal.aborted) {
          throw request.signal.reason || new Error('The operation was aborted');
        }
        var nativeUrl = request.url.replace(/^http:\/\/127\.0\.0\.1(?=[:\/]|$)/, 'http://localhost');
        var nativeInit = {
          method: request.method || 'GET',
          headers: request.headers instanceof Headers ? request.headers.entries() : [],
          decompress: !init || init.decompress !== false,
          timeout: init && init.timeout || 30000
        };
        var body = request._body == null
          ? null
          : (typeof request._body === 'string' ? new TextEncoder().encode(request._body) : request._body);
        var response = responseFromNative(g.__nativeFetchSync(nativeUrl, nativeInit, body));
        response.url = request.url;
        return response;
      });
    };
  }

  g.URL = URL;
  g.URLSearchParams = URLSearchParams;
  g.Blob = Blob;
  g.FormData = FormData;
  g.Headers = Headers;
  g.Request = Request;
  g.Response = Response;

  function exactToBytes(data) {
    if (typeof data === 'string') return new TextEncoder().encode(data);
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new TextEncoder().encode(String(data));
  }

  function exactDecode(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function exactEnsureFs() {
    if (typeof g.__exactEnsureFs === 'function') {
      try { g.__exactEnsureFs(); } catch (_) {}
    }
  }

  function ExactFile(path, options) {
    this.name = String(path && typeof path === 'object' && path.pathname ? decodeURIComponent(path.pathname) : path);
    this.type = options && options.type || 'application/octet-stream';
  }
  Object.defineProperty(ExactFile.prototype, 'size', {
    get: function() {
      exactEnsureFs();
      try { return JSON.parse(g.__exactStat(this.name)).size || 0; } catch (_) { return 0; }
    }
  });
  Object.defineProperty(ExactFile.prototype, 'lastModified', {
    get: function() {
      exactEnsureFs();
      try { return JSON.parse(g.__exactStat(this.name)).mtime_ms || 0; } catch (_) { return 0; }
    }
  });
  ExactFile.prototype.text = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() { return exactDecode(g.__exactReadFile(name)); });
  };
  ExactFile.prototype.json = function() {
    return this.text().then(function(text) { return JSON.parse(text); });
  };
  ExactFile.prototype.arrayBuffer = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() {
      var bytes = g.__exactReadFile(name);
      var out = new Uint8Array(bytes.byteLength || bytes.length || 0);
      for (var i = 0; i < out.length; i++) out[i] = bytes[i];
      return out.buffer;
    });
  };
  ExactFile.prototype.bytes = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() { return g.__exactReadFile(name); });
  };
  ExactFile.prototype.exists = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() {
      try { g.__exactAccess(name, 0); return true; } catch (_) { return false; }
    });
  };
  ExactFile.prototype.stat = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() {
      try { return JSON.parse(g.__exactStat(name)); } catch (_) { return null; }
    });
  };
  ExactFile.prototype.slice = function(begin, end, type) {
    exactEnsureFs();
    var bytes = g.__exactReadFile(this.name);
    return new Blob([bytes.slice(begin || 0, end === undefined ? bytes.length : end)], { type: type || this.type });
  };
  ExactFile.prototype.writer = function() {
    var name = this.name;
    var started = false;
    return {
      write: function(data) {
        exactEnsureFs();
        var bytes = exactToBytes(data);
        if (!started || typeof g.__exactAppendFile !== 'function') {
          g.__exactWriteFile(name, bytes);
          started = true;
        } else {
          g.__exactAppendFile(name, bytes);
        }
        return bytes.length;
      },
      end: function() {},
      flush: function() {}
    };
  };
  ExactFile.prototype.toString = function() { return 'ExactFile("' + this.name + '")'; };

  var Exact = g.Exact || {};
  Exact.version = Exact.version || '0.1.0';
  Exact.platform = Exact.platform || 'cli';
  Exact.file = typeof Exact.file === 'function' ? Exact.file : function(path, options) {
    return new ExactFile(path, options);
  };
  Exact.write = typeof Exact.write === 'function' ? Exact.write : function(dest, data) {
    exactEnsureFs();
    return Promise.resolve().then(function() {
      var path = typeof dest === 'string' ? dest : dest.name;
      var bytes = exactToBytes(data);
      g.__exactWriteFile(path, bytes);
      return bytes.length;
    });
  };
  Exact.env = Exact.env || g.process.env;
  g.Exact = Exact;
  var Bun = g.Bun || Exact;
  Bun.file = typeof Bun.file === 'function' ? Bun.file : Exact.file;
  Bun.write = typeof Bun.write === 'function' ? Bun.write : Exact.write;
  Bun.env = Bun.env || g.process.env;
  Bun.fetch = typeof Bun.fetch === 'function' ? Bun.fetch : g.fetch;
  Bun.argv = Bun.argv || g.process.argv || [];
  Bun.main = Bun.main || (g.process.argv && g.process.argv[1]) || '';
  Bun.which = typeof Bun.which === 'function' ? Bun.which : function(cmd) {
    if (typeof cmd !== 'string' || !cmd) return null;
    if (typeof g.__exactWhich !== 'function' &&
        typeof g.__exactEnsureChildProcess === 'function') {
      try { g.__exactEnsureChildProcess(); } catch (_) {}
    }
    if (typeof g.__exactWhich === 'function') return g.__exactWhich(cmd);
    return null;
  };

  function normalizeBunCommand(cmd, opts) {
    var args;
    var options = opts || {};
    if (Array.isArray(cmd)) {
      args = cmd.slice();
    } else if (cmd && typeof cmd === 'object' && Array.isArray(cmd.cmd)) {
      args = cmd.cmd.slice();
      options = {};
      for (var key in cmd) if (key !== 'cmd') options[key] = cmd[key];
      if (opts) for (var key2 in opts) options[key2] = opts[key2];
    } else {
      throw new TypeError('Bun.spawn expects a command array or object with cmd');
    }
    if (!args.length) throw new TypeError('Bun.spawn command array must not be empty');
    return { args: args, options: options };
  }

  Bun.spawnSync = typeof Bun.spawnSync === 'function' ? Bun.spawnSync : function(cmd, opts) {
    var normalized = normalizeBunCommand(cmd, opts);
    var cp = require('node:child_process');
    var result = cp.spawnSync(normalized.args[0], normalized.args.slice(1), normalized.options);
    return {
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      exitCode: result.status == null ? -1 : result.status,
      success: result.status === 0
    };
  };
  Bun.spawn = typeof Bun.spawn === 'function' ? Bun.spawn : function(cmd, opts) {
    var result = Bun.spawnSync(cmd, opts);
    var stdout = result.stdout || '';
    var stderr = result.stderr || '';
    return {
      pid: 0,
      stdout: { text: function() { return Promise.resolve(String(stdout)); } },
      stderr: { text: function() { return Promise.resolve(String(stderr)); } },
      exited: Promise.resolve(result.exitCode),
      exitCode: result.exitCode,
      killed: false,
      kill: function() { return false; },
      ref: function() { return this; },
      unref: function() { return this; }
    };
  };

  function exactDecodeBase64(value) {
    if (!value) return new Uint8Array(0);
    if (typeof atob === 'function') {
      var binary = atob(String(value));
      var out = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
      return out;
    }
    return new Uint8Array(0);
  }

  Bun.serve = typeof Bun.serve === 'function' ? Bun.serve : function(options) {
    if (!options || typeof options !== 'object') throw new TypeError('Bun.serve() expects an options object');
    var fetchHandler = options.fetch;
    if (typeof fetchHandler !== 'function') throw new TypeError('Bun.serve() requires a fetch handler function');
    if (typeof g.__exactHttpServe !== 'function' && typeof g.__exactEnsureHttp === 'function') {
      g.__exactEnsureHttp();
    }
    if (typeof g.__exactHttpServe !== 'function') throw new Error('HTTP server not available');
    var port = options.port == null ? 3000 : Number(options.port);
    var hostname = options.hostname == null ? '127.0.0.1' : String(options.hostname);
    var result = JSON.parse(g.__exactHttpServe(port, hostname));
    if (result.error) throw new Error(result.error);
    var serverId = result.id;
    var actualPort = result.port || port;
    var closed = false;

    function buildRequest(data) {
      var requestUrl = data.url || '/';
      if (requestUrl.indexOf('http://') !== 0 && requestUrl.indexOf('https://') !== 0) {
        requestUrl = 'http://' + (hostname === '0.0.0.0' ? 'localhost' : hostname) + ':' + actualPort + requestUrl;
      }
      var init = { method: data.method || 'GET', headers: data.headers || [] };
      if (data.hasBody && data.body) init.body = exactDecodeBase64(data.body);
      return new Request(requestUrl, init);
    }
    function sendResponse(requestId, response) {
      if (!(response instanceof Response)) response = new Response(response == null ? '' : String(response));
      var headers = [];
      response.headers.forEach(function(value, key) { headers.push([key, value]); });
      response.arrayBuffer().then(function(buffer) {
        g.__exactHttpRespond(serverId, requestId, response.status || 200, JSON.stringify(headers), new Uint8Array(buffer));
      }, function() {
        g.__exactHttpRespond(serverId, requestId, 500, JSON.stringify([['content-type', 'text/plain']]), new TextEncoder().encode('Internal Server Error'));
      });
    }
    function handleRequest(json) {
      var data;
      try { data = JSON.parse(json); } catch (_) { return; }
      var request;
      try { request = buildRequest(data); } catch (_) {
        sendResponse(data.id || 0, new Response('Bad Request', { status: 400 }));
        return;
      }
      Promise.resolve()
        .then(function() { return fetchHandler(request, server); })
        .then(function(response) { sendResponse(data.id || 0, response); })
        .catch(function(err) {
          var errorHandler = options.error;
          if (typeof errorHandler === 'function') {
            try {
              Promise.resolve(errorHandler(err)).then(function(response) {
                sendResponse(data.id || 0, response);
              }, function() {
                sendResponse(data.id || 0, new Response('Internal Server Error', { status: 500 }));
              });
              return;
            } catch (_) {}
          }
          sendResponse(data.id || 0, new Response('Internal Server Error', { status: 500 }));
        });
    }
    function poll() {
      if (closed) return;
      var handled = false;
      if (typeof g.__exactHttpPoll === 'function') {
        while (true) {
          var json = g.__exactHttpPoll(serverId);
          if (!json) break;
          handled = true;
          handleRequest(json);
        }
      }
      if (typeof g.__exactHttpWait === 'function') {
        g.__exactHttpWait(serverId, 1000).then(function(json) {
          if (json) handleRequest(json);
          if (!closed) setTimeout(poll, 0);
        }, function() {
          if (!closed) setTimeout(poll, 50);
        });
      } else {
        setTimeout(poll, handled ? 0 : 50);
      }
    }
    var server = {
      port: actualPort,
      hostname: hostname === '0.0.0.0' ? 'localhost' : hostname,
      url: new URL('http://' + (hostname === '0.0.0.0' ? 'localhost' : hostname) + ':' + actualPort + '/'),
      development: !!options.development,
      id: String(serverId),
      pendingRequests: 0,
      stop: function(force) {
        closed = true;
        if (typeof g.__exactHttpClose === 'function') g.__exactHttpClose(serverId, force ? 1 : 0);
      },
      reload: function(next) {
        if (next && typeof next.fetch === 'function') fetchHandler = next.fetch;
      },
      ref: function() { if (typeof g.__exactHttpSetRef === 'function') g.__exactHttpSetRef(serverId, 1); return server; },
      unref: function() { if (typeof g.__exactHttpSetRef === 'function') g.__exactHttpSetRef(serverId, 0); return server; },
      requestIP: function() { return null; },
      upgrade: function() { return false; },
      publish: function() {},
      fetch: fetchHandler
    };
    setTimeout(poll, 0);
    return server;
  };
  g.Bun = Bun;

  g.__exactRuntimeLoaded = true;
})(globalThis);"#;

const WINDOWS_RUNTIME_LOADED_PROBE: &str =
    "typeof globalThis === 'object' && globalThis.__exactRuntimeLoaded === true";

async fn load_windows_minimal_runtime(engine: &dyn Engine) -> Result<()> {
    let loaded = engine
        .eval_immediate(WINDOWS_RUNTIME_LOADED_PROBE)
        .await
        .context("failed to probe the Windows minimal runtime")?;
    if !matches!(loaded.as_deref().map(str::trim), Some("true")) {
        engine
            .eval_immediate(WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP)
            .await?;
    }
    engine::hermes::finalize_compartment_baseline(engine).await
}

/// Mark bytecode as incompatible with the embedded runtime.
/// Called from the engine layer when bytecode loading fails.
pub fn mark_bytecode_incompatible() {
    BYTECODE_INCOMPATIBLE.store(true, Ordering::Relaxed);
}

fn build_exec_argv(cli: &Cli) -> Vec<String> {
    let mut exec_argv = Vec::new();

    if cli.expose_internals {
        exec_argv.push("--expose-internals".to_string());
    }
    if let Some(stack_size) = &cli.stack_size {
        exec_argv.push(format!("--stack-size={stack_size}"));
    }
    if let Some(max_http_header_size) = cli.max_http_header_size {
        exec_argv.push(format!("--max-http-header-size={max_http_header_size}"));
    }
    if cli.inspect {
        exec_argv.push("--inspect".to_string());
    }
    if cli.inspect_wait {
        exec_argv.push("--inspect-wait".to_string());
    }
    if cli.inspect_open {
        exec_argv.push("--inspect-open".to_string());
    }
    if cli.inspect_pause {
        exec_argv.push("--inspect-pause".to_string());
    }
    if cli.keep_alive {
        exec_argv.push("--keep-alive".to_string());
    }
    if let Some(port) = cli.inspect_port {
        exec_argv.push(format!("--inspect-port={port}"));
    }
    if let Some(host) = &cli.inspect_host {
        exec_argv.push(format!("--inspect-host={host}"));
    }
    if let Ok(extra_exec_argv) = env::var("EXACT_COMPAT_EXEC_ARGV") {
        if let Ok(extra_args) = serde_json::from_str::<Vec<String>>(&extra_exec_argv) {
            exec_argv.extend(extra_args.into_iter().filter(|arg| !arg.is_empty()));
        }
    }

    exec_argv
}

/// Preserve the explicit foreground-audit entry when child-process shims
/// reconstruct an Ibex invocation from `process.execArgv`.
fn build_audit_exec_argv(cli: &Cli) -> Vec<String> {
    let mut exec_argv = vec!["capsec".to_string(), "audit".to_string()];
    exec_argv.extend(build_exec_argv(cli));
    exec_argv
}

fn read_raw_argv0(exec_path: &str) -> String {
    env::var("EXACT_RAW_ARGV0")
        .ok()
        .unwrap_or_else(|| env::args().next().unwrap_or_else(|| exec_path.to_string()))
}

fn normalize_candidate(candidate: impl AsRef<Path>) -> Option<String> {
    let candidate = candidate.as_ref();
    let path = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(candidate)
    };

    if path.exists() && path.is_file() {
        path.to_str().map(|path| path.to_string())
    } else {
        None
    }
}

fn resolve_exec_path(extra_candidates: &[&str]) -> String {
    env::var("EXACT_EXECUTABLE")
        .ok()
        .and_then(normalize_candidate)
        .or_else(|| {
            env::var("EXACT_COMPAT_EXECUTABLE")
                .ok()
                .and_then(normalize_candidate)
        })
        .or_else(|| {
            env::current_exe()
                .ok()
                .filter(|path| path.exists() && path.is_file())
                .and_then(|path| path.to_str().map(|path| path.to_string()))
        })
        .or_else(|| env::args().next().and_then(normalize_candidate))
        .or_else(|| normalize_candidate(".cargo-targets/main/debug/ibex"))
        .or_else(|| normalize_candidate(".cargo-targets/main/release/ibex"))
        .or_else(|| normalize_candidate("target/debug/ibex"))
        .or_else(|| normalize_candidate("target/release/ibex"))
        .or_else(|| extra_candidates.iter().find_map(normalize_candidate))
        .unwrap_or_else(|| "ibex".to_string())
}

const ARMED_INSPECTOR_CLOSED_MESSAGE: &str =
    "armed capability runtime closes inspector activation and configuration";

/// Runtime wrapper that owns the engine and host configuration.
pub struct Runtime {
    engine: Arc<dyn Engine>,
    host: Host,
    // The preload carries trusted bootstrap-only process data. Once Hermes has
    // sealed it, even a nominally idempotent second load must not recreate the
    // temporary root globals that the seal just removed.
    runtime_bootstrap_loaded: tokio::sync::OnceCell<()>,
    /// Supervisor-private storage location and scope derived before engine
    /// construction. It contains no operation or spelling projectable to JS.
    history_startup: crate::history::HistoryStartupCapture,
    session_io: Option<crate::terminal_session::SessionIoPlan>,
    /// Canonical root authenticated into this exact armed Host. It remains
    /// native-only and is used solely to select the direct entry object for
    /// digest-bound generated-artifact construction.
    authenticated_project_root: Option<std::path::PathBuf>,
    /// Exact binary-runtime cache root authenticated before Host/engine
    /// construction. Armed generated ingress reuses this value verbatim.
    authenticated_runtime_cache_root: Option<std::path::PathBuf>,
    bundle_format: BundleFormat,
    exec_argv: Vec<String>,
    compat_modes: Vec<String>,
}

/// Supervisor-owned launch material for a session worker.
///
/// The supervisor authenticates and freshens the production snapshot exactly
/// once, before spawn.  Only the digest-bound snapshot and the independently
/// observed arming identity cross the authenticated bootstrap channel; the
/// project path and history scope stay in this process.
/// @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker
/// @ref LLP 0025#9-history
pub(crate) struct PreparedSessionWorkerRuntime {
    application: Vec<u8>,
    binding: crate::session_worker::ArmedSessionBinding,
    project_root: std::path::PathBuf,
    project_object: capsec_semantics::model::ObjectIdentity,
    history_startup: crate::history::HistoryStartupCapture,
}

impl PreparedSessionWorkerRuntime {
    pub(crate) fn application(&self) -> &[u8] {
        &self.application
    }

    pub(crate) fn binding(&self) -> &crate::session_worker::ArmedSessionBinding {
        &self.binding
    }

    pub(crate) fn project_root(&self) -> &std::path::Path {
        &self.project_root
    }

    pub(crate) fn project_object(&self) -> &capsec_semantics::model::ObjectIdentity {
        &self.project_object
    }

    pub(crate) fn history_startup(&self) -> crate::history::HistoryStartupCapture {
        self.history_startup.clone()
    }
}

/// The only runtime-bearing application payload admitted by the private
/// worker bootstrap. `deny_unknown_fields` makes version skew a startup
/// refusal instead of silently ignoring a security-bearing field.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionWorkerRuntimeMaterial {
    snapshot: serde_json::Value,
    expected_identity: capsec_semantics::arming::ExpectedArmingIdentity,
}

/// Closed source-ingress state for one armed REPL session.
///
/// The security-bearing objects stay together: the exact Host that
/// authenticated the armed snapshot, the Host's cached opaque session token,
/// the one exclusive ordinal allocator for that token, and the captured
/// session-I/O route. Each operation separately rejoins that Host to the exact
/// live engine generation before it derives the runtime VFS and cwd. REPL code
/// can ask this adapter to evaluate fixed ingress forms, but cannot select a
/// principal, source shape, referrer, or session credential.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
/// @ref LLP 0024#1-the-in-memory-source-api
pub(crate) struct ReplSessionIngress {
    host: Host,
    session: ibex_runtime::engine::evaluation::ArmedSessionToken,
    sequence: ibex_runtime::engine::evaluation::SubmissionSequence,
    session_io: crate::terminal_session::SessionIoPlan,
}

/// Closed distinction consumed by the terminal adapter. Operator-controlled
/// source/VFS refusals are recoverable at the next prompt; authenticated
/// session, handle, owner-thread, poison, and protocol failures terminate the
/// engine session. Keeping the original error preserves typed diagnostics
/// without giving presentation code a string-classification oracle.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthenticatedEvaluationFailure {
    #[error("{0:#}")]
    Refusal(anyhow::Error),
    #[error("{0:#}")]
    EngineFault(anyhow::Error),
}

impl AuthenticatedEvaluationFailure {
    pub(crate) const fn is_engine_fault(&self) -> bool {
        matches!(self, Self::EngineFault(_))
    }
}

/// Final semantic disposition of one authenticated file-program execution.
///
/// Orderly completion deliberately carries no status: its status is resolved
/// from the supervisor-authoritative `process.exitCode` mirror only after the
/// keep-alive set reaches quiescence. A cooperative lifecycle outcome carries
/// its own status and must never be collapsed into that orderly mirror.
/// @ref LLP 0025#8-exit-and-lifecycle
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum AuthenticatedFileProgramOutcome {
    Completed,
    Lifecycle {
        status: i32,
        secondary_diagnostics: Vec<String>,
    },
    Failed {
        status: i32,
        diagnostic: String,
    },
}

fn authenticated_file_lifecycle(status: i32) -> AuthenticatedFileProgramOutcome {
    AuthenticatedFileProgramOutcome::Lifecycle {
        status,
        secondary_diagnostics: Vec::new(),
    }
}

fn authenticated_file_throw_diagnostic(thrown: crate::engine::AuthenticatedThrow) -> String {
    let mut diagnostic = format!(
        "uncaught file-program exception: {}",
        thrown.value.diagnostic_text()
    );
    if let Some(message) = thrown.metadata.message() {
        diagnostic.push('\n');
        diagnostic.push_str(message);
    }
    if let Some(stack) = thrown.metadata.stack() {
        diagnostic.push('\n');
        diagnostic.push_str(stack);
    }
    for position in thrown.metadata.positions() {
        diagnostic.push_str(&format!(
            "\nat {}:{}:{}",
            position.source_label, position.line, position.column
        ));
    }
    diagnostic
}

fn authenticated_file_lifecycle_outcome(
    lifecycle: &ibex_runtime::session_lifecycle::SessionLifecyclePort,
    evaluation_status: i32,
) -> AuthenticatedFileProgramOutcome {
    use ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT;

    match lifecycle.take_pending_request() {
        Some(request) if request.status == evaluation_status => {
            authenticated_file_lifecycle(request.status)
        }
        Some(request) => AuthenticatedFileProgramOutcome::Failed {
            status: EXIT_STATUS_ENGINE_FAULT,
            diagnostic: format!(
                "authenticated file-program lifecycle status disagreed with the supervisor record (evaluation {evaluation_status}, supervisor {}, request {})",
                request.status, request.request_id
            ),
        },
        None => AuthenticatedFileProgramOutcome::Failed {
            status: EXIT_STATUS_ENGINE_FAULT,
            diagnostic: format!(
                "authenticated file-program lifecycle outcome {evaluation_status} had no pending supervisor record"
            ),
        },
    }
}

fn authenticated_file_async_failure_outcome(
    failures: Vec<crate::engine::AuthenticatedAsyncFailure>,
    receipt_cleanup_error: Option<anyhow::Error>,
) -> AuthenticatedFileProgramOutcome {
    use ibex_runtime::session_constants::{
        EXIT_STATUS_ENGINE_FAULT, EXIT_STATUS_NON_INTERACTIVE_FAILURE,
    };

    let status = if failures.iter().any(|failure| {
        matches!(
            failure,
            crate::engine::AuthenticatedAsyncFailure::PreReceiptLoss { .. }
        )
    }) {
        // LLP 0024 defines a pre-receipt loss as a worker/engine fault: the
        // consumer cannot reconstruct which failure event was lost.
        EXIT_STATUS_ENGINE_FAULT
    } else {
        EXIT_STATUS_NON_INTERACTIVE_FAILURE
    };
    let mut diagnostic = String::from("unhandled asynchronous file-program failure");
    for failure in failures {
        diagnostic.push_str("\n- ");
        diagnostic.push_str(&failure.to_string());
    }
    if let Some(error) = receipt_cleanup_error {
        diagnostic.push_str(&format!(
            "\n- suppressed-result cleanup failed after the primary asynchronous failure: {error:#}"
        ));
    }
    AuthenticatedFileProgramOutcome::Failed { status, diagnostic }
}

fn append_authenticated_file_diagnostic(
    outcome: AuthenticatedFileProgramOutcome,
    detail: &str,
) -> AuthenticatedFileProgramOutcome {
    match outcome {
        AuthenticatedFileProgramOutcome::Failed {
            status,
            mut diagnostic,
        } => {
            diagnostic.push_str("\n- ");
            diagnostic.push_str(detail);
            AuthenticatedFileProgramOutcome::Failed { status, diagnostic }
        }
        AuthenticatedFileProgramOutcome::Lifecycle {
            status,
            mut secondary_diagnostics,
        } => {
            secondary_diagnostics.push(detail.to_owned());
            AuthenticatedFileProgramOutcome::Lifecycle {
                status,
                secondary_diagnostics,
            }
        }
        outcome => outcome,
    }
}

fn authenticated_file_release_outcome(
    lifecycle: &ibex_runtime::session_lifecycle::SessionLifecyclePort,
    request_before_release: Option<ibex_runtime::session_lifecycle::LifecycleExitRequest>,
    release_error: Option<anyhow::Error>,
) -> Option<AuthenticatedFileProgramOutcome> {
    use ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT;

    let request = request_before_release.or_else(|| lifecycle.take_pending_request());
    if let Some(request) = request {
        let mut outcome = authenticated_file_lifecycle(request.status);
        if let Some(error) = release_error {
            outcome = append_authenticated_file_diagnostic(
                outcome,
                &format!(
                    "failed to release the undisplayed file-program completion after cooperative exit: {error:#}"
                ),
            );
        }
        return Some(outcome);
    }
    release_error.map(|error| AuthenticatedFileProgramOutcome::Failed {
        status: EXIT_STATUS_ENGINE_FAULT,
        diagnostic: format!("failed to release the undisplayed file-program completion: {error:#}"),
    })
}

async fn preserve_file_evaluation_after_async_collection_error(
    engine: &dyn Engine,
    lifecycle: &ibex_runtime::session_lifecycle::SessionLifecyclePort,
    evaluation: std::result::Result<
        crate::engine::AuthenticatedEvaluation,
        AuthenticatedEvaluationFailure,
    >,
    collection_error: anyhow::Error,
) -> AuthenticatedFileProgramOutcome {
    use crate::engine::AuthenticatedEvaluation;
    use ibex_runtime::session_constants::{
        EXIT_STATUS_ENGINE_FAULT, EXIT_STATUS_INTERRUPT, EXIT_STATUS_NON_INTERACTIVE_FAILURE,
    };

    let collection_detail = format!(
        "asynchronous failure collection failed after file-program evaluation settled: {collection_error:#}"
    );
    match evaluation {
        Err(error) => {
            let status = if error.is_engine_fault() {
                EXIT_STATUS_ENGINE_FAULT
            } else {
                EXIT_STATUS_NON_INTERACTIVE_FAILURE
            };
            AuthenticatedFileProgramOutcome::Failed {
                status,
                diagnostic: format!(
                    "authenticated file-program evaluation failed: {error:#}\n- {collection_detail}"
                ),
            }
        }
        Ok(AuthenticatedEvaluation::Lifecycle(status)) => append_authenticated_file_diagnostic(
            authenticated_file_lifecycle_outcome(lifecycle, status),
            &collection_detail,
        ),
        Ok(AuthenticatedEvaluation::Throw(thrown)) => AuthenticatedFileProgramOutcome::Failed {
            status: EXIT_STATUS_NON_INTERACTIVE_FAILURE,
            diagnostic: format!(
                "{}\n- {collection_detail}",
                authenticated_file_throw_diagnostic(thrown)
            ),
        },
        Ok(AuthenticatedEvaluation::Cancelled) => AuthenticatedFileProgramOutcome::Failed {
            status: EXIT_STATUS_INTERRUPT,
            diagnostic: format!(
                "authenticated file-program evaluation was cancelled\n- {collection_detail}"
            ),
        },
        Ok(AuthenticatedEvaluation::Value { receipt, .. }) => {
            let receipt_cleanup_error = match receipt {
                Some(receipt) => engine.release_undisplayed_value(receipt).await.err(),
                None => None,
            };
            if let Some(request) = lifecycle.take_pending_request() {
                let mut outcome = authenticated_file_lifecycle(request.status);
                outcome = append_authenticated_file_diagnostic(outcome, &collection_detail);
                if let Some(error) = receipt_cleanup_error {
                    outcome = append_authenticated_file_diagnostic(
                        outcome,
                        &format!("suppressed-result cleanup also failed: {error:#}"),
                    );
                }
                return outcome;
            }
            let mut diagnostic = collection_detail;
            if let Some(error) = receipt_cleanup_error {
                diagnostic.push_str(&format!(
                    "\n- suppressed-result cleanup also failed: {error:#}"
                ));
            }
            AuthenticatedFileProgramOutcome::Failed {
                status: EXIT_STATUS_ENGINE_FAULT,
                diagnostic,
            }
        }
        Ok(AuthenticatedEvaluation::Empty) => {
            if let Some(request) = lifecycle.take_pending_request() {
                append_authenticated_file_diagnostic(
                    authenticated_file_lifecycle(request.status),
                    &collection_detail,
                )
            } else {
                AuthenticatedFileProgramOutcome::Failed {
                    status: EXIT_STATUS_ENGINE_FAULT,
                    diagnostic: collection_detail,
                }
            }
        }
    }
}

/// Apply the LLP 0025 non-interactive cause precedence after authenticated
/// file evaluation. The engine reports asynchronous failures but never chooses
/// process fatality; this consumer must drain and classify them before orderly
/// `process.exitCode` can be consulted by the CLI owner.
/// @ref LLP 0024#9-asynchronous-failures
/// @ref LLP 0025#8-exit-and-lifecycle
async fn settle_authenticated_file_program(
    engine: &dyn Engine,
    lifecycle: &ibex_runtime::session_lifecycle::SessionLifecyclePort,
    evaluation: std::result::Result<
        crate::engine::AuthenticatedEvaluation,
        AuthenticatedEvaluationFailure,
    >,
) -> Result<AuthenticatedFileProgramOutcome> {
    use crate::engine::AuthenticatedEvaluation;
    use ibex_runtime::session_constants::{
        EXIT_STATUS_ENGINE_FAULT, EXIT_STATUS_INTERRUPT, EXIT_STATUS_NON_INTERACTIVE_FAILURE,
    };

    let initial_async_failures = match engine.take_authenticated_async_failures().await {
        Ok(failures) => failures,
        Err(error) => {
            return Ok(preserve_file_evaluation_after_async_collection_error(
                engine, lifecycle, evaluation, error,
            )
            .await)
        }
    };
    if !initial_async_failures.is_empty() {
        // Background work can become reportable while a top-level-await file
        // evaluation is still in flight. Classify that already-published event
        // before the later foreground outcome, matching the worker-program
        // settlement path. If the foreground outcome retained a value, release
        // it as cleanup without allowing a cleanup failure to replace the
        // already-latched asynchronous cause.
        let receipt_cleanup_error = match evaluation {
            Ok(crate::engine::AuthenticatedEvaluation::Value {
                receipt: Some(receipt),
                ..
            }) => engine.release_undisplayed_value(receipt).await.err(),
            _ => None,
        };
        return Ok(authenticated_file_async_failure_outcome(
            initial_async_failures,
            receipt_cleanup_error,
        ));
    }

    let evaluation = match evaluation {
        Ok(evaluation) => evaluation,
        Err(error) => {
            let status = if error.is_engine_fault() {
                EXIT_STATUS_ENGINE_FAULT
            } else {
                EXIT_STATUS_NON_INTERACTIVE_FAILURE
            };
            return Ok(AuthenticatedFileProgramOutcome::Failed {
                status,
                diagnostic: format!("authenticated file-program evaluation failed: {error:#}"),
            });
        }
    };

    match evaluation {
        AuthenticatedEvaluation::Lifecycle(status) => {
            // The Host's accepted request is supervisor-authoritative. The
            // engine outcome is only a paired notification and may not select
            // a different status or manufacture a lifecycle cause.
            return Ok(authenticated_file_lifecycle_outcome(lifecycle, status));
        }
        AuthenticatedEvaluation::Throw(thrown) => {
            return Ok(AuthenticatedFileProgramOutcome::Failed {
                status: EXIT_STATUS_NON_INTERACTIVE_FAILURE,
                diagnostic: authenticated_file_throw_diagnostic(thrown),
            });
        }
        AuthenticatedEvaluation::Cancelled => {
            return Ok(AuthenticatedFileProgramOutcome::Failed {
                status: EXIT_STATUS_INTERRUPT,
                diagnostic: "authenticated file-program evaluation was cancelled".to_owned(),
            });
        }
        AuthenticatedEvaluation::Value { receipt, .. } => {
            if let Some(receipt) = receipt {
                // Observe lifecycle on both sides of the potentially blocking
                // release. Once accepted, that request is the primary cause;
                // a release failure is secondary cleanup damage only.
                let request_before_release = lifecycle.take_pending_request();
                let release_error = engine.release_undisplayed_value(receipt).await.err();
                if let Some(outcome) = authenticated_file_release_outcome(
                    lifecycle,
                    request_before_release,
                    release_error,
                ) {
                    return Ok(outcome);
                }
            }
        }
        AuthenticatedEvaluation::Empty => {}
    }

    // A cooperative request can arrive while foreground evaluation is in
    // flight without being encoded in that evaluation's result. Latch it
    // before starting any more program work, just as the worker settlement
    // path does; a later drain failure must not replace this earlier cause.
    if let Some(request) = lifecycle.take_pending_request() {
        return Ok(authenticated_file_lifecycle(request.status));
    }

    // Keep the drain result pending until the asynchronous-event and lifecycle
    // channels have been inspected. A failure published earlier in the drain
    // wins before a later cooperative request; otherwise the request carries
    // the primary cause. Both override orderly process.exitCode.
    let drain = engine.drive_authenticated_program_to_quiescence().await;
    let async_failures = match engine.take_authenticated_async_failures().await {
        Ok(failures) => failures,
        Err(collection_error) => {
            // A request committed while the program drain was running is an
            // already-latched cause. Collection failure is later diagnostic
            // damage and cannot replace it.
            if let Some(request) = lifecycle.take_pending_request() {
                return Ok(append_authenticated_file_diagnostic(
                    authenticated_file_lifecycle(request.status),
                    &format!(
                        "asynchronous failure collection failed after cooperative exit: {collection_error:#}"
                    ),
                ));
            }
            return Ok(match drain {
                Err(error) => {
                    let status = if error.is_engine_fault() {
                        EXIT_STATUS_ENGINE_FAULT
                    } else {
                        EXIT_STATUS_NON_INTERACTIVE_FAILURE
                    };
                    AuthenticatedFileProgramOutcome::Failed {
                        status,
                        diagnostic: format!(
                            "authenticated file-program drain failed: {error:#}\n- asynchronous failure collection also failed: {collection_error:#}"
                        ),
                    }
                }
                Ok(()) => AuthenticatedFileProgramOutcome::Failed {
                    status: EXIT_STATUS_ENGINE_FAULT,
                    diagnostic: format!(
                        "asynchronous failure collection failed after the authenticated file-program drain: {collection_error:#}"
                    ),
                },
            });
        }
    };
    if !async_failures.is_empty() {
        return Ok(authenticated_file_async_failure_outcome(
            async_failures,
            None,
        ));
    }

    if let Some(request) = lifecycle.take_pending_request() {
        return Ok(authenticated_file_lifecycle(request.status));
    }

    if let Err(error) = drain {
        let status = if error.is_engine_fault() {
            EXIT_STATUS_ENGINE_FAULT
        } else {
            EXIT_STATUS_NON_INTERACTIVE_FAILURE
        };
        return Ok(AuthenticatedFileProgramOutcome::Failed {
            status,
            diagnostic: format!("authenticated file-program drain failed: {error:#}"),
        });
    }

    Ok(AuthenticatedFileProgramOutcome::Completed)
}

/// Settle one ready-only turn after `--keep-alive` has reopened an otherwise
/// completed authenticated file session. Each turn drains the structured
/// asynchronous-failure lane before treating a cooperative request or engine
/// error as primary, matching the full program settlement above without
/// waiting for the keep-alive set to become empty.
/// @ref LLP 0024#9-asynchronous-failures
/// @ref LLP 0025#8-exit-and-lifecycle
async fn settle_authenticated_file_keep_alive_tick(
    engine: &dyn Engine,
    lifecycle: &ibex_runtime::session_lifecycle::SessionLifecyclePort,
) -> Option<AuthenticatedFileProgramOutcome> {
    use ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT;

    let initial_async_failures = match engine.take_authenticated_async_failures().await {
        Ok(failures) => failures,
        Err(error) => {
            let detail = format!(
                "asynchronous failure collection failed before the authenticated file keep-alive turn: {error:#}"
            );
            if let Some(request) = lifecycle.take_pending_request() {
                return Some(append_authenticated_file_diagnostic(
                    authenticated_file_lifecycle(request.status),
                    &detail,
                ));
            }
            return Some(AuthenticatedFileProgramOutcome::Failed {
                status: EXIT_STATUS_ENGINE_FAULT,
                diagnostic: detail,
            });
        }
    };
    if !initial_async_failures.is_empty() {
        return Some(authenticated_file_async_failure_outcome(
            initial_async_failures,
            None,
        ));
    }
    if let Some(request) = lifecycle.take_pending_request() {
        return Some(authenticated_file_lifecycle(request.status));
    }

    let drive = engine.drive_ready_tasks().await;
    let async_failures = match engine.take_authenticated_async_failures().await {
        Ok(failures) => failures,
        Err(collection_error) => {
            let collection_detail = format!(
                "asynchronous failure collection failed after the authenticated file keep-alive turn: {collection_error:#}"
            );
            if let Some(request) = lifecycle.take_pending_request() {
                return Some(append_authenticated_file_diagnostic(
                    authenticated_file_lifecycle(request.status),
                    &collection_detail,
                ));
            }
            return Some(match drive {
                Ok(()) => AuthenticatedFileProgramOutcome::Failed {
                    status: EXIT_STATUS_ENGINE_FAULT,
                    diagnostic: collection_detail,
                },
                Err(error) => AuthenticatedFileProgramOutcome::Failed {
                    status: EXIT_STATUS_ENGINE_FAULT,
                    diagnostic: format!(
                        "authenticated file keep-alive event-loop drive failed: {error:#}\n- {collection_detail}"
                    ),
                },
            });
        }
    };
    if !async_failures.is_empty() {
        return Some(authenticated_file_async_failure_outcome(
            async_failures,
            None,
        ));
    }
    if let Some(request) = lifecycle.take_pending_request() {
        // Hermes reports its typed lifecycle stop through the same negative
        // ready-poll return used for faults. The authenticated Host record is
        // authoritative, so that paired drive error cannot replace or tarnish
        // the cooperative cause.
        return Some(authenticated_file_lifecycle(request.status));
    }
    drive
        .err()
        .map(|error| AuthenticatedFileProgramOutcome::Failed {
            status: EXIT_STATUS_ENGINE_FAULT,
            diagnostic: format!("authenticated file keep-alive event-loop drive failed: {error:#}"),
        })
}

pub(crate) type ReplEvaluationFailure = AuthenticatedEvaluationFailure;

/// Closed source ingress for the two non-file inline product routes.
///
/// `-e`/`-p`/`ibex eval` and program stdin share the authenticated native
/// evaluator with the REPL, but they do not share its session record or
/// command surface. Their exact entry tuple selects one fixed constructor in
/// `SubmissionSequence`; source bytes are the only caller-controlled field.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
/// @ref LLP 0024#1-the-in-memory-source-api
pub(crate) struct AuthenticatedInlineIngress {
    _host: Host,
    session: ibex_runtime::engine::evaluation::ArmedSessionToken,
    sequence: ibex_runtime::engine::evaluation::SubmissionSequence,
    project_referrer: capsec_semantics::model::LogicalPath,
    session_io: crate::terminal_session::SessionIoPlan,
}

/// Closed direct-file source ingress. The entry path is reconstructed only
/// from the digest-bound virtual file URL retained by the armed snapshot; the
/// original host spelling, persistent bundle bytes, `require` wrapper, and
/// bare file evaluator are not part of this route.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
/// @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
/// @ref LLP 0023#2-identity-versus-spelling
/// @ref LLP 0024#1-the-in-memory-source-api
pub(crate) struct AuthenticatedFileIngress {
    host: Host,
    vfs: ibex_runtime::vfs::VirtualFileSystem,
    session: ibex_runtime::engine::evaluation::ArmedSessionToken,
    sequence: ibex_runtime::engine::evaluation::SubmissionSequence,
    entry: ibex_runtime::vfs::NamespacePath,
    project_root: std::path::PathBuf,
    /// Exact binary-runtime cache root authenticated before arming and reused
    /// as the parent of fresh generated artifacts and read-only prepared graph
    /// cache hints. It is never rediscovered after arming.
    runtime_cache_root: std::path::PathBuf,
    bundle_format: BundleFormat,
    session_io: crate::terminal_session::SessionIoPlan,
}

#[cfg(feature = "module-runner")]
struct RuntimePreparedActivationCacheLocator {
    runtime_cache_root: PathBuf,
    project_root: PathBuf,
    source_entry: PathBuf,
    bundle_format: BundleFormat,
}

#[cfg(feature = "module-runner")]
impl ibex_runtime::module_loader::runner_pipeline::PreparedActivationCacheLocatorV1
    for RuntimePreparedActivationCacheLocator
{
    fn locate(
        &self,
        _target: &ibex_runtime::module_loader::identity::SourceId,
    ) -> Result<Vec<ibex_runtime::module_loader::runner_pipeline::PreparedActivationCacheCandidateV1>>
    {
        #[cfg(test)]
        PREPARED_ACTIVATION_LOCATOR_CALLS.fetch_add(1, Ordering::SeqCst);

        use ibex_runtime::module_loader::artifact::digest_bytes;
        use ibex_runtime::module_loader::runner_pipeline::{
            prepared_graph_cache_dir, PreparedActivationCacheCandidateV1,
        };

        let checked_cache = ibex_runtime::cache_topology::authenticate_internal_cache_root(
            &self.runtime_cache_root,
            std::slice::from_ref(&self.project_root),
        )
        .context("authenticated activation cache no longer has safe topology")?;
        anyhow::ensure!(
            checked_cache == self.runtime_cache_root,
            "authenticated activation cache canonical path changed after arming"
        );
        let bundles_root = self.runtime_cache_root.join("bundles");
        let metadata = match std::fs::symlink_metadata(&bundles_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Ok(Vec::new());
        }
        let canonical_bundles_root = match std::fs::canonicalize(&bundles_root) {
            Ok(path) if path.parent() == Some(self.runtime_cache_root.as_path()) => path,
            _ => return Ok(Vec::new()),
        };

        let mut formats = vec![self.bundle_format];
        if self.bundle_format == BundleFormat::Cjs {
            formats.push(BundleFormat::Esm);
        }
        let mut discovered = Vec::new();
        for format in formats {
            let cache_key = bundle_cache_key(&self.source_entry, format)?;
            let artifact_root = bundle_artifact_root(&canonical_bundles_root, &cache_key);
            let mut artifact_dirs = match std::fs::read_dir(&artifact_root) {
                Ok(entries) => entries
                    .filter_map(std::result::Result::ok)
                    .filter_map(|entry| {
                        entry
                            .file_type()
                            .ok()
                            .filter(|kind| kind.is_dir() && !kind.is_symlink())
                            .filter(|_| !entry.file_name().to_string_lossy().starts_with('.'))
                            .map(|_| entry.path())
                    })
                    .collect::<Vec<_>>(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => continue,
            };
            artifact_dirs.sort();
            for artifact_dir in artifact_dirs {
                let output = bundle_entry_path(&artifact_dir, format);
                let Ok(manifest) = read_bundle_manifest_once(&output) else {
                    continue;
                };
                if !matches!(manifest.version, 3 | 4) || !valid_sha256(&manifest.graph_digest) {
                    continue;
                }
                let deployment_graph_digest = digest_bytes(
                    "ibex/rolldown-deployment-graph/1",
                    manifest.graph_digest.as_bytes(),
                )?;
                discovered.push(PreparedActivationCacheCandidateV1 {
                    cache_dir: prepared_graph_cache_dir(&artifact_dir, &deployment_graph_digest),
                    deployment_graph_digest,
                });
            }
        }
        Ok(discovered)
    }
}

/// Debug-only native-runner conformance uses the production publisher and
/// consumer at the exact post-acquisition activation boundary. This makes a
/// `prepared` receipt prove prepared carriers for modules reached after entry.
/// @ref LLP 0028#5-conformance-gates-telemetry-and-rollout
#[cfg(all(
    feature = "module-runner",
    debug_assertions,
    feature = "capsec-conformance-observer"
))]
struct NativeRunnerPreparedActivationCacheLocator {
    artifact_dir: PathBuf,
    deployment_graph_digest: capsec_semantics::model::Digest,
}

#[cfg(all(
    feature = "module-runner",
    debug_assertions,
    feature = "capsec-conformance-observer"
))]
impl ibex_runtime::module_loader::runner_pipeline::PreparedActivationCacheLocatorV1
    for NativeRunnerPreparedActivationCacheLocator
{
    fn publish_authenticated_records(
        &self,
        graph: &ibex_runtime::module_loader::runner_pipeline::SourceModuleGraphV1,
        record_ids: &std::collections::BTreeSet<ibex_runtime::module_loader::identity::SourceId>,
    ) -> Result<()> {
        ibex_runtime::module_loader::runner_pipeline::publish_prepared_activation_records_v1(
            graph,
            record_ids,
            &self.artifact_dir,
            self.deployment_graph_digest.clone(),
        )?;
        Ok(())
    }

    fn locate(
        &self,
        _target: &ibex_runtime::module_loader::identity::SourceId,
    ) -> Result<Vec<ibex_runtime::module_loader::runner_pipeline::PreparedActivationCacheCandidateV1>>
    {
        use ibex_runtime::module_loader::runner_pipeline::{
            prepared_graph_cache_dir, PreparedActivationCacheCandidateV1,
        };

        Ok(vec![PreparedActivationCacheCandidateV1 {
            cache_dir: prepared_graph_cache_dir(&self.artifact_dir, &self.deployment_graph_digest),
            deployment_graph_digest: self.deployment_graph_digest.clone(),
        }])
    }
}

struct PreparedAuthenticatedGeneratedEntry {
    entry: crate::engine::AuthenticatedGeneratedEntry,
}

/// Process-private scratch space for one authenticated generated evaluation.
///
/// A persistent bundle cache is only a performance hint: all of its hashes are
/// public and therefore cannot prove that its bytes came from the authenticated
/// compiler invocation.  Production generated admission instead compiles into
/// this unpredictable, non-reusable directory and retains owned bytes before
/// the directory is removed.
/// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
struct FreshGeneratedArtifactRoot {
    path: PathBuf,
}

impl FreshGeneratedArtifactRoot {
    fn create(cache_dir: &Path) -> Result<Self> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        std::fs::create_dir_all(cache_dir).with_context(|| {
            format!(
                "failed to create authenticated generated staging parent {}",
                cache_dir.display()
            )
        })?;
        for _ in 0..32 {
            let mut nonce = [0u8; 24];
            getrandom::getrandom(&mut nonce)
                .context("failed to name authenticated generated staging root")?;
            let path = cache_dir.join(format!(
                ".authenticated-generated-{}",
                URL_SAFE_NO_PAD.encode(nonce)
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => {
                    let metadata = std::fs::symlink_metadata(&path)?;
                    anyhow::ensure!(
                        metadata.is_dir() && !metadata.file_type().is_symlink(),
                        "authenticated generated staging root is not a directory"
                    );
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
                        anyhow::ensure!(
                            metadata.permissions().mode() & 0o077 == 0
                                && metadata.uid() == unsafe { libc::geteuid() },
                            "authenticated generated staging root is not process-private"
                        );
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create authenticated generated staging root {}",
                            path.display()
                        )
                    })
                }
            }
        }
        anyhow::bail!("failed to allocate a unique authenticated generated staging root")
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FreshGeneratedArtifactRoot {
    fn drop(&mut self) {
        // Prepared evaluation owns the bytes, never this pathname. Cleanup is
        // deliberately best-effort and cannot invalidate an admitted entry.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// One parity-safe virtual mount row copied out of the session VFS. No
/// backing-store spelling, descriptor, principal, or session handle is
/// represented in this view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplMountDescription {
    virtual_path: Arc<str>,
    logical_root: capsec_semantics::model::LogicalRoot,
    attributes: ibex_runtime::vfs::MountAttributes,
}

impl ReplMountDescription {
    pub(crate) fn from_worker_projection(
        virtual_path: Arc<str>,
        logical_root: capsec_semantics::model::LogicalRoot,
        attributes: ibex_runtime::vfs::MountAttributes,
    ) -> Self {
        Self {
            virtual_path,
            logical_root,
            attributes,
        }
    }

    pub(crate) fn virtual_path(&self) -> &str {
        &self.virtual_path
    }

    pub(crate) const fn logical_root(&self) -> capsec_semantics::model::LogicalRoot {
        self.logical_root
    }

    pub(crate) const fn attributes(&self) -> ibex_runtime::vfs::MountAttributes {
        self.attributes
    }
}

/// Read-only `.mounts` payload. It is an owned projection rather than a VFS
/// reference, so callers can render it but cannot resolve or open a path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplMountsDescription {
    virtual_cwd: Arc<str>,
    mounts: Vec<ReplMountDescription>,
}

impl ReplMountsDescription {
    pub(crate) fn from_worker_projection(
        virtual_cwd: Arc<str>,
        mounts: Vec<ReplMountDescription>,
    ) -> Self {
        Self {
            virtual_cwd,
            mounts,
        }
    }

    pub(crate) fn virtual_cwd(&self) -> &str {
        &self.virtual_cwd
    }

    pub(crate) fn mounts(&self) -> &[ReplMountDescription] {
        &self.mounts
    }
}

impl ReplSessionIngress {
    fn from_armed_repl_runtime(
        host: Host,
        session_io: crate::terminal_session::SessionIoPlan,
    ) -> Result<Self> {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let snapshot = host
            .armed_snapshot()
            .context("REPL source ingress requires an authenticated armed snapshot")?;
        let entry = snapshot.entry();
        entry
            .validate()
            .context("REPL source ingress refused an invalid authenticated entry tuple")?;
        if entry.kind != ArmedEntryKind::Repl
            || entry.identity.as_str() != "ibex:repl"
            || !matches!(
                entry.mode,
                ArmedExecutionMode::Interactive | ArmedExecutionMode::Transcript
            )
        {
            anyhow::bail!(
                "REPL source ingress requires the authenticated repl/ibex:repl entry tuple"
            );
        }
        if session_io.route.entry_kind != entry.kind
            || session_io.route.mode != entry.mode
            || session_io.route.synthetic_identity() != Some(entry.identity.as_str())
        {
            anyhow::bail!(
                "REPL source ingress session-I/O route does not match the authenticated entry tuple"
            );
        }

        let session = host
            .mint_armed_session_token()
            .context("failed to retain the authenticated REPL session token")?;
        let sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
            .context("failed to claim the REPL submission sequence")?;

        Ok(Self {
            host,
            session,
            sequence,
            session_io,
        })
    }

    /// Semantic input mode captured before arming and matched exactly against
    /// the authenticated entry. Callers do not re-observe stdin or the TTY.
    pub(crate) const fn mode(&self) -> capsec_semantics::arming::ArmedExecutionMode {
        self.session_io.route.mode
    }

    /// Presentation facts captured before arming. This is a read-only value;
    /// it cannot grant editor control or ANSI output that capture did not.
    pub(crate) const fn presentation(&self) -> crate::terminal_session::CapturedPresentation {
        self.session_io.presentation
    }

    /// Shared supervisor/Host lifecycle state retained by this closed session.
    pub(crate) fn session_lifecycle(
        &self,
    ) -> ibex_runtime::session_lifecycle::SessionLifecyclePort {
        self.host.session_lifecycle()
    }

    /// Canonical operator `.exit` route with Host-supplied authority inputs.
    pub(crate) fn request_operator_exit(
        &self,
    ) -> ibex_runtime::session_lifecycle::LifecycleRequestDisposition {
        self.host.request_operator_exit()
    }

    /// Copy the parity-safe virtual mount table and cwd for `.mounts`.
    /// @ref LLP 0022#8-commands — `.mounts` exposes only what prompt code can
    /// discover by probing the virtual namespace.
    /// @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
    pub(crate) async fn mounts_description(
        &self,
        engine: &dyn Engine,
    ) -> Result<ReplMountsDescription> {
        let runtime_vfs = engine
            .authenticated_runtime_vfs(&self.host)
            .await
            .context("failed to retain the authenticated REPL runtime namespace")?;
        let cwd = runtime_vfs
            .capture_cwd()
            .context("failed to capture the authenticated REPL virtual cwd")?;
        Ok(ReplMountsDescription {
            virtual_cwd: Arc::from(cwd.virtual_path()),
            mounts: runtime_vfs
                .mounts()?
                .iter()
                .map(|mount| ReplMountDescription {
                    virtual_path: Arc::from(mount.virtual_path()),
                    logical_root: mount.logical_root(),
                    attributes: mount.attributes(),
                })
                .collect(),
        })
    }

    /// Evaluate one prompt or transcript record through the fixed REPL source
    /// shape. The byte limit is checked before an ordinal becomes in-flight;
    /// strict UTF-8 validation happens while closing the immutable capsule.
    pub(crate) async fn evaluate_inline(
        &mut self,
        engine: &dyn Engine,
        bytes: Vec<u8>,
    ) -> std::result::Result<crate::engine::AuthenticatedEvaluation, ReplEvaluationFailure> {
        let runtime_vfs = engine
            .authenticated_runtime_vfs(&self.host)
            .await
            .map_err(classify_authenticated_preparation_failure)?;
        let base = runtime_vfs
            .capture_cwd()
            .map_err(anyhow::Error::new)
            .map_err(classify_authenticated_preparation_failure)?;
        let request = self
            .inline_request(&base, bytes)
            .map_err(classify_authenticated_preparation_failure)?;
        engine
            .evaluate_authenticated(&self.session, request)
            .await
            .map_err(classify_authenticated_engine_failure)
    }

    /// Resolve and evaluate one `.load` argument through the authenticated
    /// VFS. Script requests enter the structured engine adapter; JSON requests
    /// are authenticated, parsed, and rendered by its Rust-only JSON arm.
    pub(crate) async fn evaluate_load(
        &mut self,
        engine: &dyn Engine,
        virtual_path: &str,
    ) -> std::result::Result<crate::engine::AuthenticatedEvaluation, ReplEvaluationFailure> {
        let runtime_vfs = engine
            .authenticated_runtime_vfs(&self.host)
            .await
            .map_err(classify_authenticated_preparation_failure)?;
        let request = self
            .load_request(&runtime_vfs, virtual_path)
            .map_err(classify_authenticated_preparation_failure)?;
        engine
            .evaluate_authenticated(&self.session, request)
            .await
            .map_err(classify_authenticated_engine_failure)
    }

    fn inline_request(
        &mut self,
        base: &ibex_runtime::vfs::NamespacePath,
        bytes: Vec<u8>,
    ) -> Result<ibex_runtime::engine::evaluation::SourceRequest> {
        use ibex_runtime::engine::evaluation::SourceRefusal;

        let max_bytes = ibex_runtime::session_constants::MAX_INPUT_BYTES;
        if bytes.len() > max_bytes {
            return Err(SourceRefusal::InputTooLarge { max_bytes }.into());
        }
        let referrer = base
            .logical_path()
            .filter(capsec_semantics::model::LogicalPath::is_canonical)
            .context("authenticated REPL cwd has no canonical logical identity")?;
        self.sequence
            .mint_repl(referrer)?
            .authorize_inline()
            .bind_bytes(bytes)
            .into_request()
            .map_err(Into::into)
    }

    fn load_request(
        &mut self,
        runtime_vfs: &ibex_runtime::vfs::AuthenticatedRuntimeVfs,
        virtual_path: &str,
    ) -> Result<ibex_runtime::engine::evaluation::SourceRequest> {
        // The command argument is passed verbatim to the VFS grammar. Only the
        // resolved namespace's canonical spelling is allowed to label and
        // authorize the loaded bytes.
        let namespace = runtime_vfs.resolve(virtual_path.as_bytes())?;
        let referrer = namespace.logical_referrer()?;
        let canonical_virtual_path = Arc::<str>::from(namespace.virtual_path());
        let submission = self.sequence.mint_load(canonical_virtual_path, referrer)?;
        self.host
            .authenticated_vfs_script_read(
                runtime_vfs.virtual_file_system()?,
                namespace,
                submission,
            )?
            .into_capsule()
            .into_request()
            .map_err(Into::into)
    }
}

fn classify_authenticated_preparation_failure(
    error: anyhow::Error,
) -> AuthenticatedEvaluationFailure {
    use ibex_runtime::engine::evaluation::SourceRefusal;
    use ibex_runtime::vfs::VfsReason;

    let recoverable_source = error
        .downcast_ref::<SourceRefusal>()
        .is_some_and(|refusal| {
            matches!(
                refusal,
                SourceRefusal::InvalidUtf8 { .. }
                    | SourceRefusal::InputTooLarge { .. }
                    | SourceRefusal::LoadModuleKindRefused
                    | SourceRefusal::LoadTypesOnlyRefused
                    | SourceRefusal::LoadUnsupportedPath
                    | SourceRefusal::FileEntryAlreadySubmitted
                    | SourceRefusal::FileBytecodeUnsupported
                    | SourceRefusal::FileUnsupportedPath
            )
        });
    let recoverable_vfs = error
        .downcast_ref::<ibex_runtime::vfs::VfsError>()
        .is_some_and(|error| {
            matches!(
                error.reason(),
                VfsReason::MalformedInput
                    | VfsReason::EncodedSeparator
                    | VfsReason::OutsideMount
                    | VfsReason::SyntheticNode
                    | VfsReason::PolicyDenied
                    | VfsReason::Absent
                    | VfsReason::SymlinkDepthExceeded
                    | VfsReason::UnmappableLink
                    | VfsReason::StaleIdentity
                    | VfsReason::InputTooLarge
                    | VfsReason::HostError
            )
        });
    if recoverable_source || recoverable_vfs {
        AuthenticatedEvaluationFailure::Refusal(error)
    } else {
        AuthenticatedEvaluationFailure::EngineFault(error)
    }
}

fn classify_authenticated_engine_failure(error: anyhow::Error) -> AuthenticatedEvaluationFailure {
    let recoverable = error
        .downcast_ref::<ibex_runtime::engine::evaluation::EngineFault>()
        .is_some_and(|fault| {
            matches!(
                fault,
                ibex_runtime::engine::evaluation::EngineFault::Rejected(_)
            )
        });
    if recoverable {
        AuthenticatedEvaluationFailure::Refusal(error)
    } else {
        AuthenticatedEvaluationFailure::EngineFault(error)
    }
}

impl AuthenticatedInlineIngress {
    fn from_armed_runtime(
        host: Host,
        session_io: crate::terminal_session::SessionIoPlan,
    ) -> Result<Self> {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let snapshot = host
            .armed_snapshot()
            .context("inline source ingress requires an authenticated armed snapshot")?;
        let entry = snapshot.entry();
        entry
            .validate()
            .context("inline source ingress refused an invalid authenticated entry tuple")?;
        let supported = matches!(
            (entry.kind, entry.mode, entry.identity.as_str()),
            (
                ArmedEntryKind::Eval,
                ArmedExecutionMode::OneShot,
                "ibex:eval"
            ) | (
                ArmedEntryKind::Stdin,
                ArmedExecutionMode::Program,
                "ibex:stdin"
            )
        );
        if !supported {
            anyhow::bail!(
                "inline source ingress requires the authenticated eval/one-shot or stdin/program entry tuple"
            );
        }
        if session_io.route.entry_kind != entry.kind
            || session_io.route.mode != entry.mode
            || session_io.route.synthetic_identity() != Some(entry.identity.as_str())
        {
            anyhow::bail!(
                "inline source ingress session-I/O route does not match the authenticated entry tuple"
            );
        }

        let session = host
            .mint_armed_session_token()
            .context("failed to retain the authenticated inline session token")?;
        let project_referrer = {
            let vfs = host
                .virtual_file_system()
                .context("failed to construct the authenticated inline virtual filesystem")?;
            let result = vfs
                .default_base()
                .context("authenticated inline route has no virtual project root")?
                .logical_path()
                .filter(capsec_semantics::model::LogicalPath::is_canonical)
                .context("authenticated inline project root has no canonical logical identity");
            vfs.close();
            result?
        };
        let sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
            .context("failed to claim the inline submission sequence")?;

        Ok(Self {
            _host: host,
            session,
            sequence,
            project_referrer,
            session_io,
        })
    }

    pub(crate) const fn mode(&self) -> capsec_semantics::arming::ArmedExecutionMode {
        self.session_io.route.mode
    }

    pub(crate) const fn entry_kind(&self) -> capsec_semantics::arming::ArmedEntryKind {
        self.session_io.route.entry_kind
    }

    /// Evaluate the exact inline byte sequence after the fixed route has
    /// derived its source label, goal, dialect, role, module kind, main flag,
    /// referrer, principal, and opaque credential.
    pub(crate) async fn evaluate(
        &mut self,
        engine: &dyn Engine,
        bytes: Vec<u8>,
    ) -> std::result::Result<crate::engine::AuthenticatedEvaluation, AuthenticatedEvaluationFailure>
    {
        let request = self
            .inline_request(bytes)
            .map_err(classify_authenticated_preparation_failure)?;
        engine
            .evaluate_authenticated(&self.session, request)
            .await
            .map_err(classify_authenticated_engine_failure)
    }

    fn inline_request(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<ibex_runtime::engine::evaluation::SourceRequest> {
        use capsec_semantics::arming::ArmedEntryKind;
        use ibex_runtime::engine::evaluation::SourceRefusal;

        let max_bytes = ibex_runtime::session_constants::MAX_INPUT_BYTES;
        if bytes.len() > max_bytes {
            return Err(SourceRefusal::InputTooLarge { max_bytes }.into());
        }
        let submission = match self.entry_kind() {
            ArmedEntryKind::Eval => self.sequence.mint_eval(self.project_referrer.clone())?,
            ArmedEntryKind::Stdin => self.sequence.mint_stdin(self.project_referrer.clone())?,
            ArmedEntryKind::File | ArmedEntryKind::Repl => {
                anyhow::bail!("inline source ingress route changed after authentication")
            }
        };
        let request = submission
            .authorize_inline()
            .bind_bytes(bytes)
            .into_request()?;
        Ok(request)
    }
}

impl AuthenticatedFileIngress {
    fn from_armed_runtime(
        host: Host,
        project_root: std::path::PathBuf,
        runtime_cache_root: std::path::PathBuf,
        bundle_format: BundleFormat,
        session_io: crate::terminal_session::SessionIoPlan,
    ) -> Result<Self> {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let snapshot = host
            .armed_snapshot()
            .context("file source ingress requires an authenticated armed snapshot")?;
        let armed_entry = snapshot.entry();
        armed_entry
            .validate()
            .context("file source ingress refused an invalid authenticated entry tuple")?;
        if armed_entry.kind != ArmedEntryKind::File
            || armed_entry.mode != ArmedExecutionMode::Program
            || session_io.route.entry_kind != armed_entry.kind
            || session_io.route.mode != armed_entry.mode
        {
            anyhow::bail!(
                "file source ingress requires the authenticated file/program entry tuple"
            );
        }

        let vfs = host
            .virtual_file_system()
            .context("failed to construct the authenticated file virtual filesystem")?;
        let entry = vfs
            .resolve_root_file_url(armed_entry.identity.as_str(), None)
            .context("authenticated file identity is outside the virtual project namespace")?;
        let source_label = ibex_runtime::vfs::SourceLabel::file(&entry)
            .context("authenticated file entry has no canonical source label")?;
        anyhow::ensure!(
            source_label.as_str() == armed_entry.identity.as_str(),
            "authenticated file entry label changed during virtual resolution"
        );
        let session = host
            .mint_armed_session_token()
            .context("failed to retain the authenticated file session token")?;
        let sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
            .context("failed to claim the file submission sequence")?;
        Ok(Self {
            host,
            vfs,
            session,
            sequence,
            entry,
            project_root,
            runtime_cache_root,
            bundle_format,
            session_io,
        })
    }

    pub(crate) const fn mode(&self) -> capsec_semantics::arming::ArmedExecutionMode {
        self.session_io.route.mode
    }

    pub(crate) const fn entry_kind(&self) -> capsec_semantics::arming::ArmedEntryKind {
        self.session_io.route.entry_kind
    }

    pub(crate) async fn evaluate(
        &mut self,
        engine: &dyn Engine,
        user_arguments: &[String],
    ) -> std::result::Result<crate::engine::AuthenticatedEvaluation, AuthenticatedEvaluationFailure>
    {
        let mut phase = StartupPhaseTrace::begin();
        let request = self
            .file_request(user_arguments)
            .map_err(classify_authenticated_preparation_failure)?;
        phase.mark("file_request");
        #[cfg(feature = "module-runner")]
        if matches!(
            &request,
            ibex_runtime::engine::evaluation::SourceRequest::Program(program)
                if program.module_kind().is_some()
        ) {
            if current_native_module_runner_target_is_advertised() {
                return engine
                    .evaluate_authenticated_module_graph(
                        &self.session,
                        request,
                        Box::new(|admitted_request| {
                            self.prepare_authenticated_module_graph(admitted_request)
                        }),
                    )
                    .await
                    .map_err(classify_authenticated_engine_failure);
            }
            if !legacy_module_loader_window_is_open() {
                return Err(classify_authenticated_preparation_failure(anyhow::anyhow!(
                    "native module runner is not advertised for {}-{} and the bounded legacy loader window is closed",
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                )));
            }
            eprintln!(
                "warning: native module runner is unadvertised for {}-{}; using compatibility loader through {}",
                std::env::consts::OS,
                std::env::consts::ARCH,
                LEGACY_MODULE_LOADER_LAST_SUPPORTED_MINOR,
            );
        }
        let generated = self
            .prepare_authenticated_generated_entry(&request)
            .await
            .ok()
            .flatten();
        match generated {
            Some(prepared) => engine
                .evaluate_authenticated_generated(&self.session, request, prepared.entry)
                .await
                .map_err(classify_authenticated_engine_failure),
            None => engine
                .evaluate_authenticated(&self.session, request)
                .await
                .map_err(classify_authenticated_engine_failure),
        }
    }

    fn file_request(
        &mut self,
        user_arguments: &[String],
    ) -> Result<ibex_runtime::engine::evaluation::SourceRequest> {
        let referrer = self.entry.logical_referrer()?;
        let submission = self.sequence.mint_file(referrer, user_arguments)?;
        let read =
            self.host
                .authenticated_vfs_file_read(&self.vfs, self.entry.clone(), submission)?;
        anyhow::ensure!(
            read.source_id().is_some(),
            "authenticated file read omitted its module SourceId"
        );
        read.into_capsule()
            .into_request()
            .map_err(anyhow::Error::new)
    }

    #[cfg(feature = "module-runner")]
    fn prepare_authenticated_module_graph(
        &self,
        request: &ibex_runtime::engine::evaluation::SourceRequest,
    ) -> Result<crate::engine::AuthenticatedModuleGraphPreparation> {
        use crate::engine::AuthenticatedModuleGraphPreparation;
        use ibex_runtime::module_loader::generation::ExecutionGeneration;
        use ibex_runtime::module_loader::runner_pipeline::{
            build_authenticated_source_graph_v1_for_host, SourceModuleGraphBuildV1,
        };

        let mut phase = StartupPhaseTrace::begin();
        let (_, source_entry) = self.authenticated_source_entry(request)?;
        phase.mark("graph_source_entry");
        let test_profile = native_runner_test_profile()?;

        // A production commitment changes admission mode before graph work:
        // attempt the parse-free publication first. Any refusal goes directly
        // to a cold authenticated source build; this startup must not rejoin
        // and accept the cache generation the independent authority refused.
        // @ref LLP 0042#migration-and-coexistence
        let commitment = if test_profile.is_none() {
            self.prepared_commitment_for_entry(&source_entry)?
        } else {
            None
        };
        let committed_attempted = commitment.is_some();
        if let Some(commitment) = commitment {
            match self.load_committed_prepared_module_graph(&source_entry, request, &commitment) {
                Ok(Some(graph)) => {
                    phase.mark("graph_committed_select");
                    return Ok(AuthenticatedModuleGraphPreparation::Native(graph));
                }
                Ok(None) => {
                    eprintln!(
                        "ibex prepared admission: committed publication missing; rebuilding cold"
                    );
                }
                Err(error) => {
                    eprintln!(
                        "ibex prepared admission refused; rebuilding cold before evaluation: {error:#}"
                    );
                }
            }
            phase.mark("graph_committed_refuse");
        }

        // The Host constructs this complete source graph only after the exact
        // entry request has been admitted and its virtual identity has been
        // re-derived above. Prepared bytes are an optional source-mode
        // acceleration; a cache miss must not put an asynchronous bundler
        // between native admission and evaluation.
        // @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
        // @ref LLP 0027#canonical-encoding-and-validation
        // @ref LLP 0055#1-the-hotrevision-counter-and-successor-law — v1 boot mints INITIAL; the producing-session mint arrives with Exact H2 wiring.
        let mut graph = match build_authenticated_source_graph_v1_for_host(
            &self.host,
            &source_entry,
            module_producer_binary_digest()?,
            &engine::hermes::bytecode_cache_identity(),
            ExecutionGeneration::INITIAL,
        )? {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                if test_profile.is_some() {
                    let telemetry = requirement.telemetry_event(env!("CARGO_PKG_VERSION"))?;
                    eprintln!(
                        "{}{}",
                        ibex_runtime::module_loader::compatibility::LEGACY_REQUIRED_TELEMETRY_PREFIX,
                        serde_json::to_string(&telemetry)?
                    );
                    let diagnostic = format!(
                        "native module-runner conformance quarantine: {}",
                        requirement
                    );
                    eprintln!("{diagnostic}");
                    anyhow::bail!(diagnostic);
                }
                if !legacy_module_loader_window_is_open() {
                    anyhow::bail!(
                        "native module runner does not support this graph and the bounded legacy loader window is closed: {}",
                        requirement.reason
                    );
                }
                eprintln!(
                    "warning: native module runner compatibility fallback (expires after {}): {}",
                    LEGACY_MODULE_LOADER_LAST_SUPPORTED_MINOR, requirement.reason
                );
                return Ok(AuthenticatedModuleGraphPreparation::LegacyRequired);
            }
        };
        phase.mark("graph_build");
        graph.set_prepared_activation_cache_locator(Arc::new(
            RuntimePreparedActivationCacheLocator {
                runtime_cache_root: self.runtime_cache_root.clone(),
                project_root: self.project_root.clone(),
                source_entry: source_entry.clone(),
                bundle_format: self.bundle_format,
            },
        ));
        let entry_join = graph.validate_authenticated_entry_request(request)?;
        let (_, retained_entry_path, _) = graph
            .records()
            .find(|(source_id, _, _)| *source_id == graph.entry())
            .context("authenticated native source graph omitted its entry record")?;
        anyhow::ensure!(
            retained_entry_path == source_entry,
            "authenticated native source graph identity changed after the structured request was admitted"
        );
        phase.mark("graph_validate");

        match test_profile {
            Some(NativeRunnerTestProfile::Source) => {
                return Ok(AuthenticatedModuleGraphPreparation::Native(graph));
            }
            Some(NativeRunnerTestProfile::Prepared) => {
                use ibex_runtime::module_loader::runner_pipeline::{
                    load_prepared_source_graph_v1, publish_prepared_source_graph_v1,
                };

                let deployment_digest = native_runner_test_deployment_digest(&graph)?;
                let artifact_dir = self.runtime_cache_root.join("native-runner-test");
                #[cfg(all(debug_assertions, feature = "capsec-conformance-observer"))]
                graph.set_prepared_activation_cache_locator(Arc::new(
                    NativeRunnerPreparedActivationCacheLocator {
                        artifact_dir: artifact_dir.clone(),
                        deployment_graph_digest: deployment_digest.clone(),
                    },
                ));
                #[cfg(not(all(debug_assertions, feature = "capsec-conformance-observer")))]
                anyhow::bail!(
                    "prepared native-runner conformance requires a debug build with the capsec-conformance-observer feature"
                );
                let cache_dir = publish_prepared_source_graph_v1(
                    &graph,
                    &artifact_dir,
                    deployment_digest.clone(),
                )?;
                let prepared = load_prepared_source_graph_v1(
                    &cache_dir,
                    &graph,
                    &entry_join,
                    &deployment_digest,
                )?;
                return Ok(AuthenticatedModuleGraphPreparation::Native(prepared));
            }
            None => {}
        }

        if !committed_attempted {
            if let Some(prepared) =
                self.load_authenticated_prepared_module_graph(&source_entry, &graph, &entry_join)?
            {
                phase.mark("graph_cache_select");
                return Ok(AuthenticatedModuleGraphPreparation::Native(prepared));
            }
        }
        phase.mark("graph_cache_select");
        Ok(AuthenticatedModuleGraphPreparation::Native(graph))
    }

    #[cfg(feature = "module-runner")]
    fn prepared_commitment_for_entry(
        &self,
        source_entry: &Path,
    ) -> Result<Option<capsec_semantics::arming::PreparedGraphCommitmentV1>> {
        use ibex_runtime::module_loader::identity::SourceId;

        let relative = source_entry
            .strip_prefix(&self.project_root)
            .context("authenticated module entry escapes the project root")?;
        let expected_components = relative
            .components()
            .map(|component| component.as_os_str().as_encoded_bytes())
            .collect::<Vec<_>>();
        let snapshot = self
            .host
            .armed_snapshot()
            .context("committed admission requires an armed snapshot")?;
        for commitment in snapshot.prepared_graphs() {
            let source_id = SourceId::decode(commitment.entry_source_id.as_str())?;
            let SourceId::File { principal, path } = source_id else {
                continue;
            };
            if !principal.is_root() || path.len() != expected_components.len() {
                continue;
            }
            if path
                .iter()
                .zip(&expected_components)
                .all(|(component, expected)| component.bytes() == *expected)
            {
                return Ok(Some(commitment.clone()));
            }
        }
        Ok(None)
    }

    #[cfg(feature = "module-runner")]
    fn load_committed_prepared_module_graph(
        &self,
        source_entry: &Path,
        request: &ibex_runtime::engine::evaluation::SourceRequest,
        commitment: &capsec_semantics::arming::PreparedGraphCommitmentV1,
    ) -> Result<Option<ibex_runtime::module_loader::runner_pipeline::SourceModuleGraphV1>> {
        use ibex_runtime::module_loader::artifact::digest_bytes;
        use ibex_runtime::module_loader::generation::ExecutionGeneration;
        use ibex_runtime::module_loader::runner_pipeline::{
            load_prepared_graph_committed_v1, prepared_graph_cache_dir,
        };

        let entry_vfs_source_id = request
            .source_id()
            .cloned()
            .context("authenticated module entry has no VFS SourceId")?;
        let checked_cache = ibex_runtime::cache_topology::authenticate_internal_cache_root(
            &self.runtime_cache_root,
            std::slice::from_ref(&self.project_root),
        )?;
        anyhow::ensure!(checked_cache == self.runtime_cache_root);
        let bundles_root = self.runtime_cache_root.join("bundles");
        let metadata = match std::fs::symlink_metadata(&bundles_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Ok(None);
        }
        let canonical_bundles_root = std::fs::canonicalize(&bundles_root)?;
        anyhow::ensure!(
            canonical_bundles_root.parent() == Some(self.runtime_cache_root.as_path()),
            "prepared bundle root escaped the authenticated runtime cache"
        );
        let mut formats = vec![self.bundle_format];
        if self.bundle_format == BundleFormat::Cjs {
            formats.push(BundleFormat::Esm);
        }
        for format in formats {
            let cache_key = bundle_cache_key(source_entry, format)?;
            let artifact_root = bundle_artifact_root(&canonical_bundles_root, &cache_key);
            let mut candidates = match std::fs::read_dir(&artifact_root) {
                Ok(entries) => entries
                    .filter_map(std::result::Result::ok)
                    .filter_map(|entry| {
                        entry
                            .file_type()
                            .ok()
                            .filter(|kind| kind.is_dir() && !kind.is_symlink())
                            .filter(|_| !entry.file_name().to_string_lossy().starts_with('.'))
                            .map(|_| entry.path())
                    })
                    .collect::<Vec<_>>(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            candidates.sort();
            for artifact_dir in candidates {
                let output = bundle_entry_path(&artifact_dir, format);
                let Ok(manifest) = read_bundle_manifest_once(&output) else {
                    continue;
                };
                if !matches!(manifest.version, 3 | 4) || !valid_sha256(&manifest.graph_digest) {
                    continue;
                }
                let deployment_digest = digest_bytes(
                    "ibex/rolldown-deployment-graph/1",
                    manifest.graph_digest.as_bytes(),
                )?;
                if deployment_digest != commitment.deployment_graph_digest {
                    continue;
                }
                let cache_dir = prepared_graph_cache_dir(&artifact_dir, &deployment_digest);
                return load_prepared_graph_committed_v1(
                    &cache_dir,
                    &self.host,
                    commitment,
                    entry_vfs_source_id,
                    &self.project_root,
                    ExecutionGeneration::INITIAL,
                )
                .map(Some);
            }
        }
        Ok(None)
    }

    /// Select only an already-published prepared graph while the admitted
    /// source graph remains the trust root. Cache absence, races, malformed
    /// manifests, and stale publications fall back to the inline graph; this
    /// path never invokes or waits for a bundler under native admission.
    /// @ref LLP 0026#phase-4-prepared-production-graph
    #[cfg(feature = "module-runner")]
    fn load_authenticated_prepared_module_graph(
        &self,
        source_entry: &Path,
        graph: &ibex_runtime::module_loader::runner_pipeline::SourceModuleGraphV1,
        entry_join: &ibex_runtime::module_loader::runner_pipeline::AuthenticatedEntryJoinV1,
    ) -> Result<Option<ibex_runtime::module_loader::runner_pipeline::SourceModuleGraphV1>> {
        use ibex_runtime::module_loader::artifact::digest_bytes;
        use ibex_runtime::module_loader::runner_pipeline::{
            load_prepared_source_graph_v1, prepared_graph_cache_dir,
        };

        let checked_cache = ibex_runtime::cache_topology::authenticate_internal_cache_root(
            &self.runtime_cache_root,
            std::slice::from_ref(&self.project_root),
        )
        .context("authenticated native-graph cache no longer has safe topology")?;
        anyhow::ensure!(
            checked_cache == self.runtime_cache_root,
            "authenticated native-graph cache canonical path changed after arming"
        );
        let bundles_root = self.runtime_cache_root.join("bundles");
        let metadata = match std::fs::symlink_metadata(&bundles_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Ok(None);
        }
        let canonical_bundles_root = match std::fs::canonicalize(&bundles_root) {
            Ok(path) if path.parent() == Some(self.runtime_cache_root.as_path()) => path,
            _ => return Ok(None),
        };

        let mut formats = vec![self.bundle_format];
        if self.bundle_format == BundleFormat::Cjs {
            formats.push(BundleFormat::Esm);
        }
        for format in formats {
            let cache_key = bundle_cache_key(source_entry, format)?;
            let artifact_root = bundle_artifact_root(&canonical_bundles_root, &cache_key);
            let mut candidates = match std::fs::read_dir(&artifact_root) {
                Ok(entries) => entries
                    .filter_map(std::result::Result::ok)
                    .filter_map(|entry| {
                        entry
                            .file_type()
                            .ok()
                            .filter(|kind| kind.is_dir() && !kind.is_symlink())
                            .filter(|_| !entry.file_name().to_string_lossy().starts_with('.'))
                            .map(|_| entry.path())
                    })
                    .collect::<Vec<_>>(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => continue,
            };
            candidates.sort();
            for artifact_dir in candidates {
                let output = bundle_entry_path(&artifact_dir, format);
                let Ok(manifest) = read_bundle_manifest_once(&output) else {
                    continue;
                };
                if !matches!(manifest.version, 3 | 4) || !valid_sha256(&manifest.graph_digest) {
                    continue;
                }
                let deployment_digest = digest_bytes(
                    "ibex/rolldown-deployment-graph/1",
                    manifest.graph_digest.as_bytes(),
                )?;
                let cache_dir = prepared_graph_cache_dir(&artifact_dir, &deployment_digest);
                if let Ok(prepared) =
                    load_prepared_source_graph_v1(&cache_dir, graph, entry_join, &deployment_digest)
                {
                    return Ok(Some(prepared));
                }
            }
        }
        Ok(None)
    }

    async fn prepare_authenticated_generated_entry(
        &self,
        request: &ibex_runtime::engine::evaluation::SourceRequest,
    ) -> Result<Option<PreparedAuthenticatedGeneratedEntry>> {
        use ibex_runtime::engine::evaluation::{ModuleKind, SourceRequest};

        if !matches!(
            request,
            SourceRequest::Program(program)
                if program.module_kind() == Some(ModuleKind::CommonJs) && program.is_main()
        ) {
            return Ok(None);
        }
        let source_id = request
            .source_id()
            .context("authenticated CommonJS entry has no SourceId")?;
        let (source_namespace, source_entry) = self.authenticated_source_entry(request)?;

        let snapshot = self
            .host
            .armed_snapshot()
            .context("generated entry requires the authenticated armed snapshot")?;
        let authority = BundleSourceProvenanceAuthority::from_snapshot(snapshot)?;
        // Recheck the actual root selected before arming and reuse that exact
        // canonical path; generated ingress must never re-read cache settings.
        // @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
        let checked_cache = ibex_runtime::cache_topology::authenticate_internal_cache_root(
            &self.runtime_cache_root,
            std::slice::from_ref(&self.project_root),
        )
        .context("authenticated generated cache no longer has safe topology")?;
        anyhow::ensure!(
            checked_cache == self.runtime_cache_root,
            "authenticated generated cache canonical path changed after arming"
        );
        let fresh_root = FreshGeneratedArtifactRoot::create(&self.runtime_cache_root)?;
        let Some(output) = run_fresh_bundler_with_source_provenance(
            &source_entry,
            fresh_root.path(),
            BundleFormat::Cjs,
            &authority,
        )
        .await
        .ok() else {
            return Ok(None);
        };
        let expected_source_sha = sha256_bytes(request.text().as_bytes());
        let Some(captured) = capture_fresh_single_original_bundle(
            &output,
            &source_entry,
            &expected_source_sha,
            &authority,
        )?
        else {
            return Ok(None);
        };
        let manifest = &captured.manifest;
        let provenance = manifest
            .source_provenance
            .as_ref()
            .context("authenticated bundle omitted original-source provenance")?;
        let Some(original) = admitted_single_original_bundle(manifest, &output) else {
            return Ok(None);
        };
        if manifest.deps[0].path != source_entry.to_string_lossy()
            || original.virtual_path != source_namespace.virtual_path()
            || original.source_label != request.source_label().as_str()
            || !source_id.authenticates_cache_key(&original.source_id)
            || source_id.defining_principal() != Some(&original.source_identity.defining_principal)
            || original.source_sha256 != expected_source_sha
        {
            return Ok(None);
        }
        let record = capsec_semantics::canonical::to_jcs_bytes(&serde_json::json!({
            "schema": "ibex/generated-single-commonjs-entry/1",
            "provenanceDigest": provenance.digest,
            "sourceId": original.source_id,
            "sourceLabel": original.source_label,
            "virtualPath": original.virtual_path,
            "definingPrincipal": original.source_identity.defining_principal,
        }))?;
        Ok(Some(PreparedAuthenticatedGeneratedEntry {
            entry: crate::engine::AuthenticatedGeneratedEntry {
                source: captured.source,
                record,
                // Provenance-bearing HBC stays closed until its evaluated
                // value is proven to be exactly one private initializer.
                bytecode: None,
            },
        }))
    }

    fn authenticated_source_entry(
        &self,
        request: &ibex_runtime::engine::evaluation::SourceRequest,
    ) -> Result<(ibex_runtime::vfs::NamespacePath, std::path::PathBuf)> {
        let requested_virtual_path = request
            .authenticated_file_virtual_path()
            .context("authenticated file entry has no virtual argv entry")?;
        let source_namespace = self
            .vfs
            .resolve_root_file_url(request.source_label().as_str(), None)
            .context("authenticated source label no longer resolves in the session VFS")?;
        // The native graph and generated fallback both begin from the exact
        // canonical VFS identity whose immutable bytes were admitted. Host
        // spelling and cache paths cannot select a different entry.
        // @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
        if source_namespace.virtual_path() != requested_virtual_path {
            anyhow::bail!("authenticated file argv entry differs from its source label");
        }
        let relative = source_namespace
            .virtual_path()
            .strip_prefix("/project/")
            .context("authenticated source is outside the project mount")?;
        let source_entry = std::fs::canonicalize(self.project_root.join(relative))
            .context("failed to retain the authenticated source entry")?;
        let reproduced_label = self
            .vfs
            .source_label_for_authenticated_project_path(&source_entry)
            .context("failed to reproduce the authenticated source label")?;
        anyhow::ensure!(
            reproduced_label.as_str() == request.source_label().as_str(),
            "retained source entry differs from the authenticated raw read"
        );
        Ok((source_namespace, source_entry))
    }
}

impl Drop for AuthenticatedFileIngress {
    fn drop(&mut self) {
        self.vfs.close();
    }
}

fn expected_identity_from_snapshot(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
) -> Result<capsec_semantics::arming::ExpectedArmingIdentity> {
    use capsec_semantics::model::Digest;

    let document = snapshot.document();
    let digest = |path: &[&str]| -> Result<Digest> {
        let value = path
            .iter()
            .try_fold(document, |value, segment| value.get(*segment))
            .with_context(|| format!("armed snapshot is missing {}", path.join(".")))?;
        Digest::new(
            value
                .as_str()
                .with_context(|| format!("armed snapshot {} is not a string", path.join(".")))?,
        )
        .map_err(anyhow::Error::msg)
    };
    Ok(capsec_semantics::arming::ExpectedArmingIdentity {
        profile: document["capsVocab"]
            .as_str()
            .context("armed snapshot is missing capsVocab")?
            .to_owned(),
        semantic_core: document["semanticCore"]
            .as_str()
            .context("armed snapshot is missing semanticCore")?
            .to_owned(),
        vocab_digest: digest(&["vocabDigest"])?,
        registry_digest: digest(&["registryDigest"])?,
        policy_digest: digest(&["policyDigest"])?,
        armed_snapshot_digest: snapshot.digest().clone(),
        target: snapshot.engine_target()?,
        engine_binary_digest: digest(&["engine", "binaryDigest"])?,
        features: snapshot.engine_features()?,
        package_graph_digest: digest(&["packageGraph", "digest"])?,
        entry: snapshot.entry().clone(),
        project_root_discovery: snapshot.project_root_discovery().clone(),
        path_canonicalizers: snapshot.path_canonicalizers().rows().to_vec(),
        protected_artifacts: snapshot.protected_artifacts().to_vec(),
        embedded_protected_artifacts: snapshot.embedded_protected_artifacts().to_vec(),
        runtime_extension_authority_digest: snapshot
            .runtime_extension_authority()
            .map(|capsule| capsule.authority_capsule_digest.clone()),
        runtime_extension_mapped_executable: snapshot
            .runtime_extension_authority()
            .map(|capsule| capsule.mapped_executable.clone()),
    })
}

fn root_owned_project_object(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
) -> Result<capsec_semantics::model::ObjectIdentity> {
    use capsec_semantics::model::LogicalRoot;

    let bindings = snapshot.root_bindings()?;
    let mut matches = bindings.iter().filter(|binding| {
        binding.logical_root == LogicalRoot::Project
            && binding.owner.is_none()
            && binding.logical_path.is_none()
    });
    let binding = matches
        .next()
        .context("armed snapshot has no root-owned project binding")?;
    anyhow::ensure!(
        matches.next().is_none(),
        "armed snapshot has more than one root-owned project binding"
    );
    Ok(binding.object.clone())
}

/// Authenticate and freshen the exact session launch before the engine worker
/// exists. History capture and the root path remain supervisor-only; the child
/// receives only a strict, MAC-protected snapshot/identity record.
pub(crate) fn prepare_session_worker_runtime(
    cli: &Cli,
    session_io: crate::terminal_session::SessionIoPlan,
) -> Result<PreparedSessionWorkerRuntime> {
    use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

    anyhow::ensure!(
        matches!(
            (session_io.route.entry_kind, session_io.route.mode),
            (ArmedEntryKind::Repl, ArmedExecutionMode::Interactive)
                | (ArmedEntryKind::Repl, ArmedExecutionMode::Transcript)
                | (ArmedEntryKind::Stdin, ArmedExecutionMode::Program)
        ),
        "session worker launch received an in-process execution route"
    );
    let history_platform = crate::history::HistoryPlatformCapture::capture(
        cli.history,
        session_io.presentation.editor_control
            && session_io.route.mode == ArmedExecutionMode::Interactive,
        cli.history_was_explicit,
    );
    let (host, _digest, project_root, _runtime_cache_root) =
        build_host_with_route(cli, session_io.route)?;
    let snapshot = host
        .armed_snapshot()
        .context("session worker launch requires an authenticated armed snapshot")?;
    let project_object = authenticated_project_history_root_object(&host, &project_root)?;
    let history_startup = history_platform.bind_authenticated_project_root(Some(
        crate::history::AuthenticatedProjectHistoryRoot {
            path: &project_root,
            object: &project_object,
        },
    ));
    let binding = crate::session_worker::ArmedSessionBinding::from_snapshot(snapshot)
        .map_err(anyhow::Error::new)?;
    let material = SessionWorkerRuntimeMaterial {
        snapshot: snapshot.document().clone(),
        expected_identity: expected_identity_from_snapshot(snapshot)?,
    };
    let application = capsec_semantics::canonical::to_jcs_bytes(
        &serde_json::to_value(material).context("failed to encode session worker launch")?,
    )?;
    Ok(PreparedSessionWorkerRuntime {
        application,
        binding,
        project_root,
        project_object,
        history_startup,
    })
}

fn authenticated_session_worker_snapshot(
    application: &[u8],
    session_io: crate::terminal_session::SessionIoPlan,
) -> Result<Arc<capsec_semantics::arming::ArmedSnapshot>> {
    use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode, ArmedSnapshot};

    anyhow::ensure!(
        matches!(
            (session_io.route.entry_kind, session_io.route.mode),
            (ArmedEntryKind::Repl, ArmedExecutionMode::Interactive)
                | (ArmedEntryKind::Repl, ArmedExecutionMode::Transcript)
                | (ArmedEntryKind::Stdin, ArmedExecutionMode::Program)
        ),
        "worker runtime received an invalid session route"
    );
    let text =
        std::str::from_utf8(application).context("session worker launch material is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .context("session worker launch material is not strict JSON")?;
    let material: SessionWorkerRuntimeMaterial = serde_json::from_value(value)
        .context("session worker launch material has the wrong shape")?;
    let snapshot_bytes = capsec_semantics::canonical::to_jcs_bytes(&material.snapshot)?;
    let snapshot = Arc::new(
        ArmedSnapshot::load(&snapshot_bytes, &material.expected_identity)
            .context("session worker refused its authenticated armed snapshot")?,
    );
    anyhow::ensure!(
        snapshot.entry().kind == session_io.route.entry_kind
            && snapshot.entry().mode == session_io.route.mode
            && session_io.route.synthetic_identity() == Some(snapshot.entry().identity.as_str()),
        "session worker route differs from the armed entry"
    );
    Ok(snapshot)
}

impl Runtime {
    /// Build a runtime from CLI configuration.
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let session_io = crate::terminal_session::SessionIoPlan::capture_for_cli(cli)
            .context("production runtime construction requires an execution route")?;
        Self::from_cli_with_session(cli, session_io)
    }

    /// Construct the engine side of an authenticated session launch without
    /// consulting argv, environment, project paths, or freshening the nonce a
    /// second time. The inherited root equality proof is completed by the
    /// caller after this constructor independently validates the snapshot's
    /// protected artifacts and root bindings.
    pub(crate) fn from_session_worker_material(
        application: &[u8],
        session_io: crate::terminal_session::SessionIoPlan,
    ) -> Result<Self> {
        let snapshot = authenticated_session_worker_snapshot(application, session_io)?;
        let digest = snapshot.digest().as_str().to_owned();
        let host_config = HostConfig {
            mode: crate::host::SecurityMode::Enforce,
            ..Default::default()
        };
        // The worker is the same binary as the parent, so it observes the same
        // compile-time `unadvertised-dev-arming` value with no env channel.
        #[cfg(feature = "insecure")]
        let host = Host::new_armed_insecure(host_config, snapshot)
            .context("failed to construct insecure session worker host")?;
        #[cfg(all(not(feature = "insecure"), feature = "unadvertised-dev-arming"))]
        let host = if unadvertised_dev_arming_active() {
            Host::new_armed_unadvertised_dev(host_config, snapshot)
        } else {
            Host::new_armed(host_config, snapshot)
        }
        .context("failed to construct authenticated session worker host")?;
        #[cfg(not(feature = "unadvertised-dev-arming"))]
        let host = Host::new_armed(host_config, snapshot)
            .context("failed to construct authenticated session worker host")?;
        crate::host::abi::install_host(host.clone());
        let engine = engine::create_engine("hermes", Some(&digest))?;
        Ok(Self::from_authenticated_session_worker_parts(
            host, engine, session_io,
        ))
    }

    fn from_authenticated_session_worker_parts(
        host: Host,
        engine: Arc<dyn Engine>,
        session_io: crate::terminal_session::SessionIoPlan,
    ) -> Self {
        let compat_modes = host
            .armed_snapshot()
            .map(|snapshot| snapshot.bootstrap_compatibility_modes().to_vec())
            .unwrap_or_default();
        let history_startup = crate::history::HistoryPlatformCapture::capture(
            crate::cli::HistoryMode::Off,
            false,
            false,
        )
        .bind_authenticated_project_root(None);
        Self {
            engine,
            host,
            runtime_bootstrap_loaded: tokio::sync::OnceCell::new(),
            history_startup,
            session_io: Some(session_io),
            authenticated_project_root: None,
            authenticated_runtime_cache_root: None,
            bundle_format: BundleFormat::Cjs,
            exec_argv: Vec::new(),
            compat_modes,
        }
    }

    /// Build a production runtime from the terminal and route facts captured
    /// before arming. The main dispatcher uses this entry point so fd topology,
    /// semantic mode, snapshot identity, and later terminal supervision all
    /// consume the same immutable observation.
    /// @ref LLP 0022#2-startup-project-identity-and-session-arming
    /// @ref LLP 0025#1-modes-descriptors-and-topology
    pub fn from_cli_with_session(
        cli: &Cli,
        session_io: crate::terminal_session::SessionIoPlan,
    ) -> Result<Self> {
        // Platform directory discovery is environment-backed, so it must run
        // before Host construction. Disabled/editorless routes short-circuit
        // inside `capture` without consulting the locator at all.
        let history_platform = crate::history::HistoryPlatformCapture::capture(
            cli.history,
            session_io.presentation.editor_control
                && session_io.route.mode
                    == capsec_semantics::arming::ArmedExecutionMode::Interactive,
            cli.history_was_explicit,
        );
        let (
            host,
            armed_snapshot_digest,
            authenticated_project_root,
            authenticated_runtime_cache_root,
        ) = build_host_with_route(cli, session_io.route)?;
        let authenticated_project_object =
            authenticated_project_history_root_object(&host, &authenticated_project_root)?;
        let compat_modes = host
            .armed_snapshot()
            .context("production Host has no armed snapshot")?
            .bootstrap_compatibility_modes()
            .to_vec();
        // Bind only to the root authenticated by that exact Host build. This
        // occurs before the engine/worker is constructed.
        let history_startup = history_platform.bind_authenticated_project_root(Some(
            crate::history::AuthenticatedProjectHistoryRoot {
                path: &authenticated_project_root,
                object: &authenticated_project_object,
            },
        ));

        // The native/shared bootstrap consumes only the digest-bound
        // projection above. Do not mirror it into the process environment:
        // that would let one runtime race or influence a later runtime's
        // requested snapshot in the same supervisor.
        crate::host::abi::install_host(host.clone());
        let mut phase = StartupPhaseTrace::begin();
        let engine = engine::create_engine(&cli.engine, armed_snapshot_digest.as_deref())?;
        phase.mark("engine_create");

        // If the engine doesn't support ESM, fall back to CJS bundling.
        // Hermes evaluateJavaScript() only supports script mode, not ES modules.
        let bundle_format = if cli.bundle_format == BundleFormat::Esm
            && !engine.supports_feature(EngineFeature::EsmModules)
        {
            BundleFormat::Cjs
        } else {
            cli.bundle_format
        };

        Ok(Self {
            engine,
            host,
            runtime_bootstrap_loaded: tokio::sync::OnceCell::new(),
            history_startup,
            session_io: Some(session_io),
            authenticated_project_root: Some(authenticated_project_root),
            authenticated_runtime_cache_root: Some(authenticated_runtime_cache_root),
            bundle_format,
            exec_argv: build_exec_argv(cli),
            compat_modes,
        })
    }

    pub fn from_audit_cli(cli: &Cli) -> Result<Self> {
        validate_diagnostic_audit_inputs(cli)?;
        if cli.policy.is_some() || crate::runtime_env("IBEX_POLICY", "EXACT_POLICY").is_some() {
            anyhow::bail!("foreground audit does not accept durable policy inputs");
        }
        let host = Host::new(HostConfig {
            mode: crate::host::SecurityMode::Audit,
            ..Default::default()
        });
        crate::host::abi::install_host(host.clone());
        let engine = engine::create_engine(&cli.engine, None)?;
        let bundle_format = if cli.bundle_format == BundleFormat::Esm
            && !engine.supports_feature(EngineFeature::EsmModules)
        {
            BundleFormat::Cjs
        } else {
            cli.bundle_format
        };
        let history_startup = crate::history::HistoryPlatformCapture::capture(
            cli.history,
            false,
            cli.history_was_explicit,
        )
        .bind_authenticated_project_root(None);
        Ok(Self {
            engine,
            host,
            runtime_bootstrap_loaded: tokio::sync::OnceCell::new(),
            history_startup,
            session_io: None,
            authenticated_project_root: None,
            authenticated_runtime_cache_root: None,
            bundle_format,
            exec_argv: build_audit_exec_argv(cli),
            compat_modes: Vec::new(),
        })
    }

    pub fn engine(&self) -> Arc<dyn Engine> {
        self.engine.clone()
    }

    // @ref LLP 0025#9-history — terminal code receives only a private capture,
    // never the authenticated root spelling or a locator callable from JS.
    // The in-process REPL adapter is retained as a target-bring-up seam while
    // supported product targets use the supervisor-owned worker route.
    #[allow(dead_code)]
    pub(crate) fn history_startup(&self) -> crate::history::HistoryStartupCapture {
        self.history_startup.clone()
    }

    /// Shared supervisor/Host lifecycle state for this exact runtime.
    pub fn session_lifecycle(&self) -> ibex_runtime::session_lifecycle::SessionLifecyclePort {
        self.host.session_lifecycle()
    }

    /// Supervisor-facing process status mirrored synchronously by the Host.
    /// This is the only production read path for `process.exitCode`; callers
    /// never evaluate a JavaScript probe after bootstrap sealing.
    /// @ref LLP 0025#8-exit-and-lifecycle
    pub fn lifecycle_exit_code(&self) -> i32 {
        self.host.lifecycle_exit_code()
    }

    /// Closed canonical `.exit` route. The Host supplies the authenticated
    /// root principal, exact lifecycle disposition, and generated command
    /// edge; callers cannot shape authority inputs.
    pub fn request_operator_exit(
        &self,
    ) -> ibex_runtime::session_lifecycle::LifecycleRequestDisposition {
        self.host.request_operator_exit()
    }

    /// Claim the only submission sequence for this exact armed REPL session.
    /// Diagnostic, file, stdin, eval, and cross-paired armed entries are
    /// refused before a VFS path or source ordinal can be admitted.
    pub(crate) fn repl_session_ingress(&self) -> Result<ReplSessionIngress> {
        let session_io = self
            .session_io
            .context("REPL source ingress requires the pre-arming session-I/O plan")?;
        ReplSessionIngress::from_armed_repl_runtime(self.host.clone(), session_io)
    }

    /// Claim the only submission sequence for an authenticated one-shot or
    /// program-stdin entry. REPL and file tuples are refused before bytes can
    /// be admitted, and the resulting adapter exposes no bare evaluator.
    pub(crate) fn authenticated_inline_ingress(&self) -> Result<AuthenticatedInlineIngress> {
        let session_io = self
            .session_io
            .context("inline source ingress requires the pre-arming session-I/O plan")?;
        AuthenticatedInlineIngress::from_armed_runtime(self.host.clone(), session_io)
    }

    /// Claim the single digest-bound direct-file submission route. The adapter
    /// reconstructs the entry solely from the armed virtual file identity,
    /// obtains its bytes through the typed VFS read, and retains the exact
    /// pre-arming project/cache roots for fresh generated admission without an
    /// environment re-read.
    /// @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
    pub(crate) fn authenticated_file_ingress(&self) -> Result<AuthenticatedFileIngress> {
        let session_io = self
            .session_io
            .context("file source ingress requires the pre-arming session-I/O plan")?;
        let project_root = self
            .authenticated_project_root
            .clone()
            .context("file source ingress requires the authenticated project root")?;
        let runtime_cache_root = self
            .authenticated_runtime_cache_root
            .clone()
            .context("file source ingress requires the authenticated runtime cache root")?;
        AuthenticatedFileIngress::from_armed_runtime(
            self.host.clone(),
            project_root,
            runtime_cache_root,
            self.bundle_format,
            session_io,
        )
    }

    pub fn session_io_plan(&self) -> Option<crate::terminal_session::SessionIoPlan> {
        self.session_io
    }

    pub(crate) fn authenticated_worker_binding(
        &self,
    ) -> Result<crate::session_worker::ArmedSessionBinding> {
        let snapshot = self
            .host
            .armed_snapshot()
            .context("worker runtime has no authenticated armed snapshot")?;
        crate::session_worker::ArmedSessionBinding::from_snapshot(snapshot)
            .map_err(anyhow::Error::new)
    }

    pub(crate) fn authenticated_worker_root_object(
        &self,
    ) -> Result<capsec_semantics::model::ObjectIdentity> {
        root_owned_project_object(
            self.host
                .armed_snapshot()
                .context("worker runtime has no authenticated armed snapshot")?,
        )
    }

    pub async fn load_runtime(&self) -> Result<()> {
        self.runtime_bootstrap_loaded
            .get_or_try_init(|| self.load_runtime_once())
            .await?;
        Ok(())
    }

    /// Run the trusted preload and engine bootstrap exactly once. Failed or
    /// cancelled attempts leave the cell empty so an operational retry remains
    /// possible; a successful seal makes every later call a read-only fast path.
    /// @ref LLP 0023#6-path-bearing-observables
    async fn load_runtime_once(&self) -> Result<()> {
        let exec_path = resolve_exec_path(&[]);
        let raw_argv0 = env::var("EXACT_RAW_ARGV0")
            .ok()
            .unwrap_or_else(|| env::args().next().unwrap_or_else(|| exec_path.clone()));
        let exec_path_json = serde_json::to_string(&exec_path)
            .with_context(|| format!("Failed to serialize exec path {}", exec_path))?;
        let raw_argv0_json =
            serde_json::to_string(&raw_argv0).unwrap_or_else(|_| format!("\"{}\"", exec_path));
        let exec_argv_json =
            serde_json::to_string(&self.exec_argv).unwrap_or_else(|_| "[]".to_string());
        let compat_modes_json =
            serde_json::to_string(&self.compat_modes).unwrap_or_else(|_| "[]".to_string());
        let preload_bootstrap = format!(
            "\
            globalThis.__exactExecPath = {};\n\
            globalThis.__exactExecArgv = {};\n\
            globalThis.__exactRawArgv0 = {};\n\
            globalThis.__exactCompatModes = {};\n\
            if (Array.isArray(globalThis.__exactCompatModes) && \
                globalThis.__exactCompatModes.indexOf('bun') !== -1 && \
                globalThis.Exact) {{\n\
              Object.defineProperty(globalThis, 'Bun', {{\n\
                value: globalThis.Exact,\n\
                writable: false,\n\
                configurable: false,\n\
                enumerable: true\n\
              }});\n\
            }}\n\
            if (typeof globalThis.__exactWhich === 'function') {{\n\
              if (globalThis.Exact) globalThis.Exact.which = globalThis.__exactWhich;\n\
              if (globalThis.Bun) globalThis.Bun.which = globalThis.__exactWhich;\n\
            }}\n\
            ",
            exec_path_json, exec_argv_json, raw_argv0_json, compat_modes_json
        );
        let preload_started = std::time::Instant::now();
        self.engine.eval_immediate(&preload_bootstrap).await?;
        if crate::trace_startup() {
            eprintln!(
                "[startup] {:<30} {:>6} us ({:>5.1} ms)",
                "runtime_preload_bootstrap",
                preload_started.elapsed().as_micros(),
                preload_started.elapsed().as_micros() as f64 / 1000.0
            );
        }
        if cfg!(windows) {
            load_windows_minimal_runtime(self.engine.as_ref()).await?;
            self.engine.finish_bootstrap().await?;
            return Ok(());
        }

        self.engine.load_runtime().await
    }

    pub async fn eval(&self, code: &str) -> Result<Option<String>> {
        if cfg!(windows) {
            let code = normalize_hashbang_for_eval(code);
            let code = wrap_source_for_tla_eval(code, true);
            return self.engine.eval(&code).await;
        }

        let exec_path = resolve_exec_path(&[]);
        let exec_path_json = serde_json::to_string(&exec_path)
            .with_context(|| format!("Failed to serialize exec path {}", exec_path))?;
        let raw_argv0 = read_raw_argv0(&exec_path);
        let raw_argv0_json =
            serde_json::to_string(&raw_argv0).unwrap_or_else(|_| format!("\"{}\"", exec_path));
        let exec_argv_json =
            serde_json::to_string(&self.exec_argv).unwrap_or_else(|_| "[]".to_string());
        let exec_bootstrap = format!(
            "\
            globalThis.__exactExecPath = {};\n\
            globalThis.__exactExecArgv = {};\n\
            globalThis.__exactRawArgv0 = {};\n\
            if (typeof globalThis.process === 'object' && globalThis.process !== null) {{\n\
                if (!Array.isArray(globalThis.process.argv)) {{ globalThis.process.argv = [globalThis.__exactExecPath]; }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'execArgv', {{\n\
                        value: globalThis.__exactExecArgv || [],\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.execArgv = globalThis.__exactExecArgv || [];\n\
                }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'argv0', {{\n\
                        value: globalThis.__exactRawArgv0 || globalThis.__exactExecPath,\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.argv0 = globalThis.__exactRawArgv0 || globalThis.__exactExecPath;\n\
                }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'execPath', {{\n\
                        value: globalThis.__exactExecPath,\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.execPath = globalThis.__exactExecPath;\n\
                }}\n\
            }} else {{\n\
                globalThis.process = {{\n\
                    argv: [globalThis.__exactExecPath],\n\
                    execArgv: globalThis.__exactExecArgv || [],\n\
                    argv0: globalThis.__exactRawArgv0,\n\
                    execPath: globalThis.__exactExecPath\n\
                }};\n\
            }}\n\
            ",
            exec_path_json, exec_argv_json, raw_argv0_json
        );
        self.engine.eval_immediate(&exec_bootstrap).await?;
        self.engine.eval(code).await
    }

    pub(crate) async fn run_authenticated_file_program(
        &self,
        args: &[String],
    ) -> Result<AuthenticatedFileProgramOutcome> {
        let mut ingress = self.authenticated_file_ingress()?;
        anyhow::ensure!(
            matches!(
                (ingress.entry_kind(), ingress.mode()),
                (
                    capsec_semantics::arming::ArmedEntryKind::File,
                    capsec_semantics::arming::ArmedExecutionMode::Program
                )
            ),
            "authenticated file ingress changed route after arming"
        );
        let evaluation = ingress.evaluate(self.engine.as_ref(), args).await;
        settle_authenticated_file_program(
            self.engine.as_ref(),
            &self.session_lifecycle(),
            evaluation,
        )
        .await
    }

    /// Drive and settle one ready-only `--keep-alive` turn. Returning `None`
    /// means the debug loop may continue; every terminal result retains the
    /// same fixed-status and cooperative-cause rules as initial file execution.
    pub(crate) async fn settle_authenticated_file_keep_alive_tick(
        &self,
    ) -> Option<AuthenticatedFileProgramOutcome> {
        settle_authenticated_file_keep_alive_tick(self.engine.as_ref(), &self.session_lifecycle())
            .await
    }

    pub async fn run_file_with_args(&self, file: &str, args: &[String]) -> Result<Option<String>> {
        anyhow::ensure!(
            self.host.armed_snapshot().is_none(),
            "armed file execution requires the structured file-program settlement path"
        );

        // Use runtime module loader instead of bundling
        // This makes require() work and enables proper module resolution
        let absolute_path = std::fs::canonicalize(file)
            .with_context(|| format!("Failed to resolve file: {}", file))?;
        let absolute_path = normalize_windows_tool_path(absolute_path);
        let path_str = absolute_path.to_string_lossy();
        let exec_path = resolve_exec_path(&["ibex"]);

        let script_entry = absolute_path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                matches!(
                    extension.to_ascii_lowercase().as_str(),
                    "mjs" | "js" | "cjs" | "ts" | "tsx" | "jsx" | "mts" | "cts"
                )
            });

        // Armed production files use `AuthenticatedFileIngress`; this method
        // is intentionally the audit/diagnostic compatibility path only.
        let entry_path = if script_entry {
            prepare_entry_with_format(&path_str, self.bundle_format).await?
        } else {
            absolute_path.clone()
        };
        // Hold a shared OS file lock for the entire execution. Quota pruning
        // takes the exclusive side, so lazy per-package chunk loads remain
        // safe without PID files (which leaked and were vulnerable to reuse).
        let _bundle_lease = acquire_bundle_execution_lease(&entry_path).await?;
        let entry_str = entry_path.to_string_lossy();

        let mut argv: Vec<String> = vec![exec_path.clone(), path_str.to_string()];
        argv.extend(args.iter().cloned());
        let argv_json = serde_json::to_string(&argv)
            .with_context(|| format!("Failed to serialize argv for file {}", file))?;
        let exec_path_json = serde_json::to_string(&exec_path)
            .with_context(|| format!("Failed to serialize exec path {}", exec_path))?;
        // Raw OS argv[0] - may differ from exec_path when argv0 option is used in spawn
        let raw_argv0 = read_raw_argv0(&exec_path);
        let raw_argv0_json =
            serde_json::to_string(&raw_argv0).unwrap_or_else(|_| format!("\"{}\"", exec_path));
        let exec_argv_json =
            serde_json::to_string(&self.exec_argv).unwrap_or_else(|_| "[]".to_string());
        // Tell the module loader the original source file path so that
        // __dirname/__filename and require.resolve work correctly even when
        // the entry is a bundle in the cache directory.
        let entry_file_json = serde_json::to_string(&path_str.to_string())
            .with_context(|| "Failed to serialize entry file path")?;
        let process_versions_code = format!(
            r#"var __exactIdentityVersions = {versions};
            if (typeof globalThis.process === 'object' && globalThis.process !== null) {{
                var __exactExistingVersions = globalThis.process.versions;
                if (!(__exactExistingVersions && typeof __exactExistingVersions === 'object')) {{
                    try {{
                        Object.defineProperty(globalThis.process, 'versions', {{
                            value: __exactIdentityVersions,
                            writable: true,
                            enumerable: true,
                            configurable: true
                        }});
                    }} catch (_) {{}}
                }}
                if (!globalThis.process.version) {{
                    globalThis.process.version = 'v' + __exactIdentityVersions.node;
                }}
            }}"#,
            versions = ibex_runtime::identity_generated::VERSIONS_JS_OBJECT,
        );
        let process_versions_code = process_versions_code.as_str();
        let compat_reapply_code = if std::env::var_os("EXACT_COMPAT_TEST").is_some() {
            "if (typeof globalThis.__exactReapplyCompatPolyfills === 'function') {\n\
                try { globalThis.__exactReapplyCompatPolyfills(); } catch (_) {}\n\
            }\n"
        } else {
            ""
        };
        let argv_code = format!(
            "\
            globalThis.__exactArgv = {};\n\
            globalThis.__exactExecArgv = {};\n\
            globalThis.__exactEntryFile = {};\n\
            globalThis.__exactExecPath = {};\n\
            globalThis.__exactRawArgv0 = {};\n\
            if (typeof globalThis.process === 'object' && globalThis.process !== null) {{\n\
                globalThis.process.argv = globalThis.__exactArgv;\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'execArgv', {{\n\
                        value: globalThis.__exactExecArgv || [],\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.execArgv = globalThis.__exactExecArgv || [];\n\
                }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'argv0', {{\n\
                        value: globalThis.__exactRawArgv0 || globalThis.__exactArgv[0] || '',\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.argv0 = globalThis.__exactRawArgv0 || globalThis.__exactArgv[0] || '';\n\
                }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'execPath', {{\n\
                        value: globalThis.__exactExecPath,\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.execPath = {};\n\
                }}\n\
            }} else {{\n\
                globalThis.process = {{ argv: globalThis.__exactArgv, execArgv: globalThis.__exactExecArgv || [], argv0: (globalThis.__exactRawArgv0 || globalThis.__exactArgv[0] || ''), execPath: {} }};\n\
            }}\n\
            {}\n\
            {}\n\
            ",
            argv_json,
            exec_argv_json,
            entry_file_json,
            exec_path_json,
            raw_argv0_json,
            exec_path_json,
            exec_path_json,
            process_versions_code,
            compat_reapply_code
        );
        // @ref LLP 0013#mechanism-3 — under per-package chunking the entry
        // bundle requires sibling chunk files (`__ibexpkg__*`) from the cache
        // dir. Tell the loader that dir so it can resolve those requires
        // absolutely, while the entry's own `__dirname`/`__filename` stay mapped
        // to the source (the loader only redirects the `__ibexpkg__` specifiers).
        let chunk_dir = entry_path
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let chunk_dir_json =
            serde_json::to_string(&chunk_dir).unwrap_or_else(|_| "\"\"".to_string());
        let argv_code = format!("globalThis.__exactChunkDir = {chunk_dir_json};\n{argv_code}");

        if cfg!(windows) {
            let source = tokio::fs::read_to_string(&entry_path)
                .await
                .with_context(|| format!("Failed to read file {}", entry_path.display()))?;
            let source = normalize_hashbang_for_eval(&source);
            let source = wrap_source_for_tla_eval(source, true);
            let code = format!("{argv_code}\n{source}");
            return self.engine.eval(&code).await;
        }

        // For .hbc bytecode files, set up argv then use engine.run_file() directly
        // since require() / module_loader uses read_to_string() which can't handle binary.
        let is_bytecode = entry_path.extension().and_then(|s| s.to_str()) == Some("hbc");
        if is_bytecode {
            self.engine.eval_immediate(&argv_code).await?;
            let content_dir = entry_path.parent().filter(|parent| {
                parent
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == ".bytecode-cache")
            });
            // Content-addressed HBC is untrusted cache data. Read and verify it
            // once, then pass those exact bytes to Hermes. Direct user-supplied
            // .hbc files retain the normal engine path behavior.
            let verified = match content_dir {
                Some(_) => {
                    let artifact =
                        engine::hermes::load_verified_bytecode_artifact(None, &entry_path)
                            .await
                            .context("Bytecode cache changed before execution")?;
                    // The HBC manifest binds bytes to its immediate JS source;
                    // this second check binds that source to the v4
                    // per-original provenance graph and to this content-keyed
                    // cache directory. A copied HBC unit with stale provenance
                    // therefore refuses before Hermes sees the buffer.
                    // @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
                    verify_bytecode_source_provenance_binding(
                        &artifact.source_path,
                        &entry_path,
                        None,
                    )
                    .await
                    .context("Bytecode source provenance changed before execution")?;
                    Some(artifact)
                }
                None => None,
            };
            let manifest_source = verified
                .as_ref()
                .map(|artifact| artifact.source_path.clone());
            let execution = match verified.as_ref() {
                Some(artifact) => {
                    self.engine
                        .run_bytecode_bytes(&artifact.bytes, &entry_str)
                        .await
                }
                None => self.engine.run_file(&entry_str).await,
            };
            match execution {
                Ok(result) => return Ok(result),
                Err(e) => {
                    // Only a genuine load failure — the bytecode buffer was
                    // rejected before any of the program ran — may delete the
                    // cached .hbc and re-run from JS source. The engine
                    // reports an eval THROW through the same Err surface; it
                    // must propagate as-is, or every side effect the program
                    // already performed (stdout, writes, network) runs a
                    // second time and the still-valid cache is discarded on
                    // every future run. (ENG-23484)
                    // @ref LLP 0005#bytecode-precompilation-hermesc — entry
                    // bytecode falls back to source on LOAD failure only,
                    // unlike the always-fall-back startup bootstrap.
                    if !engine::hermes::is_bytecode_load_error(&e) {
                        return Err(e);
                    }
                    // Bytecode failed to load (version mismatch or corrupt).
                    // Mark bytecode as incompatible so we don't re-compile.
                    BYTECODE_INCOMPATIBLE.store(true, Ordering::Relaxed);
                    // Delete the stale .hbc and fall through to require() with JS source.
                    if let Some(content_dir) = content_dir {
                        let _ = tokio::fs::remove_dir_all(content_dir).await;
                    } else {
                        let _ = tokio::fs::remove_file(&entry_path).await;
                    }
                    // Derive the JS source path from bytecode source path.
                    // .hbc files can be produced from either a raw source (.ts)
                    // or a bundled output (.bundle.mjs/.bundle.js), so fallback
                    // must try a few likely source variants.
                    // The .hbc was produced by `entry.with_extension("hbc")`,
                    // so reversing that with `.with_extension("js")` etc.
                    // correctly reconstructs the original bundle path
                    // (e.g. foo.bundle.hbc → foo.bundle.js / foo.bundle.mjs).
                    let mut fallback_paths: Vec<std::path::PathBuf> =
                        manifest_source.into_iter().collect();
                    fallback_paths.extend([
                        entry_path.with_extension("js"),
                        entry_path.with_extension("mjs"),
                        entry_path.with_extension("ts"),
                        entry_path.with_extension("tsx"),
                        entry_path.with_extension("jsx"),
                    ]);

                    if let Some(js_path) = fallback_paths.iter().find(|p| p.exists()) {
                        let js_str = js_path.to_string_lossy().to_string();
                        let js_json = serde_json::to_string(&js_str).with_context(|| {
                            format!("Failed to serialize fallback path {}", js_str)
                        })?;
                        // Determine format from the actual file extension, not
                        // self.bundle_format, since TLA may have switched CJS→ESM.
                        let is_esm = js_path.extension().and_then(|e| e.to_str()) == Some("mjs");
                        return if is_esm {
                            self.run_entry_with_tla_shim(js_path, true).await
                        } else {
                            let fallback_code = format!("require({});", js_json);
                            self.engine.eval(&fallback_code).await
                        };
                    }
                    anyhow::bail!("Bytecode loading failed and no JS source fallback found");
                }
            }
        }

        // An entry that skipped the bundler (standalone runs) may still carry
        // top-level await, which the loader's CJS `require()` chain cannot
        // evaluate — both branches below must route it through the async
        // entry shim, which transpiles in-process and wraps.
        let entry_untranspiled_tla = entry_path == absolute_path && {
            let raw = tokio::fs::read_to_string(&entry_path)
                .await
                .unwrap_or_default();
            contains_top_level_await(&raw)
        };

        if !self.engine.supports_feature(EngineFeature::TopLevelAwait) {
            self.engine.eval_immediate(&argv_code).await?;

            let entry_is_esm = entry_path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("mjs"));
            if self.bundle_format == BundleFormat::Cjs && !entry_is_esm && !entry_untranspiled_tla {
                let entry_json = serde_json::to_string(&entry_str)
                    .with_context(|| format!("Failed to serialize path {}", path_str))?;
                let code = format!("require({});", entry_json);
                return self.engine.eval(&code).await;
            }

            return self.run_entry_with_tla_shim(&entry_path, true).await;
        }

        match self.bundle_format {
            BundleFormat::Cjs => {
                self.engine.eval_immediate(&argv_code).await?;

                // An entry that skipped the bundler (standalone runs) may
                // still carry top-level await, which the loader's CJS
                // `require()` chain cannot evaluate — route it through the
                // async entry shim, which transpiles in-process and wraps.
                if entry_untranspiled_tla {
                    return self.run_entry_with_tla_shim(&entry_path, true).await;
                }

                let entry_json = serde_json::to_string(&entry_str.to_string())
                    .with_context(|| format!("Failed to serialize path {}", path_str))?;
                let code = format!(
                    "\
                    require({});",
                    entry_json
                );

                // Load the file through the module system using require()
                self.engine.eval(&code).await
            }
            BundleFormat::Esm => {
                self.engine.eval_immediate(&argv_code).await?;
                self.engine.run_file(&entry_str).await
            }
        }
    }

    async fn run_entry_with_tla_shim(
        &self,
        entry_path: &Path,
        is_main_file: bool,
    ) -> Result<Option<String>> {
        let source = tokio::fs::read_to_string(entry_path)
            .await
            .with_context(|| format!("Failed to read JS source {}", entry_path.display()))?;
        // When the entry reaches this path untranspiled (standalone runs skip
        // the bundler), lower TS/ESM in-process before wrapping.
        let needs_lowering = entry_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                matches!(
                    ext.to_ascii_lowercase().as_str(),
                    // review R3/R4: .mts/.cts crashed on raw types and .mjs/.js
                    // ESM entries got an undefined import.meta — all source
                    // extensions lower in-process before wrapping.
                    "ts" | "tsx" | "jsx" | "mts" | "cts" | "mjs" | "js"
                )
            });
        let source = if needs_lowering {
            ibex_runtime::module_loader::transpile::transpile_module_to_cjs(&source, entry_path)?
        } else {
            source
        };
        let source = std::borrow::Cow::Owned(source);
        let source = normalize_hashbang_for_eval(&source);

        // Check if the source needs the async IIFE wrapper.
        // We check for `await` as a keyword anywhere in the source (not just at
        // brace depth 0) because `await` inside top-level for/if/while blocks is
        // still TLA even though it's at brace depth > 0. The async IIFE wrapper
        // is harmless for code that doesn't use TLA, so false positives are fine.
        //
        // The run-the-file-raw fast path is only sound when NO lowering
        // happened: the shim check ran on the LOWERED source, and a lowered
        // entry's on-disk file may be raw ESM/TS that Hermes cannot parse in
        // script mode (a static-import .mjs with no TLA hit exactly this —
        // clean lowering, "no shim needed", then SyntaxError on the raw
        // imports). Once lowering happened, evaluate the lowered source; the
        // wrapper also supplies the module/exports/__filename/__dirname
        // bindings the swc CJS output references. (ENG-23484)
        if !needs_lowering && !source_needs_tla_shim(source.as_ref()) {
            let entry_str = entry_path.to_string_lossy().to_string();
            return self.engine.run_file(&entry_str).await;
        }

        let wrapped = wrap_entry_source_for_eval(source, is_main_file, needs_lowering);
        self.engine.eval(&wrapped).await
    }

    pub async fn start_inspector(&self, host: &str, port: u16) -> Result<()> {
        // The CLI spelling guard is useful early rejection, but this is the
        // capability sink shared by every Runtime constructor, including the
        // authenticated pre-Clap session-worker route. Refuse while the armed
        // Host is still available and before the Engine can allocate a debugger
        // backend or bind a CDP listener.
        // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
        // @ref LLP 0022#2-startup-project-identity-and-session-arming
        if self.host.armed_snapshot().is_some() {
            anyhow::bail!(ARMED_INSPECTOR_CLOSED_MESSAGE);
        }
        self.engine.start_inspector(host, port).await
    }

    pub async fn stop_inspector(&self) -> Result<()> {
        self.engine.stop_inspector().await
    }

    /// Pause through the debugger control ABI. This remains available after
    /// armed bootstrap has sealed all source-evaluation ingress.
    pub async fn pause_inspector(&self) -> Result<()> {
        self.engine.pause_inspector().await
    }

    pub async fn wait_for_inspector(&self) -> Result<()> {
        self.engine.wait_for_inspector().await
    }

    pub async fn wait_for_debugger(&self) -> Result<()> {
        self.engine.wait_for_debugger().await
    }
}

const PRODUCTION_RUN_NONCE_BYTES: usize = 16;
const CONTRACT_FIXTURE_RUN_NONCE: &str = "AQIDBAUGBwgJCgsMDQ4PEA";

fn production_run_nonce_from_bytes(bytes: &[u8; PRODUCTION_RUN_NONCE_BYTES]) -> Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    anyhow::ensure!(
        nonce != CONTRACT_FIXTURE_RUN_NONCE,
        "OS randomness produced the reserved capsec contract-fixture run nonce"
    );
    Ok(nonce)
}

fn fresh_production_run_nonce() -> Result<String> {
    let mut bytes = [0u8; PRODUCTION_RUN_NONCE_BYTES];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        anyhow::anyhow!("OS randomness unavailable for production run nonce: {error}")
    })?;
    production_run_nonce_from_bytes(&bytes)
}

fn finalize_production_snapshot(value: &mut serde_json::Value) -> Result<()> {
    value["runNonce"] = serde_json::json!(fresh_production_run_nonce()?);
    // Production arming must use the frozen digest contract, including its
    // schema-aware semantic-set canonicalization. The low-level domain helper
    // hashes the input's current array order and can therefore mint a digest
    // that ArmedSnapshot::load correctly rejects after freshening the nonce.
    let digest = capsec_semantics::digest::compute_checked_contract_digest(
        capsec_semantics::digest::DigestKind::ArmedSnapshot,
        value,
    )?;
    value["armedSnapshotDigest"] = serde_json::json!(digest);
    Ok(())
}

/// Authenticate the immutable production snapshot before either the host or
/// Hermes can observe project code. The independently generated expected
/// identity is launcher input, not policy authority, and is discarded after
/// arming. @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
#[cfg(test)]
fn build_host(cli: &Cli) -> Result<(Host, Option<String>)> {
    let session_io = crate::terminal_session::SessionIoPlan::capture_for_cli(cli)
        .context("production host construction requires an execution route")?;
    let (host, digest, _, _) = build_host_with_route(cli, session_io.route)?;
    Ok((host, digest))
}

#[derive(Clone, Debug)]
struct AuthenticatedLaunchEntry {
    project_root: std::path::PathBuf,
    /// Exact canonical binary-runtime cache root checked against the mounted
    /// project tree. Later startup materialization must reuse this path rather
    /// than re-reading environment-derived cache configuration.
    runtime_cache_root: std::path::PathBuf,
    project_discovery: ProjectRootDiscovery,
    entry: capsec_semantics::arming::ArmedEntry,
}

fn cli_file_entry(cli: &Cli) -> Option<&str> {
    cli.file.as_deref().or(match cli.command.as_ref() {
        Some(crate::cli::Commands::Run { file, .. }) => Some(file.as_str()),
        _ => None,
    })
}

/// Authenticate the filesystem half of the launch identity once, then derive
/// the digest-bound virtual label from that exact canonical path. Synthetic
/// source identities come only from the closed route table.
/// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
fn authenticate_launch_entry(
    cli: &Cli,
    route: crate::terminal_session::SelectedExecutionRoute,
) -> Result<AuthenticatedLaunchEntry> {
    use capsec_semantics::arming::ArmedEntryKind;
    use capsec_semantics::model::NonEmptyString;

    let canonical_file = if route.entry_kind == ArmedEntryKind::File {
        let raw = cli_file_entry(cli).context("file execution route has no file entry")?;
        Some(
            std::fs::canonicalize(raw)
                .with_context(|| format!("failed to authenticate entry path {raw}"))?,
        )
    } else {
        None
    };
    let project_discovery =
        authenticated_project_root_discovery_for_entry(cli, canonical_file.as_deref())?;
    emit_project_root_discovery_diagnostic(&project_discovery);
    let project_root = project_discovery.selected_root.clone();
    let runtime_cache_root = runtime_cache_dir()?;
    std::fs::create_dir_all(&runtime_cache_root).with_context(|| {
        format!(
            "failed to create binary runtime cache root {}",
            runtime_cache_root.display()
        )
    })?;
    let runtime_cache_root = ibex_runtime::cache_topology::authenticate_internal_cache_root(
        &runtime_cache_root,
        std::slice::from_ref(&project_root),
    )
    .context("binary runtime cache overlaps the authenticated project tree")?;
    let identity = match canonical_file.as_deref() {
        Some(file) => {
            ibex_runtime::vfs::source_label_for_authenticated_project_path(&project_root, file)?
                .as_str()
                .to_owned()
        }
        None => route
            .synthetic_identity()
            .context("synthetic execution route has no fixed identity")?
            .to_owned(),
    };
    let entry = capsec_semantics::arming::ArmedEntry {
        kind: route.entry_kind,
        identity: NonEmptyString::new(identity).map_err(anyhow::Error::msg)?,
        mode: route.mode,
    };
    entry.validate().map_err(anyhow::Error::msg)?;
    Ok(AuthenticatedLaunchEntry {
        project_root,
        runtime_cache_root,
        project_discovery,
        entry,
    })
}

/// Return the object identity from the exact project binding authenticated by
/// this Host, after verifying that its host spelling is the launcher's
/// canonical project root. History reopens that spelling and compares the
/// resulting descriptor identity before deriving any durable witness.
fn authenticated_project_history_root_object(
    host: &Host,
    project_root: &std::path::Path,
) -> Result<capsec_semantics::model::ObjectIdentity> {
    use capsec_semantics::model::LogicalRoot;

    let snapshot = host
        .armed_snapshot()
        .context("history requires an authenticated armed snapshot")?;
    let bindings = snapshot.root_bindings()?;
    let project_bindings = bindings
        .iter()
        .filter(|binding| {
            binding.logical_root == LogicalRoot::Project
                && binding.owner.is_none()
                && binding.logical_path.is_none()
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        project_bindings.len() == 1,
        "history requires exactly one root-owned project binding"
    );
    let expected_host_path: capsec_semantics::model::LogicalPath =
        serde_json::from_value(serde_json::json!({
            "root": "absolute",
            "components": runtime_path_components_json(project_root)?,
            "hostBound": true,
        }))?;
    let binding = project_bindings[0];
    anyhow::ensure!(
        binding.host_path == expected_host_path,
        "authenticated project binding does not match the launch project root"
    );
    Ok(binding.object.clone())
}

/// If a snapshot declares the private `home` coordinate, bind it exactly to
/// the binary cache root independently authenticated for this launch. External
/// snapshots may omit the private coordinate; it is never treated as a public
/// VFS mount or as the authority for cache placement.
/// @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
fn validate_optional_home_cache_binding(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
    runtime_cache_root: &std::path::Path,
) -> Result<()> {
    use capsec_semantics::model::{LogicalRoot, ObjectIdentity};

    let homes = snapshot
        .root_bindings()?
        .iter()
        .filter(|binding| binding.logical_root == LogicalRoot::Home)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        homes.len() <= 1,
        "armed snapshot has more than one private home binding"
    );
    let Some(home) = homes.first() else {
        return Ok(());
    };
    anyhow::ensure!(
        home.owner.is_none() && home.logical_path.is_none(),
        "armed snapshot private home binding is not ownerless"
    );
    let home_path = std::fs::canonicalize(runtime_host_path_from_logical(&home.host_path)?)
        .context("cannot canonicalize armed private home binding")?;
    anyhow::ensure!(
        home_path == runtime_cache_root,
        "armed private home binding differs from the authenticated binary cache root"
    );
    let observed: ObjectIdentity =
        serde_json::from_value(runtime_object_identity_json(&home_path)?)
            .context("cannot decode authenticated binary cache object identity")?;
    anyhow::ensure!(
        observed == home.object,
        "armed private home binding object differs from the authenticated binary cache root"
    );
    Ok(())
}

fn requested_bootstrap_compatibility_modes(cli: &Cli) -> Vec<String> {
    let bun = cli.compat.as_deref() == Some("bun") || crate::env_flag_enabled("EXACT_COMPAT_BUN");
    let fixture = crate::env_flag_enabled("EXACT_COMPAT_TEST");
    let mut modes = Vec::new();
    if bun {
        modes.push("bun".to_owned());
    }
    if fixture {
        modes.push("fixture".to_owned());
        if std::env::var("EXACT_TEST_SECTION").as_deref() == Ok("bun") {
            modes.push("fixture:bun".to_owned());
        }
    }
    modes
}

fn build_host_with_route(
    cli: &Cli,
    route: crate::terminal_session::SelectedExecutionRoute,
) -> Result<(Host, Option<String>, std::path::PathBuf, std::path::PathBuf)> {
    use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
    use std::sync::Arc;

    validate_production_inputs(cli)?;
    #[cfg(feature = "module-runner")]
    let native_runner_conformance = native_runner_test_profile()?.is_some();
    match (&cli.capsec_armed_snapshot, &cli.capsec_arming_identity) {
        (None, None) => build_default_armed_host(cli, authenticate_launch_entry(cli, route)?),
        (Some(_), None) | (None, Some(_)) => anyhow::bail!(
            "--capsec-armed-snapshot and --capsec-arming-identity must be provided together"
        ),
        (Some(snapshot_path), Some(identity_path)) => {
            #[cfg(feature = "module-runner")]
            anyhow::ensure!(
                !native_runner_conformance,
                "native module-runner conformance fixtures cannot supply an armed snapshot"
            );
            if cli.inspect
                || cli.inspect_wait
                || cli.inspect_open
                || cli.inspect_pause
                || cli.inspect_port.is_some()
                || cli.inspect_host.is_some()
            {
                anyhow::bail!(
                    "armed capability startup closes inspector activation and configuration"
                );
            }
            if cli.compat.is_some() {
                anyhow::bail!("armed capability startup closes compatibility facades");
            }
            if cli.expose_internals
                || cli.stack_size.is_some()
                || cli.max_http_header_size.is_some()
            {
                anyhow::bail!(
                    "armed capability startup closes hidden runtime-fidelity configuration"
                );
            }
            if cli.policy.is_some()
                || !cli.allow.is_empty()
                || !cli.deny.is_empty()
                || cli.allow_all
                || cli.allow_env_endowments
                || !matches!(
                    cli.capsec,
                    crate::cli::CapSecMode::Auto | crate::cli::CapSecMode::Enforce
                )
            {
                anyhow::bail!(
                    "armed capability startup cannot be combined with legacy policy, mode, allow, deny, allow-all, or environment-endowment overrides"
                );
            }
            let launch = authenticate_launch_entry(cli, route)?;
            let snapshot_bytes = std::fs::read(snapshot_path).with_context(|| {
                format!(
                    "failed to read armed capability snapshot {}",
                    snapshot_path.display()
                )
            })?;
            let identity_bytes = std::fs::read(identity_path).with_context(|| {
                format!(
                    "failed to read capsec arming identity {}",
                    identity_path.display()
                )
            })?;
            let identity_text = std::str::from_utf8(&identity_bytes)
                .context("capsec arming identity is not UTF-8")?;
            let identity_value = capsec_semantics::strict_json::parse_strict(identity_text)
                .context("invalid strict JSON in capsec arming identity")?;
            let expected: ExpectedArmingIdentity =
                serde_json::from_value(identity_value).context("invalid capsec arming identity")?;
            let mut expected = observed_arming_identity(expected, &snapshot_bytes)?;
            let AuthenticatedLaunchEntry {
                project_root,
                runtime_cache_root,
                project_discovery,
                entry,
            } = launch;
            expected.entry = entry;
            expected.project_root_discovery = project_discovery.armed_record()?;
            // Authenticate the launcher-supplied document before changing it.
            // Its nonce is template/test input only: runtime construction owns
            // the fresh nonce and therefore the final armed digest.
            let template = ArmedSnapshot::load(&snapshot_bytes, &expected)
                .context("refused to authenticate capability snapshot template")?;
            anyhow::ensure!(
                template.bootstrap_compatibility_modes().is_empty(),
                "externally supplied armed snapshots close compatibility bootstrap controls"
            );
            let mut runtime_document = template.document().clone();
            finalize_production_snapshot(&mut runtime_document)
                .context("failed to finalize fresh production capability snapshot")?;
            expected.armed_snapshot_digest = capsec_semantics::model::Digest::new(
                runtime_document["armedSnapshotDigest"]
                    .as_str()
                    .context("finalized capability snapshot has no digest")?,
            )
            .map_err(anyhow::Error::msg)?;
            let snapshot = Arc::new(
                ArmedSnapshot::load(&serde_json::to_vec(&runtime_document)?, &expected)
                    .context("refused to arm finalized capability snapshot")?,
            );
            validate_optional_home_cache_binding(&snapshot, &runtime_cache_root)?;
            let digest = snapshot.digest().as_str().to_owned();
            let host = Host::new_armed(
                HostConfig {
                    mode: crate::host::SecurityMode::Enforce,
                    ..Default::default()
                },
                snapshot,
            )
            .context("failed to construct armed capability host")?;
            Ok((host, Some(digest), project_root, runtime_cache_root))
        }
    }
}

fn push_typed_package_import_edges(
    edges: &mut Vec<serde_json::Value>,
    importer: &serde_json::Value,
    imported: &serde_json::Value,
    request_specifier: &str,
) {
    for (resolution_kind, conditions) in [
        ("common-js-require", vec!["node", "require"]),
        ("dynamic-import", vec!["import", "node"]),
        ("esm-static", vec!["import", "node"]),
    ] {
        edges.push(serde_json::json!({
            "importer": importer,
            "imported": imported,
            "requestSpecifier": request_specifier,
            "resolutionKind": resolution_kind,
            "conditions": conditions,
            "attributes": {},
        }));
    }
}

/// Project the policy's exact import allowlists into typed package-graph
/// edges. Root edges come only from `rootImports`; a package that is reachable
/// transitively or merely has a policy row must not be promoted to direct Root
/// authority during snapshot construction.
// @ref LLP 0022#2-startup-project-identity-and-session-arming — rootImports is the authenticated
// direct-import boundary, while package rows govern their own outgoing edges.
fn policy_package_graph_edges(
    policy_principals: &[serde_json::Value],
    root_package_imports: &[String],
) -> Result<Vec<serde_json::Value>> {
    let principals_by_locator = policy_principals
        .iter()
        .filter_map(|row| {
            Some((
                row["principal"]["locator"].as_str()?.to_string(),
                row["principal"].clone(),
            ))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut graph_edges = Vec::new();
    let root_principal = serde_json::json!({"kind": "root", "identity": "project-root"});
    for locator in root_package_imports {
        let imported = principals_by_locator
            .get(locator)
            .with_context(|| format!("canonical root imports unknown package locator {locator}"))?;
        push_typed_package_import_edges(
            &mut graph_edges,
            &root_principal,
            imported,
            imported["name"]
                .as_str()
                .context("canonical imported principal has no package name")?,
        );
    }
    for row in policy_principals {
        let importer = &row["principal"];
        for locator in row["imports"]["packages"]
            .as_array()
            .context("canonical package imports must be an array")?
        {
            let locator = locator
                .as_str()
                .context("canonical package import must be a locator string")?;
            let imported = principals_by_locator.get(locator).with_context(|| {
                format!("canonical policy imports unknown package locator {locator}")
            })?;
            push_typed_package_import_edges(
                &mut graph_edges,
                importer,
                imported,
                imported["name"]
                    .as_str()
                    .context("canonical imported principal has no package name")?,
            );
        }
    }
    Ok(graph_edges)
}

/// Per-phase marks for `IBEX_STARTUP_TRACE=1`, in the same `[startup]` line
/// format as the launcher's marks. Each mark reports the time since the
/// previous mark, so the ceremony's cost decomposes into attributable phases
/// instead of one opaque gap between `cli_parse` and the first engine line.
pub(crate) struct StartupPhaseTrace {
    enabled: bool,
    last: std::time::Instant,
}

impl StartupPhaseTrace {
    pub(crate) fn begin() -> Self {
        Self {
            enabled: crate::trace_startup(),
            last: std::time::Instant::now(),
        }
    }

    pub(crate) fn mark(&mut self, label: &str) {
        if self.enabled {
            let elapsed = self.last.elapsed();
            eprintln!(
                "[startup] {:<30} {:>6} us ({:>5.1} ms)",
                label,
                elapsed.as_micros(),
                elapsed.as_micros() as f64 / 1000.0
            );
        }
        self.last = std::time::Instant::now();
    }
}

fn build_default_armed_host(
    cli: &Cli,
    launch: AuthenticatedLaunchEntry,
) -> Result<(Host, Option<String>, std::path::PathBuf, std::path::PathBuf)> {
    use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
    use capsec_semantics::digest::{
        compute_checked_contract_digest, compute_domain_digest, DigestKind,
    };
    use capsec_semantics::model::Digest;

    let mut phase = StartupPhaseTrace::begin();
    validate_production_inputs(cli)?;
    #[cfg(feature = "module-runner")]
    let native_runner_conformance = native_runner_test_profile()?.is_some();
    #[cfg(not(feature = "module-runner"))]
    let native_runner_conformance = false;
    for line in check_capsec_readiness(
        crate::host::SecurityMode::Enforce,
        CapsecStage::Run,
        capsec_readiness(cli),
        false,
    )? {
        eprintln!("{line}");
    }
    phase.mark("arm_readiness_check");
    if cli.capsec == crate::cli::CapSecMode::Audit {
        anyhow::bail!("foreground audit requires its separate diagnostic arming workflow");
    }
    let AuthenticatedLaunchEntry {
        project_root,
        runtime_cache_root: cache_root,
        project_discovery,
        entry,
    } = launch;
    let project_root_discovery = project_discovery.armed_record()?;
    let root_object = runtime_object_identity_json(&project_root)?;
    let components = runtime_path_components_json(&project_root)?;

    #[cfg(feature = "insecure")]
    let engine_identity = crate::engine::hermes::HermesEngine::loaded_engine_identity_insecure()?;
    #[cfg(not(feature = "insecure"))]
    let engine_identity = crate::engine::hermes::HermesEngine::loaded_engine_identity()?;
    phase.mark("arm_engine_identity");
    let engine_digest = engine_identity.binary_digest.clone();
    let engine_object = serde_json::to_value(&engine_identity.object)?;
    if crate::runtime_env("IBEX_POLICY", "EXACT_POLICY").is_some() {
        anyhow::bail!("environment-selected policy paths are forbidden in production");
    }
    let current_identity: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    let digest_from_current = |field: &str| -> Result<capsec_semantics::model::Digest> {
        capsec_semantics::model::Digest::new(
            current_identity[field]
                .as_str()
                .with_context(|| format!("current CapSec identity is missing {field}"))?,
        )
        .map_err(anyhow::Error::msg)
    };
    let expected_policy_identity = capsec_semantics::policy::ExpectedPolicyIdentity {
        profile: "ibex/capsec/1".into(),
        semantic_core: "capsec/semantics/1".into(),
        vocab_digest: digest_from_current("vocabDigest")?,
        registry_digest: digest_from_current("registryDigest")?,
    };
    let policy_profile = capsec_semantics::registry::ValidatedProfile::from_json(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/capability-definitions.json"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/policy-rules.json"
        )),
    )?;
    // The synthesized no-artifact default below must carry the same v2 graph
    // and entry identity a generated artifact would, so the frozen policy
    // digest schema accepts it. The identity covers exactly the entry the
    // launcher authenticated (or the project manifest for entry-less routes).
    // @ref LLP 0014#the-generated-artifact — the canonical artifact is
    // ibex/capsec-policy/2; a v1-shaped default cannot pass the frozen digest
    // projection, so the default is v2-shaped even when no artifact exists.
    let policy_entry_path = match cli_file_entry(cli) {
        Some(entry) => {
            let path = Path::new(entry);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            }
        }
        None => project_root.join("package.json"),
    };
    let policy_entry_path = std::fs::canonicalize(&policy_entry_path).with_context(|| {
        format!(
            "failed to authenticate policy entry {}",
            policy_entry_path.display()
        )
    })?;
    let policy_entry_relative =
        policy_entry_path
            .strip_prefix(&project_root)
            .with_context(|| {
                format!(
                    "policy entry {} is outside project root {}",
                    policy_entry_path.display(),
                    project_root.display()
                )
            })?;
    let policy_entry_name = policy_entry_relative
        .to_str()
        .context("canonical policy graph identity requires a Unicode project-relative entry")?
        .replace(std::path::MAIN_SEPARATOR, "/");
    let policy_entry_source = std::fs::read(&policy_entry_path).with_context(|| {
        format!(
            "failed to authenticate policy entry {}",
            policy_entry_path.display()
        )
    })?;
    let policy_entry_integrity =
        ibex_runtime::module_loader::artifact::source_integrity(&policy_entry_source)?;
    let policy_entry_identity = serde_json::json!({
        "root": "project",
        "components": runtime_path_components_json(policy_entry_relative)?,
        "sourceIntegrity": policy_entry_integrity,
    });
    let policy_graph_snapshot = serde_json::json!({
        "graphSnapshotSchema": "ibex/authenticated-graph-snapshot/1",
        "entryIdentity": policy_entry_identity,
        "nodes": [{
            "principal": "<root>",
            "modulePath": policy_entry_name,
            "sourceIntegrity": policy_entry_integrity,
        }],
        "packages": [],
        "edges": [],
        "candidateSets": [],
    });
    let policy_graph_identity = compute_domain_digest(
        "ibex/authenticated-graph-snapshot/1",
        &policy_graph_snapshot,
        &[],
    )?;
    let policy_path = cli
        .policy
        .clone()
        .unwrap_or_else(|| project_root.join("ibex-policy.json"));
    let mut policy = serde_json::json!({
        "policySchema": "ibex/capsec-policy/2",
        "capsVocab": "ibex/capsec/1",
        "semanticCore": "capsec/semantics/1",
        "vocabDigest": expected_policy_identity.vocab_digest.clone(),
        "registryDigest": expected_policy_identity.registry_digest.clone(),
        "policyDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "purpose": "production",
        "mode": "enforce",
        "graphIdentity": policy_graph_identity,
        "entryIdentity": policy_entry_identity,
        "targetProfile": {"kind": "source", "profile": "portable-v1"},
        "mountProfile": "project-v1",
        "rootCeiling": [],
        "computedCandidates": {
            "schema": "ibex/computed-candidate-manifest/1",
            "declarations": [],
            "packageClosureOptIns": [],
            "materializedSites": [],
        },
        "rootImports": [],
        "principals": [],
    });
    let policy_loaded = policy_path.exists();
    if policy_loaded {
        let bytes = std::fs::read(&policy_path).with_context(|| {
            format!("failed to read canonical policy {}", policy_path.display())
        })?;
        let text = std::str::from_utf8(&bytes).context("canonical policy is not UTF-8")?;
        policy = capsec_semantics::strict_json::parse_strict(text)
            .context("canonical policy is not strict JSON")?;
    } else if cli.policy.is_some() {
        anyhow::bail!("canonical policy {} not found", policy_path.display());
    }
    if native_runner_conformance {
        if policy_loaded {
            anyhow::bail!(
                "native module-runner conformance fixtures cannot supply a project policy"
            );
        }
        // The real-binary source/prepared harness gets only its disposable
        // project tree and the stdout broker needed by the result oracle.
        // @ref LLP 0019#tier-3-the-rustoxc-module-artifact-producer
        policy["rootCeiling"] = serde_json::json!([
            {
                "authority": {
                    "cap": "fs:list",
                    "resource": {
                        "kind": "path-tree",
                        "path": {"root": "project", "components": []}
                    }
                },
                "provenance": [{
                    "kind": "direct",
                    "source": "IBEX_TEST_NATIVE_RUNNER_PROFILE"
                }]
            },
            {
                "authority": {
                    "cap": "fs:read",
                    "resource": {
                        "kind": "path-tree",
                        "path": {"root": "project", "components": []}
                    }
                },
                "provenance": [{
                    "kind": "direct",
                    "source": "IBEX_TEST_NATIVE_RUNNER_PROFILE"
                }]
            },
            {
                "authority": {
                    "cap": "stdio:write",
                    "resource": {
                        "kind": "stdio",
                        "stream": "stdout",
                        "source": {
                            "kind": "broker",
                            "identity": "ibex:console:stdout"
                        }
                    }
                },
                "provenance": [{
                    "kind": "direct",
                    "source": "IBEX_TEST_NATIVE_RUNNER_PROFILE"
                }]
            }
        ]);
    }
    for (field, expected) in [
        ("policySchema", "ibex/capsec-policy/2"),
        ("capsVocab", "ibex/capsec/1"),
        ("semanticCore", "capsec/semantics/1"),
        ("purpose", "production"),
        ("mode", "enforce"),
    ] {
        if policy[field].as_str() != Some(expected) {
            anyhow::bail!("canonical production policy has invalid {field}");
        }
    }
    // Unadvertised dev arming with no authored policy: the root authority ceiling
    // gates ambient-root authorization (a decision denies at the root-ceiling
    // stratum before ever reaching the floor). A default build synthesizes an
    // empty ceiling, so the root principal cannot read the entry program or
    // project files (`ibex run <file>`, or fs.* in the REPL). Raise the ceiling
    // to cover the project subtree so ambient root authorizes reads/writes
    // within the project. External effects (network, environment, paths outside
    // the project) stay outside the ceiling and remain closed — the capability
    // model stays meaningful; only the project mount is opened for local
    // development. Only when synthesizing the default policy; an authored
    // `ibex-policy.json` is never widened. Compiled only under the feature.
    // @ref LLP 0038#2-root-authority-ceiling-raised-to-the-project-subtree —
    // why the ceiling and not a floor: the floor strata are never reached,
    // because the root-ceiling gate denies first.
    #[cfg(feature = "unadvertised-dev-arming")]
    if !policy_loaded && !native_runner_conformance {
        // Canonically sorted by capability; arming refuses an unsorted ceiling.
        // `path:cwd-*` is required for *relative* paths: resolving `foo.txt`
        // observes the session cwd before any fs effect, so without it every
        // relative read fails with "EACCES: cwd: filesystem policy denied"
        // even though the fs capabilities are present.
        let project_tree = serde_json::json!({
            "kind": "path-tree",
            "path": {"root": "project", "components": []},
        });
        let session_cwd = serde_json::json!({"kind": "session-state", "name": "cwd"});
        // `lifecycle:exit`/`exit-request` authorizes the *cooperative exit
        // request* — the operator Ctrl-D/`.exit` route and root-attributed
        // `process.exit()`. Without it the step-6 ceiling gate denies the
        // operator's own EOF and the secure-dev REPL cannot be exited
        // cleanly (exit 1, "operator exit was denied by the typed lifecycle
        // route"). The exit-code get/set dispositions are distinct resources
        // and are NOT granted here, so orderly shutdown consistently exits 0.
        // @ref LLP 0025#8-exit-and-lifecycle — orderly shutdown (Ctrl+D at an
        // empty prompt, `.exit`) and root-attributed cooperative exit must
        // succeed; only non-root attribution receives the typed denial.
        let lifecycle_exit_request = serde_json::json!({
            "kind": "session-lifecycle",
            "disposition": "exit-request",
        });
        policy["rootCeiling"] = serde_json::json!([
            ("fs:list", &project_tree),
            ("fs:read", &project_tree),
            ("fs:watch", &project_tree),
            ("fs:write", &project_tree),
            ("lifecycle:exit", &lifecycle_exit_request),
            // `path:cwd-mutate` (process.chdir) is deliberately omitted: the
            // registry restricts it to `path-exact`, so it could only ever name
            // one exact directory rather than the project subtree.
            ("path:cwd-observe", &session_cwd),
        ]
        .iter()
        .map(|(cap, resource)| serde_json::json!({
            "authority": {"cap": cap, "resource": resource},
            "provenance": [{
                "kind": "direct",
                "source": "ibex:unadvertised-dev-arming:project-ceiling",
            }],
        }))
        .collect::<Vec<_>>());
    }
    let policy_digest = compute_checked_contract_digest(DigestKind::Policy, &policy)?;
    if policy_loaded && policy["policyDigest"].as_str() != Some(policy_digest.as_str()) {
        anyhow::bail!("canonical policy digest is stale or tampered");
    } else {
        policy["policyDigest"] = serde_json::json!(policy_digest.as_str());
    }
    let canonical_policy = capsec_semantics::policy::CanonicalPolicy::load(
        &serde_json::to_vec(&policy)?,
        &expected_policy_identity,
        &policy_profile.definitions,
    )
    .with_context(|| {
        if policy.get("rootImports").is_none() {
            "canonical production policy predates explicit root-import provenance; regenerate it"
        } else {
            "canonical production policy failed typed validation"
        }
    })?;
    let mut root_package_imports = canonical_policy
        .root_imports
        .iter()
        .map(|locator| locator.as_str().to_owned())
        .collect::<Vec<_>>();
    root_package_imports.sort();
    let policy_digest = canonical_policy.policy_digest.as_str().to_owned();
    policy = serde_json::to_value(canonical_policy)?;
    phase.mark("arm_policy_load");
    let policy_principals = policy["principals"]
        .as_array()
        .context("canonical policy principals must be an array")?;
    let mut root_builtins = crate::module_loader::RUNTIME_GATED_NODE_BUILTINS
        .iter()
        .map(|name| format!("node:{name}"))
        .collect::<Vec<_>>();
    root_builtins.sort();
    let native_runner_root_floor = if native_runner_conformance {
        policy["rootCeiling"]
            .as_array()
            .context("native runner root ceiling must be an array")?
            .iter()
            .map(|row| row["authority"].clone())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut snapshot_principals = vec![serde_json::json!({
        "principal": {"kind": "root", "identity": "project-root"},
        "floor": native_runner_root_floor,
        "denials": [],
        "escalationCeiling": [],
        "imports": {
            "builtins": root_builtins,
            "packages": root_package_imports.clone()
        },
        "endowments": [],
    })];
    let mut graph_nodes = Vec::new();
    let mut package_bindings = Vec::new();
    let installed_packages = authenticated_installed_packages(&project_root, policy_principals)?;
    phase.mark("arm_packages_auth");
    for row in policy_principals {
        let principal = row["principal"].clone();
        let authority_rows = |field: &str| -> Result<Vec<serde_json::Value>> {
            row[field]
                .as_array()
                .context("canonical authority rows must be arrays")?
                .iter()
                .map(|entry| {
                    entry
                        .get("authority")
                        .cloned()
                        .context("canonical authority row is missing authority")
                })
                .collect()
        };
        snapshot_principals.push(serde_json::json!({
            "principal": principal,
            "floor": authority_rows("floor")?,
            "denials": authority_rows("denials")?,
            "escalationCeiling": authority_rows("escalationCeiling")?,
            "imports": row["imports"].clone(),
            "endowments": row["endowments"].clone(),
        }));
        if let (Some(name), Some(locator), Some(integrity)) = (
            principal["name"].as_str(),
            principal["locator"].as_str(),
            principal["integrity"].as_str(),
        ) {
            let matches = installed_packages
                .iter()
                .filter(|package| {
                    package.name == name
                        && package.locator == locator
                        && package.integrity == integrity
                })
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                anyhow::bail!(
                    "authenticated package principal {locator} has {} installed roots",
                    matches.len()
                );
            }
            let package_root = matches[0].root.clone();
            let object = runtime_object_identity_json(&package_root)?;
            let package_components = runtime_path_components_json(&package_root)?;
            let project_relative = package_root.strip_prefix(&project_root).with_context(|| {
                format!(
                    "authenticated package root {} is outside project {}",
                    package_root.display(),
                    project_root.display()
                )
            })?;
            let virtual_components = runtime_path_components_json(project_relative)?;
            graph_nodes.push(serde_json::json!({
                "principal": principal,
                "resolvingSpecifier": name,
                "rootObject": object,
                "virtualAliases": [{
                    "root": "project",
                    "components": virtual_components,
                }],
                "platformDisposition": "required",
            }));
            package_bindings.push(serde_json::json!({
                    "logicalRoot": "package",
                    "owner": principal,
                    "hostPath": {"root": "absolute", "components": package_components, "hostBound": true},
                    "object": object,
            }));
        }
    }
    // @ref LLP 0023#12-package-bindings-are-derived-from-the-graph-and-contained-in-the-project
    // — snapshot edges bind the caller-visible request and resolution mode to
    // one exact package principal before the resolver can inspect its root.
    let graph_edges = policy_package_graph_edges(policy_principals, &root_package_imports)?;
    let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    value["workflow"] = serde_json::json!("production");
    value["effectiveMode"] = serde_json::json!("enforce");
    // @ref LLP 0022#11-delegated-obligations — OBL-ENV-BASE is a digest-bound,
    // explicitly empty session base. Exact-name values can exist only in the
    // independently authorized principal overlays carried by policy rows.
    value["environmentBase"] = serde_json::json!([]);
    value["bootstrapCompatibilityModes"] =
        serde_json::to_value(requested_bootstrap_compatibility_modes(cli))?;
    value["policyDigest"] = serde_json::json!(policy_digest);
    // The armed root ceiling is exactly the canonical policy's authored root
    // ceiling — never the template's. An absent authored ceiling arms bounded
    // and empty rather than inheriting the example document's unbounded value.
    // `insecure` arms the root ceiling unbounded, so `ceiling_allows` is true
    // for every effect and ambient root authorizes all capabilities. This is
    // only one of the three mechanisms that feature turns off; the mount
    // restriction and the native gates are opened via `ex_host_is_armed()`.
    // @ref LLP 0038#fully-open-mode-insecure
    #[cfg(feature = "insecure")]
    {
        value["rootAuthorityCeiling"] = serde_json::json!({"kind": "unbounded"});
    }
    #[cfg(not(feature = "insecure"))]
    {
        value["rootAuthorityCeiling"] = serde_json::json!({
            "kind": "bounded",
            "authorities": policy["rootCeiling"]
                .as_array()
                .context("canonical root ceiling must be an array")?
                .iter()
                .map(|row| row["authority"].clone())
                .collect::<Vec<_>>(),
        });
    }
    // @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine — the
    // current bootstrap has no root-attributed capability effect, so its exact
    // least-authority floor is empty; future effects must add source-derived
    // selectors and retained-callback denial evidence together.
    value["bootstrapAuthorityFloor"] = serde_json::json!([]);
    value["engine"] = serde_json::json!({
        "target": exact_runtime_target(),
        "binaryDigest": engine_digest,
        "features": observed_structural_features(),
    });
    value["packageGraph"] = serde_json::json!({
        "digest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "nodes": graph_nodes,
        "importEdges": graph_edges,
    });
    let graph_digest = compute_domain_digest(
        "ibex:capsec:package-graph:1",
        &value["packageGraph"],
        &["digest".to_string()],
    )?;
    value["packageGraph"]["digest"] = serde_json::json!(graph_digest);
    value["principals"] = serde_json::Value::Array(snapshot_principals);
    let mut epoch = [0u8; 8];
    getrandom::getrandom(&mut epoch).context("failed to generate CapSec channel epoch")?;
    value["channelEpoch"] = serde_json::json!(u64::from_le_bytes(epoch).max(1).to_string());
    let mut root_bindings = vec![serde_json::json!({
        "logicalRoot": "project",
        "hostPath": {"root": "absolute", "components": components, "hostBound": true},
        "object": root_object,
    })];
    let cache_components = runtime_path_components_json(&cache_root)?;
    let cache_object = runtime_object_identity_json(&cache_root)?;
    root_bindings.push(serde_json::json!({
        "logicalRoot": "home",
        "hostPath": {"root": "absolute", "components": cache_components, "hostBound": true},
        "object": cache_object,
    }));
    root_bindings.extend(package_bindings);
    value["rootBindings"] = serde_json::Value::Array(root_bindings);
    value["pathCanonicalizers"] = serde_json::to_value(runtime_path_canonicalizers(
        value["rootBindings"]
            .as_array()
            .context("armed root bindings must be an array")?,
    )?)?;
    value["entry"] = serde_json::to_value(entry)?;
    value["projectRootDiscovery"] = serde_json::to_value(&project_root_discovery)?;
    phase.mark("arm_snapshot_document");
    let policy_bytes = capsec_semantics::canonical::to_jcs_bytes(&policy)?;
    let graph_bytes = capsec_semantics::canonical::to_jcs_bytes(&value["packageGraph"])?;
    let registry_digest_name = value["registryDigest"]
        .as_str()
        .context("registry digest missing")?
        .to_owned();
    // Warm path: authenticate the pinned registry artifact against the
    // build-time digest. Cold path: pin the build-generated canonical bytes.
    // Both are derived from the exact checked-in registry inputs by build.rs;
    // startup never needs to parse and canonicalize the ~17 MB record.
    let registry_object =
        match pin_precomputed_registry_artifact(&cache_root, &registry_digest_name)? {
            Some(artifact) => artifact,
            None => materialize_protected_artifact(
                &cache_root,
                "registry",
                &registry_digest_name,
                CAPSEC_REGISTRY_RECORD_JCS,
            )?,
        };
    phase.mark("arm_registry_record");
    let policy_object = materialize_protected_artifact(
        &cache_root,
        "armed-policy",
        value["policyDigest"]
            .as_str()
            .context("policy digest missing")?,
        &policy_bytes,
    )?;
    let graph_object = materialize_protected_artifact(
        &cache_root,
        "package-graph",
        value["packageGraph"]["digest"]
            .as_str()
            .context("package graph digest missing")?,
        &graph_bytes,
    )?;
    phase.mark("arm_artifact_materialize");
    value["protectedObjects"] = serde_json::json!([
        {"role": "armed-policy", "object": policy_object.object, "deniedActions": ["fs:write"]},
        {"role": "engine-binary", "object": engine_object, "deniedActions": ["fs:write"]},
        {"role": "package-graph", "object": graph_object.object, "deniedActions": ["fs:write"]},
        {"role": "registry", "object": registry_object.object, "deniedActions": ["fs:write"]},
    ]);
    finalize_production_snapshot(&mut value)?;
    let digest_at = |path: &[&str]| -> Result<Digest> {
        let field = path
            .iter()
            .fold(&value, |current, segment| &current[*segment]);
        Digest::new(field.as_str().context("missing default arming digest")?)
            .map_err(anyhow::Error::msg)
    };
    let engine_host_path = serde_json::from_value(serde_json::json!({
        "root": "absolute",
        "components": runtime_path_components_json(&engine_identity.engine_artifact_path)?,
        "hostBound": true,
    }))?;
    let expected = ExpectedArmingIdentity {
        profile: value["capsVocab"].as_str().unwrap().into(),
        semantic_core: value["semanticCore"].as_str().unwrap().into(),
        vocab_digest: digest_at(&["vocabDigest"])?,
        registry_digest: digest_at(&["registryDigest"])?,
        policy_digest: digest_at(&["policyDigest"])?,
        armed_snapshot_digest: Digest::new(
            value["armedSnapshotDigest"]
                .as_str()
                .context("missing armed snapshot digest")?,
        )
        .map_err(anyhow::Error::msg)?,
        target: value["engine"]["target"].as_str().unwrap().into(),
        engine_binary_digest: digest_at(&["engine", "binaryDigest"])?,
        features: value["engine"]["features"]
            .as_array()
            .unwrap()
            .iter()
            .map(|feature| feature.as_str().unwrap().into())
            .collect(),
        package_graph_digest: digest_at(&["packageGraph", "digest"])?,
        entry: serde_json::from_value(value["entry"].clone())?,
        project_root_discovery,
        path_canonicalizers: serde_json::from_value(value["pathCanonicalizers"].clone())?,
        protected_artifacts: vec![
            capsec_semantics::arming::ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::ArmedPolicy,
                host_path: policy_object.host_path,
                object: serde_json::from_value(value["protectedObjects"][0]["object"].clone())?,
                content_digest: policy_object.content_digest,
            },
            capsec_semantics::arming::ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::EngineBinary,
                host_path: engine_host_path,
                object: engine_identity.object,
                content_digest: digest_at(&["engine", "binaryDigest"])?,
            },
            capsec_semantics::arming::ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::PackageGraph,
                host_path: graph_object.host_path,
                object: serde_json::from_value(value["protectedObjects"][2]["object"].clone())?,
                content_digest: graph_object.content_digest,
            },
            capsec_semantics::arming::ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::Registry,
                host_path: registry_object.host_path,
                object: serde_json::from_value(value["protectedObjects"][3]["object"].clone())?,
                content_digest: registry_object.content_digest,
            },
        ],
        embedded_protected_artifacts: vec![],
        runtime_extension_authority_digest: None,
        runtime_extension_mapped_executable: None,
    };
    phase.mark("arm_snapshot_build");
    let snapshot = Arc::new(ArmedSnapshot::load(
        &serde_json::to_vec(&value)?,
        &expected,
    )?);
    phase.mark("arm_snapshot_load");
    validate_optional_home_cache_binding(&snapshot, &cache_root)?;
    let digest = snapshot.digest().as_str().to_owned();
    let host_config = HostConfig {
        mode: crate::host::SecurityMode::Enforce,
        ..Default::default()
    };
    let host = construct_default_armed_host(host_config, snapshot)?;
    phase.mark("arm_host_new");
    Ok((host, Some(digest), project_root, cache_root))
}

fn construct_default_armed_host(
    config: HostConfig,
    snapshot: Arc<capsec_semantics::arming::ArmedSnapshot>,
) -> Result<Host> {
    #[cfg(feature = "module-runner")]
    if native_runner_test_profile()?.is_some() {
        #[cfg(all(
            debug_assertions,
            feature = "capsec-conformance-observer",
            not(feature = "insecure")
        ))]
        {
            return Host::new_armed_for_native_module_runner_conformance(config, snapshot)
                .context("failed to construct native module-runner conformance host");
        }
        #[cfg(not(all(
            debug_assertions,
            feature = "capsec-conformance-observer",
            not(feature = "insecure")
        )))]
        anyhow::bail!(
            "IBEX_TEST_NATIVE_RUNNER_PROFILE requires a secure debug build with the capsec-conformance-observer feature"
        );
    }

    #[cfg(feature = "insecure")]
    {
        return Host::new_armed_insecure(config, snapshot)
            .context("failed to construct insecure armed capability host");
    }
    #[cfg(all(not(feature = "insecure"), feature = "unadvertised-dev-arming"))]
    if unadvertised_dev_arming_active() {
        return Host::new_armed_unadvertised_dev(config, snapshot)
            .context("failed to construct unadvertised development host");
    }
    Host::new_armed(config, snapshot).context("failed to construct armed capability host")
}

/// Whether the opt-in `unadvertised-dev-arming` feature is compiled in. When it
/// is, `ibex` arms without a checked target advertisement (loud banner; every
/// other authenticator still runs). The feature is compile-time, so both the
/// parent process and the re-exec'd session worker (the same binary) observe the
/// same value with no runtime environment or CLI surface, and a default/shipped
/// build has no unadvertised arming path at all — the production advertisement
/// is its sole arming route.
/// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
#[allow(dead_code)] // The default `insecure` profile selects its stricter compile-time branch first.
pub(crate) fn unadvertised_dev_arming_active() -> bool {
    cfg!(feature = "unadvertised-dev-arming")
}

/// Print the one-time dev-arming warning banner at startup when the
/// `unadvertised-dev-arming` feature is compiled in. No-op otherwise.
pub(crate) fn emit_unadvertised_dev_arming_banner_if_active() {
    #[cfg(feature = "unadvertised-dev-arming")]
    {
        eprintln!(
            "\x1b[1;33mibex: DEV ARMING — running WITHOUT a checked target advertisement.\x1b[0m"
        );
        // The two modes make very different security claims, so they must not
        // print the same banner. @ref LLP 0038#fully-open-mode-insecure
        #[cfg(feature = "insecure")]
        eprintln!(
            "\x1b[1;31mibex: INSECURE BUILD — ALL security enforcement is DISABLED.\x1b[0m\nibex: this process can read and write your entire filesystem, spawn processes, and reach the network. There is no sandbox. Never ship, publish, or run untrusted code with this build."
        );
        #[cfg(not(feature = "insecure"))]
        eprintln!(
            "ibex: capabilities are still enforced, but this is NOT an advertised target. Do not ship or trust this run."
        );
    }
}

fn exact_runtime_target() -> String {
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        "x86" => "i686",
        other => other,
    };
    let suffix = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "ios" => "apple-ios",
        "tvos" => "apple-tvos",
        "linux" => "unknown-linux-gnu",
        "android" => "linux-android",
        "windows" => "pc-windows-msvc",
        other => other,
    };
    format!("{architecture}-{suffix}")
}

fn observed_structural_features() -> Vec<String> {
    ibex_runtime::engine::loaded_engine_structural_features()
}

fn observed_arming_identity(
    mut supplied: capsec_semantics::arming::ExpectedArmingIdentity,
    snapshot_bytes: &[u8],
) -> Result<capsec_semantics::arming::ExpectedArmingIdentity> {
    supplied = ibex_runtime::host::embedder_artifacts::verify_expected_identity(supplied)?;
    let snapshot_text = std::str::from_utf8(snapshot_bytes)
        .context("capsec armed snapshot is not UTF-8 while probing bound volumes")?;
    let snapshot = capsec_semantics::strict_json::parse_strict(snapshot_text)
        .context("invalid strict JSON in capsec armed snapshot while probing bound volumes")?;
    supplied.path_canonicalizers = runtime_path_canonicalizers(
        snapshot["rootBindings"]
            .as_array()
            .context("capsec armed snapshot rootBindings must be an array")?,
    )?;
    Ok(supplied)
}

const PROJECT_ROOT_MARKER_SET_VERSION: &str =
    capsec_semantics::arming::PROJECT_ROOT_MARKER_SET_VERSION;
const PROJECT_ROOT_FALLBACK_DIAGNOSTIC: &str = "IBEX_PROJECT_ROOT_ORIGIN_FALLBACK";
const PROJECT_ROOT_WIDE_MOUNT_DIAGNOSTIC: &str = "IBEX_PROJECT_ROOT_WIDE_MOUNT_REFUSED";
const PROJECT_ROOT_LOCKFILES: [&str; 5] = [
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lockb",
    "bun.lock",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectRootMarkerKind {
    ExplicitProject,
    PnpmWorkspace,
    PackageWorkspace,
    Lockfile,
    PackageManifest,
    OriginFallback,
}

impl ProjectRootMarkerKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitProject => "explicit-project",
            Self::PnpmWorkspace => "pnpm-workspace",
            Self::PackageWorkspace => "package-workspace",
            Self::Lockfile => "lockfile",
            Self::PackageManifest => "package-manifest",
            Self::OriginFallback => "origin-fallback",
        }
    }

    fn armed(self) -> capsec_semantics::arming::ArmedProjectRootMarkerKind {
        use capsec_semantics::arming::ArmedProjectRootMarkerKind;

        match self {
            Self::ExplicitProject => ArmedProjectRootMarkerKind::ExplicitProject,
            Self::PnpmWorkspace => ArmedProjectRootMarkerKind::PnpmWorkspace,
            Self::PackageWorkspace => ArmedProjectRootMarkerKind::PackageWorkspace,
            Self::Lockfile => ArmedProjectRootMarkerKind::Lockfile,
            Self::PackageManifest => ArmedProjectRootMarkerKind::PackageManifest,
            Self::OriginFallback => ArmedProjectRootMarkerKind::OriginFallback,
        }
    }
}

/// The authenticated inputs to project-root selection. This is deliberately a
/// richer value than the selected path so the marker kind, marker path, and
/// marker-set version remain available to the armed-snapshot construction.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectRootDiscovery {
    origin: PathBuf,
    selected_root: PathBuf,
    marker_kind: ProjectRootMarkerKind,
    marker_path: Option<PathBuf>,
    marker_set_version: &'static str,
    diagnostic: Option<&'static str>,
}

impl ProjectRootDiscovery {
    fn armed_record(&self) -> Result<capsec_semantics::arming::ArmedProjectRootDiscovery> {
        Ok(capsec_semantics::arming::ArmedProjectRootDiscovery {
            origin: runtime_authenticated_host_path(&self.origin)?,
            selected_root: runtime_authenticated_host_path(&self.selected_root)?,
            marker_kind: self.marker_kind.armed(),
            marker_path: self
                .marker_path
                .as_deref()
                .map(runtime_authenticated_host_path)
                .transpose()?,
            marker_set_version: self.marker_set_version.to_owned(),
        })
    }
}

#[derive(Debug)]
struct DirectoryProjectMarkers {
    workspace: Option<(ProjectRootMarkerKind, PathBuf)>,
    lockfile: Option<PathBuf>,
    manifest: Option<PathBuf>,
}

#[cfg(test)]
fn authenticated_project_root(cli: &Cli, entry: Option<&str>) -> Result<std::path::PathBuf> {
    let entry_path = entry
        .map(|entry| {
            std::fs::canonicalize(entry)
                .with_context(|| format!("failed to authenticate entry path {entry}"))
        })
        .transpose()?;
    authenticated_project_root_for_entry(cli, entry_path.as_deref())
}

#[cfg(test)]
fn authenticated_project_root_for_entry(
    cli: &Cli,
    entry_path: Option<&std::path::Path>,
) -> Result<std::path::PathBuf> {
    let discovery = authenticated_project_root_discovery_for_entry(cli, entry_path)?;
    emit_project_root_discovery_diagnostic(&discovery);
    Ok(discovery.selected_root)
}

fn emit_project_root_discovery_diagnostic(discovery: &ProjectRootDiscovery) {
    if let Some(diagnostic) = discovery.diagnostic {
        eprintln!(
            "{diagnostic}: no selecting {} marker was found; using discovery origin {}",
            discovery.marker_set_version,
            discovery.origin.display()
        );
    }
    debug_assert_eq!(
        discovery.marker_kind == ProjectRootMarkerKind::OriginFallback,
        discovery.diagnostic.is_some()
    );
    debug_assert_eq!(
        discovery.marker_kind == ProjectRootMarkerKind::OriginFallback,
        discovery.marker_path.is_none()
    );
    debug_assert!(!discovery.marker_kind.as_str().is_empty());
}

/// Select the one project root whose object identity will be bound into the
/// generated armed snapshot. Every execution mode uses this same discovery
/// rule; only the origin differs between file and non-file routes.
/// @ref LLP 0023#11-project-root-discovery — deterministic authority-boundary discovery
fn authenticated_project_root_discovery_for_entry(
    cli: &Cli,
    entry_path: Option<&Path>,
) -> Result<ProjectRootDiscovery> {
    let origin = entry_path
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
        .unwrap_or(std::env::current_dir()?);

    let home = dirs::home_dir();
    discover_project_root_from_origin(
        &origin,
        cli.project_root.as_deref(),
        entry_path,
        home.as_deref(),
        filesystem_device_id,
    )
}

fn discover_project_root_from_origin<F>(
    origin: &Path,
    explicit_root: Option<&Path>,
    entry_path: Option<&Path>,
    home_boundary: Option<&Path>,
    mut device_id: F,
) -> Result<ProjectRootDiscovery>
where
    F: FnMut(&Path) -> Result<String>,
{
    let origin = std::fs::canonicalize(origin).with_context(|| {
        format!(
            "failed to authenticate project discovery origin {}",
            origin.display()
        )
    })?;
    if !origin.is_dir() {
        anyhow::bail!(
            "project discovery origin is not a directory: {}",
            origin.display()
        );
    }

    if let Some(explicit) = explicit_root {
        let root = std::fs::canonicalize(explicit).with_context(|| {
            format!("failed to authenticate project root {}", explicit.display())
        })?;
        if !root.is_dir() {
            anyhow::bail!("project root is not a directory: {}", root.display());
        }
        if entry_path.is_some_and(|entry| !entry.starts_with(&root)) {
            anyhow::bail!(
                "entry is outside the explicitly authenticated project root {}",
                root.display()
            );
        }
        return Ok(ProjectRootDiscovery {
            origin,
            selected_root: root.clone(),
            marker_kind: ProjectRootMarkerKind::ExplicitProject,
            marker_path: Some(root),
            marker_set_version: PROJECT_ROOT_MARKER_SET_VERSION,
            diagnostic: None,
        });
    }

    let home_boundary = home_boundary
        .map(|home| {
            std::fs::canonicalize(home).with_context(|| {
                format!(
                    "failed to authenticate invoking user's home boundary {}",
                    home.display()
                )
            })
        })
        .transpose()?;
    if home_boundary.as_deref() == Some(origin.as_path()) {
        anyhow::bail!(
            "{PROJECT_ROOT_WIDE_MOUNT_DIAGNOSTIC}: discovery origin {} is the invoking user's home directory; pass --project-root explicitly",
            origin.display()
        );
    }
    if origin.parent().is_none() {
        anyhow::bail!(
            "{PROJECT_ROOT_WIDE_MOUNT_DIAGNOSTIC}: discovery origin {} is a filesystem root; pass --project-root explicitly",
            origin.display()
        );
    }

    let origin_device = device_id(&origin).with_context(|| {
        format!(
            "failed to authenticate filesystem for project discovery origin {}",
            origin.display()
        )
    })?;
    let mut cursor = origin.clone();
    let mut outermost_workspace: Option<(PathBuf, ProjectRootMarkerKind, PathBuf)> = None;
    let mut nearest_lockfile: Option<(PathBuf, PathBuf)> = None;
    let mut nearest_manifest: Option<(PathBuf, PathBuf)> = None;

    loop {
        // Home and the filesystem root are stop boundaries, not candidates.
        if home_boundary.as_deref() == Some(cursor.as_path()) || cursor.parent().is_none() {
            break;
        }

        let parent = cursor
            .parent()
            .expect("filesystem-root cursor was handled above");
        let next_cursor = if home_boundary.as_deref() == Some(parent) {
            None
        } else {
            match device_id(parent) {
                Ok(parent_device) if parent_device == origin_device => Some(parent),
                Ok(_) => {
                    // The mount point itself is the device stop boundary, so
                    // its marker is not eligible. Starting exactly there also
                    // makes origin fallback a potentially device-wide mount.
                    if cursor == origin {
                        anyhow::bail!(
                            "{PROJECT_ROOT_WIDE_MOUNT_DIAGNOSTIC}: discovery origin {} is a device boundary; pass --project-root explicitly",
                            origin.display()
                        );
                    }
                    break;
                }
                // The current directory is authenticated, but the parent is
                // not. Inspect current, then stop before the parent.
                Err(_) => None,
            }
        };

        if let Err(error) = std::fs::read_dir(&cursor) {
            if cursor == origin {
                return Err(error).with_context(|| {
                    format!(
                        "failed to authenticate project discovery origin {}",
                        cursor.display()
                    )
                });
            }
            // A non-origin ancestor the runtime cannot enumerate is a stop
            // boundary. It is not safe to conclude that markers are absent.
            break;
        }
        let markers = inspect_directory_project_markers(&cursor, &origin)?;
        if let Some((kind, marker_path)) = markers.workspace {
            // Ascent is inside-out, so replacement makes the final workspace
            // the outermost matching declaration.
            outermost_workspace = Some((cursor.clone(), kind, marker_path));
        }
        if nearest_lockfile.is_none() {
            nearest_lockfile = markers
                .lockfile
                .map(|marker_path| (cursor.clone(), marker_path));
        }
        if nearest_manifest.is_none() {
            nearest_manifest = markers
                .manifest
                .map(|marker_path| (cursor.clone(), marker_path));
        }

        let Some(next_cursor) = next_cursor else {
            break;
        };
        cursor = next_cursor.to_path_buf();
    }

    let selected = outermost_workspace
        .map(|(root, kind, marker_path)| (root, kind, Some(marker_path)))
        .or_else(|| {
            nearest_lockfile.map(|(root, marker_path)| {
                (root, ProjectRootMarkerKind::Lockfile, Some(marker_path))
            })
        })
        .or_else(|| {
            nearest_manifest.map(|(root, marker_path)| {
                (
                    root,
                    ProjectRootMarkerKind::PackageManifest,
                    Some(marker_path),
                )
            })
        });
    let (selected_root, marker_kind, marker_path, diagnostic) = match selected {
        Some((root, kind, marker_path)) => (root, kind, marker_path, None),
        None => (
            origin.clone(),
            ProjectRootMarkerKind::OriginFallback,
            None,
            Some(PROJECT_ROOT_FALLBACK_DIAGNOSTIC),
        ),
    };
    Ok(ProjectRootDiscovery {
        origin,
        selected_root,
        marker_kind,
        marker_path,
        marker_set_version: PROJECT_ROOT_MARKER_SET_VERSION,
        diagnostic,
    })
}

fn inspect_directory_project_markers(
    directory: &Path,
    origin: &Path,
) -> Result<DirectoryProjectMarkers> {
    let pnpm_path = directory.join("pnpm-workspace.yaml");
    let pnpm_patterns = read_marker_bytes(&pnpm_path)?
        .map(|bytes| {
            parse_pnpm_workspace_patterns(&bytes).with_context(|| {
                format!(
                    "malformed or unreadable project-root marker {}",
                    pnpm_path.display()
                )
            })
        })
        .transpose()?;

    let manifest_path = directory.join("package.json");
    let package_patterns = read_marker_bytes(&manifest_path)?
        .map(|bytes| {
            parse_package_workspace_patterns(&bytes).with_context(|| {
                format!(
                    "malformed or unreadable project-root marker {}",
                    manifest_path.display()
                )
            })
        })
        .transpose()?;

    // Both declarations are validated when present. The versioned marker
    // table orders pnpm first when two matching declarations share a root.
    let workspace = if pnpm_patterns
        .as_ref()
        .is_some_and(|patterns| workspace_contains_origin(directory, origin, patterns))
    {
        Some((ProjectRootMarkerKind::PnpmWorkspace, pnpm_path))
    } else if package_patterns
        .as_ref()
        .and_then(Option::as_ref)
        .is_some_and(|patterns| workspace_contains_origin(directory, origin, patterns))
    {
        Some((
            ProjectRootMarkerKind::PackageWorkspace,
            manifest_path.clone(),
        ))
    } else {
        None
    };

    let mut lockfile = None;
    for name in PROJECT_ROOT_LOCKFILES {
        let path = directory.join(name);
        if authenticate_marker_presence(&path)? && lockfile.is_none() {
            lockfile = Some(path);
        }
    }

    Ok(DirectoryProjectMarkers {
        workspace,
        lockfile,
        manifest: package_patterns.map(|_| manifest_path),
    })
}

fn read_marker_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            let metadata = std::fs::metadata(path).with_context(|| {
                format!(
                    "malformed or unreadable project-root marker {}",
                    path.display()
                )
            })?;
            if !metadata.is_file() {
                anyhow::bail!(
                    "malformed or unreadable project-root marker {}: marker is not a file",
                    path.display()
                );
            }
            std::fs::read(path).map(Some).with_context(|| {
                format!(
                    "malformed or unreadable project-root marker {}",
                    path.display()
                )
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "malformed or unreadable project-root marker {}",
                path.display()
            )
        }),
    }
}

fn authenticate_marker_presence(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            let metadata = std::fs::metadata(path).with_context(|| {
                format!(
                    "malformed or unreadable project-root marker {}",
                    path.display()
                )
            })?;
            if !metadata.is_file() {
                anyhow::bail!(
                    "malformed or unreadable project-root marker {}: marker is not a file",
                    path.display()
                );
            }
            std::fs::File::open(path).with_context(|| {
                format!(
                    "malformed or unreadable project-root marker {}",
                    path.display()
                )
            })?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "malformed or unreadable project-root marker {}",
                path.display()
            )
        }),
    }
}

fn parse_package_workspace_patterns(bytes: &[u8]) -> Result<Option<Vec<String>>> {
    let value: serde_json::Value = serde_json::from_slice(bytes).context("invalid package JSON")?;
    let object = value
        .as_object()
        .context("package manifest must be a JSON object")?;
    let Some(workspaces) = object.get("workspaces") else {
        return Ok(None);
    };
    let values = if let Some(values) = workspaces.as_array() {
        values
    } else if let Some(workspaces) = workspaces.as_object() {
        workspaces
            .get("packages")
            .and_then(serde_json::Value::as_array)
            .context("workspaces object must contain a packages array")?
    } else {
        anyhow::bail!("workspaces must be an array or an object with a packages array");
    };
    let patterns = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .context("workspace pattern must be a string")
                .and_then(validate_workspace_pattern)
        })
        .collect::<Result<Vec<_>>>()?;
    if patterns.is_empty() {
        Ok(None)
    } else {
        Ok(Some(patterns))
    }
}

fn parse_pnpm_workspace_patterns(bytes: &[u8]) -> Result<Vec<String>> {
    let source = std::str::from_utf8(bytes).context("workspace YAML is not UTF-8")?;
    if source.contains('\t') {
        anyhow::bail!("workspace YAML contains unsupported tab indentation");
    }

    let lines = source.lines().collect::<Vec<_>>();
    validate_pnpm_yaml_subset(&lines)?;
    let mut packages_line = None;
    for (index, line) in lines.iter().enumerate() {
        let without_comment = strip_yaml_comment(line)?;
        let trimmed = without_comment.trim();
        if trimmed.is_empty() || trimmed == "---" || trimmed == "..." {
            continue;
        }
        if line.len() == line.trim_start().len() {
            if let Some((key, _)) = trimmed.split_once(':') {
                if key.trim() == "packages" && packages_line.replace(index).is_some() {
                    anyhow::bail!("workspace YAML contains duplicate packages keys");
                }
            }
        }
    }
    let index = packages_line.context("workspace YAML must contain a top-level packages list")?;
    let header = strip_yaml_comment(lines[index])?;
    let (_, inline) = header.split_once(':').context("malformed packages key")?;
    let inline = inline.trim();
    let raw_patterns = if inline.is_empty() {
        let mut patterns = Vec::new();
        let mut sequence_indentation = None;
        for line in lines.iter().skip(index + 1) {
            let without_comment = strip_yaml_comment(line)?;
            if without_comment.trim().is_empty() {
                continue;
            }
            if line.len() == line.trim_start().len() {
                break;
            }
            let indentation = line.len() - line.trim_start().len();
            if sequence_indentation
                .replace(indentation)
                .is_some_and(|expected| expected != indentation)
            {
                anyhow::bail!("packages sequence uses inconsistent indentation");
            }
            let item = without_comment
                .trim_start()
                .strip_prefix('-')
                .context("packages must be a YAML sequence of scalar patterns")?
                .trim();
            patterns.push(parse_yaml_scalar(item)?);
        }
        if patterns.is_empty() {
            anyhow::bail!("packages must be a YAML list");
        }
        patterns
    } else {
        parse_yaml_inline_sequence(inline)?
    };
    raw_patterns
        .into_iter()
        .map(|pattern| validate_workspace_pattern(&pattern))
        .collect()
}

/// Validate the deliberately small YAML subset accepted for discovery. The
/// package list and ordinary nested mappings/sequences used by pnpm are
/// supported; anchors, multiline scalars, and structurally ambiguous input
/// fail closed instead of being partially interpreted.
fn validate_pnpm_yaml_subset(lines: &[&str]) -> Result<()> {
    for line in lines {
        let without_comment = strip_yaml_comment(line)?;
        let trimmed = without_comment.trim();
        if trimmed.is_empty() || trimmed == "---" || trimmed == "..." {
            continue;
        }

        validate_yaml_flow_delimiters(trimmed)?;
        let indentation = line.len() - line.trim_start().len();
        let sequence_item = trimmed == "-" || trimmed.starts_with("- ");
        let payload = if sequence_item {
            trimmed.strip_prefix('-').expect("sequence prefix").trim()
        } else {
            trimmed
        };
        let mapping = yaml_mapping_separator(payload);
        if indentation == 0 && mapping.is_none() {
            anyhow::bail!("workspace YAML root must be a mapping");
        }
        if indentation > 0 && !sequence_item && mapping.is_none() {
            anyhow::bail!("workspace YAML contains an unsupported scalar continuation");
        }
        let scalar = mapping
            .map(|separator| payload[separator + 1..].trim())
            .unwrap_or(payload);
        if scalar.starts_with('|') || scalar.starts_with('>') {
            anyhow::bail!("multiline YAML scalars are unsupported in workspace markers");
        }
        if scalar.starts_with('&') || scalar.starts_with('*') {
            anyhow::bail!("YAML anchors and aliases are unsupported in workspace markers");
        }
    }
    Ok(())
}

fn yaml_mapping_separator(value: &str) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if let Some(active) = quote {
            if active == '"' && character == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if character == active && !escaped {
                quote = None;
            }
            escaped = false;
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            ':' => return Some(index),
            _ => {}
        }
    }
    None
}

fn validate_yaml_flow_delimiters(value: &str) -> Result<()> {
    let mut delimiters = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if let Some(active) = quote {
            if active == '"' && character == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if character == active && !escaped {
                quote = None;
            }
            escaped = false;
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '[' | '{' => delimiters.push(character),
            ']' => {
                if delimiters.pop() != Some('[') {
                    anyhow::bail!("workspace YAML has unbalanced flow delimiters");
                }
            }
            '}' => {
                if delimiters.pop() != Some('{') {
                    anyhow::bail!("workspace YAML has unbalanced flow delimiters");
                }
            }
            _ => {}
        }
    }
    if quote.is_some() || !delimiters.is_empty() {
        anyhow::bail!("workspace YAML has an unterminated quoted or flow value");
    }
    Ok(())
}

fn strip_yaml_comment(line: &str) -> Result<&str> {
    let mut quote = None;
    let mut previous = None;
    for (index, character) in line.char_indices() {
        match (quote, character) {
            (None, '\'') | (None, '"') => quote = Some(character),
            (Some(active), current) if active == current && previous != Some('\\') => quote = None,
            (None, '#') if previous.is_none_or(char::is_whitespace) => return Ok(&line[..index]),
            _ => {}
        }
        previous = Some(character);
    }
    if quote.is_some() {
        anyhow::bail!("unterminated quoted YAML scalar");
    }
    Ok(line)
}

fn parse_yaml_inline_sequence(value: &str) -> Result<Vec<String>> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .context("packages must be a YAML list")?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let characters = inner.char_indices().collect::<Vec<_>>();
    for (offset, character) in &characters {
        match (quote, *character) {
            (None, '\'') | (None, '"') => quote = Some(*character),
            (Some(active), current) if active == current => quote = None,
            (None, ',') => {
                values.push(parse_yaml_scalar(inner[start..*offset].trim())?);
                start = *offset + character.len_utf8();
            }
            _ => {}
        }
    }
    if quote.is_some() {
        anyhow::bail!("unterminated quoted YAML scalar");
    }
    values.push(parse_yaml_scalar(inner[start..].trim())?);
    Ok(values)
}

fn parse_yaml_scalar(value: &str) -> Result<String> {
    if value.is_empty() {
        anyhow::bail!("workspace pattern must not be empty");
    }
    if let Some(value) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        return Ok(value.replace("''", "'"));
    }
    if let Some(value) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        if value.contains('\\') {
            anyhow::bail!("escaped YAML workspace patterns are unsupported");
        }
        return Ok(value.to_owned());
    }
    if value.starts_with(['\'', '"']) || value.ends_with(['\'', '"']) {
        anyhow::bail!("malformed quoted YAML scalar");
    }
    if value.starts_with(['&', '*']) {
        anyhow::bail!("YAML anchors and aliases are unsupported in workspace patterns");
    }
    Ok(value.to_owned())
}

fn validate_workspace_pattern(pattern: &str) -> Result<String> {
    let glob = pattern.strip_prefix('!').unwrap_or(pattern);
    if glob.is_empty() {
        anyhow::bail!("workspace pattern must not be empty");
    }
    if glob.contains(['?', '[', ']', '{', '}', '\\']) {
        anyhow::bail!("workspace pattern uses an unsupported glob construct: {pattern}");
    }
    if glob.as_bytes().windows(3).any(|window| window == b"***") {
        anyhow::bail!("workspace pattern uses an unsupported star run: {pattern}");
    }
    Ok(pattern.to_owned())
}

fn workspace_contains_origin(declaring: &Path, origin: &Path, patterns: &[String]) -> bool {
    let mut candidates = Vec::new();
    let mut cursor = Some(origin);
    while let Some(candidate) = cursor {
        let Ok(relative) = candidate.strip_prefix(declaring) else {
            return false;
        };
        let Some(relative) = workspace_relative_path_bytes(relative) else {
            return false;
        };
        candidates.push(relative);
        if candidate == declaring {
            break;
        }
        cursor = candidate.parent();
    }

    let mut included = None;
    for pattern in patterns {
        let (exclude, glob) = match pattern.strip_prefix('!') {
            Some(glob) => (true, glob),
            None => (false, pattern.as_str()),
        };
        if candidates
            .iter()
            .any(|candidate| workspace_glob_matches_bytes(glob.as_bytes(), candidate))
        {
            included = Some(!exclude);
        }
    }
    included.unwrap_or(false)
}

fn workspace_relative_path_bytes(relative: &Path) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let mut result = Vec::new();
        for component in relative.components() {
            if !result.is_empty() {
                result.push(b'/');
            }
            result.extend_from_slice(component.as_os_str().as_bytes());
        }
        Some(result)
    }

    #[cfg(not(unix))]
    {
        // Workspace declarations are UTF-8 documents. A non-Unicode path
        // cannot safely match a literal declaration on these platforms.
        relative
            .to_str()
            .map(|relative| relative.replace('\\', "/").into_bytes())
    }
}

#[cfg(test)]
fn workspace_glob_matches(pattern: &str, candidate: &str) -> bool {
    workspace_glob_matches_bytes(pattern.as_bytes(), candidate.as_bytes())
}

fn workspace_glob_matches_bytes(pattern: &[u8], candidate: &[u8]) -> bool {
    let mut previous = vec![false; candidate.len() + 1];
    previous[0] = true;
    let mut pattern_index = 0;
    while pattern_index < pattern.len() {
        let mut current = vec![false; candidate.len() + 1];
        if pattern[pattern_index] == b'*' {
            let double_star = pattern.get(pattern_index + 1) == Some(&b'*');
            current[0] = previous[0];
            for candidate_index in 1..=candidate.len() {
                current[candidate_index] = previous[candidate_index]
                    || ((double_star || candidate[candidate_index - 1] != b'/')
                        && current[candidate_index - 1]);
            }
            pattern_index += if double_star { 2 } else { 1 };
        } else {
            for candidate_index in 1..=candidate.len() {
                current[candidate_index] = previous[candidate_index - 1]
                    && pattern[pattern_index] == candidate[candidate_index - 1];
            }
            pattern_index += 1;
        }
        previous = current;
    }
    previous[candidate.len()]
}

#[cfg(unix)]
fn filesystem_device_id(path: &Path) -> Result<String> {
    use std::os::unix::fs::MetadataExt;

    Ok(std::fs::metadata(path)
        .with_context(|| format!("failed to authenticate ancestor {}", path.display()))?
        .dev()
        .to_string())
}

#[cfg(not(unix))]
fn filesystem_device_id(path: &Path) -> Result<String> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("failed to authenticate ancestor {}", path.display()))?;
    canonical
        .components()
        .next()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .context("canonical ancestor has no filesystem prefix")
}

#[derive(Clone, Debug)]
struct InstalledPackageIdentity {
    name: String,
    locator: String,
    integrity: String,
    root: std::path::PathBuf,
}

fn authenticated_installed_packages(
    project_root: &std::path::Path,
    principals: &[serde_json::Value],
) -> Result<Vec<InstalledPackageIdentity>> {
    use std::collections::{BTreeSet, VecDeque};

    let wanted = principals
        .iter()
        .map(|row| {
            let principal = &row["principal"];
            Ok((
                principal["name"]
                    .as_str()
                    .context("package principal is missing name")?
                    .to_owned(),
                principal["locator"]
                    .as_str()
                    .context("package principal is missing locator")?
                    .to_owned(),
                principal["integrity"]
                    .as_str()
                    .context("package principal is missing integrity")?
                    .to_owned(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut queue = VecDeque::from([project_root.join("node_modules")]);
    let mut visited_node_modules = BTreeSet::new();
    let mut candidate_roots = BTreeSet::new();
    while let Some(node_modules) = queue.pop_front() {
        let canonical_nm = match std::fs::canonicalize(&node_modules) {
            Ok(path) => path,
            Err(_) => continue,
        };
        if !visited_node_modules.insert(canonical_nm.clone()) {
            continue;
        }
        let mut entries = std::fs::read_dir(&canonical_nm)
            .with_context(|| format!("failed to enumerate {}", canonical_nm.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name();
            let path = entry.path();
            if name == ".bin" {
                continue;
            }
            if name.to_string_lossy().starts_with('@') {
                let mut scoped = match std::fs::read_dir(&path) {
                    Ok(entries) => entries.collect::<std::io::Result<Vec<_>>>()?,
                    Err(_) => continue,
                };
                scoped.sort_by_key(std::fs::DirEntry::file_name);
                for package in scoped {
                    if package.path().join("package.json").is_file() {
                        let root = std::fs::canonicalize(package.path())?;
                        queue.push_back(root.join("node_modules"));
                        candidate_roots.insert(root);
                    }
                }
                continue;
            }
            if name == ".pnpm" {
                for store_entry in std::fs::read_dir(&path)? {
                    queue.push_back(store_entry?.path().join("node_modules"));
                }
                continue;
            }
            if path.join("package.json").is_file() {
                let root = std::fs::canonicalize(path)?;
                queue.push_back(root.join("node_modules"));
                candidate_roots.insert(root);
            }
        }
    }

    let mut discovered = Vec::new();
    for root in candidate_roots {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("package.json"))?)
                .with_context(|| format!("invalid package manifest in {}", root.display()))?;
        let Some(name) = manifest.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let locator = manifest
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(|version| format!("{name}@{version}"))
            .unwrap_or_else(|| name.to_owned());
        let matches_any = wanted.iter().any(|(wanted_name, wanted_locator, _)| {
            wanted_name == name && wanted_locator == &locator
        });
        if !matches_any {
            continue;
        }
        let integrity = crate::module_loader::package_tree_integrity(&root)
            .with_context(|| format!("failed to authenticate package tree {}", root.display()))?;
        discovered.push(InstalledPackageIdentity {
            name: name.to_owned(),
            locator,
            integrity,
            root,
        });
    }

    for (name, locator, integrity) in &wanted {
        let candidates = discovered
            .iter()
            .filter(|package| &package.name == name && &package.locator == locator)
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            anyhow::bail!(
                "package principal {locator} resolved to {} installed roots; duplicate name+locator roots are ambiguous even when only one integrity matches",
                candidates.len()
            );
        }
        if &candidates[0].integrity != integrity {
            anyhow::bail!(
                "package principal {locator} has installed integrity {}, expected {integrity}",
                candidates[0].integrity
            );
        }
    }
    Ok(discovered)
}

fn runtime_object_identity_json(path: &std::path::Path) -> Result<serde_json::Value> {
    let identity = ibex_runtime::host::object_identity_for_host_path(path)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to identify {}", path.display()))?;
    serde_json::to_value(identity).context("serializing runtime object identity")
}

fn runtime_path_components_json(path: &std::path::Path) -> Result<Vec<serde_json::Value>> {
    use std::path::Component;

    path.components()
        .filter_map(|component| match component {
            Component::Prefix(prefix) => Some(runtime_path_component_json(prefix.as_os_str())),
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir => Some(Err(anyhow::anyhow!(
                "authenticated runtime path contains an unresolved parent component"
            ))),
            Component::Normal(value) => Some(runtime_path_component_json(value)),
        })
        .collect()
}

/// Build the trusted per-volume alias table before the armed digest is
/// finalized. macOS armed execution currently admits APFS only: its
/// normalization behavior is Unicode-9, while `_PC_CASE_SENSITIVE` selects
/// the case-sensitive or case-folding variant for the exact bound volume.
/// Other filesystems fail closed instead of borrowing APFS semantics.
/// @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment
fn runtime_path_canonicalizers(
    root_bindings: &[serde_json::Value],
) -> Result<Vec<capsec_semantics::path_alias::BoundVolumePathCanonicalizer>> {
    use capsec_semantics::arming::ArmedRootBinding;
    use capsec_semantics::model::{ObjectIdentity, ObjectPlatform};
    use capsec_semantics::path_alias::{
        BoundVolumePathCanonicalizer, PathAliasCanonicalizerIdentity,
    };

    let mut rows = std::collections::BTreeMap::new();
    for raw in root_bindings {
        let binding: ArmedRootBinding = serde_json::from_value(raw.clone())
            .context("cannot decode root binding while selecting path canonicalizers")?;
        let path = runtime_host_path_from_logical(&binding.host_path)?;
        let observed: ObjectIdentity = serde_json::from_value(runtime_object_identity_json(&path)?)
            .context("cannot decode observed bound-volume object identity")?;
        if observed != binding.object {
            anyhow::bail!(
                "bound-volume adapter object mismatch for {}",
                path.display()
            );
        }
        let identity = match binding.object.platform {
            ObjectPlatform::Apple => apple_volume_path_canonicalizer(&path)?,
            ObjectPlatform::Windows => PathAliasCanonicalizerIdentity::WindowsAsciiCasefoldV1,
            ObjectPlatform::Unix | ObjectPlatform::Android => {
                PathAliasCanonicalizerIdentity::ByteIdentityV1
            }
        };
        let row = BoundVolumePathCanonicalizer {
            platform: binding.object.platform,
            volume: binding.object.volume,
            identity,
        };
        let key = (row.platform, row.volume.clone());
        if rows
            .insert(key, row.clone())
            .is_some_and(|prior| prior != row)
        {
            anyhow::bail!("one bound volume reported inconsistent path canonicalizers");
        }
    }
    let mut rows = rows.into_values().collect::<Vec<_>>();
    rows.sort_by_cached_key(|row| {
        capsec_semantics::canonical::to_jcs_bytes(
            &serde_json::to_value(row).expect("canonicalizer row serializes"),
        )
        .expect("canonicalizer row is valid JCS")
    });
    Ok(rows)
}

fn runtime_host_path_from_logical(
    path: &capsec_semantics::model::LogicalPath,
) -> Result<std::path::PathBuf> {
    use capsec_semantics::model::{LogicalRoot, PathComponent};
    if path.root != LogicalRoot::Absolute || path.host_bound != Some(true) {
        anyhow::bail!("bound-volume adapter received a non-host logical path");
    }
    let mut result = std::path::PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
    for component in &path.components {
        match component {
            PathComponent::Utf8(value) => result.push(value),
            PathComponent::Base64Url(bytes) => {
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStringExt;
                    result.push(std::ffi::OsString::from_vec(bytes.clone()));
                }
                #[cfg(not(unix))]
                anyhow::bail!("non-Unicode bound path is unsupported on this target");
            }
        }
    }
    Ok(result)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
fn apple_volume_path_canonicalizer(
    path: &std::path::Path,
) -> Result<capsec_semantics::path_alias::PathAliasCanonicalizerIdentity> {
    use capsec_semantics::path_alias::PathAliasCanonicalizerIdentity;
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("bound Apple volume path contains NUL")?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut filesystem) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot inspect bound Apple volume filesystem");
    }
    let filesystem_name = unsafe { std::ffi::CStr::from_ptr(filesystem.f_fstypename.as_ptr()) }
        .to_str()
        .context("bound Apple volume filesystem name is not UTF-8")?;
    if filesystem_name != "apfs" {
        anyhow::bail!(
            "armed macOS path canonicalization supports APFS only; bound volume uses {filesystem_name}"
        );
    }
    let case_sensitive = unsafe { libc::pathconf(path.as_ptr(), libc::_PC_CASE_SENSITIVE) };
    match case_sensitive {
        0 => Ok(PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1),
        1 => Ok(PathAliasCanonicalizerIdentity::AppleApfsUnicode9NfdV1),
        _ => Err(std::io::Error::last_os_error())
            .context("cannot determine whether the bound APFS volume is case-sensitive"),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
fn apple_volume_path_canonicalizer(
    _path: &std::path::Path,
) -> Result<capsec_semantics::path_alias::PathAliasCanonicalizerIdentity> {
    anyhow::bail!("an Apple volume identity cannot be armed on this target")
}

fn runtime_authenticated_host_path(
    path: &std::path::Path,
) -> Result<capsec_semantics::model::LogicalPath> {
    serde_json::from_value(serde_json::json!({
        "root": "absolute",
        "components": runtime_path_components_json(path)?,
        "hostBound": true,
    }))
    .with_context(|| {
        format!(
            "failed to encode authenticated host path {}",
            path.display()
        )
    })
}

fn runtime_path_component_json(value: &std::ffi::OsStr) -> Result<serde_json::Value> {
    let component = if let Some(value) = value.to_str() {
        capsec_semantics::model::PathComponent::utf8(value.to_owned())
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            capsec_semantics::model::PathComponent::binary(value.as_bytes().to_vec())
        }
        #[cfg(not(unix))]
        {
            return Err(anyhow::anyhow!(
                "non-Unicode runtime path cannot be represented on this target"
            ));
        }
    }
    .map_err(anyhow::Error::msg)?;
    serde_json::to_value(component).map_err(Into::into)
}

#[derive(Debug)]
struct MaterializedProtectedArtifact {
    host_path: capsec_semantics::model::LogicalPath,
    object: serde_json::Value,
    content_digest: capsec_semantics::model::Digest,
}

/// Shared build-time SHA-256, length, and canonical bytes for the armed
/// registry record. Native and CLI startup use one embedded copy.
const CAPSEC_REGISTRY_RECORD_CONTENT_DIGEST: &str =
    ibex_runtime::host::embedder_artifacts::CAPSEC_REGISTRY_RECORD_CONTENT_DIGEST;
const CAPSEC_REGISTRY_RECORD_CONTENT_LEN: &str =
    ibex_runtime::host::embedder_artifacts::CAPSEC_REGISTRY_RECORD_CONTENT_LEN;
const CAPSEC_REGISTRY_RECORD_JCS: &[u8] =
    ibex_runtime::host::embedder_artifacts::CAPSEC_REGISTRY_RECORD_JCS;

/// Warm-start fast path for the registry protected artifact: authenticate an
/// already-pinned cache file against the build-time content digest instead of
/// re-parsing and re-canonicalizing ~17 MB of embedded registry JSON on every
/// launch (that construction dominated arming time; see
/// issues/20260724-insecure-startup-performance.md). Trust is unchanged — a
/// SHA-256 match against the digest of the exact bytes the cold path would
/// construct is equivalent to the cold path's byte comparison, and the same
/// permission/regular-file pinning checks apply. Any doubt (missing file,
/// wrong length or mode, digest mismatch) returns `None` so the cold path
/// rebuilds and byte-verifies the artifact, keeping mismatch failures loud.
fn pin_precomputed_registry_artifact(
    cache_root: &std::path::Path,
    digest_name: &str,
) -> Result<Option<MaterializedProtectedArtifact>> {
    #[cfg(not(feature = "insecure"))]
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    #[cfg(not(feature = "insecure"))]
    use base64::Engine as _;
    #[cfg(not(feature = "insecure"))]
    use sha2::{Digest as _, Sha256};
    #[cfg(not(feature = "insecure"))]
    use std::io::Read as _;

    let expected_digest = CAPSEC_REGISTRY_RECORD_CONTENT_DIGEST.trim();
    let Ok(expected_len) = CAPSEC_REGISTRY_RECORD_CONTENT_LEN.trim().parse::<u64>() else {
        return Ok(None);
    };
    let Ok(directory) = std::fs::canonicalize(cache_root.join("capsec-artifacts")) else {
        return Ok(None);
    };
    let filename_digest = digest_name
        .strip_prefix("sha256-")
        .unwrap_or(digest_name)
        .replace(|character: char| !character.is_ascii_alphanumeric(), "_");
    let path = directory.join(format!("{filename_digest}.registry.json"));
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let Ok(file) = options.open(&path) else {
        return Ok(None);
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != expected_len {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o222 != 0 {
            return Ok(None);
        }
    }
    #[cfg(not(unix))]
    if !metadata.permissions().readonly() {
        return Ok(None);
    }
    #[cfg(not(feature = "insecure"))]
    {
        let mut file = &file;
        let mut observed = Vec::with_capacity(expected_len as usize);
        file.read_to_end(&mut observed)?;
        let observed_digest = format!(
            "sha256-{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(&observed))
        );
        if observed_digest != expected_digest {
            return Ok(None);
        }
    }
    // Insecure builds make no artifact-authentication claim. The compile-time
    // profile may reuse the build-pinned artifact after cheap shape, length,
    // permission, and object capture checks; secure builds above still hash
    // every byte and fall back to reconstruction on any mismatch.
    // @ref LLP 0038#fully-open-mode-insecure
    let identity = ibex_runtime::host::object_identity_for_open_file(&file)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let object =
        serde_json::to_value(identity).context("serializing protected artifact identity")?;
    let path = std::fs::canonicalize(&path)?;
    let host_path = serde_json::from_value(serde_json::json!({
        "root": "absolute",
        "components": runtime_path_components_json(&path)?,
        "hostBound": true,
    }))?;
    let content_digest =
        capsec_semantics::model::Digest::new(expected_digest).map_err(anyhow::Error::msg)?;
    Ok(Some(MaterializedProtectedArtifact {
        host_path,
        object,
        content_digest,
    }))
}

#[cfg(test)]
mod precomputed_registry_record_tests {
    use super::*;

    /// The warm-path digest is only sound if build.rs constructs exactly the
    /// record the cold path constructs. Rebuild it here through the runtime's
    /// own code and require the digests to agree, so a field added or
    /// reordered on one side fails this test instead of silently forcing
    /// every startup down the cold path (or worse, pinning the wrong bytes).
    #[test]
    fn precomputed_registry_record_digest_matches_runtime_construction() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};

        let template: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        let record = serde_json::json!({
            "registryDigest": template["registryDigest"],
            "capabilityDefinitions": serde_json::from_str::<serde_json::Value>(
                ibex_runtime::capsec_registry_generated::CAPSEC_CAPABILITY_DEFINITIONS_JSON,
            )
            .unwrap(),
            "coverageEdges": serde_json::from_str::<serde_json::Value>(
                ibex_runtime::capsec_registry_generated::CAPSEC_COVERAGE_EDGES_JSON,
            )
            .unwrap(),
            "targetCells": serde_json::from_str::<serde_json::Value>(
                ibex_runtime::capsec_registry_generated::CAPSEC_TARGET_CELLS_JSON,
            )
            .unwrap(),
            "policyRules": serde_json::from_str::<serde_json::Value>(
                ibex_runtime::capsec_registry_generated::CAPSEC_POLICY_RULES_JSON,
            )
            .unwrap(),
        });
        let bytes = capsec_semantics::canonical::to_jcs_bytes(&record).unwrap();
        assert_eq!(
            format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes))),
            CAPSEC_REGISTRY_RECORD_CONTENT_DIGEST.trim(),
            "build.rs registry-record precompute diverged from the runtime construction"
        );
        assert_eq!(
            bytes.len().to_string(),
            CAPSEC_REGISTRY_RECORD_CONTENT_LEN.trim(),
            "build.rs registry-record length diverged from the runtime construction"
        );
        assert_eq!(
            bytes, CAPSEC_REGISTRY_RECORD_JCS,
            "build.rs registry-record bytes diverged from the runtime construction"
        );
    }
}

fn materialize_protected_artifact(
    cache_root: &std::path::Path,
    role: &str,
    digest: &str,
    bytes: &[u8],
) -> Result<MaterializedProtectedArtifact> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    use std::io::{Read as _, Seek as _, Write as _};

    fn validate_pinned_artifact(
        file: &mut std::fs::File,
        expected: &[u8],
        path: &std::path::Path,
    ) -> Result<serde_json::Value> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            anyhow::bail!(
                "protected artifact is not a regular file: {}",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o222 != 0 {
                anyhow::bail!("protected artifact is mutable: {}", path.display());
            }
        }
        #[cfg(not(unix))]
        if !metadata.permissions().readonly() {
            anyhow::bail!("protected artifact is mutable: {}", path.display());
        }
        file.rewind()?;
        let mut observed = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut observed)?;
        if observed != expected {
            anyhow::bail!("protected artifact content mismatch at {}", path.display());
        }
        let identity = ibex_runtime::host::object_identity_for_open_file(file)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        serde_json::to_value(identity).context("serializing protected artifact identity")
    }

    let directory = cache_root.join("capsec-artifacts");
    std::fs::create_dir_all(&directory)?;
    let directory_metadata = std::fs::symlink_metadata(&directory)?;
    if !directory_metadata.is_dir() || directory_metadata.file_type().is_symlink() {
        anyhow::bail!(
            "protected artifact parent is not a stable directory: {}",
            directory.display()
        );
    }
    let directory = std::fs::canonicalize(directory)?;
    let filename_digest = digest
        .strip_prefix("sha256-")
        .unwrap_or(digest)
        .replace(|character: char| !character.is_ascii_alphanumeric(), "_");
    let path = directory.join(format!("{filename_digest}.{role}.json"));

    let open_existing = || -> Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        options
            .open(&path)
            .with_context(|| format!("failed to pin protected artifact {}", path.display()))
    };

    let object = if path.exists() {
        let mut file = open_existing()?;
        validate_pinned_artifact(&mut file, bytes, &path)?
    } else {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .context("failed to name protected artifact staging file")?;
        let temporary = directory.join(format!(
            ".{filename_digest}.{role}.{}.tmp",
            URL_SAFE_NO_PAD.encode(nonce)
        ));
        let mut staged = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let publish_result = (|| -> Result<serde_json::Value> {
            staged.write_all(bytes)?;
            staged.sync_all()?;
            let mut permissions = staged.metadata()?.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                permissions.set_mode(0o400);
            }
            #[cfg(not(unix))]
            permissions.set_readonly(true);
            staged.set_permissions(permissions)?;
            staged.sync_all()?;
            let identity = validate_pinned_artifact(&mut staged, bytes, &temporary)?;

            match std::fs::hard_link(&temporary, &path) {
                Ok(()) => {
                    std::fs::File::open(&directory)?.sync_all()?;
                    Ok(identity)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let mut existing = open_existing()?;
                    validate_pinned_artifact(&mut existing, bytes, &path)
                }
                Err(error) => Err(error.into()),
            }
        })();
        let _ = std::fs::remove_file(&temporary);
        publish_result?
    };
    let path = std::fs::canonicalize(&path)?;
    let host_path = serde_json::from_value(serde_json::json!({
        "root": "absolute",
        "components": runtime_path_components_json(&path)?,
        "hostBound": true,
    }))?;
    let content_digest = capsec_semantics::model::Digest::new(format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)?;
    Ok(MaterializedProtectedArtifact {
        host_path,
        object,
        content_digest,
    })
}

/// Runtime-registry diagnostics are not a production entry surface. Reject
/// them before arming artifacts, Hermes allocation, or project code can be
/// observed. Eval, program-stdin, and REPL routes are admitted here only
/// because their product dispatch is required to cross the fixed,
/// authenticated ingress defined by the session specifications.
/// @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
pub(crate) fn reject_closed_diagnostic_cli(cli: &Cli) -> Result<()> {
    if matches!(
        cli.command.as_ref(),
        Some(crate::cli::Commands::Debug { .. })
    ) {
        anyhow::bail!("production capability enforcement closes debug commands");
    }
    Ok(())
}

fn validate_runtime_inputs(cli: &Cli, reject_closed_environment: bool) -> Result<()> {
    reject_closed_diagnostic_cli(cli)?;
    if crate::runtime_env("IBEX_POLICY", "EXACT_POLICY").is_some() {
        anyhow::bail!("environment-selected policy paths are forbidden in production");
    }
    if reject_closed_environment {
        crate::host::reject_closed_startup_environment()?;
    }
    if cli.allow_all
        || matches!(
            cli.capsec,
            crate::cli::CapSecMode::Audit | crate::cli::CapSecMode::Permissive
        )
        || !cli.allow.is_empty()
        || !cli.deny.is_empty()
        || cli.allow_env_endowments
        || cli.capsec_allow_advisory
        || crate::env_flag_enabled("IBEX_CAPSEC_ALLOW_ADVISORY")
    {
        anyhow::bail!(
            "production capability enforcement rejects legacy allow/deny, environment endowment widening, and advisory-attribution overrides"
        );
    }
    let run_inspector = matches!(
        cli.command.as_ref(),
        Some(crate::cli::Commands::Run { inspect: true, .. })
            | Some(crate::cli::Commands::Run {
                inspect_wait: true,
                ..
            })
            | Some(crate::cli::Commands::Run {
                inspect_open: true,
                ..
            })
            | Some(crate::cli::Commands::Run {
                inspect_pause: true,
                ..
            })
            | Some(crate::cli::Commands::Run {
                inspect_port: Some(_),
                ..
            })
            | Some(crate::cli::Commands::Run {
                inspect_host: Some(_),
                ..
            })
    );
    let external_arming_artifact_supplied =
        cli.capsec_armed_snapshot.is_some() || cli.capsec_arming_identity.is_some();
    if (cli.compat.is_some() && external_arming_artifact_supplied)
        || cli.inspect
        || cli.inspect_wait
        || cli.inspect_open
        || cli.inspect_pause
        || cli.inspect_port.is_some()
        || cli.inspect_host.is_some()
        || cli.expose_internals
        || cli.stack_size.is_some()
        || cli.max_http_header_size.is_some()
        || run_inspector
    {
        anyhow::bail!(
            "production capability enforcement closes compatibility, inspector, and runtime-fidelity overrides"
        );
    }
    Ok(())
}

pub(crate) fn validate_production_inputs(cli: &Cli) -> Result<()> {
    validate_runtime_inputs(cli, true)
}

/// The separately named foreground audit is the diagnostic channel for
/// exercising legacy startup branches. It retains every CLI/policy restriction
/// above, but does not apply the production registry's ambient-control closure.
/// @ref LLP 0021#default-execution-contract
fn validate_diagnostic_audit_inputs(cli: &Cli) -> Result<()> {
    validate_runtime_inputs(cli, false)
}

/// Apply the enforce/audit isolation prerequisite (per-package chunking) for the
/// `ibex build` path, mirroring what `build_host_config` does for a run. Without
/// this, a build under an enforce policy compiles a flat single-Domain bundle and
/// the resulting `.hbc`, run under `--capsec enforce`, attributes every
/// `node_modules` frame to the trusted root — the capability gate never fires for
/// a dependency. Returns the resolved mode (Enforce/Audit imply chunking).
/// @ref LLP 0013#mechanism-3 — (ENG-22760)
pub(crate) fn apply_build_isolation(cli: &Cli) -> Result<crate::host::SecurityMode> {
    validate_production_inputs(cli)?;
    if cli.capsec == crate::cli::CapSecMode::Audit {
        anyhow::bail!("foreground audit cannot be persisted as a production build posture");
    }
    let mode = crate::host::SecurityMode::Enforce;
    for line in check_capsec_readiness(mode, CapsecStage::Build, capsec_readiness(cli), false)? {
        eprintln!("{line}");
    }
    Ok(mode)
}

/// Snapshot of the attribution prerequisites behind the capsec model at the
/// moment a run/build resolves its security mode (ENG-22884). Selecting
/// `enforce`/`audit` only changes host-boundary *decision* logic; whether those
/// decisions bind to real per-package principals depends on these
/// prerequisites, and nothing previously reported when they were missing.
/// @ref LLP 0013#mechanism-3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapsecReadiness {
    /// Frame-derived attribution is compiled in: the linked Hermes exports
    /// `ex_hermes_vm_current_package_id`, so build.rs defined
    /// `EXACT_HAVE_FRAME_ATTRIBUTION` (cfg `exact_frame_attribution`). When
    /// false the engine falls back to native-callback / thread-local module-id
    /// attribution, which stored callbacks and patched prototypes can defeat.
    frame_attribution: bool,
    /// Per-package principal isolation state after
    /// `enable_isolation_prerequisites` has applied the enforce/audit default.
    package_isolation: PackageIsolation,
    /// Reachability hardening (Mechanism 1 lockdown / Mechanism 2 compartment
    /// withholding) requested for this process.
    lockdown: bool,
    /// The policy artifact declares a runtime-grant ceiling for dynamic
    /// permission prompts.
    dynamic_ceiling: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageIsolation {
    /// Per-package chunking is on (the enforce/audit default): each bundled
    /// npm package gets its own chunk → Domain → principal.
    Enabled,
    /// The operator explicitly set `IBEX_PER_PACKAGE_CHUNKS=0`: bundled
    /// dependencies collapse into the trusted root principal, so the
    /// capability gate never fires for them. Only the unbundled loader path
    /// still attributes per package.
    DisabledByOperator,
}

/// Which pipeline stage is consulting readiness. A missing frame-attribution
/// bridge is a property of the *executing* engine, and a built `.hbc` may run
/// under a different (patched) engine — so it hard-fails only `Run` and warns
/// on `Build`. An explicitly disabled package layout is baked into the built
/// artifact, so it is a hard prerequisite at both stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapsecStage {
    Run,
    Build,
}

/// Gather the live readiness snapshot. Call after
/// `enable_isolation_prerequisites` so `IBEX_PER_PACKAGE_CHUNKS` reflects the
/// enforce/audit default; a remaining `0` is an explicit operator opt-out.
fn capsec_readiness(_cli: &Cli) -> CapsecReadiness {
    let package_isolation = PackageIsolation::Enabled;
    CapsecReadiness {
        frame_attribution: cfg!(exact_frame_attribution),
        package_isolation,
        lockdown: true,
        // Foreground audit is policyless; production dynamic authority comes
        // from the immutable typed snapshot rather than this compatibility
        // readiness diagnostic.
        dynamic_ceiling: false,
    }
}

/// ENG-22884 — decide whether the resolved capsec mode may proceed with the
/// observed readiness, and produce the stderr report lines. Enforce fails
/// closed when a hard attribution prerequisite is missing unless the operator
/// passed the advisory escape hatch; audit always proceeds but reports
/// conspicuously; permissive stays silent (capsec is not being claimed).
fn check_capsec_readiness(
    mode: crate::host::SecurityMode,
    stage: CapsecStage,
    readiness: CapsecReadiness,
    _allow_advisory: bool,
) -> Result<Vec<String>> {
    use crate::host::SecurityMode;
    if mode == SecurityMode::Permissive {
        return Ok(Vec::new());
    }

    let report = format!(
        "capsec readiness: frame-attribution={} package-isolation={} lockdown={} dynamic-ceiling={}",
        if readiness.frame_attribution {
            "present"
        } else {
            "missing"
        },
        match readiness.package_isolation {
            PackageIsolation::Enabled => "per-package",
            PackageIsolation::DisabledByOperator => "disabled(IBEX_PER_PACKAGE_CHUNKS=0)",
        },
        if readiness.lockdown { "on" } else { "off" },
        if readiness.dynamic_ceiling {
            "configured"
        } else {
            "not-configured"
        },
    );

    // Hard prerequisites: enforce refuses to proceed without them (absent the
    // advisory escape hatch). Soft: always warn, never fail.
    let mut hard: Vec<String> = Vec::new();
    let mut soft: Vec<String> = Vec::new();
    if !readiness.frame_attribution {
        let detail = "frame-derived attribution (the linked Hermes engine lacks the \
                      ex_hermes_vm_current_package_id bridge, so attribution falls back to a \
                      forgeable thread-local module id)";
        match stage {
            CapsecStage::Run => hard.push(detail.to_string()),
            CapsecStage::Build => soft.push(format!(
                "this engine build lacks {detail}; running the built artifact under this \
                 engine's enforce mode will fail closed"
            )),
        }
    }
    if readiness.package_isolation == PackageIsolation::DisabledByOperator {
        hard.push(
            "per-package principal isolation (IBEX_PER_PACKAGE_CHUNKS=0: bundled dependencies \
             collapse into the trusted root principal)"
                .to_string(),
        );
    }
    if !readiness.lockdown {
        hard.push(
            "structural runtime lockdown (shared intrinsics would remain mutable)".to_string(),
        );
    }

    if hard.is_empty() && soft.is_empty() {
        return Ok(vec![report]);
    }

    if mode == SecurityMode::Enforce && !hard.is_empty() {
        anyhow::bail!(
            "capsec enforce requires attribution prerequisites this {} does not satisfy:\n  - {}\n{}\n\
             Refusing to present advisory attribution as enforcement; use the separately named \
             foreground capsec audit workflow for diagnostics.",
            match stage {
                CapsecStage::Run => "run",
                CapsecStage::Build => "build",
            },
            hard.join("\n  - "),
            report,
        );
    }

    let mode_label = if mode == SecurityMode::Enforce {
        "enforce"
    } else {
        "audit"
    };
    let mut lines = Vec::new();
    if !hard.is_empty() {
        lines.push(format!(
            "warning: capsec {mode_label} is proceeding with ADVISORY attribution — capability \
             decisions may attribute a dependency's access to the trusted root:"
        ));
        for item in &hard {
            lines.push(format!("warning:   missing prerequisite: {item}"));
        }
    }
    for item in soft {
        lines.push(format!("warning: {item}"));
    }
    lines.push(report);
    Ok(lines)
}

/// Enable the per-package **attribution** prerequisite that enforce/audit mode
/// implies (ENG-22681). Selecting enforce (via `--capsec enforce` or a policy
/// artifact's `mode: "enforce"`) only changes the host-boundary *decision*
/// logic; on its own it does not give a bundled dependency its own runtime
/// principal. A default flat bundle collapses to one Hermes Domain, so every
/// `node_modules` frame carries the trusted root principal and the capability
/// gate — which only bites non-root principals — never fires for a dependency.
/// That makes a generated enforce policy a footgun: it looks like enforcement
/// while a dependency's `fs`/`env`/network access is attributed to root.
///
/// So under enforce **and** audit we turn on per-package chunking (each npm
/// package becomes its own chunk → its own Domain → its own principal). An
/// explicit `IBEX_PER_PACKAGE_CHUNKS=0` is treated as advisory attribution by
/// `check_capsec_readiness`: audit warns, and enforce fails closed unless the
/// operator also passes `--capsec-allow-advisory`. This is the attribution
/// prerequisite the RFC's Mechanism 3 needs for a bundled app; the unbundled
/// loader path already attributes per package, and a bundler that is unavailable
/// degrades to that path, so this never hard-fails a run on its own. Set as an
/// env var (before engine boot and before bundling) so it reaches the bundler,
/// the bundle-cache key, and any spawned children uniformly.
///
/// Reachability hardening (Mechanism 1 lockdown + Mechanism 2 compartment
/// withholding) stays **opt-in** via `--lockdown`: freezing intrinsics is the
/// RFC's documented top compat risk (Risks §1) and is orthogonal to the
/// attribution footgun this closes — an ungranted package's dangerous op is
/// already denied at the host boundary once it is attributed to its own
/// principal. @ref LLP 0013#mechanism-3
pub async fn prepare_entry_with_format(
    entry: &str,
    bundle_format: BundleFormat,
) -> Result<PathBuf> {
    prepare_entry_with_format_and_bytecode(entry, bundle_format, true).await
}

async fn prepare_entry_with_format_and_bytecode(
    entry: &str,
    bundle_format: BundleFormat,
    allow_bytecode: bool,
) -> Result<PathBuf> {
    let cache_dir = runtime_cache_dir()?;
    prepare_entry_with_format_and_bytecode_in_cache(
        entry,
        bundle_format,
        allow_bytecode,
        &cache_dir,
    )
    .await
}

/// Prepare source for `ibex build` inside the already authenticated cache.
/// Feeding the build an entry-cache HBC would ask hermesc to compile bytecode
/// as JavaScript and lose the directory containing per-package chunks.
pub(crate) async fn prepare_entry_for_bytecode_build_in_cache(
    entry: &str,
    bundle_format: BundleFormat,
    runtime_cache_root: &Path,
) -> Result<PathBuf> {
    prepare_entry_with_format_and_bytecode_in_cache(entry, bundle_format, false, runtime_cache_root)
        .await
}

async fn prepare_entry_with_format_and_bytecode_in_cache(
    entry: &str,
    bundle_format: BundleFormat,
    allow_bytecode: bool,
    runtime_cache_root: &Path,
) -> Result<PathBuf> {
    let path = PathBuf::from(entry);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let path = normalize_windows_tool_path(path);
    if !path.exists() {
        anyhow::bail!("Entry file not found: {}", path.display());
    }
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

    if ext.eq_ignore_ascii_case("hbc") {
        return Ok(path);
    }

    let is_compat_js_fixture = compat_loader_fixture_mode() && matches!(ext, "js" | "cjs" | "mjs");
    if is_compat_js_fixture {
        // Compatibility fixtures depend on the raw loader behavior and can
        // break when the entry file is pre-bundled before execution.
        return Ok(path);
    }

    let needs_bundle = matches!(
        ext,
        "ts" | "tsx" | "jsx" | "js" | "mjs" | "cjs" | "mts" | "cts"
    );
    if !needs_bundle {
        return Ok(path);
    }

    let bundles_root = ensure_real_internal_cache_subdirectory(runtime_cache_root, "bundles")?;
    let cache_key = bundle_cache_key(&path, bundle_format)?;
    let artifact_root = bundle_artifact_root(&bundles_root, &cache_key);

    if let Some(output) = find_fresh_bundle(&artifact_root, &path, bundle_format).await {
        // Bundle is cached. Try bytecode if not already known incompatible.
        if allow_bytecode
            && !BYTECODE_INCOMPATIBLE.load(Ordering::Relaxed)
            && crate::runtime_env("IBEX_NO_BYTECODE", "EX_NO_BYTECODE").is_none()
        {
            if let Ok(bytecode_path) = prepare_bytecode_entry(&output).await {
                return Ok(bytecode_path);
            }
        }
        return Ok(output);
    }

    // If the source uses top-level await and we're targeting CJS, use ESM instead.
    // Rolldown rejects TLA in CJS mode, but ESM handles it fine. The TLA shim in
    // run_file_with_args will wrap the ESM output in an async IIFE for Hermes.
    let effective_format = if bundle_format == BundleFormat::Cjs {
        let source = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        if contains_top_level_await(&source) {
            BundleFormat::Esm
        } else {
            bundle_format
        }
    } else {
        bundle_format
    };

    // If format changed, recompute output path
    let artifact_root = if effective_format != bundle_format {
        let new_key = bundle_cache_key(&path, effective_format)?;
        bundle_artifact_root(&bundles_root, &new_key)
    } else {
        artifact_root
    };

    if let Some(output) = find_fresh_bundle(&artifact_root, &path, effective_format).await {
        return if allow_bytecode
            && !BYTECODE_INCOMPATIBLE.load(Ordering::Relaxed)
            && crate::runtime_env("IBEX_NO_BYTECODE", "EX_NO_BYTECODE").is_none()
        {
            prepare_bytecode_entry(&output).await.or(Ok(output))
        } else {
            Ok(output)
        };
    }

    let prepared = match run_bundler(&path, &artifact_root, effective_format).await {
        Ok(output) => output,
        Err(err) => {
            let err_msg = format!("{}", err);
            // If rolldown rejects TLA in CJS mode (e.g. await inside for/if/while
            // blocks that our heuristic missed), retry with ESM format.
            if effective_format == BundleFormat::Cjs && err_msg.contains("Top-level await") {
                let esm_key = bundle_cache_key(&path, BundleFormat::Esm)?;
                let esm_root = bundle_artifact_root(&bundles_root, &esm_key);
                match run_bundler(&path, &esm_root, BundleFormat::Esm).await {
                    Ok(output) => output,
                    Err(esm_err) => return Err(esm_err),
                }
            } else if needs_bundle {
                let mut context = serde_json::Map::new();
                context.insert(
                    "entry".to_string(),
                    serde_json::Value::String(path.display().to_string()),
                );
                context.insert(
                    "format".to_string(),
                    serde_json::Value::String(effective_format.as_str().to_string()),
                );
                context.insert(
                    "error".to_string(),
                    serde_json::Value::String(err.to_string()),
                );
                // Bundling is an optimization, never a requirement: a missing
                // bun/node runner is the normal standalone case. The
                // in-process loader pipeline takes over silently; real
                // bundler failures still warn.
                let missing_runner = err_msg.contains("required to run the bundler");
                agent_logs::record_bundler_log(
                    if missing_runner { "info" } else { "warn" },
                    format!(
                        "Bundler unavailable; using the in-process module pipeline. {}",
                        err
                    ),
                    Some(context),
                );
                if !missing_runner {
                    eprintln!(
                        "Warning: bundler failed ({}). Using the in-process module pipeline.",
                        err
                    );
                }
                path.clone()
            } else {
                return Err(err);
            }
        }
    };

    // A raw `.cjs` entry needs the compatibility loader's CommonJS wrapper;
    // compiling those bytes directly to HBC and executing them as a script
    // loses `module`, `exports`, `require`, and CommonJS top-level `this`.
    // Prepared bundle output is self-contained and remains bytecode-eligible.
    // @ref LLP 0028#4-reachability-inventory-and-retirement-matrix
    if prepared == path && ext.eq_ignore_ascii_case("cjs") {
        return Ok(prepared);
    }

    // Try to compile to bytecode for faster startup on subsequent runs.
    // Skip if we've already detected that hermesc produces incompatible bytecode,
    // or if bytecode is explicitly disabled.
    if !allow_bytecode
        || BYTECODE_INCOMPATIBLE.load(Ordering::Relaxed)
        || crate::runtime_env("IBEX_NO_BYTECODE", "EX_NO_BYTECODE").is_some()
    {
        return Ok(prepared);
    }
    match prepare_bytecode_entry(&prepared).await {
        Ok(bytecode_path) => Ok(bytecode_path),
        Err(_err) => {
            // hermesc not available or compilation failed — run JS source directly
            Ok(prepared)
        }
    }
}

fn deps_manifest_path(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_os_string();
    path.push(".deps.json");
    PathBuf::from(path)
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleDigestRecord {
    path: String,
    sha256: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BundleResolutionInput {
    kind: String,
    path: String,
    sha256: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleSourceIdentity {
    defining_principal: capsec_semantics::model::Principal,
    logical_root: capsec_semantics::model::LogicalRoot,
    lexical_components: Vec<String>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleOriginalModuleProvenance {
    source_id: String,
    source_label: String,
    virtual_path: String,
    binding_virtual_prefix: String,
    source_identity: BundleSourceIdentity,
    source_sha256: String,
    dep_index: usize,
    chunks: Vec<String>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleSourceProvenance {
    schema: String,
    armed_snapshot_digest: String,
    package_graph_digest: String,
    authority_digest: String,
    modules: Vec<BundleOriginalModuleProvenance>,
    digest: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleSourceProvenanceAuthorityBinding {
    logical_root: capsec_semantics::model::LogicalRoot,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<capsec_semantics::model::Principal>,
    backing_root: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleSourceProvenanceAuthority {
    schema: &'static str,
    armed_snapshot_digest: String,
    package_graph_digest: String,
    root_identity: capsec_semantics::model::Principal,
    bindings: Vec<BundleSourceProvenanceAuthorityBinding>,
}

impl BundleSourceProvenanceAuthority {
    /// Project the already-validated armed graph into the bundler's one-shot
    /// native input. Backing roots are used only by the child process to map
    /// captured source objects; the emitted source-provenance projection
    /// contains virtual paths and SourceIds only.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    fn from_snapshot(snapshot: &capsec_semantics::arming::ArmedSnapshot) -> Result<Self> {
        use capsec_semantics::model::{Digest, LogicalRoot, Principal};

        let root_identity: Principal =
            serde_json::from_value(snapshot.document()["rootIdentity"].clone())
                .context("armed snapshot root identity is malformed")?;
        anyhow::ensure!(
            root_identity.is_root(),
            "armed snapshot root identity is not root"
        );
        let package_graph_digest = snapshot.document()["packageGraph"]["digest"]
            .as_str()
            .context("armed snapshot package graph has no digest")?;
        Digest::new(package_graph_digest.to_owned()).map_err(anyhow::Error::msg)?;

        let mut bindings = Vec::new();
        for binding in snapshot.root_bindings()? {
            if !matches!(
                binding.logical_root,
                LogicalRoot::Project | LogicalRoot::Package
            ) {
                continue;
            }
            let backing_root =
                std::fs::canonicalize(runtime_host_path_from_logical(&binding.host_path)?)?;
            let backing_root = backing_root
                .to_str()
                .context("source provenance does not support non-UTF-8 binding roots")?
                .to_owned();
            match binding.logical_root {
                LogicalRoot::Project => anyhow::ensure!(
                    binding.owner.is_none() && binding.logical_path.is_none(),
                    "source provenance project binding is not root-owned"
                ),
                LogicalRoot::Package => anyhow::ensure!(
                    binding.owner.as_ref().is_some_and(Principal::is_package)
                        && binding.logical_path.is_none(),
                    "source provenance package binding has no package owner"
                ),
                _ => unreachable!(),
            }
            bindings.push(BundleSourceProvenanceAuthorityBinding {
                logical_root: binding.logical_root,
                owner: binding.owner.clone(),
                backing_root,
            });
        }
        anyhow::ensure!(
            !bindings.is_empty(),
            "armed snapshot has no source bindings"
        );
        bindings.sort_by(|left, right| {
            left.backing_root
                .as_bytes()
                .cmp(right.backing_root.as_bytes())
        });
        Ok(Self {
            schema: "ibex/source-provenance-authority/1",
            armed_snapshot_digest: snapshot.digest().as_str().to_owned(),
            package_graph_digest: package_graph_digest.to_owned(),
            root_identity,
            bindings,
        })
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(self)?).map_err(Into::into)
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleCacheManifest {
    version: u32,
    entry: String,
    resolution_digest: String,
    graph_digest: String,
    deps: Vec<BundleDigestRecord>,
    outputs: Vec<BundleDigestRecord>,
    resolution_inputs: Vec<BundleResolutionInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_provenance: Option<BundleSourceProvenance>,
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

async fn sha256_file(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("Failed to hash {}", path.display()))?;
    Ok(sha256_bytes(&bytes))
}

async fn read_bundle_manifest(output: &Path) -> Result<BundleCacheManifest> {
    let output = output.to_path_buf();
    tokio::task::spawn_blocking(move || read_bundle_manifest_once(&output))
        .await
        .context("bundle cache manifest reader stopped")?
}

fn read_bundle_manifest_once(output: &Path) -> Result<BundleCacheManifest> {
    let raw = read_regular_file_once(
        &deps_manifest_path(output),
        MAX_AUTHENTICATED_GENERATED_MANIFEST_BYTES,
        "bundle cache manifest",
    )?;
    serde_json::from_slice(&raw).context("parse bundle cache manifest")
}

const MAX_AUTHENTICATED_GENERATED_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_AUTHENTICATED_GENERATED_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;

/// Open one compiler product without following a final symlink and retain its
/// bytes from that descriptor. The caller hashes this returned vector; it must
/// never authenticate a pathname and then reopen that pathname for execution.
fn read_regular_file_once(path: &Path, maximum_bytes: u64, role: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;

    #[cfg(not(unix))]
    {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect {role} {}", path.display()))?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "{role} is not a non-symlink regular file: {}",
            path.display()
        );
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_NONBLOCK prevents a hostile FIFO at the final component from
        // wedging admission before the descriptor metadata check rejects it.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {role} {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("failed to inspect opened {role} {}", path.display()))?;
    anyhow::ensure!(
        before.is_file() && before.len() <= maximum_bytes,
        "{role} is not a bounded regular file: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        anyhow::ensure!(
            before.nlink() == 1 && before.uid() == unsafe { libc::geteuid() },
            "{role} is not an exclusively owned compiler product: {}",
            path.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        anyhow::ensure!(
            before.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                == 0,
            "{role} is a reparse point: {}",
            path.display()
        );
    }
    let capacity = usize::try_from(before.len()).context("compiler product is too large")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to retain {role} {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("failed to re-inspect opened {role} {}", path.display()))?;
    anyhow::ensure!(
        after.is_file()
            && after.len() == before.len()
            && after.len() == u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        "{role} changed while it was retained: {}",
        path.display()
    );
    Ok(bytes)
}

struct CapturedSingleOriginalBundle {
    manifest: BundleCacheManifest,
    source: Vec<u8>,
}

/// Capture the deliberately narrow generated form from one fresh compiler
/// invocation. The manifest is parsed once, every admitted output is read once
/// through a no-follow regular-file descriptor, and all digest comparisons are
/// made over those exact owned bytes.
fn capture_fresh_single_original_bundle(
    output: &Path,
    source_entry: &Path,
    expected_source_sha: &str,
    authority: &BundleSourceProvenanceAuthority,
) -> Result<Option<CapturedSingleOriginalBundle>> {
    // Keep each fail-closed reason adjacent to its predicate for review while
    // exposing only the raw-source fallback to callers.
    macro_rules! reject_capture {
        ($reason:literal) => {{
            let _ = $reason;
            return Ok(None);
        }};
    }
    let manifest_bytes = read_regular_file_once(
        &deps_manifest_path(output),
        MAX_AUTHENTICATED_GENERATED_MANIFEST_BYTES,
        "authenticated generated manifest",
    )?;
    let manifest: BundleCacheManifest = serde_json::from_slice(&manifest_bytes)
        .context("parse authenticated generated manifest")?;
    let Ok(canonical_source_entry) = std::fs::canonicalize(source_entry) else {
        reject_capture!("source entry disappeared");
    };

    if manifest.version != 4
        || !valid_sha256(&manifest.graph_digest)
        || !valid_sha256(&manifest.resolution_digest)
        || !validate_bundle_source_provenance(&manifest, Some(authority))
        || manifest.deps.len() != 1
        || manifest.deps[0].path != canonical_source_entry.to_string_lossy()
        || manifest.deps[0].sha256 != expected_source_sha
    {
        reject_capture!("manifest/source authority fields");
    }
    let Ok(canonical_manifest_entry) = std::fs::canonicalize(&manifest.entry) else {
        reject_capture!("manifest entry disappeared");
    };
    if canonical_source_entry != canonical_manifest_entry || manifest.resolution_inputs.is_empty() {
        reject_capture!("entry or resolution-input shape");
    }

    let mut previous_resolution: Option<(&str, &str)> = None;
    for input in &manifest.resolution_inputs {
        if !Path::new(&input.path).is_absolute() || !valid_sha256(&input.sha256) {
            reject_capture!("resolution-input path or digest shape");
        }
        let ordering_key = (input.path.as_str(), input.kind.as_str());
        if previous_resolution.is_some_and(|previous| previous >= ordering_key)
            || bundle_resolution_input_digest(input).as_deref() != Some(input.sha256.as_str())
        {
            reject_capture!("resolution-input ordering or current digest");
        }
        previous_resolution = Some(ordering_key);
    }
    let encoded_resolution = serde_json::to_vec(&manifest.resolution_inputs)?;
    if sha256_bytes(&encoded_resolution) != manifest.resolution_digest {
        reject_capture!("resolution-input projection digest");
    }

    let Some(original) = admitted_single_original_bundle(&manifest, output) else {
        reject_capture!("single-original shape");
    };
    if original.source_sha256 != expected_source_sha {
        reject_capture!("original source digest");
    }
    let Some(artifact_dir) = output.parent() else {
        reject_capture!("artifact directory");
    };
    let Some(entry_output) = output
        .strip_prefix(artifact_dir)
        .ok()
        .and_then(normalized_relative_artifact_path)
    else {
        reject_capture!("entry output path");
    };

    let mut previous_output: Option<&str> = None;
    let mut source = None;
    let mut expected_files = Vec::with_capacity(manifest.outputs.len());
    for artifact in &manifest.outputs {
        let relative = Path::new(&artifact.path);
        if normalized_relative_artifact_path(relative).as_deref() != Some(artifact.path.as_str())
            || !valid_sha256(&artifact.sha256)
            || previous_output.is_some_and(|previous| previous >= artifact.path.as_str())
        {
            reject_capture!("output record path/digest/order");
        }
        let bytes = read_regular_file_once(
            &artifact_dir.join(relative),
            MAX_AUTHENTICATED_GENERATED_OUTPUT_BYTES,
            "authenticated generated output",
        )?;
        if sha256_bytes(&bytes) != artifact.sha256 {
            reject_capture!("owned output digest");
        }
        if artifact.path == entry_output {
            source = Some(bytes);
        }
        expected_files.push(artifact.path.clone());
        previous_output = Some(&artifact.path);
    }
    let Some(source) = source else {
        reject_capture!("entry absent from outputs");
    };
    let mut actual_files = Vec::new();
    if !collect_bundle_output_files(artifact_dir, artifact_dir, &mut actual_files) {
        reject_capture!("output directory shape");
    }
    actual_files.sort();
    if actual_files != expected_files {
        reject_capture!("output file inventory");
    }

    Ok(Some(CapturedSingleOriginalBundle { manifest, source }))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn bundle_resolution_input_digest(input: &BundleResolutionInput) -> Option<String> {
    let path = Path::new(&input.path);
    match input.kind.as_str() {
        "file" => std::fs::read(path).ok().map(|bytes| sha256_bytes(&bytes)),
        "symlink" => std::fs::read_link(path)
            .ok()
            .and_then(|target| target.to_str().map(|value| sha256_bytes(value.as_bytes()))),
        "missing" => match std::fs::symlink_metadata(path) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                Some(sha256_bytes(b"missing"))
            }
            _ => None,
        },
        "directory" => {
            let mut entries = std::fs::read_dir(path)
                .ok()?
                .collect::<std::io::Result<Vec<_>>>()
                .ok()?;
            entries.sort_by(|left, right| {
                left.file_name()
                    .to_str()
                    .unwrap_or("")
                    .as_bytes()
                    .cmp(right.file_name().to_str().unwrap_or("").as_bytes())
            });
            let mut encoded = Vec::new();
            for entry in entries {
                let name = entry.file_name();
                let name = name.to_str()?;
                let metadata = std::fs::symlink_metadata(entry.path()).ok()?;
                let kind = if metadata.file_type().is_symlink() {
                    b'l'
                } else if metadata.is_dir() {
                    b'd'
                } else if metadata.is_file() {
                    b'f'
                } else {
                    b'o'
                };
                encoded.push(kind);
                encoded.push(0);
                encoded.extend_from_slice(name.as_bytes());
                encoded.push(0);
                if metadata.file_type().is_symlink() {
                    let target = std::fs::read_link(entry.path()).ok()?;
                    encoded.extend_from_slice(target.to_str()?.as_bytes());
                }
                encoded.push(b'\n');
            }
            Some(sha256_bytes(&encoded))
        }
        _ => None,
    }
}

fn normalized_relative_artifact_path(path: &Path) -> Option<String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return None;
    }
    Some(
        path.components()
            .filter_map(|component| match component {
                std::path::Component::Normal(part) => Some(part.to_string_lossy()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn collect_bundle_output_files(root: &Path, current: &Path, files: &mut Vec<String>) -> bool {
    let Ok(entries) = std::fs::read_dir(current) else {
        return false;
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            return false;
        };
        let Ok(relative) = path.strip_prefix(root) else {
            return false;
        };
        let Some(relative_string) = normalized_relative_artifact_path(relative) else {
            return false;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if metadata.file_type().is_symlink() {
            // Published generated code is immutable regular-file content; a
            // symlink could retarget after digest verification.
            return false;
        }
        if metadata.is_dir() {
            // Derived bytecode/control directories are not bundler outputs.
            if name.starts_with('.') {
                continue;
            }
            if !collect_bundle_output_files(root, &path, files) {
                return false;
            }
        } else if metadata.is_file() {
            if name == ".last-used"
                || name == ".lease"
                || relative_string.ends_with(".deps.json")
                || relative_string.ends_with(".hbc")
                || relative_string.ends_with(".hbc.meta.json")
            {
                continue;
            }
            files.push(relative_string);
        } else {
            return false;
        }
    }
    true
}

fn source_label_for_bundle_virtual_path(virtual_path: &str) -> Option<String> {
    if virtual_path == "/project"
        || !virtual_path.starts_with("/project/")
        || virtual_path.contains('\0')
        || virtual_path
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return None;
    }
    let mut label = String::from("file://");
    for byte in virtual_path.bytes() {
        if byte == b'/' || byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
        {
            label.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut label, "%{byte:02X}").ok()?;
        }
    }
    Some(label)
}

fn bundle_source_id(identity: &BundleSourceIdentity) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let payload = serde_json::json!({
        "kind": "file",
        "definingPrincipal": identity.defining_principal,
        "logicalRoot": identity.logical_root,
        "lexicalComponents": identity.lexical_components,
        "sourceIdSchema": "ibex.source-id.v1",
    });
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&payload).ok()?;
    Some(format!(
        "ibex-source-id-v1:{}",
        URL_SAFE_NO_PAD.encode(canonical)
    ))
}

fn normalized_bundle_virtual_prefix(prefix: &str) -> bool {
    (prefix == "/project" || prefix.starts_with("/project/"))
        && !prefix.ends_with('/')
        && !prefix.contains('\0')
        && !prefix
            .split('/')
            .any(|component| component == "." || component == "..")
}

fn normal_utf8_path_components(path: &Path) -> Option<Vec<String>> {
    path.components()
        .map(|component| match component {
            std::path::Component::Normal(value) => value.to_str().map(str::to_owned),
            _ => None,
        })
        .collect()
}

fn validate_bundle_source_provenance(
    manifest: &BundleCacheManifest,
    expected_authority: Option<&BundleSourceProvenanceAuthority>,
) -> bool {
    use capsec_semantics::model::LogicalRoot;

    let Some(provenance) = manifest.source_provenance.as_ref() else {
        return manifest.version == 3 && expected_authority.is_none();
    };
    let Some(expected_authority) = expected_authority else {
        // An internally consistent cache sidecar is not authentication. The
        // caller must retain the native armed authority that selected these
        // bindings and compare it here; otherwise a cache writer could simply
        // recompute every digest after substituting a different SourceId.
        // Even with that comparison, public hashes authenticate no compiler:
        // production generated execution separately requires a fresh private
        // invocation and descriptor-captured bytes.
        return false;
    };
    let Ok(expected_authority_bytes) = expected_authority.canonical_bytes() else {
        return false;
    };
    let project_bindings = expected_authority
        .bindings
        .iter()
        .filter(|binding| binding.logical_root == LogicalRoot::Project)
        .collect::<Vec<_>>();
    let Some(project_binding) = (project_bindings.len() == 1).then_some(project_bindings[0]) else {
        return false;
    };
    let project_root = Path::new(&project_binding.backing_root);
    if expected_authority.schema != "ibex/source-provenance-authority/1"
        || !expected_authority.root_identity.is_root()
        || project_binding.owner.is_some()
        || !project_root.is_absolute()
    {
        return false;
    }
    let mut authority_roots = std::collections::BTreeSet::new();
    for binding in &expected_authority.bindings {
        let backing_root = Path::new(&binding.backing_root);
        if !backing_root.is_absolute()
            || backing_root.strip_prefix(project_root).is_err()
            || !authority_roots.insert(binding.backing_root.as_str())
            || match binding.logical_root {
                LogicalRoot::Project => binding.owner.is_some(),
                LogicalRoot::Package => binding
                    .owner
                    .as_ref()
                    .is_none_or(|owner| !owner.is_package()),
                _ => true,
            }
        {
            return false;
        }
    }
    if manifest.version != 4
        || provenance.schema != "ibex/source-provenance/1"
        || provenance.armed_snapshot_digest != expected_authority.armed_snapshot_digest
        || provenance.package_graph_digest != expected_authority.package_graph_digest
        || provenance.authority_digest != sha256_bytes(&expected_authority_bytes)
        || capsec_semantics::model::Digest::new(provenance.armed_snapshot_digest.clone()).is_err()
        || capsec_semantics::model::Digest::new(provenance.package_graph_digest.clone()).is_err()
        || !valid_sha256(&provenance.authority_digest)
        || !valid_sha256(&provenance.digest)
        || provenance.modules.is_empty()
    {
        return false;
    }
    let projection = serde_json::json!({
        "schema": provenance.schema,
        "armedSnapshotDigest": provenance.armed_snapshot_digest,
        "packageGraphDigest": provenance.package_graph_digest,
        "authorityDigest": provenance.authority_digest,
        "modules": provenance.modules,
    });
    let Ok(canonical_projection) = capsec_semantics::canonical::to_jcs_bytes(&projection) else {
        return false;
    };
    if sha256_bytes(&canonical_projection) != provenance.digest {
        return false;
    }

    let output_names = manifest
        .outputs
        .iter()
        .map(|output| output.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut covered_deps = vec![false; manifest.deps.len()];
    let mut previous_source_id: Option<&str> = None;
    for module in &provenance.modules {
        if previous_source_id.is_some_and(|previous| previous >= module.source_id.as_str())
            || bundle_source_id(&module.source_identity).as_deref()
                != Some(module.source_id.as_str())
            || !valid_sha256(&module.source_sha256)
            || module.dep_index >= manifest.deps.len()
            || covered_deps[module.dep_index]
            || manifest.deps[module.dep_index].sha256 != module.source_sha256
            || !normalized_bundle_virtual_prefix(&module.binding_virtual_prefix)
            || module.source_identity.lexical_components.is_empty()
            || module
                .source_identity
                .lexical_components
                .iter()
                .any(|component| {
                    component.is_empty()
                        || component == "."
                        || component == ".."
                        || component.contains(['/', '\0'])
                })
        {
            return false;
        }
        match module.source_identity.logical_root {
            LogicalRoot::Project if !module.source_identity.defining_principal.is_root() => {
                return false
            }
            LogicalRoot::Package if !module.source_identity.defining_principal.is_package() => {
                return false
            }
            LogicalRoot::Project | LogicalRoot::Package => {}
            _ => return false,
        }
        // Reproduce the authenticated binding projection in native code. Merely
        // matching the authority digest is insufficient: an untrusted cache
        // writer could keep that digest while relabelling a package source as
        // root-owned and recomputing every public manifest digest.
        let dep_path = Path::new(&manifest.deps[module.dep_index].path);
        let Some((binding, binding_relative)) = expected_authority
            .bindings
            .iter()
            .filter_map(|binding| {
                dep_path
                    .strip_prefix(Path::new(&binding.backing_root))
                    .ok()
                    .map(|relative| (binding, relative))
            })
            .max_by_key(|(binding, _)| Path::new(&binding.backing_root).components().count())
        else {
            return false;
        };
        let expected_principal = binding
            .owner
            .as_ref()
            .unwrap_or(&expected_authority.root_identity);
        let Some(expected_lexical_components) = normal_utf8_path_components(binding_relative)
        else {
            return false;
        };
        let Some(project_relative) = dep_path
            .strip_prefix(project_root)
            .ok()
            .and_then(normal_utf8_path_components)
        else {
            return false;
        };
        let Some(binding_project_relative) = Path::new(&binding.backing_root)
            .strip_prefix(project_root)
            .ok()
            .and_then(normal_utf8_path_components)
        else {
            return false;
        };
        let expected_binding_virtual_prefix = if binding_project_relative.is_empty() {
            "/project".to_owned()
        } else {
            format!("/project/{}", binding_project_relative.join("/"))
        };
        let expected_full_virtual_path = format!("/project/{}", project_relative.join("/"));
        if binding.logical_root != module.source_identity.logical_root
            || expected_principal != &module.source_identity.defining_principal
            || expected_lexical_components != module.source_identity.lexical_components
            || expected_binding_virtual_prefix != module.binding_virtual_prefix
            || expected_full_virtual_path != module.virtual_path
        {
            return false;
        }
        let expected_virtual_path = format!(
            "{}/{}",
            module.binding_virtual_prefix,
            module.source_identity.lexical_components.join("/")
        );
        if expected_virtual_path != module.virtual_path
            || source_label_for_bundle_virtual_path(&module.virtual_path).as_deref()
                != Some(module.source_label.as_str())
            || module.chunks.is_empty()
        {
            return false;
        }
        let mut previous_chunk: Option<&str> = None;
        for chunk in &module.chunks {
            if normalized_relative_artifact_path(Path::new(chunk)).as_deref()
                != Some(chunk.as_str())
                || !output_names.contains(chunk.as_str())
                || previous_chunk.is_some_and(|previous| previous >= chunk.as_str())
            {
                return false;
            }
            previous_chunk = Some(chunk);
        }
        covered_deps[module.dep_index] = true;
        previous_source_id = Some(&module.source_id);
    }
    if covered_deps.iter().any(|covered| !covered) {
        return false;
    }
    let graph_projection = serde_json::json!({
        "deps": manifest.deps,
        "outputs": manifest.outputs,
        "sourceProvenanceDigest": provenance.digest,
    });
    let Ok(canonical_graph) = capsec_semantics::canonical::to_jcs_bytes(&graph_projection) else {
        return false;
    };
    sha256_bytes(&canonical_graph) == manifest.graph_digest
}

/// A cached bundle is fresh only when every dependency and every output still
/// matches the SHA-256 digest committed by its manifest. File size and mtime
/// are never source identity (ENG-24257). Freshness is deliberately not
/// compiler authentication: a cache writer can recompute every public digest,
/// so this predicate is never the production generated-execution admission.
async fn bundle_cache_is_fresh(output: &Path, entry: &Path) -> bool {
    bundle_cache_is_fresh_with_source_provenance(output, entry, None).await
}

async fn bundle_cache_is_fresh_with_source_provenance(
    output: &Path,
    entry: &Path,
    expected_authority: Option<&BundleSourceProvenanceAuthority>,
) -> bool {
    if !output.is_file() {
        return false;
    }
    let Ok(manifest) = read_bundle_manifest(output).await else {
        return false;
    };
    if !matches!(manifest.version, 3 | 4)
        || !valid_sha256(&manifest.graph_digest)
        || !valid_sha256(&manifest.resolution_digest)
        || !validate_bundle_source_provenance(&manifest, expected_authority)
    {
        return false;
    }
    let canonical_entry = std::fs::canonicalize(entry).unwrap_or_else(|_| entry.to_path_buf());
    let manifest_entry =
        std::fs::canonicalize(&manifest.entry).unwrap_or_else(|_| PathBuf::from(&manifest.entry));
    if canonical_entry != manifest_entry {
        return false;
    }

    if manifest.resolution_inputs.is_empty() {
        return false;
    }
    let mut previous_resolution: Option<(&str, &str)> = None;
    for input in &manifest.resolution_inputs {
        if !Path::new(&input.path).is_absolute() || !valid_sha256(&input.sha256) {
            return false;
        }
        let ordering_key = (input.path.as_str(), input.kind.as_str());
        if previous_resolution.is_some_and(|previous| previous >= ordering_key) {
            return false;
        }
        previous_resolution = Some(ordering_key);
        if bundle_resolution_input_digest(input).as_deref() != Some(input.sha256.as_str()) {
            return false;
        }
    }
    let Ok(encoded_resolution) = serde_json::to_vec(&manifest.resolution_inputs) else {
        return false;
    };
    if sha256_bytes(&encoded_resolution) != manifest.resolution_digest {
        return false;
    }

    if manifest.deps.is_empty() {
        return false;
    }
    let mut previous_dep: Option<&str> = None;
    let canonical_entry_string = canonical_entry.to_string_lossy();
    let mut includes_entry = false;
    for dep in &manifest.deps {
        if !valid_sha256(&dep.sha256)
            || previous_dep.is_some_and(|previous| previous >= dep.path.as_str())
        {
            return false;
        }
        previous_dep = Some(&dep.path);
        let path = Path::new(&dep.path);
        let Ok(canonical_dep) = std::fs::canonicalize(path) else {
            return false;
        };
        if canonical_dep.to_string_lossy() != dep.path {
            return false;
        }
        includes_entry |= dep.path == canonical_entry_string;
        let Ok(digest) = sha256_file(path).await else {
            return false;
        };
        if digest != dep.sha256 {
            return false;
        }
    }
    if !includes_entry {
        return false;
    }
    if manifest.version == 3 {
        let Ok(encoded_deps) = serde_json::to_vec(&manifest.deps) else {
            return false;
        };
        if sha256_bytes(&encoded_deps) != manifest.graph_digest {
            return false;
        }
    }

    let Some(artifact_dir) = output.parent() else {
        return false;
    };
    if manifest.outputs.is_empty() {
        return false;
    }
    let Some(expected_entry_output) = output
        .strip_prefix(artifact_dir)
        .ok()
        .and_then(normalized_relative_artifact_path)
    else {
        return false;
    };
    let mut previous_output: Option<&str> = None;
    let mut includes_output = false;
    let mut expected_files = Vec::with_capacity(manifest.outputs.len());
    for artifact in &manifest.outputs {
        let relative = Path::new(&artifact.path);
        let Some(normalized) = normalized_relative_artifact_path(relative) else {
            return false;
        };
        if normalized != artifact.path
            || !valid_sha256(&artifact.sha256)
            || previous_output.is_some_and(|previous| previous >= artifact.path.as_str())
        {
            return false;
        }
        previous_output = Some(&artifact.path);
        includes_output |= artifact.path == expected_entry_output;
        let Ok(digest) = sha256_file(&artifact_dir.join(relative)).await else {
            return false;
        };
        if digest != artifact.sha256 {
            return false;
        }
        expected_files.push(artifact.path.clone());
    }
    if !includes_output {
        return false;
    }
    let mut actual_files = Vec::new();
    if !collect_bundle_output_files(artifact_dir, artifact_dir, &mut actual_files) {
        return false;
    }
    actual_files.sort();
    if actual_files != expected_files {
        return false;
    }

    true
}

/// Return the sole original only for the deliberately narrow generated form
/// the production loader can execute without exposing a per-original registry:
/// one dependency, one provenance row, one entry chunk, and at most its map.
fn admitted_single_original_bundle<'a>(
    manifest: &'a BundleCacheManifest,
    output: &Path,
) -> Option<&'a BundleOriginalModuleProvenance> {
    let provenance = manifest.source_provenance.as_ref()?;
    if manifest.version != 4 || manifest.deps.len() != 1 || provenance.modules.len() != 1 {
        return None;
    }
    let artifact_dir = output.parent()?;
    let entry_output = output
        .strip_prefix(artifact_dir)
        .ok()
        .and_then(normalized_relative_artifact_path)?;
    let map_output = format!("{entry_output}.map");
    let original = &provenance.modules[0];
    (original.dep_index == 0
        && original.chunks.as_slice() == [entry_output.as_str()]
        && manifest
            .outputs
            .iter()
            .all(|artifact| artifact.path == entry_output || artifact.path == map_output))
    .then_some(original)
}

/// Project one digest-verified CJS chunk into the closed record accepted by the
/// bootstrap loader's original-module registry. This projection deliberately
/// contains no dependency/backing path. Native must retain `expected_authority`
/// through dispatch; ordinary resolver output cannot mint this record schema.
///
/// The remaining integration point is compiler-generated begin/commit/abort
/// calls around each Rolldown original-module initializer before this record is
/// dispatched. Until that transform exists, armed direct-file execution does
/// not select this seam.
/// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
#[cfg_attr(not(test), allow(dead_code))]
async fn authenticated_generated_cjs_bundle_resolution(
    bundle_entry: &Path,
    source_entry: &Path,
    chunk: &Path,
    expected_authority: &BundleSourceProvenanceAuthority,
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        bundle_cache_is_fresh_with_source_provenance(
            bundle_entry,
            source_entry,
            Some(expected_authority),
        )
        .await,
        "generated bundle provenance is stale or unauthenticated"
    );
    let manifest = read_bundle_manifest(bundle_entry).await?;
    let provenance = manifest
        .source_provenance
        .as_ref()
        .context("generated bundle has no per-original provenance")?;
    let artifact_dir = bundle_entry
        .parent()
        .context("generated bundle has no artifact directory")?;
    let chunk_name = chunk
        .strip_prefix(artifact_dir)
        .ok()
        .and_then(normalized_relative_artifact_path)
        .context("generated chunk escapes its authenticated artifact")?;
    anyhow::ensure!(
        !chunk_name.contains('/')
            && !chunk_name.contains("..")
            && chunk_name
                .bytes()
                .enumerate()
                .all(|(index, byte)| byte.is_ascii_alphanumeric()
                    || byte == b'_'
                    || (index > 0 && matches!(byte, b'@' | b'+' | b'.' | b'-'))),
        "generated chunk name cannot be projected into the closed loader protocol"
    );
    anyhow::ensure!(
        manifest
            .outputs
            .iter()
            .any(|output| output.path == chunk_name),
        "generated chunk is absent from the authenticated output set"
    );
    let modules = provenance
        .modules
        .iter()
        .filter(|module| {
            module
                .chunks
                .iter()
                .any(|candidate| candidate == &chunk_name)
        })
        .map(|module| {
            serde_json::json!({
                "sourceId": module.source_id,
                "sourceLabel": module.source_label,
                "virtualPath": module.virtual_path,
                "definingPrincipal": module.source_identity.defining_principal,
            })
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !modules.is_empty(),
        "generated chunk has no authenticated original modules"
    );
    let source = tokio::fs::read_to_string(chunk)
        .await
        .context("generated CJS chunk is not UTF-8")?;
    Ok(serde_json::json!({
        "schema": "ibex/generated-bundle-resolution/1",
        "kind": "cjs",
        "source": source,
        "virtualPath": format!(
            "/project/.ibex-generated/{}/{}",
            provenance.digest, chunk_name
        ),
        "sourceLabel": format!("ibex:bundle/{}/{}", provenance.digest, chunk_name),
        "sourceProvenance": {
            "schema": "ibex/source-provenance-chunk/1",
            "digest": provenance.digest,
            "chunk": chunk_name,
            "modules": modules,
        },
    }))
}

#[cfg(test)]
fn bytecode_manifest_path(bytecode: &Path) -> PathBuf {
    let mut path = bytecode.as_os_str().to_os_string();
    path.push(".meta.json");
    PathBuf::from(path)
}

#[cfg(test)]
async fn bytecode_cache_is_fresh(source: &Path, bytecode: &Path) -> bool {
    engine::hermes::bytecode_artifact_is_fresh(source, bytecode).await
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BytecodeSourceProvenanceManifest {
    schema: String,
    source_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_provenance_digest: Option<String>,
    bytecode_sha256: String,
    toolchain_identity: String,
    digest: String,
}

fn bytecode_source_provenance_manifest_path(bytecode: &Path) -> PathBuf {
    let mut path = bytecode.as_os_str().to_os_string();
    path.push(".provenance.json");
    PathBuf::from(path)
}

fn bytecode_source_provenance_projection(
    source_sha256: &str,
    source_provenance_digest: Option<&str>,
    bytecode_sha256: &str,
    toolchain_identity: &str,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "ibex/bytecode-source-provenance/1",
        "sourceSha256": source_sha256,
        "sourceProvenanceDigest": source_provenance_digest,
        "bytecodeSha256": bytecode_sha256,
        "toolchainIdentity": toolchain_identity,
    })
}

async fn write_bytecode_source_provenance_manifest(
    bytecode: &Path,
    source_sha256: &str,
    source_provenance_digest: Option<&str>,
    toolchain_identity: &str,
) -> Result<()> {
    let bytecode_sha256 = sha256_file(bytecode).await?;
    let projection = bytecode_source_provenance_projection(
        source_sha256,
        source_provenance_digest,
        &bytecode_sha256,
        toolchain_identity,
    );
    let digest = sha256_bytes(&capsec_semantics::canonical::to_jcs_bytes(&projection)?);
    let manifest = BytecodeSourceProvenanceManifest {
        schema: "ibex/bytecode-source-provenance/1".to_owned(),
        source_sha256: source_sha256.to_owned(),
        source_provenance_digest: source_provenance_digest.map(str::to_owned),
        bytecode_sha256,
        toolchain_identity: toolchain_identity.to_owned(),
        digest,
    };
    tokio::fs::write(
        bytecode_source_provenance_manifest_path(bytecode),
        serde_json::to_vec(&manifest)?,
    )
    .await?;
    Ok(())
}

async fn bytecode_cache_is_fresh_with_source_provenance(
    source: &Path,
    bytecode: &Path,
    expected_authority: Option<&BundleSourceProvenanceAuthority>,
) -> bool {
    if !engine::hermes::bytecode_artifact_is_fresh(source, bytecode).await {
        return false;
    }
    verify_bytecode_source_provenance_binding(source, bytecode, expected_authority)
        .await
        .is_ok()
}

/// Return the authenticated provenance digest paired with a generated bundle
/// source. A sibling manifest is security-bearing, never optional: it must be
/// fresh, and a runtime bundle-cache path without one is refused. Legacy v3
/// unarmed bundles have no provenance claim and use the `none` cache-key arm;
/// a v4 claim always requires retained native authority. Raw project source
/// likewise has no bundle provenance.
async fn verified_bundle_source_provenance_digest(
    source: &Path,
    expected_authority: Option<&BundleSourceProvenanceAuthority>,
) -> Result<Option<String>> {
    let manifest_path = deps_manifest_path(source);
    let bundles_root = runtime_cache_dir()?.join("bundles");
    if !manifest_path.exists() {
        if source.starts_with(&bundles_root) {
            anyhow::bail!("bundle cache source has no source-provenance manifest");
        }
        return Ok(None);
    }
    let manifest = read_bundle_manifest(source).await?;
    let entry = PathBuf::from(&manifest.entry);
    anyhow::ensure!(
        bundle_cache_is_fresh_with_source_provenance(source, &entry, expected_authority).await,
        "bundle source-provenance manifest is stale or tampered"
    );
    if manifest.version == 3 {
        anyhow::ensure!(
            expected_authority.is_none() && manifest.source_provenance.is_none(),
            "legacy bundle cannot carry authenticated source provenance"
        );
        return Ok(None);
    }
    let provenance = manifest
        .source_provenance
        .context("bundle cache source has no per-original source provenance")?;
    anyhow::ensure!(
        manifest.version == 4 && valid_sha256(&provenance.digest),
        "bundle cache source provenance has an unsupported version"
    );
    Ok(Some(provenance.digest))
}

fn bytecode_content_cache_key(
    source_path: &str,
    source_digest: &str,
    toolchain_identity: &str,
    source_provenance_digest: Option<&str>,
) -> String {
    sha256_bytes(
        format!(
            "bytecode-cache-v4\0{source_path}\0{source_digest}\0{toolchain_identity}\0{}",
            source_provenance_digest.unwrap_or("none")
        )
        .as_bytes(),
    )
}

async fn verify_bytecode_source_provenance_binding(
    source: &Path,
    bytecode: &Path,
    expected_authority: Option<&BundleSourceProvenanceAuthority>,
) -> Result<()> {
    let source = std::fs::canonicalize(source)
        .with_context(|| format!("bytecode source is missing: {}", source.display()))?;
    let source_path = source
        .to_str()
        .context("bytecode cache does not support non-UTF-8 source paths")?;
    let source_digest = sha256_file(&source).await?;
    let provenance_digest =
        verified_bundle_source_provenance_digest(&source, expected_authority).await?;
    let bytecode_digest = sha256_file(bytecode).await?;
    let toolchain_identity = engine::hermes::bytecode_cache_identity();
    let expected_key = bytecode_content_cache_key(
        source_path,
        &source_digest,
        &toolchain_identity,
        provenance_digest.as_deref(),
    );
    anyhow::ensure!(
        bytecode
            .parent()
            .and_then(Path::file_name)
            .and_then(std::ffi::OsStr::to_str)
            == Some(expected_key.as_str()),
        "bytecode cache path is not bound to source provenance"
    );
    let raw_manifest = tokio::fs::read(bytecode_source_provenance_manifest_path(bytecode))
        .await
        .context("bytecode cache has no source-provenance attestation")?;
    let manifest: BytecodeSourceProvenanceManifest = serde_json::from_slice(&raw_manifest)
        .context("invalid bytecode source-provenance attestation")?;
    let projection = bytecode_source_provenance_projection(
        &manifest.source_sha256,
        manifest.source_provenance_digest.as_deref(),
        &manifest.bytecode_sha256,
        &manifest.toolchain_identity,
    );
    let observed_manifest_digest =
        sha256_bytes(&capsec_semantics::canonical::to_jcs_bytes(&projection)?);
    anyhow::ensure!(
        manifest.schema == "ibex/bytecode-source-provenance/1"
            && manifest.source_sha256 == source_digest
            && manifest.source_provenance_digest == provenance_digest
            && manifest.bytecode_sha256 == bytecode_digest
            && manifest.toolchain_identity == toolchain_identity
            && valid_sha256(&manifest.digest)
            && manifest.digest == observed_manifest_digest,
        "bytecode source-provenance attestation is stale or tampered"
    );
    Ok(())
}

fn touch_bytecode_artifact(artifact_dir: &Path) {
    std::fs::write(artifact_dir.join(".last-used"), []).ok();
}

fn is_bytecode_cache_key(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.len() == 64
            && name
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    })
}

fn ensure_bytecode_cache_root(cache_parent: &Path) -> Result<PathBuf> {
    let cache_parent = cache_parent.to_path_buf();
    std::fs::create_dir_all(&cache_parent).with_context(|| {
        format!(
            "Failed to create runtime cache directory {}",
            cache_parent.display()
        )
    })?;
    let cache_parent = std::fs::canonicalize(&cache_parent).with_context(|| {
        format!(
            "Failed to authenticate runtime cache directory {}",
            cache_parent.display()
        )
    })?;
    let cache_root = cache_parent.join(".bytecode-cache");
    match std::fs::symlink_metadata(&cache_root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(&cache_root) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(
                            &cache_root,
                            std::fs::Permissions::from_mode(0o700),
                        )?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Failed to create bytecode cache {}", cache_root.display())
                    })
                }
            }
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(&cache_root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "Bytecode cache root must be a real directory, not a symlink or file: {}",
            cache_root.display()
        );
    }
    let authenticated = std::fs::canonicalize(&cache_root).with_context(|| {
        format!(
            "Failed to authenticate bytecode cache {}",
            cache_root.display()
        )
    })?;
    if authenticated.parent() != Some(cache_parent.as_path()) {
        anyhow::bail!(
            "Bytecode cache {} escapes runtime cache {}",
            authenticated.display(),
            cache_parent.display()
        );
    }
    Ok(authenticated)
}

fn bytecode_cache_parent_for_source(source: &Path) -> Result<PathBuf> {
    let runtime_root = runtime_cache_dir()?;
    std::fs::create_dir_all(&runtime_root)?;
    let runtime_root = std::fs::canonicalize(runtime_root)?;
    let bundles_root = runtime_root.join("bundles");
    if source.starts_with(&bundles_root) {
        return source
            .parent()
            .map(Path::to_path_buf)
            .context("bundle cache source has no parent");
    }
    Ok(runtime_root)
}

fn cleanup_abandoned_bytecode_temp_dirs(cache_root: &Path) {
    let Ok(entries) = std::fs::read_dir(cache_root) else {
        return;
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let owner = [".stage-", ".invalid-", ".evict-"]
            .iter()
            .find_map(|prefix| {
                name.strip_prefix(prefix)
                    .and_then(|rest| rest.split('-').next())
                    .and_then(|pid| pid.parse::<u32>().ok())
            });
        if owner.is_some_and(|pid| !process_is_running(pid)) {
            std::fs::remove_dir_all(entry.path()).ok();
        }
    }
}

fn prune_bytecode_cache_to_limit(cache_root: &Path, keep: &Path, limit: u64) {
    cleanup_abandoned_bytecode_temp_dirs(cache_root);
    let Ok(entries) = std::fs::read_dir(cache_root) else {
        return;
    };
    let mut artifacts = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            if path == keep || !file_type.is_dir() || !is_bytecode_cache_key(&entry.file_name()) {
                return None;
            }
            let metadata = entry.metadata().ok()?;
            let recency = std::fs::metadata(path.join(".last-used"))
                .and_then(|marker| marker.modified())
                .or_else(|_| metadata.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            Some((recency, cached_directory_size(&path), path))
        })
        .collect::<Vec<_>>();
    let mut total = cached_directory_size(cache_root);
    artifacts.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in artifacts {
        if total <= limit {
            break;
        }
        let Ok(Some(gate)) = try_acquire_bundle_artifact_gate(&path) else {
            continue;
        };
        if bundle_artifact_has_live_lease(&path) {
            drop(gate);
            continue;
        }
        let quarantine = cache_root.join(format!(
            ".evict-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0),
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("artifact")
        ));
        let renamed = std::fs::rename(&path, &quarantine).is_ok();
        drop(gate);
        if renamed && std::fs::remove_dir_all(&quarantine).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

fn enforce_bytecode_cache_quota(cache_root: &Path, keep: &Path) {
    const DEFAULT_LIMIT: u64 = 256 * 1024 * 1024;
    let limit = std::env::var("IBEX_BYTECODE_CACHE_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LIMIT);
    prune_bytecode_cache_to_limit(cache_root, keep, limit);
}

async fn prepare_bytecode_entry(entry: &Path) -> Result<PathBuf> {
    prepare_bytecode_entry_with_source_provenance(entry, None).await
}

async fn prepare_bytecode_entry_with_source_provenance(
    entry: &Path,
    expected_authority: Option<&BundleSourceProvenanceAuthority>,
) -> Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let source_identity = std::fs::canonicalize(entry)
        .with_context(|| format!("Failed to authenticate bytecode source {}", entry.display()))?;
    // A bundle-cache source may be evicted by another process. Hold its shared
    // lease through the single source read, compilation, and HBC publication.
    let _source_lease = acquire_bundle_execution_lease(&source_identity).await?;
    let source = tokio::fs::read(&source_identity).await?;
    let source_digest_before = sha256_bytes(&source);
    let source_provenance_digest =
        verified_bundle_source_provenance_digest(&source_identity, expected_authority).await?;
    anyhow::ensure!(
        source_provenance_digest.is_none(),
        "provenance-bearing HBC is refused because no authenticated single-initializer wrapper format is admitted"
    );
    // Generated-code caches fail closed unless the mapped runtime binary can
    // be attested. Explicit `ibex build` output is not a cache and remains
    // available on platforms (currently Windows) without mapped-module
    // identity support; the cache-specific gate belongs here, not in the
    // generic compiler wrapper.
    ibex_runtime::engine::loaded_engine_binary_identity()
        .map_err(anyhow::Error::msg)
        .context("cannot authenticate the loaded Hermes engine for bytecode cache use")?;
    let toolchain_identity = engine::hermes::bytecode_cache_identity();
    let source_path = source_identity
        .to_str()
        .context("bytecode cache does not support non-UTF-8 source paths")?;
    let cache_key = bytecode_content_cache_key(
        source_path,
        &source_digest_before,
        &toolchain_identity,
        source_provenance_digest.as_deref(),
    );
    let cache_parent = bytecode_cache_parent_for_source(&source_identity)?;
    let cache_root = ensure_bytecode_cache_root(&cache_parent)?;
    let final_dir = cache_root.join(&cache_key);
    let hbc_path = final_dir.join("entry.hbc");
    if bytecode_cache_is_fresh_with_source_provenance(
        &source_identity,
        &hbc_path,
        expected_authority,
    )
    .await
    {
        touch_bytecode_artifact(&final_dir);
        return Ok(hbc_path);
    }

    tokio::fs::create_dir_all(&cache_root).await?;
    let seq = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let stage_dir = cache_root.join(format!(
        ".stage-{}-{seq}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    tokio::fs::create_dir(&stage_dir).await?;
    let stage_hbc = stage_dir.join("entry.hbc");
    if let Err(error) =
        engine::hermes::compile_source_to_bytecode(&source_identity, &source, &stage_hbc, None)
            .await
    {
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        return Err(error);
    }
    let source_digest_after = sha256_file(&source_identity).await?;
    if source_digest_before != source_digest_after {
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        anyhow::bail!(
            "Source changed while compiling bytecode for {}",
            source_identity.display()
        );
    }
    if let Err(error) = write_bytecode_source_provenance_manifest(
        &stage_hbc,
        &source_digest_before,
        source_provenance_digest.as_deref(),
        &toolchain_identity,
    )
    .await
    {
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        return Err(error).context("failed to bind bytecode to source provenance");
    }

    let gate = acquire_bundle_artifact_gate(&final_dir).await?;
    let mut quarantine = None;
    if final_dir.exists() {
        if bytecode_cache_is_fresh_with_source_provenance(
            &source_identity,
            &hbc_path,
            expected_authority,
        )
        .await
        {
            tokio::fs::remove_dir_all(&stage_dir).await.ok();
            touch_bytecode_artifact(&final_dir);
            return Ok(hbc_path);
        }
        let invalid = cache_root.join(format!(
            ".invalid-{}-{}-{seq}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        tokio::fs::rename(&final_dir, &invalid).await?;
        quarantine = Some(invalid);
    }
    if let Err(error) = tokio::fs::rename(&stage_dir, &final_dir).await {
        if let Some(invalid) = quarantine.as_ref() {
            tokio::fs::rename(invalid, &final_dir).await.ok();
        }
        return Err(error)
            .with_context(|| format!("Failed to publish bytecode cache {}", final_dir.display()));
    }
    if let Some(invalid) = quarantine {
        tokio::fs::remove_dir_all(invalid).await.ok();
    }
    touch_bytecode_artifact(&final_dir);
    drop(gate);
    enforce_bytecode_cache_quota(&cache_root, &final_dir);

    Ok(hbc_path)
}

fn normalize_hashbang_for_eval(source: &str) -> Cow<'_, str> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let has_source_mapping_url = source.contains("sourceMappingURL=");
    if !source.starts_with("#!") && !has_source_mapping_url {
        return Cow::Borrowed(source);
    }

    let mut normalized = String::with_capacity(source.len());
    for (index, line) in source.split_inclusive('\n').enumerate() {
        if index == 0 && line.starts_with("#!") {
            normalized.push_str("//");
            normalized.push_str(&line[2..]);
            continue;
        }

        // Strip a sourceMappingURL comment only when the whole line is that
        // comment (leading whitespace aside) — that is the only position this
        // textual scan can prove is a comment. A mid-line match is NOT
        // provably one: `out.push("//# sourceMappingURL=" + url);` is code
        // that GENERATES sourcemap comments, and truncating at the marker
        // corrupted such source into a syntax error (ENG-23484).
        // Under-stripping merely leaves a stale sourcemap pointer behind,
        // which is harmless by comparison.
        let trimmed = line.trim_start();
        if trimmed.starts_with("//#") && trimmed.contains("sourceMappingURL=") {
            if line.ends_with('\n') {
                normalized.push('\n');
            }
            continue;
        }

        normalized.push_str(line);
    }
    Cow::Owned(normalized)
}

fn normalize_windows_tool_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let value = path.to_string_lossy();
        if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = value.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    path
}

fn source_needs_tla_shim(source: &str) -> bool {
    // String/comment-aware: `await` inside a string literal (or a comment)
    // must not trigger the wrapper. The dynamic-import check stays a
    // substring match: the wrapper rewrite is required whenever a real
    // `import(` exists, and a false positive only costs a harmless wrap.
    contains_await_keyword(source) || source.contains("import(")
}

fn wrap_source_for_tla_eval(source: Cow<'_, str>, is_main_file: bool) -> String {
    wrap_source_for_tla_eval_with(source, is_main_file, false)
}

/// `already_lowered` marks swc output from the in-process pipeline: its
/// imports, `import.meta`, and dynamic `import()` are already CJS, so the
/// legacy string rewrites must not touch it (review R2 — they corrupted
/// string literals and identifiers like `reimport(`). The rewrites survive
/// only for rolldown ESM bundle outputs (Implementation Notes deferral 10).
fn wrap_source_for_tla_eval_with(
    source: Cow<'_, str>,
    is_main_file: bool,
    already_lowered: bool,
) -> String {
    if !source_needs_tla_shim(source.as_ref()) {
        return source.into_owned();
    }
    wrap_entry_source_for_eval(source, is_main_file, already_lowered)
}

/// Unconditionally wrap an entry source in the async-IIFE eval shim. Callers
/// that may pass source needing no shim at all should go through
/// `wrap_source_for_tla_eval_with`, which passes such source through
/// untouched. `run_entry_with_tla_shim` calls this directly for every lowered
/// entry — even one with no TLA — because bare eval of swc's CJS output lacks
/// the `module`/`exports`/`__filename`/`__dirname` bindings the wrapper's IIFE
/// parameters supply, and the async wrap is harmless for non-TLA code.
/// (ENG-23484)
fn wrap_entry_source_for_eval(
    source: Cow<'_, str>,
    is_main_file: bool,
    already_lowered: bool,
) -> String {
    let transformed = if already_lowered {
        source.into_owned()
    } else {
        let mut transformed = if source.contains("import ") || source.contains("export ") {
            transpile_esm_to_script(source.as_ref())
        } else {
            source.into_owned()
        };
        transformed = transformed.replace("import.meta", "globalThis.__exactImportMeta");
        transformed = transformed.replace("import(", "globalThis.require(");
        transformed
    };

    // `__filename`/`__dirname` are IIFE *parameters* (not a prelude inside the
    // body) so a leading "use strict" directive in the source stays the first
    // statement of the function body. The bundler's `define` lowers
    // `import.meta.url` to a `__filename`-based expression that only the CJS
    // module wrapper used to provide — evaluating the ESM/TLA output without
    // these bindings was ledger item 1 (`ReferenceError: __filename`).
    // `module`/`exports` bindings let in-process-lowered CJS entries run
    // under the same wrap; an entry's own exports are discarded, matching
    // `require(entry)` semantics. The scoped `require` keeps SWC-lowered
    // dynamic imports relative to the source entry instead of resolving from
    // the eval realm's empty referrer. Native still returns an opaque display
    // identity for the dependency; only the resolver receives the absolute
    // spelling that the diagnostic entry already exposed as __exactEntryFile.
    format!(
        "globalThis.__exactImportMeta = globalThis.__exactImportMeta || {{}};\n\
         globalThis.__exactImportMeta.main = {};\n\
         (async function(__filename, __dirname, module, exports, require) {{\n{}\n}})(\
         (typeof globalThis.__exactEntryFile === 'string' ? globalThis.__exactEntryFile : ''), \
         (function (p) {{ var s = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\\\')); return s > 0 ? p.slice(0, s) : p; }})\
         (typeof globalThis.__exactEntryFile === 'string' ? globalThis.__exactEntryFile : ''), \
         {{ exports: {{}} }}, {{}}, \
         (function (entryFile) {{ \
             var normalized = entryFile.replace(/\\\\/g, '/'); \
             var slash = normalized.lastIndexOf('/'); \
             var base = slash >= 0 ? normalized.slice(0, slash) : '.'; \
             return function (specifier) {{ \
                 if (typeof specifier === 'string' && \
                     (specifier.indexOf('./') === 0 || specifier.indexOf('../') === 0)) {{ \
                     return globalThis.require(base + '/' + specifier); \
                 }} \
                 return globalThis.require(specifier); \
             }}; \
         }})(typeof globalThis.__exactEntryFile === 'string' ? globalThis.__exactEntryFile : ''));",
        if is_main_file { "true" } else { "false" },
        transformed
    )
}

/// String-, comment-, and regex-aware scan for an `await` keyword anywhere in
/// the source. Any depth counts: `await` inside top-level `for`/`if` blocks is
/// still TLA, and wrapping non-TLA async code is harmless, so no brace tracking
/// is needed — only literals, comments, and regex literals are excluded.
///
/// Identifiers are consumed as whole words so `await` is matched only on a word
/// boundary (`awaited`/`awaitTime`/`kawaii` are not TLA). A `/` is disambiguated
/// between a regex literal and a division operator by tracking whether the
/// previous significant token was value-producing: without this, `await` inside
/// a regex literal (`var re = /await/g`) was read as a real keyword, so the REPL
/// wrapped the line in an async IIFE and the `var`/function binding no longer
/// leaked to the global object — a silent regression of the bug ENG-22957
/// aimed to close. (ENG-23031)
///
/// Shared with the REPL so `.time`/prompt input use the same detection instead
/// of a raw `contains("await")`. (ENG-22957)
pub(crate) fn contains_await_keyword(source: &str) -> bool {
    scan_for_await_keyword(source, false)
}

/// Like `contains_await_keyword`, but only reports `await` at brace depth 0
/// (true top-level): `await` inside functions, methods, or class bodies is not
/// top-level await. Used to pick the bundle format and to route untranspiled
/// entries / `-e` code through the TLA shim.
///
/// Built on the same string-, comment-, and regex-aware scanner as
/// `contains_await_keyword`: the previous standalone implementation was not
/// regex-aware, so a depth-0 regex literal containing `await` (e.g.
/// `const RE = /(await)/;`) flipped the bundle format CJS→ESM and re-routed
/// execution of a perfectly valid app (ENG-23484; scanner-level fix mirrors
/// ENG-23031's for `contains_await_keyword`).
pub(crate) fn contains_top_level_await(source: &str) -> bool {
    scan_for_await_keyword(source, true)
}

/// The shared scanner behind `contains_await_keyword` (any depth) and
/// `contains_top_level_await` (`top_level_only`, brace depth 0 with an
/// `await:` label exclusion). See `contains_await_keyword` for the tokenizer
/// rationale.
fn scan_for_await_keyword(source: &str, top_level_only: bool) -> bool {
    let bytes = source.as_bytes();
    let mut i = 0usize;
    // Whether a `/` here begins a regex literal (value position) rather than a
    // division operator. True at input start and after operators/punctuators
    // that expect an expression; false after a value token (identifier, `)`,
    // `]`, number, string, regex).
    let mut regex_allowed = true;
    // Brace depth for `top_level_only`: braces inside strings, comments, and
    // regex literals are consumed by their opaque spans and never counted.
    let mut brace_depth: i32 = 0;

    while i < bytes.len() {
        let b = bytes[i];

        // Whitespace never produces a value, so it must not disturb
        // `regex_allowed` (`a /b/` is division, not a regex after the space).
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c') {
            i += 1;
            continue;
        }

        // Comments: skip without changing the previous significant token.
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }

        // String / template literal: opaque span. Template interpolation is not
        // inspected (matching the prior scanner); a literal is a value, so a
        // following `/` is division.
        if b == b'\'' || b == b'"' || b == b'`' {
            let quote = b;
            i += 1;
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                i += 1;
                if c == quote {
                    break;
                }
            }
            regex_allowed = false;
            continue;
        }

        // Regex literal in value position: skip `/…/flags`, honoring escapes and
        // `[…]` character classes (which may contain an unescaped `/`).
        if b == b'/' && regex_allowed {
            i += 1;
            let mut in_class = false;
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'\n' {
                    break; // unterminated literal; stop scanning it
                }
                i += 1;
                match c {
                    b'[' => in_class = true,
                    b']' => in_class = false,
                    b'/' if !in_class => break,
                    _ => {}
                }
            }
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1; // regex flags
            }
            regex_allowed = false;
            continue;
        }

        // Identifier / keyword.
        if b == b'_' || b == b'$' || b.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
            if &source[start..i] == "await"
                // Top-level mode: only depth 0 counts, and `await:` is a
                // label (in sloppy scripts `await` is not reserved), not TLA.
                && (!top_level_only || (brace_depth == 0 && bytes.get(i) != Some(&b':')))
            {
                return true;
            }
            // After a value identifier `/` is division; after a keyword that
            // expects an expression it starts a regex.
            regex_allowed = keyword_precedes_expression(&source[start..i]);
            continue;
        }

        // Braces: track depth for `top_level_only`. Both act like the generic
        // punctuation below for regex disambiguation (a `/` after `{` or `}`
        // starts a regex, matching the prior scanner behavior).
        if b == b'{' {
            brace_depth += 1;
            regex_allowed = true;
            i += 1;
            continue;
        }
        if b == b'}' {
            brace_depth -= 1;
            regex_allowed = true;
            i += 1;
            continue;
        }

        // Numeric literal: a value, so a following `/` is division. Consuming a
        // little loosely (digits, `.`, exponent/hex letters) is fine — we only
        // need `regex_allowed` to end up false.
        if b.is_ascii_digit() {
            i += 1;
            while i < bytes.len() && (is_ident_byte(bytes[i]) || bytes[i] == b'.') {
                i += 1;
            }
            regex_allowed = false;
            continue;
        }

        // Any other punctuation/operator. A `/` after a closing `)`/`]` is
        // division; after everything else (`= , ( { [ ! ? : ; + - * % < > & | ^`)
        // it starts a regex.
        regex_allowed = !matches!(b, b')' | b']');
        i += 1;
    }
    false
}

/// Keywords after which a `/` begins a regex literal rather than division,
/// because they syntactically expect an expression to follow. (ENG-23031)
fn keyword_precedes_expression(word: &str) -> bool {
    matches!(
        word,
        "return"
            | "typeof"
            | "instanceof"
            | "in"
            | "of"
            | "new"
            | "delete"
            | "void"
            | "do"
            | "else"
            | "yield"
            | "await"
            | "case"
            | "throw"
    )
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn digest_field(hasher: &mut Sha256, label: &str, bytes: &[u8]) {
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn bundler_cache_input_paths() -> Result<Vec<PathBuf>> {
    // Outside a checkout there is no bundler to run and no scripts to hash;
    // the cache key must not require a repo.
    let Ok(root) = repo_root() else {
        return Ok(Vec::new());
    };
    [
        "packages/ibex-devtools/src/scripts/rolldown-bundle.mjs",
        "packages/ibex-devtools/src/scripts/transforms.mjs",
        // @ref LLP 0019#consequences — ENG-22987: the canonical Hermes-compat transforms
        // (for-of scoping, exponentiation, BigInt, async generators) moved out
        // of transforms.mjs into hermes-compat.mjs, which transforms.mjs now
        // re-exports. The bundle cache must hash the file the logic actually
        // lives in, or an edit to the transform semantics would not invalidate
        // cached bundles.
        "packages/ibex-devtools/src/scripts/hermes-compat.mjs",
        // @ref LLP 0014#parse-and-strip — the grant-attribute strip runs in
        // every bundle; its logic changing must invalidate cached bundles.
        "packages/ibex-devtools/src/scripts/import-grants.mjs",
    ]
    .into_iter()
    .map(|relative| authenticated_repo_file(&root, Path::new(relative)))
    .collect()
}

#[derive(Clone)]
struct BundlerToolchainIdentity {
    runner: PathBuf,
    runner_name: &'static str,
    digest: [u8; 32],
}

fn collect_authenticated_tool_files(
    path: &Path,
    package_store_root: &Path,
    visited_dirs: &mut std::collections::HashSet<PathBuf>,
    visited_files: &mut std::collections::HashSet<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    const MAX_TOOL_FILES: usize = 4096;
    let canonical = std::fs::canonicalize(path).with_context(|| {
        format!(
            "Failed to authenticate bundler dependency {}",
            path.display()
        )
    })?;
    if !canonical.starts_with(package_store_root) {
        anyhow::bail!(
            "Bundler dependency {} escapes authenticated package store {}",
            canonical.display(),
            package_store_root.display()
        );
    }
    let metadata = std::fs::metadata(&canonical)?;
    if metadata.is_file() {
        if visited_files.insert(canonical.clone()) {
            if files.len() >= MAX_TOOL_FILES {
                anyhow::bail!("Bundler dependency tree exceeds {MAX_TOOL_FILES} files");
            }
            files.push(canonical);
        }
        return Ok(());
    }
    if !metadata.is_dir() || !visited_dirs.insert(canonical.clone()) {
        return Ok(());
    }
    let mut entries = std::fs::read_dir(&canonical)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        collect_authenticated_tool_files(
            &entry.path(),
            package_store_root,
            visited_dirs,
            visited_files,
            files,
        )?;
    }
    Ok(())
}

fn compute_bundler_toolchain_identity() -> Result<BundlerToolchainIdentity> {
    const MAX_TOOL_BYTES: u64 = 512 * 1024 * 1024;
    let root = repo_root()?;
    let (runner, runner_name) = find_js_runner()?;
    let runner = std::fs::canonicalize(&runner)
        .with_context(|| format!("Failed to authenticate JS runner {}", runner.display()))?;
    let runner_bytes = std::fs::read(&runner)
        .with_context(|| format!("Failed to read JS runner {}", runner.display()))?;
    if runner_bytes.len() as u64 > MAX_TOOL_BYTES {
        anyhow::bail!("JS runner exceeds the authenticated tool size limit");
    }

    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "identity-version", b"bundler-toolchain-v1");
    digest_field(&mut hasher, "runner-name", runner_name.as_bytes());
    digest_field(
        &mut hasher,
        "runner-path",
        runner.to_string_lossy().as_bytes(),
    );
    digest_field(&mut hasher, "runner-content", &runner_bytes);

    let mut inputs = bundler_cache_input_paths()?;
    for relative in ["package.json", "bun.lock"] {
        let candidate = root.join(relative);
        if candidate.is_file() {
            inputs.push(authenticated_repo_file(&root, Path::new(relative))?);
        }
    }

    // Rolldown's JS package loads a platform-specific native binding and
    // helper packages from the enclosing installation node_modules directory.
    // Bind that exact resolved tree, not just package.json/lockfile metadata.
    let package_store_root = std::fs::canonicalize(root.join("node_modules"))
        .context("Failed to authenticate the installed package store")?;
    let rolldown = std::fs::canonicalize(root.join("node_modules/rolldown"))
        .context("Failed to authenticate the installed rolldown package")?;
    let install_root = rolldown
        .parent()
        .context("Installed rolldown package has no dependency root")?;
    let mut tool_files = Vec::new();
    collect_authenticated_tool_files(
        install_root,
        &package_store_root,
        &mut std::collections::HashSet::new(),
        &mut std::collections::HashSet::new(),
        &mut tool_files,
    )?;
    inputs.extend(tool_files);
    inputs.sort();
    inputs.dedup();

    let mut total = runner_bytes.len() as u64;
    for input in inputs {
        let bytes = std::fs::read(&input)
            .with_context(|| format!("Failed to read bundler input {}", input.display()))?;
        total = total
            .checked_add(bytes.len() as u64)
            .context("Bundler tooling size overflow")?;
        if total > MAX_TOOL_BYTES {
            anyhow::bail!("Bundler dependency tree exceeds the authenticated tool size limit");
        }
        digest_field(&mut hasher, "tool-path", input.to_string_lossy().as_bytes());
        digest_field(&mut hasher, "tool-content", &bytes);
    }

    Ok(BundlerToolchainIdentity {
        runner,
        runner_name,
        digest: hasher.finalize().into(),
    })
}

fn bundler_toolchain_identity() -> Result<BundlerToolchainIdentity> {
    // Computing this identity authenticates the runner plus thousands of
    // installed tool files. Serialize the cold path so concurrent bundle
    // publishers do not all repeat that scan before one of them fills the
    // cache. Failed scans remain retryable.
    static CACHED: std::sync::OnceLock<std::sync::Mutex<Option<BundlerToolchainIdentity>>> =
        std::sync::OnceLock::new();
    let mut cached = CACHED
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .map_err(|_| anyhow::anyhow!("Bundler toolchain identity cache is poisoned"))?;
    if let Some(identity) = cached.as_ref() {
        return Ok(identity.clone());
    }
    let identity = compute_bundler_toolchain_identity()?;
    *cached = Some(identity.clone());
    Ok(identity)
}

fn verify_bundler_toolchain_identity(expected: &BundlerToolchainIdentity) -> Result<()> {
    let current = compute_bundler_toolchain_identity()?;
    if current.runner != expected.runner
        || current.runner_name != expected.runner_name
        || current.digest != expected.digest
    {
        anyhow::bail!("Bundler runner or dependency tree changed during this process");
    }
    Ok(())
}

fn bundle_cache_key(entry: &Path, bundle_format: BundleFormat) -> Result<String> {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "cache-version", b"bundle-cache-v8-sha256");
    digest_field(&mut hasher, "format", bundle_format.as_str().as_bytes());
    let block_scoping_mode: &[u8] = if crate::hermes_es6_block_scoping_enabled() {
        b"enabled"
    } else {
        b"legacy"
    };
    digest_field(&mut hasher, "hermes-es6-block-scoping", block_scoping_mode);
    // @ref LLP 0013#mechanism-2 — a compartmentalized bundle references the
    // `__compartments` registry, which only exists under lockdown/compartments.
    // It MUST NOT be reused for a non-compartment run (the reference would throw
    // ReferenceError), nor vice versa. Fold the state into the cache key so the
    // two variants are cached under distinct paths. This mirrors the same signal
    // `run_bundler` uses to pass `--compartments`.
    // Resolve with the same truthiness parse the engine uses (ENG-22634), and
    // key the cache on that resolved bool so a compartmentalized bundle can never
    // be reused for a non-compartment run (or vice versa).
    digest_field(&mut hasher, "compartments", b"1");
    // @ref LLP 0013#mechanism-3 — per-package chunking changes the output shape
    // (multiple chunk files), so it must key distinctly from a flat bundle. Use
    // the same truthiness parse as the other two read sites so `=0` is a real
    // opt-out and the cache key agrees with what the bundler actually emitted.
    digest_field(&mut hasher, "per-package-chunks", b"1");
    let canonical_entry = std::fs::canonicalize(entry)
        .with_context(|| format!("Failed to resolve bundle entry {}", entry.display()))?;
    let canonical_entry_utf8 = canonical_entry.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "Bundle cache does not support a non-UTF-8 entry path: {}",
            canonical_entry.display()
        )
    })?;
    digest_field(&mut hasher, "entry-path", canonical_entry_utf8.as_bytes());
    digest_field(
        &mut hasher,
        "entry-content",
        &std::fs::read(&canonical_entry)?,
    );

    // Outside a checkout (or when no runner is installed), bundling is
    // unavailable and the loader falls back to its in-process path. Preserve
    // that fallback while ensuring every actually runnable bundler cache key
    // includes the exact runner, Rolldown JS/native packages, lockfile, and
    // transform scripts that will produce the artifact.
    match bundler_toolchain_identity() {
        Ok(identity) => digest_field(&mut hasher, "bundler-toolchain", &identity.digest),
        Err(_) => digest_field(&mut hasher, "bundler-toolchain", b"unavailable"),
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn bundle_file_ext(format: BundleFormat) -> &'static str {
    match format {
        BundleFormat::Cjs => "js",
        BundleFormat::Esm => "mjs",
    }
}

/// Where a bundle's entry file lands in the cache. A flat bundle is a single
/// file named by the cache key. A per-package-chunked bundle also emits sibling
/// chunk files (`__ibexpkg__*`, and the shared `rolldown-runtime.js`) into the
/// entry's directory with **fixed, cross-bundle names** — so it gets its own
/// per-key subdirectory, otherwise two concurrently-bundled apps race on the
/// shared `rolldown-runtime.js` name and corrupt each other's cache (a real
/// hazard for concurrent `ibex run` of different apps, surfaced once enforce
/// began auto-enabling chunking — ENG-22681). @ref LLP 0013#mechanism-3
fn ensure_real_internal_cache_subdirectory(cache_root: &Path, name: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(cache_root).with_context(|| {
        format!(
            "Failed to create runtime cache root {}",
            cache_root.display()
        )
    })?;
    let cache_root = std::fs::canonicalize(cache_root).with_context(|| {
        format!(
            "Failed to authenticate runtime cache root {}",
            cache_root.display()
        )
    })?;
    let child = cache_root.join(name);
    match std::fs::symlink_metadata(&child) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(&child) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(&child)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "internal cache subroot must be a real directory: {}",
        child.display()
    );
    let child = std::fs::canonicalize(&child)?;
    anyhow::ensure!(
        child.parent() == Some(cache_root.as_path()),
        "internal cache subroot escaped its authenticated parent: {}",
        child.display()
    );
    Ok(child)
}

fn bundle_artifact_root(bundles_root: &Path, key: &str) -> PathBuf {
    bundles_root.join(key)
}

fn bundle_entry_path(artifact_dir: &Path, format: BundleFormat) -> PathBuf {
    artifact_dir.join(format!("bundle.{}", bundle_file_ext(format)))
}

fn process_is_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        return result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    }
    #[cfg(windows)]
    {
        type Handle = *mut std::ffi::c_void;
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
            fn CloseHandle(handle: Handle) -> i32;
        }
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        unsafe { CloseHandle(handle) };
        return true;
    }
    #[allow(unreachable_code)]
    false
}

struct BundleArtifactGate {
    file: std::fs::File,
}

impl Drop for BundleArtifactGate {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn bundle_gate_path(artifact_dir: &Path) -> PathBuf {
    let name = artifact_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    artifact_dir.with_file_name(format!(".{name}.gate"))
}

fn try_acquire_bundle_artifact_gate(artifact_dir: &Path) -> Result<Option<BundleArtifactGate>> {
    let gate = bundle_gate_path(artifact_dir);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&gate)
        .with_context(|| format!("Failed to open bundle artifact gate {}", gate.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(BundleArtifactGate { file })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(error)
            .with_context(|| format!("Failed to lock bundle artifact gate {}", gate.display())),
    }
}

async fn acquire_bundle_artifact_gate(artifact_dir: &Path) -> Result<BundleArtifactGate> {
    for _ in 0..500 {
        if let Some(gate) = try_acquire_bundle_artifact_gate(artifact_dir)? {
            return Ok(gate);
        }
        // Never park a Tokio worker while another process publishes/prunes.
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let gate = bundle_gate_path(artifact_dir);
    anyhow::bail!(
        "Timed out acquiring bundle artifact gate {}",
        gate.display()
    )
}

pub(crate) struct BundleLease {
    files: Vec<std::fs::File>,
}

impl Drop for BundleLease {
    fn drop(&mut self) {
        for file in &self.files {
            let _ = file.unlock();
        }
    }
}

fn acquire_bundle_lease(artifact_dir: &Path) -> Result<BundleLease> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(artifact_dir.join(".lease"))
        .with_context(|| format!("Failed to lease bundle artifact {}", artifact_dir.display()))?;
    file.lock_shared()
        .with_context(|| format!("Failed to lock bundle artifact {}", artifact_dir.display()))?;
    std::fs::write(artifact_dir.join(".last-used"), []).ok();
    Ok(BundleLease { files: vec![file] })
}

fn bundle_artifact_has_live_lease(artifact_dir: &Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(artifact_dir.join(".lease"))
    else {
        return false;
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(std::fs::TryLockError::WouldBlock) => true,
        Err(_) => true,
    }
}

pub(crate) async fn acquire_bundle_execution_lease(path: &Path) -> Result<Option<BundleLease>> {
    let mut retained = None;
    if let (Some(artifact_dir), Some(cache_root)) =
        (path.parent(), path.parent().and_then(Path::parent))
    {
        if cache_root
            .file_name()
            .is_some_and(|name| name == ".bytecode-cache")
            && artifact_dir.file_name().is_some_and(is_bytecode_cache_key)
        {
            let gate = acquire_bundle_artifact_gate(artifact_dir).await?;
            if !artifact_dir.is_dir() {
                anyhow::bail!(
                    "Bytecode cache artifact disappeared before execution: {}",
                    artifact_dir.display()
                );
            }
            retained = Some(acquire_bundle_lease(artifact_dir)?);
            drop(gate);
        }
    }

    let bundles_root = runtime_cache_dir()?.join("bundles");
    let mut current = path.parent();
    while let Some(directory) = current {
        if directory
            .parent()
            .and_then(Path::parent)
            .is_some_and(|parent| parent == bundles_root)
        {
            let gate = acquire_bundle_artifact_gate(directory).await?;
            if !directory.is_dir() {
                anyhow::bail!(
                    "Bundle cache artifact disappeared before execution: {}",
                    directory.display()
                );
            }
            let mut lease = acquire_bundle_lease(directory)?;
            drop(gate);
            if let Some(mut bytecode_lease) = retained {
                bytecode_lease.files.append(&mut lease.files);
                return Ok(Some(bytecode_lease));
            }
            return Ok(Some(lease));
        }
        if !directory.starts_with(&bundles_root) {
            break;
        }
        current = directory.parent();
    }
    Ok(retained)
}

async fn find_fresh_bundle(
    artifact_root: &Path,
    entry: &Path,
    format: BundleFormat,
) -> Option<PathBuf> {
    let mut entries = tokio::fs::read_dir(artifact_root).await.ok()?;
    while let Ok(Some(candidate)) = entries.next_entry().await {
        let file_type = candidate.file_type().await.ok()?;
        if !file_type.is_dir() || candidate.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let candidate_path = candidate.path();
        let _gate = acquire_bundle_artifact_gate(&candidate_path).await.ok()?;
        let output = bundle_entry_path(&candidate_path, format);
        if bundle_cache_is_fresh(&output, entry).await {
            std::fs::write(candidate_path.join(".last-used"), []).ok();
            return Some(output);
        }
    }
    None
}

/// Copy the per-package chunk siblings a chunked bundle emitted — the
/// `__ibexpkg__*` package chunks and the shared `rolldown-runtime.js` — from the
/// bundle entry's directory into `dest_dir`. A flat `.hbc` produced by
/// `ibex build` lives away from its cache-dir chunks; the run path sets
/// `__exactChunkDir` to the artifact's own directory, so the chunks must sit next
/// to the built `.hbc` or the entry's `require('__ibexpkg__…')` fails to resolve.
/// The copied set is exactly what the loader's chunk-redirect recognizes
/// (module-loader.js). Returns the number of chunk files copied. (ENG-22760)
/// @ref LLP 0013#mechanism-3
pub(crate) fn ship_chunk_siblings(bundle_entry: &Path, dest_dir: &Path) -> Result<usize> {
    let Some(src_dir) = bundle_entry.parent() else {
        return Ok(0);
    };
    // No-op when the bundle already lives in the destination (an in-place run).
    if src_dir == dest_dir {
        return Ok(0);
    }
    std::fs::create_dir_all(dest_dir)?;
    let mut copied = 0usize;
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Mirror the loader's recognized chunk set; any other file (the entry
        // bundle, a source map) is not a chunk and must not be copied.
        let is_chunk = name_str.starts_with("__ibexpkg__") || name_str == "rolldown-runtime.js";
        if !is_chunk || !entry.file_type()?.is_file() {
            continue;
        }
        std::fs::copy(entry.path(), dest_dir.join(&name)).with_context(|| {
            format!(
                "failed to copy chunk {} into {}",
                name_str,
                dest_dir.display()
            )
        })?;
        copied += 1;
    }
    Ok(copied)
}

fn transpile_esm_to_script(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut import_id = 0usize;
    let mut export_block_depth: Option<usize> = None;

    for line in source.split_inclusive('\n') {
        let trimmed = line.trim_start();

        if let Some(depth) = export_block_depth.as_mut() {
            *depth = update_export_block_depth(*depth, line);
            if *depth == 0 {
                export_block_depth = None;
            }
            continue;
        }

        if trimmed.starts_with("import ") {
            if let Some(imported) = transpile_esm_import_statement(trimmed, &mut import_id) {
                output.push_str(&imported);
            }
            continue;
        }

        if trimmed.starts_with("export {") {
            let remaining_depth = update_export_block_depth(0, line);
            if remaining_depth != 0 {
                export_block_depth = Some(remaining_depth);
            }
            continue;
        }

        if trimmed.starts_with("export * from ") || trimmed == "export {}" {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("export ") {
            if let Some(prefix_len) = line.find("export ") {
                output.push_str(&line[..prefix_len]);
                output.push_str(rest);
                if line.ends_with('\n') {
                    output.push('\n');
                }
                continue;
            }
        }

        output.push_str(line);
    }

    output
}

fn update_export_block_depth(mut depth: usize, line: &str) -> usize {
    let mut chars = line.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template = false;
    let mut escaping = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            break;
        }

        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }

        if escaping {
            escaping = false;
            continue;
        }

        if in_single_quote {
            if ch == '\\' {
                escaping = true;
            } else if ch == '\'' {
                in_single_quote = false;
            }
            continue;
        }

        if in_double_quote {
            if ch == '\\' {
                escaping = true;
            } else if ch == '"' {
                in_double_quote = false;
            }
            continue;
        }

        if in_template {
            if ch == '\\' {
                escaping = true;
            } else if ch == '`' {
                in_template = false;
            }
            continue;
        }

        if ch == '/' {
            match chars.peek().copied() {
                Some('/') => {
                    chars.next();
                    in_line_comment = true;
                    continue;
                }
                Some('*') => {
                    chars.next();
                    in_block_comment = true;
                    continue;
                }
                _ => {}
            }
        }

        match ch {
            '\'' => in_single_quote = true,
            '"' => in_double_quote = true,
            '`' => in_template = true,
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    depth
}

fn transpile_esm_import_statement(line: &str, import_id: &mut usize) -> Option<String> {
    let line = line.trim();
    if !line.starts_with("import ") {
        return None;
    }

    let body = line
        .trim_start_matches("import ")
        .trim()
        .trim_end_matches(';')
        .trim();
    if body.is_empty() {
        return None;
    }

    if !body.contains(" from ") {
        return Some(format!("globalThis.require({});\n", body));
    }

    let mut parts = body.splitn(2, " from ");
    let imports = parts.next()?.trim();
    let module = parts.next()?.trim().trim_end_matches(';');
    if imports.is_empty() {
        return Some(format!("globalThis.require({});\n", module));
    }

    if imports.starts_with("* as ") {
        let alias = imports.trim_start_matches("* as ").trim();
        return Some(format!("const {alias} = globalThis.require({module});\n"));
    }

    if imports.starts_with('{') && imports.ends_with('}') {
        // Convert ESM `as` aliases to destructuring `:` syntax.
        // e.g. `{ setTimeout as setTimeout$1 }` → `{ setTimeout: setTimeout$1 }`
        let destructured = convert_import_as_to_destructure(imports);
        return Some(format!(
            "const {destructured} = globalThis.require({module});\n"
        ));
    }

    if let Some((default_name, named_part)) = imports.split_once(',') {
        let default_name = default_name.trim();
        let named_part = named_part.trim();
        if default_name.is_empty() {
            return None;
        }

        let module_var = format!("__ex_module_{import_id}");
        *import_id += 1;
        let mut out = String::new();
        out.push_str(&format!(
            "const {module_var} = globalThis.require({module});\n"
        ));
        out.push_str(&format!(
            "const {default_name} = {module_var}.default ?? {module_var};\n"
        ));
        if named_part.starts_with('{') && named_part.ends_with('}') {
            out.push_str(&format!("const {named_part} = {module_var};\n"));
        } else if named_part.starts_with("* as ") {
            let alias = named_part.trim_start_matches("* as ").trim();
            out.push_str(&format!("const {alias} = {module_var};\n"));
        }
        return Some(out);
    }

    Some(format!(
        "const {imports} = globalThis.require({module}).default ?? globalThis.require({module});\n"
    ))
}

/// Convert ESM import `as` aliases to destructuring `:` syntax.
/// E.g. `{ setTimeout as setTimeout$1, foo }` → `{ setTimeout: setTimeout$1, foo }`
fn convert_import_as_to_destructure(imports: &str) -> String {
    // Strip outer braces, process each binding, re-wrap
    let inner = imports.trim_start_matches('{').trim_end_matches('}').trim();
    let bindings: Vec<String> = inner
        .split(',')
        .map(|b| {
            let b = b.trim();
            if let Some((orig, alias)) = b.split_once(" as ") {
                format!("{}: {}", orig.trim(), alias.trim())
            } else {
                b.to_string()
            }
        })
        .collect();
    format!("{{ {} }}", bindings.join(", "))
}

fn unique_bundle_stage_dir(artifact_root: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    artifact_root.join(format!(
        ".stage-{}-{seq}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ))
}

fn cached_directory_size(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => cached_directory_size(&entry.path()),
            Ok(file_type) if file_type.is_file() => {
                entry.metadata().map(|metadata| metadata.len()).unwrap_or(0)
            }
            _ => 0,
        })
        .sum()
}

fn cleanup_abandoned_bundle_temp_dirs(bundles_root: &Path) {
    let Ok(keys) = std::fs::read_dir(bundles_root) else {
        return;
    };
    for key in keys.filter_map(|entry| entry.ok()) {
        let Ok(children) = std::fs::read_dir(key.path()) else {
            continue;
        };
        for child in children.filter_map(|entry| entry.ok()) {
            let name = child.file_name().to_string_lossy().into_owned();
            let owner = [".stage-", ".invalid-", ".evict-"]
                .iter()
                .find_map(|prefix| {
                    name.strip_prefix(prefix)
                        .and_then(|rest| rest.split('-').next())
                        .and_then(|pid| pid.parse::<u32>().ok())
                });
            if owner.is_some_and(|pid| !process_is_running(pid)) {
                std::fs::remove_dir_all(child.path()).ok();
            }
        }
    }
}

fn prune_bundle_cache_to_limit(bundles_root: &Path, keep: &Path, limit: u64) {
    cleanup_abandoned_bundle_temp_dirs(bundles_root);
    let Ok(keys) = std::fs::read_dir(bundles_root) else {
        return;
    };
    let mut artifacts = Vec::new();
    for key in keys.filter_map(|entry| entry.ok()) {
        let Ok(children) = std::fs::read_dir(key.path()) else {
            continue;
        };
        for child in children.filter_map(|entry| entry.ok()) {
            let path = child.path();
            let Ok(metadata) = child.metadata() else {
                continue;
            };
            if path == keep
                || !metadata.is_dir()
                || child.file_name().to_string_lossy().starts_with('.')
            {
                continue;
            }
            let recency = std::fs::metadata(path.join(".last-used"))
                .and_then(|marker| marker.modified())
                .or_else(|_| metadata.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            artifacts.push((recency, cached_directory_size(&path), path));
        }
    }
    // Include active stages/gates/quarantines in accounting even though only
    // completed, unlocked artifacts are eviction candidates.
    let mut total = cached_directory_size(bundles_root);
    artifacts.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in artifacts {
        if total <= limit {
            break;
        }
        let Ok(Some(gate)) = try_acquire_bundle_artifact_gate(&path) else {
            continue;
        };
        if bundle_artifact_has_live_lease(&path) {
            drop(gate);
            continue;
        }
        let quarantine = path.with_file_name(format!(
            ".evict-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0),
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("artifact")
        ));
        let renamed = std::fs::rename(&path, &quarantine).is_ok();
        drop(gate);
        if renamed && std::fs::remove_dir_all(&quarantine).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

fn enforce_bundle_cache_quota(artifact_root: &Path, keep: &Path) {
    const DEFAULT_LIMIT: u64 = 512 * 1024 * 1024;
    let limit = std::env::var("IBEX_BUNDLE_CACHE_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LIMIT);
    if let Some(bundles_root) = artifact_root.parent() {
        prune_bundle_cache_to_limit(bundles_root, keep, limit);
    }
}

async fn run_bundler(
    entry: &Path,
    artifact_root: &Path,
    bundle_format: BundleFormat,
) -> Result<PathBuf> {
    run_bundler_with_source_provenance(entry, artifact_root, bundle_format, None).await
}

async fn run_bundler_with_source_provenance(
    entry: &Path,
    artifact_root: &Path,
    bundle_format: BundleFormat,
    source_provenance_authority: Option<&BundleSourceProvenanceAuthority>,
) -> Result<PathBuf> {
    run_bundler_with_source_provenance_mode(
        entry,
        artifact_root,
        bundle_format,
        source_provenance_authority,
        BundlePublicationMode::ReusableCache,
        None,
    )
    .await
}

/// Compile one authenticated generated entry into a caller-owned fresh root.
/// A graph-named directory appearing before our atomic publication is a hard
/// collision, never a cache hit.
async fn run_fresh_bundler_with_source_provenance(
    entry: &Path,
    artifact_root: &Path,
    bundle_format: BundleFormat,
    source_provenance_authority: &BundleSourceProvenanceAuthority,
) -> Result<PathBuf> {
    run_bundler_with_source_provenance_mode(
        entry,
        artifact_root,
        bundle_format,
        Some(source_provenance_authority),
        BundlePublicationMode::FreshPrivate,
        None,
    )
    .await
}

struct BundleCaptureBarrier {
    entry: PathBuf,
    directory: PathBuf,
}

#[cfg(test)]
async fn run_bundler_with_test_capture_barrier(
    entry: &Path,
    artifact_root: &Path,
    bundle_format: BundleFormat,
    barrier_entry: &Path,
    barrier_directory: &Path,
) -> Result<PathBuf> {
    let barrier = BundleCaptureBarrier {
        entry: barrier_entry.to_path_buf(),
        directory: barrier_directory.to_path_buf(),
    };
    run_bundler_with_source_provenance_mode(
        entry,
        artifact_root,
        bundle_format,
        None,
        BundlePublicationMode::ReusableCache,
        Some(&barrier),
    )
    .await
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum BundlePublicationMode {
    ReusableCache,
    FreshPrivate,
}

fn configure_js_tool_environment(
    command: &mut tokio::process::Command,
    private_environment: &Path,
) {
    // Bundler and policy outputs are executed or authenticated downstream.
    // Start from no inherited environment: a denylist cannot enumerate every
    // Node/Bun/native-loader injection control, and PATH is unnecessary because
    // the selected runner is an authenticated absolute path.
    // @ref LLP 0023#6-path-bearing-observables
    command.env_clear();
    command
        .env("HOME", private_environment)
        .env("XDG_CONFIG_HOME", private_environment)
        .env("XDG_CACHE_HOME", private_environment)
        .env("TMPDIR", private_environment)
        .env("TMP", private_environment)
        .env("TEMP", private_environment)
        .env("BUN_RUNTIME_TRANSPILER_CACHE_PATH", private_environment)
        .env("NODE_DISABLE_COMPILE_CACHE", "1")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC");
    #[cfg(windows)]
    command
        .env("USERPROFILE", private_environment)
        .env("APPDATA", private_environment)
        .env("LOCALAPPDATA", private_environment);
}

async fn run_bundler_with_source_provenance_mode(
    entry: &Path,
    artifact_root: &Path,
    bundle_format: BundleFormat,
    source_provenance_authority: Option<&BundleSourceProvenanceAuthority>,
    publication_mode: BundlePublicationMode,
    test_capture_barrier: Option<&BundleCaptureBarrier>,
) -> Result<PathBuf> {
    if entry.to_str().is_none() || artifact_root.to_str().is_none() {
        anyhow::bail!(
            "Bundling/cache publication does not support non-UTF-8 paths: entry={}, cache={}",
            entry.display(),
            artifact_root.display()
        );
    }
    let toolchain = bundler_toolchain_identity()?;
    verify_bundler_toolchain_identity(&toolchain)?;
    let runner = toolchain.runner.clone();
    let runner_name = toolchain.runner_name;
    let script = bundler_script_path()?;
    let working_dir = bundler_working_dir()?;
    let timeout = timeout_from_env("EXACT_BUNDLER_TIMEOUT_MS", DEFAULT_BUNDLER_TIMEOUT_MS);

    tokio::fs::create_dir_all(artifact_root)
        .await
        .with_context(|| format!("Failed to create {}", artifact_root.display()))?;
    let stage_dir = unique_bundle_stage_dir(artifact_root);
    tokio::fs::create_dir(&stage_dir)
        .await
        .with_context(|| format!("Failed to create bundle stage {}", stage_dir.display()))?;
    let output = bundle_entry_path(&stage_dir, bundle_format);

    let source_provenance_input = if let Some(authority) = source_provenance_authority {
        let bytes = authority.canonical_bytes()?;
        let digest = sha256_bytes(&bytes);
        let path = stage_dir.join(".source-provenance-authority.json");
        tokio::fs::write(&path, bytes)
            .await
            .context("failed to stage source-provenance authority")?;
        Some((path, digest))
    } else {
        None
    };

    let private_runner_environment = {
        let path = stage_dir.join(".runner-environment");
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&path).with_context(|| {
            format!(
                "failed to create authenticated bundler environment {}",
                path.display()
            )
        })?;
        path
    };
    let private_bun_config = if runner_name == "bun" {
        let path = private_runner_environment.join("bunfig.toml");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| {
                use std::io::Write as _;
                file.write_all(b"# intentionally empty authenticated bundler config\n")
            })
            .with_context(|| format!("failed to create private Bun config {}", path.display()))?;
        Some(path)
    } else {
        None
    };

    let mut command = tokio::process::Command::new(&runner);
    if let Some(config) = private_bun_config.as_ref() {
        command.arg("--no-env-file").arg(format!(
            "--config={}",
            config
                .to_str()
                .context("private Bun config path is not UTF-8")?
        ));
    }
    command
        .arg(&script)
        .arg("--entry")
        .arg(entry)
        .arg("--out")
        .arg(&output)
        .arg("--format")
        .arg(bundle_format.as_str())
        .arg("--sourcemap")
        .arg("--cache-manifest")
        .current_dir(&working_dir);
    configure_js_tool_environment(&mut command, &private_runner_environment);
    if let Some(barrier) = test_capture_barrier {
        // This explicitly scoped hook exercises cache-publication races. It
        // is never sourced from the process environment, so a parallel
        // bundler cannot inherit another test's temporary paths.
        debug_assert!(publication_mode == BundlePublicationMode::ReusableCache);
        command
            .env("IBEX_TEST_BUNDLE_BARRIER_ENTRY", &barrier.entry)
            .env("IBEX_TEST_BUNDLE_BARRIER_DIR", &barrier.directory);
    }
    if let Some((authority_path, authority_digest)) = source_provenance_input.as_ref() {
        command
            .arg("--source-provenance-authority")
            .arg(authority_path)
            .arg("--source-provenance-authority-sha256")
            .arg(authority_digest);
    }
    // @ref LLP 0013#mechanism-2 — when the runtime boots with lockdown, bundle
    // package (node_modules) code through the per-package compartment rewrite so
    // its bare globals resolve against the runtime compartment registry.
    command.arg("--compartments");
    // @ref LLP 0013#mechanism-3 — per-package chunking so a bundled app gets
    // per-package frame attribution (each package chunk loads into its own
    // Domain). Auto-enabled under enforce/audit (see enable_isolation_prereqs);
    // `IBEX_PER_PACKAGE_CHUNKS=0` opts out. iife can't split; the bundler
    // ignores the flag there.
    command.arg("--per-package-chunks");
    let cmd_output_result = output_with_timeout(
        &mut command,
        timeout,
        &format!("bundler via {}", runner_name),
    )
    .await;
    // Compiler configuration is private scratch, not a cache member.
    tokio::fs::remove_dir_all(&private_runner_environment)
        .await
        .with_context(|| {
            format!(
                "failed to remove private bundler environment {}",
                private_runner_environment.display()
            )
        })?;
    if let Some((authority_path, _)) = source_provenance_input.as_ref() {
        // This file contains backing roots and must never become a published
        // cache member. The child has exited, so no consumer retains it.
        if let Err(error) = tokio::fs::remove_file(authority_path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tokio::fs::remove_dir_all(&stage_dir).await.ok();
                return Err(error).context(
                    "failed to remove private source-provenance authority before publication",
                );
            }
        }
    }
    let cmd_output = match cmd_output_result {
        Ok(output) => output,
        Err(error) => {
            tokio::fs::remove_dir_all(&stage_dir).await.ok();
            return Err(error);
        }
    };

    if let Err(error) = verify_bundler_toolchain_identity(&toolchain) {
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        return Err(error).context("Bundler toolchain changed while producing cache output");
    }

    if !cmd_output.status.success() {
        let stderr = String::from_utf8_lossy(&cmd_output.stderr);
        let stdout = String::from_utf8_lossy(&cmd_output.stdout);
        let combined = format!("{}{}", stderr, stdout);
        let mut context = serde_json::Map::new();
        context.insert(
            "entry".to_string(),
            serde_json::Value::String(entry.display().to_string()),
        );
        context.insert(
            "output".to_string(),
            serde_json::Value::String(output.display().to_string()),
        );
        context.insert(
            "format".to_string(),
            serde_json::Value::String(bundle_format.as_str().to_string()),
        );
        context.insert(
            "status".to_string(),
            serde_json::Value::String(cmd_output.status.to_string()),
        );
        agent_logs::record_bundler_log(
            "error",
            format!(
                "Bundler exited with status {}: {}",
                cmd_output.status, combined
            ),
            Some(context),
        );
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        anyhow::bail!(
            "Bundler exited with status {}: {}",
            cmd_output.status,
            combined
        );
    }

    if !bundle_cache_is_fresh_with_source_provenance(&output, entry, source_provenance_authority)
        .await
    {
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        anyhow::bail!(
            "Bundler did not produce a complete digest-verified artifact in {}",
            stage_dir.display()
        );
    }
    let manifest = read_bundle_manifest(&output).await?;
    if let Some((_, expected_authority_digest)) = source_provenance_input.as_ref() {
        let provenance = manifest
            .source_provenance
            .as_ref()
            .context("bundler omitted authenticated per-original source provenance")?;
        anyhow::ensure!(
            manifest.version == 4 && provenance.authority_digest == *expected_authority_digest,
            "bundler source provenance does not match its authenticated authority input"
        );
    }
    let final_dir = artifact_root.join(&manifest.graph_digest);
    let final_output = bundle_entry_path(&final_dir, bundle_format);
    let gate = acquire_bundle_artifact_gate(&final_dir).await?;
    let mut quarantined = None;
    if final_dir.exists() {
        if publication_mode == BundlePublicationMode::FreshPrivate {
            tokio::fs::remove_dir_all(&stage_dir).await.ok();
            anyhow::bail!(
                "Fresh authenticated generated artifact collided before publication: {}",
                final_dir.display()
            );
        }
        if bundle_cache_is_fresh_with_source_provenance(
            &final_output,
            entry,
            source_provenance_authority,
        )
        .await
        {
            tokio::fs::remove_dir_all(&stage_dir).await.ok();
            std::fs::write(final_dir.join(".last-used"), []).ok();
            drop(gate);
            enforce_bundle_cache_quota(artifact_root, &final_dir);
            return Ok(final_output);
        }
        if bundle_artifact_has_live_lease(&final_dir) {
            tokio::fs::remove_dir_all(&stage_dir).await.ok();
            anyhow::bail!(
                "Cannot repair invalid bundle artifact {} while another process holds a live lease",
                final_dir.display()
            );
        }
        let quarantine = final_dir.with_file_name(format!(
            ".invalid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        tokio::fs::rename(&final_dir, &quarantine)
            .await
            .with_context(|| {
                format!(
                    "Failed to quarantine invalid bundle artifact {}",
                    final_dir.display()
                )
            })?;
        quarantined = Some(quarantine);
    }
    if let Err(error) = tokio::fs::rename(&stage_dir, &final_dir).await {
        if let Some(quarantine) = quarantined.as_ref() {
            let _ = tokio::fs::rename(quarantine, &final_dir).await;
        }
        return Err(error).with_context(|| {
            format!(
                "Failed to atomically publish bundle cache {}",
                final_dir.display()
            )
        });
    }
    if let Some(quarantine) = quarantined {
        tokio::fs::remove_dir_all(quarantine).await.ok();
    }
    if publication_mode == BundlePublicationMode::ReusableCache {
        std::fs::write(final_dir.join(".last-used"), []).ok();
    }
    drop(gate);
    if publication_mode == BundlePublicationMode::ReusableCache {
        enforce_bundle_cache_quota(artifact_root, &final_dir);
    }
    Ok(final_output)
}

fn bundler_script_path() -> Result<PathBuf> {
    let root = repo_root()?;
    authenticated_repo_file(
        &root,
        Path::new("packages/ibex-devtools/src/scripts/rolldown-bundle.mjs"),
    )
}

/// `ibex policy generate|check` — runs the LLP 0014 policy generator with the
/// same JS-runner resolution as the bundler. The generator's exit code is the
/// command's exit code (`check` uses 1 for drift, the CI-gate contract).
/// @ref LLP 0014#runtime-and-cli
pub async fn run_policy_command(command: &crate::cli::PolicyCommands) -> Result<()> {
    use crate::cli::PolicyCommands;

    let toolchain = policy_authoring_toolchain()?;
    let script = &toolchain.script;
    let runner = &toolchain.runner;
    let runner_name = toolchain.runner_name;
    let private_environment = FreshGeneratedArtifactRoot::create(&std::env::temp_dir())?;

    let compiled_entry = match command {
        PolicyCommands::Generate {
            entry,
            target_triple: Some(_),
            ..
        }
        | PolicyCommands::Check {
            entry,
            target_triple: Some(_),
            ..
        } => Some(entry),
        _ => None,
    };
    let authenticated_graph_snapshot = if let Some(entry) = compiled_entry {
        let path = private_environment
            .path()
            .join("authenticated-graph-snapshot.canonical.json");
        let bytes = crate::sfe::capture_compiled_policy_snapshot(entry)
            .context("failed to capture the compiled policy graph")?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| {
                use std::io::Write as _;
                file.write_all(&bytes)
            })
            .with_context(|| {
                format!(
                    "failed to publish private policy graph snapshot {}",
                    path.display()
                )
            })?;
        Some(path)
    } else {
        None
    };

    let mut cmd = tokio::process::Command::new(&runner);
    configure_js_tool_environment(&mut cmd, private_environment.path());
    cmd.current_dir(std::env::current_dir().context("failed to capture policy working directory")?);
    if runner_name == "bun" {
        let bun_config = private_environment.path().join("bunfig.toml");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&bun_config)
            .and_then(|mut file| {
                use std::io::Write as _;
                file.write_all(b"# intentionally empty authenticated policy config\n")
            })
            .with_context(|| {
                format!(
                    "failed to create private Bun policy config {}",
                    bun_config.display()
                )
            })?;
        cmd.arg("--no-env-file").arg(format!(
            "--config={}",
            bun_config
                .to_str()
                .context("private Bun policy config path is not UTF-8")?
        ));
    }
    cmd.arg(&script);
    if let Some(snapshot) = authenticated_graph_snapshot.as_ref() {
        cmd.arg("--authenticated-graph-snapshot").arg(snapshot);
    }
    match command {
        PolicyCommands::Generate {
            entry,
            out,
            mode,
            target_profile,
            target_triple,
            mount_profile,
        } => {
            cmd.arg("--entry").arg(entry);
            if let Some(out) = out {
                cmd.arg("--out").arg(out);
            }
            if let Some(mode) = mode {
                cmd.arg("--mode").arg(mode);
            }
            if let Some(profile) = target_profile {
                cmd.arg("--target-profile").arg(profile);
            }
            if let Some(target) = target_triple {
                cmd.arg("--target-triple").arg(target);
            }
            if let Some(mount) = mount_profile {
                cmd.arg("--mount-profile").arg(mount);
            }
        }
        PolicyCommands::Check {
            entry,
            out,
            mode,
            target_profile,
            target_triple,
            mount_profile,
        } => {
            cmd.arg("--entry").arg(entry).arg("--check");
            if let Some(out) = out {
                cmd.arg("--out").arg(out);
            }
            // Forward the mode so the regenerated artifact stamps the same
            // `mode` the committed one carries — else an audit-mode policy
            // false-drifts against an enforce-default regeneration. (ENG-22642)
            if let Some(mode) = mode {
                cmd.arg("--mode").arg(mode);
            }
            if let Some(profile) = target_profile {
                cmd.arg("--target-profile").arg(profile);
            }
            if let Some(target) = target_triple {
                cmd.arg("--target-triple").arg(target);
            }
            if let Some(mount) = mount_profile {
                cmd.arg("--mount-profile").arg(mount);
            }
        }
    }
    // Inherit stdio: the generator's report is the user-facing output.
    let status = cmd
        .status()
        .await
        .context("failed to spawn the policy generator")?;
    toolchain.verify_after_execution()?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

struct PolicyAuthoringToolchain {
    runner: PathBuf,
    runner_name: &'static str,
    script: PathBuf,
    packaged_root: Option<PathBuf>,
}

impl PolicyAuthoringToolchain {
    fn verify_after_execution(&self) -> Result<()> {
        let Some(root) = self.packaged_root.as_ref() else {
            return Ok(());
        };
        let digest = RELEASE_POLICY_TOOLCHAIN_DIGEST
            .context("release policy-toolchain verification lost its compiled trust root")?;
        ibex_sfe_catalog::policy_toolchain::admit_policy_toolchain_directory(
            root,
            digest,
            current_policy_toolchain_target()?,
        )
        .context("SFP004 packaged policy toolchain changed during policy authoring")?;
        Ok(())
    }
}

fn policy_authoring_toolchain() -> Result<PolicyAuthoringToolchain> {
    if let Some(digest) = RELEASE_POLICY_TOOLCHAIN_DIGEST {
        let executable =
            std::env::current_exe().context("SFP001 cannot locate the release Ibex executable")?;
        let install_root = executable
            .parent()
            .context("SFP001 release Ibex executable has no installation directory")?;
        let directory_name =
            ibex_sfe_catalog::policy_toolchain::policy_toolchain_directory_name(digest)
                .context("SFP001 compiled policy-toolchain trust root is invalid")?;
        let root = install_root.join(directory_name);
        let admitted =
            ibex_sfe_catalog::policy_toolchain::admit_policy_toolchain_directory(
                &root,
                digest,
                current_policy_toolchain_target()?,
            )
            .with_context(|| {
                format!(
                    "SFP002 packaged policy author unavailable: install the policy-toolchain directory next to {}",
                    executable.display()
                )
            })?;
        return Ok(PolicyAuthoringToolchain {
            runner: admitted.runner,
            runner_name: "bun",
            script: admitted.script,
            packaged_root: Some(root),
        });
    }

    let root = repo_root()?;
    let script = authenticated_repo_file(
        &root,
        Path::new("packages/ibex-devtools/src/scripts/generate-policy.mjs"),
    )?;
    let (runner, runner_name) = find_js_runner()?;
    Ok(PolicyAuthoringToolchain {
        runner,
        runner_name,
        script,
        packaged_root: None,
    })
}

fn current_policy_toolchain_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        (os, arch) => {
            anyhow::bail!("SFP003 no standalone policy-toolchain target exists for {os}-{arch}")
        }
    }
}

fn bundler_working_dir() -> Result<PathBuf> {
    let root = repo_root()?;
    let legacy_js_dir = root.join("js");
    if legacy_js_dir.is_dir() {
        return Ok(legacy_js_dir);
    }
    Ok(root)
}

#[derive(Clone)]
struct CapturedJsRunnerSelection {
    path: PathBuf,
    name: &'static str,
}

fn discover_js_runner() -> Result<CapturedJsRunnerSelection> {
    let search_path =
        std::env::var_os("PATH").context("PATH is unavailable while capturing the JS runner")?;
    let cwd = std::env::current_dir().context("failed to capture the runner search directory")?;
    #[cfg(windows)]
    let candidates = [("node.exe", "node"), ("bun.exe", "bun")];
    #[cfg(not(windows))]
    let candidates = [("bun", "bun"), ("node", "node")];
    for (executable, name) in candidates {
        let Ok(path) = which::which_in(executable, Some(&search_path), &cwd) else {
            continue;
        };
        let path = std::fs::canonicalize(&path)
            .with_context(|| format!("failed to capture JS runner {}", path.display()))?;
        return Ok(CapturedJsRunnerSelection { path, name });
    }
    anyhow::bail!("bun or node is required to run the bundler")
}

fn captured_js_runner_selection() -> Result<CapturedJsRunnerSelection> {
    static CAPTURED: std::sync::OnceLock<std::result::Result<CapturedJsRunnerSelection, String>> =
        std::sync::OnceLock::new();
    CAPTURED
        .get_or_init(|| discover_js_runner().map_err(|error| format!("{error:#}")))
        .clone()
        .map_err(anyhow::Error::msg)
}

/// Freeze PATH-based runner selection before any worker, Host, or engine can
/// execute project code. The selected path is only an operator-trusted input;
/// BundlerToolchainIdentity is the trust boundary that hashes the canonical
/// runner and full tool tree and re-verifies them before and after execution.
pub(crate) fn capture_bundler_runner_selection() {
    let _ = captured_js_runner_selection();
}

fn find_js_runner() -> Result<(PathBuf, &'static str)> {
    let selection = captured_js_runner_selection()?;
    Ok((selection.path, selection.name))
}

fn repo_root() -> Result<PathBuf> {
    fn find_from(start: &Path) -> Option<PathBuf> {
        start.ancestors().find_map(|ancestor| {
            if ancestor.join("vendored-generated").is_dir()
                && ancestor
                    .join("packages")
                    .join("ibex-runtime-js")
                    .join("package.json")
                    .is_file()
                && ancestor
                    .join("packages")
                    .join("ibex-devtools")
                    .join("package.json")
                    .is_file()
            {
                std::fs::canonicalize(ancestor).ok()
            } else {
                None
            }
        })
    }

    if let Some(raw) =
        std::env::var_os("IBEX_REPO_ROOT").or_else(|| std::env::var_os("EXACT_REPO_ROOT"))
    {
        let root = PathBuf::from(raw);
        if !root.is_absolute() {
            anyhow::bail!("IBEX_REPO_ROOT must be an absolute authenticated directory");
        }
        return find_from(&root).ok_or_else(|| {
            anyhow::anyhow!(
                "IBEX_REPO_ROOT does not identify an Ibex checkout: {}",
                root.display()
            )
        });
    }

    // The compile-time checkout is authenticated by the build. Never inspect
    // the application cwd or its ancestors: an app can create a lookalike
    // packages/ tree and otherwise select executable bundler code (the same
    // confused-tool-discovery class as ENG-24254's fake Hermes compiler).
    if let Some(found) = find_from(Path::new(env!("CARGO_MANIFEST_DIR"))) {
        return Ok(found);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(found) = find_from(&exe_path) {
            return Ok(found);
        }
    }

    anyhow::bail!(
        "Failed to resolve an authenticated Ibex tooling root. Set IBEX_REPO_ROOT to an absolute trusted checkout"
    )
}

fn authenticated_repo_file(root: &Path, relative: &Path) -> Result<PathBuf> {
    let canonical_root = std::fs::canonicalize(root).with_context(|| {
        format!(
            "Failed to authenticate Ibex tooling root {}",
            root.display()
        )
    })?;
    let candidate = canonical_root.join(relative);
    let canonical = std::fs::canonicalize(&candidate)
        .with_context(|| format!("Ibex tooling file not found at {}", candidate.display()))?;
    if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
        anyhow::bail!(
            "Ibex tooling file {} escapes authenticated root {}",
            canonical.display(),
            canonical_root.display()
        );
    }
    Ok(canonical)
}

static RUNTIME_CACHE_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

fn resolved_runtime_cache_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_dir {
        anyhow::ensure!(
            path.is_absolute(),
            "--runtime-cache-dir must be an absolute trusted path"
        );
        return Ok(path.to_path_buf());
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join("Library").join("Caches").join("Ibex"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("ibex"));
        }
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(".cache").join("ibex"));
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("ibex"));
        }
    }

    anyhow::bail!("Failed to determine cache directory")
}

/// Capture the operator-selected runtime cache before any execution path can
/// materialize code or security artifacts. The selected directory is later
/// canonicalized and authenticated against every JavaScript-mounted root.
// @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings — the cache is operator-selectable but never a JavaScript mount
pub fn configure_runtime_cache_dir(override_dir: Option<&Path>) -> Result<()> {
    let mut selected = resolved_runtime_cache_dir(override_dir)?;
    if override_dir.is_some() {
        std::fs::create_dir_all(&selected).with_context(|| {
            format!(
                "failed to create operator-selected runtime cache {}",
                selected.display()
            )
        })?;
        let metadata = std::fs::symlink_metadata(&selected)?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "--runtime-cache-dir must name a real directory, not a symlink or file"
        );
        selected = std::fs::canonicalize(&selected).with_context(|| {
            format!(
                "failed to authenticate operator-selected runtime cache {}",
                selected.display()
            )
        })?;
    }
    if let Some(existing) = RUNTIME_CACHE_DIR_OVERRIDE.get() {
        anyhow::ensure!(
            existing == &selected,
            "runtime cache directory changed after process initialization"
        );
        return Ok(());
    }
    RUNTIME_CACHE_DIR_OVERRIDE
        .set(selected)
        .map_err(|_| anyhow::anyhow!("runtime cache directory changed during initialization"))
}

/// Return the process-lifetime runtime cache selection.
pub fn runtime_cache_dir() -> Result<PathBuf> {
    if let Some(path) = RUNTIME_CACHE_DIR_OVERRIDE.get() {
        return Ok(path.clone());
    }
    resolved_runtime_cache_dir(None)
}

pub(crate) fn authenticate_build_runtime_cache(cli: &Cli, entry: &str) -> Result<PathBuf> {
    let entry = std::fs::canonicalize(entry)
        .with_context(|| format!("failed to authenticate build entry path {entry}"))?;
    let project = authenticated_project_root_discovery_for_entry(cli, Some(&entry))?;
    emit_project_root_discovery_diagnostic(&project);
    let cache = runtime_cache_dir()?;
    std::fs::create_dir_all(&cache).with_context(|| {
        format!(
            "failed to create binary runtime cache root {}",
            cache.display()
        )
    })?;
    ibex_runtime::cache_topology::authenticate_internal_cache_root(
        &cache,
        std::slice::from_ref(&project.selected_root),
    )
    .context("build cache overlaps the authenticated project tree")
}

/// Compute default output path for `ibex build`.
pub fn compute_build_output(file: &str, outdir: Option<&Path>) -> Result<PathBuf> {
    let entry_path = Path::new(file);
    let stem = entry_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid entry file"))?;

    let output_dir = outdir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dist"));

    if !output_dir.exists() {
        std::fs::create_dir_all(&output_dir)?;
    }

    Ok(output_dir.join(format!("{}.hbc", stem)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;
    use tempfile::tempdir;

    #[test]
    fn runtime_cache_override_requires_an_absolute_operator_path() {
        let error = resolved_runtime_cache_dir(Some(Path::new("relative/cache")))
            .expect_err("relative cache selection must fail closed")
            .to_string();
        assert!(
            error.contains("must be an absolute trusted path"),
            "{error}"
        );

        let absolute = std::env::temp_dir().join("ibex-runtime-cache-contract");
        assert_eq!(
            resolved_runtime_cache_dir(Some(&absolute)).unwrap(),
            absolute
        );
    }

    #[test]
    fn package_graph_projects_only_explicit_root_imports_as_root_edges() {
        let package_a = serde_json::json!({
            "kind": "package",
            "name": "package-a",
            "integrity": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "locator": "package-a@1.0.0",
        });
        let package_b = serde_json::json!({
            "kind": "package",
            "name": "package-b",
            "integrity": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
            "locator": "package-b@1.0.0",
        });
        let principals = vec![
            serde_json::json!({
                "principal": package_a,
                "imports": {"builtins": [], "packages": ["package-b@1.0.0"]},
            }),
            serde_json::json!({
                "principal": package_b,
                "imports": {"builtins": [], "packages": []},
            }),
        ];
        let edges =
            policy_package_graph_edges(&principals, &["package-a@1.0.0".to_owned()]).unwrap();
        assert_eq!(edges.len(), 6, "three typed modes per declared edge");

        let root = serde_json::json!({"kind": "root", "identity": "project-root"});
        assert_eq!(
            edges
                .iter()
                .filter(|edge| edge["importer"] == root && edge["imported"] == package_a)
                .count(),
            3,
        );
        assert_eq!(
            edges
                .iter()
                .filter(|edge| edge["importer"] == package_a && edge["imported"] == package_b)
                .count(),
            3,
        );
        assert!(edges
            .iter()
            .all(|edge| !(edge["importer"] == root && edge["imported"] == package_b)));
    }

    #[cfg(unix)]
    #[test]
    fn bundles_subroot_refuses_preexisting_symlink_redirect() {
        use std::os::unix::fs::symlink;

        let cache = tempdir().unwrap();
        let project = tempdir().unwrap();
        symlink(project.path(), cache.path().join("bundles")).unwrap();
        let error = ensure_real_internal_cache_subdirectory(cache.path(), "bundles")
            .expect_err("bundle cache must not follow a preexisting subroot symlink");
        assert!(
            error.to_string().contains("must be a real directory"),
            "unexpected error: {error:#}"
        );
    }

    #[cfg(all(feature = "module-runner", unix))]
    #[test]
    fn module_producer_digest_refuses_a_replaced_executable_path() {
        let directory = tempdir().unwrap();
        let executable_path = directory.path().join("producer");
        let mapped_path = directory.path().join("producer.mapped");
        std::fs::write(&executable_path, b"mapped producer A").unwrap();
        let expected =
            module_producer_file_state(&std::fs::metadata(&executable_path).unwrap()).object;

        std::fs::rename(&executable_path, &mapped_path).unwrap();
        std::fs::write(&executable_path, b"replacement producer B").unwrap();
        let error =
            capture_module_producer_binary_digest_from_path(&executable_path, expected, true)
                .expect_err("a replacement pathname must not relabel the mapped producer");
        assert!(
            error
                .to_string()
                .contains("different object than the running image"),
            "unexpected replacement error: {error:#}"
        );

        assert_eq!(
            capture_module_producer_binary_digest_from_path(&mapped_path, expected, true).unwrap(),
            ibex_runtime::module_loader::artifact::digest_bytes(
                "ibex/module-producer-binary/1",
                b"mapped producer A",
            )
            .unwrap()
        );
    }

    #[cfg(all(feature = "module-runner", windows))]
    #[test]
    fn windows_module_producer_digest_refuses_a_replaced_executable_path() {
        let directory = tempdir().unwrap();
        let executable_path = directory.path().join("producer.exe");
        let mapped_path = directory.path().join("producer.mapped.exe");
        std::fs::write(&executable_path, b"mapped producer A").unwrap();
        let original = open_windows_module_producer(&executable_path).unwrap();
        let expected = windows_module_producer_file_state(&original)
            .unwrap()
            .object;
        drop(original);

        std::fs::rename(&executable_path, &mapped_path).unwrap();
        std::fs::write(&executable_path, b"replacement producer B").unwrap();
        let error = capture_windows_module_producer_digest_from_path(&executable_path, &expected)
            .expect_err("a replacement pathname must not relabel the mapped producer");
        assert!(
            error
                .to_string()
                .contains("different object than the running image"),
            "unexpected replacement error: {error:#}"
        );

        assert_eq!(
            capture_windows_module_producer_digest_from_path(&mapped_path, &expected).unwrap(),
            ibex_runtime::module_loader::artifact::digest_bytes(
                "ibex/module-producer-binary/1",
                b"mapped producer A",
            )
            .unwrap()
        );
    }

    #[cfg(feature = "module-runner")]
    #[test]
    fn module_producer_digest_cache_captures_once_and_fails_sticky() {
        use capsec_semantics::model::Digest;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        const CALLERS: usize = 8;
        let cache: Arc<OnceLock<std::result::Result<Digest, String>>> = Arc::new(OnceLock::new());
        let captures = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(CALLERS));
        let expected = ibex_runtime::module_loader::artifact::digest_bytes(
            "ibex/module-producer-binary/1",
            b"one producer",
        )
        .unwrap();
        let threads = (0..CALLERS)
            .map(|_| {
                let cache = cache.clone();
                let captures = captures.clone();
                let barrier = barrier.clone();
                let expected = expected.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    cached_module_producer_binary_digest(&cache, || {
                        captures.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        Ok(expected)
                    })
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), expected);
        }
        assert_eq!(captures.load(Ordering::SeqCst), 1);

        let failed: OnceLock<std::result::Result<Digest, String>> = OnceLock::new();
        let first = cached_module_producer_binary_digest(&failed, || {
            anyhow::bail!("mapped object unavailable")
        })
        .unwrap_err();
        let second = cached_module_producer_binary_digest(&failed, || {
            panic!("a failed process identity must not be recaptured mid-process")
        })
        .unwrap_err();
        assert_eq!(first.to_string(), second.to_string());
    }

    #[cfg(all(feature = "module-runner", feature = "insecure"))]
    #[test]
    fn insecure_module_producer_identity_is_the_transform_contract() {
        assert_eq!(
            module_producer_binary_digest().unwrap(),
            ibex_runtime::module_loader::producer_spike::module_artifact_transform_fingerprint_v1()
                .unwrap()
                .digest()
                .unwrap()
        );
    }

    fn test_source_provenance_authority(project_root: &Path) -> BundleSourceProvenanceAuthority {
        use capsec_semantics::model::{LogicalRoot, NonEmptyString, Principal};

        BundleSourceProvenanceAuthority {
            schema: "ibex/source-provenance-authority/1",
            armed_snapshot_digest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            package_graph_digest: "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA".to_owned(),
            root_identity: Principal::Root {
                identity: NonEmptyString::new("portable-test-project").unwrap(),
            },
            bindings: vec![BundleSourceProvenanceAuthorityBinding {
                logical_root: LogicalRoot::Project,
                owner: None,
                backing_root: std::fs::canonicalize(project_root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            }],
        }
    }

    fn bind_snapshot_fixture_project_root(
        value: &mut serde_json::Value,
        origin: &Path,
        project_root: &Path,
        marker_kind: &str,
        marker_path: Option<&Path>,
    ) {
        let project_path = runtime_authenticated_host_path(project_root).unwrap();
        let project_binding = value["rootBindings"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|binding| binding["logicalRoot"] == "project")
            .unwrap();
        project_binding["hostPath"] = serde_json::to_value(&project_path).unwrap();
        project_binding["object"] = runtime_object_identity_json(project_root).unwrap();

        // Keep fixture package bindings beneath the substituted project root.
        // The package suffix is stable fixture data; the project prefix is the
        // authenticated launch binding this helper is replacing.
        for binding in value["rootBindings"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .filter(|binding| binding["logicalRoot"] == "package")
        {
            let old = binding["hostPath"]["components"]
                .as_array()
                .unwrap()
                .clone();
            let suffix = old
                .iter()
                .position(|component| component["value"] == "node_modules")
                .map(|start| old[start..].to_vec())
                .unwrap();
            let mut rebased = runtime_path_components_json(project_root).unwrap();
            rebased.extend(suffix);
            binding["hostPath"] = serde_json::json!({
                "root": "absolute",
                "components": rebased,
                "hostBound": true,
            });
        }

        // External-snapshot tests cross the production bound-volume probe.
        // Materialize package roots and stamp every fixture binding with the
        // actual object identity observed at its host path; a caller-supplied
        // platform/volume claim is intentionally not trusted.
        for binding in value["rootBindings"].as_array_mut().unwrap() {
            let decoded: capsec_semantics::arming::ArmedRootBinding =
                serde_json::from_value(binding.clone()).unwrap();
            let host_path = runtime_host_path_from_logical(&decoded.host_path).unwrap();
            if decoded.logical_root == capsec_semantics::model::LogicalRoot::Package {
                std::fs::create_dir_all(&host_path).unwrap();
            }
            binding["object"] = runtime_object_identity_json(&host_path).unwrap();
        }

        value["projectRootDiscovery"] = serde_json::json!({
            "origin": runtime_authenticated_host_path(origin).unwrap(),
            "selectedRoot": project_path,
            "markerKind": marker_kind,
            "markerPath": marker_path
                .map(runtime_authenticated_host_path)
                .transpose()
                .unwrap(),
            "markerSetVersion": PROJECT_ROOT_MARKER_SET_VERSION,
        });
        let bindings: Vec<capsec_semantics::arming::ArmedRootBinding> =
            serde_json::from_value(value["rootBindings"].clone()).unwrap();
        value["pathCanonicalizers"] = serde_json::to_value(
            capsec_semantics::path_alias::contract_fixture_canonicalizer_rows(
                bindings
                    .iter()
                    .map(|binding| (binding.object.platform, binding.object.volume.clone())),
            )
            .unwrap(),
        )
        .unwrap();
    }

    #[derive(Default)]
    struct WindowsMinimalBootstrapEngine {
        evaluated: std::sync::Mutex<Vec<String>>,
        runtime_loaded: AtomicBool,
    }

    #[async_trait::async_trait]
    impl Engine for WindowsMinimalBootstrapEngine {
        fn name(&self) -> &str {
            "windows-minimal-bootstrap-test"
        }

        fn version(&self) -> Result<String> {
            Ok("test".to_string())
        }

        async fn load_runtime(&self) -> Result<()> {
            anyhow::bail!("the Windows minimal bootstrap must not load the full runtime")
        }

        async fn eval(&self, _code: &str) -> Result<Option<String>> {
            anyhow::bail!("the Windows minimal bootstrap must use immediate evaluation")
        }

        async fn eval_immediate(&self, code: &str) -> Result<Option<String>> {
            self.evaluated.lock().unwrap().push(code.to_string());
            if code == WINDOWS_RUNTIME_LOADED_PROBE {
                Ok(Some(self.runtime_loaded.load(Ordering::SeqCst).to_string()))
            } else if code == WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP {
                self.runtime_loaded.store(true, Ordering::SeqCst);
                Ok(None)
            } else if code == crate::engine::hermes::FINALIZE_COMPARTMENT_BASELINE {
                Ok(Some("true".to_string()))
            } else {
                anyhow::bail!("unexpected bootstrap script")
            }
        }

        async fn run_file(&self, _path: &str) -> Result<Option<String>> {
            anyhow::bail!("unexpected file evaluation")
        }

        async fn start_inspector(&self, _host: &str, _port: u16) -> Result<()> {
            anyhow::bail!("unexpected inspector start")
        }

        async fn stop_inspector(&self) -> Result<()> {
            anyhow::bail!("unexpected inspector stop")
        }

        fn supports_feature(&self, _feature: EngineFeature) -> bool {
            false
        }
    }

    #[cfg(not(windows))]
    #[derive(Default)]
    struct IdempotentRuntimeLoadEngine {
        evaluated: std::sync::Mutex<Vec<String>>,
        load_calls: std::sync::atomic::AtomicUsize,
    }

    #[cfg(not(windows))]
    #[async_trait::async_trait]
    impl Engine for IdempotentRuntimeLoadEngine {
        fn name(&self) -> &str {
            "runtime-load-idempotence-test"
        }

        fn version(&self) -> Result<String> {
            Ok("test".to_string())
        }

        async fn load_runtime(&self) -> Result<()> {
            self.load_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn eval(&self, _code: &str) -> Result<Option<String>> {
            anyhow::bail!("runtime preload must use immediate evaluation")
        }

        async fn eval_immediate(&self, code: &str) -> Result<Option<String>> {
            self.evaluated.lock().unwrap().push(code.to_owned());
            Ok(None)
        }

        async fn run_file(&self, _path: &str) -> Result<Option<String>> {
            anyhow::bail!("unexpected file evaluation")
        }

        async fn start_inspector(&self, _host: &str, _port: u16) -> Result<()> {
            anyhow::bail!("unexpected inspector start")
        }

        async fn stop_inspector(&self) -> Result<()> {
            anyhow::bail!("unexpected inspector stop")
        }

        fn supports_feature(&self, _feature: EngineFeature) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct InspectorProbeEngine {
        starts: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Engine for InspectorProbeEngine {
        fn name(&self) -> &str {
            "inspector-probe-test"
        }

        fn version(&self) -> Result<String> {
            Ok("test".to_owned())
        }

        async fn load_runtime(&self) -> Result<()> {
            Ok(())
        }

        async fn eval(&self, _code: &str) -> Result<Option<String>> {
            Ok(None)
        }

        async fn run_file(&self, _path: &str) -> Result<Option<String>> {
            Ok(None)
        }

        async fn start_inspector(&self, _host: &str, _port: u16) -> Result<()> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn stop_inspector(&self) -> Result<()> {
            Ok(())
        }

        fn supports_feature(&self, _feature: EngineFeature) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct FileProgramSettlementProbeEngine {
        drive_calls: std::sync::atomic::AtomicUsize,
        ready_drive_calls: std::sync::atomic::AtomicUsize,
        async_failure_calls: std::sync::atomic::AtomicUsize,
        async_failures: std::sync::Mutex<Vec<crate::engine::AuthenticatedAsyncFailure>>,
        async_failures_after_drive: std::sync::Mutex<Vec<crate::engine::AuthenticatedAsyncFailure>>,
        async_failure_error_on_call: usize,
        drain_failure: Option<FileProgramDrainProbeFailure>,
        ready_drive_failure: bool,
        ready_lifecycle: Option<(ibex_runtime::session_lifecycle::SessionLifecyclePort, i32)>,
    }

    #[derive(Clone, Copy)]
    enum FileProgramDrainProbeFailure {
        Unhandled,
        EngineFault,
    }

    impl FileProgramSettlementProbeEngine {
        fn with_async_failure(summary: &str) -> Self {
            Self {
                async_failures: std::sync::Mutex::new(vec![
                    crate::engine::AuthenticatedAsyncFailure::capture_unavailable(summary),
                ]),
                ..Self::default()
            }
        }

        fn with_async_failure_after_drive(summary: &str) -> Self {
            Self {
                async_failures_after_drive: std::sync::Mutex::new(vec![
                    crate::engine::AuthenticatedAsyncFailure::capture_unavailable(summary),
                ]),
                ..Self::default()
            }
        }

        fn with_pre_receipt_loss(count: u64) -> Self {
            Self {
                async_failures: std::sync::Mutex::new(vec![
                    crate::engine::AuthenticatedAsyncFailure::PreReceiptLoss { count },
                ]),
                ..Self::default()
            }
        }

        fn with_async_failure_collection_error_on_call(call: usize) -> Self {
            Self {
                async_failure_error_on_call: call,
                ..Self::default()
            }
        }

        fn with_drain_and_collection_failures(drain_failure: FileProgramDrainProbeFailure) -> Self {
            Self {
                async_failure_error_on_call: 2,
                drain_failure: Some(drain_failure),
                ..Self::default()
            }
        }

        fn with_ready_lifecycle_and_drive_failure(
            lifecycle: ibex_runtime::session_lifecycle::SessionLifecyclePort,
            status: i32,
        ) -> Self {
            Self {
                ready_drive_failure: true,
                ready_lifecycle: Some((lifecycle, status)),
                ..Self::default()
            }
        }
    }

    #[async_trait::async_trait]
    impl Engine for FileProgramSettlementProbeEngine {
        fn name(&self) -> &str {
            "file-program-settlement-probe"
        }

        fn version(&self) -> Result<String> {
            Ok("test".to_owned())
        }

        async fn load_runtime(&self) -> Result<()> {
            Ok(())
        }

        async fn eval(&self, _code: &str) -> Result<Option<String>> {
            anyhow::bail!("file settlement must not use bare evaluation")
        }

        async fn take_authenticated_async_failures(
            &self,
        ) -> Result<Vec<crate::engine::AuthenticatedAsyncFailure>> {
            let call = self.async_failure_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.async_failure_error_on_call {
                anyhow::bail!("probe asynchronous failure collection failed on call {call}");
            }
            Ok(std::mem::take(&mut *self.async_failures.lock().unwrap()))
        }

        async fn drive_ready_tasks(&self) -> Result<()> {
            self.ready_drive_calls.fetch_add(1, Ordering::SeqCst);
            let delayed = std::mem::take(&mut *self.async_failures_after_drive.lock().unwrap());
            self.async_failures.lock().unwrap().extend(delayed);
            if let Some((lifecycle, status)) = &self.ready_lifecycle {
                let _ = lifecycle.request_exit(
                    ibex_runtime::session_lifecycle::LifecyclePrincipal::Root,
                    *status,
                );
            }
            if self.ready_drive_failure {
                anyhow::bail!("ready poll reported the paired lifecycle stop")
            }
            Ok(())
        }

        async fn drive_authenticated_program_to_quiescence(
            &self,
        ) -> std::result::Result<(), crate::engine::AuthenticatedProgramDrainFailure> {
            self.drive_calls.fetch_add(1, Ordering::SeqCst);
            let delayed = std::mem::take(&mut *self.async_failures_after_drive.lock().unwrap());
            self.async_failures.lock().unwrap().extend(delayed);
            match self.drain_failure {
                None => Ok(()),
                Some(FileProgramDrainProbeFailure::Unhandled) => {
                    Err(crate::engine::AuthenticatedProgramDrainFailure::Unhandled(
                        anyhow::anyhow!("primary program drain failure"),
                    ))
                }
                Some(FileProgramDrainProbeFailure::EngineFault) => Err(
                    crate::engine::AuthenticatedProgramDrainFailure::EngineFault(anyhow::anyhow!(
                        "primary program drain engine fault"
                    )),
                ),
            }
        }

        async fn run_file(&self, _path: &str) -> Result<Option<String>> {
            anyhow::bail!("file settlement must not use bare file evaluation")
        }

        async fn start_inspector(&self, _host: &str, _port: u16) -> Result<()> {
            anyhow::bail!("unexpected inspector start")
        }

        async fn stop_inspector(&self) -> Result<()> {
            Ok(())
        }

        fn supports_feature(&self, _feature: EngineFeature) -> bool {
            false
        }
    }

    #[test]
    fn lifecycle_accepted_during_file_release_survives_cleanup_failure() {
        use ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT;
        use ibex_runtime::session_lifecycle::{
            LifecyclePrincipal, LifecycleRequestDisposition, SessionLifecyclePort,
        };

        let lifecycle = SessionLifecyclePort::default();
        let request_before_release = lifecycle.take_pending_request();
        assert!(request_before_release.is_none());
        assert!(matches!(
            lifecycle.request_exit(LifecyclePrincipal::Root, 41),
            LifecycleRequestDisposition::Accepted { .. }
        ));
        let outcome = authenticated_file_release_outcome(
            &lifecycle,
            request_before_release,
            Some(anyhow::anyhow!("release failed after lifecycle commit")),
        )
        .expect("a lifecycle accepted during release must settle the program");
        let AuthenticatedFileProgramOutcome::Lifecycle {
            status,
            secondary_diagnostics,
        } = outcome
        else {
            panic!("cleanup failure replaced the accepted lifecycle cause")
        };
        assert_eq!(status, 41);
        assert_eq!(secondary_diagnostics.len(), 1);
        assert!(secondary_diagnostics[0].contains("release failed after lifecycle commit"));

        let no_lifecycle = authenticated_file_release_outcome(
            &SessionLifecyclePort::default(),
            None,
            Some(anyhow::anyhow!("primary release failure")),
        )
        .expect("a release failure without lifecycle must settle as a fault");
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = no_lifecycle else {
            panic!("an unowned release failure must remain an engine fault")
        };
        assert_eq!(status, EXIT_STATUS_ENGINE_FAULT);
        assert!(diagnostic.contains("primary release failure"));
    }

    #[tokio::test]
    async fn authenticated_file_program_settlement_preserves_primary_cause() {
        use crate::engine::AuthenticatedEvaluation;
        use ibex_runtime::session_constants::EXIT_STATUS_NON_INTERACTIVE_FAILURE;
        use ibex_runtime::session_lifecycle::{
            LifecycleGetDisposition, LifecyclePrincipal, LifecycleRequestDisposition,
            LifecycleSetDisposition, SessionLifecyclePort,
        };

        // Normal completion drains and checks the structured failure channel,
        // but leaves the orderly exitCode mirror for the CLI owner to resolve.
        let normal_engine = FileProgramSettlementProbeEngine::default();
        let normal_lifecycle = SessionLifecyclePort::default();
        assert_eq!(
            normal_lifecycle.set_exit_code(LifecyclePrincipal::Root, 5),
            LifecycleSetDisposition::Accepted { status: 5 }
        );
        assert_eq!(
            settle_authenticated_file_program(
                &normal_engine,
                &normal_lifecycle,
                Ok(AuthenticatedEvaluation::Empty),
            )
            .await
            .unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(
            normal_lifecycle.get_exit_code(LifecyclePrincipal::Root),
            LifecycleGetDisposition::Value(5)
        );
        assert_eq!(normal_engine.drive_calls.load(Ordering::SeqCst), 1);
        assert_eq!(normal_engine.async_failure_calls.load(Ordering::SeqCst), 2);

        // A foreground lifecycle outcome carries its own status and does not
        // enter the ordinary completion drain.
        let lifecycle_engine = FileProgramSettlementProbeEngine::default();
        let lifecycle = SessionLifecyclePort::default();
        assert!(matches!(
            lifecycle.request_exit(LifecyclePrincipal::Root, 7),
            LifecycleRequestDisposition::Accepted { .. }
        ));
        assert_eq!(
            settle_authenticated_file_program(
                &lifecycle_engine,
                &lifecycle,
                Ok(AuthenticatedEvaluation::Lifecycle(7)),
            )
            .await
            .unwrap(),
            authenticated_file_lifecycle(7)
        );
        assert!(!lifecycle.has_pending_request());
        assert_eq!(lifecycle_engine.drive_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            lifecycle_engine.async_failure_calls.load(Ordering::SeqCst),
            1
        );

        // A cooperative request published while evaluation was in flight is
        // latched before any further program work can introduce a later cause.
        let pending_lifecycle_engine = FileProgramSettlementProbeEngine::default();
        let pending_lifecycle = SessionLifecyclePort::default();
        assert!(matches!(
            pending_lifecycle.request_exit(LifecyclePrincipal::Root, 11),
            LifecycleRequestDisposition::Accepted { .. }
        ));
        assert_eq!(
            settle_authenticated_file_program(
                &pending_lifecycle_engine,
                &pending_lifecycle,
                Ok(AuthenticatedEvaluation::Empty),
            )
            .await
            .unwrap(),
            authenticated_file_lifecycle(11)
        );
        assert!(!pending_lifecycle.has_pending_request());
        assert_eq!(
            pending_lifecycle_engine.drive_calls.load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            pending_lifecycle_engine
                .async_failure_calls
                .load(Ordering::SeqCst),
            1
        );

        // A failure already published while evaluation was suspended wins
        // before a later foreground outcome and is drained exactly once.
        let pre_outcome_engine = FileProgramSettlementProbeEngine::with_async_failure("early");
        let pre_outcome_lifecycle = SessionLifecyclePort::default();
        let outcome = settle_authenticated_file_program(
            &pre_outcome_engine,
            &pre_outcome_lifecycle,
            Ok(AuthenticatedEvaluation::Cancelled),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = outcome else {
            panic!("an already-published asynchronous failure must win")
        };
        assert_eq!(status, EXIT_STATUS_NON_INTERACTIVE_FAILURE);
        assert!(diagnostic.contains("early"));
        assert_eq!(pre_outcome_engine.drive_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            pre_outcome_engine
                .async_failure_calls
                .load(Ordering::SeqCst),
            1
        );

        // An unhandled asynchronous failure is the primary termination cause:
        // it exits 1 even when user code selected a nonzero orderly exitCode.
        let async_engine = FileProgramSettlementProbeEngine::with_async_failure_after_drive("boom");
        let async_lifecycle = SessionLifecyclePort::default();
        assert_eq!(
            async_lifecycle.set_exit_code(LifecyclePrincipal::Root, 7),
            LifecycleSetDisposition::Accepted { status: 7 }
        );
        let outcome = settle_authenticated_file_program(
            &async_engine,
            &async_lifecycle,
            Ok(AuthenticatedEvaluation::Empty),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = outcome else {
            panic!("async failure must produce a fixed file-program failure")
        };
        assert_eq!(status, EXIT_STATUS_NON_INTERACTIVE_FAILURE);
        assert!(diagnostic.contains("unhandled asynchronous file-program failure"));
        assert!(diagnostic.contains("boom"));
        assert_eq!(
            async_lifecycle.get_exit_code(LifecyclePrincipal::Root),
            LifecycleGetDisposition::Value(7),
            "the failed cause overrides rather than mutating orderly exitCode"
        );
        assert_eq!(async_engine.drive_calls.load(Ordering::SeqCst), 1);
        assert_eq!(async_engine.async_failure_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn authenticated_file_keep_alive_tick_settles_lifecycle_and_async_failure() {
        use ibex_runtime::session_constants::EXIT_STATUS_NON_INTERACTIVE_FAILURE;
        use ibex_runtime::session_lifecycle::SessionLifecyclePort;

        // Hermes currently pairs its authenticated lifecycle record with a
        // negative ready-poll return. The Host record remains authoritative and
        // the generic drive error must not replace it with status 70.
        let lifecycle = SessionLifecyclePort::default();
        let lifecycle_engine =
            FileProgramSettlementProbeEngine::with_ready_lifecycle_and_drive_failure(
                lifecycle.clone(),
                29,
            );
        assert_eq!(
            settle_authenticated_file_keep_alive_tick(&lifecycle_engine, &lifecycle).await,
            Some(authenticated_file_lifecycle(29))
        );
        assert_eq!(lifecycle_engine.ready_drive_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            lifecycle_engine.async_failure_calls.load(Ordering::SeqCst),
            2
        );

        // A callback failure published by the ready turn is a fixed
        // non-interactive failure, rather than falling through to the file's
        // already-completed outcome and orderly exitCode.
        let async_engine =
            FileProgramSettlementProbeEngine::with_async_failure_after_drive("keep-alive boom");
        let outcome = settle_authenticated_file_keep_alive_tick(
            &async_engine,
            &SessionLifecyclePort::default(),
        )
        .await
        .expect("the asynchronous failure must terminate keep-alive");
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = outcome else {
            panic!("the keep-alive asynchronous failure lost its fixed status")
        };
        assert_eq!(status, EXIT_STATUS_NON_INTERACTIVE_FAILURE);
        assert!(diagnostic.contains("keep-alive boom"));
        assert_eq!(async_engine.ready_drive_calls.load(Ordering::SeqCst), 1);
        assert_eq!(async_engine.async_failure_calls.load(Ordering::SeqCst), 2);

        let idle_engine = FileProgramSettlementProbeEngine::default();
        assert_eq!(
            settle_authenticated_file_keep_alive_tick(
                &idle_engine,
                &SessionLifecyclePort::default(),
            )
            .await,
            None
        );
    }

    #[tokio::test]
    async fn authenticated_file_program_collection_faults_preserve_fixed_causes() {
        use crate::engine::AuthenticatedEvaluation;
        use ibex_runtime::session_constants::{
            EXIT_STATUS_ENGINE_FAULT, EXIT_STATUS_INTERRUPT, EXIT_STATUS_NON_INTERACTIVE_FAILURE,
        };
        use ibex_runtime::session_lifecycle::SessionLifecyclePort;

        let evaluation_engine =
            FileProgramSettlementProbeEngine::with_async_failure_collection_error_on_call(1);
        let outcome = settle_authenticated_file_program(
            &evaluation_engine,
            &SessionLifecyclePort::default(),
            Err(AuthenticatedEvaluationFailure::EngineFault(
                anyhow::anyhow!("primary evaluation engine fault"),
            )),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = outcome else {
            panic!("evaluation engine fault must remain fixed")
        };
        assert_eq!(status, EXIT_STATUS_ENGINE_FAULT);
        assert!(diagnostic.contains("primary evaluation engine fault"));
        assert!(diagnostic.contains("collection failed"));

        let refusal_engine =
            FileProgramSettlementProbeEngine::with_async_failure_collection_error_on_call(1);
        let outcome = settle_authenticated_file_program(
            &refusal_engine,
            &SessionLifecyclePort::default(),
            Err(AuthenticatedEvaluationFailure::Refusal(anyhow::anyhow!(
                "primary evaluation refusal"
            ))),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = outcome else {
            panic!("evaluation refusal must remain fixed")
        };
        assert_eq!(status, EXIT_STATUS_NON_INTERACTIVE_FAILURE);
        assert!(diagnostic.contains("primary evaluation refusal"));
        assert!(diagnostic.contains("collection failed"));

        let cancellation_engine =
            FileProgramSettlementProbeEngine::with_async_failure_collection_error_on_call(1);
        let outcome = settle_authenticated_file_program(
            &cancellation_engine,
            &SessionLifecyclePort::default(),
            Ok(AuthenticatedEvaluation::Cancelled),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = outcome else {
            panic!("cancellation must remain fixed")
        };
        assert_eq!(status, EXIT_STATUS_INTERRUPT);
        assert!(diagnostic.contains("was cancelled"));
        assert!(diagnostic.contains("collection failed"));

        for (drain_failure, expected_status, primary) in [
            (
                FileProgramDrainProbeFailure::Unhandled,
                EXIT_STATUS_NON_INTERACTIVE_FAILURE,
                "primary program drain failure",
            ),
            (
                FileProgramDrainProbeFailure::EngineFault,
                EXIT_STATUS_ENGINE_FAULT,
                "primary program drain engine fault",
            ),
        ] {
            let engine =
                FileProgramSettlementProbeEngine::with_drain_and_collection_failures(drain_failure);
            let outcome = settle_authenticated_file_program(
                &engine,
                &SessionLifecyclePort::default(),
                Ok(AuthenticatedEvaluation::Empty),
            )
            .await
            .unwrap();
            let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = outcome else {
                panic!("program drain cause must remain fixed")
            };
            assert_eq!(status, expected_status);
            assert!(diagnostic.contains(primary));
            assert!(diagnostic.contains("collection also failed"));
        }
    }

    #[tokio::test]
    async fn authenticated_file_program_collection_fault_without_primary_is_engine_fault() {
        use crate::engine::AuthenticatedEvaluation;
        use ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT;
        use ibex_runtime::session_lifecycle::SessionLifecyclePort;

        let engine =
            FileProgramSettlementProbeEngine::with_async_failure_collection_error_on_call(1);
        let outcome = settle_authenticated_file_program(
            &engine,
            &SessionLifecyclePort::default(),
            Ok(AuthenticatedEvaluation::Empty),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = outcome else {
            panic!("an unowned collection fault must terminate as an engine fault")
        };
        assert_eq!(status, EXIT_STATUS_ENGINE_FAULT);
        assert!(diagnostic.contains("collection failed"));

        let engine = FileProgramSettlementProbeEngine::with_pre_receipt_loss(3);
        let outcome = settle_authenticated_file_program(
            &engine,
            &SessionLifecyclePort::default(),
            Ok(AuthenticatedEvaluation::Empty),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = outcome else {
            panic!("pre-receipt loss must terminate as an engine fault")
        };
        assert_eq!(status, EXIT_STATUS_ENGINE_FAULT);
        assert!(diagnostic.contains("lost 3 asynchronous failure event(s) before receipt"));
    }

    #[tokio::test]
    async fn authenticated_file_program_lifecycle_requires_matching_supervisor_record() {
        use crate::engine::AuthenticatedEvaluation;
        use ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT;
        use ibex_runtime::session_lifecycle::{
            LifecyclePrincipal, LifecycleRequestDisposition, SessionLifecyclePort,
        };

        let missing = settle_authenticated_file_program(
            &FileProgramSettlementProbeEngine::default(),
            &SessionLifecyclePort::default(),
            Ok(AuthenticatedEvaluation::Lifecycle(7)),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = missing else {
            panic!("a lifecycle outcome without a supervisor record must fail closed")
        };
        assert_eq!(status, EXIT_STATUS_ENGINE_FAULT);
        assert!(diagnostic.contains("had no pending supervisor record"));

        let mismatch_port = SessionLifecyclePort::default();
        assert!(matches!(
            mismatch_port.request_exit(LifecyclePrincipal::Root, 9),
            LifecycleRequestDisposition::Accepted { .. }
        ));
        let mismatch = settle_authenticated_file_program(
            &FileProgramSettlementProbeEngine::default(),
            &mismatch_port,
            Ok(AuthenticatedEvaluation::Lifecycle(7)),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Failed { status, diagnostic } = mismatch else {
            panic!("a mismatched lifecycle outcome must fail closed")
        };
        assert_eq!(status, EXIT_STATUS_ENGINE_FAULT);
        assert!(diagnostic.contains("evaluation 7"));
        assert!(diagnostic.contains("supervisor 9"));
        assert!(!mismatch_port.has_pending_request());

        let matching_port = SessionLifecyclePort::default();
        assert!(matches!(
            matching_port.request_exit(LifecyclePrincipal::Root, 11),
            LifecycleRequestDisposition::Accepted { .. }
        ));
        let matching = settle_authenticated_file_program(
            &FileProgramSettlementProbeEngine::with_async_failure_collection_error_on_call(1),
            &matching_port,
            Ok(AuthenticatedEvaluation::Lifecycle(11)),
        )
        .await
        .unwrap();
        let AuthenticatedFileProgramOutcome::Lifecycle {
            status,
            secondary_diagnostics,
        } = matching
        else {
            panic!("a matching lifecycle outcome must preserve its status")
        };
        assert_eq!(status, 11);
        assert_eq!(secondary_diagnostics.len(), 1);
        assert!(secondary_diagnostics[0].contains("collection failed"));
        assert!(!matching_port.has_pending_request());
    }

    fn inspector_probe_runtime(host: Host, engine: Arc<InspectorProbeEngine>) -> Runtime {
        Runtime {
            engine,
            host,
            runtime_bootstrap_loaded: tokio::sync::OnceCell::new(),
            history_startup: crate::history::HistoryPlatformCapture::capture(
                crate::cli::HistoryMode::Off,
                false,
                false,
            )
            .bind_authenticated_project_root(None),
            session_io: None,
            authenticated_project_root: None,
            authenticated_runtime_cache_root: None,
            bundle_format: BundleFormat::Cjs,
            exec_argv: Vec::new(),
            compat_modes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn unarmed_runtime_retains_inspector_dispatch() {
        let engine = Arc::new(InspectorProbeEngine::default());
        let runtime = inspector_probe_runtime(Host::new(HostConfig::default()), engine.clone());

        Runtime::start_inspector(&runtime, "127.0.0.1", 0)
            .await
            .unwrap();

        assert_eq!(engine.starts.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test]
    async fn session_worker_material_runtime_refuses_inspector_before_engine_dispatch() {
        let project = tempdir().unwrap();
        let plan = repl_ingress_test_plan(capsec_semantics::arming::ArmedExecutionMode::Transcript);
        let supervisor_host = armed_repl_ingress_test_host(
            project.path(),
            capsec_semantics::arming::ArmedExecutionMode::Transcript,
        );
        let snapshot = supervisor_host.armed_snapshot().unwrap();
        let material = SessionWorkerRuntimeMaterial {
            snapshot: snapshot.document().clone(),
            expected_identity: expected_identity_from_snapshot(snapshot).unwrap(),
        };
        let application =
            capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(material).unwrap())
                .unwrap();
        let authenticated = authenticated_session_worker_snapshot(&application, plan).unwrap();
        let worker_host = unsafe {
            Host::new_armed_for_test(
                HostConfig {
                    mode: crate::host::SecurityMode::Enforce,
                    ..Default::default()
                },
                authenticated,
            )
        }
        .unwrap();
        let engine = Arc::new(InspectorProbeEngine::default());
        let runtime =
            Runtime::from_authenticated_session_worker_parts(worker_host, engine.clone(), plan);

        let error = Runtime::start_inspector(&runtime, "127.0.0.1", 0)
            .await
            .expect_err("an armed session-worker Runtime must close the inspector");

        assert_eq!(error.to_string(), ARMED_INSPECTOR_CLOSED_MESSAGE);
        assert_eq!(engine.starts.load(Ordering::SeqCst), 0);
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn runtime_load_preload_is_single_shot_after_success() {
        let engine = Arc::new(IdempotentRuntimeLoadEngine::default());
        let runtime = Runtime {
            engine: engine.clone(),
            host: Host::new(HostConfig::default()),
            runtime_bootstrap_loaded: tokio::sync::OnceCell::new(),
            history_startup: crate::history::HistoryPlatformCapture::capture(
                crate::cli::HistoryMode::Off,
                false,
                false,
            )
            .bind_authenticated_project_root(None),
            session_io: None,
            authenticated_project_root: None,
            authenticated_runtime_cache_root: None,
            bundle_format: BundleFormat::Cjs,
            exec_argv: vec!["--test-runtime-flag".to_owned()],
            compat_modes: Vec::new(),
        };

        runtime.load_runtime().await.unwrap();
        runtime.load_runtime().await.unwrap();

        assert_eq!(engine.load_calls.load(Ordering::SeqCst), 1);
        let evaluated = engine.evaluated.lock().unwrap();
        assert_eq!(evaluated.len(), 1);
        for temporary_root in [
            "__exactExecPath",
            "__exactExecArgv",
            "__exactRawArgv0",
            "__exactCompatModes",
        ] {
            assert!(
                evaluated[0].contains(temporary_root),
                "the one trusted preload omitted {temporary_root}"
            );
        }
    }

    #[cfg(all(not(windows), feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_bun_preload_pins_the_canonical_principal_environment_proxy() {
        struct ResetHost;
        impl Drop for ResetHost {
            fn drop(&mut self) {
                crate::host::abi::install_host(Host::strict());
            }
        }

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _environment = ProductionEnvGuard::capture();
        std::env::set_var("NODE_ENV", "host-production-must-not-project");
        let project = tempdir().unwrap();
        let host = armed_ingress_test_host_with_compatibility(
            project.path(),
            capsec_semantics::arming::ArmedEntryKind::Repl,
            "ibex:repl",
            capsec_semantics::arming::ArmedExecutionMode::Transcript,
            &["bun"],
        );
        let digest = host.armed_snapshot().unwrap().digest().as_str().to_owned();
        let compat_modes = host
            .armed_snapshot()
            .unwrap()
            .bootstrap_compatibility_modes()
            .to_vec();
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = ResetHost;
        let engine: Arc<dyn Engine> = Arc::new(
            crate::engine::hermes::HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap(),
        );
        let runtime = Runtime {
            engine,
            host: host.clone(),
            runtime_bootstrap_loaded: tokio::sync::OnceCell::new(),
            history_startup: crate::history::HistoryPlatformCapture::capture(
                crate::cli::HistoryMode::Off,
                false,
                false,
            )
            .bind_authenticated_project_root(None),
            session_io: None,
            authenticated_project_root: None,
            authenticated_runtime_cache_root: None,
            bundle_format: BundleFormat::Cjs,
            exec_argv: Vec::new(),
            compat_modes,
        };

        runtime.load_runtime().await.unwrap();
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence =
            ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone()).unwrap();
        let request = sequence
            .mint_repl(capsec_semantics::model::LogicalPath {
                root: capsec_semantics::model::LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                r#"(function () {
                  var processDescriptor = Object.getOwnPropertyDescriptor(process, 'env');
                  var exactDescriptor = Object.getOwnPropertyDescriptor(Exact, 'env');
                  var bunDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'Bun');
                  var before = process.env;
                  try { process.env = {}; } catch (_error) {}
                  try { Exact.env = {}; } catch (_error) {}
                  try { Bun = {}; } catch (_error) {}
                  try { Object.defineProperty(globalThis, 'Bun', { value: {} }); } catch (_error) {}
                  return JSON.stringify({
                    bunIsExact: Bun === Exact,
                    processIsExact: process.env === Exact.env,
                    processIsBun: process.env === Bun.env,
                    hostNodeEnvWithheld: process.env.NODE_ENV === undefined,
                    principalEnvironmentEmpty: Object.keys(process.env).length === 0,
                    bunVersionPresent: typeof process.versions.bun === 'string',
                    identitySurvivedMutation: before === process.env && Bun === Exact,
                    processDescriptor: {
                      writable: processDescriptor.writable,
                      configurable: processDescriptor.configurable
                    },
                    exactDescriptor: {
                      hasGetter: typeof exactDescriptor.get === 'function',
                      configurable: exactDescriptor.configurable
                    },
                    bunDescriptor: {
                      writable: bunDescriptor.writable,
                      configurable: bunDescriptor.configurable
                    }
                  });
                })()"#
                    .as_bytes()
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let evaluation = runtime
            .engine
            .evaluate_authenticated(&session, request)
            .await
            .unwrap();
        let crate::engine::AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
            panic!("authenticated Bun environment probe did not return: {evaluation:?}")
        };
        assert_eq!(
            display.kind,
            crate::engine::AuthenticatedDisplayKind::String
        );
        let encoded: String = serde_json::from_str(&display.text).unwrap();
        runtime
            .engine
            .release_undisplayed_value(receipt.expect("Bun environment probe value receipt"))
            .await
            .unwrap();
        let observed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            observed,
            serde_json::json!({
                "bunIsExact": true,
                "processIsExact": true,
                "processIsBun": true,
                "hostNodeEnvWithheld": true,
                "principalEnvironmentEmpty": true,
                "bunVersionPresent": true,
                "identitySurvivedMutation": true,
                "processDescriptor": { "writable": false, "configurable": false },
                "exactDescriptor": { "hasGetter": true, "configurable": false },
                "bunDescriptor": { "writable": false, "configurable": false }
            })
        );
    }

    #[tokio::test]
    async fn windows_minimal_bootstrap_runs_once_and_finalizes_each_load() {
        let engine = WindowsMinimalBootstrapEngine::default();

        load_windows_minimal_runtime(&engine).await.unwrap();
        load_windows_minimal_runtime(&engine).await.unwrap();

        let evaluated = engine.evaluated.lock().unwrap();
        assert_eq!(evaluated.len(), 5);
        assert_eq!(evaluated[0], WINDOWS_RUNTIME_LOADED_PROBE);
        assert_eq!(evaluated[1], WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP);
        assert_eq!(
            evaluated[2],
            crate::engine::hermes::FINALIZE_COMPARTMENT_BASELINE
        );
        assert_eq!(evaluated[3], WINDOWS_RUNTIME_LOADED_PROBE);
        assert_eq!(
            evaluated[4],
            crate::engine::hermes::FINALIZE_COMPARTMENT_BASELINE
        );
    }

    /// Scoped typed delay injection for cross-thread runtime-callback
    /// producers (the lib crate's extern is private, so the bin declares the
    /// same C symbol; it only exists in observer builds).
    #[cfg(feature = "capsec-conformance-observer")]
    struct RuntimeCallbackDelayGuard;

    #[cfg(feature = "capsec-conformance-observer")]
    impl RuntimeCallbackDelayGuard {
        fn new(milliseconds: u64) -> Self {
            extern "C" {
                fn ibex_test_set_runtime_callback_delay_ms(milliseconds: u64);
            }
            unsafe { ibex_test_set_runtime_callback_delay_ms(milliseconds) };
            Self
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    impl Drop for RuntimeCallbackDelayGuard {
        fn drop(&mut self) {
            extern "C" {
                fn ibex_test_set_runtime_callback_delay_ms(milliseconds: u64);
            }
            unsafe { ibex_test_set_runtime_callback_delay_ms(0) };
        }
    }

    struct ProductionEnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl ProductionEnvGuard {
        fn capture() -> Self {
            Self(
                [
                    "IBEX_LOCKDOWN",
                    "IBEX_COMPARTMENTS",
                    "IBEX_PER_PACKAGE_CHUNKS",
                    "IBEX_SEAL_SELF_GRANT",
                    "IBEX_ENDOW",
                    "IBEX_REPO_ROOT",
                    "EXACT_REPO_ROOT",
                    "EXACT_COMPAT_TEST",
                    "NODE_ENV",
                ]
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
            )
        }
    }

    impl Drop for ProductionEnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn armed_repl_ingress_test_host(
        project_root: &Path,
        mode: capsec_semantics::arming::ArmedExecutionMode,
    ) -> Host {
        armed_ingress_test_host_with_compatibility(
            project_root,
            capsec_semantics::arming::ArmedEntryKind::Repl,
            "ibex:repl",
            mode,
            &[],
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn armed_ingress_test_host(
        project_root: &Path,
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        entry_identity: &str,
        mode: capsec_semantics::arming::ArmedExecutionMode,
    ) -> Host {
        armed_ingress_test_host_with_compatibility(
            project_root,
            entry_kind,
            entry_identity,
            mode,
            &[],
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn armed_ingress_test_host_with_compatibility(
        project_root: &Path,
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        entry_identity: &str,
        mode: capsec_semantics::arming::ArmedExecutionMode,
        bootstrap_compatibility_modes: &[&str],
    ) -> Host {
        armed_ingress_test_host_with_options(
            project_root,
            entry_kind,
            entry_identity,
            mode,
            bootstrap_compatibility_modes,
            false,
            true,
            true,
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn armed_ingress_test_host_with_root_fs_read(
        project_root: &Path,
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        entry_identity: &str,
        mode: capsec_semantics::arming::ArmedExecutionMode,
    ) -> Host {
        armed_ingress_test_host_with_options(
            project_root,
            entry_kind,
            entry_identity,
            mode,
            &[],
            true,
            true,
            true,
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn armed_ingress_test_host_with_options(
        project_root: &Path,
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        entry_identity: &str,
        mode: capsec_semantics::arming::ArmedExecutionMode,
        bootstrap_compatibility_modes: &[&str],
        grant_root_fs_read: bool,
        allow_fixture_package_dynamic_import: bool,
        allow_fixture_package_commonjs_require: bool,
    ) -> Host {
        use capsec_semantics::arming::{
            ArmedEntry, ArmedSnapshot, ExpectedArmingIdentity, ExpectedProtectedArtifact,
            ProtectedArtifactRole,
        };
        use capsec_semantics::model::{Digest, NonEmptyString};

        let project_root = std::fs::canonicalize(project_root).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        value["workflow"] = serde_json::json!("production");
        value["effectiveMode"] = serde_json::json!("enforce");
        value["bootstrapCompatibilityModes"] = serde_json::json!(bootstrap_compatibility_modes);
        value["entry"] = serde_json::to_value(ArmedEntry {
            kind: entry_kind,
            identity: NonEmptyString::new(entry_identity).unwrap(),
            mode,
        })
        .unwrap();
        if grant_root_fs_read {
            let root = value["principals"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["principal"]["kind"] == "root")
                .expect("fixture snapshot omitted its root authority row");
            root["floor"].as_array_mut().unwrap().insert(
                0,
                serde_json::json!({
                    "cap": "fs:read",
                    "resource": {
                        "kind": "path-tree",
                        "path": {"root": "project", "components": []},
                    },
                }),
            );
            let builtins = root["imports"]["builtins"].as_array_mut().unwrap();
            builtins.push(serde_json::json!("node:fs"));
            builtins.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            builtins.dedup();
        }
        bind_snapshot_fixture_project_root(
            &mut value,
            &project_root,
            &project_root,
            "explicit-project",
            Some(&project_root),
        );
        let root_bindings = value["rootBindings"].as_array().unwrap().clone();
        let project_components = root_bindings
            .iter()
            .find(|binding| binding["logicalRoot"] == "project")
            .unwrap()["hostPath"]["components"]
            .as_array()
            .unwrap()
            .clone();
        for node in value["packageGraph"]["nodes"].as_array_mut().unwrap() {
            let principal = node["principal"].clone();
            let binding = root_bindings
                .iter()
                .find(|binding| binding.get("owner") == Some(&principal))
                .unwrap();
            let package_components = binding["hostPath"]["components"].as_array().unwrap();
            let (logical_root, relative) = package_components
                .strip_prefix(project_components.as_slice())
                .map(|relative| ("project", relative.to_vec()))
                .unwrap_or_else(|| ("package", Vec::new()));
            node["resolvingSpecifier"] = principal["name"].clone();
            node["rootObject"] = binding["object"].clone();
            node["virtualAliases"] = serde_json::json!([{
                "root": logical_root,
                "components": relative,
            }]);
            node["platformDisposition"] = serde_json::json!("required");
        }
        let mut typed_edges = Vec::new();
        for edge in value["packageGraph"]["importEdges"].as_array().unwrap() {
            let request = edge["imported"]["name"].as_str().unwrap();
            for (kind, conditions) in [
                ("common-js-require", vec!["node", "require"]),
                ("dynamic-import", vec!["import", "node"]),
                ("esm-static", vec!["import", "node"]),
            ] {
                if kind == "dynamic-import" && !allow_fixture_package_dynamic_import {
                    continue;
                }
                if kind == "common-js-require" && !allow_fixture_package_commonjs_require {
                    continue;
                }
                typed_edges.push(serde_json::json!({
                    "importer": edge["importer"],
                    "imported": edge["imported"],
                    "requestSpecifier": request,
                    "resolutionKind": kind,
                    "conditions": conditions,
                    "attributes": {},
                }));
            }
        }
        value["packageGraph"]["importEdges"] = serde_json::Value::Array(typed_edges);
        value["packageGraph"]["digest"] = serde_json::Value::String(
            capsec_semantics::digest::compute_domain_digest(
                "ibex:capsec:package-graph:1",
                &value["packageGraph"],
                &["digest".to_owned()],
            )
            .unwrap(),
        );
        let digest = capsec_semantics::digest::compute_checked_contract_digest(
            capsec_semantics::digest::DigestKind::ArmedSnapshot,
            &value,
        )
        .unwrap();
        value["armedSnapshotDigest"] = serde_json::json!(digest);
        let digest_at = |path: &[&str]| {
            let field = path
                .iter()
                .fold(&value, |current, segment| &current[*segment]);
            Digest::new(field.as_str().unwrap()).unwrap()
        };
        let protected_artifacts = value["protectedObjects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let role: ProtectedArtifactRole =
                    serde_json::from_value(row["role"].clone()).unwrap();
                let content_digest = match role {
                    ProtectedArtifactRole::EngineBinary => digest_at(&["engine", "binaryDigest"]),
                    ProtectedArtifactRole::ExactOperationManifest => {
                        digest_at(&["exactEmbedder", "operationManifestDigest"])
                    }
                    ProtectedArtifactRole::ArmedPolicy => digest_at(&["policyDigest"]),
                    ProtectedArtifactRole::PackageGraph => digest_at(&["packageGraph", "digest"]),
                    ProtectedArtifactRole::Registry => digest_at(&["registryDigest"]),
                    ProtectedArtifactRole::RuntimeExtensionAuthorityCapsule => {
                        digest_at(&["runtimeExtensions", "authorityCapsuleDigest"])
                    }
                };
                ExpectedProtectedArtifact {
                    role,
                    host_path: serde_json::from_value(serde_json::json!({
                        "root": "absolute",
                        "components": [
                            {"encoding": "utf8", "value": "fixture"},
                            {"encoding": "utf8", "value": row["role"].as_str().unwrap()}
                        ],
                        "hostBound": true,
                    }))
                    .unwrap(),
                    object: serde_json::from_value(row["object"].clone()).unwrap(),
                    content_digest,
                }
            })
            .collect();
        let expected = ExpectedArmingIdentity {
            profile: value["capsVocab"].as_str().unwrap().into(),
            semantic_core: value["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest_at(&["vocabDigest"]),
            registry_digest: digest_at(&["registryDigest"]),
            policy_digest: digest_at(&["policyDigest"]),
            armed_snapshot_digest: digest_at(&["armedSnapshotDigest"]),
            target: value["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: value["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            entry: serde_json::from_value(value["entry"].clone()).unwrap(),
            project_root_discovery: serde_json::from_value(value["projectRootDiscovery"].clone())
                .unwrap(),
            path_canonicalizers: serde_json::from_value(value["pathCanonicalizers"].clone())
                .unwrap(),
            protected_artifacts,
            embedded_protected_artifacts: Vec::new(),
            runtime_extension_authority_digest: None,
            runtime_extension_mapped_executable: None,
        };
        let snapshot =
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();
        // SAFETY: this unit-test fixture authenticates the complete snapshot
        // above and intentionally substitutes complete target cells so the
        // ingress seam can be tested without a production target artifact.
        unsafe {
            Host::new_armed_for_test(
                HostConfig {
                    mode: crate::host::SecurityMode::Enforce,
                    ..Default::default()
                },
                Arc::new(snapshot),
            )
        }
        .unwrap()
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn repl_ingress_test_plan(
        mode: capsec_semantics::arming::ArmedExecutionMode,
    ) -> crate::terminal_session::SessionIoPlan {
        ingress_test_plan(capsec_semantics::arming::ArmedEntryKind::Repl, mode)
    }

    /// Build the exact armed engine/ingress pair used by executable session
    /// conformance tests without promoting a pending target advertisement.
    /// The returned Host must remain alive for the complete engine lifetime.
    #[cfg(feature = "capsec-conformance-observer")]
    pub(crate) fn session_conformance_repl_parts(
        project_root: &Path,
    ) -> Result<(Host, Arc<dyn Engine>, ReplSessionIngress)> {
        session_conformance_repl_parts_for_mode(
            project_root,
            capsec_semantics::arming::ArmedExecutionMode::Transcript,
        )
    }

    /// Observer-only adapter fixture for terminal conformance. The mode is
    /// authenticated into the same complete test snapshot as the transcript
    /// gates; this does not create or promote a production target advertisement.
    #[cfg(feature = "capsec-conformance-observer")]
    pub(crate) fn session_conformance_repl_parts_for_mode(
        project_root: &Path,
        mode: capsec_semantics::arming::ArmedExecutionMode,
    ) -> Result<(Host, Arc<dyn Engine>, ReplSessionIngress)> {
        anyhow::ensure!(
            matches!(
                mode,
                capsec_semantics::arming::ArmedExecutionMode::Interactive
                    | capsec_semantics::arming::ArmedExecutionMode::Transcript
            ),
            "session conformance REPL fixture requires an interactive or transcript mode"
        );
        let host = armed_repl_ingress_test_host(project_root, mode);
        let plan = repl_ingress_test_plan(mode);
        let digest = host
            .armed_snapshot()
            .context("session conformance Host has no armed snapshot")?
            .digest()
            .as_str()
            .to_owned();
        crate::host::abi::install_host(host.clone());
        let engine = crate::engine::create_engine("hermes", Some(&digest))?;
        let ingress = ReplSessionIngress::from_armed_repl_runtime(host.clone(), plan)?;
        Ok((host, engine, ingress))
    }

    /// Build an armed observer-only Runtime for the exact production direct
    /// execution adapters. This substitutes complete test cells without
    /// creating or promoting a production target advertisement.
    #[cfg(feature = "capsec-conformance-observer")]
    pub(crate) fn session_conformance_direct_runtime(
        project_root: &Path,
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        entry_identity: &str,
        mode: capsec_semantics::arming::ArmedExecutionMode,
    ) -> Result<Runtime> {
        session_conformance_direct_runtime_with_authority(
            project_root,
            entry_kind,
            entry_identity,
            mode,
            false,
            true,
            true,
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn session_conformance_direct_runtime_with_root_fs_read(
        project_root: &Path,
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        entry_identity: &str,
        mode: capsec_semantics::arming::ArmedExecutionMode,
    ) -> Result<Runtime> {
        session_conformance_direct_runtime_with_authority(
            project_root,
            entry_kind,
            entry_identity,
            mode,
            true,
            true,
            true,
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn session_conformance_direct_runtime_with_package_dynamic_import_policy(
        project_root: &Path,
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        entry_identity: &str,
        mode: capsec_semantics::arming::ArmedExecutionMode,
        allow_fixture_package_dynamic_import: bool,
    ) -> Result<Runtime> {
        session_conformance_direct_runtime_with_authority(
            project_root,
            entry_kind,
            entry_identity,
            mode,
            false,
            allow_fixture_package_dynamic_import,
            true,
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn session_conformance_direct_runtime_with_package_commonjs_require_policy(
        project_root: &Path,
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        entry_identity: &str,
        mode: capsec_semantics::arming::ArmedExecutionMode,
        allow_fixture_package_commonjs_require: bool,
    ) -> Result<Runtime> {
        session_conformance_direct_runtime_with_authority(
            project_root,
            entry_kind,
            entry_identity,
            mode,
            false,
            true,
            allow_fixture_package_commonjs_require,
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn session_conformance_direct_runtime_with_authority(
        project_root: &Path,
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        entry_identity: &str,
        mode: capsec_semantics::arming::ArmedExecutionMode,
        grant_root_fs_read: bool,
        allow_fixture_package_dynamic_import: bool,
        allow_fixture_package_commonjs_require: bool,
    ) -> Result<Runtime> {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        anyhow::ensure!(
            matches!(
                (entry_kind, mode),
                (ArmedEntryKind::Eval, ArmedExecutionMode::OneShot)
                    | (ArmedEntryKind::File, ArmedExecutionMode::Program)
            ),
            "direct-execution observer fixture requires eval/one-shot or file/program"
        );
        let project_root = std::fs::canonicalize(project_root)
            .context("direct-execution observer project root is not canonical")?;
        let runtime_cache_root = project_root
            .parent()
            .context("direct-execution observer project root has no parent")?
            .join(format!(
                ".ibex-direct-execution-cache-{}",
                std::process::id()
            ));
        std::fs::create_dir_all(&runtime_cache_root)?;
        let runtime_cache_root = std::fs::canonicalize(runtime_cache_root)?;
        let host = if grant_root_fs_read {
            armed_ingress_test_host_with_root_fs_read(
                &project_root,
                entry_kind,
                entry_identity,
                mode,
            )
        } else {
            armed_ingress_test_host_with_options(
                &project_root,
                entry_kind,
                entry_identity,
                mode,
                &[],
                false,
                allow_fixture_package_dynamic_import,
                allow_fixture_package_commonjs_require,
            )
        };
        let plan = ingress_test_plan(entry_kind, mode);
        let digest = host
            .armed_snapshot()
            .context("direct-execution observer Host has no armed snapshot")?
            .digest()
            .as_str()
            .to_owned();
        crate::host::abi::install_host(host.clone());
        let engine = crate::engine::create_engine("hermes", Some(&digest))?;
        Ok(Runtime {
            engine,
            host,
            runtime_bootstrap_loaded: tokio::sync::OnceCell::new(),
            history_startup: crate::history::HistoryPlatformCapture::capture(
                crate::cli::HistoryMode::Off,
                false,
                true,
            )
            .bind_authenticated_project_root(None),
            session_io: Some(plan),
            authenticated_project_root: Some(project_root),
            authenticated_runtime_cache_root: Some(runtime_cache_root),
            bundle_format: BundleFormat::Cjs,
            exec_argv: Vec::new(),
            compat_modes: Vec::new(),
        })
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[derive(Default)]
    struct AuthenticatedModuleGraphSpyEngine {
        graph_calls: std::sync::atomic::AtomicUsize,
        fallback_calls: std::sync::atomic::AtomicUsize,
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[async_trait::async_trait]
    impl Engine for AuthenticatedModuleGraphSpyEngine {
        fn name(&self) -> &str {
            "authenticated-module-graph-spy"
        }

        fn version(&self) -> Result<String> {
            Ok("test".to_owned())
        }

        async fn load_runtime(&self) -> Result<()> {
            Ok(())
        }

        async fn eval(&self, _code: &str) -> Result<Option<String>> {
            anyhow::bail!("authenticated file path reached bare eval")
        }

        async fn evaluate_authenticated(
            &self,
            _session: &ibex_runtime::engine::evaluation::ArmedSessionToken,
            _request: ibex_runtime::engine::evaluation::SourceRequest,
        ) -> Result<crate::engine::AuthenticatedEvaluation> {
            self.fallback_calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("authenticated native graph fell back to source eval")
        }

        async fn evaluate_authenticated_generated(
            &self,
            _session: &ibex_runtime::engine::evaluation::ArmedSessionToken,
            _request: ibex_runtime::engine::evaluation::SourceRequest,
            _entry: crate::engine::AuthenticatedGeneratedEntry,
        ) -> Result<crate::engine::AuthenticatedEvaluation> {
            self.fallback_calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("authenticated native graph fell back to generated eval")
        }

        fn evaluate_authenticated_module_graph<'a>(
            &'a self,
            _session: &'a ibex_runtime::engine::evaluation::ArmedSessionToken,
            request: ibex_runtime::engine::evaluation::SourceRequest,
            prepare: crate::engine::AuthenticatedModuleGraphPreparer<'a>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<crate::engine::AuthenticatedEvaluation>>
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let graph = match prepare(&request)? {
                    crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) => graph,
                    crate::engine::AuthenticatedModuleGraphPreparation::LegacyRequired => {
                        self.fallback_calls.fetch_add(1, Ordering::SeqCst);
                        anyhow::bail!("spy received an unexpected legacy graph fallback")
                    }
                };
                let (_, path, entry) = graph
                    .records()
                    .find(|(source_id, _, _)| *source_id == graph.entry())
                    .context("spy graph omitted its entry")?;
                anyhow::ensure!(
                    path.ends_with("entry.mjs")
                        && entry.artifact().semantics.source_integrity == *request.source_digest(),
                    "spy received a graph not joined to the structured request"
                );
                self.graph_calls.fetch_add(1, Ordering::SeqCst);
                Ok(crate::engine::AuthenticatedEvaluation::Empty)
            })
        }

        async fn run_file(&self, _path: &str) -> Result<Option<String>> {
            anyhow::bail!("authenticated file path reached bare file execution")
        }

        async fn start_inspector(&self, _host: &str, _port: u16) -> Result<()> {
            anyhow::bail!("unexpected inspector start")
        }

        async fn stop_inspector(&self) -> Result<()> {
            Ok(())
        }

        fn supports_feature(&self, _feature: EngineFeature) -> bool {
            false
        }
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    fn authenticated_module_graph_spy_runtime(
        project_root: &Path,
        engine: Arc<dyn Engine>,
    ) -> Result<Runtime> {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let project_root = std::fs::canonicalize(project_root)?;
        let runtime_cache_root = project_root
            .parent()
            .context("spy project has no parent")?
            .join("native-graph-cache");
        std::fs::create_dir_all(&runtime_cache_root)?;
        let runtime_cache_root = std::fs::canonicalize(runtime_cache_root)?;
        let host = armed_ingress_test_host(
            &project_root,
            ArmedEntryKind::File,
            "file:///project/entry.mjs",
            ArmedExecutionMode::Program,
        );
        crate::host::abi::install_host(host.clone());
        Ok(Runtime {
            engine,
            host,
            runtime_bootstrap_loaded: tokio::sync::OnceCell::new(),
            history_startup: crate::history::HistoryPlatformCapture::capture(
                crate::cli::HistoryMode::Off,
                false,
                true,
            )
            .bind_authenticated_project_root(None),
            session_io: Some(ingress_test_plan(
                ArmedEntryKind::File,
                ArmedExecutionMode::Program,
            )),
            authenticated_project_root: Some(project_root),
            authenticated_runtime_cache_root: Some(runtime_cache_root),
            bundle_format: BundleFormat::Cjs,
            exec_argv: Vec::new(),
            compat_modes: Vec::new(),
        })
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn authenticated_file_program_reaches_request_bound_native_graph() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"native-reachability","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(
            project.join("entry.mjs"),
            "import { value } from './dep.mjs'; globalThis.__nativeValue = value;\n",
        )
        .unwrap();
        std::fs::write(project.join("dep.mjs"), "export const value = 42;\n").unwrap();

        let spy = Arc::new(AuthenticatedModuleGraphSpyEngine::default());
        let runtime = authenticated_module_graph_spy_runtime(&project, spy.clone()).unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(spy.graph_calls.load(Ordering::SeqCst), 1);
        assert_eq!(spy.fallback_calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_native_entry_syntax_refusal_consumes_its_one_shot_ordinal() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-entry-syntax","private":true,"type":"module"}"#,
        )
        .unwrap();
        let entry = directory.path().join("entry.mjs");
        std::fs::write(&entry, "export const = ;\n").unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.mjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();

        assert!(
            matches!(
                ingress.evaluate(engine.as_ref(), &[]).await,
                Err(AuthenticatedEvaluationFailure::Refusal(_))
            ),
            "entry syntax must be a submitted, recoverable refusal"
        );
        std::fs::write(&entry, "export const recovered = 1;\n").unwrap();
        let replay = ingress.evaluate(engine.as_ref(), &[]).await.unwrap_err();
        assert!(matches!(replay, AuthenticatedEvaluationFailure::Refusal(_)));
        assert!(
            replay.to_string().contains("already been submitted"),
            "native admission did not consume the file request exactly once: {replay:#}"
        );
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_native_dependency_syntax_refusal_consumes_its_one_shot_ordinal() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-dependency-syntax","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.mjs"),
            "import { recovered } from './dep.mjs'; globalThis.__dependencyRecovered = recovered;\n",
        )
        .unwrap();
        let dependency = directory.path().join("dep.mjs");
        std::fs::write(&dependency, "export const = ;\n").unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.mjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();

        assert!(
            matches!(
                ingress.evaluate(engine.as_ref(), &[]).await,
                Err(AuthenticatedEvaluationFailure::Refusal(_))
            ),
            "dependency syntax must be a submitted, recoverable refusal"
        );
        std::fs::write(&dependency, "export const recovered = 2;\n").unwrap();
        let replay = ingress.evaluate(engine.as_ref(), &[]).await.unwrap_err();
        assert!(matches!(replay, AuthenticatedEvaluationFailure::Refusal(_)));
        assert!(
            replay.to_string().contains("already been submitted"),
            "native admission did not consume the dependency request exactly once: {replay:#}"
        );
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn aborted_authenticated_native_tla_releases_its_target_for_a_successor_timer() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-tla-abort","private":true,"type":"module"}"#,
        )
        .unwrap();
        let entry = directory.path().join("entry.mjs");
        std::fs::write(
            &entry,
            "await new Promise((resolve) => setTimeout(() => { process.exitCode = 23; resolve(); }, 250));\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.mjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();

        let mut suspended = Box::pin(ingress.evaluate(engine.as_ref(), &[]));
        tokio::select! {
            result = &mut suspended => {
                panic!("the top-level-await graph settled before it could be aborted: {result:?}")
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
        }
        drop(suspended);

        tokio::time::sleep(std::time::Duration::from_millis(275)).await;
        assert!(
            runtime
                .settle_authenticated_file_keep_alive_tick()
                .await
                .is_none(),
            "the successor timer failed after the graph future was dropped"
        );
        assert_eq!(runtime.lifecycle_exit_code(), 23);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn authenticated_native_tla_wakes_from_host_io_without_a_javascript_timer() {
        use ibex_runtime::module_loader::identity::SourceId;

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        // Hold the worker completion long enough to force the graph through
        // its callback-only park. The module itself schedules no timer.
        // Typed observer knob, not an env var (see
        // issues/closed/20260727-test-delay-injection-is-a-global-env-var.md);
        // effective only in observer builds, exactly like the env-var read
        // it replaces, which was observer-gated in C++.
        #[cfg(feature = "capsec-conformance-observer")]
        let _delay_guard = RuntimeCallbackDelayGuard::new(100);
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-host-io-tla","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(directory.path().join("data.txt"), "host-io-only").unwrap();
        std::fs::write(
            directory.path().join("entry.mjs"),
            "import { promises as fs } from 'node:fs';\nconst text = await fs.readFile('/project/data.txt', 'utf8');\nif (text !== 'host-io-only') throw new Error('bad fs result');\nprocess.exitCode = 43;\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime_with_root_fs_read(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.mjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();
        let request = ingress.file_request(&[]).unwrap();

        let preflight = ingress
            .prepare_authenticated_module_graph(&request)
            .unwrap_or_else(|error| panic!("callback-only graph preflight failed: {error:#}"));
        let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight else {
            panic!("the callback-only graph unexpectedly selected the legacy loader")
        };
        assert!(
            graph
                .records()
                .any(|(source_id, _, _)| matches!(source_id, SourceId::Builtin { .. })),
            "the preflight graph omitted its authenticated node:fs builtin"
        );

        let session = ingress.session.clone();
        // The timeout guards a hang (a graph that never wakes without a JS
        // timer), not latency: keep it wide so parallel-suite CPU saturation
        // cannot false-fail the wake.
        let evaluation = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            engine.evaluate_authenticated_module_graph(
                &session,
                request,
                Box::new(|admitted| ingress.prepare_authenticated_module_graph(admitted)),
            ),
        )
        .await
        .expect("the callback-only TLA graph did not wake")
        .expect("the callback-only TLA graph failed");
        assert!(
            matches!(evaluation, crate::engine::AuthenticatedEvaluation::Empty),
            "unexpected callback-only TLA evaluation: {evaluation:?}"
        );
        assert_eq!(runtime.lifecycle_exit_code(), 43);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn authenticated_commonjs_require_uses_call_time_compatibility_vfs_context() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"compat-commonjs-vfs","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(directory.path().join("data.txt"), "commonjs-vfs").unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "const fs = require('node:fs');\nconst text = fs.readFileSync('/project/data.txt', 'utf8');\nif (text !== 'commonjs-vfs') throw new Error('bad fs result');\nprocess.exitCode = 47;\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime_with_root_fs_read(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.cjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();
        let request = ingress.file_request(&[]).unwrap();

        let preflight = ingress
            .prepare_authenticated_module_graph(&request)
            .unwrap_or_else(|error| panic!("CommonJS VFS graph preflight failed: {error:#}"));
        let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight else {
            panic!("an authored CommonJS require selected the compatibility loader")
        };
        assert_eq!(
            graph.records().count(),
            1,
            "node:fs was discovered before the exact require site"
        );
        assert!(graph
            .deferred_dynamic_links()
            .get(graph.entry())
            .unwrap()
            .commonjs_require_specifiers
            .contains("node:fs"));

        let session = ingress.session.clone();
        let evaluation = engine
            .evaluate_authenticated_module_graph(
                &session,
                request,
                Box::new(|admitted| ingress.prepare_authenticated_module_graph(admitted)),
            )
            .await
            .expect("the CommonJS VFS graph failed");
        if let crate::engine::AuthenticatedEvaluation::Value { receipt, .. } = evaluation {
            if let Some(receipt) = receipt {
                engine.release_undisplayed_value(receipt).await.unwrap();
            }
        } else {
            assert!(
                matches!(evaluation, crate::engine::AuthenticatedEvaluation::Empty),
                "unexpected native CommonJS VFS evaluation: {evaluation:?}"
            );
        }
        assert_eq!(runtime.lifecycle_exit_code(), 47);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_commonjs_require_preserves_cycles_and_partial_exports() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-commonjs-cycle","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "const a = require('./a.cjs');\nif (a.value !== 42 || a.fromB !== 41 || require('./a.cjs') !== a) throw new Error('bad cycle');\nprocess.exitCode = 48;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("a.cjs"),
            "exports.first = 41;\nconst b = require('./b.cjs');\nexports.fromB = b.saw;\nexports.value = 42;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("b.cjs"),
            "const a = require('./a.cjs');\nexports.saw = a.first;\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.cjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();
        let request = ingress.file_request(&[]).unwrap();
        let preflight = ingress
            .prepare_authenticated_module_graph(&request)
            .unwrap();
        let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight else {
            panic!("the CommonJS cycle selected the compatibility loader")
        };
        assert_eq!(graph.records().count(), 1);

        let session = ingress.session.clone();
        let evaluation = engine
            .evaluate_authenticated_module_graph(
                &session,
                request,
                Box::new(|admitted| ingress.prepare_authenticated_module_graph(admitted)),
            )
            .await
            .expect("the CommonJS cycle graph failed");
        if let crate::engine::AuthenticatedEvaluation::Value { receipt, .. } = evaluation {
            if let Some(receipt) = receipt {
                engine.release_undisplayed_value(receipt).await.unwrap();
            }
        } else {
            assert!(matches!(
                evaluation,
                crate::engine::AuthenticatedEvaluation::Empty
            ));
        }
        assert_eq!(runtime.lifecycle_exit_code(), 48);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_commonjs_require_reports_esm_cycle_without_partial_publication() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-commonjs-esm-cycle","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "const namespace = require('./a.mjs');\nif (namespace.status !== 51) throw new Error('bad recovered cycle result');\nprocess.exitCode = namespace.status;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("a.mjs"),
            "import { cycleStatus } from './b.cjs';\nexport const status = cycleStatus + 1;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("b.cjs"),
            "let cycleStatus = 0;\ntry { require('./a.mjs'); } catch (error) {\n  if (!String(error && error.message).includes('ERR_REQUIRE_CYCLE_MODULE')) throw error;\n  cycleStatus = 50;\n}\nexports.cycleStatus = cycleStatus;\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.cjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();
        let request = ingress.file_request(&[]).unwrap();
        let preflight = ingress
            .prepare_authenticated_module_graph(&request)
            .unwrap();
        let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight else {
            panic!("the CommonJS/ESM cycle selected the compatibility loader")
        };
        assert_eq!(graph.records().count(), 1);

        let session = ingress.session.clone();
        let evaluation = engine
            .evaluate_authenticated_module_graph(
                &session,
                request,
                Box::new(|admitted| ingress.prepare_authenticated_module_graph(admitted)),
            )
            .await
            .expect("the recoverable CommonJS/ESM cycle graph failed");
        if let crate::engine::AuthenticatedEvaluation::Value { receipt, .. } = evaluation {
            if let Some(receipt) = receipt {
                engine.release_undisplayed_value(receipt).await.unwrap();
            }
        } else {
            assert!(
                matches!(evaluation, crate::engine::AuthenticatedEvaluation::Empty),
                "unexpected recovered CommonJS/ESM cycle evaluation: {evaluation:?}"
            );
        }
        assert_eq!(runtime.lifecycle_exit_code(), 51);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_commonjs_require_failure_does_not_poison_later_activation() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-commonjs-retry","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "let refusals = 0;\nfor (let attempt = 0; attempt < 2; attempt += 1) {\n  try { require('./missing.cjs'); } catch (_) { refusals += 1; }\n}\nconst target = require('./ok.cjs');\nif (refusals !== 2 || target.status !== 52 || globalThis.__requireRetryRuns !== 1) throw new Error('require failure poisoned provider state');\nprocess.exitCode = target.status;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("ok.cjs"),
            "globalThis.__requireRetryRuns = (globalThis.__requireRetryRuns || 0) + 1;\nmodule.exports = { status: 52 };\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.cjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 52);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_commonjs_require_policy_denial_never_evaluates_target() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-commonjs-policy-denial","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "let denied = false;\ntry { require('image-lib'); } catch (error) {\n  denied = String(error && error.message).includes('CommonJS require activation refused');\n}\nif (!denied || globalThis.__deniedRequireTargetRan) throw new Error('policy-denied require reached its target');\nprocess.exitCode = 53;\n",
        )
        .unwrap();
        let package = directory.path().join("node_modules/image-lib");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"image-lib","version":"2.4.1","type":"commonjs","exports":"./index.cjs"}"#,
        )
        .unwrap();
        std::fs::write(
            package.join("index.cjs"),
            "globalThis.__deniedRequireTargetRan = true;\nthrow new Error('policy-denied require target evaluated');\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime_with_package_commonjs_require_policy(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.cjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
            false,
        )
        .unwrap();
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 53);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_commonjs_require_cannot_borrow_bootstrap_internal_objects() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-bootstrap-internal-denial","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "let denied = false;\ntry { require('internal/test/binding'); } catch (_) { denied = true; }\nif (!denied) throw new Error('borrowed bootstrap internal object');\nprocess.exitCode = 49;\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.cjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();
        let request = ingress.file_request(&[]).unwrap();
        let preflight = ingress
            .prepare_authenticated_module_graph(&request)
            .unwrap();
        let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight else {
            panic!("the bootstrap-internal denial selected the compatibility loader")
        };
        assert_eq!(graph.records().count(), 1);
        assert!(graph
            .deferred_dynamic_links()
            .get(graph.entry())
            .unwrap()
            .commonjs_require_specifiers
            .contains("internal/test/binding"));

        let session = ingress.session.clone();
        let evaluation = engine
            .evaluate_authenticated_module_graph(
                &session,
                request,
                Box::new(|admitted| ingress.prepare_authenticated_module_graph(admitted)),
            )
            .await
            .expect("the bootstrap-internal denial graph failed");
        assert!(
            !matches!(evaluation, crate::engine::AuthenticatedEvaluation::Throw(_)),
            "authored code borrowed a bootstrap-internal object: {evaluation:?}"
        );
        assert_eq!(runtime.lifecycle_exit_code(), 49);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn closed_compatibility_window_keeps_call_time_import_and_require_native() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        std::env::set_var("IBEX_LEGACY_MODULE_LOADER", "0");

        // A missing literal call-time target must not move Node's failure to
        // graph preparation. If the guarded site stays dead, the program
        // completes without resolving, authorizing, linking, or evaluating it.
        for (entry_name, package_type, source) in [
            (
                "entry.mjs",
                "module",
                "if (false) import('./missing.mjs');\nexport const reached = true;\n",
            ),
            (
                "entry.cjs",
                "commonjs",
                "if (false) require('./missing.cjs');\nmodule.exports = true;\n",
            ),
        ] {
            let directory = tempdir().unwrap();
            std::fs::write(
                directory.path().join("package.json"),
                format!(
                    r#"{{"name":"closed-compatibility-window","private":true,"type":"{package_type}"}}"#
                ),
            )
            .unwrap();
            std::fs::write(directory.path().join(entry_name), source).unwrap();
            let entry_uri = format!("file:///project/{entry_name}");
            let runtime = session_conformance_direct_runtime(
                directory.path(),
                ArmedEntryKind::File,
                &entry_uri,
                ArmedExecutionMode::Program,
            )
            .unwrap();
            {
                let mut ingress = runtime.authenticated_file_ingress().unwrap();
                let request = ingress.file_request(&[]).unwrap();
                let preparation = ingress
                    .prepare_authenticated_module_graph(&request)
                    .unwrap_or_else(|error| {
                        panic!("deferred call-time edge preflight failed: {error:#}")
                    });
                let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preparation
                else {
                    panic!("a deferred call-time edge required the compatibility loader")
                };
                assert_eq!(graph.records().count(), 1);
                let deferred = graph.deferred_dynamic_links();
                assert_eq!(deferred.len(), 1);
                let entry = deferred.get(graph.entry()).unwrap();
                assert_eq!(
                    entry_name == "entry.mjs",
                    entry.literal_specifiers.contains("./missing.mjs")
                );
                assert_eq!(
                    entry_name == "entry.cjs",
                    entry.commonjs_require_specifiers.contains("./missing.cjs")
                );
            }
            runtime.load_runtime().await.unwrap();
            assert_eq!(
                runtime.run_authenticated_file_program(&[]).await.unwrap(),
                AuthenticatedFileProgramOutcome::Completed,
                "dead call-time edge changed the program outcome for {entry_name}"
            );
            assert_eq!(runtime.lifecycle_exit_code(), 0);
        }
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn authenticated_prepared_initial_graph_activates_prepared_commonjs_target() {
        use ibex_runtime::module_loader::artifact::digest_bytes;
        use ibex_runtime::module_loader::runner_pipeline::{
            publish_prepared_activation_records_v1, publish_prepared_source_graph_v1,
        };

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"native-prepared-require","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        let source_entry = project.join("entry.cjs");
        std::fs::write(
            &source_entry,
            "const target = require('./target.cjs');\nprocess.exitCode = target.status;\n",
        )
        .unwrap();
        std::fs::write(
            project.join("target.cjs"),
            "module.exports = { status: 54 };\n",
        )
        .unwrap();

        let runtime = session_conformance_direct_runtime(
            &project,
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.cjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();
        let request = ingress.file_request(&[]).unwrap();
        let mut inline = match ingress
            .prepare_authenticated_module_graph(&request)
            .unwrap()
        {
            crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) => graph,
            crate::engine::AuthenticatedModuleGraphPreparation::LegacyRequired => {
                panic!("the exact source graph unexpectedly required legacy execution")
            }
        };
        assert!(inline.prepared_entries().unwrap().is_none());

        let bundles_root =
            ensure_real_internal_cache_subdirectory(&ingress.runtime_cache_root, "bundles")
                .unwrap();
        let cache_key = bundle_cache_key(&source_entry, ingress.bundle_format).unwrap();
        let artifact_dir = bundle_artifact_root(&bundles_root, &cache_key).join("exact-hit");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        let output = bundle_entry_path(&artifact_dir, ingress.bundle_format);
        std::fs::write(&output, b"prepared locator only\n").unwrap();
        let graph_digest = "a".repeat(64);
        let manifest = BundleCacheManifest {
            version: 4,
            entry: std::fs::canonicalize(&source_entry)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            resolution_digest: "b".repeat(64),
            graph_digest: graph_digest.clone(),
            deps: Vec::new(),
            outputs: Vec::new(),
            resolution_inputs: Vec::new(),
            source_provenance: None,
        };
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let deployment_digest =
            digest_bytes("ibex/rolldown-deployment-graph/1", graph_digest.as_bytes()).unwrap();
        publish_prepared_source_graph_v1(&inline, &artifact_dir, deployment_digest.clone())
            .unwrap();
        let initial_ids = inline
            .records()
            .map(|(source_id, _, _)| source_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let entry_id = inline.entry().clone();
        inline
            .activate_commonjs_require_target(&entry_id, "./target.cjs", 1)
            .unwrap();
        let activated_ids = inline
            .records()
            .map(|(source_id, _, _)| source_id.clone())
            .filter(|source_id| !initial_ids.contains(source_id))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(activated_ids.len(), 1);
        publish_prepared_activation_records_v1(
            &inline,
            &activated_ids,
            &artifact_dir,
            deployment_digest,
        )
        .unwrap();
        drop(ingress);
        drop(runtime);

        let runtime = session_conformance_direct_runtime(
            &project,
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.cjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();
        let request = ingress.file_request(&[]).unwrap();
        let prepared = match ingress
            .prepare_authenticated_module_graph(&request)
            .unwrap()
        {
            crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) => graph,
            crate::engine::AuthenticatedModuleGraphPreparation::LegacyRequired => {
                panic!("the exact prepared graph unexpectedly required legacy execution")
            }
        };
        assert!(
            prepared.prepared_entries().unwrap().is_some(),
            "the exact source-derived prepared publication was not selected"
        );
        assert_eq!(
            prepared.records().count(),
            1,
            "the deferred CommonJS target was discovered while selecting the prepared entry"
        );

        PREPARED_ACTIVATION_LOCATOR_CALLS.store(0, Ordering::SeqCst);
        let session = ingress.session.clone();
        let evaluation = engine
            .evaluate_authenticated_module_graph(
                &session,
                request,
                Box::new(|admitted| ingress.prepare_authenticated_module_graph(admitted)),
            )
            .await
            .expect("the prepared-initial CommonJS graph failed");
        if let crate::engine::AuthenticatedEvaluation::Value { receipt, .. } = evaluation {
            if let Some(receipt) = receipt {
                engine.release_undisplayed_value(receipt).await.unwrap();
            }
        } else {
            assert!(
                matches!(evaluation, crate::engine::AuthenticatedEvaluation::Empty),
                "unexpected prepared-initial evaluation: {evaluation:?}"
            );
        }
        assert_eq!(runtime.lifecycle_exit_code(), 54);
        assert_eq!(
            PREPARED_ACTIVATION_LOCATOR_CALLS.load(Ordering::SeqCst),
            1,
            "production did not discover the prepared target at its exact reached require"
        );
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn authenticated_file_graph_refuses_entry_changed_after_request_read() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"native-reread","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(project.join("entry.mjs"), "export const value = 1;\n").unwrap();
        let spy = Arc::new(AuthenticatedModuleGraphSpyEngine::default());
        let runtime = authenticated_module_graph_spy_runtime(&project, spy).unwrap();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();
        let request = ingress.file_request(&[]).unwrap();
        std::fs::write(project.join("entry.mjs"), "export const value = 2;\n").unwrap();
        let error = match ingress.prepare_authenticated_module_graph(&request) {
            Err(error) => error,
            Ok(_) => panic!("a mutable reread replaced the credential-bound entry"),
        };
        assert!(
            error
                .to_string()
                .contains("changed after the structured request"),
            "unexpected mismatch error: {error:#}"
        );
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_engine_refuses_prebuilt_graph_with_stale_entry_bytes() {
        use ibex_runtime::module_loader::generation::ExecutionGeneration;
        use ibex_runtime::module_loader::runner_pipeline::{
            build_authenticated_source_graph_v1_for_host, SourceModuleGraphBuildV1,
        };

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"native-engine-reread","private":true,"type":"module"}"#,
        )
        .unwrap();
        let entry = directory.path().join("entry.mjs");
        std::fs::write(&entry, "process.exitCode = 99; export const value = 2;\n").unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            capsec_semantics::arming::ArmedEntryKind::File,
            "file:///project/entry.mjs",
            capsec_semantics::arming::ArmedExecutionMode::Program,
        )
        .unwrap();
        let engine = runtime.engine.clone();
        let mut ingress = runtime.authenticated_file_ingress().unwrap();
        let stale_graph = match build_authenticated_source_graph_v1_for_host(
            &ingress.host,
            &entry,
            module_producer_binary_digest().unwrap(),
            &engine::hermes::bytecode_cache_identity(),
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => panic!(
                "prebuilt stale graph unexpectedly required legacy: {}",
                requirement.reason
            ),
        };
        stale_graph.plan().unwrap();
        std::fs::write(&entry, "process.exitCode = 41; export const value = 1;\n").unwrap();
        let request = ingress.file_request(&[]).unwrap();
        let admitted_digest = request.source_digest().clone();
        let stale_integrity = stale_graph
            .records()
            .find(|(source_id, _, _)| *source_id == stale_graph.entry())
            .expect("prebuilt stale graph omitted its entry")
            .2
            .artifact()
            .semantics
            .source_integrity
            .clone();
        assert_ne!(stale_integrity, admitted_digest);
        let session = ingress.session.clone();
        let returned_native = Arc::new(AtomicBool::new(false));
        let returned_native_in_preparer = returned_native.clone();

        let error = engine
            .evaluate_authenticated_module_graph(
                &session,
                request,
                Box::new(move |admitted_request| {
                    assert_eq!(admitted_request.source_digest(), &admitted_digest);
                    returned_native_in_preparer.store(true, Ordering::Release);
                    Ok(crate::engine::AuthenticatedModuleGraphPreparation::Native(
                        stale_graph,
                    ))
                }),
            )
            .await
            .expect_err("the engine accepted a prebuilt graph with stale entry bytes");
        assert!(
            error
                .to_string()
                .contains("does not belong to its admitted request"),
            "unexpected central graph-join refusal: {error:#}"
        );
        assert!(
            returned_native.load(Ordering::Acquire),
            "the preparer failed before returning its mismatched native graph"
        );
        assert_eq!(
            runtime.lifecycle_exit_code(),
            0,
            "the substituted graph executed before the central join"
        );
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn authenticated_native_graph_stays_alive_through_delayed_dynamic_import() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"compatibility-quiescence","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.mjs"),
            "const delayed = setTimeout(() => { import('./dep.mjs').then(({ status }) => { process.exitCode = status; }); }, 50);\nif (delayed && typeof delayed.unref === 'function') delayed.unref();\nelse if (typeof globalThis.__exactTimerUnref === 'function') globalThis.__exactTimerUnref(delayed);\nelse throw new Error('timer unref unavailable');\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("dep.mjs"),
            "export const status = 37;\n",
        )
        .unwrap();
        let mut runtime = session_conformance_direct_runtime(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.mjs",
            ArmedExecutionMode::Program,
        )
        .unwrap();
        runtime.exec_argv.push("--keep-alive".to_owned());
        {
            let mut ingress = runtime.authenticated_file_ingress().unwrap();
            let request = ingress.file_request(&[]).unwrap();
            let preflight = ingress
                .prepare_authenticated_module_graph(&request)
                .unwrap_or_else(|error| panic!("delayed-import preflight failed: {error:#}"));
            let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight
            else {
                panic!("a delayed dynamic import required the compatibility loader")
            };
            assert_eq!(graph.records().count(), 1);
            assert_eq!(graph.deferred_dynamic_links().len(), 1);
        }
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(
            runtime.lifecycle_exit_code(),
            0,
            "the unreferenced timer must survive the ordinary program drain"
        );
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        for _ in 0..20 {
            let outcome = runtime.settle_authenticated_file_keep_alive_tick().await;
            assert!(
                outcome.is_none(),
                "the delayed import should set exitCode without terminating keep-alive: {outcome:?}"
            );
            if runtime.lifecycle_exit_code() == 37 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.lifecycle_exit_code(), 37);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn authenticated_commonjs_import_uses_retained_native_activation_graph() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"commonjs-native-activation","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "const delayed = setTimeout(() => { import('./dep.mjs').then(({ status }) => { process.exitCode = status; }); }, 50);\nif (delayed && typeof delayed.unref === 'function') delayed.unref();\nelse if (typeof globalThis.__exactTimerUnref === 'function') globalThis.__exactTimerUnref(delayed);\nelse throw new Error('timer unref unavailable');\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("dep.mjs"),
            "export const status = 38;\n",
        )
        .unwrap();
        let mut runtime = session_conformance_direct_runtime(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.cjs",
            ArmedExecutionMode::Program,
        )
        .unwrap();
        runtime.exec_argv.push("--keep-alive".to_owned());
        {
            let mut ingress = runtime.authenticated_file_ingress().unwrap();
            let request = ingress.file_request(&[]).unwrap();
            let preflight = ingress
                .prepare_authenticated_module_graph(&request)
                .unwrap_or_else(|error| panic!("CommonJS import preflight failed: {error:#}"));
            let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight
            else {
                panic!("CommonJS import required the compatibility loader")
            };
            assert_eq!(graph.records().count(), 1);
            assert_eq!(graph.deferred_dynamic_links().len(), 1);
        }
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        for _ in 0..20 {
            let outcome = runtime.settle_authenticated_file_keep_alive_tick().await;
            assert!(
                outcome.is_none(),
                "CommonJS import should settle without terminating keep-alive: {outcome:?}"
            );
            if runtime.lifecycle_exit_code() == 38 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.lifecycle_exit_code(), 38);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn authenticated_commonjs_require_activates_exact_target_in_drive() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"commonjs-require-native-activation","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "const first = require('./dep.cjs');\nconst second = require('./dep.cjs');\nif (first !== second || globalThis.__requireTargetRuns !== 1) throw new Error('require target was not cached');\nprocess.exitCode = first.status;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("dep.cjs"),
            "globalThis.__requireTargetRuns = (globalThis.__requireTargetRuns || 0) + 1;\nmodule.exports = { status: 39 };\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.cjs",
            ArmedExecutionMode::Program,
        )
        .unwrap();
        {
            let mut ingress = runtime.authenticated_file_ingress().unwrap();
            let request = ingress.file_request(&[]).unwrap();
            let preflight = ingress
                .prepare_authenticated_module_graph(&request)
                .unwrap_or_else(|error| panic!("CommonJS require preflight failed: {error:#}"));
            let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight
            else {
                panic!("CommonJS require required the compatibility loader")
            };
            assert_eq!(graph.records().count(), 1);
            let deferred = graph.deferred_dynamic_links();
            assert_eq!(deferred.len(), 1);
            assert!(deferred
                .get(graph.entry())
                .unwrap()
                .commonjs_require_specifiers
                .contains("./dep.cjs"));
        }
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 39);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn authenticated_commonjs_require_evaluates_synchronous_esm_closure() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"commonjs-require-esm-activation","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "const namespace = require('./dep.mjs');\nprocess.exitCode = namespace.status;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("dep.mjs"),
            "import { value } from './value.mjs';\nexport const status = value + 1;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("value.mjs"),
            "export const value = 42;\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.cjs",
            ArmedExecutionMode::Program,
        )
        .unwrap();
        {
            let mut ingress = runtime.authenticated_file_ingress().unwrap();
            let request = ingress.file_request(&[]).unwrap();
            let preflight = ingress
                .prepare_authenticated_module_graph(&request)
                .unwrap_or_else(|error| panic!("CommonJS require-ESM preflight failed: {error:#}"));
            let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight
            else {
                panic!("CommonJS require-ESM required the compatibility loader")
            };
            assert_eq!(graph.records().count(), 1);
        }
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 43);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn authenticated_commonjs_require_rejects_async_tainted_esm_before_publication() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"commonjs-require-async-refusal","private":true,"type":"commonjs"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.cjs"),
            "try {\n  require('./dep.mjs');\n  process.exitCode = 90;\n} catch (error) {\n  if (globalThis.__asyncRequireTargetRan) process.exitCode = 92;\n  else process.exitCode = String(error && error.message).includes('ERR_REQUIRE_ASYNC_MODULE') ? 44 : 91;\n}\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("dep.mjs"),
            "await Promise.resolve();\nglobalThis.__asyncRequireTargetRan = true;\nexport const status = 1;\n",
        )
        .unwrap();
        let runtime = session_conformance_direct_runtime(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.cjs",
            ArmedExecutionMode::Program,
        )
        .unwrap();
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 44);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn retained_native_activation_drains_nested_tla_imports() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"nested-native-activation","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.mjs"),
            "const delayed = setTimeout(() => { import('./middle.mjs').then(({ status }) => { process.exitCode = status; }); }, 50);\nif (delayed && typeof delayed.unref === 'function') delayed.unref();\nelse if (typeof globalThis.__exactTimerUnref === 'function') globalThis.__exactTimerUnref(delayed);\nelse throw new Error('timer unref unavailable');\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("middle.mjs"),
            "const dependency = await import('./dep.mjs');\nexport const status = dependency.status;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("dep.mjs"),
            "export const status = 40;\n",
        )
        .unwrap();
        let mut runtime = session_conformance_direct_runtime(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.mjs",
            ArmedExecutionMode::Program,
        )
        .unwrap();
        runtime.exec_argv.push("--keep-alive".to_owned());
        {
            let mut ingress = runtime.authenticated_file_ingress().unwrap();
            let request = ingress.file_request(&[]).unwrap();
            let preflight = ingress
                .prepare_authenticated_module_graph(&request)
                .unwrap_or_else(|error| panic!("nested import preflight failed: {error:#}"));
            let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight
            else {
                panic!("nested dynamic imports required the compatibility loader")
            };
            assert_eq!(graph.records().count(), 1);
            assert_eq!(graph.deferred_dynamic_links().len(), 1);
        }
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        for _ in 0..40 {
            let outcome = runtime.settle_authenticated_file_keep_alive_tick().await;
            assert!(
                outcome.is_none(),
                "nested TLA imports should settle without terminating keep-alive: {outcome:?}"
            );
            if runtime.lifecycle_exit_code() == 40 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.lifecycle_exit_code(), 40);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn retained_native_activation_rejects_only_the_failed_import() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"failed-native-activation","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.mjs"),
            "const delayed = setTimeout(() => { import('./missing.mjs').then(() => { process.exitCode = 99; }, (error) => { if (!String(error).includes('dynamic module activation refused')) throw error; process.exitCode = 41; }); }, 50);\nif (delayed && typeof delayed.unref === 'function') delayed.unref();\nelse if (typeof globalThis.__exactTimerUnref === 'function') globalThis.__exactTimerUnref(delayed);\nelse throw new Error('timer unref unavailable');\n",
        )
        .unwrap();
        let mut runtime = session_conformance_direct_runtime(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.mjs",
            ArmedExecutionMode::Program,
        )
        .unwrap();
        runtime.exec_argv.push("--keep-alive".to_owned());
        {
            let mut ingress = runtime.authenticated_file_ingress().unwrap();
            let request = ingress.file_request(&[]).unwrap();
            let preflight = ingress
                .prepare_authenticated_module_graph(&request)
                .unwrap_or_else(|error| panic!("failed import preflight failed: {error:#}"));
            let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight
            else {
                panic!("a deferred missing import required the compatibility loader")
            };
            assert_eq!(graph.records().count(), 1);
            assert_eq!(graph.deferred_dynamic_links().len(), 1);
        }
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        for _ in 0..20 {
            let outcome = runtime.settle_authenticated_file_keep_alive_tick().await;
            assert!(
                outcome.is_none(),
                "a rejected import should not terminate keep-alive: {outcome:?}"
            );
            if runtime.lifecycle_exit_code() == 41 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.lifecycle_exit_code(), 41);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn retained_native_activation_publishes_a_static_cycle_atomically() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"cyclic-native-activation","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.mjs"),
            "const delayed = setTimeout(() => { import('./a.mjs').then(({ status }) => { process.exitCode = status; }); }, 50);\nif (delayed && typeof delayed.unref === 'function') delayed.unref();\nelse if (typeof globalThis.__exactTimerUnref === 'function') globalThis.__exactTimerUnref(delayed);\nelse throw new Error('timer unref unavailable');\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("a.mjs"),
            "import { valueB } from './b.mjs';\nexport const valueA = 20;\nexport const status = valueB() + 2;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("b.mjs"),
            "import { valueA } from './a.mjs';\nexport function valueB() { return valueA * 2; }\n",
        )
        .unwrap();
        let mut runtime = session_conformance_direct_runtime(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.mjs",
            ArmedExecutionMode::Program,
        )
        .unwrap();
        runtime.exec_argv.push("--keep-alive".to_owned());
        {
            let mut ingress = runtime.authenticated_file_ingress().unwrap();
            let request = ingress.file_request(&[]).unwrap();
            let preflight = ingress
                .prepare_authenticated_module_graph(&request)
                .unwrap_or_else(|error| panic!("cyclic import preflight failed: {error:#}"));
            let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight
            else {
                panic!("a deferred cyclic target required the compatibility loader")
            };
            assert_eq!(graph.records().count(), 1);
            assert_eq!(graph.deferred_dynamic_links().len(), 1);
        }
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        for _ in 0..20 {
            let outcome = runtime.settle_authenticated_file_keep_alive_tick().await;
            assert!(
                outcome.is_none(),
                "a cyclic target should settle without terminating keep-alive: {outcome:?}"
            );
            if runtime.lifecycle_exit_code() == 42 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.lifecycle_exit_code(), 42);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn retained_native_activation_reaches_only_the_chosen_computed_candidate() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"computed-native-activation","private":true,"type":"module","ibex":{"computedCandidates":{"sites":[{"requester":"entry.mjs","label":"routes","specifiers":["./chosen.mjs","./dead.mjs"]}]}}}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.mjs"),
            "const chosen = './chosen.mjs';\nconst delayed = setTimeout(() => { import(chosen, { with: { 'ibex:site': 'routes' } }).then(({ status }) => { process.exitCode = status; }); }, 50);\nif (delayed && typeof delayed.unref === 'function') delayed.unref();\nelse if (typeof globalThis.__exactTimerUnref === 'function') globalThis.__exactTimerUnref(delayed);\nelse throw new Error('timer unref unavailable');\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("chosen.mjs"),
            "export const status = 43;\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("dead.mjs"),
            "throw new Error('an unchosen computed candidate was evaluated');\n",
        )
        .unwrap();
        let mut runtime = session_conformance_direct_runtime(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.mjs",
            ArmedExecutionMode::Program,
        )
        .unwrap();
        runtime.exec_argv.push("--keep-alive".to_owned());
        {
            let mut ingress = runtime.authenticated_file_ingress().unwrap();
            let request = ingress.file_request(&[]).unwrap();
            let preflight = ingress
                .prepare_authenticated_module_graph(&request)
                .unwrap_or_else(|error| panic!("computed import preflight failed: {error:#}"));
            let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight
            else {
                panic!("a deferred computed import required the compatibility loader")
            };
            assert_eq!(graph.records().count(), 1);
            let deferred = graph.deferred_dynamic_links();
            assert_eq!(deferred.len(), 1);
            let candidates = &deferred.values().next().unwrap().computed_candidates;
            assert_eq!(candidates.len(), 2);
            assert!(candidates
                .iter()
                .any(|(_, spelling)| spelling == "./chosen.mjs"));
            assert!(candidates
                .iter()
                .any(|(_, spelling)| spelling == "./dead.mjs"));
        }
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        for _ in 0..20 {
            let outcome = runtime.settle_authenticated_file_keep_alive_tick().await;
            assert!(
                outcome.is_none(),
                "a computed candidate should settle without terminating keep-alive: {outcome:?}"
            );
            if runtime.lifecycle_exit_code() == 43 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.lifecycle_exit_code(), 43);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test]
    async fn retained_native_activation_turns_package_policy_denial_into_a_rejected_import() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"denied-native-activation","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("entry.mjs"),
            "const delayed = setTimeout(() => { import('image-lib').then(() => { process.exitCode = 99; }, (error) => { if (!String(error).includes('dynamic module activation refused')) throw error; process.exitCode = 44; }); }, 50);\nif (delayed && typeof delayed.unref === 'function') delayed.unref();\nelse if (typeof globalThis.__exactTimerUnref === 'function') globalThis.__exactTimerUnref(delayed);\nelse throw new Error('timer unref unavailable');\n",
        )
        .unwrap();
        let package = directory.path().join("node_modules/image-lib");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"image-lib","version":"2.4.1","type":"module","exports":"./index.mjs"}"#,
        )
        .unwrap();
        std::fs::write(
            package.join("index.mjs"),
            "throw new Error('a policy-denied package target was evaluated');\n",
        )
        .unwrap();
        let mut runtime = session_conformance_direct_runtime_with_package_dynamic_import_policy(
            directory.path(),
            ArmedEntryKind::File,
            "file:///project/entry.mjs",
            ArmedExecutionMode::Program,
            false,
        )
        .unwrap();
        runtime.exec_argv.push("--keep-alive".to_owned());
        {
            let mut ingress = runtime.authenticated_file_ingress().unwrap();
            let request = ingress.file_request(&[]).unwrap();
            let preflight = ingress
                .prepare_authenticated_module_graph(&request)
                .unwrap_or_else(|error| panic!("denied import preflight failed: {error:#}"));
            let crate::engine::AuthenticatedModuleGraphPreparation::Native(graph) = preflight
            else {
                panic!("a deferred denied import required the compatibility loader")
            };
            assert_eq!(graph.records().count(), 1);
            assert_eq!(graph.deferred_dynamic_links().len(), 1);
        }
        runtime.load_runtime().await.unwrap();
        assert_eq!(
            runtime.run_authenticated_file_program(&[]).await.unwrap(),
            AuthenticatedFileProgramOutcome::Completed
        );
        assert_eq!(runtime.lifecycle_exit_code(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        for _ in 0..20 {
            let outcome = runtime.settle_authenticated_file_keep_alive_tick().await;
            assert!(
                outcome.is_none(),
                "a denied import should reject without terminating keep-alive: {outcome:?}"
            );
            if runtime.lifecycle_exit_code() == 44 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.lifecycle_exit_code(), 44);
    }

    #[cfg(all(
        feature = "module-runner",
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn compatibility_call_time_refusals_preserve_import_and_require_error_timing() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::set_var("EXACT_COMPAT_TEST", "1");
        std::env::remove_var("IBEX_LEGACY_MODULE_LOADER");

        {
            let directory = tempdir().unwrap();
            let project = directory.path().join("dynamic");
            std::fs::create_dir(&project).unwrap();
            std::fs::write(
                project.join("package.json"),
                r#"{"name":"compat-dynamic-refusal","private":true,"type":"module"}"#,
            )
            .unwrap();
            std::fs::write(
                project.join("entry.mjs"),
                "let synchronous = false;\nlet first;\nlet second;\nlet coerced;\nlet symbolImport;\nlet coercions = 0;\ntry {\n  first = import('./missing.mjs');\n  second = import('./missing.mjs');\n  coerced = import({ toString() { coercions += 1; return './missing-coerced.mjs'; } });\n  symbolImport = import(Symbol('missing'));\n} catch (_) { synchronous = true; }\nif (synchronous || first === second) throw new Error('dynamic import did not return fresh promises');\nif (coercions !== 1) throw new Error('dynamic import did not apply ToString exactly once');\nconst outcomes = await Promise.all([first, second, coerced, symbolImport].map((promise) => promise.then(() => 'fulfilled', () => 'rejected')));\nif (outcomes.some((outcome) => outcome !== 'rejected')) throw new Error('invalid dynamic import did not reject');\nprocess.exitCode = 39;\n",
            )
            .unwrap();
            let runtime = session_conformance_direct_runtime(
                &project,
                ArmedEntryKind::File,
                "file:///project/entry.mjs",
                ArmedExecutionMode::Program,
            )
            .unwrap();
            runtime.load_runtime().await.unwrap();
            assert_eq!(
                runtime.run_authenticated_file_program(&[]).await.unwrap(),
                AuthenticatedFileProgramOutcome::Completed
            );
            assert_eq!(runtime.lifecycle_exit_code(), 39);
        }

        {
            let directory = tempdir().unwrap();
            let project = directory.path().join("commonjs");
            std::fs::create_dir(&project).unwrap();
            std::fs::write(
                project.join("package.json"),
                r#"{"name":"compat-require-refusal","private":true,"type":"commonjs"}"#,
            )
            .unwrap();
            std::fs::write(
                project.join("entry.cjs"),
                "let synchronous = false;\ntry { require('./missing.cjs'); } catch (_) { synchronous = true; }\nif (!synchronous) throw new Error('missing require did not throw synchronously');\nprocess.exitCode = 38;\n",
            )
            .unwrap();
            let runtime = session_conformance_direct_runtime(
                &project,
                ArmedEntryKind::File,
                "file:///project/entry.cjs",
                ArmedExecutionMode::Program,
            )
            .unwrap();
            runtime.load_runtime().await.unwrap();
            assert_eq!(
                runtime.run_authenticated_file_program(&[]).await.unwrap(),
                AuthenticatedFileProgramOutcome::Completed
            );
            assert_eq!(runtime.lifecycle_exit_code(), 38);
        }
    }

    #[cfg(all(
        feature = "capsec-conformance-observer",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn structured_session_dynamic_import_retains_referrer_and_reauthorizes_cache_hits() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let directory = tempdir().unwrap();
        let subdirectory = directory.path().join("sub");
        std::fs::create_dir(&subdirectory).unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"structured-dynamic-import","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("value.mjs"),
            "export const where = 'root-decoy'; export const runs = -1;\n",
        )
        .unwrap();
        let dependency_path = subdirectory.join("value.mjs");
        std::fs::write(
            &dependency_path,
            "globalThis.__structuredDynamicRuns = (globalThis.__structuredDynamicRuns || 0) + 1; export const where = 'sub'; export const runs = globalThis.__structuredDynamicRuns;\n",
        )
        .unwrap();
        std::fs::write(
            subdirectory.join("install.js"),
            "var retainedDynamicImport = function () { return import('./value.mjs'); }; 'installed';\n",
        )
        .unwrap();

        let (_host, engine, mut ingress) =
            session_conformance_repl_parts(directory.path()).unwrap();
        engine.load_runtime().await.unwrap();
        let installed = ingress
            .evaluate_load(engine.as_ref(), "sub/install.js")
            .await
            .unwrap();
        if let crate::engine::AuthenticatedEvaluation::Value {
            receipt: Some(receipt),
            ..
        } = installed
        {
            engine.release_undisplayed_value(receipt).await.unwrap();
        }

        crate::host::abi::reset_session_root_resolve_counts_for_test();
        let dead_branch = ingress
            .evaluate_inline(
                engine.as_ref(),
                b"if (false) import('./must-not-resolve.mjs'); 'dead-ok'".to_vec(),
            )
            .await
            .unwrap();
        let crate::engine::AuthenticatedEvaluation::Value { display, receipt } = dead_branch else {
            panic!("a dead dynamic-import branch did not complete normally")
        };
        assert_eq!(display.text, serde_json::to_string("dead-ok").unwrap());
        assert_eq!(
            crate::host::abi::session_root_resolve_counts_for_test(),
            (0, 0),
            "a dead dynamic-import branch touched the session resolver"
        );
        engine
            .release_undisplayed_value(receipt.expect("dead-branch value must retain a receipt"))
            .await
            .unwrap();

        let first = ingress
            .evaluate_inline(
                engine.as_ref(),
                b"var firstRetainedPromise = retainedDynamicImport(); var firstRetained = await firstRetainedPromise; JSON.stringify([firstRetained.where, firstRetained.runs])".to_vec(),
            )
            .await
            .unwrap();
        let crate::engine::AuthenticatedEvaluation::Value { display, receipt } = first else {
            panic!("the first retained dynamic import did not complete normally")
        };
        let first_json: String = serde_json::from_str(&display.text).unwrap();
        assert_eq!(first_json, r#"["sub",1]"#);
        engine
            .release_undisplayed_value(receipt.expect("first import value must retain a receipt"))
            .await
            .unwrap();
        assert_eq!(
            crate::host::abi::session_root_resolve_counts_for_test(),
            (1, 1),
            "the first relative dynamic import must use one metadata and one full session resolution"
        );

        std::fs::write(
            &dependency_path,
            "throw new Error('a cached dynamic import re-read changed source');\n",
        )
        .unwrap();
        let second = ingress
            .evaluate_inline(
                engine.as_ref(),
                b"var secondRetainedPromise = retainedDynamicImport(); var secondRetained = await secondRetainedPromise; JSON.stringify({ freshPromise: secondRetainedPromise !== firstRetainedPromise, sameNamespace: secondRetained === firstRetained, where: secondRetained.where, runs: secondRetained.runs })".to_vec(),
            )
            .await
            .unwrap();
        let crate::engine::AuthenticatedEvaluation::Value { display, receipt } = second else {
            panic!("the cached retained dynamic import did not complete normally")
        };
        let second_json: String = serde_json::from_str(&display.text).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&second_json).unwrap(),
            serde_json::json!({
                "freshPromise": true,
                "sameNamespace": true,
                "where": "sub",
                "runs": 1,
            })
        );
        engine
            .release_undisplayed_value(receipt.expect("cached import value must retain a receipt"))
            .await
            .unwrap();
        assert_eq!(
            crate::host::abi::session_root_resolve_counts_for_test(),
            (1, 1),
            "a cache hit repeated session resolution or source acquisition"
        );

        let poisoned_promise = ingress
            .evaluate_inline(
                engine.as_ref(),
                b"var structuredOriginalPromise = globalThis.Promise; var structuredPoisonCalls = 0; var structuredPoison = { resolve() { structuredPoisonCalls += 1; throw new Error('mutable Promise.resolve was used'); }, prototype: { then() { structuredPoisonCalls += 1; throw new Error('mutable Promise.prototype.then was used'); } } }; globalThis.Promise = structuredPoison; var structuredPoisonInstalled = globalThis.Promise === structuredPoison; var structuredPoisonSynchronous = false; var structuredPoisonedPromise; try { structuredPoisonedPromise = retainedDynamicImport(); } catch (_) { structuredPoisonSynchronous = true; } globalThis.Promise = structuredOriginalPromise; var structuredPoisonedNamespace = await structuredPoisonedPromise; JSON.stringify({ installed: structuredPoisonInstalled, synchronous: structuredPoisonSynchronous, nativePromise: structuredPoisonedPromise instanceof structuredOriginalPromise, sameNamespace: structuredPoisonedNamespace === secondRetained, poisonCalls: structuredPoisonCalls })".to_vec(),
            )
            .await
            .unwrap();
        let crate::engine::AuthenticatedEvaluation::Value { display, receipt } = poisoned_promise
        else {
            panic!("the Promise-poisoned retained dynamic import did not complete normally")
        };
        let poisoned_json: String = serde_json::from_str(&display.text).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&poisoned_json).unwrap(),
            serde_json::json!({
                "installed": true,
                "synchronous": false,
                "nativePromise": true,
                "sameNamespace": true,
                "poisonCalls": 0,
            })
        );
        engine
            .release_undisplayed_value(
                receipt.expect("Promise-poisoned import value must retain a receipt"),
            )
            .await
            .unwrap();
        assert_eq!(
            crate::host::abi::session_root_resolve_counts_for_test(),
            (1, 1),
            "Promise poisoning changed cached dynamic-import resolution"
        );

        crate::host::abi::reset_session_root_resolve_counts_for_test();
        let rejected = ingress
            .evaluate_inline(
                engine.as_ref(),
                b"let structuredSynchronous = false; let structuredFirst; let structuredSecond; let structuredCoerced; let structuredSymbol; let structuredCoercions = 0; try { structuredFirst = import('./missing.mjs'); structuredSecond = import('./missing.mjs'); structuredCoerced = import({ toString() { structuredCoercions += 1; return './missing-coerced.mjs'; } }); structuredSymbol = import(Symbol('missing')); } catch (_) { structuredSynchronous = true; } const structuredOutcomes = await Promise.all([structuredFirst, structuredSecond, structuredCoerced, structuredSymbol].map((promise) => promise.then(() => 'fulfilled', () => 'rejected'))); JSON.stringify({ synchronous: structuredSynchronous, fresh: structuredFirst !== structuredSecond, coercions: structuredCoercions, outcomes: structuredOutcomes })".to_vec(),
            )
            .await
            .unwrap();
        let crate::engine::AuthenticatedEvaluation::Value { display, receipt } = rejected else {
            panic!("structured rejected-import semantics did not settle normally")
        };
        let rejected_json: String = serde_json::from_str(&display.text).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rejected_json).unwrap(),
            serde_json::json!({
                "synchronous": false,
                "fresh": true,
                "coercions": 1,
                "outcomes": ["rejected", "rejected", "rejected", "rejected"],
            })
        );
        engine
            .release_undisplayed_value(
                receipt.expect("rejected-import value must retain a receipt"),
            )
            .await
            .unwrap();
        assert_eq!(
            crate::host::abi::session_root_resolve_counts_for_test(),
            (0, 3),
            "invalid imports must reject after ToString without a full source read"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn ingress_test_plan(
        entry_kind: capsec_semantics::arming::ArmedEntryKind,
        mode: capsec_semantics::arming::ArmedExecutionMode,
    ) -> crate::terminal_session::SessionIoPlan {
        use crate::terminal_session::{
            CapturedPresentation, NativeTerminalFacts, PresentationTopology,
            SelectedExecutionRoute, SessionIoPlan,
        };

        let interactive = mode == capsec_semantics::arming::ArmedExecutionMode::Interactive;
        SessionIoPlan {
            route: SelectedExecutionRoute { entry_kind, mode },
            terminal_facts: NativeTerminalFacts {
                stdin_is_tty: interactive,
                stdout_is_tty: interactive,
                stderr_is_tty: false,
            },
            presentation: CapturedPresentation {
                topology: if interactive {
                    PresentationTopology::StdoutTty
                } else {
                    PresentationTopology::Transcript
                },
                session_ansi: interactive,
                editor_control: interactive,
            },
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn repl_ingress_retains_authenticated_mode_and_exclusive_sequence() {
        use capsec_semantics::arming::ArmedExecutionMode;

        let project = tempdir().unwrap();
        let host = armed_repl_ingress_test_host(project.path(), ArmedExecutionMode::Transcript);
        let plan = repl_ingress_test_plan(ArmedExecutionMode::Transcript);
        let mismatched = repl_ingress_test_plan(ArmedExecutionMode::Interactive);
        let error = ReplSessionIngress::from_armed_repl_runtime(host.clone(), mismatched)
            .err()
            .expect("pre-arming I/O facts cannot be cross-paired with the snapshot");
        assert!(error.to_string().contains("does not match"));

        let ingress = ReplSessionIngress::from_armed_repl_runtime(host.clone(), plan).unwrap();
        assert_eq!(ingress.mode(), ArmedExecutionMode::Transcript);
        assert_eq!(ingress.presentation(), plan.presentation);
        assert!(!ingress.presentation().session_ansi);
        assert!(!ingress.presentation().editor_control);
        let vfs = host.virtual_file_system().unwrap();
        let base = vfs.default_base().unwrap();
        assert_eq!(base.virtual_path(), "/project");
        assert_eq!(vfs.mounts().len(), 1);
        assert_eq!(vfs.mounts()[0].virtual_path(), "/project");
        assert_eq!(
            vfs.mounts()[0].logical_root(),
            capsec_semantics::model::LogicalRoot::Project
        );
        assert_eq!(
            vfs.mounts()[0].attributes().lifecycle,
            ibex_runtime::vfs::MountLifecycle::Session
        );
        assert!(
            !format!("{vfs:?}").contains(project.path().to_string_lossy().as_ref()),
            "parity-safe mount diagnostics must not contain a backing host path"
        );
        vfs.close();

        let error = ReplSessionIngress::from_armed_repl_runtime(host.clone(), plan)
            .err()
            .expect("one armed session cannot claim two submission sequences");
        assert_eq!(
            error.downcast_ref::<ibex_runtime::engine::evaluation::SourceRefusal>(),
            Some(&ibex_runtime::engine::evaluation::SourceRefusal::SequenceAlreadyClaimed)
        );
        drop(ingress);
        ReplSessionIngress::from_armed_repl_runtime(host, plan)
            .expect("dropping the ingress releases its exclusive sequence");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn repl_ingress_bounds_and_authenticates_inline_bytes_before_evaluation() {
        use capsec_semantics::arming::ArmedExecutionMode;

        let project = tempdir().unwrap();
        let host = armed_repl_ingress_test_host(project.path(), ArmedExecutionMode::Transcript);
        let plan = repl_ingress_test_plan(ArmedExecutionMode::Transcript);
        let vfs = host.virtual_file_system().unwrap();
        let base = vfs.default_base().unwrap();
        let mut ingress = ReplSessionIngress::from_armed_repl_runtime(host, plan).unwrap();
        let too_large = vec![b'x'; ibex_runtime::session_constants::MAX_INPUT_BYTES + 1];
        let error = ingress.inline_request(&base, too_large).unwrap_err();
        assert!(error.to_string().contains("authenticated input limit"));

        let invalid_utf8 = ingress.inline_request(&base, vec![0xff]).unwrap_err();
        assert!(invalid_utf8.to_string().contains("not valid UTF-8"));
        let request = ingress
            .inline_request(&base, b"const answer: number = 42".to_vec())
            .unwrap();
        assert_eq!(request.source_label().as_str(), "repl:1");
        assert_eq!(request.text().as_str(), "const answer: number = 42");
        assert_eq!(
            request.execution_mode(),
            ibex_runtime::engine::evaluation::ExecutionMode::Transcript
        );
        assert_eq!(
            request.entry_kind(),
            ibex_runtime::engine::evaluation::EntryKind::Repl
        );
        assert!(request.authenticated_principal().is_root());
        assert!(request.virtual_referrer().components.is_empty());
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn non_file_inline_ingress_derives_eval_and_program_stdin_shapes() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};
        use ibex_runtime::engine::evaluation::{
            EntryKind, ExecutionMode, ModuleKind, ParserDialect, SourceGoal, SourceRequest,
            SourceRole,
        };

        let project = tempdir().unwrap();
        let eval_host = armed_ingress_test_host(
            project.path(),
            ArmedEntryKind::Eval,
            "ibex:eval",
            ArmedExecutionMode::OneShot,
        );
        let eval_plan = ingress_test_plan(ArmedEntryKind::Eval, ArmedExecutionMode::OneShot);
        let wrong_plan = ingress_test_plan(ArmedEntryKind::Stdin, ArmedExecutionMode::Program);
        let error = AuthenticatedInlineIngress::from_armed_runtime(eval_host.clone(), wrong_plan)
            .err()
            .expect("the authenticated entry cannot be cross-paired with another route");
        assert!(error.to_string().contains("does not match"));

        let mut eval =
            AuthenticatedInlineIngress::from_armed_runtime(eval_host, eval_plan).unwrap();
        assert_eq!(eval.mode(), ArmedExecutionMode::OneShot);
        let eval_request = eval
            .inline_request(b"const answer: number = await Promise.resolve(42)".to_vec())
            .unwrap();
        assert_eq!(eval_request.source_label().as_str(), "ibex:eval");
        assert_eq!(eval_request.execution_mode(), ExecutionMode::OneShot);
        assert_eq!(eval_request.entry_kind(), EntryKind::Eval);
        let SourceRequest::Program(eval_program) = &eval_request else {
            panic!("eval source must be a program request")
        };
        assert_eq!(eval_program.goal(), SourceGoal::ScriptWithExtensions);
        assert_eq!(eval_program.dialect(), ParserDialect::TypeScript);
        assert_eq!(eval_program.role(), SourceRole::Entry);
        assert_eq!(eval_program.module_kind(), None);
        assert!(!eval_program.is_main());

        let stdin_host = armed_ingress_test_host(
            project.path(),
            ArmedEntryKind::Stdin,
            "ibex:stdin",
            ArmedExecutionMode::Program,
        );
        let stdin_plan = ingress_test_plan(ArmedEntryKind::Stdin, ArmedExecutionMode::Program);
        let mut stdin =
            AuthenticatedInlineIngress::from_armed_runtime(stdin_host, stdin_plan).unwrap();
        let stdin_request = stdin
            .inline_request(b"export const answer: number = await Promise.resolve(42)".to_vec())
            .unwrap();
        assert_eq!(stdin_request.source_label().as_str(), "ibex:stdin");
        assert_eq!(stdin_request.execution_mode(), ExecutionMode::Program);
        assert_eq!(stdin_request.entry_kind(), EntryKind::Stdin);
        let SourceRequest::Program(stdin_program) = &stdin_request else {
            panic!("stdin source must be a program request")
        };
        assert_eq!(stdin_program.goal(), SourceGoal::Module);
        assert_eq!(stdin_program.dialect(), ParserDialect::TypeScript);
        assert_eq!(stdin_program.role(), SourceRole::Entry);
        assert_eq!(stdin_program.module_kind(), Some(ModuleKind::Esm));
        assert!(stdin_program.is_main());
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn repl_ingress_load_uses_vfs_canonical_path_and_authenticated_bytes() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("src")).unwrap();
        std::fs::write(
            project.path().join("src/a b.ts"),
            "export const answer: number = 42;\n",
        )
        .unwrap();
        std::fs::write(project.path().join("src/data.json"), "{\"answer\":42}\n").unwrap();
        let (host, engine, mut ingress) = session_conformance_repl_parts(project.path()).unwrap();
        engine.load_runtime().await.unwrap();
        let runtime_vfs = engine.authenticated_runtime_vfs(&host).await.unwrap();
        let request = ingress
            .load_request(&runtime_vfs, "src/../src/a b.ts")
            .unwrap();
        assert_eq!(
            request.source_label().as_str(),
            "repl:1:/project/src/a b.ts"
        );
        assert_eq!(
            request.text().as_str(),
            "export const answer: number = 42;\n"
        );
        assert_eq!(request.virtual_referrer().components.len(), 1);
        assert_eq!(request.virtual_referrer().components[0].bytes(), b"src");
        drop(request);

        let json = ingress.load_request(&runtime_vfs, "src/data.json").unwrap();
        assert!(matches!(
            &json,
            ibex_runtime::engine::evaluation::SourceRequest::JsonData(_)
        ));
        assert_eq!(
            json.source_label().as_str(),
            "repl:1:/project/src/data.json"
        );
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn repl_ingress_uses_native_runtime_cwd_after_chdir() {
        use crate::engine::{AuthenticatedDisplayKind, AuthenticatedEvaluation};
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        async fn take_string(engine: &dyn Engine, evaluation: AuthenticatedEvaluation) -> String {
            let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
                panic!("authenticated REPL source did not produce a value")
            };
            assert_eq!(display.kind, AuthenticatedDisplayKind::String);
            engine
                .release_undisplayed_value(
                    receipt.expect("authenticated REPL value has no display receipt"),
                )
                .await
                .unwrap();
            serde_json::from_str(&display.text).unwrap()
        }

        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let project = tempdir().unwrap();
        std::fs::create_dir(project.path().join("sub")).unwrap();
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"repl-cwd-projection","private":true,"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(
            project.path().join("sub/relative.mjs"),
            "export default 'module-from-sub';\n",
        )
        .unwrap();
        std::fs::write(project.path().join("sub/loaded.js"), "'load-from-sub';\n").unwrap();

        let host = armed_ingress_test_host_with_root_fs_read(
            project.path(),
            ArmedEntryKind::Repl,
            "ibex:repl",
            ArmedExecutionMode::Transcript,
        );
        let foreign_host = armed_ingress_test_host_with_root_fs_read(
            project.path(),
            ArmedEntryKind::Repl,
            "ibex:repl",
            ArmedExecutionMode::Transcript,
        );
        let digest = host.armed_snapshot().unwrap().digest().as_str().to_owned();
        crate::host::abi::install_host(host.clone());
        let engine = crate::engine::create_engine("hermes", Some(&digest)).unwrap();
        let mut ingress = ReplSessionIngress::from_armed_repl_runtime(
            host.clone(),
            repl_ingress_test_plan(ArmedExecutionMode::Transcript),
        )
        .unwrap();
        engine.load_runtime().await.unwrap();
        let foreign_error = engine
            .authenticated_runtime_vfs(&foreign_host)
            .await
            .unwrap_err();
        assert_eq!(
            foreign_error
                .downcast_ref::<ibex_runtime::vfs::VfsError>()
                .unwrap()
                .reason(),
            ibex_runtime::vfs::VfsReason::StaleSession,
            "an engine generation must reject an equal-snapshot foreign Host"
        );

        let changed = ingress
            .evaluate_inline(
                engine.as_ref(),
                b"process.chdir('/project/sub'); process.cwd()".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(take_string(engine.as_ref(), changed).await, "/project/sub");

        let imported = ingress
            .evaluate_inline(
                engine.as_ref(),
                b"var replCwdModule = await import('./relative.mjs'); replCwdModule.default"
                    .to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(
            take_string(engine.as_ref(), imported).await,
            "module-from-sub"
        );

        let loaded = ingress
            .evaluate_load(engine.as_ref(), "loaded.js")
            .await
            .unwrap();
        assert_eq!(take_string(engine.as_ref(), loaded).await, "load-from-sub");

        let mounts = ingress.mounts_description(engine.as_ref()).await.unwrap();
        assert_eq!(mounts.virtual_cwd(), "/project/sub");
        assert_eq!(mounts.mounts().len(), 1);
        assert_eq!(mounts.mounts()[0].virtual_path(), "/project");
        assert!(
            !format!("{mounts:?}").contains(project.path().to_string_lossy().as_ref()),
            "runtime cwd projection disclosed the backing host path"
        );

        let stale_lease = engine.authenticated_runtime_vfs(&host).await.unwrap();
        drop(ingress);
        drop(engine);
        assert_eq!(
            stale_lease.capture_cwd().unwrap_err().reason(),
            ibex_runtime::vfs::VfsReason::StaleSession,
            "an ingress lease retained past native teardown must fail stale"
        );
    }

    fn test_project_root_discovery(
        origin: &Path,
        stop_boundary: &Path,
    ) -> Result<ProjectRootDiscovery> {
        discover_project_root_from_origin(origin, None, None, Some(stop_boundary), |_| {
            Ok("test-device".to_owned())
        })
    }

    #[test]
    fn authenticated_project_root_falls_back_to_origin_and_records_explicit_override() {
        let manifestless = tempdir().unwrap();
        let entry = manifestless.path().join("src/app.js");
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(&entry, "console.log('manifestless');\n").unwrap();
        let implicit = Cli::parse_from(["ibex", entry.to_str().unwrap()]);
        let canonical_entry = std::fs::canonicalize(&entry).unwrap();
        let discovery = discover_project_root_from_origin(
            canonical_entry.parent().unwrap(),
            None,
            Some(&canonical_entry),
            manifestless.path().parent(),
            |_| Ok("test-device".to_owned()),
        );
        let discovery = discovery.unwrap();
        assert_eq!(
            discovery.selected_root,
            std::fs::canonicalize(entry.parent().unwrap()).unwrap()
        );
        assert_eq!(discovery.marker_kind, ProjectRootMarkerKind::OriginFallback);
        assert_eq!(discovery.marker_path, None);
        assert_eq!(discovery.diagnostic, Some(PROJECT_ROOT_FALLBACK_DIAGNOSTIC));
        assert_eq!(
            discovery.marker_set_version,
            PROJECT_ROOT_MARKER_SET_VERSION
        );
        assert_eq!(
            authenticated_project_root(&implicit, implicit.file.as_deref()).unwrap(),
            std::fs::canonicalize(entry.parent().unwrap()).unwrap()
        );

        let explicit = Cli::parse_from([
            "ibex",
            "--project-root",
            manifestless.path().to_str().unwrap(),
            entry.to_str().unwrap(),
        ]);
        let explicit_discovery = discover_project_root_from_origin(
            canonical_entry.parent().unwrap(),
            Some(manifestless.path()),
            Some(&canonical_entry),
            manifestless.path().parent(),
            |_| Ok("test-device".to_owned()),
        )
        .unwrap();
        assert_eq!(
            explicit_discovery.marker_kind,
            ProjectRootMarkerKind::ExplicitProject
        );
        assert_eq!(
            explicit_discovery.marker_path,
            Some(std::fs::canonicalize(manifestless.path()).unwrap())
        );
        assert_eq!(
            authenticated_project_root(&explicit, explicit.file.as_deref()).unwrap(),
            std::fs::canonicalize(manifestless.path()).unwrap()
        );
    }

    #[test]
    fn authenticated_project_root_discovers_manifest_above_src_entry() {
        let project = tempdir().unwrap();
        let entry = project.path().join("src/app.js");
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(project.path().join("package.json"), "{\"name\":\"app\"}\n").unwrap();
        std::fs::write(&entry, "console.log('src entry');\n").unwrap();
        let cli = Cli::parse_from(["ibex", entry.to_str().unwrap()]);
        let discovery =
            test_project_root_discovery(entry.parent().unwrap(), project.path().parent().unwrap())
                .unwrap();
        assert_eq!(
            discovery.marker_kind,
            ProjectRootMarkerKind::PackageManifest
        );
        assert_eq!(
            discovery.marker_path,
            Some(std::fs::canonicalize(project.path().join("package.json")).unwrap())
        );
        assert_eq!(
            authenticated_project_root(&cli, cli.file.as_deref()).unwrap(),
            std::fs::canonicalize(project.path()).unwrap()
        );
    }

    #[test]
    fn project_root_discovery_uses_ancestor_inclusive_workspace_membership() {
        for member_has_lockfile in [false, true] {
            let workspace = tempdir().unwrap();
            let member = workspace.path().join("packages/foo");
            let origin = member.join("src/deep");
            std::fs::create_dir_all(&origin).unwrap();
            std::fs::write(
                workspace.path().join("package.json"),
                "{\"private\":true,\"workspaces\":[\"packages/*\"]}\n",
            )
            .unwrap();
            std::fs::write(member.join("package.json"), "{\"name\":\"foo\"}\n").unwrap();
            if member_has_lockfile {
                std::fs::write(member.join("package-lock.json"), "{}\n").unwrap();
            }

            let discovery =
                test_project_root_discovery(&origin, workspace.path().parent().unwrap()).unwrap();
            assert_eq!(
                discovery.selected_root,
                std::fs::canonicalize(workspace.path()).unwrap(),
                "workspace must beat the member's nearer marker (member lockfile: {member_has_lockfile})"
            );
            assert_eq!(
                discovery.marker_kind,
                ProjectRootMarkerKind::PackageWorkspace
            );
        }
    }

    #[test]
    fn project_root_discovery_selects_the_outermost_matching_workspace() {
        let outer = tempdir().unwrap();
        let inner = outer.path().join("packages/foo");
        let origin = inner.join("members/bar/src");
        std::fs::create_dir_all(&origin).unwrap();
        std::fs::write(
            outer.path().join("package.json"),
            "{\"workspaces\":[\"packages/**\"]}\n",
        )
        .unwrap();
        std::fs::write(
            inner.join("package.json"),
            "{\"workspaces\":[\"members/*\"]}\n",
        )
        .unwrap();

        let discovery =
            test_project_root_discovery(&origin, outer.path().parent().unwrap()).unwrap();
        assert_eq!(
            discovery.selected_root,
            std::fs::canonicalize(outer.path()).unwrap()
        );
        assert_eq!(
            discovery.marker_kind,
            ProjectRootMarkerKind::PackageWorkspace
        );
    }

    #[test]
    fn project_root_discovery_supports_pnpm_membership_and_last_match_wins() {
        let workspace = tempdir().unwrap();
        let member = workspace.path().join("packages/foo");
        let origin = member.join("src");
        std::fs::create_dir_all(&origin).unwrap();
        std::fs::write(member.join("package.json"), "{\"name\":\"foo\"}\n").unwrap();
        let marker = workspace.path().join("pnpm-workspace.yaml");
        std::fs::write(
            &marker,
            "packages:\n  - 'packages/**'\n  - '!packages/foo/**'\n",
        )
        .unwrap();

        let excluded =
            test_project_root_discovery(&origin, workspace.path().parent().unwrap()).unwrap();
        assert_eq!(
            excluded.selected_root,
            std::fs::canonicalize(&member).unwrap()
        );
        assert_eq!(excluded.marker_kind, ProjectRootMarkerKind::PackageManifest);

        std::fs::write(
            &marker,
            "packages:\n  - 'packages/**'\n  - '!packages/foo/**'\n  - 'packages/foo'\n",
        )
        .unwrap();
        let reincluded =
            test_project_root_discovery(&origin, workspace.path().parent().unwrap()).unwrap();
        assert_eq!(
            reincluded.selected_root,
            std::fs::canonicalize(workspace.path()).unwrap()
        );
        assert_eq!(reincluded.marker_kind, ProjectRootMarkerKind::PnpmWorkspace);
        assert_eq!(
            reincluded.marker_path,
            Some(std::fs::canonicalize(marker).unwrap())
        );
    }

    #[test]
    fn project_root_marker_v1_parsers_and_glob_dialect_are_exact() {
        assert_eq!(
            parse_package_workspace_patterns(
                br#"{"workspaces":{"packages":["apps/*","tools/**"]}}"#
            )
            .unwrap(),
            Some(vec!["apps/*".to_owned(), "tools/**".to_owned()])
        );
        assert_eq!(
            parse_pnpm_workspace_patterns(b"packages: [packages/*, '!packages/private']\n")
                .unwrap(),
            vec!["packages/*".to_owned(), "!packages/private".to_owned()]
        );
        assert!(workspace_glob_matches("packages/*", "packages/foo"));
        assert!(!workspace_glob_matches("packages/*", "packages/foo/src"));
        assert!(workspace_glob_matches("packages/**", "packages/foo/src"));
        for unsupported in ["apps/?", "apps/[ab]", "apps/{a,b}", "apps/\\*"] {
            assert!(
                validate_workspace_pattern(unsupported).is_err(),
                "unsupported construct was accepted: {unsupported}"
            );
        }
        assert!(parse_pnpm_workspace_patterns(b"packages:\n - apps/*\n  - tools/*\n").is_err());
        assert!(parse_pnpm_workspace_patterns(b"packages:\nother: value\n").is_err());
        assert!(parse_pnpm_workspace_patterns(b"packages:\n  - apps/*\nbroken: [\n").is_err());
    }

    #[test]
    fn project_root_discovery_recognizes_each_v1_lockfile() {
        for lockfile in PROJECT_ROOT_LOCKFILES {
            let project = tempdir().unwrap();
            let member = project.path().join("packages/foo");
            let origin = member.join("src");
            std::fs::create_dir_all(&origin).unwrap();
            std::fs::write(member.join("package.json"), "{\"name\":\"foo\"}\n").unwrap();
            std::fs::write(project.path().join(lockfile), b"lock\n").unwrap();

            let discovery =
                test_project_root_discovery(&origin, project.path().parent().unwrap()).unwrap();
            assert_eq!(
                discovery.selected_root,
                std::fs::canonicalize(project.path()).unwrap()
            );
            assert_eq!(discovery.marker_kind, ProjectRootMarkerKind::Lockfile);
            assert_eq!(
                discovery.marker_path.as_deref().and_then(Path::file_name),
                Some(std::ffi::OsStr::new(lockfile))
            );
        }
    }

    #[test]
    fn project_root_discovery_fails_closed_on_malformed_markers() {
        let project = tempdir().unwrap();
        let origin = project.path().join("src");
        std::fs::create_dir_all(&origin).unwrap();
        let package_marker = project.path().join("package.json");
        std::fs::write(&package_marker, "{\"workspaces\":\"packages/*\"}\n").unwrap();
        let error =
            test_project_root_discovery(&origin, project.path().parent().unwrap()).unwrap_err();
        assert!(
            format!("{error:#}").contains(package_marker.to_str().unwrap()),
            "marker error must name its file: {error:#}"
        );

        std::fs::write(
            &package_marker,
            "{\"workspaces\":[\"packages/{foo,bar}\"]}\n",
        )
        .unwrap();
        let error =
            test_project_root_discovery(&origin, project.path().parent().unwrap()).unwrap_err();
        assert!(
            format!("{error:#}").contains("unsupported glob construct"),
            "unsupported glob must fail closed: {error:#}"
        );

        std::fs::remove_file(&package_marker).unwrap();
        let pnpm_marker = project.path().join("pnpm-workspace.yaml");
        std::fs::write(&pnpm_marker, "packages: packages/*\n").unwrap();
        let error =
            test_project_root_discovery(&origin, project.path().parent().unwrap()).unwrap_err();
        assert!(
            format!("{error:#}").contains(pnpm_marker.to_str().unwrap()),
            "marker error must name its file: {error:#}"
        );

        std::fs::remove_file(&pnpm_marker).unwrap();
        std::fs::create_dir(&package_marker).unwrap();
        let error =
            test_project_root_discovery(&origin, project.path().parent().unwrap()).unwrap_err();
        assert!(
            format!("{error:#}").contains(package_marker.to_str().unwrap())
                && format!("{error:#}").contains("marker is not a file"),
            "unreadable marker must fail closed and name its file: {error:#}"
        );
    }

    #[test]
    fn project_root_discovery_stops_before_home_and_refuses_home_as_origin() {
        let sandbox = tempdir().unwrap();
        let home = sandbox.path().join("home");
        let origin = home.join("project/src");
        std::fs::create_dir_all(&origin).unwrap();
        std::fs::write(home.join("package.json"), "{\"name\":\"stray\"}\n").unwrap();

        let discovery = discover_project_root_from_origin(&origin, None, None, Some(&home), |_| {
            Ok("test-device".to_owned())
        })
        .unwrap();
        assert_eq!(
            discovery.selected_root,
            std::fs::canonicalize(&origin).unwrap()
        );
        assert_eq!(discovery.marker_kind, ProjectRootMarkerKind::OriginFallback);

        let error = discover_project_root_from_origin(&home, None, None, Some(&home), |_| {
            Ok("test-device".to_owned())
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(PROJECT_ROOT_WIDE_MOUNT_DIAGNOSTIC),
            "wide home fallback must have a distinct diagnostic: {error:#}"
        );
    }

    #[test]
    fn project_root_discovery_stops_before_a_device_boundary() {
        let outer = tempdir().unwrap();
        let mounted = outer.path().join("mounted");
        let origin = mounted.join("src");
        std::fs::create_dir_all(&origin).unwrap();
        std::fs::write(
            outer.path().join("package.json"),
            "{\"name\":\"outside-device\"}\n",
        )
        .unwrap();
        std::fs::write(
            mounted.join("package.json"),
            "{\"name\":\"device-boundary\"}\n",
        )
        .unwrap();
        let canonical_mounted = std::fs::canonicalize(&mounted).unwrap();
        let discovery = discover_project_root_from_origin(&origin, None, None, None, |path| {
            Ok(if path.starts_with(&canonical_mounted) {
                "mounted-device"
            } else {
                "outer-device"
            }
            .to_owned())
        })
        .unwrap();
        assert_eq!(
            discovery.selected_root,
            std::fs::canonicalize(&origin).unwrap()
        );
        assert_eq!(discovery.marker_kind, ProjectRootMarkerKind::OriginFallback);

        let error = discover_project_root_from_origin(&mounted, None, None, None, |path| {
            Ok(if path.starts_with(&canonical_mounted) {
                "mounted-device"
            } else {
                "outer-device"
            }
            .to_owned())
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(PROJECT_ROOT_WIDE_MOUNT_DIAGNOSTIC),
            "device-wide origin fallback must have a distinct diagnostic: {error:#}"
        );
    }

    #[test]
    fn authenticated_launch_entry_binds_the_selected_route_to_a_virtual_label() {
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        let project = tempdir().unwrap();
        let entry = project.path().join("src/a b%é.js");
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(project.path().join("package.json"), "{\"name\":\"app\"}\n").unwrap();
        std::fs::write(&entry, "42;\n").unwrap();
        let cli = Cli::parse_from([
            "ibex",
            "--project-root",
            project.path().to_str().unwrap(),
            entry.to_str().unwrap(),
        ]);
        let launch = authenticate_launch_entry(
            &cli,
            crate::terminal_session::SelectedExecutionRoute {
                entry_kind: ArmedEntryKind::File,
                mode: ArmedExecutionMode::Program,
            },
        )
        .unwrap();
        assert_eq!(
            launch.project_root,
            std::fs::canonicalize(project.path()).unwrap()
        );
        assert_eq!(
            launch.project_discovery.marker_kind,
            ProjectRootMarkerKind::ExplicitProject
        );
        assert_eq!(
            launch.project_discovery.marker_set_version,
            PROJECT_ROOT_MARKER_SET_VERSION
        );
        assert_eq!(launch.entry.kind, ArmedEntryKind::File);
        assert_eq!(launch.entry.mode, ArmedExecutionMode::Program);
        assert_eq!(
            launch.entry.identity.as_str(),
            "file:///project/src/a%20b%25%C3%A9.js"
        );

        let eval_cli = Cli::parse_from([
            "ibex",
            "--project-root",
            project.path().to_str().unwrap(),
            "--eval",
            "42",
        ]);
        let eval = authenticate_launch_entry(
            &eval_cli,
            crate::terminal_session::SelectedExecutionRoute {
                entry_kind: ArmedEntryKind::Eval,
                mode: ArmedExecutionMode::OneShot,
            },
        )
        .unwrap();
        assert_eq!(eval.entry.identity.as_str(), "ibex:eval");
    }

    #[test]
    fn authenticated_packages_reject_duplicate_locator_with_one_drifted_copy() {
        let project = tempdir().unwrap();
        let first = project.path().join("node_modules/dup");
        let parent = project.path().join("node_modules/parent");
        let second = parent.join("node_modules/dup");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(
            first.join("package.json"),
            r#"{"name":"dup","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(first.join("index.js"), "module.exports = 'valid';").unwrap();
        std::fs::write(
            parent.join("package.json"),
            r#"{"name":"parent","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            second.join("package.json"),
            r#"{"name":"dup","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(second.join("index.js"), "module.exports = 'drifted';").unwrap();
        let expected = crate::module_loader::package_tree_integrity(&first).unwrap();
        let principals = vec![serde_json::json!({
            "principal": {
                "kind": "package",
                "name": "dup",
                "locator": "dup@1.0.0",
                "integrity": expected,
            }
        })];

        let error = authenticated_installed_packages(project.path(), &principals).unwrap_err();
        assert!(
            error.to_string().contains("duplicate name+locator roots"),
            "{error:#}"
        );
    }

    #[test]
    fn protected_artifacts_are_distinct_pinned_and_reject_mutable_reuse() {
        let cache = tempdir().unwrap();
        let roles = ["armed-policy", "engine-binary", "package-graph", "registry"];
        let mut identities = std::collections::BTreeSet::new();
        for role in roles {
            let bytes = format!("protected:{role}");
            let identity = materialize_protected_artifact(
                cache.path(),
                role,
                "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                bytes.as_bytes(),
            )
            .unwrap();
            assert!(identities.insert(identity.object.to_string()));
        }
        assert_eq!(identities.len(), 4);

        let directory = cache.path().join("capsec-artifacts");
        let policy = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.to_string_lossy().contains("armed-policy"))
            .unwrap();
        let mut permissions = std::fs::metadata(&policy).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o600);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        std::fs::set_permissions(&policy, permissions).unwrap();
        let error = materialize_protected_artifact(
            cache.path(),
            "armed-policy",
            "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            b"protected:armed-policy",
        )
        .unwrap_err();
        assert!(error.to_string().contains("mutable"), "{error:#}");
    }

    fn write_arming_fixture(directory: &Path) -> (PathBuf, PathBuf, String, PathBuf) {
        use capsec_semantics::arming::ExpectedArmingIdentity;
        use capsec_semantics::model::Digest;

        let entry_path = directory.join("app.ts");
        std::fs::write(
            directory.join("package.json"),
            "{\"name\":\"arming-fixture\"}\n",
        )
        .unwrap();
        std::fs::write(&entry_path, "1 + 1;\n").unwrap();
        let canonical_root = std::fs::canonicalize(directory).unwrap();
        let canonical_entry = std::fs::canonicalize(&entry_path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        value["workflow"] = serde_json::Value::String("production".into());
        value["effectiveMode"] = serde_json::Value::String("enforce".into());
        bind_snapshot_fixture_project_root(
            &mut value,
            &canonical_root,
            &canonical_root,
            "package-manifest",
            Some(&canonical_root.join("package.json")),
        );
        let package_principal = value["packageGraph"]["nodes"][0]["principal"].clone();
        let root_principal = value["rootIdentity"].clone();
        let package_object = value["rootBindings"][0]["object"].clone();
        value["packageGraph"]["nodes"][0] = serde_json::json!({
            "principal": package_principal.clone(),
            "resolvingSpecifier": "image-lib",
            "rootObject": package_object,
            "virtualAliases": [{
                "root": "project",
                "components": [
                    {"encoding": "utf8", "value": "node_modules"},
                    {"encoding": "utf8", "value": "image-lib"}
                ]
            }],
            "platformDisposition": "required"
        });
        value["packageGraph"]["importEdges"] = serde_json::json!([
            {
                "importer": root_principal.clone(),
                "imported": package_principal.clone(),
                "requestSpecifier": "image-lib",
                "resolutionKind": "common-js-require",
                "conditions": ["node", "require"],
                "attributes": {}
            },
            {
                "importer": root_principal.clone(),
                "imported": package_principal.clone(),
                "requestSpecifier": "image-lib",
                "resolutionKind": "dynamic-import",
                "conditions": ["import", "node"],
                "attributes": {}
            },
            {
                "importer": root_principal,
                "imported": package_principal,
                "requestSpecifier": "image-lib",
                "resolutionKind": "esm-static",
                "conditions": ["import", "node"],
                "attributes": {}
            }
        ]);
        value["packageGraph"]["digest"] = serde_json::Value::String(
            capsec_semantics::digest::compute_domain_digest(
                "ibex:capsec:package-graph:1",
                &value["packageGraph"],
                &["digest".to_owned()],
            )
            .unwrap(),
        );
        let engine = crate::engine::hermes::HermesEngine::loaded_engine_identity()
            .expect("arming fixture requires the authenticated loaded engine");
        value["engine"]["target"] = serde_json::Value::String(exact_runtime_target());
        value["engine"]["binaryDigest"] = serde_json::Value::String(engine.binary_digest.clone());
        value["engine"]["features"] = serde_json::to_value(observed_structural_features()).unwrap();
        value["entry"] = serde_json::json!({
            "kind": "file",
            "identity": ibex_runtime::vfs::source_label_for_authenticated_project_path(
                &canonical_root,
                &canonical_entry,
            )
            .unwrap()
            .as_str(),
            "mode": "program",
        });
        let protected_engine = value["protectedObjects"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["role"] == "engine-binary")
            .unwrap();
        protected_engine["object"] = serde_json::to_value(&engine.object).unwrap();
        let policy_artifact = materialize_protected_artifact(
            directory,
            "armed-policy",
            value["policyDigest"].as_str().unwrap(),
            b"authenticated canonical policy fixture",
        )
        .unwrap();
        let graph_artifact = materialize_protected_artifact(
            directory,
            "package-graph",
            value["packageGraph"]["digest"].as_str().unwrap(),
            b"authenticated package graph fixture",
        )
        .unwrap();
        let registry_artifact = materialize_protected_artifact(
            directory,
            "registry",
            value["registryDigest"].as_str().unwrap(),
            b"authenticated registry fixture",
        )
        .unwrap();
        for (role, object) in [
            ("armed-policy", &policy_artifact.object),
            ("package-graph", &graph_artifact.object),
            ("registry", &registry_artifact.object),
        ] {
            value["protectedObjects"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["role"] == role)
                .unwrap()["object"] = object.clone();
        }
        let digest = capsec_semantics::digest::compute_checked_contract_digest(
            capsec_semantics::digest::DigestKind::ArmedSnapshot,
            &value,
        )
        .unwrap();
        value["armedSnapshotDigest"] = serde_json::Value::String(digest.clone());
        let digest_at = |path: &[&str]| {
            let field = path
                .iter()
                .fold(&value, |current, segment| &current[*segment]);
            Digest::new(field.as_str().unwrap()).unwrap()
        };
        let expected = ExpectedArmingIdentity {
            profile: value["capsVocab"].as_str().unwrap().into(),
            semantic_core: value["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest_at(&["vocabDigest"]),
            registry_digest: digest_at(&["registryDigest"]),
            policy_digest: digest_at(&["policyDigest"]),
            armed_snapshot_digest: digest_at(&["armedSnapshotDigest"]),
            target: value["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: value["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            entry: serde_json::from_value(value["entry"].clone()).unwrap(),
            project_root_discovery: serde_json::from_value(value["projectRootDiscovery"].clone())
                .unwrap(),
            path_canonicalizers: serde_json::from_value(value["pathCanonicalizers"].clone())
                .unwrap(),
            protected_artifacts: vec![
                capsec_semantics::arming::ExpectedProtectedArtifact {
                    role: capsec_semantics::arming::ProtectedArtifactRole::ArmedPolicy,
                    host_path: policy_artifact.host_path,
                    object: serde_json::from_value(value["protectedObjects"][0]["object"].clone())
                        .unwrap(),
                    content_digest: policy_artifact.content_digest,
                },
                capsec_semantics::arming::ExpectedProtectedArtifact {
                    role: capsec_semantics::arming::ProtectedArtifactRole::EngineBinary,
                    host_path: serde_json::from_value(serde_json::json!({
                        "root": "absolute",
                        "components": runtime_path_components_json(&engine.engine_artifact_path)
                            .unwrap(),
                        "hostBound": true,
                    }))
                    .unwrap(),
                    object: engine.object,
                    content_digest: digest_at(&["engine", "binaryDigest"]),
                },
                capsec_semantics::arming::ExpectedProtectedArtifact {
                    role: capsec_semantics::arming::ProtectedArtifactRole::PackageGraph,
                    host_path: graph_artifact.host_path,
                    object: serde_json::from_value(value["protectedObjects"][2]["object"].clone())
                        .unwrap(),
                    content_digest: graph_artifact.content_digest,
                },
                capsec_semantics::arming::ExpectedProtectedArtifact {
                    role: capsec_semantics::arming::ProtectedArtifactRole::Registry,
                    host_path: registry_artifact.host_path,
                    object: serde_json::from_value(value["protectedObjects"][3]["object"].clone())
                        .unwrap(),
                    content_digest: registry_artifact.content_digest,
                },
            ],
            embedded_protected_artifacts: vec![],
            runtime_extension_authority_digest: None,
            runtime_extension_mapped_executable: None,
        };
        let snapshot_path = directory.join("armed.json");
        let identity_path = directory.join("identity.json");
        std::fs::write(&snapshot_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        std::fs::write(
            &identity_path,
            serde_json::to_vec_pretty(&expected).unwrap(),
        )
        .unwrap();
        (snapshot_path, identity_path, digest, entry_path)
    }

    #[tokio::test]
    async fn armed_startup_requires_paired_artifacts() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::remove_var("IBEX_LOCKDOWN");
        std::env::remove_var("IBEX_COMPARTMENTS");
        let cli = Cli::parse_from(["ibex", "--capsec-armed-snapshot", "snapshot.json", "app.ts"]);
        let error = build_host(&cli)
            .err()
            .expect("must reject unpaired artifacts")
            .to_string();
        assert!(error.contains("must be provided together"), "{error}");
    }

    #[test]
    fn production_entry_admits_only_authenticated_execution_routes() {
        let vectors = [
            vec!["--eval", "1 + 1"],
            vec!["--print", "1 + 1"],
            vec!["eval", "1 + 1"],
            vec!["repl"],
            vec![],
        ];
        for vector in vectors {
            let mut argv = vec!["ibex"];
            argv.extend(vector);
            let cli = Cli::parse_from(argv);
            reject_closed_diagnostic_cli(&cli)
                .expect("authenticated eval, stdin, and REPL routes pass the diagnostic gate");
        }
    }

    #[tokio::test]
    async fn production_entry_closes_debug_before_artifact_io() {
        let _env = ProductionEnvGuard::capture();
        let vectors = [
            vec!["debug", "modules"],
            vec![
                "--eval",
                "globalThis.__closedSmuggledEval = true",
                "debug",
                "modules",
            ],
        ];
        for vector in vectors {
            let mut argv = vec![
                "ibex",
                "--capsec-armed-snapshot",
                "missing-snapshot.json",
                "--capsec-arming-identity",
                "missing-identity.json",
            ];
            argv.extend(vector);
            let cli = Cli::parse_from(argv);
            let error = crate::run(cli)
                .await
                .expect_err("production diagnostic entry must be closed");
            let error = format!("{error:#}");
            assert!(error.contains("closes debug commands"), "{error}");
            assert!(
                !error.contains("failed to read") && !error.contains("__closed"),
                "diagnostic input reached artifact or evaluator I/O: {error}"
            );
        }
    }

    #[test]
    fn foreground_audit_remains_open_and_propagates_its_entry_to_children() {
        let cli = Cli::parse_from(["ibex", "capsec", "audit", "fixture.js"]);
        reject_closed_diagnostic_cli(&cli).expect("explicit foreground audit remains open");
        let exec_argv = build_audit_exec_argv(&cli);
        assert_eq!(exec_argv.first().map(String::as_str), Some("capsec"));
        assert_eq!(exec_argv.get(1).map(String::as_str), Some("audit"));
    }

    #[tokio::test]
    async fn armed_startup_rejects_legacy_authority_overrides_before_io() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::remove_var("IBEX_LOCKDOWN");
        std::env::remove_var("IBEX_COMPARTMENTS");
        let cli = Cli::parse_from([
            "ibex",
            "--capsec-armed-snapshot",
            "missing-snapshot.json",
            "--capsec-arming-identity",
            "missing-identity.json",
            "--allow",
            "fs:read:/tmp",
            "app.ts",
        ]);
        let error = build_host(&cli)
            .err()
            .expect("must reject legacy overrides")
            .to_string();
        assert!(
            error.contains("rejects legacy allow/deny")
                && error.contains("environment endowment widening"),
            "{error}"
        );
        assert!(
            !error.contains("failed to read"),
            "override must fail before artifact I/O: {error}"
        );
    }

    #[tokio::test]
    async fn armed_startup_closes_every_inspector_activation_before_io() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::remove_var("IBEX_LOCKDOWN");
        std::env::remove_var("IBEX_COMPARTMENTS");
        for inspector_args in [
            vec!["--inspect"],
            vec!["--inspect-wait"],
            vec!["--inspect-open"],
            vec!["--inspect-pause"],
            vec!["--inspect-port", "9230"],
            vec!["--inspect-host", "127.0.0.1"],
        ] {
            let mut args = vec![
                "ibex",
                "--capsec-armed-snapshot",
                "missing-snapshot.json",
                "--capsec-arming-identity",
                "missing-identity.json",
            ];
            args.extend(inspector_args);
            args.push("app.ts");
            let cli = Cli::parse_from(args);
            let error = build_host(&cli)
                .err()
                .expect("armed inspector configuration must be closed")
                .to_string();
            assert!(
                error.contains("closes compatibility, inspector")
                    && error.contains("runtime-fidelity overrides"),
                "{error}"
            );
            assert!(
                !error.contains("failed to read"),
                "inspector closure must precede artifact I/O: {error}"
            );
        }
    }

    #[tokio::test]
    async fn armed_startup_closes_compatibility_facades_before_io() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::remove_var("IBEX_LOCKDOWN");
        std::env::remove_var("IBEX_COMPARTMENTS");
        let cli = Cli::parse_from([
            "ibex",
            "--capsec-armed-snapshot",
            "missing-snapshot.json",
            "--capsec-arming-identity",
            "missing-identity.json",
            "--compat",
            "bun",
            "app.ts",
        ]);
        let error = build_host(&cli)
            .err()
            .expect("armed compatibility facade must be closed")
            .to_string();
        assert!(error.contains("closes compatibility"), "{error}");
        assert!(
            !error.contains("failed to read"),
            "compatibility closure must precede artifact I/O: {error}"
        );
    }

    #[test]
    fn default_arming_captures_bun_compatibility_instead_of_rejecting_it() {
        let cli = Cli::parse_from(["ibex", "--compat", "bun", "app.ts"]);
        validate_runtime_inputs(&cli, false)
            .expect("default arming must admit the fixed Bun compatibility mode");
        assert_eq!(
            requested_bootstrap_compatibility_modes(&cli)
                .first()
                .map(String::as_str),
            Some("bun")
        );
    }

    #[tokio::test]
    async fn armed_startup_closes_hidden_runtime_fidelity_flags_before_io() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::remove_var("IBEX_LOCKDOWN");
        std::env::remove_var("IBEX_COMPARTMENTS");
        for fidelity_args in [
            vec!["--expose-internals"],
            vec!["--stack-size", "2048"],
            vec!["--max-http-header-size", "32768"],
        ] {
            let mut args = vec![
                "ibex",
                "--capsec-armed-snapshot",
                "missing-snapshot.json",
                "--capsec-arming-identity",
                "missing-identity.json",
            ];
            args.extend(fidelity_args);
            args.push("app.ts");
            let cli = Cli::parse_from(args);
            let error = build_host(&cli)
                .err()
                .expect("armed hidden runtime configuration must be closed")
                .to_string();
            assert!(error.contains("runtime-fidelity"), "{error}");
            assert!(
                !error.contains("failed to read"),
                "runtime configuration closure must precede artifact I/O: {error}"
            );
        }
    }

    #[test]
    fn production_run_nonce_is_canonical_and_rejects_the_contract_vector() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let nonce = production_run_nonce_from_bytes(&[0; PRODUCTION_RUN_NONCE_BYTES]).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&nonce).unwrap().len(), 16);
        assert!(!nonce.contains('='));

        let contract_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let error = production_run_nonce_from_bytes(&contract_bytes)
            .expect_err("the committed contract nonce must never arm production")
            .to_string();
        assert!(
            error.contains("reserved capsec contract-fixture"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn armed_startup_authenticates_engine_before_refusing_legacy_advertisement() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::remove_var("IBEX_LOCKDOWN");
        std::env::remove_var("IBEX_COMPARTMENTS");
        let directory = tempdir().unwrap();
        let (snapshot, identity, _, entry) = write_arming_fixture(directory.path());
        let cli = Cli::parse_from([
            "ibex".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.into_os_string(),
            "--capsec-arming-identity".into(),
            identity.into_os_string(),
            entry.into_os_string(),
        ]);
        let default_error = build_host(&cli)
            .err()
            .expect("legacy target advertisement must not arm");
        let default_error = format!("{default_error:#}");
        assert!(
            default_error
                .contains("legacy v1 target advertisements are diagnostic-only and remain closed"),
            "{default_error}"
        );
        assert!(!default_error.contains("engine object"), "{default_error}");
        let (snapshot, identity, _, entry) = write_arming_fixture(directory.path());
        let explicit = Cli::parse_from([
            "ibex".into(),
            "--capsec".into(),
            "enforce".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.into_os_string(),
            "--capsec-arming-identity".into(),
            identity.into_os_string(),
            entry.into_os_string(),
        ]);
        let explicit_error = build_host(&explicit)
            .err()
            .expect("explicit enforce cannot bypass target advertisements");
        let explicit_error = format!("{explicit_error:#}");
        assert_eq!(explicit_error, default_error);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn external_snapshot_cannot_self_assert_a_bound_volume_canonicalizer() {
        let directory = tempdir().unwrap();
        let (snapshot, identity, _, entry) = write_arming_fixture(directory.path());
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&snapshot).unwrap()).unwrap();
        let current = document["pathCanonicalizers"][0]["identity"]
            .as_str()
            .unwrap();
        document["pathCanonicalizers"][0]["identity"] =
            serde_json::json!(if current == "apple-apfs-unicode9-nfd-v1" {
                "apple-apfs-unicode9-safe-casefold-nfd-v1"
            } else {
                "apple-apfs-unicode9-nfd-v1"
            });
        let digest = capsec_semantics::digest::compute_checked_contract_digest(
            capsec_semantics::digest::DigestKind::ArmedSnapshot,
            &document,
        )
        .unwrap();
        document["armedSnapshotDigest"] = serde_json::json!(digest);
        std::fs::write(&snapshot, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        let mut claimed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&identity).unwrap()).unwrap();
        claimed["pathCanonicalizers"] = document["pathCanonicalizers"].clone();
        claimed["armedSnapshotDigest"] = document["armedSnapshotDigest"].clone();
        std::fs::write(&identity, serde_json::to_vec_pretty(&claimed).unwrap()).unwrap();

        let cli = Cli::parse_from([
            "ibex".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.into_os_string(),
            "--capsec-arming-identity".into(),
            identity.into_os_string(),
            entry.into_os_string(),
        ]);
        let error = format!(
            "{:#}",
            build_host(&cli)
                .err()
                .expect("independent volume probe must reject a caller-selected algorithm")
        );
        assert!(
            error.contains("bound-volume canonicalizers differ"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn armed_startup_rejects_tampered_template_before_freshening() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::remove_var("IBEX_LOCKDOWN");
        std::env::remove_var("IBEX_COMPARTMENTS");
        let directory = tempdir().unwrap();
        let (snapshot, identity, _, entry) = write_arming_fixture(directory.path());
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&snapshot).unwrap()).unwrap();
        tampered["runNonce"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA");
        std::fs::write(&snapshot, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
        let cli = Cli::parse_from([
            "ibex".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.into_os_string(),
            "--capsec-arming-identity".into(),
            identity.into_os_string(),
            entry.into_os_string(),
        ]);
        let error = build_host(&cli)
            .err()
            .expect("freshening must not repair an unauthenticated template");
        let message = format!("{error:#}");
        assert!(message.contains("digest is stale or tampered"), "{message}");
    }

    #[test]
    fn external_snapshot_refuses_mismatched_protected_artifact_identity_and_content() {
        let directory = tempdir().unwrap();
        let (snapshot, identity, _, entry) = write_arming_fixture(directory.path());
        let original_identity = std::fs::read(&identity).unwrap();

        let mut mismatched_object: serde_json::Value =
            serde_json::from_slice(&original_identity).unwrap();
        let first = mismatched_object["protectedArtifacts"][0]["object"].clone();
        mismatched_object["protectedArtifacts"][0]["object"] =
            mismatched_object["protectedArtifacts"][1]["object"].clone();
        mismatched_object["protectedArtifacts"][1]["object"] = first;
        std::fs::write(&identity, serde_json::to_vec(&mismatched_object).unwrap()).unwrap();
        let cli = Cli::parse_from([
            "ibex".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.clone().into_os_string(),
            "--capsec-arming-identity".into(),
            identity.clone().into_os_string(),
            entry.into_os_string(),
        ]);
        let error = format!(
            "{:#}",
            build_host(&cli).err().expect("object mismatch must refuse")
        );
        assert!(
            error.contains("independently authenticated artifact role"),
            "{error}"
        );

        let mut mismatched_content: serde_json::Value =
            serde_json::from_slice(&original_identity).unwrap();
        mismatched_content["protectedArtifacts"][0]["contentDigest"] =
            serde_json::json!("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        std::fs::write(&identity, serde_json::to_vec(&mismatched_content).unwrap()).unwrap();
        let error = format!(
            "{:#}",
            build_host(&cli)
                .err()
                .expect("content mismatch must refuse")
        );
        assert!(error.contains("content digest changed"), "{error}");
        assert!(
            !error.contains("no unique verified advertisement"),
            "artifact mismatch must refuse before target promotion: {error}"
        );
    }

    fn file_hash(path: &Path) -> String {
        sha256_bytes(&std::fs::read(path).expect("read file for digest"))
    }

    // ENG-22760 — `ibex build` under enforce/audit must ship the per-package
    // chunk siblings next to the `.hbc`, or the built artifact silently loses
    // per-package attribution (a flat single-Domain run). Ship exactly the set
    // the loader's chunk-redirect recognizes (`__ibexpkg__*`, `rolldown-runtime.js`)
    // and nothing else (not the entry bundle, its deps json, or unrelated files).
    #[test]
    fn ship_chunk_siblings_copies_only_recognized_chunks() {
        let src = tempdir().unwrap();
        let dest = tempdir().unwrap();
        // A chunked bundle dir as the bundler emits it.
        std::fs::write(src.path().join("bundle.js"), "entry").unwrap();
        std::fs::write(src.path().join("bundle.js.map"), "{}").unwrap();
        std::fs::write(src.path().join("bundle.js.deps.json"), "[]").unwrap();
        std::fs::write(src.path().join("__ibexpkg__evil-pkg@1.0.0.js"), "chunk").unwrap();
        std::fs::write(src.path().join("__ibexpkg__evil-pkg@1.0.0.js.map"), "{}").unwrap();
        std::fs::write(src.path().join("rolldown-runtime.js"), "rt").unwrap();
        std::fs::write(src.path().join("unrelated.txt"), "x").unwrap();

        let entry = src.path().join("bundle.js");
        let copied = ship_chunk_siblings(&entry, dest.path()).unwrap();

        // The chunk, its map, and the shared runtime are shipped...
        assert!(dest.path().join("__ibexpkg__evil-pkg@1.0.0.js").exists());
        assert!(dest
            .path()
            .join("__ibexpkg__evil-pkg@1.0.0.js.map")
            .exists());
        assert!(dest.path().join("rolldown-runtime.js").exists());
        assert_eq!(copied, 3);
        // ...but the entry bundle, its deps json, its map, and unrelated files
        // are not (they'd shadow the entry / bloat the artifact).
        assert!(!dest.path().join("bundle.js").exists());
        assert!(!dest.path().join("bundle.js.map").exists());
        assert!(!dest.path().join("bundle.js.deps.json").exists());
        assert!(!dest.path().join("unrelated.txt").exists());

        // Shipping into the bundle's own directory (an in-place run) is a no-op.
        assert_eq!(ship_chunk_siblings(&entry, src.path()).unwrap(), 0);
    }

    #[tokio::test]
    async fn production_build_isolation_is_always_enforce_and_rejects_weakening() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        use crate::host::SecurityMode;
        let cli = Cli::parse_from(["ibex", "app.ts"]);
        assert_eq!(apply_build_isolation(&cli).unwrap(), SecurityMode::Enforce);
        let forced = Cli::parse_from(["ibex", "--capsec", "permissive", "app.ts"]);
        assert!(apply_build_isolation(&forced).is_err());
        let allow_all = Cli::parse_from(["ibex", "--allow-all", "app.ts"]);
        assert!(apply_build_isolation(&allow_all).is_err());
        let audit = Cli::parse_from(["ibex", "--capsec", "audit", "app.ts"]);
        assert!(apply_build_isolation(&audit).is_err());
    }

    #[tokio::test]
    #[cfg(not(feature = "insecure"))]
    async fn default_and_explicit_enforce_refuse_the_same_unadvertised_target() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        let project = tempdir().unwrap();
        let entry = project.path().join("app.ts");
        std::fs::write(project.path().join("package.json"), "{\"name\":\"app\"}\n").unwrap();
        std::fs::write(&entry, "1 + 1\n").unwrap();
        let auto = Cli::parse_from(["ibex", entry.to_str().unwrap()]);
        let explicit = Cli::parse_from(["ibex", "--capsec", "enforce", entry.to_str().unwrap()]);
        let auto_error = build_host(&auto)
            .err()
            .expect("default enforce must refuse an unadvertised target");
        let explicit_error = build_host(&explicit)
            .err()
            .expect("explicit enforce cannot bypass target advertisements");
        let auto_error = format!("{auto_error:#}");
        let explicit_error = format!("{explicit_error:#}");
        assert_eq!(auto_error, explicit_error);
        assert!(
            auto_error
                .contains("legacy v1 target advertisements are diagnostic-only and remain closed"),
            "{auto_error}"
        );
    }

    #[tokio::test]
    #[cfg(not(feature = "insecure"))]
    async fn default_arming_ingests_only_digest_valid_canonical_policy() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        let directory = tempdir().unwrap();
        let entry = directory.path().join("app.ts");
        std::fs::write(
            directory.path().join("package.json"),
            "{\"name\":\"test-app\"}\n",
        )
        .unwrap();
        std::fs::write(&entry, "1 + 1").unwrap();
        let package_root = directory.path().join("node_modules/image-lib");
        std::fs::create_dir_all(&package_root).unwrap();
        std::fs::write(
            package_root.join("package.json"),
            r#"{"name":"image-lib","version":"2.4.1"}"#,
        )
        .unwrap();
        std::fs::write(package_root.join("index.js"), "module.exports = {};\n").unwrap();
        let package_integrity =
            crate::module_loader::package_tree_integrity(&package_root).unwrap();
        let mut policy: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/canonical-policy.canonical.json"
        )))
        .unwrap();
        policy["principals"][0]["principal"]["integrity"] = serde_json::json!(package_integrity);
        let policy_digest = capsec_semantics::digest::compute_checked_contract_digest(
            capsec_semantics::digest::DigestKind::Policy,
            &policy,
        )
        .unwrap();
        policy["policyDigest"] = serde_json::json!(policy_digest);
        std::fs::write(
            directory.path().join("ibex-policy.json"),
            capsec_semantics::canonical::to_jcs_bytes(&policy).unwrap(),
        )
        .unwrap();
        let cli = Cli::parse_from(["ibex", entry.to_str().unwrap()]);
        let error = build_host(&cli)
            .err()
            .expect("valid policy and package root must reach the promotion gate");
        let error = format!("{error:#}");
        assert!(
            error.contains("legacy v1 target advertisements are diagnostic-only and remain closed"),
            "{error}"
        );

        let mut tampered = policy.clone();
        tampered["principals"][0]["floor"] = serde_json::json!([]);
        std::fs::write(
            directory.path().join("ibex-policy.json"),
            serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        let error = build_host(&cli).err().expect("tampered policy must fail");
        let error = format!("{error:#}");
        assert!(error.contains("digest is stale or tampered"), "{error}");

        for field in ["vocabDigest", "registryDigest"] {
            let mut stale = policy.clone();
            stale[field] = serde_json::json!("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            let digest = capsec_semantics::digest::compute_domain_digest(
                capsec_semantics::digest::POLICY_DOMAIN,
                &stale,
                &["policyDigest".to_string()],
            )
            .unwrap();
            stale["policyDigest"] = serde_json::json!(digest);
            std::fs::write(
                directory.path().join("ibex-policy.json"),
                serde_json::to_vec(&stale).unwrap(),
            )
            .unwrap();
            let error = build_host(&cli)
                .err()
                .expect("stale semantic identity must fail");
            let error = format!("{error:#}");
            assert!(error.contains("failed typed validation"), "{error}");
        }
    }

    // ENG-22884 — enforce must not silently proceed as full-strength capsec when
    // an attribution prerequisite is missing. The readiness snapshot is passed
    // as data so the missing-EXACT_HAVE_FRAME_ATTRIBUTION and
    // IBEX_PER_PACKAGE_CHUNKS=0 shapes are simulated without recompiling or
    // mutating process-global env.
    #[test]
    fn capsec_enforce_fails_closed_without_attribution_prerequisites() {
        use crate::host::SecurityMode;

        let ready = CapsecReadiness {
            frame_attribution: true,
            package_isolation: PackageIsolation::Enabled,
            lockdown: true,
            dynamic_ceiling: false,
        };

        // Fully-ready enforce proceeds and emits exactly the readiness report.
        let lines =
            check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Run, ready, false).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("frame-attribution=present"));
        assert!(lines[0].contains("package-isolation=per-package"));

        // Lockdown is a structural prerequisite, not an optional claim ceiling.
        let enforce_without_lockdown = CapsecReadiness {
            lockdown: false,
            ..ready
        };
        let error = check_capsec_readiness(
            SecurityMode::Enforce,
            CapsecStage::Run,
            enforce_without_lockdown,
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("structural runtime lockdown"));

        // Missing frame attribution (an engine built without
        // EXACT_HAVE_FRAME_ATTRIBUTION): an enforce run fails closed with the
        // escape hatch named in the error...
        let advisory = CapsecReadiness {
            frame_attribution: false,
            ..ready
        };
        let err = check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Run, advisory, false)
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("frame-derived attribution"));
        assert!(msg.contains("foreground capsec audit"));

        // The removed advisory override cannot weaken enforce.
        assert!(
            check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Run, advisory, true)
                .is_err()
        );

        // An explicit IBEX_PER_PACKAGE_CHUNKS=0 collapses bundled dependencies
        // into the root principal — hard prerequisite at run AND build stage
        // (the flat layout is baked into the built artifact).
        let collapsed = CapsecReadiness {
            package_isolation: PackageIsolation::DisabledByOperator,
            ..ready
        };
        assert!(
            check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Run, collapsed, false)
                .is_err()
        );
        assert!(check_capsec_readiness(
            SecurityMode::Enforce,
            CapsecStage::Build,
            collapsed,
            false
        )
        .is_err());

        // Building with an attribution-less engine proceeds (the artifact may
        // run under a patched engine) but warns instead of staying silent.
        let lines =
            check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Build, advisory, false)
                .unwrap();
        assert!(lines.iter().any(|l| l.starts_with("warning:")));

        // Audit never fails closed but must be conspicuous about advisory
        // attribution.
        let lines =
            check_capsec_readiness(SecurityMode::Audit, CapsecStage::Run, advisory, false).unwrap();
        assert!(lines.iter().any(|l| l.contains("ADVISORY")));
        assert!(lines.iter().any(|l| l.contains("audit")));

        // Permissive claims no capsec, so it stays silent.
        assert!(check_capsec_readiness(
            SecurityMode::Permissive,
            CapsecStage::Run,
            advisory,
            false
        )
        .unwrap()
        .is_empty());
    }

    #[tokio::test]
    async fn authenticated_single_original_bundle_has_the_only_admitted_generated_shape() {
        let project = tempdir().unwrap();
        let cache = tempdir().unwrap();
        let entry = project.path().join("entry.cjs");
        std::fs::write(
            &entry,
            "globalThis.__singleOriginalRuns = (globalThis.__singleOriginalRuns || 0) + 1; module.exports = { answer: 42 };\n",
        )
        .unwrap();
        let authority = test_source_provenance_authority(project.path());
        let output = run_bundler_with_source_provenance(
            &entry,
            &cache.path().join("cache-key"),
            BundleFormat::Cjs,
            Some(&authority),
        )
        .await
        .unwrap();
        let manifest = read_bundle_manifest(&output).await.unwrap();
        let original = admitted_single_original_bundle(&manifest, &output)
            .expect("one original entry chunk plus its map must be admitted")
            .clone();
        assert_eq!(original.dep_index, 0);
        let source_sha = sha256_file(&entry).await.unwrap();
        assert_eq!(original.source_sha256, source_sha);
        let captured =
            capture_fresh_single_original_bundle(&output, &entry, &source_sha, &authority)
                .unwrap()
                .expect("the exact single-original compiler output must be capturable");
        assert!(!captured.source.is_empty());

        let mut chunked = manifest.clone();
        chunked.outputs.push(BundleDigestRecord {
            path: "rolldown-runtime.js".to_owned(),
            sha256: "0".repeat(64),
        });
        assert!(admitted_single_original_bundle(&chunked, &output).is_none());
        let mut multi = manifest.clone();
        multi
            .source_provenance
            .as_mut()
            .unwrap()
            .modules
            .push(original);
        assert!(admitted_single_original_bundle(&multi, &output).is_none());
    }

    #[tokio::test]
    async fn authenticated_generated_execution_ignores_self_consistent_persistent_cache_forgery() {
        let project = tempdir().unwrap();
        let cache = tempdir().unwrap();
        let entry = project.path().join("entry.cjs");
        std::fs::write(&entry, "module.exports = { authentic: 42 };\n").unwrap();
        let authority = test_source_provenance_authority(project.path());

        // Demonstrate the exact reason a public digest manifest is not proof
        // of compiler authorship: a persistent cache writer can replace the
        // output and recompute every public output/graph digest.
        let persistent_root = cache.path().join("persistent-cache");
        let persistent_output = run_bundler_with_source_provenance(
            &entry,
            &persistent_root,
            BundleFormat::Cjs,
            Some(&authority),
        )
        .await
        .unwrap();
        let forged_source = b"module.exports = { forgedCacheCode: true };\n";
        std::fs::write(&persistent_output, forged_source).unwrap();
        let mut forged_manifest = read_bundle_manifest(&persistent_output).await.unwrap();
        let output_name = persistent_output
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap();
        forged_manifest
            .outputs
            .iter_mut()
            .find(|record| record.path == output_name)
            .unwrap()
            .sha256 = sha256_bytes(forged_source);
        let graph_projection = serde_json::json!({
            "deps": forged_manifest.deps,
            "outputs": forged_manifest.outputs,
            "sourceProvenanceDigest": forged_manifest.source_provenance.as_ref().unwrap().digest,
        });
        forged_manifest.graph_digest =
            sha256_bytes(&capsec_semantics::canonical::to_jcs_bytes(&graph_projection).unwrap());
        std::fs::write(
            deps_manifest_path(&persistent_output),
            serde_json::to_vec(&forged_manifest).unwrap(),
        )
        .unwrap();
        assert!(
            bundle_cache_is_fresh_with_source_provenance(
                &persistent_output,
                &entry,
                Some(&authority),
            )
            .await,
            "self-consistent public hashes are cache freshness, not compiler authentication"
        );

        // Production admission has no lookup into that cache. It creates an
        // unpredictable private root and accepts only this invocation's bytes.
        let fresh_root = FreshGeneratedArtifactRoot::create(cache.path()).unwrap();
        let fresh_root_path = fresh_root.path().to_owned();
        assert!(!persistent_output.starts_with(&fresh_root_path));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&fresh_root_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        let fresh_output = run_fresh_bundler_with_source_provenance(
            &entry,
            fresh_root.path(),
            BundleFormat::Cjs,
            &authority,
        )
        .await
        .unwrap();
        let source_sha = sha256_file(&entry).await.unwrap();
        let captured =
            capture_fresh_single_original_bundle(&fresh_output, &entry, &source_sha, &authority)
                .unwrap()
                .expect("fresh compiler output must be admitted");
        assert!(!captured
            .source
            .windows(b"forgedCacheCode".len())
            .any(|window| window == b"forgedCacheCode"));

        // Replacing the pathname after capture cannot change the bytes passed
        // to Hermes, and cleanup cannot invalidate them either.
        let retained = captured.source.clone();
        std::fs::write(&fresh_output, b"post-capture replacement\n").unwrap();
        assert_eq!(captured.source, retained);
        drop(fresh_root);
        assert!(!fresh_root_path.exists());
        assert_eq!(captured.source, retained);
    }

    #[tokio::test]
    async fn authenticated_generated_capture_rejects_changed_output_digest() {
        let project = tempdir().unwrap();
        let cache = tempdir().unwrap();
        let entry = project.path().join("entry.cjs");
        std::fs::write(&entry, "module.exports = 42;\n").unwrap();
        let authority = test_source_provenance_authority(project.path());
        let fresh_root = FreshGeneratedArtifactRoot::create(cache.path()).unwrap();
        let output = run_fresh_bundler_with_source_provenance(
            &entry,
            fresh_root.path(),
            BundleFormat::Cjs,
            &authority,
        )
        .await
        .unwrap();
        std::fs::write(&output, b"module.exports = 'changed';\n").unwrap();
        assert!(capture_fresh_single_original_bundle(
            &output,
            &entry,
            &sha256_file(&entry).await.unwrap(),
            &authority,
        )
        .unwrap()
        .is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn authenticated_generated_capture_never_follows_manifest_or_output_symlink() {
        use std::os::unix::fs::symlink;

        let project = tempdir().unwrap();
        let cache = tempdir().unwrap();
        let entry = project.path().join("entry.cjs");
        std::fs::write(&entry, "module.exports = 42;\n").unwrap();
        let authority = test_source_provenance_authority(project.path());
        let fresh_root = FreshGeneratedArtifactRoot::create(cache.path()).unwrap();
        let output = run_fresh_bundler_with_source_provenance(
            &entry,
            fresh_root.path(),
            BundleFormat::Cjs,
            &authority,
        )
        .await
        .unwrap();
        let source_sha = sha256_file(&entry).await.unwrap();
        let manifest_path = deps_manifest_path(&output);
        let manifest_bytes = std::fs::read(&manifest_path).unwrap();
        let manifest_target = fresh_root.path().join("same-authenticated-manifest.json");
        std::fs::write(&manifest_target, &manifest_bytes).unwrap();
        std::fs::remove_file(&manifest_path).unwrap();
        symlink(&manifest_target, &manifest_path).unwrap();
        let manifest_error =
            match capture_fresh_single_original_bundle(&output, &entry, &source_sha, &authority) {
                Err(error) => error,
                Ok(_) => panic!("the final manifest component must be opened no-follow"),
            };
        assert!(
            format!("{manifest_error:#}")
                .contains("failed to open authenticated generated manifest"),
            "{manifest_error:#}"
        );
        std::fs::remove_file(&manifest_path).unwrap();
        std::fs::write(&manifest_path, manifest_bytes).unwrap();

        let target = fresh_root.path().join("same-authenticated-bytes.js");
        std::fs::copy(&output, &target).unwrap();
        std::fs::remove_file(&output).unwrap();
        symlink(&target, &output).unwrap();
        let error =
            match capture_fresh_single_original_bundle(&output, &entry, &source_sha, &authority) {
                Err(error) => error,
                Ok(_) => panic!("the final output component must be opened no-follow"),
            };
        assert!(
            format!("{error:#}").contains("failed to open authenticated generated output"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bundle_manifest_reader_rejects_symlinks_and_fifos_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let output = directory.path().join("entry.js");
        std::fs::write(&output, b"void 0;\n").unwrap();
        let manifest_path = deps_manifest_path(&output);
        let target = directory.path().join("attacker-manifest.json");
        std::fs::write(&target, b"{}").unwrap();
        symlink(&target, &manifest_path).unwrap();
        let symlink_error = match read_bundle_manifest(&output).await {
            Err(error) => error,
            Ok(_) => panic!("bundle manifest final component must be opened no-follow"),
        };
        assert!(
            format!("{symlink_error:#}").contains("failed to open bundle cache manifest"),
            "{symlink_error:#}"
        );

        std::fs::remove_file(&manifest_path).unwrap();
        let fifo_path = std::ffi::CString::new(manifest_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let fifo_result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_bundle_manifest(&output),
        )
        .await
        .expect("a FIFO manifest must not block the cache reader");
        let fifo_error = match fifo_result {
            Err(error) => error,
            Ok(_) => panic!("a FIFO manifest is not a regular file"),
        };
        assert!(
            format!("{fifo_error:#}").contains("not a bounded regular file"),
            "{fifo_error:#}"
        );
    }

    #[test]
    fn fresh_bundler_builds_only_the_closed_private_environment() {
        let private = tempdir().unwrap();
        let mut command = tokio::process::Command::new("unused-runner");
        command.env("IBEX_UNLISTED_PARENT_SENTINEL", "attacker-controlled");
        configure_js_tool_environment(&mut command, private.path());
        let environment = command
            .as_std()
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value
                        .expect("fresh environment never carries an env_remove tombstone")
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let private = private.path().to_string_lossy().into_owned();
        #[allow(unused_mut)] // extended with Windows-only private-directory keys
        let mut expected = std::collections::BTreeMap::from([
            (
                "BUN_RUNTIME_TRANSPILER_CACHE_PATH".to_owned(),
                private.clone(),
            ),
            ("HOME".to_owned(), private.clone()),
            ("LANG".to_owned(), "C".to_owned()),
            ("LC_ALL".to_owned(), "C".to_owned()),
            ("NODE_DISABLE_COMPILE_CACHE".to_owned(), "1".to_owned()),
            ("TEMP".to_owned(), private.clone()),
            ("TMP".to_owned(), private.clone()),
            ("TMPDIR".to_owned(), private.clone()),
            ("TZ".to_owned(), "UTC".to_owned()),
            ("XDG_CACHE_HOME".to_owned(), private.clone()),
            ("XDG_CONFIG_HOME".to_owned(), private.clone()),
        ]);
        #[cfg(windows)]
        expected.extend([
            ("APPDATA".to_owned(), private.clone()),
            ("LOCALAPPDATA".to_owned(), private.clone()),
            ("USERPROFILE".to_owned(), private),
        ]);
        assert_eq!(environment, expected);
        assert!(!environment.contains_key("PATH"));
        assert!(!environment.contains_key("IBEX_UNLISTED_PARENT_SENTINEL"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fresh_bundler_real_child_does_not_inherit_an_unlisted_parent_value() {
        let private = tempdir().unwrap();
        let env_program = ["/usr/bin/env", "/bin/env"]
            .into_iter()
            .find(|candidate| Path::new(candidate).is_file())
            .expect("system env utility");
        let mut command = tokio::process::Command::new(env_program);
        command.env("IBEX_UNLISTED_PARENT_SENTINEL", "attacker-controlled");
        configure_js_tool_environment(&mut command, private.path());
        let output = command.output().await.unwrap();
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(environment.len(), 11, "{environment:#?}");
        assert!(!environment.contains_key("PATH"));
        assert!(!environment.contains_key("IBEX_UNLISTED_PARENT_SENTINEL"));
    }

    #[tokio::test]
    async fn authenticated_bundle_provenance_is_per_original_and_authority_bound() {
        let project = tempdir().unwrap();
        let cache = tempdir().unwrap();
        let entry = project.path().join("entry.js");
        let dependency_root = project.path().join("node_modules/dependency");
        std::fs::create_dir_all(&dependency_root).unwrap();
        let dependency = dependency_root.join("index.js");
        std::fs::write(
            &entry,
            "const dependency = require('./node_modules/dependency'); module.exports = dependency.value;\n",
        )
        .unwrap();
        std::fs::write(&dependency, "exports.value = 42;\n").unwrap();
        let mut authority = test_source_provenance_authority(project.path());
        let package_principal: capsec_semantics::model::Principal =
            serde_json::from_value(serde_json::json!({
                "kind": "package",
                "name": "dependency",
                "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
                "locator": "dependency@1.0.0",
            }))
            .unwrap();
        authority
            .bindings
            .push(BundleSourceProvenanceAuthorityBinding {
                logical_root: capsec_semantics::model::LogicalRoot::Package,
                owner: Some(package_principal),
                backing_root: std::fs::canonicalize(&dependency_root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            });
        authority.bindings.sort_by(|left, right| {
            left.backing_root
                .as_bytes()
                .cmp(right.backing_root.as_bytes())
        });
        let output = run_bundler_with_source_provenance(
            &entry,
            &cache.path().join("cache-key"),
            BundleFormat::Cjs,
            Some(&authority),
        )
        .await
        .unwrap();

        assert!(
            bundle_cache_is_fresh_with_source_provenance(&output, &entry, Some(&authority)).await
        );
        assert!(
            !bundle_cache_is_fresh(&output, &entry).await,
            "an internally consistent sidecar is not authentication without retained authority"
        );
        let mut manifest = read_bundle_manifest(&output).await.unwrap();
        let provenance = manifest.source_provenance.as_ref().unwrap();
        assert_eq!(provenance.modules.len(), 2);
        assert!(
            admitted_single_original_bundle(&manifest, &output).is_none(),
            "flattened multi-original output must remain on the raw authenticated route"
        );
        assert_ne!(
            provenance.modules[0].source_id,
            provenance.modules[1].source_id
        );
        for module in &provenance.modules {
            assert_eq!(
                bundle_source_id(&module.source_identity).as_deref(),
                Some(module.source_id.as_str())
            );
            assert!(!module
                .source_label
                .contains(project.path().to_string_lossy().as_ref()));
            assert!(!module.chunks.is_empty());
            assert!(module
                .chunks
                .iter()
                .all(|chunk| manifest.outputs.iter().any(|output| &output.path == chunk)));
        }
        let generated_record =
            authenticated_generated_cjs_bundle_resolution(&output, &entry, &output, &authority)
                .await
                .unwrap();
        assert_eq!(
            generated_record["schema"],
            "ibex/generated-bundle-resolution/1"
        );
        assert_eq!(
            generated_record["sourceProvenance"]["schema"],
            "ibex/source-provenance-chunk/1"
        );
        assert!(!generated_record["sourceProvenance"]
            .to_string()
            .contains(project.path().to_string_lossy().as_ref()));

        let original_output = std::fs::read(&output).unwrap();
        let original_manifest = manifest.clone();
        std::fs::write(&output, b"module.exports = 'cache replacement';\n").unwrap();
        let output_name = output
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap();
        manifest
            .outputs
            .iter_mut()
            .find(|record| record.path == output_name)
            .unwrap()
            .sha256 = sha256_file(&output).await.unwrap();
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(
            !bundle_cache_is_fresh_with_source_provenance(&output, &entry, Some(&authority)).await,
            "v4 graph identity must bind generated output bytes, not their self-declared hashes"
        );
        std::fs::write(&output, original_output).unwrap();
        manifest = original_manifest.clone();
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        // Keeping the authentic authority digest is not enough. A cache writer
        // must not be able to relabel a package original as root-owned and then
        // recompute every public digest around the forgery.
        let provenance = manifest.source_provenance.as_mut().unwrap();
        let package_module = provenance
            .modules
            .iter_mut()
            .find(|module| {
                module.source_identity.logical_root == capsec_semantics::model::LogicalRoot::Package
            })
            .unwrap();
        package_module.source_identity.defining_principal = authority.root_identity.clone();
        package_module.source_identity.logical_root = capsec_semantics::model::LogicalRoot::Project;
        package_module.source_identity.lexical_components = vec![
            "node_modules".to_owned(),
            "dependency".to_owned(),
            "index.js".to_owned(),
        ];
        package_module.binding_virtual_prefix = "/project".to_owned();
        package_module.source_id = bundle_source_id(&package_module.source_identity).unwrap();
        provenance
            .modules
            .sort_by(|left, right| left.source_id.as_bytes().cmp(right.source_id.as_bytes()));
        let projection = serde_json::json!({
            "schema": provenance.schema,
            "armedSnapshotDigest": provenance.armed_snapshot_digest,
            "packageGraphDigest": provenance.package_graph_digest,
            "authorityDigest": provenance.authority_digest,
            "modules": provenance.modules,
        });
        provenance.digest =
            sha256_bytes(&capsec_semantics::canonical::to_jcs_bytes(&projection).unwrap());
        let graph_projection = serde_json::json!({
            "deps": manifest.deps,
            "outputs": manifest.outputs,
            "sourceProvenanceDigest": provenance.digest,
        });
        manifest.graph_digest =
            sha256_bytes(&capsec_semantics::canonical::to_jcs_bytes(&graph_projection).unwrap());
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(
            !bundle_cache_is_fresh_with_source_provenance(&output, &entry, Some(&authority)).await,
            "native must reproduce the authenticated binding projection"
        );

        let mut manifest = original_manifest;
        manifest.source_provenance.as_mut().unwrap().modules[0].source_label =
            "file:///project/forged.js".to_owned();
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(
            !bundle_cache_is_fresh_with_source_provenance(&output, &entry, Some(&authority)).await
        );
    }

    #[tokio::test]
    async fn bundle_cache_freshness_tracks_dependency_and_output_digests() {
        let dir = tempdir().expect("tempdir");
        let artifact_dir = tempdir().expect("artifact tempdir");
        let entry = dir.path().join("entry.ts");
        let dep = dir.path().join("dep.ts");
        let output = artifact_dir.path().join("entry.bundle.js");
        std::fs::write(&entry, "import './dep.ts';").expect("write entry");
        std::fs::write(&dep, "export const v = 1;").expect("write dep");
        std::fs::write(&output, "bundled").expect("write output");
        let canonical_entry = std::fs::canonicalize(&entry).unwrap();
        let canonical_dep = std::fs::canonicalize(&dep).unwrap();

        // No dependency manifest → stale (pre-manifest caches rebuild once).
        assert!(!bundle_cache_is_fresh(&output, &entry).await);

        let mut deps = vec![
            BundleDigestRecord {
                path: canonical_entry.to_string_lossy().into_owned(),
                sha256: sha256_file(&entry).await.unwrap(),
            },
            BundleDigestRecord {
                path: canonical_dep.to_string_lossy().into_owned(),
                sha256: sha256_file(&dep).await.unwrap(),
            },
        ];
        deps.sort_by(|left, right| left.path.cmp(&right.path));
        let graph_digest = sha256_bytes(&serde_json::to_vec(&deps).unwrap());
        let mut resolution_inputs = vec![BundleResolutionInput {
            kind: "directory".into(),
            path: dir.path().to_string_lossy().into_owned(),
            sha256: String::new(),
        }];
        resolution_inputs[0].sha256 =
            bundle_resolution_input_digest(&resolution_inputs[0]).unwrap();
        let resolution_digest = sha256_bytes(&serde_json::to_vec(&resolution_inputs).unwrap());
        let mut manifest = BundleCacheManifest {
            version: 3,
            entry: canonical_entry.to_string_lossy().into_owned(),
            resolution_digest,
            graph_digest,
            deps,
            outputs: vec![BundleDigestRecord {
                path: output.file_name().unwrap().to_string_lossy().into_owned(),
                sha256: sha256_file(&output).await.unwrap(),
            }],
            resolution_inputs,
            source_provenance: None,
        };
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .expect("write manifest");
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // A newly-added resolution candidate can retarget an import even when
        // every old positive dependency still exists unchanged.
        let candidate = dir.path().join("dep.js");
        std::fs::write(&candidate, "export const v = 'new candidate';").unwrap();
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
        std::fs::remove_file(&candidate).unwrap();
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // The manifest is a closed inventory: unbound emitted files are never
        // allowed to sit beside executable chunks/maps.
        let unbound_output = artifact_dir.path().join("unbound.js");
        std::fs::write(&unbound_output, "tampered").unwrap();
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
        std::fs::remove_file(&unbound_output).unwrap();
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        let correct_graph_digest = manifest.graph_digest.clone();
        manifest.graph_digest = "0".repeat(64);
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
        manifest.graph_digest = correct_graph_digest;
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // Same-length edits invalidate even when an attacker restores the old
        // timestamp, so a coarse filesystem clock cannot preserve stale code.
        let original_modified = std::fs::metadata(&dep).unwrap().modified().unwrap();
        std::fs::write(&dep, "export const v = 2;").expect("edit dep");
        std::fs::File::options()
            .write(true)
            .open(&dep)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_modified))
            .unwrap();
        assert_eq!(
            std::fs::metadata(&dep).unwrap().modified().unwrap(),
            original_modified
        );
        assert!(!bundle_cache_is_fresh(&output, &entry).await);

        std::fs::write(&dep, "export const v = 1;").expect("restore dep");
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // Clock skew alone is not content identity either: an unchanged file
        // remains valid even when its mtime jumps into the future.
        std::fs::File::options()
            .write(true)
            .open(&dep)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::SystemTime::now() + std::time::Duration::from_secs(86_400),
            ))
            .unwrap();
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // Output tampering is rejected before execution too.
        std::fs::write(&output, "tampered").expect("tamper output");
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
        std::fs::write(&output, "bundled").expect("restore output");
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // A deleted dependency invalidates too.
        std::fs::remove_file(&dep).expect("remove dep");
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
    }

    #[cfg(unix)]
    #[test]
    fn bundle_resolution_witness_tracks_symlink_retargets() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let entry = dir.path().join("entry.js");
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        std::fs::write(first.join("index.js"), "one").unwrap();
        std::fs::write(second.join("index.js"), "two").unwrap();
        std::fs::write(&entry, "require('./selected')").unwrap();
        let selected = dir.path().join("selected");
        symlink(&first, &selected).unwrap();
        let before = BundleResolutionInput {
            kind: "symlink".into(),
            path: selected.to_string_lossy().into_owned(),
            sha256: String::new(),
        };
        let before_digest = bundle_resolution_input_digest(&before).unwrap();
        std::fs::remove_file(&selected).unwrap();
        symlink(&second, &selected).unwrap();
        let after_digest = bundle_resolution_input_digest(&before).unwrap();
        assert_ne!(before_digest, after_digest);
    }

    #[test]
    fn bundle_resolution_witness_treats_a_child_of_a_file_as_missing() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("entry.js");
        std::fs::write(&file, "module.exports = 1;").unwrap();
        let impossible_child = file.join("index.js");
        let witness = BundleResolutionInput {
            kind: "missing".into(),
            path: impossible_child.to_string_lossy().into_owned(),
            sha256: sha256_bytes(b"missing"),
        };

        assert_eq!(
            bundle_resolution_input_digest(&witness),
            Some(witness.sha256.clone())
        );
    }

    #[tokio::test]
    async fn bytecode_cache_rejects_same_length_source_and_output_tampering() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("entry.js");
        let bytecode = dir.path().join("entry.hbc");
        std::fs::write(&source, "module.exports = 1").unwrap();
        std::fs::write(&bytecode, b"valid-looking-bytecode").unwrap();
        let manifest = serde_json::json!({
            "version": 2,
            "sourcePath": std::fs::canonicalize(&source).unwrap().to_string_lossy(),
            "sourceSha256": sha256_file(&source).await.unwrap(),
            "bytecodeSha256": sha256_file(&bytecode).await.unwrap(),
            "sourceMapPath": null,
            "sourceMapSha256": null,
            "toolchainIdentity": engine::hermes::bytecode_cache_identity(),
        });
        std::fs::write(
            bytecode_manifest_path(&bytecode),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(bytecode_cache_is_fresh(&source, &bytecode).await);

        std::fs::write(&source, "module.exports = 2").unwrap();
        assert!(!bytecode_cache_is_fresh(&source, &bytecode).await);
        std::fs::write(&source, "module.exports = 1").unwrap();
        std::fs::write(&bytecode, b"tampered-bytecode---").unwrap();
        assert!(!bytecode_cache_is_fresh(&source, &bytecode).await);
    }

    #[tokio::test]
    async fn provenance_aware_hbc_refuses_without_an_authenticated_wrapper_function_format() {
        assert_ne!(
            bytecode_content_cache_key("/source.js", "a", "tool", Some("provenance-a")),
            bytecode_content_cache_key("/source.js", "a", "tool", Some("provenance-b")),
        );

        let project = tempdir().unwrap();
        let cache = tempdir().unwrap();
        let entry = project.path().join("entry.js");
        std::fs::write(&entry, "module.exports = 42;\n").unwrap();
        let authority = test_source_provenance_authority(project.path());
        let bundle = run_bundler_with_source_provenance(
            &entry,
            &cache.path().join("cache-key"),
            BundleFormat::Cjs,
            Some(&authority),
        )
        .await
        .unwrap();
        let refusal = prepare_bytecode_entry_with_source_provenance(&bundle, Some(&authority))
            .await
            .unwrap_err();
        assert!(
            format!("{refusal:#}").contains("no authenticated single-initializer wrapper format"),
            "{refusal:#}"
        );

        let manifest_path = deps_manifest_path(&bundle);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest["sourceProvenance"]["digest"] = serde_json::json!("0".repeat(64));
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let tampered = prepare_bytecode_entry_with_source_provenance(&bundle, Some(&authority))
            .await
            .unwrap_err();
        assert!(
            format!("{tampered:#}").contains("stale or tampered"),
            "tampered provenance must refuse before the unavailable-HBC gate: {tampered:#}"
        );
    }

    #[tokio::test]
    async fn content_addressed_bytecode_cache_repairs_corrupt_existing_unit() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("entry.js");
        std::fs::write(&source, "globalThis.__bytecodeRepair = 1;\n").unwrap();
        let first = match prepare_bytecode_entry(&source).await {
            Ok(path) => path,
            Err(_) => return, // checked-in hermesc is optional in minimal dev envs
        };
        assert!(bytecode_cache_is_fresh(&source, &first).await);
        std::fs::write(&first, b"corrupt-bytecode").unwrap();
        assert!(!bytecode_cache_is_fresh(&source, &first).await);
        let repaired = prepare_bytecode_entry(&source).await.unwrap();
        assert_eq!(repaired, first);
        assert!(bytecode_cache_is_fresh(&source, &repaired).await);
        assert!(repaired
            .components()
            .any(|component| component.as_os_str() == ".bytecode-cache"));
        std::fs::remove_dir_all(repaired.parent().unwrap()).ok();
    }

    #[test]
    fn bytecode_cache_quota_evicts_lru_units_and_skips_locked_publishers() {
        let dir = tempdir().unwrap();
        let old = dir.path().join("a".repeat(64));
        let locked = dir.path().join("b".repeat(64));
        let leased = dir.path().join("c".repeat(64));
        let current = dir.path().join("d".repeat(64));
        for artifact in [&old, &locked, &leased, &current] {
            std::fs::create_dir(artifact).unwrap();
            std::fs::write(artifact.join("entry.hbc"), vec![0u8; 64]).unwrap();
            touch_bytecode_artifact(artifact);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let mut dead_pid = std::process::id().saturating_add(1_000_000);
        while process_is_running(dead_pid) {
            dead_pid = dead_pid.saturating_add(1);
        }
        let abandoned = dir.path().join(format!(".stage-{dead_pid}-1-dead"));
        let live = dir
            .path()
            .join(format!(".stage-{}-1-live", std::process::id()));
        std::fs::create_dir(&abandoned).unwrap();
        std::fs::create_dir(&live).unwrap();
        let locked_gate = try_acquire_bundle_artifact_gate(&locked)
            .unwrap()
            .expect("test owns publisher gate");
        let execution_lease = acquire_bundle_lease(&leased).unwrap();

        prune_bytecode_cache_to_limit(dir.path(), &current, 64);
        assert!(!old.exists(), "oldest unlocked HBC unit should be evicted");
        assert!(
            locked.exists(),
            "a live publisher gate must prevent eviction"
        );
        assert!(
            leased.exists(),
            "a live execution lease must prevent eviction"
        );
        assert!(current.exists(), "the current HBC unit must be retained");
        assert!(
            !abandoned.exists(),
            "dead publisher stages must be reclaimed"
        );
        assert!(live.exists(), "live publisher stages must not be reclaimed");
        drop(execution_lease);
        drop(locked_gate);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_bundle_publishers_converge_on_one_complete_artifact() {
        let dir = tempdir().expect("tempdir");
        let artifact_dir = tempdir().expect("artifact tempdir");
        let entry = dir.path().join("entry.js");
        let artifact_root = artifact_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = { answer: 42 };\n").unwrap();

        let mut tasks = Vec::new();
        for _ in 0..4 {
            let entry = entry.clone();
            let artifact_root = artifact_root.clone();
            tasks.push(tokio::spawn(async move {
                run_bundler(&entry, &artifact_root, BundleFormat::Cjs).await
            }));
        }
        let mut outputs = Vec::new();
        for task in tasks {
            outputs.push(task.await.unwrap().unwrap());
        }
        assert!(outputs.iter().all(|output| output == &outputs[0]));
        assert!(bundle_cache_is_fresh(&outputs[0], &entry).await);
        assert_eq!(
            std::fs::read_dir(&artifact_root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".stage-"))
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn corrupt_existing_bundle_graph_is_quarantined_and_repaired() {
        let source_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let entry = source_dir.path().join("entry.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = 42;\n").unwrap();
        let first = run_bundler(&entry, &artifact_root, BundleFormat::Cjs)
            .await
            .unwrap();
        std::fs::write(&first, "tampered output").unwrap();
        assert!(!bundle_cache_is_fresh(&first, &entry).await);

        let repaired = run_bundler(&entry, &artifact_root, BundleFormat::Cjs)
            .await
            .unwrap();
        assert_eq!(repaired, first);
        assert!(bundle_cache_is_fresh(&repaired, &entry).await);
        assert_eq!(
            std::fs::read_dir(&artifact_root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".invalid-"))
                .count(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_rejects_source_mutation_after_rolldown_capture() {
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let source_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let entry = source_dir.path().join("entry.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = 'before';\n").unwrap();
        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task_barrier_dir = barrier_dir.path().to_path_buf();
        let task = tokio::spawn(async move {
            run_bundler_with_test_capture_barrier(
                &task_entry,
                &task_root,
                BundleFormat::Cjs,
                &task_entry,
                &task_barrier_dir,
            )
            .await
        });
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();
        if reached_barrier {
            std::fs::write(&entry, "module.exports = 'after!';\n").unwrap();
        }
        // Always unblock and join the child before asserting so a timeout
        // cannot strand a subprocess.
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        assert!(
            reached_barrier,
            "bundler never reached source capture barrier: {result:?}"
        );
        assert!(result.is_err(), "mixed-version bundle must not publish");
        assert!(
            std::fs::read_dir(&artifact_root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .all(|entry| entry.file_name().to_string_lossy().starts_with('.')),
            "no completed graph may survive a mid-build source edit"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_rejects_resolution_candidate_added_after_resolver_decision() {
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let source_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let entry = source_dir.path().join("entry.js");
        let selected = source_dir.path().join("dep.ts");
        let higher_precedence = source_dir.path().join("dep.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = require('./dep').value;\n").unwrap();
        std::fs::write(&selected, "exports.value = 'typescript';\n").unwrap();
        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task_barrier_entry = selected.clone();
        let task_barrier_dir = barrier_dir.path().to_path_buf();
        let task = tokio::spawn(async move {
            run_bundler_with_test_capture_barrier(
                &task_entry,
                &task_root,
                BundleFormat::Cjs,
                &task_barrier_entry,
                &task_barrier_dir,
            )
            .await
        });
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();
        if reached_barrier {
            std::fs::write(&higher_precedence, "exports.value = 'javascript';\n").unwrap();
        }
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        assert!(
            reached_barrier,
            "bundler never resolved/captured dep.ts: {result:?}"
        );
        assert!(
            result.is_err(),
            "a build whose resolution precedence changed must not publish"
        );
        assert!(std::fs::read_dir(&artifact_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .all(|entry| entry.file_name().to_string_lossy().starts_with('.')));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_witnesses_hoisted_packages_above_nested_project_boundaries() {
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let workspace = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let project = workspace.path().join("apps/project");
        let selected_package = workspace.path().join("node_modules/pkg");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::create_dir_all(&selected_package).unwrap();
        let entry = project.join("entry.js");
        let selected = selected_package.join("index.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = require('pkg').value;\n").unwrap();
        std::fs::write(
            selected_package.join("package.json"),
            r#"{"name":"pkg","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(&selected, "exports.value = 'workspace';\n").unwrap();

        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task_barrier_entry = selected.clone();
        let task_barrier_dir = barrier_dir.path().to_path_buf();
        let task = tokio::spawn(async move {
            run_bundler_with_test_capture_barrier(
                &task_entry,
                &task_root,
                BundleFormat::Cjs,
                &task_barrier_entry,
                &task_barrier_dir,
            )
            .await
        });
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();

        // Node lookup ignores the nested .git boundary. This newly-created
        // package is closer to the importer than the package selected above,
        // so publication must fail even though the selected source is intact.
        let closer_package = workspace.path().join("apps/node_modules/pkg");
        if reached_barrier {
            std::fs::create_dir_all(&closer_package).unwrap();
            std::fs::write(
                closer_package.join("package.json"),
                r#"{"name":"pkg","main":"index.js"}"#,
            )
            .unwrap();
            std::fs::write(
                closer_package.join("index.js"),
                "exports.value = 'closer';\n",
            )
            .unwrap();
        }
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        assert!(
            reached_barrier,
            "bundler never resolved hoisted package: {result:?}"
        );
        assert!(
            result.is_err(),
            "a closer hoisted package added mid-build must prevent publication"
        );
        assert!(std::fs::read_dir(&artifact_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .all(|entry| entry.file_name().to_string_lossy().starts_with('.')));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_witnesses_bare_package_subpath_extension_precedence() {
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let project = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let package = project.path().join("node_modules/pkg");
        let nested = package.join("lib");
        std::fs::create_dir_all(&nested).unwrap();
        let entry = project.path().join("entry.js");
        let selected = nested.join("value.ts");
        let higher_precedence = nested.join("value.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(&entry, "module.exports = require('pkg/lib/value').value;\n").unwrap();
        std::fs::write(&selected, "exports.value = 'typescript';\n").unwrap();

        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task_barrier_entry = selected.clone();
        let task_barrier_dir = barrier_dir.path().to_path_buf();
        let task = tokio::spawn(async move {
            run_bundler_with_test_capture_barrier(
                &task_entry,
                &task_root,
                BundleFormat::Cjs,
                &task_barrier_entry,
                &task_barrier_dir,
            )
            .await
        });
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();
        if reached_barrier {
            std::fs::write(&higher_precedence, "exports.value = 'javascript';\n").unwrap();
        }
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        assert!(
            reached_barrier,
            "bundler never resolved package subpath: {result:?}"
        );
        assert!(
            result.is_err(),
            "adding a higher-precedence package subpath candidate must prevent publication"
        );
        assert!(std::fs::read_dir(&artifact_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .all(|entry| entry.file_name().to_string_lossy().starts_with('.')));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_witnesses_package_main_target_extension_precedence() {
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let project = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let package = project.path().join("node_modules/pkg");
        let nested = package.join("lib");
        std::fs::create_dir_all(&nested).unwrap();
        let entry = project.path().join("entry.js");
        let selected = nested.join("value.json");
        let higher_precedence = nested.join("value.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0","main":"lib/value"}"#,
        )
        .unwrap();
        std::fs::write(&entry, "module.exports = require('pkg').value;\n").unwrap();
        std::fs::write(&selected, r#"{"value":"json"}"#).unwrap();

        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task_barrier_entry = selected.clone();
        let task_barrier_dir = barrier_dir.path().to_path_buf();
        let task = tokio::spawn(async move {
            run_bundler_with_test_capture_barrier(
                &task_entry,
                &task_root,
                BundleFormat::Cjs,
                &task_barrier_entry,
                &task_barrier_dir,
            )
            .await
        });
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();
        if reached_barrier {
            std::fs::write(&higher_precedence, "exports.value = 'javascript';\n").unwrap();
        }
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        assert!(
            reached_barrier,
            "bundler never resolved package main target: {result:?}"
        );
        assert!(
            result.is_err(),
            "adding a higher-precedence package main candidate must prevent publication"
        );
        assert!(std::fs::read_dir(&artifact_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .all(|entry| entry.file_name().to_string_lossy().starts_with('.')));
    }

    #[test]
    fn bundle_cache_quota_evicts_old_graphs_but_keeps_current() {
        let dir = tempdir().unwrap();
        let old = dir.path().join("key-a/graph-old");
        let keep = dir.path().join("key-b/graph-current");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("bundle.js"), vec![0u8; 64]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::write(keep.join("bundle.js"), vec![0u8; 64]).unwrap();

        prune_bundle_cache_to_limit(dir.path(), &keep, 64);
        assert!(!old.exists());
        assert!(keep.exists());
    }

    #[test]
    fn bundle_cache_quota_respects_raii_file_lock_lease() {
        let dir = tempdir().unwrap();
        let keep = dir.path().join("key-new").join("graph-new");
        let leased = dir.path().join("key-old").join("graph-old");
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::create_dir_all(&leased).unwrap();
        std::fs::write(keep.join("bundle.js"), vec![0u8; 64]).unwrap();
        std::fs::write(leased.join("bundle.js"), vec![0u8; 64]).unwrap();
        let lease = acquire_bundle_lease(&leased).unwrap();

        prune_bundle_cache_to_limit(dir.path(), &keep, 64);
        assert!(leased.exists(), "live shared lease must prevent eviction");
        drop(lease);
        prune_bundle_cache_to_limit(dir.path(), &keep, 64);
        assert!(
            !leased.exists(),
            "RAII drop must make the artifact evictable"
        );
    }

    #[tokio::test]
    async fn failed_bundle_publish_cleans_incomplete_stage() {
        let dir = tempdir().unwrap();
        let artifact_dir = tempdir().expect("artifact tempdir");
        let entry = dir.path().join("invalid.js");
        let artifact_root = artifact_dir.path().join("cache-key");
        std::fs::write(&entry, "function broken( {\n").unwrap();
        assert!(run_bundler(&entry, &artifact_root, BundleFormat::Cjs)
            .await
            .is_err());
        let stage_count = std::fs::read_dir(&artifact_root)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".stage-"))
            .count();
        assert_eq!(stage_count, 0);
    }

    #[test]
    fn await_detection_ignores_strings_and_comments() {
        assert!(contains_await_keyword("const x = await f();"));
        assert!(contains_await_keyword("for (const y of z) { await y; }"));
        assert!(!contains_await_keyword("console.log(\"await\")"));
        assert!(!contains_await_keyword("// await in a comment"));
        assert!(!contains_await_keyword("/* await */ let a = 1;"));
        assert!(!contains_await_keyword("let awaited = `await ${'await'}`;"));
        assert!(!contains_await_keyword("let kawaii = 1;"));
    }

    #[test]
    fn await_detection_skips_regex_literals() {
        // `await` inside a regex literal is not a keyword — the scanner must not
        // report TLA (which would move a `var`/function binding into an async
        // IIFE and drop it from the global scope). (ENG-23031)
        assert!(!contains_await_keyword("var re = /await/g"));
        assert!(!contains_await_keyword("var re = /(await)/"));
        assert!(!contains_await_keyword("const re = /a\\/await/;"));
        assert!(!contains_await_keyword("var re = /[/await]/"));
        assert!(!contains_await_keyword("x.replace(/await/g, '')"));
        assert!(!contains_await_keyword("return /await/.test(s)"));

        // A `/` after a value is division, so a real `await` following it is
        // still detected (the regex heuristic must not swallow later code).
        assert!(contains_await_keyword("var q = a / b; await c"));
        assert!(contains_await_keyword("var q = /re/.source; await c"));
        // `typeof x` is a value, so `/ await y` is a division then a real await.
        assert!(contains_await_keyword("typeof x / await y"));
    }

    #[test]
    fn tla_wrap_binds_filename_for_import_meta_lowering() {
        let wrapped = wrap_source_for_tla_eval(
            std::borrow::Cow::Borrowed("console.log((\"file://\" + __filename));\nawait 1;"),
            true,
        );
        assert!(
            wrapped.contains("(async function(__filename, __dirname, module, exports, require)"),
            "wrapped: {wrapped}"
        );
        assert!(wrapped.contains("__exactEntryFile"), "wrapped: {wrapped}");
        assert!(
            wrapped.contains("globalThis.require(base + '/' + specifier)"),
            "wrapped: {wrapped}"
        );
    }

    #[test]
    fn hash_file_contents_changes_when_content_changes() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("entry.js");

        std::fs::write(&path, "aaaa").expect("write initial contents");
        let first = file_hash(&path);

        std::fs::write(&path, "bbbb").expect("write updated contents");
        let second = file_hash(&path);

        assert_ne!(first, second);
    }

    #[test]
    fn bundler_cache_input_paths_cover_shared_bundler_sources() {
        // In-repo runs hash both bundler scripts; outside a checkout the list
        // is empty by design.
        let paths = bundler_cache_input_paths().unwrap();

        assert_eq!(paths.len(), 4);
        assert!(paths
            .iter()
            .any(|path| path.ends_with("packages/ibex-devtools/src/scripts/rolldown-bundle.mjs")));
        assert!(paths
            .iter()
            .any(|path| path.ends_with("packages/ibex-devtools/src/scripts/transforms.mjs")));
        // @ref LLP 0019#decision — ENG-22987: the extracted canonical transform source.
        assert!(paths
            .iter()
            .any(|path| path.ends_with("packages/ibex-devtools/src/scripts/hermes-compat.mjs")));
        assert!(paths
            .iter()
            .any(|path| path.ends_with("packages/ibex-devtools/src/scripts/import-grants.mjs")));
        assert!(paths.iter().all(|path| path.exists()));
    }

    #[test]
    fn bundler_toolchain_identity_authenticates_selected_runner_and_install() {
        if find_js_runner().is_err() {
            return;
        }
        let identity = compute_bundler_toolchain_identity().unwrap();
        assert!(identity.runner.is_absolute());
        assert!(identity.runner.is_file());
        assert_ne!(identity.digest, [0; 32]);
        assert_eq!(
            identity.digest,
            bundler_toolchain_identity().unwrap().digest,
            "the cached identity must describe the same captured toolchain"
        );
    }

    #[tokio::test]
    async fn application_cwd_cannot_select_lookalike_bundler_tooling() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::remove_var("IBEX_REPO_ROOT");
        std::env::remove_var("EXACT_REPO_ROOT");

        let fake = tempdir().unwrap();
        std::fs::create_dir_all(fake.path().join("vendored-generated")).unwrap();
        std::fs::create_dir_all(fake.path().join("packages/ibex-runtime-js")).unwrap();
        std::fs::create_dir_all(fake.path().join("packages/ibex-devtools/src/scripts")).unwrap();
        std::fs::write(
            fake.path().join("packages/ibex-runtime-js/package.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(
            fake.path().join("packages/ibex-devtools/package.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(
            fake.path()
                .join("packages/ibex-devtools/src/scripts/rolldown-bundle.mjs"),
            "throw new Error('application-controlled bundler executed');",
        )
        .unwrap();

        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(fake.path()).unwrap();
        let selected = bundler_script_path();
        std::env::set_current_dir(original).unwrap();

        let selected = selected.unwrap();
        assert!(selected.starts_with(std::fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap()));
        assert!(!selected.starts_with(fake.path()));
    }

    #[cfg(feature = "module-runner")]
    #[test]
    fn native_module_runner_has_a_nonempty_exact_target_advertisement() {
        assert!(native_module_runner_target_is_advertised(
            "macos", "aarch64"
        ));
        assert!(native_module_runner_target_is_advertised("linux", "x86_64"));
        assert!(!native_module_runner_target_is_advertised(
            "windows", "x86_64"
        ));
        assert!(!native_module_runner_target_is_advertised(
            "macos", "x86_64"
        ));
        assert!(!native_module_runner_target_is_advertised("ios", "aarch64"));
    }

    #[test]
    fn detects_top_level_await_call_syntax() {
        assert!(contains_top_level_await("await(fetchStuff())\n"));
        assert!(!contains_top_level_await(
            "async function run() { await(fetchStuff()); }\n"
        ));
    }

    #[test]
    fn top_level_await_detection_skips_regex_literals() {
        // `await` inside a depth-0 regex literal is not TLA — the false
        // positive flipped the bundle format CJS→ESM and hard-failed valid
        // apps that merely declared a regex mentioning `await`. (ENG-23484;
        // mirrors the ENG-23031 fix for contains_await_keyword.)
        assert!(!contains_top_level_await("const RE = /(await)/;"));
        assert!(!contains_top_level_await("var re = /await/g"));
        assert!(!contains_top_level_await("const re = /a\\/await/;"));
        assert!(!contains_top_level_await("x.replace(/await/g, '')"));

        // A `/` after a value is division; a real `await` after it is still
        // detected, and a regex must not swallow the rest of the line.
        assert!(contains_top_level_await("var q = a / b; await c"));
        assert!(contains_top_level_await("const re = /await/; await go()"));
    }

    #[test]
    fn top_level_await_detection_keeps_depth_and_context_rules() {
        // Depth: only brace depth 0 is top-level.
        assert!(contains_top_level_await("await x;"));
        assert!(contains_top_level_await("const v = await f();"));
        assert!(!contains_top_level_await("if (x) { await y; }"));
        assert!(!contains_top_level_await(
            "class C { async m() { await x; } }"
        ));
        // Strings, comments, identifiers, labels.
        assert!(!contains_top_level_await("console.log(\"await\")"));
        assert!(!contains_top_level_await("// await\nlet a = 1;"));
        assert!(!contains_top_level_await("/* await */ let a = 1;"));
        assert!(!contains_top_level_await("let awaited = `await`;"));
        assert!(!contains_top_level_await("await: {}"));
        // Braces inside a regex literal must not corrupt the depth count.
        assert!(contains_top_level_await("const re = /a{2}[{]/; await x"));
    }

    #[test]
    fn transpile_esm_to_script_skips_multiline_export_block_without_semicolon_heuristic() {
        let source = r#"
export {
  thing,
  other // semicolon; in comment should not end the block
} from "./mod.js";
console.log("kept");
"#;
        let transpiled = transpile_esm_to_script(source);
        assert!(transpiled.contains("console.log(\"kept\");"));
        assert!(!transpiled.contains("export {"));
        assert!(!transpiled.contains("from \"./mod.js\""));
    }

    #[test]
    fn normalize_candidate_returns_existing_file_path() {
        let dir = tempdir().expect("temp dir");
        let file = dir.path().join("entry.js");
        std::fs::write(&file, "console.log('hi')").expect("write temp file");
        let resolved = normalize_candidate(&file).expect("resolved candidate");

        assert_eq!(resolved, file.to_string_lossy());
    }

    #[test]
    fn normalize_hashbang_for_eval_rewrites_hashbang_as_comment() {
        let normalized = normalize_hashbang_for_eval("#!/usr/bin/env node\nconsole.log('ok');\n");

        assert_eq!(
            normalized.as_ref(),
            "///usr/bin/env node\nconsole.log('ok');\n"
        );
    }

    #[test]
    fn normalize_hashbang_for_eval_strips_only_whole_line_sourcemap_comments() {
        // A line that IS a sourceMappingURL comment (leading whitespace aside)
        // is stripped; the marker inside a string literal — code that
        // generates sourcemap comments — must survive untouched. Truncating
        // it mid-line corrupted the source on every TLA-shim evaluation.
        // (ENG-23484)
        let source = "const banner = \"//# sourceMappingURL=x.map\";\n\
                      out.push(\"//# sourceMappingURL=\" + url);\n\
                      \t//# sourceMappingURL=indented.map\n\
                      //# sourceMappingURL=real.map\n";
        let normalized = normalize_hashbang_for_eval(source);

        assert_eq!(
            normalized.as_ref(),
            "const banner = \"//# sourceMappingURL=x.map\";\n\
             out.push(\"//# sourceMappingURL=\" + url);\n\
             \n\
             \n"
        );
    }

    #[test]
    fn normalize_hashbang_for_eval_keeps_trailing_code_before_sourcemap_comment() {
        // A trailing same-line comment after real code is no longer stripped:
        // this scan cannot prove comment position mid-line, and keeping a
        // stale sourcemap pointer is harmless next to truncating code.
        let source = "doWork(); //# sourceMappingURL=inline.map\n";
        let normalized = normalize_hashbang_for_eval(source);

        assert_eq!(normalized.as_ref(), source);
    }

    #[tokio::test]
    async fn runtime_executes_hashbang_entry_files() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        let dir = tempdir().expect("temp dir");
        let module_file = dir.path().join("module.js");
        let entry_file = dir.path().join("entry.js");

        std::fs::write(
            &module_file,
            "#!/usr/bin/env node\nmodule.exports = { value: 'module-ok' };\n",
        )
        .expect("write shebang module");
        std::fs::write(
            &entry_file,
            "#!/usr/bin/env node\nglobalThis.__hashbangEntry = 'entry';\nawait Promise.resolve();\nglobalThis.__hashbangEntry += '-ok';\n",
        )
        .expect("write shebang entry");

        let cli = Cli::parse_from(["ibex".to_string(), entry_file.to_string_lossy().to_string()]);
        let runtime = Runtime::from_audit_cli(&cli).expect("diagnostic runtime");
        runtime.load_runtime().await.expect("load runtime");

        let module_json = serde_json::to_string(&module_file.to_string_lossy().to_string())
            .expect("serialize module path");
        let module_result = runtime
            .eval(&format!(
                "(function() {{ return require({}).value === 'module-ok'; }})()",
                module_json
            ))
            .await
            .expect("require shebang module")
            .unwrap_or_default();
        assert_eq!(module_result.trim(), "true");

        runtime
            .run_file_with_args(entry_file.to_str().expect("entry path"), &[])
            .await
            .expect("run shebang entry");

        let entry_result = runtime
            .eval("(function() { return globalThis.__hashbangEntry === 'entry-ok'; })()")
            .await
            .expect("inspect entry result")
            .unwrap_or_default();
        assert_eq!(entry_result.trim(), "true");
    }

    #[tokio::test]
    async fn module_loader_preserves_nested_syntax_error_after_partial_exports() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        let dir = tempdir().expect("temp dir");
        let parent_file = dir.path().join("parent.mjs");
        let child_file = dir.path().join("child.js");

        std::fs::write(
            &child_file,
            "var err = new SyntaxError('nested syntax root');\nthrow err;\n",
        )
        .expect("write child module");
        std::fs::write(
            &parent_file,
            r#"
function _export(target, all) {
  for (var name in all) {
    Object.defineProperty(target, name, { enumerable: true, get: all[name] });
  }
}
var value = "parent export";
_export(module.exports, { value: function() { return value; } });
require("./child.js");
"#,
        )
        .expect("write parent module");

        let cli = Cli::parse_from([
            "ibex".to_string(),
            parent_file.to_string_lossy().to_string(),
        ]);
        let runtime = Runtime::from_audit_cli(&cli).expect("diagnostic runtime");
        runtime.load_runtime().await.expect("load runtime");

        let parent_json = serde_json::to_string(&parent_file.to_string_lossy().to_string())
            .expect("serialize parent path");
        let err = runtime
            .eval(&format!("require({});", parent_json))
            .await
            .expect_err("nested SyntaxError should be preserved");
        let message = format!("{err:#}");

        assert!(
            message.contains("nested syntax root"),
            "root nested error should survive: {message}"
        );
        assert!(
            !message.contains("property is not configurable")
                && !message.contains("Cannot redefine property"),
            "partial parent module must not be rerun and mask the root error: {message}"
        );
    }

    #[tokio::test]
    async fn module_loader_async_fn_await_import_stays_on_direct_path() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        // Guard against over-broad await-fallback routing (ENG-22811 review):
        // a module whose only `await import()` lives inside an ordinary async
        // function must load on the direct path — its top-level throws stay
        // synchronous errors instead of being swallowed as promise rejections
        // by an async wrapper, and its exports must not be ESM-shimmed.
        let dir = tempdir().expect("temp dir");
        let dep_file = dir.path().join("dep.js");
        let ok_file = dir.path().join("ok.js");
        let throwing_file = dir.path().join("throwing.js");

        std::fs::write(&dep_file, "module.exports = { ok: true };\n").expect("write dep module");
        std::fs::write(
            &ok_file,
            r#"
async function lazy() {
  var mod = await import("./dep.js");
  return mod.ok;
}
module.exports.lazy = lazy;
"#,
        )
        .expect("write ok module");
        std::fs::write(
            &throwing_file,
            r#"
async function lazy() {
  return await import("./dep.js");
}
module.exports.lazy = lazy;
throw new Error("sync-throw-marker");
"#,
        )
        .expect("write throwing module");

        let cli = Cli::parse_from(["ibex".to_string(), ok_file.to_string_lossy().to_string()]);
        let runtime = Runtime::from_audit_cli(&cli).expect("diagnostic runtime");
        runtime.load_runtime().await.expect("load runtime");

        let ok_json = serde_json::to_string(&ok_file.to_string_lossy().to_string())
            .expect("serialize ok path");
        let direct_result = runtime
            .eval(&format!(
                "(function() {{ var m = require({ok_json}); return (typeof m.lazy === 'function') && m.__esmShimmed === undefined; }})();"
            ))
            .await
            .expect("async-fn await module should load directly")
            .unwrap_or_default();
        assert_eq!(
            direct_result.trim(),
            "true",
            "module with await inside an async function must not be routed through the fallback"
        );

        let throwing_json = serde_json::to_string(&throwing_file.to_string_lossy().to_string())
            .expect("serialize throwing path");
        let err = runtime
            .eval(&format!("require({throwing_json});"))
            .await
            .expect_err("top-level throw must stay a synchronous require error");
        let message = format!("{err:#}");
        assert!(
            message.contains("sync-throw-marker"),
            "synchronous top-level throw should propagate, not become a rejection: {message}"
        );
    }
}
