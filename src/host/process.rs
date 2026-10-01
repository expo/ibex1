//! Process and environment operations for the Host ABI
//!
//! These operations are gated by the env and spawn capabilities.
//! Note: spawn is not available on iOS (no child processes).

use anyhow::Result;
use capsec_semantics::model::EnvironmentName;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

type EnvOverlay = HashMap<String, Option<String>>;

static COMPILED_ENVIRONMENT_BASE: OnceLock<CompiledEnvironmentBase> = OnceLock::new();

fn env_overlay() -> &'static RwLock<EnvOverlay> {
    static OVERLAY: OnceLock<RwLock<EnvOverlay>> = OnceLock::new();
    OVERLAY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Insecure-mode ambient environment: a one-shot snapshot of the host
/// environment inherited at startup, plus every later JavaScript mutation.
/// This is the *only* base `process.env` projection that ever contains host
/// values; it exists solely behind the compile-time `insecure` feature and an
/// explicit launcher install call. Armed secure runtimes (including
/// `unadvertised-dev-arming`) keep their digest-bound empty base plus
/// per-principal overlays, and embedders never inherit ambient host values
/// unless they call `install_insecure_ambient_environment` themselves.
/// Names are raw host names (not canonical `EnvironmentName`s): the ambient
/// projection is Node compatibility state, not typed-decision state, and it is
/// installed before arming so it is not a post-arm host read.
/// @ref LLP 0038#fully-open-mode-insecure — insecure projects the inherited
/// host environment through `process.env`; every secure mode keeps it empty.
#[cfg(feature = "insecure")]
mod insecure_ambient {
    use std::collections::BTreeMap;
    use std::sync::{OnceLock, RwLock};

    /// canonical key -> (display name, value). Sorted map so enumeration is
    /// deterministic; on Windows the canonical key is uppercased because host
    /// environment names are case-insensitive there (Node semantics), while
    /// the display name preserves the first-seen spelling.
    pub(super) type AmbientMap = BTreeMap<String, (String, String)>;

    pub(super) static STORE: OnceLock<RwLock<AmbientMap>> = OnceLock::new();

    pub(super) fn canonical_key(name: &str) -> String {
        if cfg!(windows) {
            name.to_uppercase()
        } else {
            name.to_owned()
        }
    }

    /// Inherited values that are a native construction handshake rather than
    /// public process environment; the unarmed compatibility path suppresses
    /// the same names. An explicit later JavaScript write of one of these
    /// names is ordinary `process.env` state and is not filtered.
    /// @ref LLP 0025#2-startup-configuration-is-captured-before-arming
    pub(super) fn is_private_construction_name(name: &str) -> bool {
        name == "EXACT_IPC_FD" || name == "EXACT_IPC_SERIALIZATION"
    }
}

/// Install the insecure ambient environment from the host environment of the
/// calling process. Idempotent; the first call wins. The CLI launcher calls
/// this at the top of `main` (parent and re-exec'd session worker alike), so
/// REPL, `eval`, `run`, and package-script routes all observe the same
/// projection. Embedders that want ambient host values in an insecure build
/// must call this explicitly — creating a runtime never installs it.
#[cfg(feature = "insecure")]
pub fn install_insecure_ambient_environment() {
    use insecure_ambient::{canonical_key, is_private_construction_name, STORE};
    let _ = STORE.get_or_init(|| {
        let mut map = insecure_ambient::AmbientMap::new();
        for (name, value) in std::env::vars_os() {
            let name = name.to_string_lossy().into_owned();
            // Skip unusable/pseudo names: empty, Windows drive-cwd entries
            // ("=C:=..."), and the private worker-construction handshake.
            if name.is_empty() || name.starts_with('=') || is_private_construction_name(&name) {
                continue;
            }
            let value = value.to_string_lossy().into_owned();
            map.entry(canonical_key(&name)).or_insert((name, value));
        }
        RwLock::new(map)
    });
}

/// True when the insecure ambient environment has been installed. Always
/// false in secure builds, where the installer does not exist.
pub fn insecure_ambient_environment_active() -> bool {
    #[cfg(feature = "insecure")]
    {
        insecure_ambient::STORE.get().is_some()
    }
    #[cfg(not(feature = "insecure"))]
    {
        false
    }
}

/// Read one name from the insecure ambient environment. `None` when the
/// projection is inactive or the name is unset (deleted names are unset).
#[cfg(feature = "insecure")]
pub fn insecure_ambient_env_get(name: &str) -> Option<String> {
    let store = insecure_ambient::STORE.get()?;
    let guard = store.read().ok()?;
    guard
        .get(&insecure_ambient::canonical_key(name))
        .map(|(_, value)| value.clone())
}

#[cfg(not(feature = "insecure"))]
pub fn insecure_ambient_env_get(_name: &str) -> Option<String> {
    None
}

/// Write (`Some`) or delete (`None`) one name in the insecure ambient
/// environment. A write updates the value while preserving the first-seen
/// display spelling on case-insensitive platforms; a delete removes the name
/// so the inherited host value does not resurface. No-op while inactive.
#[cfg(feature = "insecure")]
pub fn insecure_ambient_env_set(name: &str, value: Option<&str>) {
    let Some(store) = insecure_ambient::STORE.get() else {
        return;
    };
    let Ok(mut guard) = store.write() else {
        return;
    };
    let key = insecure_ambient::canonical_key(name);
    match value {
        Some(value) => match guard.get_mut(&key) {
            Some(entry) => entry.1 = value.to_owned(),
            None => {
                guard.insert(key, (name.to_owned(), value.to_owned()));
            }
        },
        None => {
            guard.remove(&key);
        }
    }
}

#[cfg(not(feature = "insecure"))]
pub fn insecure_ambient_env_set(_name: &str, _value: Option<&str>) {}

/// Number of names in the insecure ambient environment, or `None` while the
/// projection is inactive.
#[cfg(feature = "insecure")]
pub fn insecure_ambient_env_key_count() -> Option<usize> {
    let store = insecure_ambient::STORE.get()?;
    store.read().ok().map(|guard| guard.len())
}

#[cfg(not(feature = "insecure"))]
pub fn insecure_ambient_env_key_count() -> Option<usize> {
    None
}

/// The display name at `index` in canonical enumeration order.
#[cfg(feature = "insecure")]
pub fn insecure_ambient_env_key_at(index: usize) -> Option<String> {
    let store = insecure_ambient::STORE.get()?;
    let guard = store.read().ok()?;
    guard.values().nth(index).map(|(name, _)| name.clone())
}

#[cfg(not(feature = "insecure"))]
pub fn insecure_ambient_env_key_at(_index: usize) -> Option<String> {
    None
}

/// Immutable compiled-application broker base. Installation is process-wide
/// and one-shot because a compiled image owns exactly one captured launch
/// environment; individual reads are still authorized against the active
/// principal stack by the native adapter before these bytes are disclosed.
/// @ref LLP 0029#4-compiled-mode-authority
#[derive(Debug)]
pub struct CompiledEnvironmentBase {
    entries: BTreeMap<EnvironmentName, Vec<u8>>,
}

impl CompiledEnvironmentBase {
    pub fn new(entries: Vec<(EnvironmentName, Vec<u8>)>) -> Result<Self> {
        let mut ordered = BTreeMap::new();
        for (name, value) in entries {
            if ordered.insert(name, value).is_some() {
                anyhow::bail!("compiled environment broker base contains a duplicate name");
            }
        }
        Ok(Self { entries: ordered })
    }

    fn value(&self, key: &str) -> Option<&[u8]> {
        let name = EnvironmentName::new(key).ok()?;
        self.entries.get(&name).map(Vec::as_slice)
    }

    fn key(&self, index: usize) -> Option<&str> {
        self.entries.keys().nth(index).map(EnvironmentName::as_str)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn compiled_environment_base() -> Option<&'static CompiledEnvironmentBase> {
    COMPILED_ENVIRONMENT_BASE.get()
}

pub fn install_compiled_environment_base(base: CompiledEnvironmentBase) -> Result<()> {
    COMPILED_ENVIRONMENT_BASE
        .set(base)
        .map_err(|_| anyhow::anyhow!("compiled environment broker base is already installed"))
}

pub fn compiled_environment_value(key: &str) -> Option<Option<Vec<u8>>> {
    compiled_environment_base().map(|base| base.value(key).map(<[u8]>::to_vec))
}

pub fn compiled_environment_key_count() -> Option<usize> {
    compiled_environment_base().map(CompiledEnvironmentBase::len)
}

pub fn compiled_environment_key(index: usize) -> Option<&'static str> {
    compiled_environment_base()?.key(index)
}

/// Get the current working directory
pub fn cwd() -> Result<PathBuf> {
    std::env::current_dir().map_err(|e| anyhow::anyhow!("Failed to get cwd: {}", e))
}

/// Change the current working directory
pub fn chdir(path: &std::path::Path) -> Result<()> {
    std::env::set_current_dir(path)
        .map_err(|e| anyhow::anyhow!("Failed to change directory: {}", e))
}

/// Get an environment variable
pub fn env_get(key: &str) -> Option<String> {
    env_overlay()
        .read()
        .ok()
        .and_then(|overlay| overlay.get(key).cloned().flatten())
}

/// Set an environment variable
pub fn env_set(key: &str, value: &str) {
    if let Ok(mut overlay) = env_overlay().write() {
        overlay.insert(key.to_string(), Some(value.to_string()));
    }
}

/// Remove an environment variable
pub fn env_remove(key: &str) {
    if let Ok(mut overlay) = env_overlay().write() {
        overlay.insert(key.to_string(), None);
    }
}

/// Get all environment variables
pub fn env_all() -> HashMap<String, String> {
    let mut all = HashMap::new();
    if let Ok(overlay) = env_overlay().read() {
        for (key, value) in overlay.iter() {
            match value {
                Some(value) => {
                    all.insert(key.clone(), value.clone());
                }
                None => {
                    all.remove(key);
                }
            }
        }
    }
    all
}

/// Get the command line arguments
pub fn argv() -> Vec<String> {
    std::env::args().collect()
}

/// Get the process ID
pub fn pid() -> u32 {
    std::process::id()
}

/// Get the platform name
pub fn platform() -> &'static str {
    #[cfg(target_os = "macos")]
    return "darwin";
    #[cfg(target_os = "android")]
    return "android";
    #[cfg(target_os = "linux")]
    return "linux";
    #[cfg(target_os = "windows")]
    return "win32";
    #[cfg(target_os = "ios")]
    return "ios";
    #[cfg(target_os = "tvos")]
    return "tvos";
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )))]
    return "unknown";
}

/// Get the CPU architecture
pub fn arch() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    return "x64";
    #[cfg(target_arch = "aarch64")]
    return "arm64";
    #[cfg(target_arch = "x86")]
    return "x86";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
    return "unknown";
}

/// Exit the process with a status code
pub fn exit(code: i32) -> ! {
    std::process::exit(code)
}

/// Result of spawning a process
#[derive(Debug)]
pub struct SpawnResult {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Get system information
pub fn system_info() -> SystemInfo {
    SystemInfo {
        platform: platform().to_string(),
        arch: arch().to_string(),
        // Repository runtime callers use the typed native system-info route;
        // this legacy helper must not recover ambient host configuration.
        // @ref LLP 0025#2-startup-configuration-is-captured-before-arming
        hostname: "localhost".to_string(),
        cpus: std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1),
    }
}

/// System information
#[derive(Debug)]
pub struct SystemInfo {
    pub platform: String,
    pub arch: String,
    pub hostname: String,
    pub cpus: usize,
}

// The ambient store's positive semantics are covered in
// `tests/insecure_process_env.rs` (its own process, outside the environment
// inventory's scanned roots); the uninstalled negative lives in
// `tests/ambient_env_requires_install.rs`.

#[cfg(test)]
mod compiled_environment_tests {
    use super::*;

    #[test]
    fn compiled_environment_base_is_canonical_and_byte_preserving() {
        let base = CompiledEnvironmentBase::new(vec![
            (EnvironmentName::new("ZED").unwrap(), vec![0xff, 0x00]),
            (EnvironmentName::new("ALPHA").unwrap(), b"value".to_vec()),
        ])
        .unwrap();
        assert_eq!(base.len(), 2);
        assert_eq!(base.key(0), Some("ALPHA"));
        assert_eq!(base.key(1), Some("ZED"));
        assert_eq!(base.value("ALPHA"), Some(b"value".as_slice()));
        assert_eq!(base.value("lowercase"), None);
    }

    #[test]
    fn compiled_environment_base_refuses_duplicate_names() {
        let duplicate = EnvironmentName::new("DUPLICATE").unwrap();
        assert!(CompiledEnvironmentBase::new(vec![
            (duplicate.clone(), b"first".to_vec()),
            (duplicate, b"second".to_vec()),
        ])
        .is_err());
    }
}
