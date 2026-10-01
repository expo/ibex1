//! Module loader for ESM and CommonJS.
//!
//! This provides a minimal resolver and loader with `exact:` builtins.
//! Node-style package resolution and full ESM/CJS interop are implemented
//! incrementally (see TODOs).

pub mod artifact;
pub mod carrier;
pub mod catalog_compiler;
#[cfg(any(test, feature = "module-runner"))]
pub mod commonjs;
pub mod commonjs_lexer;
pub mod compatibility;
pub mod composition;
pub mod composition_refusals_generated;
pub mod computed_candidates;
pub mod embedded_graph;
#[cfg(any(test, feature = "module-runner"))]
pub mod generation;
#[cfg(any(test, feature = "module-runner"))]
pub mod graph;
#[cfg(any(test, feature = "module-runner"))]
pub mod hot_revision;
#[cfg(any(test, feature = "module-runner"))]
pub mod hot_update;
pub mod identity;
pub mod producer_spike;
#[cfg(any(test, feature = "module-runner"))]
pub mod runner_pipeline;
pub mod script_frontend;
#[cfg(any(test, feature = "module-runner"))]
pub mod security;
pub(crate) mod transform_config_generated;
pub mod transpile;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oxc_resolver::{
    FileMetadata as ResolverFileMetadata, FileSystem as ResolverFileSystem, ModuleType,
    ResolveError, ResolveOptions, Resolver, ResolverGeneric,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::SystemTime;

#[cfg(any(unix, windows))]
use std::collections::VecDeque;
#[cfg(unix)]
use std::ffi::CString;
#[cfg(any(unix, windows))]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use identity::{ConditionSet, ImportAttributes, ResolutionKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Esm,
    CommonJs,
    Json,
    Builtin,
}

/// Opaque compatibility referrer for an unarmed/dev Host. The backing path is
/// retained in the Host registry and never serialized; the virtual spelling is
/// a synthetic display identity only. Armed records always use
/// [`crate::vfs::ResolverLogicalPath`] instead.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateResolverPath {
    schema: String,
    session_handle: String,
    handle: String,
    virtual_path: String,
}

impl PrivateResolverPath {
    pub(crate) fn new(
        session_handle: String,
        handle: String,
        virtual_path: String,
    ) -> anyhow::Result<Self> {
        if !resolver_session_handle_is_canonical(&session_handle)
            || !private_resolver_handle_is_canonical(&handle)
            || virtual_path != format!("/project/.ibex-resolver/{handle}")
        {
            anyhow::bail!("invalid private resolver path record");
        }
        Ok(Self {
            schema: "ibex/private-resolver-ref/1".into(),
            session_handle,
            handle,
            virtual_path,
        })
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn session_handle(&self) -> &str {
        &self.session_handle
    }

    pub fn virtual_path(&self) -> &str {
        &self.virtual_path
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != "ibex/private-resolver-ref/1"
            || !resolver_session_handle_is_canonical(&self.session_handle)
            || !private_resolver_handle_is_canonical(&self.handle)
            || self.virtual_path != format!("/project/.ibex-resolver/{}", self.handle)
        {
            anyhow::bail!("invalid private resolver path record");
        }
        Ok(())
    }
}

fn resolver_session_handle_is_canonical(handle: &str) -> bool {
    handle.len() == 19
        && handle.starts_with("mrs")
        && handle[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn private_resolver_handle_is_canonical(handle: &str) -> bool {
    handle.len() == 17
        && handle.starts_with('r')
        && handle[1..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone)]
pub struct ResolvedModule {
    /// Portable identity used by typed module artifacts and the native module
    /// runner. Host paths remain display/debug labels and never replace it.
    /// The compatibility runtime's independently authenticated VFS/cache
    /// identity remains in `source_id` below; armed hosts stamp both forms from
    /// the same retained binding rather than translating either from a path.
    pub artifact_source_id: Option<identity::SourceId>,
    pub id: String,
    pub kind: ModuleKind,
    pub path: Option<PathBuf>,
    pub source: Option<String>,
    /// Package selector reported by resolver/package metadata, not inferred by
    /// the JS loader from the resolved path. `None` means first-party/root or
    /// an unclassified local path.
    pub package_name: Option<String>,
    /// Canonical package root for propagating a package classification across
    /// relative imports inside a linked/realpathed dependency.
    pub package_root: Option<PathBuf>,
    /// The self-reported `version` field of the resolved module's own nearest
    /// `package.json` when the module lives under `node_modules`, else `None`.
    /// Combined with the resolver/path-derived package **name** by the loader
    /// into `name@version`, so coexisting versions of one package get distinct
    /// principals/compartments and a `name@version` policy selector can pin a
    /// specific installed version. This is not an integrity boundary against a
    /// malicious package that forges its manifest version; authoritative identity
    /// would need lockfile/integrity input. @ref LLP 0013#resolved-questions
    /// (ENG-22621/ENG-22768)
    pub package_version: Option<String>,
    /// Integrity authenticated by the armed package graph. The generic
    /// resolver leaves this unset; `Host::resolve_module_meta` fills it only
    /// after matching the exact verified package-root binding.
    pub package_integrity: Option<String>,
    /// Authenticated module-cache identity. Builtins receive their manifest
    /// source key immediately; armed file modules receive identity only after
    /// their canonical path and bytes have been reauthenticated.
    pub source_id: Option<crate::vfs::SourceId>,
    /// Deterministic virtual display identity paired with a file `source_id`.
    pub source_label: Option<crate::vfs::SourceLabel>,
    /// Virtual absolute path used by module/import-meta observables. It is
    /// deliberately separate from the native-only resolver path above.
    pub virtual_path: Option<String>,
    /// Host-independent path record serialized as resolver `path`. The native
    /// host path above is retained only inside Rust and never crosses into JS.
    pub resolver_path: Option<crate::vfs::ResolverLogicalPath>,
    /// Host-independent package binding root serialized as resolver `pkgRoot`.
    /// Project and builtin records leave this absent.
    pub resolver_package_root: Option<crate::vfs::ResolverLogicalPath>,
    /// Opaque unarmed/dev fallback retained by Host. Mutually exclusive with
    /// `resolver_path`; it contains no backing spelling.
    pub private_resolver_path: Option<PrivateResolverPath>,
    pub private_resolver_package_root: Option<PrivateResolverPath>,
}

pub struct ModuleLoader {
    builtins: HashMap<&'static str, BuiltinModule>,
    resolver_import: Resolver,
    resolver_require: Resolver,
    /// Memoized `version` per package root dir (the nearest `package.json`), so
    /// version derivation is one read per package, not per module. (ENG-22621)
    package_versions: std::sync::RwLock<HashMap<PathBuf, Option<String>>>,
    environment: CapturedModuleLoaderEnvironment,
    transpile_mode: TranspileMode,
}

/// The complete filesystem input admitted to one armed resolver invocation.
///
/// `boundary_root` is the already-authenticated project root. Package
/// manifests and their absences are captured by Host through its typed VFS
/// read path and are the *only* `package.json` facts visible to OXC. A manifest
/// missing from both sets is recorded for a later authenticated Host discovery
/// pass and behaves as absent during this resolver attempt; it is never opened
/// from the ambient host filesystem.
///
/// @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
/// @ref LLP 0023#21-staged-authorization-identity
#[derive(Clone)]
pub(crate) struct AuthenticatedResolverInputs {
    inner: Arc<AuthenticatedResolverInputState>,
}

struct AuthenticatedResolverInputState {
    boundary_root: PathBuf,
    package_manifests: BTreeMap<PathBuf, Arc<[u8]>>,
    absent_package_manifests: BTreeSet<PathBuf>,
    denied_principal_subtrees: BTreeSet<PathBuf>,
    uncaptured_package_manifest_probes: std::sync::Mutex<BTreeSet<PathBuf>>,
    #[cfg(any(unix, windows))]
    boundary_handle: std::fs::File,
}

impl AuthenticatedResolverInputs {
    pub(crate) fn new(
        boundary_root: PathBuf,
        expected_boundary_object: &capsec_semantics::model::ObjectIdentity,
        package_manifests: BTreeMap<PathBuf, Vec<u8>>,
        absent_package_manifests: BTreeSet<PathBuf>,
        denied_principal_subtrees: BTreeSet<PathBuf>,
    ) -> Result<Self> {
        let boundary_root = lexical_absolute_path_for_resolver(&boundary_root)
            .context("authenticated resolver boundary is not an absolute normalized path")?;
        anyhow::ensure!(
            resolver_paths_equal(&boundary_root, &boundary_root)?,
            "authenticated resolver boundary is outside the bound alias contract"
        );

        // Validate the whole caller-supplied namespace before opening the
        // boundary descriptor. An outside manifest key must therefore fail
        // before this constructor performs any filesystem I/O.
        let mut captured = BTreeMap::<PathBuf, Arc<[u8]>>::new();
        for (path, bytes) in package_manifests {
            let path = lexical_absolute_path_for_resolver(&path)
                .context("authenticated package manifest path is not absolute")?;
            anyhow::ensure!(
                resolver_path_starts_with(&path, &boundary_root)?,
                "authenticated package manifest is outside the resolver boundary"
            );
            anyhow::ensure!(
                resolver_is_package_manifest(&path)?,
                "authenticated resolver inputs may contain only package.json bytes"
            );
            anyhow::ensure!(
                !captured
                    .keys()
                    .any(|candidate| resolver_paths_equal(candidate, &path).unwrap_or(false)),
                "authenticated package manifest paths are not unique after normalization"
            );
            captured.insert(path, Arc::<[u8]>::from(bytes));
        }
        let mut absent = BTreeSet::<PathBuf>::new();
        for path in absent_package_manifests {
            let path = lexical_absolute_path_for_resolver(&path)
                .context("authenticated absent package manifest path is not absolute")?;
            anyhow::ensure!(
                resolver_path_starts_with(&path, &boundary_root)?,
                "authenticated absent package manifest is outside the resolver boundary"
            );
            anyhow::ensure!(
                resolver_is_package_manifest(&path)?,
                "authenticated resolver absences may contain only package.json paths"
            );
            anyhow::ensure!(
                !captured
                    .keys()
                    .any(|candidate| resolver_paths_equal(candidate, &path).unwrap_or(false)),
                "package manifest cannot be both captured and authenticated absent"
            );
            anyhow::ensure!(
                !absent
                    .iter()
                    .any(|candidate| resolver_paths_equal(candidate, &path).unwrap_or(false)),
                "authenticated absent package manifest paths are not unique after normalization"
            );
            absent.insert(path);
        }
        let mut denied_subtrees = BTreeSet::<PathBuf>::new();
        for path in denied_principal_subtrees {
            let path = lexical_absolute_path_for_resolver(&path)
                .context("denied principal subtree path is not absolute")?;
            anyhow::ensure!(
                !resolver_paths_equal(&path, &boundary_root)?
                    && resolver_path_starts_with(&path, &boundary_root)?,
                "denied principal subtree must be a strict descendant of the resolver boundary"
            );
            anyhow::ensure!(
                !denied_subtrees
                    .iter()
                    .any(|candidate| resolver_paths_equal(candidate, &path).unwrap_or(false)),
                "denied principal subtree paths are not unique after normalization"
            );
            denied_subtrees.insert(path);
        }
        let inside_denied_subtree = |path: &Path| {
            denied_subtrees
                .iter()
                .any(|denied| resolver_path_starts_with(path, denied).unwrap_or(true))
        };
        anyhow::ensure!(
            captured.keys().all(|path| !inside_denied_subtree(path)),
            "captured package manifest is inside a denied principal subtree"
        );
        anyhow::ensure!(
            absent.iter().all(|path| !inside_denied_subtree(path)),
            "absent package manifest is inside a denied principal subtree"
        );

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (
                boundary_root,
                expected_boundary_object,
                captured,
                absent,
                denied_subtrees,
            );
            anyhow::bail!("authenticated module resolution requires descriptor-relative traversal");
        }

        #[cfg(unix)]
        {
            let boundary_handle =
                std::fs::File::from(open_resolver_boundary(&boundary_root).with_context(|| {
                    format!(
                        "failed to retain authenticated resolver boundary {}",
                        boundary_root.display()
                    )
                })?);
            let actual_boundary_object = crate::vfs::object_identity_for_metadata(
                &boundary_handle.metadata().with_context(|| {
                    format!(
                        "failed to inspect authenticated resolver boundary {}",
                        boundary_root.display()
                    )
                })?,
            )?;
            anyhow::ensure!(
                &actual_boundary_object == expected_boundary_object,
                "authenticated resolver boundary object changed before retention"
            );
            Ok(Self {
                inner: Arc::new(AuthenticatedResolverInputState {
                    boundary_root,
                    package_manifests: captured,
                    absent_package_manifests: absent,
                    denied_principal_subtrees: denied_subtrees,
                    uncaptured_package_manifest_probes: std::sync::Mutex::new(BTreeSet::new()),
                    boundary_handle,
                }),
            })
        }

        #[cfg(windows)]
        {
            let boundary_handle =
                open_resolver_boundary_windows(&boundary_root).with_context(|| {
                    format!(
                        "failed to retain authenticated resolver boundary {}",
                        boundary_root.display()
                    )
                })?;
            let actual_boundary_object =
                crate::host::object_identity_for_open_file(&boundary_handle)?;
            anyhow::ensure!(
                &actual_boundary_object == expected_boundary_object,
                "authenticated resolver boundary object changed before retention"
            );
            Ok(Self {
                inner: Arc::new(AuthenticatedResolverInputState {
                    boundary_root,
                    package_manifests: captured,
                    absent_package_manifests: absent,
                    denied_principal_subtrees: denied_subtrees,
                    uncaptured_package_manifest_probes: std::sync::Mutex::new(BTreeSet::new()),
                    boundary_handle,
                }),
            })
        }
    }

    pub(crate) fn boundary_root(&self) -> &Path {
        &self.inner.boundary_root
    }

    pub(crate) fn uncaptured_package_manifest_probes(&self) -> Result<BTreeSet<PathBuf>> {
        self.inner
            .uncaptured_package_manifest_probes
            .lock()
            .map(|probes| probes.clone())
            .map_err(|_| anyhow!("authenticated resolver manifest-probe ledger is poisoned"))
    }

    fn normalize_in_boundary(&self, path: &Path) -> io::Result<PathBuf> {
        #[cfg(windows)]
        let path = align_windows_resolver_namespace(path, self.boundary_root())?;
        #[cfg(not(windows))]
        let path = path.to_path_buf();
        let normalized = lexical_absolute_path_for_resolver(&path)?;
        if !resolver_path_starts_with(&normalized, self.boundary_root())? {
            return Err(resolver_boundary_refusal());
        }
        if self
            .inner
            .denied_principal_subtrees
            .iter()
            .any(|denied| resolver_path_starts_with(&normalized, denied).unwrap_or(true))
        {
            return Err(resolver_boundary_refusal());
        }
        Ok(normalized)
    }

    fn manifest_input(&self, path: &Path) -> io::Result<ResolverManifestInput<'_>> {
        let normalized = self.normalize_in_boundary(path)?;
        if !resolver_is_package_manifest(&normalized)? {
            return Ok(ResolverManifestInput::NotManifest);
        }
        if let Some(bytes) = self
            .inner
            .package_manifests
            .iter()
            .find_map(|(path, bytes)| {
                resolver_paths_equal(path, &normalized)
                    .unwrap_or(false)
                    .then_some(bytes)
            })
        {
            return Ok(ResolverManifestInput::Present(bytes.as_ref()));
        }
        if self
            .inner
            .absent_package_manifests
            .iter()
            .any(|path| resolver_paths_equal(path, &normalized).unwrap_or(false))
        {
            return Ok(ResolverManifestInput::Unavailable);
        }
        self.inner
            .uncaptured_package_manifest_probes
            .lock()
            .map_err(|_| {
                io::Error::other("authenticated resolver manifest-probe ledger is poisoned")
            })?
            .insert(normalized);
        Ok(ResolverManifestInput::Unavailable)
    }

    fn parse_manifest(&self, path: &Path) -> Result<Value> {
        let bytes = match self.manifest_input(path)? {
            ResolverManifestInput::Present(bytes) => bytes,
            ResolverManifestInput::Unavailable => {
                anyhow::bail!("authenticated package manifest was not captured")
            }
            ResolverManifestInput::NotManifest => {
                anyhow::bail!("authenticated package manifest path is invalid")
            }
        };
        serde_json::from_slice(bytes)
            .with_context(|| format!("Invalid authenticated package manifest {}", path.display()))
    }

    fn file_system(&self) -> BoundedResolverFileSystem {
        BoundedResolverFileSystem {
            inputs: Some(self.clone()),
        }
    }

    #[cfg(windows)]
    fn oxc_path(&self, path: &Path) -> io::Result<PathBuf> {
        let text = path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "authenticated resolver path is not Unicode",
            )
        })?;
        Ok(PathBuf::from(
            normalize_windows_verbatim_path_text(text).as_ref(),
        ))
    }
}

enum ResolverManifestInput<'a> {
    NotManifest,
    Present(&'a [u8]),
    Unavailable,
}

/// OXC filesystem used only by armed resolution. Target metadata remains a
/// descriptor-relative host lookup inside the retained project root; manifest
/// reads are served exclusively from `AuthenticatedResolverInputs`.
#[derive(Clone, Default)]
struct BoundedResolverFileSystem {
    inputs: Option<AuthenticatedResolverInputs>,
}

impl BoundedResolverFileSystem {
    fn inputs(&self) -> io::Result<&AuthenticatedResolverInputs> {
        self.inputs.as_ref().ok_or_else(resolver_boundary_refusal)
    }

    fn normalized(&self, path: &Path) -> io::Result<PathBuf> {
        self.inputs()?.normalize_in_boundary(path)
    }

    fn manifest_input(&self, path: &Path) -> io::Result<ResolverManifestInput<'_>> {
        self.inputs()?.manifest_input(path)
    }
}

impl ResolverFileSystem for BoundedResolverFileSystem {
    fn new() -> Self {
        // Armed callers always use `ResolverGeneric::new_with_file_system`.
        // Keeping the trait constructor inert makes an accidental generic
        // `new` fail closed on its first operation.
        Self::default()
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let normalized = self.normalized(path)?;
        match self.manifest_input(&normalized)? {
            ResolverManifestInput::Present(bytes) => Ok(bytes.to_vec()),
            ResolverManifestInput::Unavailable => Err(resolver_manifest_not_found()),
            ResolverManifestInput::NotManifest => Err(resolver_boundary_refusal()),
        }
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        String::from_utf8(self.read(path)?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "manifest is not UTF-8"))
    }

    fn metadata(&self, path: &Path) -> io::Result<ResolverFileMetadata> {
        let normalized = self.normalized(path)?;
        match self.manifest_input(&normalized)? {
            ResolverManifestInput::Present(_) => {
                return Ok(ResolverFileMetadata::new(true, false, false));
            }
            ResolverManifestInput::Unavailable => return Err(resolver_manifest_not_found()),
            ResolverManifestInput::NotManifest => {}
        }

        #[cfg(unix)]
        {
            let resolved = resolve_bounded_unix_path(self.inputs()?, &normalized)?;
            Ok(resolver_metadata_from_stat(&resolved.metadata))
        }

        #[cfg(windows)]
        {
            let resolved = resolve_bounded_windows_path(self.inputs()?, &normalized)?;
            Ok(resolver_metadata_from_windows(&resolved.metadata))
        }

        #[cfg(not(any(unix, windows)))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "authenticated resolver filesystem is Unix-only",
        ))
    }

    fn symlink_metadata(&self, path: &Path) -> io::Result<ResolverFileMetadata> {
        let normalized = self.normalized(path)?;
        match self.manifest_input(&normalized)? {
            ResolverManifestInput::Present(_) => {
                return Ok(ResolverFileMetadata::new(true, false, false));
            }
            ResolverManifestInput::Unavailable => return Err(resolver_manifest_not_found()),
            ResolverManifestInput::NotManifest => {}
        }

        #[cfg(unix)]
        {
            bounded_unix_symlink_metadata(self.inputs()?, &normalized)
                .map(|metadata| resolver_metadata_from_stat(&metadata))
        }

        #[cfg(windows)]
        {
            bounded_windows_symlink_metadata(self.inputs()?, &normalized)
                .map(|metadata| resolver_metadata_from_windows(&metadata))
        }

        #[cfg(not(any(unix, windows)))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "authenticated resolver filesystem is Unix-only",
        ))
    }

    fn read_link(&self, path: &Path) -> std::result::Result<PathBuf, ResolveError> {
        let normalized = self.normalized(path)?;
        match self.manifest_input(&normalized)? {
            ResolverManifestInput::Present(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "captured manifests are regular files",
                )
                .into());
            }
            ResolverManifestInput::Unavailable => {
                return Err(resolver_manifest_not_found().into());
            }
            ResolverManifestInput::NotManifest => {}
        }

        #[cfg(unix)]
        {
            bounded_unix_read_link(self.inputs()?, &normalized).map_err(Into::into)
        }

        #[cfg(windows)]
        {
            bounded_windows_read_link(self.inputs()?, &normalized).map_err(Into::into)
        }

        #[cfg(not(any(unix, windows)))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "authenticated resolver filesystem is Unix-only",
        )
        .into())
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        let normalized = self.normalized(path)?;
        match self.manifest_input(&normalized)? {
            ResolverManifestInput::Present(_) => {
                #[cfg(unix)]
                {
                    let parent = normalized.parent().ok_or_else(resolver_boundary_refusal)?;
                    let resolved_parent = resolve_bounded_unix_path(self.inputs()?, parent)?;
                    if !resolver_metadata_from_stat(&resolved_parent.metadata).is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotADirectory,
                            "manifest parent is not a directory",
                        ));
                    }
                    return Ok(resolved_parent.canonical_path.join("package.json"));
                }

                #[cfg(windows)]
                {
                    let parent = normalized.parent().ok_or_else(resolver_boundary_refusal)?;
                    let resolved_parent = resolve_bounded_windows_path(self.inputs()?, parent)?;
                    if !resolver_metadata_from_windows(&resolved_parent.metadata).is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotADirectory,
                            "manifest parent is not a directory",
                        ));
                    }
                    return self
                        .inputs()?
                        .oxc_path(&resolved_parent.canonical_path.join("package.json"));
                }

                #[cfg(not(any(unix, windows)))]
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "authenticated resolver filesystem is Unix-only",
                    ));
                }
            }
            ResolverManifestInput::Unavailable => return Err(resolver_manifest_not_found()),
            ResolverManifestInput::NotManifest => {}
        }

        #[cfg(unix)]
        {
            resolve_bounded_unix_path(self.inputs()?, &normalized)
                .map(|resolved| resolved.canonical_path)
        }

        #[cfg(windows)]
        {
            resolve_bounded_windows_path(self.inputs()?, &normalized)
                .and_then(|resolved| self.inputs()?.oxc_path(&resolved.canonical_path))
        }

        #[cfg(not(any(unix, windows)))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "authenticated resolver filesystem is Unix-only",
        ))
    }
}

fn resolver_boundary_refusal() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "resolver path is outside the authenticated boundary",
    )
}

fn resolver_manifest_not_found() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "authenticated package manifest is unavailable",
    )
}

fn lexical_absolute_path_for_resolver(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolver path is not absolute",
        ));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    if !normalized.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolver path normalization lost its root",
        ));
    }
    Ok(normalized)
}

fn resolver_paths_equal(left: &Path, right: &Path) -> io::Result<bool> {
    #[cfg(windows)]
    {
        return Ok(windows_resolver_path_key(left)? == windows_resolver_path_key(right)?);
    }
    #[cfg(not(windows))]
    Ok(left == right)
}

fn resolver_path_starts_with(path: &Path, prefix: &Path) -> io::Result<bool> {
    #[cfg(windows)]
    {
        let path = windows_resolver_path_key(path)?;
        let prefix = windows_resolver_path_key(prefix)?;
        return Ok(path.starts_with(&prefix));
    }
    #[cfg(not(windows))]
    Ok(path.starts_with(prefix))
}

fn resolver_is_package_manifest(path: &Path) -> io::Result<bool> {
    #[cfg(windows)]
    {
        let Some(file_name) = path.file_name() else {
            return Ok(false);
        };
        let file_name = resolver_windows_component(file_name)?;
        return Ok(crate::vfs::windows_component_is_alias_safe(file_name)
            && file_name.eq_ignore_ascii_case("package.json"));
    }
    #[cfg(not(windows))]
    Ok(path.file_name() == Some(OsStr::new("package.json")))
}

/// Produce the authorization comparison key for a retained Windows path.
/// This does not replace the lexical path used for diagnostics or SourceId.
///
/// @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment
#[cfg(windows)]
fn windows_resolver_path_key(path: &Path) -> io::Result<Vec<String>> {
    path.components()
        .map(|component| {
            let text = component.as_os_str().to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "authenticated resolver path component is not Unicode",
                )
            })?;
            if matches!(component, Component::Normal(_))
                && !crate::vfs::windows_component_is_alias_safe(text)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "authenticated resolver path is outside the bound Windows alias contract",
                ));
            }
            if !text.is_ascii() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "authenticated resolver root is outside the bound Windows alias contract",
                ));
            }
            Ok(text.to_ascii_lowercase())
        })
        .collect()
}

#[cfg(windows)]
fn align_windows_resolver_namespace(path: &Path, boundary: &Path) -> io::Result<PathBuf> {
    let path = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "authenticated resolver path is not Unicode",
        )
    })?;
    let boundary = boundary.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "authenticated resolver boundary is not Unicode",
        )
    })?;
    if boundary.starts_with(r"\\?\") {
        if path.starts_with(r"\\?\") {
            return Ok(PathBuf::from(path));
        }
        if let Some(unc) = path.strip_prefix(r"\\") {
            return Ok(PathBuf::from(format!(r"\\?\UNC\{unc}")));
        }
        return Ok(PathBuf::from(format!(r"\\?\{path}")));
    }
    Ok(PathBuf::from(
        normalize_windows_verbatim_path_text(path).as_ref(),
    ))
}

#[cfg(windows)]
struct BoundedWindowsResolution {
    canonical_path: PathBuf,
    metadata: std::fs::Metadata,
    directory: Option<std::fs::File>,
}

#[cfg(windows)]
fn open_resolver_boundary_windows(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let boundary = options.open(path)?;
    let metadata = boundary.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "authenticated resolver boundary is not a regular directory",
        ));
    }
    crate::vfs::windows_require_casefold_directory(&boundary)?;
    Ok(boundary)
}

#[cfg(windows)]
fn resolver_windows_component(component: &OsStr) -> io::Result<&str> {
    component.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "authenticated resolver path component is not Unicode",
        )
    })
}

#[cfg(windows)]
fn resolver_metadata_from_windows(metadata: &std::fs::Metadata) -> ResolverFileMetadata {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let reparse = metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    ResolverFileMetadata::new(
        !reparse && metadata.is_file(),
        !reparse && metadata.is_dir(),
        reparse,
    )
}

#[cfg(windows)]
fn resolver_windows_object(
    file: &std::fs::File,
) -> io::Result<capsec_semantics::model::ObjectIdentity> {
    crate::host::object_identity_for_open_file(file)
        .map_err(|error| io::Error::other(error.to_string()))
}

/// Resolve a Windows path entirely beneath the retained boundary. Every
/// ordinary directory transition is opened handle-relative without following
/// a reparse point and object-matched against the witnessed handle. Microsoft
/// symlink and mount-point targets are read twice through that same retained
/// object, lexically contained with the full pending tail, and checked against
/// denied principal subtrees before target lookup.
///
/// @ref LLP 0023#21-staged-authorization-identity
#[cfg(windows)]
fn resolve_bounded_windows_path(
    inputs: &AuthenticatedResolverInputs,
    path: &Path,
) -> io::Result<BoundedWindowsResolution> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let normalized = inputs.normalize_in_boundary(path)?;
    let mut pending = resolver_relative_components(inputs, &normalized)?;
    let mut current = inputs.inner.boundary_handle.try_clone()?;
    let mut resolved = Vec::<OsString>::new();
    let mut reparse_depth = 0usize;

    if pending.is_empty() {
        return Ok(BoundedWindowsResolution {
            canonical_path: inputs.boundary_root().to_path_buf(),
            metadata: current.metadata()?,
            directory: Some(current),
        });
    }

    loop {
        let component = pending.pop_front().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "resolver traversal became empty",
            )
        })?;
        let component_text = resolver_windows_component(&component)?;
        let witnessed = crate::vfs::windows_open_relative_no_follow(
            &current,
            component_text,
            crate::vfs::WindowsRelativeOpen::Metadata,
        )?;
        let metadata = witnessed.metadata()?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            reparse_depth += 1;
            if reparse_depth > 40 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "resolver reparse depth exceeded",
                ));
            }
            let target = crate::vfs::windows_read_verified_reparse_target(
                &current,
                component_text,
                &witnessed,
            )?;
            let mut combined = crate::vfs::windows_reparse_target_under_root(
                inputs.boundary_root(),
                &resolved,
                &target,
            )?;
            combined.extend(pending.iter().cloned());
            let combined_target = resolver_canonical_path(inputs, &combined);
            let combined_target = inputs.normalize_in_boundary(&combined_target)?;
            pending = resolver_relative_components(inputs, &combined_target)?;
            current = inputs.inner.boundary_handle.try_clone()?;
            resolved.clear();
            if pending.is_empty() {
                return Ok(BoundedWindowsResolution {
                    canonical_path: inputs.boundary_root().to_path_buf(),
                    metadata: current.metadata()?,
                    directory: Some(current),
                });
            }
            continue;
        }

        if pending.is_empty() {
            let directory = if metadata.is_dir() {
                let opened = crate::vfs::windows_open_relative_no_follow(
                    &current,
                    component_text,
                    crate::vfs::WindowsRelativeOpen::Directory,
                )?;
                if resolver_windows_object(&opened)? != resolver_windows_object(&witnessed)? {
                    return Err(io::Error::other(
                        "authenticated resolver directory changed during retention",
                    ));
                }
                crate::vfs::windows_require_casefold_directory(&opened)?;
                Some(opened)
            } else {
                None
            };
            resolved.push(component);
            return Ok(BoundedWindowsResolution {
                canonical_path: resolver_canonical_path(inputs, &resolved),
                metadata,
                directory,
            });
        }

        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "resolver path traverses a non-directory",
            ));
        }
        let opened = crate::vfs::windows_open_relative_no_follow(
            &current,
            component_text,
            crate::vfs::WindowsRelativeOpen::Directory,
        )?;
        if resolver_windows_object(&opened)? != resolver_windows_object(&witnessed)? {
            return Err(io::Error::other(
                "authenticated resolver directory changed during retention",
            ));
        }
        crate::vfs::windows_require_casefold_directory(&opened)?;
        current = opened;
        resolved.push(component);
    }
}

#[cfg(windows)]
fn bounded_windows_parent(
    inputs: &AuthenticatedResolverInputs,
    path: &Path,
) -> io::Result<(BoundedWindowsResolution, OsString)> {
    let normalized = inputs.normalize_in_boundary(path)?;
    let final_component = normalized
        .file_name()
        .ok_or_else(resolver_boundary_refusal)?
        .to_os_string();
    let parent = normalized.parent().ok_or_else(resolver_boundary_refusal)?;
    let resolved_parent = resolve_bounded_windows_path(inputs, parent)?;
    if !resolved_parent.metadata.is_dir() || resolved_parent.directory.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "resolver path parent is not a directory",
        ));
    }
    Ok((resolved_parent, final_component))
}

#[cfg(windows)]
fn bounded_windows_symlink_metadata(
    inputs: &AuthenticatedResolverInputs,
    path: &Path,
) -> io::Result<std::fs::Metadata> {
    let normalized = inputs.normalize_in_boundary(path)?;
    if normalized == inputs.boundary_root() {
        return inputs.inner.boundary_handle.metadata();
    }
    let (parent, final_component) = bounded_windows_parent(inputs, &normalized)?;
    let parent_handle = parent
        .directory
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotADirectory, "invalid parent"))?;
    crate::vfs::windows_open_relative_no_follow(
        parent_handle,
        resolver_windows_component(&final_component)?,
        crate::vfs::WindowsRelativeOpen::Metadata,
    )?
    .metadata()
}

#[cfg(windows)]
fn bounded_windows_read_link(
    inputs: &AuthenticatedResolverInputs,
    path: &Path,
) -> io::Result<PathBuf> {
    let normalized = inputs.normalize_in_boundary(path)?;
    let (parent, final_component) = bounded_windows_parent(inputs, &normalized)?;
    let parent_handle = parent
        .directory
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotADirectory, "invalid parent"))?;
    let component_text = resolver_windows_component(&final_component)?;
    let witnessed = crate::vfs::windows_open_relative_no_follow(
        parent_handle,
        component_text,
        crate::vfs::WindowsRelativeOpen::Metadata,
    )?;
    if !resolver_metadata_from_windows(&witnessed.metadata()?).is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolver object is not a symlink",
        ));
    }
    let target = crate::vfs::windows_read_verified_reparse_target(
        parent_handle,
        component_text,
        &witnessed,
    )?;
    let parent_components = resolver_relative_components(inputs, &parent.canonical_path)?
        .into_iter()
        .collect::<Vec<_>>();
    let target_components = crate::vfs::windows_reparse_target_under_root(
        inputs.boundary_root(),
        &parent_components,
        &target,
    )?;
    let absolute_target = resolver_canonical_path(inputs, &target_components);
    let _ = inputs.normalize_in_boundary(&absolute_target)?;
    Ok(match target {
        crate::vfs::WindowsReparseTarget::Relative(target)
        | crate::vfs::WindowsReparseTarget::Absolute(target) => PathBuf::from(target),
    })
}

#[cfg(unix)]
struct BoundedUnixResolution {
    canonical_path: PathBuf,
    metadata: libc::stat,
    directory: Option<OwnedFd>,
}

#[cfg(unix)]
fn open_resolver_boundary(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolver boundary contains a NUL byte",
        )
    })?;
    // SAFETY: `path` is a live NUL-terminated string. The returned descriptor
    // is checked for failure and immediately moved into `OwnedFd`.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a new owned descriptor above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
fn duplicate_resolver_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `fd` is borrowed for this call; `fcntl` creates a distinct owned
    // descriptor on success.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` returned a new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

#[cfg(unix)]
fn resolver_component_cstring(component: &OsStr) -> io::Result<CString> {
    CString::new(component.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolver path component contains a NUL byte",
        )
    })
}

#[cfg(unix)]
fn resolver_fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `metadata` points to writable storage for one `stat`; `fd` is a
    // live borrowed descriptor.
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstat` initialized the whole output structure.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn resolver_fstatat_nofollow(parent: RawFd, component: &OsStr) -> io::Result<libc::stat> {
    let component = resolver_component_cstring(component)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `component` and `metadata` are valid for this call; `parent` is
    // retained by the caller. `AT_SYMLINK_NOFOLLOW` prevents target access.
    if unsafe {
        libc::fstatat(
            parent,
            component.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstatat` initialized the output structure.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn resolver_open_directory_at(parent: RawFd, component: &OsStr) -> io::Result<OwnedFd> {
    let component = resolver_component_cstring(component)?;
    // SAFETY: `component` is a live NUL-terminated string and `parent` is a
    // retained directory descriptor. `O_NOFOLLOW` closes the lstat/open race.
    let fd = unsafe {
        libc::openat(
            parent,
            component.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
fn resolver_read_link_at(parent: RawFd, component: &OsStr) -> io::Result<PathBuf> {
    let component = resolver_component_cstring(component)?;
    let mut capacity = 256usize;
    loop {
        let mut bytes = vec![0u8; capacity];
        // SAFETY: the component string is valid, the output buffer has
        // `capacity` writable bytes, and `parent` remains live for this call.
        let length = unsafe {
            libc::readlinkat(
                parent,
                component.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        let length = usize::try_from(length)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid symlink length"))?;
        if length < bytes.len() {
            bytes.truncate(length);
            return Ok(PathBuf::from(OsString::from_vec(bytes)));
        }
        capacity = capacity.checked_mul(2).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "symlink target is too long")
        })?;
        if capacity > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "symlink target is too long",
            ));
        }
    }
}

#[cfg(unix)]
fn resolver_stat_is_dir(metadata: &libc::stat) -> bool {
    metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
}

#[cfg(unix)]
fn resolver_stat_is_symlink(metadata: &libc::stat) -> bool {
    metadata.st_mode & libc::S_IFMT == libc::S_IFLNK
}

#[cfg(unix)]
fn resolver_metadata_from_stat(metadata: &libc::stat) -> ResolverFileMetadata {
    let kind = metadata.st_mode & libc::S_IFMT;
    ResolverFileMetadata::new(
        kind == libc::S_IFREG,
        kind == libc::S_IFDIR,
        kind == libc::S_IFLNK,
    )
}

#[cfg(any(unix, windows))]
fn resolver_relative_components(
    inputs: &AuthenticatedResolverInputs,
    path: &Path,
) -> io::Result<VecDeque<OsString>> {
    let normalized = inputs.normalize_in_boundary(path)?;
    #[cfg(windows)]
    let relative = {
        if !resolver_path_starts_with(&normalized, inputs.boundary_root())? {
            return Err(resolver_boundary_refusal());
        }
        normalized
            .components()
            .skip(inputs.boundary_root().components().count())
            .collect::<PathBuf>()
    };
    #[cfg(not(windows))]
    let relative = normalized
        .strip_prefix(inputs.boundary_root())
        .map_err(|_| resolver_boundary_refusal())?
        .to_path_buf();
    let mut components = VecDeque::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => components.push_back(value.to_os_string()),
            Component::CurDir => {}
            _ => return Err(resolver_boundary_refusal()),
        }
    }
    Ok(components)
}

#[cfg(any(unix, windows))]
fn resolver_canonical_path(
    inputs: &AuthenticatedResolverInputs,
    components: &[OsString],
) -> PathBuf {
    let mut path = inputs.boundary_root().to_path_buf();
    path.extend(components);
    path
}

#[cfg(unix)]
fn resolve_bounded_unix_path(
    inputs: &AuthenticatedResolverInputs,
    path: &Path,
) -> io::Result<BoundedUnixResolution> {
    let normalized = inputs.normalize_in_boundary(path)?;
    let mut pending = resolver_relative_components(inputs, &normalized)?;
    let mut current = duplicate_resolver_fd(inputs.inner.boundary_handle.as_raw_fd())?;
    let mut resolved = Vec::<OsString>::new();
    let mut symlink_depth = 0usize;

    if pending.is_empty() {
        return Ok(BoundedUnixResolution {
            canonical_path: inputs.boundary_root().to_path_buf(),
            metadata: resolver_fstat(current.as_raw_fd())?,
            directory: Some(current),
        });
    }

    loop {
        let component = pending.pop_front().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "resolver traversal became empty",
            )
        })?;
        let metadata = resolver_fstatat_nofollow(current.as_raw_fd(), &component)?;
        if resolver_stat_is_symlink(&metadata) {
            symlink_depth += 1;
            if symlink_depth > 40 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "resolver symlink depth exceeded",
                ));
            }
            let target = resolver_read_link_at(current.as_raw_fd(), &component)?;
            let parent = resolver_canonical_path(inputs, &resolved);
            let target = if target.is_absolute() {
                target
            } else {
                parent.join(target)
            };
            // This lexical containment decision happens before the target is
            // ever opened or statted. An outside link is therefore a refusal,
            // not a target-existence probe.
            let mut combined_target = target;
            combined_target.extend(pending.iter());
            // Validate the entire substituted path, including the unconsumed
            // tail. Checking only the raw link target lets an ancestor target
            // plus that tail enter a denied principal subtree before the next
            // lookup.
            let combined_target = inputs.normalize_in_boundary(&combined_target)?;
            pending = resolver_relative_components(inputs, &combined_target)?;
            current = duplicate_resolver_fd(inputs.inner.boundary_handle.as_raw_fd())?;
            resolved.clear();
            if pending.is_empty() {
                return Ok(BoundedUnixResolution {
                    canonical_path: inputs.boundary_root().to_path_buf(),
                    metadata: resolver_fstat(current.as_raw_fd())?,
                    directory: Some(current),
                });
            }
            continue;
        }

        if pending.is_empty() {
            resolved.push(component.clone());
            let directory = if resolver_stat_is_dir(&metadata) {
                Some(resolver_open_directory_at(current.as_raw_fd(), &component)?)
            } else {
                None
            };
            return Ok(BoundedUnixResolution {
                canonical_path: resolver_canonical_path(inputs, &resolved),
                metadata,
                directory,
            });
        }

        if !resolver_stat_is_dir(&metadata) {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "resolver path traverses a non-directory",
            ));
        }
        current = resolver_open_directory_at(current.as_raw_fd(), &component)?;
        resolved.push(component);
    }
}

#[cfg(unix)]
fn bounded_unix_parent(
    inputs: &AuthenticatedResolverInputs,
    path: &Path,
) -> io::Result<(BoundedUnixResolution, OsString)> {
    let normalized = inputs.normalize_in_boundary(path)?;
    let final_component = normalized
        .file_name()
        .ok_or_else(resolver_boundary_refusal)?
        .to_os_string();
    let parent = normalized.parent().ok_or_else(resolver_boundary_refusal)?;
    let resolved_parent = resolve_bounded_unix_path(inputs, parent)?;
    if !resolver_stat_is_dir(&resolved_parent.metadata) || resolved_parent.directory.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "resolver path parent is not a directory",
        ));
    }
    Ok((resolved_parent, final_component))
}

#[cfg(unix)]
fn bounded_unix_symlink_metadata(
    inputs: &AuthenticatedResolverInputs,
    path: &Path,
) -> io::Result<libc::stat> {
    let normalized = inputs.normalize_in_boundary(path)?;
    if normalized == inputs.boundary_root() {
        return resolver_fstat(inputs.inner.boundary_handle.as_raw_fd());
    }
    let (parent, final_component) = bounded_unix_parent(inputs, &normalized)?;
    let parent_fd = parent
        .directory
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotADirectory, "invalid parent"))?;
    resolver_fstatat_nofollow(parent_fd.as_raw_fd(), &final_component)
}

#[cfg(unix)]
fn bounded_unix_read_link(
    inputs: &AuthenticatedResolverInputs,
    path: &Path,
) -> io::Result<PathBuf> {
    let normalized = inputs.normalize_in_boundary(path)?;
    let (parent, final_component) = bounded_unix_parent(inputs, &normalized)?;
    let parent_fd = parent
        .directory
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotADirectory, "invalid parent"))?;
    let metadata = resolver_fstatat_nofollow(parent_fd.as_raw_fd(), &final_component)?;
    if !resolver_stat_is_symlink(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolver object is not a symlink",
        ));
    }
    let target = resolver_read_link_at(parent_fd.as_raw_fd(), &final_component)?;
    let absolute_target = if target.is_absolute() {
        target.clone()
    } else {
        parent.canonical_path.join(&target)
    };
    // Validate the raw link target before OXC is allowed to recurse into it.
    // No target metadata or content operation precedes this check.
    let _ = inputs.normalize_in_boundary(&absolute_target)?;
    Ok(target)
}

const DEFAULT_TRANSPILE_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TranspileMode {
    DiagnosticPersistentCache,
    ArmedFreshInMemory,
}

/// Process environment values that affect module lowering are captured while
/// the Host is being constructed, before an armed Host is published. Module
/// evaluation never re-enters the mutable host environment. Cache locations
/// are retained only for unarmed diagnostic loaders; armed lowering never
/// resolves or accesses them.
/// @ref LLP 0025#2-startup-configuration-is-captured-before-arming
struct CapturedModuleLoaderEnvironment {
    runtime_transform: Option<String>,
    legacy_runtime_transform: Option<String>,
    transpile_script: Option<PathBuf>,
    transpile_cache_max_bytes: u64,
    test_transpile_input_barrier: Option<PathBuf>,
    runtime_cache_dir: std::result::Result<PathBuf, String>,
    fallback_temp_dir: PathBuf,
    transpile_cache_dir: std::sync::OnceLock<std::result::Result<PathBuf, String>>,
    transpile_tooling_hash: std::sync::OnceLock<std::result::Result<[u8; 32], String>>,
    transpile_override_identity: Option<std::result::Result<TranspileOverrideIdentity, String>>,
}

impl CapturedModuleLoaderEnvironment {
    fn capture() -> Self {
        let transpile_script = std::env::var("EXACT_TRANSPILE_SCRIPT")
            .ok()
            .map(PathBuf::from);
        let transpile_override_identity = transpile_script.as_ref().map(|path| {
            compute_transpile_override_identity(path).map_err(|error| format!("{error:#}"))
        });
        Self {
            runtime_transform: std::env::var("IBEX_RUNTIME_TRANSFORM").ok(),
            legacy_runtime_transform: std::env::var("EXACT_RUNTIME_TRANSFORM").ok(),
            transpile_script,
            transpile_cache_max_bytes: std::env::var("IBEX_TRANSPILE_CACHE_MAX_BYTES")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(DEFAULT_TRANSPILE_CACHE_MAX_BYTES),
            test_transpile_input_barrier: std::env::var("IBEX_TEST_TRANSPILE_INPUT_BARRIER")
                .ok()
                .map(PathBuf::from),
            // Android's app-provided cache root (and the platform-directory
            // fallback used elsewhere) is resolved while Host constructs the
            // loader. Only an unarmed diagnostic import consumes this capture.
            // @ref LLP 0025#2-startup-configuration-is-captured-before-arming
            runtime_cache_dir: crate::runtime_cache_dir().map_err(|error| error.to_string()),
            fallback_temp_dir: std::env::temp_dir(),
            transpile_cache_dir: std::sync::OnceLock::new(),
            transpile_tooling_hash: std::sync::OnceLock::new(),
            // The override's immediate parent tree and its PATH-selected
            // runner are frozen at the same Host-construction boundary. A
            // later transpiling import cannot select a different compiler.
            transpile_override_identity,
        }
    }

    fn runtime_transform(&self) -> Option<&str> {
        self.runtime_transform.as_deref()
    }

    fn legacy_runtime_transform(&self) -> Option<&str> {
        self.legacy_runtime_transform.as_deref()
    }
}

#[derive(Clone)]
struct BuiltinModule {
    source_key: &'static str,
    source: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct BuiltinManifestRegistration {
    specifier: &'static str,
    source_key: &'static str,
}

/// Whether the generated builtin manifest owns this exact public specifier.
/// @ref LLP 0004#one-source-many-specifiers — every authored alias belongs to
/// the builtin import axis even when it is not spelled with a `node:` prefix.
pub(crate) fn is_registered_builtin_specifier(specifier: &str) -> bool {
    BUILTIN_MANIFEST_REGISTRATIONS
        .iter()
        .any(|registration| registration.specifier == specifier)
}

/// Whether the bootstrap loader owns this exact internal object spelling.
/// These names are not registry modules and never enter package resolution.
/// Native builtin execution uses the same generated list to retain the edge
/// as a sealed bootstrap-closure lookup instead of inventing a module record.
/// @ref LLP 0004#one-source-many-specifiers
pub(crate) fn is_bootstrap_internal_module_specifier(specifier: &str) -> bool {
    BOOTSTRAP_INTERNAL_MODULE_SPECIFIERS.contains(&specifier)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BuiltinManifestDebugEntry {
    pub specifier: &'static str,
    pub source_key: &'static str,
    pub source_kind: &'static str,
    pub source_path: Option<&'static str>,
    pub platform_availability: &'static str,
    pub module_builtin: bool,
    pub bundle_external: bool,
}

include!(concat!(env!("OUT_DIR"), "/builtin_manifest.generated.rs"));

impl Default for ModuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

fn module_resolve_options(module_type: bool, conditions: &ConditionSet) -> ResolveOptions {
    ResolveOptions {
        extensions: vec![
            ".js".into(),
            ".cjs".into(),
            ".mjs".into(),
            ".ts".into(),
            ".tsx".into(),
            ".jsx".into(),
            ".mts".into(),
            ".cts".into(),
            ".json".into(),
        ],
        // `default` is unconditional in package exports and must not be an
        // active condition. Import and require remain separate resolution and
        // authorization domains. @ref LLP 0026#1-source-admission-and-resolution
        condition_names: conditions.names().map(Into::into).collect(),
        module_type,
        // TS NodeNext convention: `./x.js` in TS sources refers to `./x.ts`
        // on disk. Real `.js` files keep priority, mirroring Vite's resolution
        // on the web side. @ref LLP 0004#the-oxc_resolver-configuration
        extension_alias: vec![
            (
                ".js".into(),
                vec![".js".into(), ".ts".into(), ".tsx".into()],
            ),
            (".mjs".into(), vec![".mjs".into(), ".mts".into()]),
            (".cjs".into(), vec![".cjs".into(), ".cts".into()]),
        ],
        ..ResolveOptions::default()
    }
}

fn authenticated_module_resolve_options(
    module_type: bool,
    conditions: &ConditionSet,
) -> ResolveOptions {
    let mut options = module_resolve_options(module_type, conditions);
    // NODE_PATH is process-global ambient authority. Armed package discovery
    // is restricted to the authenticated boundary and captured manifests.
    options.node_path = false;
    options
}

impl ModuleLoader {
    pub fn new() -> Self {
        let builtins = build_builtin_registry(BUILTIN_MANIFEST_REGISTRATIONS);

        Self {
            builtins,
            resolver_import: Resolver::new(module_resolve_options(
                true,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
            )),
            resolver_require: Resolver::new(module_resolve_options(
                true,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            )),
            package_versions: std::sync::RwLock::new(HashMap::new()),
            environment: CapturedModuleLoaderEnvironment::capture(),
            transpile_mode: TranspileMode::DiagnosticPersistentCache,
        }
    }

    /// Permanently close persistent transpile-cache and subprocess paths before
    /// this loader is published through an armed Host. Armed TypeScript/JSX
    /// lowering consumes the loader's captured source and transform selection
    /// directly in process; public cache hashes are not compiler authorship.
    /// @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
    pub(crate) fn arm_fresh_transpilation(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.environment.transpile_script.is_none(),
            "EXACT_TRANSPILE_SCRIPT is a diagnostic-only developer escape and is unavailable to an armed host"
        );
        anyhow::ensure!(
            self.transpile_mode == TranspileMode::DiagnosticPersistentCache,
            "module loader transpilation was already armed"
        );
        self.transpile_mode = TranspileMode::ArmedFreshInMemory;
        Ok(())
    }

    /// Resolve only the kind metadata for one already-authorized direct file.
    /// Direct `.js` ingress uses the import/entry resolver's package `type`
    /// classification so the Host, rather than operator input or source
    /// sniffing, closes the authenticated ESM/CommonJS shape.
    ///
    /// The caller must complete target authorization before invoking this
    /// method because OXC may inspect an enclosing package manifest.
    /// @ref LLP 0024#4-grammar-selection
    #[allow(dead_code)] // Retained for unarmed diagnostic callers and differential tests.
    pub(crate) fn resolve_direct_file_meta(&self, path: &Path) -> Result<ResolvedModule> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("direct file has no parent directory"))?;
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow!("direct file name is not UTF-8"))?;
        let resolver = Resolver::new(module_resolve_options(
            true,
            &ConditionSet::for_kind(ResolutionKind::Entry),
        ));
        let resolved =
            self.resolve_with_resolver_at(&resolver, &format!("./{name}"), parent, false, None)?;
        let expected = std::fs::canonicalize(path)
            .with_context(|| format!("failed to authenticate direct file {}", path.display()))?;
        let actual = resolved
            .path
            .as_deref()
            .ok_or_else(|| anyhow!("direct file resolver returned no path"))?
            .canonicalize()
            .with_context(|| "failed to authenticate resolved direct file")?;
        if actual != expected {
            anyhow::bail!("direct file resolver selected a different path");
        }
        Ok(resolved)
    }

    /// Resolve an already-authenticated direct file without consulting any
    /// manifest or symlink target outside `inputs.boundary_root()`. The exact
    /// target comparison prevents extension aliases or a package entry point
    /// from silently replacing the submitted file.
    /// @ref LLP 0024#4-grammar-selection
    pub(crate) fn resolve_direct_file_meta_authenticated(
        &self,
        path: &Path,
        inputs: &AuthenticatedResolverInputs,
    ) -> Result<ResolvedModule> {
        let path = inputs.normalize_in_boundary(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("direct file has no parent directory"))?;
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow!("direct file name is not UTF-8"))?;
        let file_system = inputs.file_system();
        let expected = file_system
            .canonicalize(&path)
            .with_context(|| format!("failed to authenticate direct file {}", path.display()))?;
        let resolver = ResolverGeneric::new_with_file_system(
            file_system,
            authenticated_module_resolve_options(
                true,
                &ConditionSet::for_kind(ResolutionKind::Entry),
            ),
        );
        #[cfg(windows)]
        let resolver_parent = inputs
            .oxc_path(parent)
            .context("authenticated direct-file parent is not representable for OXC")?;
        #[cfg(not(windows))]
        let resolver_parent = parent.to_path_buf();
        let resolved = self.resolve_with_resolver_at(
            &resolver,
            &format!("./{name}"),
            &resolver_parent,
            false,
            Some(inputs),
        )?;
        let actual_path = resolved
            .path
            .as_deref()
            .ok_or_else(|| anyhow!("direct file resolver returned no path"))?;
        let actual = inputs
            .file_system()
            .canonicalize(actual_path)
            .context("failed to authenticate resolved direct file")?;
        if actual != expected {
            anyhow::bail!("direct file resolver selected a different path");
        }
        Ok(resolved)
    }

    /// Armed general resolution. Unlike `resolve_meta`, `#imports` is handled
    /// by the same bounded OXC resolver as relative and bare requests; the
    /// legacy `find_package_root` helper is deliberately unreachable here.
    #[allow(dead_code)] // Retained for untyped internal CommonJS callers.
    pub(crate) fn resolve_meta_authenticated(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        preflighted_requested_path: Option<&Path>,
        inputs: &AuthenticatedResolverInputs,
    ) -> Result<ResolvedModule> {
        self.resolve_meta_authenticated_typed(
            specifier,
            referrer,
            preflighted_requested_path,
            ResolutionKind::CommonJsRequire,
            &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            &ImportAttributes::default(),
            inputs,
        )
    }

    /// Typed armed resolution. OXC sees only the descriptor-backed filesystem
    /// and captured manifest bytes, while resolution kind/conditions select the
    /// same distinct import and require domains used by the module runner.
    pub(crate) fn resolve_meta_authenticated_typed(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        preflighted_requested_path: Option<&Path>,
        kind: ResolutionKind,
        conditions: &ConditionSet,
        attributes: &ImportAttributes,
        inputs: &AuthenticatedResolverInputs,
    ) -> Result<ResolvedModule> {
        let specifier = specifier.trim();
        if specifier.is_empty() {
            return Err(anyhow!("Empty module specifier"));
        }
        let specifier = strip_file_module_decorations(specifier);
        #[cfg(windows)]
        let normalized_specifier = normalize_windows_verbatim_path_text(specifier);
        #[cfg(windows)]
        let specifier = normalized_specifier.as_ref();
        if !attributes.is_empty() && kind == ResolutionKind::CommonJsRequire {
            return Err(anyhow!(
                "CommonJS require does not accept import attributes"
            ));
        }
        if let Some(module) = self.resolve_builtin_meta(specifier)? {
            return Self::validate_import_attributes(module, kind, attributes);
        }
        if specifier.starts_with("exact:") {
            return Err(anyhow!("Unknown exact builtin: {}", specifier));
        }
        if specifier.starts_with("node:") {
            return Err(anyhow!("Unsupported node builtin: {}", specifier));
        }

        let base_dir = authenticated_resolver_base_dir(
            inputs,
            referrer,
            specifier,
            preflighted_requested_path,
        )?;
        let resolver = ResolverGeneric::new_with_file_system(
            inputs.file_system(),
            authenticated_module_resolve_options(true, conditions),
        );
        let resolved =
            self.resolve_with_resolver_at(&resolver, specifier, &base_dir, false, Some(inputs))?;
        Self::validate_import_attributes(resolved, kind, attributes)
    }

    /// Resolve a graph-approved bare request from its authenticated package
    /// binding. The package-root manifest is parsed only from captured bytes;
    /// disk contents cannot change `name`, `version`, `exports`, or kind.
    #[allow(dead_code)] // Retained for untyped internal CommonJS callers.
    pub(crate) fn resolve_meta_from_authenticated_bound_package(
        &self,
        specifier: &str,
        package_name: &str,
        package_root: &Path,
        inputs: &AuthenticatedResolverInputs,
    ) -> Result<ResolvedModule> {
        self.resolve_meta_from_authenticated_bound_package_typed(
            specifier,
            package_name,
            package_root,
            ResolutionKind::CommonJsRequire,
            &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            &ImportAttributes::default(),
            inputs,
        )
    }

    pub(crate) fn resolve_meta_from_authenticated_bound_package_typed(
        &self,
        specifier: &str,
        package_name: &str,
        package_root: &Path,
        kind: ResolutionKind,
        conditions: &ConditionSet,
        attributes: &ImportAttributes,
        inputs: &AuthenticatedResolverInputs,
    ) -> Result<ResolvedModule> {
        if !attributes.is_empty() && kind == ResolutionKind::CommonJsRequire {
            return Err(anyhow!(
                "CommonJS require does not accept import attributes"
            ));
        }
        let specifier = specifier.trim();
        let requested_name = package_name_from_bare_specifier(specifier)
            .ok_or_else(|| anyhow!("bound package resolution requires a bare specifier"))?;
        if requested_name != package_name {
            return Err(anyhow!("bound package name differs from requested package"));
        }
        let package_root = inputs.normalize_in_boundary(package_root)?;
        let manifest_path = package_root.join("package.json");
        let manifest = inputs.parse_manifest(&manifest_path)?;
        if manifest.get("name").and_then(Value::as_str) != Some(package_name) {
            anyhow::bail!("authenticated package manifest name differs from its principal");
        }
        let suffix = specifier
            .strip_prefix(package_name)
            .ok_or_else(|| anyhow!("bound package prefix is absent"))?;
        if !suffix.is_empty() && !suffix.starts_with('/') {
            return Err(anyhow!("invalid package subpath"));
        }
        if suffix
            .split('/')
            .any(|component| component == "." || component == "..")
        {
            return Err(anyhow!("package subpath contains traversal components"));
        }

        let anchored_specifier = if manifest
            .get("exports")
            .is_some_and(|value| !value.is_null())
        {
            specifier.to_owned()
        } else if suffix.is_empty() {
            ".".to_owned()
        } else {
            format!(".{suffix}")
        };
        let resolver = ResolverGeneric::new_with_file_system(
            inputs.file_system(),
            authenticated_module_resolve_options(true, conditions),
        );
        #[cfg(windows)]
        let resolver_package_root = inputs
            .oxc_path(&package_root)
            .context("authenticated package root is not representable for OXC")?;
        #[cfg(not(windows))]
        let resolver_package_root = package_root.clone();
        let mut resolved = self.resolve_with_resolver_at(
            &resolver,
            &anchored_specifier,
            &resolver_package_root,
            false,
            Some(inputs),
        )?;
        let canonical_package_root = inputs
            .file_system()
            .canonicalize(&package_root)
            .context("failed to authenticate bound package root")?;
        let canonical_package_root = inputs
            .normalize_in_boundary(&canonical_package_root)
            .context("authenticated bound package root changed namespace")?;
        resolved.package_name = Some(package_name.to_owned());
        resolved.package_root = Some(canonical_package_root);
        resolved.package_version = manifest
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Self::validate_import_attributes(resolved, kind, attributes)
    }

    /// The `version` of the package that owns `path`, when `path` is under a
    /// `node_modules` tree — read from the nearest enclosing `package.json` and
    /// memoized per package root. `None` for first-party/workspace code (no
    /// `node_modules` ancestor) or a manifest with no `version`. The resolver
    /// metadata/path is authoritative for the package name; the version is
    /// self-reported and only distinguishes coexisting installed copies.
    /// Version-pinned selectors are therefore convenience/precision, not a trust
    /// boundary against a malicious package forging its package.json.
    /// @ref LLP 0013#resolved-questions — ENG-22621/ENG-22768
    fn package_version_for(&self, path: &Path) -> Option<String> {
        // Read the version from the package's OWN root (`node_modules/<name>`,
        // the same segment the loader derives the package NAME from), NOT the
        // nearest enclosing package.json: a package commonly ships a nested,
        // versionless `package.json` (e.g. `dist/package.json` with
        // `{"type":"module"}`, or subpath-exports dirs), and walking to the
        // nearest one would read that versionless manifest and silently degrade
        // the identity to the bare name — disabling version pinning for those
        // packages. (ENG-22621)
        let root = package_root_in_node_modules(path)?;
        if let Ok(memo) = self.package_versions.read() {
            if let Some(v) = memo.get(&root) {
                return v.clone();
            }
        }
        let version = read_package_manifest(&root.join("package.json"))
            .ok()
            .and_then(|m| m.get("version").and_then(Value::as_str).map(str::to_string));
        if let Ok(mut memo) = self.package_versions.write() {
            memo.insert(root, version.clone());
        }
        version
    }

    pub fn resolve(&self, specifier: &str, referrer: Option<&Path>) -> Result<ResolvedModule> {
        let meta = self.resolve_meta_typed(
            specifier,
            referrer,
            ResolutionKind::CommonJsRequire,
            &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            &ImportAttributes::default(),
        )?;
        self.load_source(meta)
    }

    pub fn resolve_meta(&self, specifier: &str, referrer: Option<&Path>) -> Result<ResolvedModule> {
        self.resolve_meta_typed(
            specifier,
            referrer,
            ResolutionKind::CommonJsRequire,
            &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            &ImportAttributes::default(),
        )
    }

    pub fn resolve_meta_typed(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
        conditions: &ConditionSet,
        attributes: &ImportAttributes,
    ) -> Result<ResolvedModule> {
        let specifier = specifier.trim();
        if specifier.is_empty() {
            return Err(anyhow!("Empty module specifier"));
        }
        let specifier = strip_file_specifier_decorations(specifier);
        #[cfg(windows)]
        let normalized_specifier = normalize_windows_verbatim_path_text(specifier);
        #[cfg(windows)]
        let specifier = normalized_specifier.as_ref();
        if !attributes.is_empty() && kind == ResolutionKind::CommonJsRequire {
            return Err(anyhow!(
                "CommonJS require does not accept import attributes"
            ));
        }
        if specifier.starts_with('#') {
            if let Some(referrer_path) = referrer {
                if let Some(module) =
                    self.resolve_package_import(specifier, referrer_path, conditions)
                {
                    return Self::validate_import_attributes(module, kind, attributes);
                }
            }
            return Err(anyhow!("Failed to resolve package import {}", specifier));
        }
        if let Some(module) = self.resolve_builtin_meta(specifier)? {
            return Self::validate_import_attributes(module, kind, attributes);
        }

        if specifier.starts_with("exact:") {
            return Err(anyhow!("Unknown exact builtin: {}", specifier));
        }

        if specifier.starts_with("node:") {
            return Err(anyhow!("Unsupported node builtin: {}", specifier));
        }

        let resolved = self.resolve_with_oxc(specifier, referrer, kind)?;
        Self::validate_import_attributes(resolved, kind, attributes)
    }

    fn validate_import_attributes(
        module: ResolvedModule,
        resolution_kind: ResolutionKind,
        attributes: &ImportAttributes,
    ) -> Result<ResolvedModule> {
        if attributes.asserts_json() && module.kind != ModuleKind::Json {
            return Err(anyhow!(
                "type=json import attribute requires a JSON module target"
            ));
        }
        if module.kind == ModuleKind::Json
            && resolution_kind != ResolutionKind::CommonJsRequire
            && !attributes.asserts_json()
        {
            return Err(anyhow!(
                "ESM JSON import requires the type=json import attribute"
            ));
        }
        Ok(module)
    }

    fn resolve_builtin_meta(&self, specifier: &str) -> Result<Option<ResolvedModule>> {
        let Some(builtin) = self.builtins.get(specifier) else {
            return Ok(None);
        };
        Ok(Some(ResolvedModule {
            artifact_source_id: Some(identity::SourceId::builtin(
                "ibex-runtime",
                builtin.source_key,
            )?),
            id: specifier.to_string(),
            kind: ModuleKind::Builtin,
            path: None,
            source: Some(builtin.source.to_owned()),
            package_name: None,
            package_root: None,
            package_version: None,
            package_integrity: None,
            source_id: Some(crate::vfs::SourceId::builtin(builtin.source_key)),
            source_label: None,
            virtual_path: None,
            resolver_path: None,
            resolver_package_root: None,
            private_resolver_path: None,
            private_resolver_package_root: None,
        }))
    }

    pub(crate) fn is_builtin_specifier(&self, specifier: &str) -> bool {
        self.builtins.contains_key(specifier.trim())
    }

    /// Resolve a bare package request from the one package root authenticated
    /// by the armed graph. Starting ordinary Node resolution at the requester's
    /// directory would still probe ambient `node_modules` trees before the
    /// post-resolution owner check. Package-self resolution keeps `exports`
    /// semantics while anchoring every permitted lookup at `package_root`; the
    /// legacy `main`/subpath case is rewritten to an exact relative lookup.
    /// @ref LLP 0021#decision-staging-and-principal-semantics
    #[allow(dead_code)] // Retained for unarmed diagnostic callers and differential tests.
    pub(crate) fn resolve_meta_from_bound_package(
        &self,
        specifier: &str,
        package_name: &str,
        package_root: &Path,
    ) -> Result<ResolvedModule> {
        self.resolve_meta_from_bound_package_typed(
            specifier,
            package_name,
            package_root,
            ResolutionKind::CommonJsRequire,
            &ImportAttributes::default(),
        )
    }

    pub(crate) fn resolve_meta_from_bound_package_typed(
        &self,
        specifier: &str,
        package_name: &str,
        package_root: &Path,
        kind: ResolutionKind,
        attributes: &ImportAttributes,
    ) -> Result<ResolvedModule> {
        let specifier = specifier.trim();
        let requested_name = package_name_from_bare_specifier(specifier)
            .ok_or_else(|| anyhow!("bound package resolution requires a bare specifier"))?;
        if requested_name != package_name {
            return Err(anyhow!("bound package name differs from requested package"));
        }

        let manifest = read_package_manifest(&package_root.join("package.json"))?;
        if manifest.get("name").and_then(Value::as_str) != Some(package_name) {
            return Err(anyhow!(
                "authenticated package manifest name differs from its principal"
            ));
        }

        let suffix = specifier
            .strip_prefix(package_name)
            .ok_or_else(|| anyhow!("bound package prefix is absent"))?;
        if !suffix.is_empty() && !suffix.starts_with('/') {
            return Err(anyhow!("invalid package subpath"));
        }
        if suffix
            .split('/')
            .any(|component| component == "." || component == "..")
        {
            return Err(anyhow!("package subpath contains traversal components"));
        }

        // A package with `exports` must go through OXC's PACKAGE_SELF path so
        // private subpaths remain private. Without `exports`, an exact relative
        // request preserves `main`/index and extension behavior without ever
        // starting an ambient node_modules search.
        let anchored_specifier = if manifest
            .get("exports")
            .is_some_and(|value| !value.is_null())
        {
            specifier.to_owned()
        } else if suffix.is_empty() {
            ".".to_owned()
        } else {
            format!(".{suffix}")
        };
        let mut resolved =
            self.resolve_with_oxc_at(&anchored_specifier, package_root, false, kind)?;
        resolved.package_name = Some(package_name.to_owned());
        resolved.package_root = Some(package_root.to_path_buf());
        resolved.package_version = manifest
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Self::validate_import_attributes(resolved, kind, attributes)
    }

    fn resolve_package_import(
        &self,
        specifier: &str,
        referrer: &Path,
        conditions: &ConditionSet,
    ) -> Option<ResolvedModule> {
        let package_root = find_package_root(referrer)?;
        let manifest_path = package_root.join("package.json");
        let manifest = read_package_manifest(&manifest_path).ok()?;
        let imports = manifest.get("imports")?.as_object()?;

        let raw_target = resolve_package_import_target(specifier, imports, conditions)?;
        let target_path = normalize_import_target(&package_root, package_root.join(raw_target))?;

        let (package_name, package_root_from_path) =
            package_name_and_root_in_node_modules(&target_path).unzip();
        let package_root_for_record = package_root_from_path.or_else(|| Some(package_root.clone()));
        let package_version = self.package_version_for(&target_path);
        Some(ResolvedModule {
            artifact_source_id: None,
            id: target_path.to_string_lossy().to_string(),
            kind: module_kind_from_path(&target_path),
            path: Some(target_path),
            source: None,
            package_name,
            package_root: package_root_for_record,
            package_version,
            package_integrity: None,
            source_id: None,
            source_label: None,
            virtual_path: None,
            resolver_path: None,
            resolver_package_root: None,
            private_resolver_path: None,
            private_resolver_package_root: None,
        })
    }

    pub fn load_source(&self, mut module: ResolvedModule) -> Result<ResolvedModule> {
        if module.source.is_some() {
            return Ok(module);
        }
        let path = module
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("Module path missing"))?;
        let (source, lowered) = self.load_module_source(path)?;
        if lowered {
            module.kind = ModuleKind::CommonJs;
        }
        // Discard any resolver prefetch: only the bytes captured by the
        // integrity traversal are eligible for execution.
        module.source = Some(source);
        Ok(module)
    }

    /// Preserve authenticated source bytes for the Oxc module-artifact
    /// producer. Unlike the compatibility loader, this never performs SWC
    /// ESM-to-CommonJS or syntax-scanner-selected lowering.
    pub(crate) fn load_runner_source_bytes(
        &self,
        mut module: ResolvedModule,
        bytes: Vec<u8>,
    ) -> Result<ResolvedModule> {
        let path = module
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("Module path missing"))?;
        module.source =
            Some(String::from_utf8(bytes).with_context(|| {
                format!("Module source is not valid UTF-8: {}", path.display())
            })?);
        Ok(module)
    }

    /// Capture unmodified source bytes for a graph producer. This deliberately
    /// bypasses the compatibility loader's file-at-a-time lowering; callers
    /// must feed the returned bytes through the authenticated artifact producer.
    /// @ref LLP 0026#1-source-admission-and-resolution
    pub fn load_runner_source(&self, mut module: ResolvedModule) -> Result<ResolvedModule> {
        if module.source.is_some() {
            return Ok(module);
        }
        let path = module
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("Module path missing"))?;
        module.source = Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read module {}", path.display()))?,
        );
        Ok(module)
    }

    /// Read and lower a module only after Host has completed the staged
    /// identity/edge authorization. Resolution-only paths never call this.
    fn load_module_source(&self, path: &Path) -> Result<(String, bool)> {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read module {}", path.display()))?;
        let needs_lowering = Self::needs_transpile(path) || Self::needs_js_downlevel(path, &source);
        if needs_lowering {
            let target = Self::transpile_target_for_source(&source);
            return Ok((self.transpile_module(path, target, &source)?, true));
        }
        Ok((source, false))
    }

    /// Compile source bytes that were captured while authenticating the
    /// package tree. Armed package loads must not reopen the pathname after
    /// integrity validation: a replacement in that gap would execute bytes
    /// that never contributed to the authenticated principal digest.
    pub(crate) fn load_source_bytes(
        &self,
        mut module: ResolvedModule,
        bytes: Vec<u8>,
    ) -> Result<ResolvedModule> {
        let path = module
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("Module path missing"))?;
        let source = String::from_utf8(bytes)
            .with_context(|| format!("Module source is not valid UTF-8: {}", path.display()))?;
        let lowered = Self::needs_transpile(path) || Self::needs_js_downlevel(path, &source);
        let source = if lowered {
            let target = Self::transpile_target_for_source(&source);
            self.transpile_module(path, target, &source)?
        } else {
            source
        };
        if lowered {
            module.kind = ModuleKind::CommonJs;
        }
        module.source = Some(source);
        Ok(module)
    }

    fn needs_transpile(path: &Path) -> bool {
        path.extension()
            .and_then(OsStr::to_str)
            .map(|ext| matches!(ext, "ts" | "tsx" | "jsx" | "mts" | "cts"))
            .unwrap_or(false)
    }

    fn needs_js_downlevel(path: &Path, source: &str) -> bool {
        // Runtime bundler outputs are already lowered for Hermes. Re-parsing
        // their script/IIFE wrapper as a module can reject legal top-level
        // `return` statements before the generated entry is ever evaluated.
        let is_runtime_bundle = path.file_name().and_then(OsStr::to_str) == Some("bundle.js")
            || path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.ends_with(".bundle.js"));
        if is_runtime_bundle && !Self::source_needs_downlevel(source) {
            return false;
        }
        path.extension()
            .and_then(OsStr::to_str)
            .map(|ext| matches!(ext, "js" | "mjs" | "cjs"))
            .unwrap_or(false)
            && Self::source_needs_downlevel(source)
    }

    fn source_needs_downlevel(source: &str) -> bool {
        Self::source_needs_async_downlevel(source)
            || Self::source_needs_for_of_scoping_fix(source)
            || Self::source_needs_loop_scope_downlevel(source)
    }

    fn source_needs_async_downlevel(source: &str) -> bool {
        fn contains_using_keyword(source: &str) -> bool {
            let bytes = source.as_bytes();
            let mut offset = 0;
            while let Some(relative) = source[offset..].find("using") {
                let start = offset + relative;
                let end = start + "using".len();
                let is_identifier =
                    |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$';
                let starts_token = start == 0 || !is_identifier(bytes[start - 1]);
                let ends_token = end == bytes.len() || !is_identifier(bytes[end]);
                if starts_token && ends_token {
                    return true;
                }
                offset = end;
            }
            false
        }

        source.contains("async function*")
            || source.contains("async function *")
            || source.contains("async*")
            || source.contains("async *")
            || source.contains("for await")
            || source.contains("await using")
            || contains_using_keyword(source)
    }

    fn scan_block_scoped_loop_closures<F>(source: &str, mut matcher: F) -> bool
    where
        F: FnMut(usize, bool, bool, bool, bool) -> bool,
    {
        fn skip_ws_and_comments(bytes: &[u8], mut idx: usize) -> usize {
            while idx < bytes.len() {
                if bytes[idx].is_ascii_whitespace() {
                    idx += 1;
                    continue;
                }
                if bytes[idx] == b'/' && bytes.get(idx + 1) == Some(&b'/') {
                    idx += 2;
                    while idx < bytes.len() && bytes[idx] != b'\n' {
                        idx += 1;
                    }
                    continue;
                }
                if bytes[idx] == b'/' && bytes.get(idx + 1) == Some(&b'*') {
                    idx += 2;
                    while idx + 1 < bytes.len() && !(bytes[idx] == b'*' && bytes[idx + 1] == b'/') {
                        idx += 1;
                    }
                    idx = (idx + 2).min(bytes.len());
                    continue;
                }
                break;
            }
            idx
        }

        fn scan_balanced_region(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
            let mut depth = 1usize;
            let mut idx = start + 1;
            let mut in_single = false;
            let mut in_double = false;
            let mut in_template = false;
            let mut in_line_comment = false;
            let mut in_block_comment = false;
            let mut escaped = false;

            while idx < bytes.len() {
                let ch = bytes[idx];
                let next = bytes.get(idx + 1).copied();

                if in_line_comment {
                    if ch == b'\n' {
                        in_line_comment = false;
                    }
                    idx += 1;
                    continue;
                }

                if in_block_comment {
                    if ch == b'*' && next == Some(b'/') {
                        in_block_comment = false;
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                    continue;
                }

                if escaped {
                    escaped = false;
                    idx += 1;
                    continue;
                }

                if in_single {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'\'' {
                        in_single = false;
                    }
                    idx += 1;
                    continue;
                }

                if in_double {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'"' {
                        in_double = false;
                    }
                    idx += 1;
                    continue;
                }

                if in_template {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'`' {
                        in_template = false;
                    }
                    idx += 1;
                    continue;
                }

                if ch == b'/' && next == Some(b'/') {
                    in_line_comment = true;
                    idx += 2;
                    continue;
                }

                if ch == b'/' && next == Some(b'*') {
                    in_block_comment = true;
                    idx += 2;
                    continue;
                }

                if ch == b'\'' {
                    in_single = true;
                    idx += 1;
                    continue;
                }

                if ch == b'"' {
                    in_double = true;
                    idx += 1;
                    continue;
                }

                if ch == b'`' {
                    in_template = true;
                    idx += 1;
                    continue;
                }

                if ch == open {
                    depth += 1;
                } else if ch == close {
                    depth -= 1;
                    if depth == 0 {
                        return Some(idx);
                    }
                }

                idx += 1;
            }

            None
        }

        let bytes = source.as_bytes();
        let mut idx = 0;

        while idx + 3 <= bytes.len() {
            if &bytes[idx..idx + 3] != b"for" {
                idx += 1;
                continue;
            }

            if idx > 0 {
                let prev = bytes[idx - 1];
                if prev == b'_' || prev.is_ascii_alphanumeric() {
                    idx += 3;
                    continue;
                }
            }

            let mut cursor = idx + 3;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor >= bytes.len() || bytes[cursor] != b'(' {
                idx += 3;
                continue;
            }

            let mut paren_depth = 1usize;
            let mut header_end = None;
            let mut semicolons = 0usize;
            let mut in_single = false;
            let mut in_double = false;
            let mut in_template = false;
            let mut in_line_comment = false;
            let mut in_block_comment = false;
            let mut escaped = false;
            let mut scan = cursor + 1;

            while scan < bytes.len() {
                let ch = bytes[scan];
                let next = bytes.get(scan + 1).copied();

                if in_line_comment {
                    if ch == b'\n' {
                        in_line_comment = false;
                    }
                    scan += 1;
                    continue;
                }

                if in_block_comment {
                    if ch == b'*' && next == Some(b'/') {
                        in_block_comment = false;
                        scan += 2;
                    } else {
                        scan += 1;
                    }
                    continue;
                }

                if escaped {
                    escaped = false;
                    scan += 1;
                    continue;
                }

                if in_single {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'\'' {
                        in_single = false;
                    }
                    scan += 1;
                    continue;
                }

                if in_double {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'"' {
                        in_double = false;
                    }
                    scan += 1;
                    continue;
                }

                if in_template {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'`' {
                        in_template = false;
                    }
                    scan += 1;
                    continue;
                }

                if ch == b'/' && next == Some(b'/') {
                    in_line_comment = true;
                    scan += 2;
                    continue;
                }

                if ch == b'/' && next == Some(b'*') {
                    in_block_comment = true;
                    scan += 2;
                    continue;
                }

                if ch == b'\'' {
                    in_single = true;
                    scan += 1;
                    continue;
                }

                if ch == b'"' {
                    in_double = true;
                    scan += 1;
                    continue;
                }

                if ch == b'`' {
                    in_template = true;
                    scan += 1;
                    continue;
                }

                if ch == b'(' {
                    paren_depth += 1;
                } else if ch == b')' {
                    paren_depth -= 1;
                    if paren_depth == 0 {
                        header_end = Some(scan);
                        break;
                    }
                } else if ch == b';' && paren_depth == 1 {
                    semicolons += 1;
                }

                scan += 1;
            }

            if let Some(end) = header_end {
                let header = source[cursor + 1..end].trim_start();
                let has_block_scoped_loop_binding = header.starts_with("let ")
                    || header.starts_with("let\t")
                    || header.starts_with("let[")
                    || header.starts_with("let{")
                    || header.starts_with("const ")
                    || header.starts_with("const\t")
                    || header.starts_with("const[")
                    || header.starts_with("const{");

                if has_block_scoped_loop_binding {
                    let body_start = skip_ws_and_comments(bytes, end + 1);
                    let body_end = if body_start < bytes.len() && bytes[body_start] == b'{' {
                        scan_balanced_region(bytes, body_start, b'{', b'}')
                            .map(|idx| idx + 1)
                            .unwrap_or(bytes.len())
                    } else {
                        let mut body_end = body_start;
                        while body_end < bytes.len() && bytes[body_end] != b';' {
                            body_end += 1;
                        }
                        if body_end < bytes.len() {
                            body_end += 1;
                        }
                        body_end
                    };
                    let body = &source[body_start..body_end];
                    let captures_loop_binding = body.contains("=>")
                        || body.contains("function")
                        || body.contains("class ")
                        || body.contains("class\n");
                    let is_for_of = semicolons < 2
                        && (header.contains(" of ")
                            || header.contains(" of\t")
                            || header.contains("\tof "));
                    let is_for_of_or_in = semicolons < 2
                        && (is_for_of
                            || header.contains(" in ")
                            || header.contains(" in\t")
                            || header.contains("\tin "));
                    let has_unsafe_for_of_control_flow = body.contains("continue")
                        || body.contains("break")
                        || body.contains("return");

                    if matcher(
                        semicolons,
                        captures_loop_binding,
                        is_for_of,
                        is_for_of_or_in,
                        has_unsafe_for_of_control_flow,
                    ) {
                        return true;
                    }
                }
                idx = end + 1;
                continue;
            }

            idx = cursor + 1;
        }

        false
    }

    fn source_needs_for_of_scoping_fix(source: &str) -> bool {
        Self::scan_block_scoped_loop_closures(
            source,
            |_, captures_loop_binding, is_for_of, _, _| captures_loop_binding && is_for_of,
        )
    }

    fn source_needs_loop_scope_downlevel(source: &str) -> bool {
        Self::scan_block_scoped_loop_closures(
            source,
            |semicolons,
             captures_loop_binding,
             _,
             is_for_of_or_in,
             has_unsafe_for_of_control_flow| {
                captures_loop_binding
                    && (semicolons >= 2 || (is_for_of_or_in && has_unsafe_for_of_control_flow))
            },
        )
    }

    fn transpile_target_for_source(source: &str) -> &'static str {
        if Self::source_needs_loop_scope_downlevel(source) {
            "es5"
        } else {
            "es2015"
        }
    }

    fn transpile_module(&self, path: &Path, target: &str, source: &str) -> Result<String> {
        if self.transpile_mode == TranspileMode::ArmedFreshInMemory {
            // This branch must precede cache-key and cache-directory selection:
            // an armed loader never resolves, reads, writes, probes, or falls
            // back through persistent transpile storage.
            // @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
            return transpile::transpile_source_to_cjs(
                source,
                path,
                target,
                self.environment.runtime_transform(),
                self.environment.legacy_runtime_transform(),
            );
        }

        let cache_key = module_cache_key(path, target, source, &self.environment)?;
        // Diagnostic cache selection is captured per loader. A cache miss
        // recreates the parent inside `run_transpile_command` before writing.
        let cache_dir = transpile_cache_dir(&self.environment)?;

        let artifact_dir = cache_dir.join(&cache_key);
        for _ in 0..3 {
            if let Some(output) = read_transpile_cache(&artifact_dir, target, source)? {
                touch_transpile_artifact(&artifact_dir);
                return Ok(output);
            }
            publish_transpile_artifact(path, &artifact_dir, target, source, &self.environment)?;
            enforce_transpile_cache_quota(
                &cache_dir,
                &artifact_dir,
                self.environment.transpile_cache_max_bytes,
            );
        }
        anyhow::bail!(
            "Transpile cache artifact {} repeatedly disappeared during publication",
            artifact_dir.display()
        )
    }

    fn resolve_with_oxc(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
    ) -> Result<ResolvedModule> {
        let base_dir = if let Some(path) = referrer {
            let resolved = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(path)
            };

            if resolved.is_dir() {
                resolved
            } else if resolved.is_file() {
                resolved
                    .parent()
                    .map(|parent| parent.to_path_buf())
                    .unwrap_or(resolved)
            } else {
                let is_probably_file = resolved
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| {
                        matches!(
                            ext,
                            "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx" | "mts" | "cts" | "json"
                        )
                    })
                    .unwrap_or(false);
                if is_probably_file {
                    resolved
                        .parent()
                        .map(|parent| parent.to_path_buf())
                        .unwrap_or(resolved)
                } else {
                    resolved
                }
            }
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        };
        #[cfg(windows)]
        let base_dir = {
            let value = base_dir.to_string_lossy();
            PathBuf::from(normalize_windows_verbatim_path_text(&value).as_ref())
        };

        self.resolve_with_oxc_at(specifier, &base_dir, true, kind)
    }

    fn resolve_with_oxc_at(
        &self,
        specifier: &str,
        base_dir: &Path,
        retry_bare_as_relative: bool,
        kind: ResolutionKind,
    ) -> Result<ResolvedModule> {
        let resolver = match kind {
            ResolutionKind::CommonJsRequire => &self.resolver_require,
            ResolutionKind::EsmStatic | ResolutionKind::DynamicImport | ResolutionKind::Entry => {
                &self.resolver_import
            }
        };
        self.resolve_with_resolver_at(resolver, specifier, base_dir, retry_bare_as_relative, None)
    }

    fn resolve_with_resolver_at<Fs: ResolverFileSystem>(
        &self,
        resolver: &ResolverGeneric<Fs>,
        specifier: &str,
        base_dir: &Path,
        retry_bare_as_relative: bool,
        authenticated_inputs: Option<&AuthenticatedResolverInputs>,
    ) -> Result<ResolvedModule> {
        let resolution = match resolver.resolve(base_dir, specifier) {
            Ok(resolution) => resolution,
            Err(err) => {
                // Native hosts pass referrer-relative entry paths without a
                // leading "./" (e.g. "packages/ibex-runtime-js/src/native"),
                // which Node-style resolution treats as bare package
                // specifiers. If the path exists on disk relative to the
                // referrer, retry as an explicit relative specifier so
                // directory imports still land on index.*.
                // @ref LLP 0004#resolution-order
                let path_like = authenticated_inputs.is_none()
                    && retry_bare_as_relative
                    && !specifier.starts_with('.')
                    && !Path::new(specifier).is_absolute()
                    && base_dir.join(specifier).exists();
                if path_like {
                    resolver
                        .resolve(base_dir, &format!("./{specifier}"))
                        .with_context(|| format!("Failed to resolve module {}", specifier))?
                } else {
                    return Err(err)
                        .with_context(|| format!("Failed to resolve module {}", specifier));
                }
            }
        };

        if let Some(inputs) = authenticated_inputs {
            let _ = inputs.normalize_in_boundary(resolution.path())?;
        }

        let full_path = resolution.full_path().to_path_buf();
        // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution —
        // Oxc resolves an ordinary Windows spelling; restore the canonical
        // object identity before authentication and authorization consume it.
        #[cfg(windows)]
        let full_path = full_path.canonicalize().with_context(|| {
            format!(
                "Failed to canonicalize resolved Windows module {}",
                full_path.display()
            )
        })?;
        // Oxc reports addon/Wasm candidates inconsistently across direct-file
        // and package resolution (a direct `.node` file can arrive as
        // CommonJS). The filename is therefore an independent fail-closed
        // guard, including case-folded spellings on case-insensitive targets.
        if let Some(extension) = full_path.extension().and_then(|value| value.to_str()) {
            if extension.eq_ignore_ascii_case("node") {
                anyhow::bail!("Native addons are closed in the CapSec profile");
            }
            if extension.eq_ignore_ascii_case("wasm") {
                anyhow::bail!("WebAssembly modules are closed in the CapSec profile");
            }
        }
        let mut kind = match resolution.module_type() {
            Some(ModuleType::Module) => ModuleKind::Esm,
            Some(ModuleType::CommonJs) => ModuleKind::CommonJs,
            Some(ModuleType::Json) => ModuleKind::Json,
            // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
            // unsupported executable loader kinds refuse before their bytes
            // enter the JavaScript compiler. Treating an addon or Wasm payload
            // as CommonJS lets a text file with a privileged extension execute.
            Some(ModuleType::Wasm) => {
                anyhow::bail!("WebAssembly modules are closed in the CapSec profile")
            }
            Some(ModuleType::Addon) => {
                anyhow::bail!("Native addons are closed in the CapSec profile")
            }
            None => ModuleKind::CommonJs,
        };
        // Explicit Node/TypeScript module extensions are source-goal facts and
        // outrank an absent or inherited package type from the resolver.
        match full_path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("mjs" | "mts") => kind = ModuleKind::Esm,
            Some("cjs" | "cts") => kind = ModuleKind::CommonJs,
            _ => {}
        }
        // Force JSON kind for .json files regardless of what OXC reports,
        // so they get parsed with JSON.parse() instead of new Function().
        if full_path.extension().and_then(|e| e.to_str()) == Some("json") {
            kind = ModuleKind::Json;
        }
        // Metadata-only resolution must never open the module body. Armed
        // callers have completed only the requested stage here; source bytes
        // are read after discovery/commit through `load_source` or supplied by
        // the authenticated package/VFS traversal through `load_source_bytes`.
        // Content-dependent downlevel classification is deferred to that same
        // authorized read so metadata resolution cannot become a read bypass.
        // @ref LLP 0023#21-staged-authorization-identity
        // The compatibility source loader may later lower TypeScript bytes to
        // CommonJS, but metadata-only resolution must preserve `.mts`'s
        // unambiguous Module source goal for authenticated graph producers.
        // @ref LLP 0026#1-source-admission-and-resolution
        let explicit_module_extension = full_path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("mts"));
        if kind == ModuleKind::Esm
            && Self::needs_transpile(&full_path)
            && !explicit_module_extension
        {
            kind = ModuleKind::CommonJs;
        }

        let (mut package_name, mut package_root) =
            package_name_and_root_in_node_modules(&full_path).unzip();
        // `package_version_for` performs an ordinary manifest read and is
        // therefore diagnostic-only. Armed resolution receives version data
        // exclusively from OXC's captured `PackageJson` record below.
        let mut package_version = authenticated_inputs
            .is_none()
            .then(|| self.package_version_for(&full_path))
            .flatten();
        if let Some(pkg) = resolution.package_json() {
            let resolved_package_root = pkg.directory().to_path_buf();
            if package_name.is_none() {
                let requested = package_name_from_bare_specifier(specifier);
                if let Some(requested_name) = requested {
                    if pkg.name() == Some(requested_name.as_str()) {
                        package_name = Some(requested_name);
                    }
                }
                package_root = Some(resolved_package_root.clone());
            }
            if package_root.is_none() {
                package_root = Some(resolved_package_root);
            }
            if package_version.is_none() {
                package_version = pkg.version().map(str::to_string);
            }
        }
        Ok(ResolvedModule {
            artifact_source_id: None,
            id: full_path.to_string_lossy().to_string(),
            kind,
            path: Some(full_path),
            source: None,
            package_name,
            package_root,
            package_version,
            package_integrity: None,
            source_id: None,
            source_label: None,
            virtual_path: None,
            resolver_path: None,
            resolver_package_root: None,
            private_resolver_path: None,
            private_resolver_package_root: None,
        })
    }
}

fn authenticated_resolver_base_dir(
    inputs: &AuthenticatedResolverInputs,
    referrer: Option<&Path>,
    specifier: &str,
    preflighted_requested_path: Option<&Path>,
) -> Result<PathBuf> {
    let Some(referrer) = referrer else {
        #[cfg(windows)]
        return inputs
            .oxc_path(inputs.boundary_root())
            .context("authenticated resolver boundary is not representable for OXC");
        #[cfg(not(windows))]
        return Ok(inputs.boundary_root().to_path_buf());
    };
    let lexical_referrer = lexical_absolute_path_for_resolver(referrer)
        .context("authenticated resolver referrer is not an absolute normalized path")?;
    let referrer = match inputs.normalize_in_boundary(&lexical_referrer) {
        Ok(referrer) => referrer,
        Err(error)
            if error.kind() == io::ErrorKind::PermissionDenied
                && !lexical_referrer.starts_with(inputs.boundary_root()) =>
        {
            let Some(requested_path) = preflighted_requested_path else {
                return Err(error)
                    .context("authenticated resolver referrer is outside its boundary");
            };
            let path_specifier = specifier.starts_with("./")
                || specifier.starts_with("../")
                || Path::new(specifier).is_absolute();
            if !path_specifier {
                return Err(error)
                    .context("authenticated resolver referrer is outside its boundary");
            }
            let requested_path = inputs
                .normalize_in_boundary(requested_path)
                .context("preflighted resolver target is outside its authenticated boundary")?;
            let base_dir = lexical_referrer
                .parent()
                .ok_or_else(|| anyhow!("authenticated resolver referrer has no parent"))?;
            let recomputed = if Path::new(specifier).is_absolute() {
                lexical_absolute_path_for_resolver(Path::new(specifier))
            } else {
                lexical_absolute_path_for_resolver(&base_dir.join(specifier))
            }
            .context("preflighted resolver request is not an absolute normalized path")?;
            let recomputed = inputs
                .normalize_in_boundary(&recomputed)
                .context("preflighted resolver request is outside its authenticated boundary")?;
            anyhow::ensure!(
                recomputed == requested_path,
                "resolver request differs from its preflighted target"
            );
            // @ref LLP 0023#22-authorization-identity-is-caller-relative —
            // the outside caller spelling is inert after exact preflight;
            // every OXC filesystem access remains descriptor-bounded to the
            // authenticated target package below.
            #[cfg(windows)]
            return inputs
                .oxc_path(base_dir)
                .context("authenticated resolver base is not representable for OXC");
            #[cfg(not(windows))]
            return Ok(base_dir.to_path_buf());
        }
        Err(error) => {
            return Err(error).context("authenticated resolver referrer is unavailable");
        }
    };
    let file_system = inputs.file_system();
    let base_dir = match file_system.metadata(&referrer) {
        Ok(metadata) if metadata.is_dir() => referrer,
        Ok(metadata) if metadata.is_file() => referrer
            .parent()
            .ok_or_else(|| anyhow!("authenticated resolver referrer has no parent"))?
            .to_path_buf(),
        Ok(_) => anyhow::bail!("authenticated resolver referrer is not a file or directory"),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && referrer
                    .extension()
                    .and_then(OsStr::to_str)
                    .is_some_and(|extension| {
                        matches!(
                            extension,
                            "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx" | "mts" | "cts" | "json"
                        )
                    }) =>
        {
            // The session lowering frontend intentionally uses a synthetic,
            // nonexistent `.ibex-session-static-import.mjs` referrer. Preserve
            // the historical file-like spelling rule without turning arbitrary
            // NotFound or any boundary refusal into a parent-directory fallback.
            referrer
                .parent()
                .ok_or_else(|| anyhow!("authenticated resolver referrer has no parent"))?
                .to_path_buf()
        }
        Err(error) => return Err(error).context("authenticated resolver referrer is unavailable"),
    };
    let base_dir = file_system
        .canonicalize(&base_dir)
        .context("failed to authenticate resolver base directory")?;
    #[cfg(windows)]
    return inputs
        .oxc_path(&base_dir)
        .context("authenticated resolver base is not representable for OXC");
    #[cfg(not(windows))]
    Ok(base_dir)
}

fn read_package_manifest(path: &Path) -> Result<Value> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read package manifest {}", path.display()))?;
    let manifest: Value = serde_json::from_str(&contents)
        .with_context(|| format!("Invalid package manifest {}", path.display()))?;
    Ok(manifest)
}

/// Hash the complete installed package content tree using the same record
/// format as the policy generator. Nested `node_modules` and VCS metadata are
/// separate graph/store state. Regular files bind their bytes; symlinks bind
/// their raw target spelling so workspace/store layouts remain usable without
/// treating first-party targets as package-owned source.
/// @ref LLP 0021#decision-staging-and-principal-semantics
pub fn package_tree_integrity(root: &Path) -> Result<String> {
    package_tree_integrity_and_source(root, None, None, false, None)
        .map(|(integrity, _, _)| integrity)
}

/// One exact source object observed by the arming-time package integrity walk.
/// The generation is either the platform's stable inode generation or the
/// fixed retained-descriptor marker backed by a live descriptor in the
/// returned inventory.
/// @ref LLP 0023#42-authenticated-package-source-is-immutable
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AuthenticatedPackageObject {
    pub(crate) object: capsec_semantics::model::ObjectIdentity,
    pub(crate) verification_generation: capsec_semantics::model::NonEmptyString,
}

/// Integrity proof and the exact object/generation set produced by the same
/// traversal. Retained descriptors are intentionally opaque to callers; their
/// lifetime is the armed Host lifetime and prevents reuse of an object number
/// on platforms without a reliable generation counter.
/// @ref LLP 0023#42-authenticated-package-source-is-immutable
pub(crate) struct AuthenticatedPackageInventory {
    pub(crate) integrity: String,
    pub(crate) objects: Vec<AuthenticatedPackageObject>,
    #[cfg(unix)]
    pub(crate) retained_descriptors: Vec<std::fs::File>,
}

/// Authenticated binding topology used to decide the defining principal of a
/// symlink target. Paths beneath the most-specific package binding are package
/// source; paths only beneath the project binding remain first-party source.
/// @ref LLP 0023#42-authenticated-package-source-is-immutable
pub(crate) struct AuthenticatedPackageMembership {
    project_root: PathBuf,
    package_roots: Vec<PathBuf>,
}

impl AuthenticatedPackageMembership {
    pub(crate) fn new(project_root: &Path, package_roots: &[PathBuf]) -> Result<Self> {
        let project_root = std::fs::canonicalize(project_root).with_context(|| {
            format!(
                "failed to canonicalize authenticated project root {}",
                project_root.display()
            )
        })?;
        let mut package_roots = package_roots
            .iter()
            .map(|root| {
                std::fs::canonicalize(root).with_context(|| {
                    format!(
                        "failed to canonicalize authenticated package root {}",
                        root.display()
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some(outside) = package_roots
            .iter()
            .find(|root| !root.starts_with(&project_root))
        {
            anyhow::bail!(
                "authenticated package root {} is outside project root {}",
                outside.display(),
                project_root.display()
            );
        }
        package_roots.sort_by_key(|root| std::cmp::Reverse(root.components().count()));
        package_roots.dedup();
        Ok(Self {
            project_root,
            package_roots,
        })
    }

    fn target_is_package_defined(&self, target: &Path) -> Result<bool> {
        if !target.starts_with(&self.project_root) {
            anyhow::bail!(
                "package symlink target {} leaves authenticated project root {}",
                target.display(),
                self.project_root.display()
            );
        }
        Ok(self
            .package_roots
            .iter()
            .any(|root| target.starts_with(root)))
    }
}

pub(crate) fn authenticated_package_inventory(
    root: &Path,
    expected_root: &capsec_semantics::model::ObjectIdentity,
    membership: &AuthenticatedPackageMembership,
) -> Result<AuthenticatedPackageInventory> {
    let (integrity, _, inventory) =
        package_tree_integrity_and_source(root, None, Some(expected_root), true, Some(membership))?;
    let mut inventory = inventory.ok_or_else(|| {
        anyhow!("package integrity traversal did not produce an authenticated object set")
    })?;
    inventory.integrity = integrity;
    Ok(inventory)
}

#[cfg(test)]
type PackageHookTarget = (PathBuf, std::sync::Arc<std::sync::Barrier>);

#[cfg(test)]
type PackageHook = std::sync::OnceLock<std::sync::Mutex<Option<PackageHookTarget>>>;

#[cfg(test)]
static PACKAGE_SOURCE_OPEN_HOOK: PackageHook = std::sync::OnceLock::new();

#[cfg(test)]
static PACKAGE_ROOT_OPEN_HOOK: PackageHook = std::sync::OnceLock::new();

#[cfg(test)]
static PACKAGE_INVENTORY_PASS_HOOK: PackageHook = std::sync::OnceLock::new();

#[cfg(test)]
fn pause_before_authenticated_source_open(path: &Path) {
    let hook = PACKAGE_SOURCE_OPEN_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|hook| hook.as_ref().cloned());
    if let Some((target, barrier)) = hook {
        if target == path {
            barrier.wait();
            barrier.wait();
        }
    }
}

#[cfg(test)]
fn pause_package_hook(hook: &PackageHook, path: &Path) {
    let hook = hook
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|hook| hook.as_ref().cloned());
    if let Some((target, barrier)) = hook {
        if target == path {
            barrier.wait();
            barrier.wait();
        }
    }
}

fn package_tree_integrity_and_source(
    root: &Path,
    source_path: Option<&Path>,
    expected_root: Option<&capsec_semantics::model::ObjectIdentity>,
    capture_inventory: bool,
    membership: Option<&AuthenticatedPackageMembership>,
) -> Result<(
    String,
    Option<Vec<u8>>,
    Option<AuthenticatedPackageInventory>,
)> {
    #[cfg(unix)]
    {
        package_tree_integrity_and_source_unix(
            root,
            source_path,
            expected_root,
            capture_inventory,
            membership,
        )
    }
    #[cfg(windows)]
    {
        let _ = membership;
        if capture_inventory {
            anyhow::bail!(
                "armed package immutability requires an object-generation adapter on this target"
            );
        }
        if expected_root.is_none() {
            let (integrity, source) = package_tree_integrity_and_source_path(root, source_path)?;
            return Ok((integrity, source, None));
        }
        let (integrity, source) =
            package_tree_integrity_and_source_windows(root, source_path, expected_root)?;
        Ok((integrity, source, None))
    }
    #[cfg(not(any(unix, windows)))]
    {
        if capture_inventory {
            anyhow::bail!(
                "armed package immutability requires an object-generation adapter on this target"
            );
        }
        let _ = membership;
        if expected_root.is_some() {
            anyhow::bail!("armed package source authentication is unavailable on this target");
        }
        let (integrity, source) = package_tree_integrity_and_source_path(root, source_path)?;
        Ok((integrity, source, None))
    }
}

#[cfg(unix)]
fn package_tree_integrity_and_source_unix(
    root: &Path,
    source_path: Option<&Path>,
    expected_root: Option<&capsec_semantics::model::ObjectIdentity>,
    capture_inventory: bool,
    membership: Option<&AuthenticatedPackageMembership>,
) -> Result<(
    String,
    Option<Vec<u8>>,
    Option<AuthenticatedPackageInventory>,
)> {
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DirectoryStamp {
        device: u64,
        inode: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    fn stamp(metadata: &std::fs::Metadata) -> DirectoryStamp {
        DirectoryStamp {
            device: metadata.dev(),
            inode: metadata.ino(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    fn object_identity(
        metadata: &std::fs::Metadata,
    ) -> Result<capsec_semantics::model::ObjectIdentity> {
        use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
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
            volume: NonEmptyString::new(format!("dev:{}", metadata.dev()))
                .map_err(anyhow::Error::msg)?,
            file: NonEmptyString::new(format!("ino:{}", metadata.ino()))
                .map_err(anyhow::Error::msg)?,
        })
    }

    fn verification_generation(fd: RawFd) -> Result<capsec_semantics::model::NonEmptyString> {
        use capsec_semantics::model::NonEmptyString;

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        {
            let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("reading package object generation");
            }
            let status = unsafe { status.assume_init() };
            // Apple documents st_gen as super-user-only. Unprivileged armed
            // execution commonly observes zero, which is not a generation.
            // In that case the Host-lifetime retained descriptor prevents the
            // dev/inode pair from being recycled beneath the exact guard.
            // @ref LLP 0023#42-authenticated-package-source-is-immutable
            if status.st_gen != 0 {
                return NonEmptyString::new(format!("apple-st-gen:{}", status.st_gen))
                    .map_err(anyhow::Error::msg);
            }
            NonEmptyString::new("retained-descriptor-v1").map_err(anyhow::Error::msg)
        }

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        {
            let _ = fd;
            NonEmptyString::new("retained-descriptor-v1").map_err(anyhow::Error::msg)
        }
    }

    fn directory_names(fd: RawFd) -> Result<Vec<Vec<u8>>> {
        let dot = b".\0";
        let enumeration_fd = unsafe {
            libc::openat(
                fd,
                dot.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if enumeration_fd < 0 {
            return Err(std::io::Error::last_os_error()).context("opening package directory");
        }
        let directory = unsafe { libc::fdopendir(enumeration_fd) };
        if directory.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(enumeration_fd) };
            return Err(error).context("enumerating package directory");
        }
        let mut names = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if matches!(name, b"." | b".." | b"node_modules" | b".git") {
                continue;
            }
            names.push(name.to_vec());
        }
        unsafe { libc::closedir(directory) };
        names.sort();
        Ok(names)
    }

    fn open_entry_no_follow(directory_fd: RawFd, name: &CString) -> Result<std::fs::File> {
        let fd = unsafe {
            libc::openat(
                directory_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd >= 0 {
            return Ok(unsafe { std::fs::File::from_raw_fd(fd) });
        }
        let ordinary_error = std::io::Error::last_os_error();
        if ordinary_error.raw_os_error() != Some(libc::ELOOP) {
            return Err(ordinary_error).context("opening package entry without following it");
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        let link_flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        // O_SYMLINK is itself the Apple no-follow contract for opening the
        // link object. Combining it with O_NOFOLLOW makes openat reject the
        // symlink with ELOOP instead of returning its descriptor.
        let link_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK;
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos"
        )))]
        {
            return Err(ordinary_error)
                .context("this target cannot retain a no-follow package symlink handle");
        }

        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos"
        ))]
        {
            let link_fd = unsafe { libc::openat(directory_fd, name.as_ptr(), link_flags) };
            if link_fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("opening package symlink object without following it");
            }
            Ok(unsafe { std::fs::File::from_raw_fd(link_fd) })
        }
    }

    fn read_link_at(directory_fd: RawFd, name: &CString) -> Result<Vec<u8>> {
        let mut capacity = 256usize;
        loop {
            let mut bytes = vec![0u8; capacity];
            let length = unsafe {
                libc::readlinkat(
                    directory_fd,
                    name.as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if length < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("reading package symlink target");
            }
            let length = usize::try_from(length).context("invalid package symlink length")?;
            if length < bytes.len() {
                bytes.truncate(length);
                return Ok(bytes);
            }
            capacity = capacity
                .checked_mul(2)
                .filter(|capacity| *capacity <= 1024 * 1024)
                .ok_or_else(|| anyhow!("package symlink target exceeds the fixed size bound"))?;
        }
    }

    fn stable_path_link(path: &Path) -> Result<(Vec<u8>, std::fs::Metadata)> {
        let before = std::fs::symlink_metadata(path)
            .with_context(|| format!("inspecting package symlink {}", path.display()))?;
        if !before.file_type().is_symlink() {
            anyhow::bail!("package symlink changed while resolving {}", path.display());
        }
        let first = std::fs::read_link(path)
            .with_context(|| format!("reading package symlink {}", path.display()))?;
        let after = std::fs::symlink_metadata(path)
            .with_context(|| format!("revalidating package symlink {}", path.display()))?;
        let second = std::fs::read_link(path)
            .with_context(|| format!("re-reading package symlink {}", path.display()))?;
        if stamp(&before) != stamp(&after)
            || object_identity(&before)? != object_identity(&after)?
            || first != second
        {
            anyhow::bail!("package symlink changed while resolving {}", path.display());
        }
        Ok((first.as_os_str().as_bytes().to_vec(), after))
    }

    fn normalize_absolute(path: &Path) -> Result<PathBuf> {
        if !path.is_absolute() {
            anyhow::bail!("package symlink resolution requires an absolute path");
        }
        let mut normalized = PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
        for component in path.components() {
            match component {
                std::path::Component::RootDir | std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                std::path::Component::Normal(component) => normalized.push(component),
                std::path::Component::Prefix(_) => {
                    anyhow::bail!("unexpected prefix in Unix package symlink")
                }
            }
        }
        Ok(normalized)
    }

    struct ResolvedPackageLink {
        path: PathBuf,
        metadata: Option<std::fs::Metadata>,
    }

    /// Resolve a link with Ibex's fixed 32-expansion bound instead of relying
    /// on a platform-dependent `realpath(3)` limit. Every encountered link is
    /// bracketed by identity/target checks and repeated objects are refused.
    fn resolve_package_link(
        link_path: &Path,
        target: &[u8],
        link_metadata: &std::fs::Metadata,
    ) -> Result<ResolvedPackageLink> {
        const MAX_SYMLINK_EXPANSIONS: usize = 32;

        let target = PathBuf::from(std::ffi::OsString::from_vec(target.to_vec()));
        let mut candidate = if target.is_absolute() {
            target
        } else {
            link_path
                .parent()
                .ok_or_else(|| anyhow!("package symlink has no parent"))?
                .join(target)
        };
        let mut expansions = 1usize;
        let mut visited = std::collections::BTreeSet::new();
        visited.insert(object_identity(link_metadata)?);

        loop {
            candidate = normalize_absolute(&candidate)?;
            let components = candidate
                .components()
                .filter_map(|component| match component {
                    std::path::Component::Normal(component) => Some(component.to_os_string()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let mut prefix = PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
            let mut expanded = false;
            for (index, component) in components.iter().enumerate() {
                prefix.push(component);
                let metadata = match std::fs::symlink_metadata(&prefix) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(ResolvedPackageLink {
                            path: candidate,
                            metadata: None,
                        });
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("resolving package symlink target {}", prefix.display())
                        });
                    }
                };
                if !metadata.file_type().is_symlink() {
                    continue;
                }
                if expansions >= MAX_SYMLINK_EXPANSIONS {
                    anyhow::bail!(
                        "package symlink target exceeds the fixed {MAX_SYMLINK_EXPANSIONS}-expansion bound"
                    );
                }
                let (nested_target, stable_metadata) = stable_path_link(&prefix)?;
                if !visited.insert(object_identity(&stable_metadata)?) {
                    anyhow::bail!("package symlink cycle detected at {}", prefix.display());
                }
                expansions += 1;
                let nested_target = PathBuf::from(std::ffi::OsString::from_vec(nested_target));
                let mut replacement = if nested_target.is_absolute() {
                    nested_target
                } else {
                    prefix
                        .parent()
                        .ok_or_else(|| anyhow!("package symlink has no parent"))?
                        .join(nested_target)
                };
                for remaining in &components[index + 1..] {
                    replacement.push(remaining);
                }
                candidate = replacement;
                expanded = true;
                break;
            }
            if expanded {
                continue;
            }
            let metadata = match std::fs::symlink_metadata(&candidate) {
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("inspecting package symlink target {}", candidate.display())
                    });
                }
            };
            return Ok(ResolvedPackageLink {
                path: candidate,
                metadata,
            });
        }
    }

    fn open_path_no_follow(path: &Path) -> Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options
            .open(path)
            .with_context(|| format!("opening resolved package object {}", path.display()))
    }

    #[derive(Default)]
    struct AuthenticatedPackageTreePass {
        records: Vec<(String, String)>,
        captured_source: Option<Vec<u8>>,
        objects: std::collections::BTreeSet<AuthenticatedPackageObject>,
        retained_descriptors: Vec<std::fs::File>,
    }

    struct AuthenticatedPackageTreeWalk<'a> {
        root: &'a Path,
        source_relative: Option<&'a Path>,
        capture_source: bool,
        capture_inventory: bool,
        membership: Option<&'a AuthenticatedPackageMembership>,
        pass: &'a mut AuthenticatedPackageTreePass,
    }

    fn retain_authenticated_object(
        opened: &std::fs::File,
        metadata: &std::fs::Metadata,
        display_path: &Path,
        pass: &mut AuthenticatedPackageTreePass,
    ) -> Result<()> {
        let generation = verification_generation(opened.as_raw_fd())?;
        let authenticated = AuthenticatedPackageObject {
            object: object_identity(metadata)?,
            verification_generation: generation,
        };
        if pass.objects.insert(authenticated) {
            pass.retained_descriptors
                .push(opened.try_clone().with_context(|| {
                    format!(
                        "retaining authenticated package object {}",
                        display_path.display()
                    )
                })?);
        }
        Ok(())
    }

    fn walk_authenticated_package_tree(
        context: &mut AuthenticatedPackageTreeWalk<'_>,
        directory_fd: RawFd,
        relative_directory: &Path,
    ) -> Result<()> {
        let before_fd = unsafe { libc::dup(directory_fd) };
        if before_fd < 0 {
            return Err(std::io::Error::last_os_error()).context("pinning package directory");
        }
        let before = unsafe { std::fs::File::from_raw_fd(before_fd) };
        let before_stamp = stamp(&before.metadata()?);
        drop(before);
        let names = directory_names(directory_fd)?;
        for name in names {
            let relative_path = relative_directory.join(std::ffi::OsString::from_vec(name.clone()));
            let capture = context.capture_source
                && context
                    .source_relative
                    .is_some_and(|source| source == relative_path);
            #[cfg(test)]
            if capture {
                pause_before_authenticated_source_open(&context.root.join(&relative_path));
            }
            let c_name = CString::new(name.clone())?;
            let mut opened = open_entry_no_follow(directory_fd, &c_name).with_context(|| {
                format!(
                    "package entry changed while opening {}",
                    context
                        .root
                        .join(relative_directory)
                        .join(std::ffi::OsString::from_vec(name.clone()))
                        .display()
                )
            })?;
            let metadata_before = opened.metadata()?;
            let relative = relative_path
                .to_str()
                .ok_or_else(|| {
                    anyhow!(
                        "Package path is not valid UTF-8: {}",
                        relative_path.display()
                    )
                })?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if metadata_before.is_dir() {
                walk_authenticated_package_tree(context, opened.as_raw_fd(), &relative_path)?;
            } else if metadata_before.is_file() {
                let generation_before = verification_generation(opened.as_raw_fd())?;
                let mut digest = Sha256::new();
                let mut bytes = capture.then(Vec::new);
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let read = opened.read(&mut buffer).with_context(|| {
                        format!("Failed to read package file {}", relative_path.display())
                    })?;
                    if read == 0 {
                        break;
                    }
                    digest.update(&buffer[..read]);
                    if let Some(captured) = bytes.as_mut() {
                        captured.extend_from_slice(&buffer[..read]);
                    }
                }
                let metadata_after = opened.metadata()?;
                let generation_after = verification_generation(opened.as_raw_fd())?;
                if stamp(&metadata_before) != stamp(&metadata_after)
                    || metadata_before.len() != metadata_after.len()
                    || generation_before != generation_after
                {
                    return Err(anyhow!(
                        "Package file changed while authenticating {}",
                        relative_path.display()
                    ));
                }
                if let Some(bytes) = bytes {
                    if context.pass.captured_source.replace(bytes).is_some() {
                        return Err(anyhow!("Package source appeared more than once"));
                    }
                }
                context.pass.records.push((
                    relative,
                    format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize())),
                ));
                if context.capture_inventory {
                    retain_authenticated_object(
                        &opened,
                        &metadata_after,
                        &context.root.join(&relative_path),
                        context.pass,
                    )?;
                }
            } else if metadata_before.file_type().is_symlink() {
                let target_before = read_link_at(directory_fd, &c_name)?;
                let reopened = open_entry_no_follow(directory_fd, &c_name)?;
                let metadata_after = reopened.metadata()?;
                let target_after = read_link_at(directory_fd, &c_name)?;
                if !metadata_after.file_type().is_symlink()
                    || stamp(&metadata_before) != stamp(&metadata_after)
                    || object_identity(&metadata_before)? != object_identity(&metadata_after)?
                    || target_before != target_after
                {
                    return Err(anyhow!(
                        "Package symlink changed while authenticating {}",
                        relative_path.display()
                    ));
                }
                context.pass.records.push((
                    relative,
                    format!(
                        "symlink-sha256-{}",
                        URL_SAFE_NO_PAD.encode(Sha256::digest(&target_before))
                    ),
                ));

                if context.capture_inventory {
                    retain_authenticated_object(
                        &opened,
                        &metadata_before,
                        &context.root.join(&relative_path),
                        context.pass,
                    )?;
                }

                if capture || context.capture_inventory {
                    let absolute_link = context.root.join(&relative_path);
                    let resolved =
                        resolve_package_link(&absolute_link, &target_before, &metadata_before)?;
                    if capture {
                        if !resolved.path.starts_with(context.root) {
                            anyhow::bail!(
                                "authenticated package source symlink leaves its defining package: {}",
                                absolute_link.display()
                            );
                        }
                        let mut target = open_path_no_follow(&resolved.path)?;
                        let target_before_metadata = target.metadata()?;
                        if !target_before_metadata.is_file() {
                            anyhow::bail!(
                                "authenticated package source symlink does not resolve to a file: {}",
                                absolute_link.display()
                            );
                        }
                        let mut bytes = Vec::new();
                        target.read_to_end(&mut bytes).with_context(|| {
                            format!(
                                "reading authenticated package source {}",
                                resolved.path.display()
                            )
                        })?;
                        let target_after_metadata = target.metadata()?;
                        let revalidated =
                            resolve_package_link(&absolute_link, &target_after, &metadata_after)?;
                        if resolved.path != revalidated.path
                            || stamp(&target_before_metadata) != stamp(&target_after_metadata)
                            || object_identity(&target_before_metadata)?
                                != object_identity(&target_after_metadata)?
                            || revalidated.metadata.as_ref().is_none_or(|metadata| {
                                object_identity(metadata).ok()
                                    != object_identity(&target_after_metadata).ok()
                            })
                        {
                            anyhow::bail!(
                                "authenticated package source symlink changed while reading {}",
                                absolute_link.display()
                            );
                        }
                        if context.pass.captured_source.replace(bytes).is_some() {
                            return Err(anyhow!("Package source appeared more than once"));
                        }
                    }

                    if context.capture_inventory {
                        let membership = context.membership.ok_or_else(|| {
                            anyhow!("package inventory lacks authenticated binding membership")
                        })?;
                        let package_defined =
                            membership.target_is_package_defined(&resolved.path)?;
                        if package_defined {
                            if let Some(metadata) = resolved
                                .metadata
                                .as_ref()
                                .filter(|metadata| metadata.is_file())
                            {
                                let target = open_path_no_follow(&resolved.path)?;
                                let opened_metadata = target.metadata()?;
                                if stamp(metadata) != stamp(&opened_metadata)
                                    || object_identity(metadata)?
                                        != object_identity(&opened_metadata)?
                                {
                                    anyhow::bail!(
                                        "package symlink target changed while authenticating {}",
                                        resolved.path.display()
                                    );
                                }
                                retain_authenticated_object(
                                    &target,
                                    &opened_metadata,
                                    &resolved.path,
                                    context.pass,
                                )?;
                            }
                        }
                    }
                }
            } else {
                return Err(anyhow!(
                    "Package content contains an unsupported file type: {relative}"
                ));
            }
        }
        let after_metadata = unsafe {
            let duplicate = libc::dup(directory_fd);
            if duplicate < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("revalidating package directory");
            }
            std::fs::File::from_raw_fd(duplicate)
        }
        .metadata()?;
        if stamp(&after_metadata) != before_stamp {
            return Err(anyhow!(
                "Package directory changed while authenticating {}",
                context.root.join(relative_directory).display()
            ));
        }
        Ok(())
    }

    let root = std::fs::canonicalize(root)
        .with_context(|| format!("Failed to canonicalize package root {}", root.display()))?;
    if capture_inventory {
        let membership = membership
            .ok_or_else(|| anyhow!("package inventory lacks authenticated binding membership"))?;
        if !membership.target_is_package_defined(&root)? {
            anyhow::bail!(
                "package inventory root {} is not owned by an authenticated package binding",
                root.display()
            );
        }
    }
    let source_relative = source_path
        .map(|source| {
            let normalized = match (source.parent(), source.file_name()) {
                (Some(parent), Some(name)) => std::fs::canonicalize(parent)
                    .map(|parent| parent.join(name))
                    .with_context(|| {
                        format!("Failed to authenticate module parent {}", parent.display())
                    })?,
                _ => source.to_path_buf(),
            };
            normalized
                .strip_prefix(&root)
                .map(Path::to_path_buf)
                .with_context(|| {
                    format!(
                        "Authenticated module source {} is outside package root {}",
                        source.display(),
                        root.display()
                    )
                })
        })
        .transpose()?;
    if source_relative.as_ref().is_some_and(|path| {
        path.components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    }) {
        return Err(anyhow!(
            "Authenticated package source is not a relative file path"
        ));
    }

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
    #[cfg(test)]
    pause_package_hook(&PACKAGE_ROOT_OPEN_HOOK, &root);
    let root_handle = options
        .open(&root)
        .with_context(|| format!("Failed to pin package root {}", root.display()))?;
    let root_metadata = root_handle.metadata()?;
    if let Some(expected) = expected_root {
        if object_identity(&root_metadata)? != *expected {
            return Err(anyhow!(
                "Authenticated package root object changed before traversal: {}",
                root.display()
            ));
        }
    }

    let inventory = |capture_source: bool,
                     capture_inventory: bool|
     -> Result<AuthenticatedPackageTreePass> {
        let mut pass = AuthenticatedPackageTreePass::default();
        {
            let mut context = AuthenticatedPackageTreeWalk {
                root: &root,
                source_relative: source_relative.as_deref(),
                capture_source,
                capture_inventory,
                membership,
                pass: &mut pass,
            };
            walk_authenticated_package_tree(&mut context, root_handle.as_raw_fd(), Path::new(""))?;
        }
        pass.records
            .sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        Ok(pass)
    };
    let first = inventory(false, false)?.records;
    #[cfg(test)]
    pause_package_hook(&PACKAGE_INVENTORY_PASS_HOOK, &root);
    let AuthenticatedPackageTreePass {
        records: second,
        captured_source,
        objects,
        retained_descriptors,
    } = inventory(source_relative.is_some(), capture_inventory)?;
    if first != second {
        return Err(anyhow!(
            "Package content changed between authenticated inventory passes"
        ));
    }
    if source_relative.is_some() && captured_source.is_none() {
        return Err(anyhow!(
            "Authenticated module source disappeared during package traversal"
        ));
    }
    let bytes = serde_json::to_vec(&second)?;
    let integrity = format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)));
    let inventory = capture_inventory.then(|| AuthenticatedPackageInventory {
        integrity: integrity.clone(),
        objects: objects.into_iter().collect(),
        retained_descriptors,
    });
    Ok((integrity, captured_source, inventory))
}

#[cfg(windows)]
fn package_tree_integrity_and_source_windows(
    root: &Path,
    source_path: Option<&Path>,
    expected_root: Option<&capsec_semantics::model::ObjectIdentity>,
) -> Result<(String, Option<Vec<u8>>)> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::{null, null_mut};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        NtCreateFile, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ObjectStamp {
        object: capsec_semantics::model::ObjectIdentity,
        attributes: u32,
        creation_time: u64,
        last_write_time: u64,
        length: u64,
    }

    fn stamp(file: &std::fs::File) -> Result<ObjectStamp> {
        let metadata = file.metadata()?;
        Ok(ObjectStamp {
            object: crate::host::object_identity_for_open_file(file)?,
            attributes: metadata.file_attributes(),
            creation_time: metadata.creation_time(),
            last_write_time: metadata.last_write_time(),
            length: metadata.file_size(),
        })
    }

    fn open_relative(
        parent: &std::fs::File,
        name: &OsStr,
        directory: bool,
    ) -> Result<std::fs::File> {
        let name_text = name
            .to_str()
            .ok_or_else(|| anyhow!("Package path component is not Unicode"))?;
        if !crate::vfs::windows_component_is_alias_safe(name_text) {
            return Err(anyhow!(
                "Package path component is outside the bound Windows alias contract"
            ));
        }
        let mut wide = name.encode_wide().collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(anyhow!("Package path contains a NUL component"));
        }
        let byte_length = wide
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(|| anyhow!("Package path component is too long"))?;
        let name = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: wide.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.as_raw_handle(),
            ObjectName: &name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let mut handle: HANDLE = INVALID_HANDLE_VALUE;
        let mut io_status = IO_STATUS_BLOCK::default();
        let desired_access = FILE_READ_ATTRIBUTES
            | SYNCHRONIZE
            | if directory {
                FILE_LIST_DIRECTORY | FILE_TRAVERSE
            } else {
                FILE_READ_DATA
            };
        let create_options = FILE_OPEN_REPARSE_POINT
            | FILE_SYNCHRONOUS_IO_NONALERT
            | if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            };
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &attributes,
                &mut io_status,
                null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                create_options,
                null_mut(),
                0,
            )
        };
        if status < 0 || handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(anyhow!(
                "package entry changed while opening it relative to its authenticated parent (NTSTATUS {status:#010x})"
            ));
        }
        Ok(unsafe { std::fs::File::from_raw_handle(handle) })
    }

    fn directory_entries(path: &Path) -> Result<Vec<(std::ffi::OsString, bool)>> {
        // `ReadDir` supplies names only. Every named object is opened against
        // the retained parent handle below; a path swap can therefore only
        // make a name fail to open or change the two-pass/expected integrity
        // inventory, never redirect the bytes or object metadata we accept.
        let mut entries = std::fs::read_dir(path)
            .with_context(|| format!("Failed to enumerate package directory {}", path.display()))?
            .map(|entry| {
                entry.and_then(|entry| {
                    let directory = entry.file_type()?.is_dir();
                    Ok((entry.file_name(), directory))
                })
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        entries
            .retain(|(name, _)| name != OsStr::new("node_modules") && name != OsStr::new(".git"));
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(entries)
    }

    fn walk(
        root: &Path,
        directory: &std::fs::File,
        relative_directory: &Path,
        source_relative: Option<&Path>,
        capture_source: bool,
        records: &mut Vec<(String, String)>,
        captured_source: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        crate::vfs::windows_require_casefold_directory(directory)?;
        let before = stamp(directory)?;
        let entries = directory_entries(&root.join(relative_directory))?;
        for (name, directory_entry) in entries {
            let relative_path = relative_directory.join(&name);
            let capture =
                capture_source && source_relative.is_some_and(|source| source == relative_path);
            #[cfg(test)]
            if capture {
                pause_before_authenticated_source_open(&root.join(&relative_path));
            }
            let mut opened =
                open_relative(directory, &name, directory_entry).with_context(|| {
                    format!(
                        "package entry changed while opening {}",
                        root.join(&relative_path).display()
                    )
                })?;
            let metadata = opened.metadata()?;
            let relative = relative_path
                .to_str()
                .ok_or_else(|| {
                    anyhow!(
                        "Package path is not valid UTF-8: {}",
                        relative_path.display()
                    )
                })?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(anyhow!(
                    "Package content contains an unauthenticated reparse point: {relative}"
                ));
            }
            if metadata.is_dir() {
                walk(
                    root,
                    &opened,
                    &relative_path,
                    source_relative,
                    capture_source,
                    records,
                    captured_source,
                )?;
            } else if metadata.is_file() {
                let before_file = stamp(&opened)?;
                let mut digest = Sha256::new();
                let mut bytes = capture.then(Vec::new);
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let read = opened.read(&mut buffer).with_context(|| {
                        format!("Failed to read package file {}", relative_path.display())
                    })?;
                    if read == 0 {
                        break;
                    }
                    digest.update(&buffer[..read]);
                    if let Some(captured) = bytes.as_mut() {
                        captured.extend_from_slice(&buffer[..read]);
                    }
                }
                if stamp(&opened)? != before_file {
                    return Err(anyhow!(
                        "Package file changed while authenticating {}",
                        relative_path.display()
                    ));
                }
                if let Some(bytes) = bytes {
                    if captured_source.replace(bytes).is_some() {
                        return Err(anyhow!("Package source appeared more than once"));
                    }
                }
                records.push((
                    relative,
                    format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize())),
                ));
            } else {
                return Err(anyhow!(
                    "Package content contains an unsupported file type: {relative}"
                ));
            }
        }
        if stamp(directory)? != before {
            return Err(anyhow!(
                "Package directory changed while authenticating {}",
                root.join(relative_directory).display()
            ));
        }
        Ok(())
    }

    let root = std::fs::canonicalize(root)
        .with_context(|| format!("Failed to canonicalize package root {}", root.display()))?;
    let source_relative = source_path
        .map(|source| {
            let normalized = match (source.parent(), source.file_name()) {
                (Some(parent), Some(name)) => std::fs::canonicalize(parent)
                    .map(|parent| parent.join(name))
                    .with_context(|| {
                        format!("Failed to authenticate module parent {}", parent.display())
                    })?,
                _ => source.to_path_buf(),
            };
            normalized
                .strip_prefix(&root)
                .map(Path::to_path_buf)
                .with_context(|| {
                    format!(
                        "Authenticated module source {} is outside package root {}",
                        source.display(),
                        root.display()
                    )
                })
        })
        .transpose()?;
    if source_relative.as_ref().is_some_and(|path| {
        path.components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    }) {
        return Err(anyhow!(
            "Authenticated package source is not a relative file path"
        ));
    }

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    #[cfg(test)]
    pause_package_hook(&PACKAGE_ROOT_OPEN_HOOK, &root);
    let root_handle = options
        .open(&root)
        .with_context(|| format!("Failed to pin package root {}", root.display()))?;
    let root_metadata = root_handle.metadata()?;
    if !root_metadata.is_dir()
        || root_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(anyhow!(
            "Authenticated package root is not a regular directory: {}",
            root.display()
        ));
    }
    crate::vfs::windows_require_casefold_directory(&root_handle)?;
    if let Some(expected) = expected_root {
        if crate::host::object_identity_for_open_file(&root_handle)? != *expected {
            return Err(anyhow!(
                "Authenticated package root object changed before traversal: {}",
                root.display()
            ));
        }
    }

    // @ref LLP 0021#module-initialization-and-trusted-source-acquisition — package bytes are inventoried twice and opened relative to the authenticated root handle without following reparse points.
    let inventory = |capture_source: bool| -> Result<(Vec<(String, String)>, Option<Vec<u8>>)> {
        let mut records = Vec::new();
        let mut captured = None;
        walk(
            &root,
            &root_handle,
            Path::new(""),
            source_relative.as_deref(),
            capture_source,
            &mut records,
            &mut captured,
        )?;
        records.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        Ok((records, captured))
    };
    let (first, _) = inventory(false)?;
    #[cfg(test)]
    pause_package_hook(&PACKAGE_INVENTORY_PASS_HOOK, &root);
    let (second, captured_source) = inventory(source_relative.is_some())?;
    if first != second {
        return Err(anyhow!(
            "Package content changed between authenticated inventory passes"
        ));
    }
    if source_relative.is_some() && captured_source.is_none() {
        return Err(anyhow!(
            "Authenticated module source disappeared during package traversal"
        ));
    }
    let bytes = serde_json::to_vec(&second)?;
    Ok((
        format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))),
        captured_source,
    ))
}

/// Authenticate the complete package tree and optionally retain the exact
/// bytes of one source file from the same pinned file handle that contributed
/// its digest record.
#[cfg(not(unix))]
fn package_tree_integrity_and_source_path(
    root: &Path,
    source_path: Option<&Path>,
) -> Result<(String, Option<Vec<u8>>)> {
    fn digest_file(path: &Path, capture: bool) -> Result<(String, Option<Vec<u8>>)> {
        #[cfg(test)]
        if capture {
            pause_before_authenticated_source_open(path);
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_FLAG_OPEN_REPARSE_POINT: inspect the named object rather
            // than following a late replacement to an unauthenticated target.
            options.custom_flags(0x0020_0000);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("Failed to open package file {}", path.display()))?;
        if !file.metadata()?.is_file() {
            return Err(anyhow!(
                "Package content changed to a non-file while authenticating {}",
                path.display()
            ));
        }
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut captured = capture.then(Vec::new);
        loop {
            let read = file
                .read(&mut buffer)
                .with_context(|| format!("Failed to read package file {}", path.display()))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
            if let Some(bytes) = captured.as_mut() {
                bytes.extend_from_slice(&buffer[..read]);
            }
        }
        Ok((
            format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize())),
            captured,
        ))
    }

    fn walk_package_tree_by_path(
        root: &Path,
        current: &Path,
        source_relative: Option<&Path>,
        records: &mut Vec<(String, String)>,
        captured_source: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        let mut entries = std::fs::read_dir(current)
            .with_context(|| {
                format!(
                    "Failed to enumerate package directory {}",
                    current.display()
                )
            })?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry.file_name();
            if name == OsStr::new("node_modules") || name == OsStr::new(".git") {
                continue;
            }
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            let relative_path = path
                .strip_prefix(root)
                .expect("walk stays below package root");
            let relative = relative_path
                .to_str()
                .ok_or_else(|| {
                    anyhow!(
                        "Package path is not valid UTF-8: {}",
                        relative_path.display()
                    )
                })?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "Package content contains an unauthenticated symlink: {relative}"
                ));
            }
            if metadata.is_dir() {
                walk_package_tree_by_path(root, &path, source_relative, records, captured_source)?;
            } else if metadata.is_file() {
                let capture = source_relative.is_some_and(|source| source == relative_path);
                let (digest, bytes) = digest_file(&path, capture)?;
                if let Some(bytes) = bytes {
                    if captured_source.replace(bytes).is_some() {
                        return Err(anyhow!("Package source appeared more than once"));
                    }
                }
                records.push((relative, digest));
            } else {
                return Err(anyhow!(
                    "Package content contains an unsupported file type: {relative}"
                ));
            }
        }
        Ok(())
    }

    let root = std::fs::canonicalize(root)
        .with_context(|| format!("Failed to canonicalize package root {}", root.display()))?;
    let source_relative = source_path
        .map(|source| {
            let normalized = match (source.parent(), source.file_name()) {
                (Some(parent), Some(name)) => std::fs::canonicalize(parent)
                    .map(|parent| parent.join(name))
                    .with_context(|| {
                        format!("Failed to authenticate module parent {}", parent.display())
                    })?,
                _ => source.to_path_buf(),
            };
            normalized
                .strip_prefix(&root)
                .map(Path::to_path_buf)
                .with_context(|| {
                    format!(
                        "Authenticated module source {} is outside package root {}",
                        source.display(),
                        root.display()
                    )
                })
        })
        .transpose()?;
    let mut records = Vec::new();
    let mut captured_source = None;
    walk_package_tree_by_path(
        &root,
        &root,
        source_relative.as_deref(),
        &mut records,
        &mut captured_source,
    )?;
    if source_relative.is_some() && captured_source.is_none() {
        return Err(anyhow!(
            "Authenticated module source disappeared during package traversal"
        ));
    }
    records.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let bytes = serde_json::to_vec(&records)?;
    Ok((
        format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))),
        captured_source,
    ))
}

pub(crate) fn authenticated_package_source(
    root: &Path,
    source_path: &Path,
    expected_integrity: &str,
    expected_root: &capsec_semantics::model::ObjectIdentity,
) -> Result<Vec<u8>> {
    let (actual, source, _) = package_tree_integrity_and_source(
        root,
        Some(source_path),
        Some(expected_root),
        false,
        None,
    )?;
    if actual != expected_integrity {
        return Err(anyhow!(
            "Installed package content changed after arming: expected {expected_integrity}, observed {actual}"
        ));
    }
    source.ok_or_else(|| anyhow!("Authenticated package source is absent"))
}

/// The installed package root for a module path: the `node_modules/<name>`
/// prefix (two segments for an `@scope/name`), using the LAST `node_modules`
/// segment so nested and pnpm layouts resolve to the package that actually owns
/// the file. Returns `None` for first-party code (no `node_modules` ancestor).
/// Mirrors the loader's `packageNameFromPath` so the version manifest agrees
/// with the derived package name. (ENG-22621)
fn package_root_in_node_modules(path: &Path) -> Option<PathBuf> {
    package_name_and_root_in_node_modules(path).map(|(_, root)| root)
}

fn package_name_and_root_in_node_modules(path: &Path) -> Option<(String, PathBuf)> {
    let comps: Vec<Component> = path.components().collect();
    let nm_idx = comps
        .iter()
        .rposition(|c| c.as_os_str() == OsStr::new("node_modules"))?;
    let name_start = nm_idx + 1;
    let first = comps.get(name_start)?;
    let scoped = first.as_os_str().to_string_lossy().starts_with('@');
    let end = if scoped {
        name_start + 2
    } else {
        name_start + 1
    };
    if end > comps.len() {
        return None; // `node_modules/@scope` with no name segment
    }
    let name = if scoped {
        format!(
            "{}/{}",
            first.as_os_str().to_string_lossy(),
            comps.get(name_start + 1)?.as_os_str().to_string_lossy()
        )
    } else {
        first.as_os_str().to_string_lossy().to_string()
    };
    Some((name, comps[..end].iter().collect()))
}

fn package_name_from_bare_specifier(specifier: &str) -> Option<String> {
    if specifier.is_empty()
        || specifier.starts_with('.')
        || specifier.starts_with('/')
        || specifier.starts_with('#')
        || Path::new(specifier).is_absolute()
    {
        return None;
    }
    let mut parts = specifier.split('/');
    let first = parts.next()?;
    if first.starts_with('@') {
        let second = parts.next()?;
        return Some(format!("{first}/{second}"));
    }
    Some(first.to_string())
}

fn strip_file_specifier_decorations(specifier: &str) -> &str {
    // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution — a Windows verbatim namespace `?` is path syntax, not a module query delimiter.
    let windows_verbatim_prefix_len = specifier.starts_with("\\\\?\\").then_some(4);
    let file_like = windows_verbatim_prefix_len.is_some()
        || specifier.starts_with('.')
        || specifier.starts_with('/')
        || Path::new(specifier).is_absolute();
    if !file_like {
        return specifier;
    }
    let search_start = windows_verbatim_prefix_len.unwrap_or(0);
    let end = specifier[search_start..]
        .char_indices()
        .find_map(|(index, character)| {
            matches!(character, '?' | '#').then_some(search_start + index)
        })
        .unwrap_or(specifier.len());
    &specifier[..end]
}

#[cfg(any(windows, test))]
fn normalize_windows_verbatim_path_text(value: &str) -> std::borrow::Cow<'_, str> {
    // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution — Oxc receives ordinary Windows drive/UNC spellings while authorization retains canonical verbatim paths.
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        return std::borrow::Cow::Owned(format!(r"\\{rest}"));
    }
    if let Some(rest) = value.strip_prefix(r"\\?\") {
        return std::borrow::Cow::Borrowed(rest);
    }
    std::borrow::Cow::Borrowed(value)
}

fn find_package_root(start: &Path) -> Option<PathBuf> {
    let mut current = if start.is_file() {
        start.parent()?.to_path_buf()
    } else {
        start.to_path_buf()
    };

    loop {
        if current.join("package.json").exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

fn pick_package_import_path(
    value: &Value,
    subpath: Option<&str>,
    conditions: &ConditionSet,
) -> Option<String> {
    match value {
        Value::String(target) => {
            if let Some(subpath) = subpath {
                if target.contains('*') {
                    return Some(target.replacen('*', subpath, 1));
                }
            }
            Some(target.to_string())
        }
        Value::Object(map) => {
            for condition in conditions.names().chain(std::iter::once("default")) {
                if let Some(condition_target) = map.get(condition) {
                    if let Some(path) =
                        pick_package_import_path(condition_target, subpath, conditions)
                    {
                        return Some(path);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn resolve_package_import_target(
    specifier: &str,
    imports: &serde_json::Map<String, Value>,
    conditions: &ConditionSet,
) -> Option<String> {
    if let Some(value) = imports.get(specifier) {
        if let Some(path) = pick_package_import_path(value, None, conditions) {
            return Some(path);
        }
    }

    // Among subpath patterns, Node selects the most specific match: the one
    // with the longest prefix (the portion before `*`) that the specifier
    // starts with. The serde_json map here is not insertion-ordered
    // (`preserve_order` is off, so keys iterate alphabetically), so we must
    // rank explicitly rather than returning the first hit.
    let mut best: Option<(&str, &Value)> = None;
    for (key, value) in imports {
        // Only `#foo/*`-style subpath patterns participate. Keep the trailing
        // slash in the prefix so `#internal/*` matches `#internal/thing` but
        // NOT the sibling specifier `#internal-utils`.
        if !key.ends_with("/*") {
            continue;
        }
        let prefix = &key[..key.len() - 1];
        if !specifier.starts_with(prefix) {
            continue;
        }
        if best.is_none_or(|(best_prefix, _)| prefix.len() > best_prefix.len()) {
            best = Some((prefix, value));
        }
    }

    let (prefix, value) = best?;
    let subpath = &specifier[prefix.len()..];
    pick_package_import_path(value, Some(subpath), conditions)
}

fn normalize_import_target(base: &Path, target: PathBuf) -> Option<PathBuf> {
    let normalized = if target.is_absolute() {
        target
    } else {
        base.join(target)
    };

    if normalized.exists() {
        return Some(normalized);
    }
    if normalized.extension().is_none() {
        for ext in ["js", "cjs", "mjs", "ts", "tsx", "jsx", "mts", "cts", "json"] {
            let candidate = normalized.with_extension(ext);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn module_kind_from_path(path: &Path) -> ModuleKind {
    match path
        .extension()
        .and_then(OsStr::to_str)
        .map(|ext| ext.to_ascii_lowercase())
    {
        Some(ext) if matches!(ext.as_str(), "mjs" | "mts" | "ts" | "tsx" | "jsx") => {
            ModuleKind::Esm
        }
        Some(ext) if ext == "json" => ModuleKind::Json,
        _ => ModuleKind::CommonJs,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn module_cache_key(
    path: &Path,
    target: &str,
    source: &str,
    environment: &CapturedModuleLoaderEnvironment,
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"loader-transpile-v14-content-addressed\0");
    hasher.update(target.as_bytes());
    hasher.update(b"\0");
    let cache_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let cache_path = cache_path.to_str().with_context(|| {
        format!(
            "Transpile cache does not support a non-UTF-8 module path: {}",
            cache_path.display()
        )
    })?;
    hasher.update(cache_path.as_bytes());
    hasher.update(b"\0");
    hasher.update(transpile_tooling_hash(environment)?);
    hasher.update(b"\0");
    hasher.update(source.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

/// Hash of the exact tooling captured for this diagnostic loader. Keeping the
/// memoization loader-local prevents one diagnostic Host from selecting
/// tooling for another while retaining the per-module cache-key fast path.
/// @ref LLP 0007#runtime-module-loading
fn transpile_tooling_hash(environment: &CapturedModuleLoaderEnvironment) -> Result<[u8; 32]> {
    environment
        .transpile_tooling_hash
        .get_or_init(|| {
            compute_transpile_tooling_hash(environment).map_err(|error| error.to_string())
        })
        .clone()
        .map_err(anyhow::Error::msg)
}

#[derive(Clone)]
struct CapturedTranspileToolFile {
    original: PathBuf,
    relative: PathBuf,
    source: std::sync::Arc<Vec<u8>>,
}

#[derive(Clone)]
struct TranspileOverrideIdentity {
    path: PathBuf,
    root: PathBuf,
    entry_relative: PathBuf,
    files: std::sync::Arc<Vec<CapturedTranspileToolFile>>,
    directory_digest: [u8; 32],
    runner: PathBuf,
    runner_name: &'static str,
    runner_digest: [u8; 32],
    digest: [u8; 32],
}

fn capture_transpile_tool_directory(
    root: &Path,
) -> Result<(Vec<CapturedTranspileToolFile>, [u8; 32])> {
    const MAX_FILES: usize = 4096;
    const MAX_BYTES: u64 = 256 * 1024 * 1024;

    fn walk_transpile_tool_directory(
        root: &Path,
        directory: &Path,
        files: &mut Vec<CapturedTranspileToolFile>,
        total: &mut u64,
    ) -> Result<()> {
        let mut entries =
            std::fs::read_dir(directory)?.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for item in entries {
            let path = item.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "Transpile override tool directories may not contain symlinks: {}",
                    path.display()
                );
            }
            if metadata.is_dir() {
                walk_transpile_tool_directory(root, &path, files, total)?;
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            if files.len() >= MAX_FILES {
                anyhow::bail!("Transpile override exceeds {MAX_FILES} authenticated files");
            }
            *total = total
                .checked_add(metadata.len())
                .context("Transpile override size overflow")?;
            if *total > MAX_BYTES {
                anyhow::bail!("Transpile override exceeds the 256 MiB authenticated size limit");
            }
            let source = std::fs::read(&path)?;
            let relative = path
                .strip_prefix(root)
                .context("Transpile override file escaped its tool root")?
                .to_path_buf();
            if relative.to_str().is_none() {
                anyhow::bail!("Transpile override paths must be valid UTF-8");
            }
            files.push(CapturedTranspileToolFile {
                original: path,
                relative,
                source: std::sync::Arc::new(source),
            });
        }
        Ok(())
    }

    let mut files = Vec::new();
    let mut total = 0;
    walk_transpile_tool_directory(root, root, &mut files, &mut total)?;
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    let mut hasher = Sha256::new();
    hasher.update(b"transpile-tool-directory-v1\0");
    for file in &files {
        hasher.update(file.relative.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update((file.source.len() as u64).to_le_bytes());
        hasher.update(file.source.as_slice());
    }
    Ok((files, hasher.finalize().into()))
}

fn compute_transpile_override_identity(path: &Path) -> Result<TranspileOverrideIdentity> {
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("Failed to authenticate transpile script {}", path.display()))?;
    let root = path
        .parent()
        .context("Transpile override has no parent directory")?
        .to_path_buf();
    let entry_relative = path
        .strip_prefix(&root)
        .context("Transpile override escaped its parent directory")?
        .to_path_buf();
    let (files, directory_digest) = capture_transpile_tool_directory(&root)?;
    if !files.iter().any(|file| file.original == path) {
        anyhow::bail!(
            "Transpile override entry was not captured: {}",
            path.display()
        );
    }
    let (runner, runner_name) = find_js_runner()?;
    let runner = std::fs::canonicalize(&runner)
        .with_context(|| format!("Failed to authenticate JS runner {}", runner.display()))?;
    const MAX_RUNNER_BYTES: u64 = 512 * 1024 * 1024;
    if std::fs::metadata(&runner)?.len() > MAX_RUNNER_BYTES {
        anyhow::bail!("Selected JS runner exceeds the 512 MiB identity limit");
    }
    let runner_digest: [u8; 32] = Sha256::digest(
        std::fs::read(&runner)
            .with_context(|| format!("Failed to read JS runner {}", runner.display()))?,
    )
    .into();
    let mut hasher = Sha256::new();
    hasher.update(b"subprocess-transpile-toolchain-v2\0");
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update(b"\0");
    hasher.update(directory_digest);
    hasher.update(runner.to_string_lossy().as_bytes());
    hasher.update(b"\0");
    hasher.update(runner_digest);
    Ok(TranspileOverrideIdentity {
        path,
        root,
        entry_relative,
        files: std::sync::Arc::new(files),
        directory_digest,
        runner,
        runner_name,
        runner_digest,
        digest: hasher.finalize().into(),
    })
}

fn transpile_override_identity(
    environment: &CapturedModuleLoaderEnvironment,
) -> Result<TranspileOverrideIdentity> {
    environment
        .transpile_override_identity
        .as_ref()
        .context("EXACT_TRANSPILE_SCRIPT must be set for subprocess transpilation")?
        .clone()
        .map_err(anyhow::Error::msg)
}

fn compute_transpile_tooling_hash(
    environment: &CapturedModuleLoaderEnvironment,
) -> Result<[u8; 32]> {
    // @ref LLP 0007#proposal — the in-process engine is part of the cache key
    // so the SWC fallback and Oxc candidate never share output.
    // Only the explicit subprocess override hashes a repo script.
    if environment.transpile_script.is_some() {
        let mut hasher = Sha256::new();
        hasher.update(b"subprocess-transpile-script\0");
        let identity = transpile_override_identity(environment)?;
        let script_path = identity.path.to_str().with_context(|| {
            format!(
                "Transpile override does not support a non-UTF-8 path: {}",
                identity.path.display()
            )
        })?;
        hasher.update(script_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(identity.digest);
        return Ok(hasher.finalize().into());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"in-process-transpile-engine\0");
    hasher.update(
        transpile::selected_engine_cache_tag(
            environment.runtime_transform(),
            environment.legacy_runtime_transform(),
        )?
        .as_bytes(),
    );
    Ok(hasher.finalize().into())
}

fn transpile_cache_dir(environment: &CapturedModuleLoaderEnvironment) -> Result<PathBuf> {
    // Resolve once per diagnostic loader rather than once per process. Armed
    // loaders return from `transpile_module` before reaching this function.
    // @ref LLP 0007#runtime-module-loading
    environment
        .transpile_cache_dir
        .get_or_init(|| resolve_transpile_cache_dir(environment).map_err(|error| error.to_string()))
        .clone()
        .map_err(anyhow::Error::msg)
}

fn resolve_transpile_cache_dir(environment: &CapturedModuleLoaderEnvironment) -> Result<PathBuf> {
    let mut dir = environment
        .runtime_cache_dir
        .clone()
        .map_err(anyhow::Error::msg)?;
    dir.push("typescript");
    dir.push("loader");
    if let Err(err) = ensure_transpile_cache_dir(&dir) {
        let fallback = environment
            .fallback_temp_dir
            .clone()
            .join("exact")
            .join("typescript")
            .join("loader");
        if let Err(fallback_err) = ensure_transpile_cache_dir(&fallback) {
            return Err(anyhow::anyhow!(
                "Failed to create transpile cache directory {} ({}) and fallback {} ({})",
                dir.display(),
                err,
                fallback.display(),
                fallback_err
            ));
        }
        std::fs::canonicalize(&fallback).with_context(|| {
            format!(
                "Failed to canonicalize transpile cache fallback {}",
                fallback.display()
            )
        })
    } else {
        std::fs::canonicalize(&dir)
            .with_context(|| format!("Failed to canonicalize transpile cache {}", dir.display()))
    }
}

fn ensure_transpile_cache_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| {
        format!(
            "Failed to create transpile cache directory {}",
            dir.display()
        )
    })?;

    let probe_path = unique_tmp_path(&dir.join(".exact-transpile-cache-write"));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path)
    {
        Ok(handle) => {
            drop(handle);
            std::fs::remove_file(&probe_path).with_context(|| {
                format!("Failed to clean up probe file {}", probe_path.display())
            })?;
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!(
            "Transpile cache directory {} is not writable: {}",
            dir.display(),
            err
        )),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TranspileCacheManifest {
    version: u32,
    target: String,
    source_sha256: String,
    output_sha256: String,
}

fn read_transpile_cache(artifact_dir: &Path, target: &str, source: &str) -> Result<Option<String>> {
    let output = artifact_dir.join("module.js");
    let manifest_path = artifact_dir.join("manifest.json");
    let (Ok(output_bytes), Ok(manifest_bytes)) =
        (std::fs::read(&output), std::fs::read(&manifest_path))
    else {
        return Ok(None);
    };
    let Ok(manifest) = serde_json::from_slice::<TranspileCacheManifest>(&manifest_bytes) else {
        return Ok(None);
    };
    let valid = manifest.version == 1
        && manifest.target == target
        && manifest.source_sha256 == sha256_hex(source.as_bytes())
        && manifest.output_sha256 == sha256_hex(&output_bytes);
    if !valid {
        return Ok(None);
    }
    String::from_utf8(output_bytes)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("cached transpile output is not UTF-8: {error}"))
}

fn transpile_cache_is_valid(artifact_dir: &Path, target: &str, source: &str) -> Result<bool> {
    Ok(read_transpile_cache(artifact_dir, target, source)?.is_some())
}

fn touch_transpile_artifact(artifact_dir: &Path) {
    // Recency is separate from the immutable code+manifest unit. Quota
    // eviction uses this marker when present, so cache hits implement LRU
    // rather than creation-time FIFO.
    let marker = artifact_dir.join(".last-used");
    let _ = std::fs::write(marker, []);
}

fn publish_transpile_artifact(
    entry: &Path,
    artifact_dir: &Path,
    target: &str,
    source: &str,
    environment: &CapturedModuleLoaderEnvironment,
) -> Result<()> {
    let stage = unique_tmp_path(artifact_dir);
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("Failed to create transpile stage {}", stage.display()))?;
    let stage_output = stage.join("module.js");
    let result = (|| -> Result<()> {
        run_transpile_command(entry, &stage_output, target, source, environment)?;
        let output_bytes = std::fs::read(&stage_output)?;
        let manifest = TranspileCacheManifest {
            version: 1,
            target: target.to_string(),
            source_sha256: sha256_hex(source.as_bytes()),
            output_sha256: sha256_hex(&output_bytes),
        };
        std::fs::write(
            stage.join("manifest.json"),
            serde_json::to_vec(&manifest).context("serialize transpile cache manifest")?,
        )?;

        for _ in 0..4 {
            match std::fs::rename(&stage, artifact_dir) {
                Ok(()) => {
                    touch_transpile_artifact(artifact_dir);
                    return Ok(());
                }
                Err(_) if artifact_dir.exists() => {
                    if transpile_cache_is_valid(artifact_dir, target, source)? {
                        std::fs::remove_dir_all(&stage).ok();
                        touch_transpile_artifact(artifact_dir);
                        return Ok(());
                    }
                    // Quarantine a corrupt same-key directory with a rename,
                    // never remove it in place while another process may be
                    // inspecting it. Only one contender wins this rename;
                    // losers retry against the winner's replacement.
                    let quarantine = unique_tmp_path(&artifact_dir.with_extension("invalid"));
                    match std::fs::rename(artifact_dir, &quarantine) {
                        Ok(()) => {
                            std::fs::remove_dir_all(&quarantine).ok();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!(
                                    "Failed to quarantine invalid transpile cache {}",
                                    artifact_dir.display()
                                )
                            })
                        }
                    }
                }
                Err(error) => return Err(error).context("publish transpile cache directory"),
            }
        }
        anyhow::bail!(
            "Transpile cache {} remained contested after repeated atomic publication attempts",
            artifact_dir.display()
        )
    })();
    if result.is_err() {
        std::fs::remove_dir_all(&stage).ok();
    }
    result
}

fn directory_size(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => directory_size(&entry.path()),
            Ok(file_type) if file_type.is_file() => {
                entry.metadata().map(|meta| meta.len()).unwrap_or(0)
            }
            _ => 0,
        })
        .sum()
}

fn prune_transpile_cache_to_limit(cache_dir: &Path, keep: &Path, limit: u64) {
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return;
    };
    let mut artifacts: Vec<_> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path() != keep)
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_dir() || entry.file_name().to_string_lossy().contains(".tmp") {
                return None;
            }
            let recency = std::fs::metadata(entry.path().join(".last-used"))
                .and_then(|marker| marker.modified())
                .or_else(|_| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            Some((recency, directory_size(&entry.path()), entry.path()))
        })
        .collect();
    let keep_size = directory_size(keep);
    let mut total = keep_size + artifacts.iter().map(|(_, size, _)| size).sum::<u64>();
    if total <= limit {
        return;
    }
    artifacts.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in artifacts {
        if total <= limit {
            break;
        }
        if std::fs::remove_dir_all(&path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

fn enforce_transpile_cache_quota(cache_dir: &Path, keep: &Path, limit: u64) {
    prune_transpile_cache_to_limit(cache_dir, keep, limit);
}

fn run_transpile_command(
    entry: &Path,
    output: &Path,
    target: &str,
    source: &str,
    environment: &CapturedModuleLoaderEnvironment,
) -> Result<()> {
    // Explicit override keeps a custom transpiler-script escape hatch;
    // everything else is in-process per LLP 0007, so TypeScript works
    // standalone without a Bun/Node subprocess.
    if environment.transpile_script.is_some() {
        let script = transpile_override_identity(environment)?;
        return run_transpile_override(
            entry,
            output,
            target,
            source,
            &script,
            environment.test_transpile_input_barrier.as_deref(),
        );
    }

    // Reuse the source the loader already read for this module instead of
    // re-reading the file inside the transpiler on a cache miss.
    let code = transpile::transpile_source_to_cjs(
        source,
        entry,
        target,
        environment.runtime_transform(),
        environment.legacy_runtime_transform(),
    )?;

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    // The caller publishes the containing staged directory atomically after
    // both module.js and its digest manifest are complete.
    std::fs::write(output, code)
        .with_context(|| format!("Failed to write {}", output.display()))?;
    Ok(())
}

fn run_transpile_override(
    entry: &Path,
    output: &Path,
    target: &str,
    source: &str,
    script: &TranspileOverrideIdentity,
    test_barrier: Option<&Path>,
) -> Result<()> {
    verify_transpile_override_identity(script)?;

    // The cache key and manifest bind `source`, the loader's single read.
    // Give the subprocess an immutable staged copy of those exact bytes;
    // sending the live entry path lets A→B (or ABA) publish output for B
    // under A's content-addressed key.
    let staged_input = unique_staged_transpile_input(entry, output);
    let staged_tool_root = unique_tmp_path(&output.with_file_name("transpile-tool"));
    struct StageCleanup<'a> {
        input: &'a Path,
        tool_root: &'a Path,
    }
    impl Drop for StageCleanup<'_> {
        fn drop(&mut self) {
            std::fs::remove_file(self.input).ok();
            std::fs::remove_dir_all(self.tool_root).ok();
        }
    }
    let _cleanup = StageCleanup {
        input: &staged_input,
        tool_root: &staged_tool_root,
    };
    if let Some(parent) = staged_input.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut input = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged_input)
        .with_context(|| {
            format!(
                "Failed to create staged transpile input {}",
                staged_input.display()
            )
        })?;
    use std::io::Write as _;
    input.write_all(source.as_bytes())?;
    input.sync_all()?;
    drop(input);

    // Stage the override entry's captured immediate-parent tree, not only its
    // entry script. Relative helpers and package.json module-mode semantics
    // within that tree are executable inputs. EXACT_TRANSPILE_SCRIPT is an
    // operator-trusted developer escape: it must be self-contained here and
    // must not rely on ancestor package/config discovery.
    std::fs::create_dir(&staged_tool_root)?;
    for tool_file in script.files.iter() {
        let staged = staged_tool_root.join(&tool_file.relative);
        if let Some(parent) = staged.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(tool_file.source.as_slice())?;
        file.sync_all()?;
    }
    let staged_script = staged_tool_root.join(&script.entry_relative);

    wait_for_transpile_test_barrier(output, test_barrier)?;
    run_transpile_subprocess(
        &staged_input,
        output,
        target,
        &staged_script,
        &script.runner,
        script.runner_name,
    )?;
    // Do not publish output if either the selected runner or any live tool
    // file changed during the subprocess. The staged copy guarantees the
    // output itself used the pre-run bytes; this check keeps the cache key
    // from blessing a concurrently upgraded toolchain.
    verify_transpile_override_identity(script)
}

fn verify_transpile_override_identity(script: &TranspileOverrideIdentity) -> Result<()> {
    let (_, current_directory_digest) = capture_transpile_tool_directory(&script.root)?;
    if current_directory_digest != script.directory_digest {
        anyhow::bail!("Transpile override tool directory changed during this process");
    }
    let current_runner_digest: [u8; 32] = Sha256::digest(
        std::fs::read(&script.runner)
            .with_context(|| format!("Failed to verify JS runner {}", script.runner.display()))?,
    )
    .into();
    if current_runner_digest != script.runner_digest {
        anyhow::bail!("Selected JS runner changed during this process");
    }
    Ok(())
}

fn unique_staged_transpile_input(entry: &Path, output: &Path) -> PathBuf {
    let base = unique_tmp_path(&output.with_file_name("transpile-input"));
    let Some(extension) = entry.extension() else {
        return base;
    };
    let mut name = base.into_os_string();
    name.push(".");
    name.push(extension);
    PathBuf::from(name)
}

fn wait_for_transpile_test_barrier(output: &Path, dir: Option<&Path>) -> Result<()> {
    let Some(dir) = dir else {
        return Ok(());
    };
    std::fs::create_dir_all(dir)?;
    if let Ok(target) = std::fs::read_to_string(dir.join("target")) {
        if target != output.to_string_lossy() {
            return Ok(());
        }
    }
    std::fs::write(dir.join("ready"), [])?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !dir.join("release").exists() {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for transpile input test barrier");
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    Ok(())
}

/// A tmp sibling of `output` whose name is unique to this process and this
/// call, so a rename-based publish can never collide with another process (or
/// another concurrent transpile in this one) writing the same cache entry. The
/// tmp stays in `output`'s directory so the rename remains atomic on one
/// filesystem.
fn unique_tmp_path(output: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut bytes = [0u8; 8];
    let rand = if getrandom::getrandom(&mut bytes).is_ok() {
        u64::from_le_bytes(bytes)
    } else {
        // getrandom only fails in pathological environments; the pid + counter
        // already disambiguate, so a time-based fallback is plenty.
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    };

    let mut name = output
        .file_name()
        .unwrap_or_else(|| OsStr::new("module"))
        .to_os_string();
    name.push(format!(".{}.{seq}.{rand:016x}.tmp", std::process::id()));
    match output.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

fn run_transpile_subprocess(
    entry: &Path,
    output: &Path,
    target: &str,
    script: &Path,
    runner: &Path,
    runner_name: &str,
) -> Result<()> {
    let private_environment = unique_tmp_path(&output.with_file_name("transpile-environment"));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&private_environment).with_context(|| {
        format!(
            "Failed to create private transpile environment {}",
            private_environment.display()
        )
    })?;
    struct PrivateEnvironmentCleanup(PathBuf);
    impl Drop for PrivateEnvironmentCleanup {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }
    let _private_environment_cleanup = PrivateEnvironmentCleanup(private_environment.clone());

    let mut command = Command::new(runner);
    configure_transpile_subprocess_environment(&mut command, &private_environment);
    command.current_dir(&private_environment);
    if runner_name == "bun" {
        let bun_config = private_environment.join("bunfig.toml");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&bun_config)
            .and_then(|mut file| {
                use std::io::Write as _;
                file.write_all(b"# intentionally empty authenticated transpile config\n")
            })
            .with_context(|| {
                format!(
                    "Failed to create private Bun config {}",
                    bun_config.display()
                )
            })?;
        command.arg("--no-env-file").arg(format!(
            "--config={}",
            bun_config
                .to_str()
                .context("private Bun config path is not UTF-8")?
        ));
    }
    let status = command
        .arg(script)
        .arg("--entry")
        .arg(entry)
        .arg("--out")
        .arg(output)
        .arg("--target")
        .arg(target)
        .status()
        .with_context(|| format!("Failed to run {} for {}", runner_name, entry.display()))?;

    if !status.success() {
        anyhow::bail!(
            "TypeScript transpile failed with status {} for {}",
            status,
            entry.display()
        );
    }

    if !output.exists() {
        anyhow::bail!(
            "TypeScript transpile did not emit output {}",
            output.display()
        );
    }

    Ok(())
}

fn configure_transpile_subprocess_environment(command: &mut Command, private_environment: &Path) {
    // The override directory and runner bytes are authenticated separately.
    // No ambient runner controls are inputs to that identity, so do not let
    // Node/Bun/native-loader variables or PATH cross into the compiler child.
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

fn find_js_runner() -> Result<(PathBuf, &'static str)> {
    let search_path = std::env::var_os("PATH")
        .context("PATH is unavailable while capturing the transpile runner")?;
    let cwd = std::env::current_dir()
        .context("failed to capture the transpile runner search directory")?;
    #[cfg(windows)]
    let candidates = [("bun.exe", "bun"), ("node.exe", "node")];
    #[cfg(not(windows))]
    let candidates = [("bun", "bun"), ("node", "node")];
    for (executable, name) in candidates {
        if let Ok(path) = which::which_in(executable, Some(&search_path), &cwd) {
            return Ok((path, name));
        }
    }
    anyhow::bail!("bun or node is required to transpile TypeScript");
}

pub fn builtin_module_debug_entries() -> &'static [BuiltinManifestDebugEntry] {
    BUILTIN_MANIFEST_DEBUG_ENTRIES
}

fn build_builtin_registry(
    registrations: &[BuiltinManifestRegistration],
) -> HashMap<&'static str, BuiltinModule> {
    let mut builtins = HashMap::new();

    for registration in registrations {
        let Some(source) = generated_builtin_source(registration.source_key) else {
            eprintln!(
                "Skipping builtin manifest entry {} with unknown source key {}",
                registration.specifier, registration.source_key
            );
            continue;
        };
        builtins.insert(
            registration.specifier,
            BuiltinModule {
                source_key: registration.source_key,
                source,
            },
        );
    }

    builtins
}

/// Strip URL decorations only from syntax which already denotes a file
/// location. Bare package names and package-import aliases keep their exact
/// spelling. This makes the native resolver agree with the VFS file-URL path
/// parser and, consequently, makes all decorations converge on one SourceId.
/// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
pub(crate) fn strip_file_module_decorations(specifier: &str) -> &str {
    let bytes = specifier.as_bytes();
    let windows_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    let file_backed = specifier.starts_with('.')
        || specifier.starts_with('/')
        || specifier.starts_with('\\')
        || specifier
            .get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("file:"))
        || windows_drive;
    if !file_backed {
        return specifier;
    }
    // `std::fs::canonicalize` returns verbatim (`\\?\`) paths on Windows.
    // That namespace marker is part of the path, not a URL query delimiter.
    // Search for decorations only after the complete marker so an
    // authenticated entry does not collapse to the root-relative spelling
    // `\\` and get misclassified as a bare package request.
    let decoration_start = if specifier.starts_with(r"\\?\") || specifier.starts_with("//?/") {
        4
    } else {
        0
    };
    let end = specifier[decoration_start..]
        .find(['?', '#'])
        .map(|offset| decoration_start + offset)
        .unwrap_or(specifier.len());
    &specifier[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn package_race_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap()
    }

    struct PackageHookReset;

    impl Drop for PackageHookReset {
        fn drop(&mut self) {
            for hook in [
                PACKAGE_SOURCE_OPEN_HOOK.get(),
                PACKAGE_ROOT_OPEN_HOOK.get(),
                PACKAGE_INVENTORY_PASS_HOOK.get(),
            ]
            .into_iter()
            .flatten()
            {
                *hook.lock().unwrap() = None;
            }
        }
    }

    #[cfg(unix)]
    fn test_object_identity(path: &Path) -> capsec_semantics::model::ObjectIdentity {
        use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).unwrap();
        ObjectIdentity {
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
            volume: NonEmptyString::new(format!("dev:{}", metadata.dev())).unwrap(),
            file: NonEmptyString::new(format!("ino:{}", metadata.ino())).unwrap(),
        }
    }

    #[cfg(unix)]
    fn test_link_object_identity(path: &Path) -> capsec_semantics::model::ObjectIdentity {
        use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path).unwrap();
        ObjectIdentity {
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
            volume: NonEmptyString::new(format!("dev:{}", metadata.dev())).unwrap(),
            file: NonEmptyString::new(format!("ino:{}", metadata.ino())).unwrap(),
        }
    }

    #[cfg(windows)]
    fn test_object_identity(path: &Path) -> capsec_semantics::model::ObjectIdentity {
        crate::host::object_identity_for_host_path(path).unwrap()
    }

    fn test_loader() -> ModuleLoader {
        ModuleLoader::new()
    }

    fn test_cache_environment(
        preferred_runtime_cache: PathBuf,
        fallback_temp_dir: PathBuf,
    ) -> CapturedModuleLoaderEnvironment {
        CapturedModuleLoaderEnvironment {
            runtime_transform: None,
            legacy_runtime_transform: None,
            transpile_script: None,
            transpile_cache_max_bytes: DEFAULT_TRANSPILE_CACHE_MAX_BYTES,
            test_transpile_input_barrier: None,
            runtime_cache_dir: Ok(preferred_runtime_cache),
            fallback_temp_dir,
            transpile_cache_dir: std::sync::OnceLock::new(),
            transpile_tooling_hash: std::sync::OnceLock::new(),
            transpile_override_identity: None,
        }
    }

    fn write_forged_transpile_cache_artifact(
        runtime_cache: &Path,
        entry: &Path,
        target: &str,
        source: &str,
        forged_output: &str,
        environment: &CapturedModuleLoaderEnvironment,
    ) -> PathBuf {
        let cache_key = module_cache_key(entry, target, source, environment).unwrap();
        let artifact = runtime_cache
            .join("typescript")
            .join("loader")
            .join(cache_key);
        std::fs::create_dir_all(&artifact).unwrap();
        std::fs::write(artifact.join("module.js"), forged_output).unwrap();
        let manifest = TranspileCacheManifest {
            version: 1,
            target: target.into(),
            source_sha256: sha256_hex(source.as_bytes()),
            output_sha256: sha256_hex(forged_output.as_bytes()),
        };
        std::fs::write(
            artifact.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        artifact
    }

    #[test]
    fn armed_loader_ignores_forged_public_hash_cache() {
        let root = tempdir().unwrap();
        let entry = root.path().join("module.ts");
        let source = "export const answer: number = 42;";
        std::fs::write(&entry, source).unwrap();
        let runtime_cache = root.path().join("cache");
        let fallback = root.path().join("fallback");
        let environment = test_cache_environment(runtime_cache.clone(), fallback);
        let forged_output = "throw new Error('forged cache executed');";
        let artifact = write_forged_transpile_cache_artifact(
            &runtime_cache,
            &entry,
            "es2015",
            source,
            forged_output,
            &environment,
        );

        let mut loader = test_loader();
        loader.environment = environment;
        loader.arm_fresh_transpilation().unwrap();
        let output = loader.transpile_module(&entry, "es2015", source).unwrap();

        assert_ne!(output, forged_output);
        assert!(!artifact.join(".last-used").exists());
    }

    #[test]
    fn armed_loader_never_touches_unusable_cache_or_fallback() {
        let root = tempdir().unwrap();
        let entry = root.path().join("module.tsx");
        let source = "export const view = <div>safe</div>;";
        std::fs::write(&entry, source).unwrap();
        let unusable_primary = root.path().join("cache-is-a-file");
        std::fs::write(&unusable_primary, b"must remain a file").unwrap();
        let untouched_fallback = root.path().join("fallback-must-remain-absent");

        let mut loader = test_loader();
        loader.environment =
            test_cache_environment(unusable_primary.clone(), untouched_fallback.clone());
        loader.arm_fresh_transpilation().unwrap();
        let output = loader.transpile_module(&entry, "es2015", source).unwrap();

        assert!(!output.is_empty());
        assert_eq!(
            std::fs::read(&unusable_primary).unwrap(),
            b"must remain a file"
        );
        assert!(!untouched_fallback.exists());
    }

    #[test]
    fn diagnostic_first_loader_state_cannot_seed_armed_transpilation() {
        let root = tempdir().unwrap();
        let entry = root.path().join("module.ts");
        let source = "export const answer: number = 42;";
        std::fs::write(&entry, source).unwrap();
        let runtime_cache = root.path().join("shared-cache");
        let fallback = root.path().join("fallback");
        let diagnostic_environment =
            test_cache_environment(runtime_cache.clone(), fallback.clone());
        let forged_output = "module.exports = 'diagnostic forged cache';";
        write_forged_transpile_cache_artifact(
            &runtime_cache,
            &entry,
            "es2015",
            source,
            forged_output,
            &diagnostic_environment,
        );

        let mut diagnostic = test_loader();
        diagnostic.environment = diagnostic_environment;
        assert_eq!(
            diagnostic
                .transpile_module(&entry, "es2015", source)
                .unwrap(),
            forged_output
        );
        assert_eq!(
            diagnostic.transpile_mode,
            TranspileMode::DiagnosticPersistentCache
        );

        let mut armed = test_loader();
        armed.environment = test_cache_environment(runtime_cache, fallback);
        armed.arm_fresh_transpilation().unwrap();
        let armed_output = armed.transpile_module(&entry, "es2015", source).unwrap();
        assert_eq!(armed.transpile_mode, TranspileMode::ArmedFreshInMemory);
        assert_ne!(armed_output, forged_output);
    }

    #[test]
    fn armed_loader_still_refuses_subprocess_override() {
        let mut loader = test_loader();
        loader.environment.transpile_script = Some(PathBuf::from("diagnostic-transpiler.js"));

        let error = loader.arm_fresh_transpilation().unwrap_err();
        assert!(error
            .to_string()
            .contains("diagnostic-only developer escape"));
        assert_eq!(
            loader.transpile_mode,
            TranspileMode::DiagnosticPersistentCache
        );
    }

    #[test]
    fn resolves_relative_extension() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mod.js");
        std::fs::write(&file, "export const x = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("./mod", Some(&dir.path().join("entry.js")))
            .unwrap();
        let resolved_path = resolved.path.unwrap();
        assert_eq!(
            resolved_path.canonicalize().unwrap(),
            file.canonicalize().unwrap()
        );
    }

    #[test]
    fn resolves_bare_specifier() {
        let dir = tempdir().unwrap();
        let node_modules = dir.path().join("node_modules");
        let pkg_dir = node_modules.join("demo-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("package.json"), r#"{ "main": "index.js" }"#).unwrap();
        std::fs::write(pkg_dir.join("index.js"), "module.exports = { ok: true };").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("demo-pkg", Some(&dir.path().join("entry.js")))
            .unwrap();
        assert!(resolved
            .path
            .unwrap()
            .ends_with("node_modules/demo-pkg/index.js"));
    }

    #[test]
    fn executable_extension_modules_fail_closed_before_source_loading() {
        let dir = tempdir().unwrap();
        let entry = dir.path().join("entry.js");
        std::fs::write(&entry, "module.exports = true;").unwrap();
        for (name, expected) in [
            ("payload.node", "Native addons are closed"),
            ("payload.NODE", "Native addons are closed"),
            ("payload.wasm", "WebAssembly modules are closed"),
            ("payload.WASM", "WebAssembly modules are closed"),
        ] {
            // Deliberately valid JavaScript: the regression was that the
            // resolver relabeled these executable kinds as CommonJS.
            std::fs::write(dir.path().join(name), "globalThis.pwned = true;").unwrap();
            let error = test_loader()
                .resolve(&format!("./{name}"), Some(&entry))
                .expect_err("unsupported executable module kind resolved as JavaScript");
            assert!(
                error.to_string().contains(expected),
                "unexpected {name} refusal: {error:#}"
            );
        }
    }

    #[test]
    fn resolves_exports_condition() {
        let dir = tempdir().unwrap();
        let node_modules = dir.path().join("node_modules");
        let pkg_dir = node_modules.join("exports-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{ "exports": { "require": "./cjs.js", "import": "./esm.js" } }"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("cjs.js"), "module.exports = { ok: true };").unwrap();
        std::fs::write(pkg_dir.join("esm.js"), "export const ok = true;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("exports-pkg", Some(&dir.path().join("entry.js")))
            .unwrap();
        assert!(resolved
            .path
            .unwrap()
            .ends_with("node_modules/exports-pkg/cjs.js"));

        let imported = loader
            .resolve_meta_typed(
                "exports-pkg",
                Some(&dir.path().join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .unwrap();
        assert!(imported
            .path
            .unwrap()
            .ends_with("node_modules/exports-pkg/esm.js"));
    }

    // ENG-23007: `require.resolve` needs only the resolved path, so `resolve_meta`
    // (which backs it over the ABI) must return the metadata WITHOUT reading or
    // transpiling the module body. The differential proof is Node's own
    // `require.resolve` semantics: resolving a module whose body is un-parseable
    // still succeeds, because resolution never touches the body.
    #[test]
    fn resolve_meta_does_not_read_or_transpile_body() {
        let dir = tempdir().unwrap();
        // A .ts body that is a hard syntax error. The full loader would try to
        // transpile it; resolve_meta must never open it.
        let file = dir.path().join("broken.ts");
        std::fs::write(&file, "export const x: = = 1 ((( not valid typescript $$$").unwrap();

        let loader = test_loader();
        let meta = loader
            .resolve_meta("./broken", Some(&dir.path().join("entry.ts")))
            .expect("resolve_meta must succeed for a syntactically-broken body");

        assert_eq!(
            meta.path.as_ref().unwrap().canonicalize().unwrap(),
            file.canonicalize().unwrap()
        );
        // The proof the body was not read/transpiled: `source` is still unset.
        // (The un-parseable body would fail transpile on the full load path.)
        assert!(
            meta.source.is_none(),
            "resolve_meta must not load the module body"
        );

        // A plain ESM file exercises the resolver's `ModuleKind::Esm` branch.
        // Metadata-only resolution must not use a speculative source prefetch:
        // the armed Host has not completed discovery/commit authorization yet.
        let esm_file = dir.path().join("plain.mjs");
        std::fs::write(&esm_file, "export const value = 1;\n").unwrap();
        let module_type_loader = test_loader();
        let esm_meta = module_type_loader
            .resolve_meta_typed(
                "./plain.mjs",
                Some(&dir.path().join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .expect("resolve_meta must not open a plain ESM body");
        assert_eq!(
            esm_meta.path.as_ref().unwrap().canonicalize().unwrap(),
            esm_file.canonicalize().unwrap()
        );
        assert!(
            esm_meta.source.is_none(),
            "resolve_meta must not prefetch a plain ESM body"
        );
    }

    #[test]
    fn direct_file_metadata_uses_authenticated_package_type_for_js() {
        let dir = tempdir().unwrap();
        let commonjs = dir.path().join("commonjs");
        let module = dir.path().join("module");
        std::fs::create_dir_all(&commonjs).unwrap();
        std::fs::create_dir_all(&module).unwrap();
        std::fs::write(commonjs.join("package.json"), r#"{"type":"commonjs"}"#).unwrap();
        std::fs::write(module.join("package.json"), r#"{"type":"module"}"#).unwrap();
        std::fs::write(commonjs.join("entry.js"), "module.exports = 1;\n").unwrap();
        std::fs::write(module.join("entry.js"), "export default 1;\n").unwrap();

        let loader = test_loader();
        assert_eq!(
            loader
                .resolve_direct_file_meta(&commonjs.join("entry.js"))
                .unwrap()
                .kind,
            ModuleKind::CommonJs
        );
        assert_eq!(
            loader
                .resolve_direct_file_meta(&module.join("entry.js"))
                .unwrap()
                .kind,
            ModuleKind::Esm
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_direct_file_refuses_nearest_malformed_manifest_but_ignores_outer_one() {
        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        let source = project.join("src");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(sandbox.path().join("package.json"), r#"{"type": "#).unwrap();
        std::fs::write(source.join("entry.js"), "module.exports = 1;\n").unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let entry = project.join("src/entry.js");
        let loader = test_loader();
        assert!(
            loader.resolve_direct_file_meta(&entry).is_err(),
            "the diagnostic resolver should demonstrate the ambient malformed-manifest failure"
        );

        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();
        let bounded = loader
            .resolve_direct_file_meta_authenticated(&entry, &inputs)
            .expect("outside parent manifest must be invisible to armed resolution");
        assert_eq!(bounded.kind, ModuleKind::CommonJs);
        assert_eq!(bounded.path.as_deref(), Some(entry.as_path()));

        // A malformed manifest inside the authenticated boundary is not the
        // same as an ambient parent: once Host captures it as the nearest
        // package scope, armed resolution must refuse instead of falling
        // through to CommonJS or continuing the upward search.
        let nearest_manifest = project.join("src/package.json");
        std::fs::write(&nearest_manifest, r#"{"type": "#).unwrap();
        let mut manifests = BTreeMap::new();
        manifests.insert(nearest_manifest, br#"{"type": "#.to_vec());
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            manifests,
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();
        let error = loader
            .resolve_direct_file_meta_authenticated(&entry, &inputs)
            .expect_err("a captured malformed nearest manifest must refuse resolution");
        assert!(
            error.to_string().contains("Failed to resolve module"),
            "unexpected malformed-manifest refusal: {error:#}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_resolver_refuses_replaced_boundary_before_lookup() {
        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        let original = sandbox.path().join("original");
        let substitute = sandbox.path().join("substitute");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&substitute).unwrap();
        let expected = test_object_identity(&project);

        std::fs::rename(&project, &original).unwrap();
        std::fs::rename(&substitute, &project).unwrap();
        let error = AuthenticatedResolverInputs::new(
            project,
            &expected,
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .err()
        .expect("a replacement boundary object must be refused");
        assert!(
            error
                .to_string()
                .contains("boundary object changed before retention"),
            "unexpected boundary refusal: {error:#}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_unknown_manifest_operations_record_without_host_lookup() {
        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let manifest = project.join("package.json");
        std::fs::write(&manifest, br#"{"type":"module"}"#).unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let manifest = project.join("package.json");
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();
        let file_system = inputs.file_system();

        assert_eq!(
            file_system.read(&manifest).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            file_system.read_to_string(&manifest).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            file_system.metadata(&manifest).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            file_system.symlink_metadata(&manifest).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(file_system
            .read_link(&manifest)
            .unwrap_err()
            .to_string()
            .contains("authenticated package manifest is unavailable"));
        assert_eq!(
            file_system.canonicalize(&manifest).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            inputs.uncaptured_package_manifest_probes().unwrap(),
            BTreeSet::from([manifest])
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_manifest_absence_suppresses_probe_and_disk_manifest() {
        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("entry.js"), "module.exports = true;\n").unwrap();
        std::fs::write(project.join("package.json"), r#"{"type": "#).unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let entry = project.join("entry.js");
        let manifest = project.join("package.json");
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::from([manifest]),
            BTreeSet::new(),
        )
        .unwrap();
        let resolved = test_loader()
            .resolve_direct_file_meta_authenticated(&entry, &inputs)
            .expect("an authenticated absence must hide a conflicting disk manifest");
        assert_eq!(resolved.kind, ModuleKind::CommonJs);
        assert!(inputs
            .uncaptured_package_manifest_probes()
            .unwrap()
            .is_empty());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_denied_foreign_subtree_blocks_symlink_but_same_root_symlink_resolves() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;
        #[cfg(windows)]
        use std::os::windows::fs::symlink_file as symlink;

        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        let foreign = project.join("node_modules/foreign");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(project.join("entry.js"), "module.exports = true;\n").unwrap();
        std::fs::write(project.join("local.js"), "module.exports = 'local';\n").unwrap();
        std::fs::write(foreign.join("target.js"), "module.exports = 'foreign';\n").unwrap();
        symlink("local.js", project.join("local-link.js")).unwrap();
        symlink(
            "node_modules/foreign/target.js",
            project.join("foreign-link.js"),
        )
        .unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let entry = project.join("entry.js");
        let foreign = project.join("node_modules/foreign");
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::from([foreign]),
        )
        .unwrap();
        let loader = test_loader();

        let local = loader
            .resolve_meta_authenticated("./local-link.js", Some(&entry), None, &inputs)
            .expect("same-principal in-bound symlink must remain resolvable");
        assert_eq!(
            local.path.as_deref(),
            Some(project.join("local.js").as_path())
        );

        let error = loader
            .resolve_meta_authenticated("./foreign-link.js", Some(&entry), None, &inputs)
            .expect_err("symlink into a denied foreign package subtree must be refused");
        assert!(
            error.to_string().contains("Failed to resolve module"),
            "unexpected denied-subtree refusal: {error:#}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_outside_referrer_bridge_requires_one_exact_preflighted_path() {
        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        let package = project.join("node_modules/shared");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("index.js"), "module.exports = 'shared';\n").unwrap();
        std::fs::write(package.join("other.js"), "module.exports = 'other';\n").unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let package = project.join("node_modules/shared");
        let target = package.join("index.js");
        let other = package.join("other.js");
        let outside_referrer = project.join(".ibex-session-static-import.mjs");
        let inputs = AuthenticatedResolverInputs::new(
            package.clone(),
            &test_object_identity(&package),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();

        let resolved_base = authenticated_resolver_base_dir(
            &inputs,
            Some(&outside_referrer),
            "./node_modules/shared/index.js",
            Some(&target),
        )
        .unwrap();
        #[cfg(unix)]
        assert_eq!(resolved_base, project);
        #[cfg(windows)]
        assert_eq!(
            resolved_base,
            PathBuf::from(normalize_windows_verbatim_path_text(project.to_str().unwrap()).as_ref())
        );
        let resolved = test_loader()
            .resolve_meta_authenticated(
                "./node_modules/shared/index.js?cache=one#fragment",
                Some(&outside_referrer),
                Some(&target),
                &inputs,
            )
            .expect("the exact preflighted target must resolve through the inert caller spelling");
        assert_eq!(resolved.path.as_deref(), Some(target.as_path()));

        let missing = authenticated_resolver_base_dir(
            &inputs,
            Some(&outside_referrer),
            "./node_modules/shared/index.js",
            None,
        )
        .expect_err("an outside referrer without a preflighted target must be refused");
        assert!(missing.to_string().contains("outside its boundary"));

        let mismatch = authenticated_resolver_base_dir(
            &inputs,
            Some(&outside_referrer),
            "./node_modules/shared/index.js",
            Some(&other),
        )
        .expect_err("a different in-boundary target must not satisfy exact preflight");
        assert!(mismatch
            .to_string()
            .contains("differs from its preflighted target"));

        let bare = authenticated_resolver_base_dir(
            &inputs,
            Some(&outside_referrer),
            "shared",
            Some(&target),
        )
        .expect_err("a bare spelling must use its authenticated package binding path");
        assert!(bare.to_string().contains("outside its boundary"));
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_outside_referrer_bridge_does_not_mask_a_denied_subtree() {
        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        let denied = project.join("node_modules/denied");
        std::fs::create_dir_all(&denied).unwrap();
        std::fs::write(project.join("allowed.js"), "module.exports = true;\n").unwrap();
        std::fs::write(denied.join("entry.js"), "module.exports = false;\n").unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let denied = project.join("node_modules/denied");
        let target = project.join("allowed.js");
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::from([denied.clone()]),
        )
        .unwrap();

        let error = authenticated_resolver_base_dir(
            &inputs,
            Some(&denied.join("entry.js")),
            "../../allowed.js",
            Some(&target),
        )
        .expect_err("an in-boundary denied referrer must remain denied");
        assert!(error.to_string().contains("unavailable"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_denied_subtree_blocks_ancestor_symlink_with_pending_tail() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;
        #[cfg(windows)]
        use std::os::windows::fs::symlink_dir as symlink;

        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        let package = project.join("node_modules/pkg");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(project.join("entry.js"), "module.exports = true;\n").unwrap();
        std::fs::write(
            package.join("index.js"),
            "module.exports = 'foreign package';\n",
        )
        .unwrap();
        symlink("node_modules", project.join("alias")).unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let entry = project.join("entry.js");
        let denied_package = project.join("node_modules/pkg");
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::from([denied_package]),
        )
        .unwrap();

        let error = test_loader()
            .resolve_meta_authenticated("./alias/pkg/index.js", Some(&entry), None, &inputs)
            .expect_err("the symlink target plus pending tail must be checked before entering pkg");
        assert!(
            error.to_string().contains("Failed to resolve module"),
            "unexpected ancestor-symlink refusal: {error:#}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_manifests_drive_kind_exports_and_package_imports() {
        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        let source = project.join("src");
        let package = project.join("node_modules/pkg");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(source.join("entry.js"), "export default 1;\n").unwrap();
        std::fs::write(source.join("inside.js"), "export const inside = true;\n").unwrap();
        std::fs::write(
            package.join("captured.js"),
            "export const captured = true;\n",
        )
        .unwrap();
        std::fs::write(package.join("ambient.js"), "module.exports = 'ambient';\n").unwrap();

        // Deliberately conflicting disk manifests prove OXC consumes the map,
        // not a path reopen, for every manifest-controlled resolver feature.
        std::fs::write(
            project.join("package.json"),
            r##"{"name":"ambient-app","type":"commonjs","imports":{"#inside":"./missing.js"}}"##,
        )
        .unwrap();
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"pkg","version":"9.9.9","type":"commonjs","exports":{".":"./ambient.js"}}"#,
        )
        .unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let entry = project.join("src/entry.js");
        let package = project.join("node_modules/pkg");
        let captured_target = package.join("captured.js");
        let mut manifests = BTreeMap::new();
        manifests.insert(
            project.join("package.json"),
            br##"{"name":"app","type":"module","imports":{"#inside":"./src/inside.js"}}"##.to_vec(),
        );
        manifests.insert(
            package.join("package.json"),
            br#"{"name":"pkg","version":"1.2.3","type":"module","exports":{".":"./captured.js"}}"#
                .to_vec(),
        );
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            manifests,
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();
        let loader = test_loader();

        assert_eq!(
            loader
                .resolve_direct_file_meta_authenticated(&entry, &inputs)
                .unwrap()
                .kind,
            ModuleKind::Esm
        );

        let imported = loader
            .resolve_meta_authenticated("#inside", Some(&entry), None, &inputs)
            .unwrap();
        assert_eq!(
            imported.path.as_deref(),
            Some(project.join("src/inside.js").as_path())
        );
        assert_eq!(imported.kind, ModuleKind::Esm);

        let synthetic_referrer = project.join(".ibex-session-static-import.mjs");
        let from_synthetic_referrer = loader
            .resolve_meta_authenticated("./src/inside.js", Some(&synthetic_referrer), None, &inputs)
            .expect("the bounded resolver must accept the session's file-like synthetic referrer");
        assert_eq!(
            from_synthetic_referrer.path.as_deref(),
            Some(project.join("src/inside.js").as_path())
        );

        let exported = loader
            .resolve_meta_authenticated("pkg", Some(&entry), None, &inputs)
            .unwrap();
        assert_eq!(exported.path.as_deref(), Some(captured_target.as_path()));
        assert_eq!(exported.kind, ModuleKind::Esm);
        assert_eq!(exported.package_version.as_deref(), Some("1.2.3"));

        let bound = loader
            .resolve_meta_from_authenticated_bound_package("pkg", "pkg", &package, &inputs)
            .unwrap();
        assert_eq!(bound.path.as_deref(), Some(captured_target.as_path()));
        assert_eq!(bound.package_root.as_deref(), Some(package.as_path()));
        assert_eq!(bound.package_version.as_deref(), Some("1.2.3"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_resolver_refuses_outside_symlink_target() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;
        #[cfg(windows)]
        use std::os::windows::fs::symlink_file;

        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        let outside = sandbox.path().join("outside");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(project.join("entry.js"), "module.exports = 1;\n").unwrap();
        std::fs::write(outside.join("target.js"), "module.exports = 'outside';\n").unwrap();
        #[cfg(unix)]
        symlink(outside.join("target.js"), project.join("escape.js")).unwrap();
        #[cfg(windows)]
        symlink_file(outside.join("target.js"), project.join("escape.js")).unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let entry = project.join("entry.js");
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();
        let error = test_loader()
            .resolve_meta_authenticated("./escape.js", Some(&entry), None, &inputs)
            .expect_err("an outside symlink target must not resolve");
        assert!(
            error.to_string().contains("Failed to resolve module"),
            "unexpected bounded resolver error: {error:#}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn authenticated_resolver_follows_contained_windows_reparse() {
        use std::os::windows::fs::symlink_file;

        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("entry.js"), "module.exports = 1;\n").unwrap();
        std::fs::write(project.join("target.js"), "module.exports = 2;\n").unwrap();
        symlink_file(project.join("target.js"), project.join("link.js")).unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let entry = project.join("entry.js");
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::from([project.join("package.json")]),
            BTreeSet::new(),
        )
        .unwrap();
        let resolved = test_loader()
            .resolve_meta_authenticated("./link.js", Some(&entry), None, &inputs)
            .expect("a contained Windows symlink must resolve through the retained boundary");
        assert_eq!(
            resolved.path.as_deref(),
            Some(project.join("target.js").as_path())
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_resolver_alias_comparisons_close_denials_and_manifest_collisions() {
        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("Project");
        let denied = project.join("Denied");
        std::fs::create_dir_all(&denied).unwrap();
        std::fs::write(denied.join("secret.js"), "module.exports = false;\n").unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::from([project.join("Denied")]),
        )
        .unwrap();
        assert_eq!(
            inputs
                .normalize_in_boundary(&project.join("denied/secret.js"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(inputs
            .normalize_in_boundary(&project.join("caf\u{e9}.js"))
            .is_err());
        assert!(inputs
            .normalize_in_boundary(&project.join("SECRET~1.JS"))
            .is_err());

        let manifests = BTreeMap::from([(
            project.join("Package.json"),
            br#"{"type":"module"}"#.to_vec(),
        )]);
        let error = match AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            manifests,
            BTreeSet::from([project.join("package.JSON")]),
            BTreeSet::new(),
        ) {
            Ok(_) => panic!("case aliases cannot be captured and absent simultaneously"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("both captured and authenticated absent"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_resolver_disables_node_path_and_cannot_select_an_ambient_package() {
        let options = authenticated_module_resolve_options(
            true,
            &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
        );
        assert!(
            !options.node_path,
            "armed resolver construction must never initialize or consult NODE_PATH"
        );
        assert!(
            options
                .modules
                .iter()
                .all(|path| !Path::new(path).is_absolute()),
            "armed resolver module search must not contain an absolute ambient root"
        );

        let sandbox = tempdir().unwrap();
        let project = sandbox.path().join("project");
        let ambient = sandbox.path().join("ambient-modules/node-path-only");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&ambient).unwrap();
        std::fs::write(project.join("entry.js"), "module.exports = 1;\n").unwrap();
        std::fs::write(
            ambient.join("package.json"),
            r#"{"name":"node-path-only","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(ambient.join("index.js"), "module.exports = 'ambient';\n").unwrap();

        let project = std::fs::canonicalize(project).unwrap();
        let entry = project.join("entry.js");
        let inputs = AuthenticatedResolverInputs::new(
            project.clone(),
            &test_object_identity(&project),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();
        let error = test_loader()
            .resolve_meta_authenticated("node-path-only", Some(&entry), None, &inputs)
            .expect_err("an ambient package outside the authenticated boundary must be invisible");
        assert!(
            error.to_string().contains("Failed to resolve module"),
            "unexpected ambient-package refusal: {error:#}"
        );
    }

    // ENG-23007: the metadata-only path skips the load that the full resolve
    // performs. For a VALID module, `resolve` populates `source` (read +
    // transpiled) while `resolve_meta` leaves it `None` for the same path.
    #[test]
    fn resolve_meta_omits_source_that_full_resolve_loads() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mod.ts");
        std::fs::write(&file, "export const answer: number = 42;").unwrap();
        let referrer = dir.path().join("entry.ts");

        let loader = test_loader();
        let meta = loader.resolve_meta("./mod", Some(&referrer)).unwrap();
        assert!(
            meta.source.is_none(),
            "resolve_meta must not populate source"
        );

        let full = loader.resolve("./mod", Some(&referrer)).unwrap();
        let source = full.source.expect("full resolve must load source");
        // Transpiled TS: the `: number` annotation is stripped, proving the full
        // path did the read + transpile work that resolve_meta skips.
        assert!(source.contains("answer"));
        assert!(!source.contains(": number"));
        assert_eq!(meta.path, full.path);
    }

    #[test]
    fn resolve_meta_does_not_prefetch_plain_esm_body() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mod.mjs");
        std::fs::write(&file, "export const answer = 42;").unwrap();

        let meta = test_loader()
            .resolve_meta_typed(
                "./mod.mjs",
                Some(&dir.path().join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .unwrap();

        assert_eq!(
            std::fs::canonicalize(meta.path.unwrap()).unwrap(),
            std::fs::canonicalize(file).unwrap()
        );
        assert!(meta.source.is_none(), "resolution must not open ESM source");
    }

    #[test]
    fn file_query_and_fragment_do_not_change_resolved_identity_input() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mod.js");
        std::fs::write(&file, "module.exports = 1;").unwrap();
        let referrer = dir.path().join("entry.js");
        let loader = test_loader();

        let plain = loader.resolve_meta("./mod.js", Some(&referrer)).unwrap();
        let decorated = loader
            .resolve_meta("./mod.js?cache=one#section", Some(&referrer))
            .unwrap();

        assert_eq!(plain.path, decorated.path);
        assert_eq!(plain.id, decorated.id);
    }

    #[test]
    fn windows_verbatim_file_specifier_preserves_namespace_question_mark() {
        let path = r"\\?\D:\a\ibex\entry.mjs";
        assert_eq!(strip_file_specifier_decorations(path), path);
        assert_eq!(
            strip_file_specifier_decorations(r"\\?\D:\a\ibex\entry.mjs?cache=one#section"),
            path
        );
        assert_eq!(
            normalize_windows_verbatim_path_text(path),
            r"D:\a\ibex\entry.mjs"
        );
        assert_eq!(
            normalize_windows_verbatim_path_text(r"\\?\UNC\server\share\entry.mjs"),
            r"\\server\share\entry.mjs"
        );
    }

    #[test]
    fn ambiguous_js_source_goal_follows_authenticated_package_type() {
        let dir = tempdir().unwrap();
        let esm = dir.path().join("esm");
        let cjs = dir.path().join("cjs");
        std::fs::create_dir_all(&esm).unwrap();
        std::fs::create_dir_all(&cjs).unwrap();
        std::fs::write(esm.join("package.json"), r#"{"type":"module"}"#).unwrap();
        std::fs::write(cjs.join("package.json"), r#"{"type":"commonjs"}"#).unwrap();
        std::fs::write(esm.join("value.js"), "export const value = 1;").unwrap();
        std::fs::write(cjs.join("value.js"), "module.exports = 1;").unwrap();
        let loader = test_loader();

        let esm_meta = loader
            .resolve_meta_typed(
                "./value.js",
                Some(&esm.join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .unwrap();
        let cjs_meta = loader
            .resolve_meta_typed(
                "./value.js",
                Some(&cjs.join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .unwrap();

        assert_eq!(esm_meta.kind, ModuleKind::Esm);
        assert_eq!(cjs_meta.kind, ModuleKind::CommonJs);
    }

    #[test]
    fn explicit_mts_source_goal_survives_metadata_only_resolution() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("entry.mts");
        std::fs::write(&file, "await Promise.resolve();").unwrap();
        let loader = test_loader();

        let meta = loader
            .resolve_meta_typed(
                file.to_str().unwrap(),
                None,
                ResolutionKind::Entry,
                &ConditionSet::for_kind(ResolutionKind::Entry),
                &ImportAttributes::default(),
            )
            .unwrap();

        assert_eq!(meta.kind, ModuleKind::Esm);
        let compatibility = loader.load_source(meta).unwrap();
        assert_eq!(compatibility.kind, ModuleKind::CommonJs);
    }

    #[test]
    fn json_import_attributes_are_typed_and_fail_closed() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("value.json"), r#"{"value":1}"#).unwrap();
        std::fs::write(dir.path().join("value.js"), "export const value = 1;").unwrap();
        let referrer = dir.path().join("entry.mjs");
        let loader = test_loader();
        let json_attributes = ImportAttributes::new([("type".into(), "json".into())]).unwrap();

        assert!(loader
            .resolve_meta_typed(
                "./value.json",
                Some(&referrer),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .is_err());
        assert_eq!(
            loader
                .resolve_meta_typed(
                    "./value.json",
                    Some(&referrer),
                    ResolutionKind::EsmStatic,
                    &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                    &json_attributes,
                )
                .unwrap()
                .kind,
            ModuleKind::Json
        );
        assert!(loader
            .resolve_meta_typed(
                "./value.js",
                Some(&referrer),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &json_attributes,
            )
            .is_err());
    }

    #[test]
    fn package_import_condition_prefers_require_over_import() {
        // `require` is the correct branch for the CJS loader; `default` remains
        // the lowest-priority fallback. (ENG-23457)
        let value: Value = serde_json::json!({
            "import": "./esm.mjs",
            "require": "./cjs.js",
            "default": "./browser.js",
        });
        assert_eq!(
            pick_package_import_path(
                &value,
                None,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
            Some("./cjs.js".to_string())
        );
    }

    #[test]
    fn package_import_condition_keeps_import_and_require_separate() {
        let value: Value = serde_json::json!({
            "import": "./esm.mjs",
            "require": "./cjs.js",
            "default": "./fallback.js",
        });
        assert_eq!(
            pick_package_import_path(
                &value,
                None,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
            ),
            Some("./esm.mjs".to_string())
        );
    }

    #[test]
    fn package_import_condition_falls_back_to_default() {
        let value: Value = serde_json::json!({ "default": "./browser.js" });
        assert_eq!(
            pick_package_import_path(
                &value,
                None,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
            Some("./browser.js".to_string())
        );
    }

    #[test]
    fn package_import_wildcard_requires_slash_boundary() {
        // `#internal/*` must match `#internal/thing` but NOT the unrelated
        // sibling `#internal-utils`. (ENG-22949 finding 2a)
        let mut imports = serde_json::Map::new();
        imports.insert(
            "#internal/*".to_string(),
            Value::String("./src/internal/*.js".to_string()),
        );
        assert_eq!(
            resolve_package_import_target(
                "#internal/thing",
                &imports,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
            Some("./src/internal/thing.js".to_string())
        );
        assert_eq!(
            resolve_package_import_target(
                "#internal-utils",
                &imports,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
            None
        );
    }

    #[test]
    fn package_import_wildcard_prefers_longest_prefix() {
        // The most specific (longest-prefix) pattern must win regardless of
        // map iteration order. serde_json iterates keys alphabetically, so
        // `#a/*` sorts before `#a/b/*` — the old first-hit loop picked the
        // wrong one. (ENG-22949 finding 2b)
        let mut imports = serde_json::Map::new();
        imports.insert("#a/*".to_string(), Value::String("./a/*.js".to_string()));
        imports.insert("#a/b/*".to_string(), Value::String("./ab/*.js".to_string()));
        assert_eq!(
            resolve_package_import_target(
                "#a/b/thing",
                &imports,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
            Some("./ab/thing.js".to_string())
        );
        assert_eq!(
            resolve_package_import_target(
                "#a/thing",
                &imports,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
            Some("./a/thing.js".to_string())
        );
    }

    #[test]
    fn unique_tmp_path_is_process_and_call_unique() {
        // The publish tmp name must differ per call and embed the pid so two
        // processes cold-loading the same cache entry never share a tmp inode.
        // (ENG-22949 finding 3)
        let output = Path::new("/tmp/exact-transpile-cache/abc123def.js");
        let a = unique_tmp_path(output);
        let b = unique_tmp_path(output);
        assert_ne!(a, b);
        // Same directory keeps the publishing rename atomic on one filesystem.
        assert_eq!(a.parent(), output.parent());
        let name = a.file_name().unwrap().to_str().unwrap();
        assert!(name.contains(&std::process::id().to_string()));
        assert!(name.ends_with(".tmp"));
    }

    #[test]
    fn transpile_cache_key_tracks_same_length_same_mtime_source_changes() {
        let dir = tempdir().unwrap();
        let entry = dir.path().join("module.ts");
        std::fs::write(&entry, "module.exports = 1").unwrap();
        let environment = CapturedModuleLoaderEnvironment::capture();
        let first = module_cache_key(&entry, "es2015", "module.exports = 1", &environment).unwrap();
        // The two sources have identical length and the file metadata is left
        // untouched between key computations. Content identity must still move.
        let second =
            module_cache_key(&entry, "es2015", "module.exports = 2", &environment).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn subprocess_transpile_consumes_staged_exact_source_across_aba_mutation() {
        if find_js_runner().is_err() {
            return;
        }
        let dir = tempdir().unwrap();
        let tool_dir = dir.path().join("tool");
        std::fs::create_dir(&tool_dir).unwrap();
        let entry = dir.path().join("module.ts");
        let output = dir.path().join("module.js");
        let script = tool_dir.join("transpile.cjs");
        let helper = tool_dir.join("helper.cjs");
        let ready = dir.path().join("ready");
        let release = dir.path().join("release");
        let observed = dir.path().join("observed-entry");
        let quoted = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
        std::fs::write(
            &script,
            format!(
                "const fs=require('fs'); if (!require('./helper.cjs')) throw new Error('missing helper'); const a=process.argv; \
                 const entry=a[a.indexOf('--entry')+1], out=a[a.indexOf('--out')+1]; \
                 fs.writeFileSync({}, entry); fs.writeFileSync({}, ''); \
                 while(!fs.existsSync({})) {{}} \
                 fs.writeFileSync(out, fs.readFileSync(entry));",
                quoted(&observed),
                quoted(&ready),
                quoted(&release),
            ),
        )
        .unwrap();
        std::fs::write(&helper, "module.exports = true;\n").unwrap();
        let script_identity = compute_transpile_override_identity(&script).unwrap();
        let source_a = "export const answer: number = 41;";
        let source_b = "export const answer: number = 99;";
        std::fs::write(&entry, source_a).unwrap();

        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                run_transpile_override(&entry, &output, "es2015", source_a, &script_identity, None)
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !ready.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let reached_barrier = ready.exists();
            if reached_barrier {
                std::fs::write(&entry, source_b).unwrap();
                std::fs::write(&entry, source_a).unwrap();
            }
            // Always release the child before joining. Panicking on the
            // deadline while a scoped child is deliberately blocked on this
            // file makes scope unwinding wait forever.
            std::fs::write(&release, []).unwrap();
            let result = handle.join().unwrap();
            assert!(
                reached_barrier,
                "transpiler did not reach barrier: {result:?}"
            );
            result.unwrap();
        });

        assert_eq!(std::fs::read_to_string(&output).unwrap(), source_a);
        let observed_entry = PathBuf::from(std::fs::read_to_string(&observed).unwrap());
        assert_ne!(observed_entry, entry);
        assert_eq!(
            observed_entry.extension().and_then(OsStr::to_str),
            Some("ts")
        );
        assert!(
            !observed_entry.exists(),
            "staged input must be removed after subprocess exit"
        );
    }

    #[test]
    fn subprocess_transpile_rejects_live_helper_mutation() {
        if find_js_runner().is_err() {
            return;
        }
        let dir = tempdir().unwrap();
        let tool_dir = dir.path().join("tool");
        std::fs::create_dir(&tool_dir).unwrap();
        let entry = dir.path().join("module.ts");
        let output = dir.path().join("module.js");
        let script = tool_dir.join("transpile.cjs");
        let helper = tool_dir.join("helper.cjs");
        let ready = dir.path().join("ready");
        let release = dir.path().join("release");
        let quoted = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
        std::fs::write(
            &script,
            format!(
                "const fs=require('fs'); require('./helper.cjs'); const a=process.argv; \
                 const entry=a[a.indexOf('--entry')+1], out=a[a.indexOf('--out')+1]; \
                 fs.writeFileSync({}, ''); while(!fs.existsSync({})) {{}} \
                 fs.writeFileSync(out, fs.readFileSync(entry));",
                quoted(&ready),
                quoted(&release),
            ),
        )
        .unwrap();
        std::fs::write(&helper, "module.exports = 'old';\n").unwrap();
        std::fs::write(&entry, "export const answer = 42;\n").unwrap();
        let identity = compute_transpile_override_identity(&script).unwrap();

        let error = std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                run_transpile_override(
                    &entry,
                    &output,
                    "es2015",
                    "export const answer = 42;\n",
                    &identity,
                    None,
                )
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !ready.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let reached_barrier = ready.exists();
            if reached_barrier {
                std::fs::write(&helper, "module.exports = 'new';\n").unwrap();
            }
            // See the sibling ABA test: a timeout must not strand the scoped
            // child in its intentional busy-wait.
            std::fs::write(&release, []).unwrap();
            let result = handle.join().unwrap();
            assert!(
                reached_barrier,
                "transpiler did not reach barrier: {result:?}"
            );
            result.unwrap_err()
        });
        assert!(
            error
                .to_string()
                .contains("tool directory changed during this process"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn transpile_cache_rejects_tampered_output() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("artifact");
        std::fs::create_dir(&artifact).unwrap();
        let source = "export const answer: number = 42";
        let output = b"exports.answer = 42;";
        std::fs::write(artifact.join("module.js"), output).unwrap();
        let manifest = TranspileCacheManifest {
            version: 1,
            target: "es2015".into(),
            source_sha256: sha256_hex(source.as_bytes()),
            output_sha256: sha256_hex(output),
        };
        std::fs::write(
            artifact.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(transpile_cache_is_valid(&artifact, "es2015", source).unwrap());
        std::fs::write(artifact.join("module.js"), "exports.answer = 99;").unwrap();
        assert!(!transpile_cache_is_valid(&artifact, "es2015", source).unwrap());
    }

    #[test]
    fn transpile_cache_quota_evicts_old_artifacts_but_keeps_current() {
        let dir = tempdir().unwrap();
        let old = dir.path().join("old");
        let current = dir.path().join("current");
        std::fs::create_dir(&old).unwrap();
        std::fs::write(old.join("module.js"), vec![0u8; 64]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::create_dir(&current).unwrap();
        std::fs::write(current.join("module.js"), vec![0u8; 64]).unwrap();

        prune_transpile_cache_to_limit(dir.path(), &current, 64);
        assert!(!old.exists());
        assert!(current.exists());
    }

    #[test]
    fn concurrent_transpile_publishers_share_one_complete_immutable_artifact() {
        let dir = tempdir().unwrap();
        let entry = dir.path().join("module.ts");
        let artifact = dir.path().join("artifact");
        let source = "export const answer: number = 42;";
        std::fs::write(&entry, source).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
        let environment = CapturedModuleLoaderEnvironment::capture();

        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..12 {
                let barrier = barrier.clone();
                let entry = entry.clone();
                let artifact = artifact.clone();
                let environment = &environment;
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    publish_transpile_artifact(&entry, &artifact, "es2015", source, environment)
                }));
            }
            for handle in handles {
                handle.join().unwrap().unwrap();
            }
        });
        assert!(transpile_cache_is_valid(&artifact, "es2015", source).unwrap());
        assert_eq!(
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
                .count(),
            0,
            "losing publishers must clean their staging directories"
        );
    }

    #[test]
    fn resolves_node_fs_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:fs", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("readFileSync"));
    }

    #[test]
    fn resolves_bun_fs_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("bun:fs", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("readFileSync"));
    }

    #[test]
    fn resolves_fs_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("fs", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("readFileSync"));
    }

    #[test]
    fn resolves_node_fs_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:fs/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("fs.promises"));
    }

    #[test]
    fn resolves_bun_fs_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("bun:fs/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("fs.promises"));
    }

    #[test]
    fn resolves_node_path_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:path", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("dirname"));
    }

    #[test]
    fn resolves_path_builtin_alias() {
        let loader = test_loader();
        let resolved = loader.resolve("path", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("dirname"));
    }

    #[test]
    fn builtin_aliases_have_distinct_ids() {
        let loader = test_loader();
        let path = loader.resolve("path", None).unwrap();
        let node_path = loader.resolve("node:path", None).unwrap();
        let bun_fs = loader.resolve("bun:fs", None).unwrap();
        let bun_fs_promises = loader.resolve("bun:fs/promises", None).unwrap();
        let node_fs = loader.resolve("node:fs", None).unwrap();
        let fs_promises = loader.resolve("node:fs/promises", None).unwrap();
        let process = loader.resolve("process", None).unwrap();
        let node_process = loader.resolve("node:process", None).unwrap();

        assert_ne!(path.id, node_path.id);
        assert_ne!(process.id, node_process.id);
        assert_ne!(bun_fs.id, node_fs.id);
        assert_ne!(bun_fs_promises.id, fs_promises.id);

        assert_eq!(path.source, node_path.source);
        assert_eq!(process.source, node_process.source);
        assert_eq!(bun_fs.source, node_fs.source);
        assert_eq!(bun_fs_promises.source, fs_promises.source);

        assert_eq!(path.source_id.as_ref(), node_path.source_id.as_ref());
        assert_eq!(process.source_id.as_ref(), node_process.source_id.as_ref());
        assert_eq!(bun_fs.source_id.as_ref(), node_fs.source_id.as_ref());
        assert_eq!(
            bun_fs_promises.source_id.as_ref(),
            fs_promises.source_id.as_ref()
        );
        assert_eq!(
            path.artifact_source_id.as_ref(),
            node_path.artifact_source_id.as_ref()
        );
        assert_eq!(
            process.artifact_source_id.as_ref(),
            node_process.artifact_source_id.as_ref()
        );
        assert_eq!(
            bun_fs.artifact_source_id.as_ref(),
            node_fs.artifact_source_id.as_ref()
        );
        assert_eq!(
            bun_fs_promises.artifact_source_id.as_ref(),
            fs_promises.artifact_source_id.as_ref()
        );
        assert!(path
            .source_id
            .as_ref()
            .unwrap()
            .cache_key()
            .starts_with("ibex-source-id-v1:"));
        assert!(path
            .artifact_source_id
            .as_ref()
            .unwrap()
            .encode()
            .unwrap()
            .starts_with("ibex-source-id-v1:"));
    }

    #[test]
    fn resolves_bun_sqlite_aliases_exact_sqlite() {
        let loader = test_loader();
        let exact_sqlite = loader.resolve("exact:sqlite", None).unwrap();
        let bun_sqlite = loader.resolve("bun:sqlite", None).unwrap();
        assert_eq!(exact_sqlite.kind, ModuleKind::Builtin);
        assert_eq!(bun_sqlite.kind, ModuleKind::Builtin);
        assert_eq!(exact_sqlite.source.as_deref(), bun_sqlite.source.as_deref());
        let exact_source = exact_sqlite.source.expect("exact:sqlite source");
        assert!(exact_source.contains("__exactSqliteOpen"));
    }

    #[test]
    fn resolves_node_process_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:process", None).unwrap();
        let source = resolved.source.unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(source.contains("function cwd"));
        assert!(source.contains("function chdir"));
    }

    #[test]
    fn resolves_process_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("process", None).unwrap();
        let source = resolved.source.unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(source.contains("function cwd"));
        assert!(source.contains("function chdir"));
    }

    #[test]
    fn resolves_node_async_hooks_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:async_hooks", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("AsyncLocalStorage"));
        assert!(source.contains("createHook"));
    }

    #[test]
    fn resolves_async_hooks_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("async_hooks", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("AsyncLocalStorage"));
    }

    #[test]
    fn resolves_node_crypto_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:crypto", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("randomBytes"));
    }

    #[test]
    fn resolves_crypto_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("crypto", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("randomBytes"));
    }

    #[test]
    fn resolves_node_events_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:events", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("EventEmitter"));
        assert!(source.contains("setMaxListeners"));
        assert!(source.contains("getMaxListeners"));
        assert!(source.contains("module.exports.default = EventEmitter"));
    }

    #[test]
    fn resolves_events_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("events", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("EventEmitter"));
    }

    #[test]
    fn resolves_node_stream_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:stream", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("PassThrough"));
    }

    #[test]
    fn resolves_stream_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("stream", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("PassThrough"));
    }

    #[test]
    fn resolves_node_stream_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:stream/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("pipeline"));
    }

    #[test]
    fn resolves_stream_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("stream/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("pipeline"));
    }

    #[test]
    fn resolves_node_buffer_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:buffer", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("toByteArray"));
        assert!(source.contains("BufferProto"));
    }

    #[test]
    fn resolves_buffer_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("buffer", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("Buffer.from"));
        assert!(source.contains("Buffer.alloc"));
    }

    #[test]
    fn resolves_node_util_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:util", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("util ="));
    }

    #[test]
    fn resolves_util_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("util", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("promisify"));
        assert!(source.contains("format"));
    }

    #[test]
    fn resolves_node_timers_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:timers", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("setTimeout"));
        assert!(source.contains("setImmediate"));
    }

    #[test]
    fn resolves_timers_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("timers", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("clearInterval"));
    }

    #[test]
    fn resolves_node_timers_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:timers/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("setTimeout"));
        assert!(source.contains("setImmediate"));
    }

    #[test]
    fn resolves_node_stream_web_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:stream/web", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("fromWeb"));
        assert!(source.contains("toWeb"));
    }

    #[test]
    fn resolves_stream_web_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("stream/web", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("ReadableStream"));
        assert!(source.contains("WritableStream"));
    }

    #[test]
    fn stream_web_aliases_share_source() {
        let loader = test_loader();
        let node_stream_web = loader.resolve("node:stream/web", None).unwrap();
        let stream_web = loader.resolve("stream/web", None).unwrap();
        assert_eq!(node_stream_web.id, "node:stream/web");
        assert_eq!(stream_web.id, "stream/web");
        assert_ne!(node_stream_web.id, stream_web.id);
        assert_eq!(node_stream_web.source, stream_web.source);
    }

    #[test]
    fn resolves_node_http_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:http", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("ClientRequest"));
        assert!(source.contains("IncomingMessage"));
    }

    #[test]
    fn resolves_http_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("http", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("request"));
    }

    #[test]
    fn resolves_node_https_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:https", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        let resolved_http = loader.resolve("http", None).unwrap();
        assert_ne!(source, resolved_http.source.unwrap());
        assert!(source.contains("tls.connect"));
        assert!(source.contains("createServer"));
    }

    #[test]
    fn resolves_node_url_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:url", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("fileURLToPath"));
        assert!(source.contains("pathToFileURL"));
    }

    #[test]
    fn resolves_url_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("url", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("require('node:url')"));
        assert!(source.contains("Object.getOwnPropertyDescriptors"));
    }

    #[test]
    fn url_aliases_use_distinct_sources() {
        let loader = test_loader();
        let node_url = loader.resolve("node:url", None).unwrap();
        let url = loader.resolve("url", None).unwrap();
        assert_eq!(node_url.id, "node:url");
        assert_eq!(url.id, "url");
        assert_ne!(node_url.id, url.id);
        assert_ne!(node_url.source, url.source);
    }

    #[test]
    fn resolves_transpiled_typescript_module() {
        let dir = tempdir().unwrap();
        let ts_file = dir.path().join("mod.ts");
        let tsx_file = dir.path().join("mod.tsx");
        let jsx_file = dir.path().join("mod.jsx");
        std::fs::write(&ts_file, "export const value: number = 42;").unwrap();
        std::fs::write(
            &tsx_file,
            "export const label: string = \"ts-x\";\nexport const value: number = 21;\n",
        )
        .unwrap();
        std::fs::write(
            &jsx_file,
            r#"
var React = { createElement: function() { return "jsx"; } };
export const value = <span />;
"#,
        )
        .unwrap();

        let loader = test_loader();

        let resolved = loader
            .resolve("./mod", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let source = resolved.source.unwrap();
        assert_eq!(resolved.kind, ModuleKind::CommonJs);
        assert!(
            !source.contains("export const"),
            "esm exports lowered: {source}"
        );
        assert!(source.contains("value"), "export wiring present: {source}");
        assert!(!source.contains(": number"), "types stripped: {source}");

        let resolved_tsx = loader
            .resolve("./mod.tsx", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let tsx_source = resolved_tsx.source.unwrap();
        assert_eq!(resolved_tsx.kind, ModuleKind::CommonJs);
        assert!(
            !tsx_source.contains("export const"),
            "esm exports lowered: {tsx_source}"
        );
        assert!(
            tsx_source.contains("value"),
            "export wiring present: {tsx_source}"
        );
        assert!(!tsx_source.contains(": number"));

        let resolved_jsx = loader
            .resolve("./mod.jsx", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let jsx_source = resolved_jsx.source.unwrap();
        assert_eq!(resolved_jsx.kind, ModuleKind::CommonJs);
        assert!(
            !jsx_source.contains("export const"),
            "esm exports lowered: {jsx_source}"
        );
        assert!(
            jsx_source.contains("value"),
            "export wiring present: {jsx_source}"
        );
        assert!(jsx_source.contains("createElement"));
        assert!(!jsx_source.contains("<span"));
    }

    #[test]
    fn detects_async_generator_method_js_for_downleveling() {
        let source = r#"
const asyncIterable = {
    async* [Symbol.asyncIterator]() {
        yield 'a';
    }
};
"#;

        assert!(ModuleLoader::source_needs_async_downlevel(source));
        assert!(ModuleLoader::needs_js_downlevel(
            std::path::Path::new("fixture.js"),
            source
        ));
        assert!(ModuleLoader::needs_js_downlevel(
            std::path::Path::new("bundle.js"),
            source
        ));
        // Runtime bundles may contain top-level syntax that is legal only in
        // their wrapper, so plain bundles remain exempt. The exemption must be
        // content-aware: a bundle that actually contains unsupported syntax is
        // still lowered before Hermes sees it.
        assert!(!ModuleLoader::needs_js_downlevel(
            std::path::Path::new("bundle.js"),
            "return (function () { return 42; })();"
        ));
    }

    #[test]
    fn detects_using_declarations_after_other_tokens_on_the_same_line() {
        assert!(ModuleLoader::source_needs_async_downlevel(
            "initialize(); using resource = acquire();"
        ));
        assert!(ModuleLoader::source_needs_async_downlevel(
            "if (ready) { using resource = acquire(); }"
        ));
        assert!(ModuleLoader::source_needs_async_downlevel(
            "initialize(); await using resource = acquireAsync();"
        ));
        assert!(!ModuleLoader::source_needs_async_downlevel(
            "const amusing = true;"
        ));
    }

    #[test]
    fn skips_for_of_loops_when_selecting_loop_scope_downlevel_target() {
        let source = r#"
const values = [1, 2, 3];
for (const value of values) {
    queue.push(() => value);
}
"#;

        assert!(ModuleLoader::source_needs_for_of_scoping_fix(source));
        assert!(!ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es2015");
    }

    #[test]
    fn detects_destructured_for_of_loops_for_es2015_scoping_fix() {
        let source = r#"
const cases = [{ value: 1 }, { value: 2 }];
for (const { value } of cases) {
    setTimeout(() => write(value), 0);
}
"#;

        assert!(ModuleLoader::source_needs_for_of_scoping_fix(source));
        assert!(!ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es2015");
    }

    #[test]
    fn keeps_for_of_loops_with_closures_and_continue_on_es5_fallback_path() {
        let source = r#"
const cases = [{ skip: false, filePath: 'a' }, { skip: false, filePath: 'b' }];
for (const testCase of cases) {
    if (testCase.skip) continue;
    setInterval(() => {
        write(testCase.filePath);
    }, 100);
}
"#;

        assert!(ModuleLoader::source_needs_for_of_scoping_fix(source));
        assert!(ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es5");
    }

    #[test]
    fn keeps_classic_let_for_loops_with_closures_on_es5_fallback_path() {
        let source = r#"
const queue = [];
for (let i = 0; i < 3; i++) {
    queue.push(() => i);
}
"#;

        assert!(ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es5");
    }

    #[test]
    fn skips_classic_let_for_loops_without_closures() {
        let source = r#"
const a = {};
for (let i = 0; i < 3; i++) {
    a[`key${i}`] = i;
}
"#;

        assert!(!ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es2015");
    }

    #[test]
    fn skips_unknown_manifest_source_keys() {
        let registrations = [
            BuiltinManifestRegistration {
                specifier: "node:process",
                source_key: "exact_process",
            },
            BuiltinManifestRegistration {
                specifier: "node:broken",
                source_key: "missing_source_key",
            },
        ];

        let builtins = build_builtin_registry(&registrations);
        assert!(builtins.contains_key("node:process"));
        assert!(!builtins.contains_key("node:broken"));
    }

    #[test]
    fn file_module_decorations_strip_without_rewriting_package_syntax() {
        for (decorated, expected) in [
            ("./x.js?v=1", "./x.js"),
            ("../x.js#fragment", "../x.js"),
            ("/project/x.js?v=1#fragment", "/project/x.js"),
            ("file:///project/x.js#fragment", "file:///project/x.js"),
            (r"C:\project\x.js?v=1", r"C:\project\x.js"),
            (r"\\server\share\x.js#fragment", r"\\server\share\x.js"),
            (r"\\?\C:\project\x.js?v=1", r"\\?\C:\project\x.js"),
            (
                r"\\?\UNC\server\share\x.js#fragment",
                r"\\?\UNC\server\share\x.js",
            ),
            ("//?/C:/project/x.js?v=1", "//?/C:/project/x.js"),
        ] {
            assert_eq!(strip_file_module_decorations(decorated), expected);
        }
        for untouched in [
            "pkg?v=1",
            "node:fs#fragment",
            "#internal",
            "@scope/pkg/x?v=1",
        ] {
            assert_eq!(strip_file_module_decorations(untouched), untouched);
        }
    }

    #[test]
    fn decorated_relative_file_requests_resolve_to_one_native_entry() {
        let dir = tempdir().unwrap();
        let entry = dir.path().join("entry.js");
        let module = dir.path().join("module.js");
        std::fs::write(&entry, "").unwrap();
        std::fs::write(&module, "module.exports = 1;\n").unwrap();
        let loader = test_loader();

        let plain = loader.resolve_meta("./module.js", Some(&entry)).unwrap();
        let query = loader
            .resolve_meta("./module.js?v=1", Some(&entry))
            .unwrap();
        let fragment = loader
            .resolve_meta("./module.js#fragment", Some(&entry))
            .unwrap();
        assert_eq!(plain.path, query.path);
        assert_eq!(plain.path, fragment.path);
        assert_eq!(plain.id, query.id);
        assert_eq!(plain.id, fragment.id);
    }

    #[test]
    fn authenticated_cache_route_skips_repeat_resolver_lookup() {
        let (runner, _) = find_js_runner().expect("JavaScript runner");
        let loader_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine/bootstrap/module-loader.js");
        let loader_path = serde_json::to_string(loader_path.to_str().unwrap()).unwrap();
        let script = r#"
const fs = require('fs');
const loader = fs.readFileSync(__LOADER_PATH__, 'utf8');
let dispatch = null;
let dependencyResolves = 0;
let importChecks = [];
let currentCwd = '/project';
globalThis.__exactHasSharedRuntimeBundle = true;
globalThis.__exactCaptureSessionStaticImport = function(fn) {
  dispatch = fn;
  return {
    resolve: nativeResolve,
    resolveMeta: nativeResolve
  };
};
globalThis.__exactGetCwd = function() { return currentCwd; };
globalThis.__exactCheckImport = function(hint, specifier, targetSourceId, resolutionKind) {
  importChecks.push([hint, specifier, targetSourceId, resolutionKind]);
  return true;
};
function logical(path) {
  return {
    schema: 'ibex/logical-path/1',
    sessionHandle: 'mrs0123456789abcdef',
    virtualPath: path,
    logicalPath: {
      root: 'project',
      components: path.slice(9).split('/').filter(Boolean).map(function(value) {
        return { encoding: 'utf8', value: value };
      }),
      hostBound: null
    },
    bindingOwner: null
  };
}
let nativeResolve = function(specifier) {
  if (specifier !== './dep space.js') throw new Error('unexpected resolver request: ' + specifier);
  dependencyResolves++;
  return JSON.stringify({
    schema: 'ibex/module-resolution/1',
    id: '/project/dep space.js',
    kind: 'cjs',
    path: logical('/project/dep space.js'),
    pkgName: null,
    pkgRoot: null,
    pkgVersion: null,
    pkgIntegrity: null,
    source: 'globalThis.__depRuns=(globalThis.__depRuns||0)+1;module.exports={run:globalThis.__depRuns,meta:import.meta.url,where:function(){throw new Error("label");}};',
    sourceId: 'ibex-source-id-v1:dep',
    sourceLabel: 'file:///project/dep%20space.js',
    virtualPath: '/project/dep space.js'
  });
};
globalThis.__exactNativeModuleResolve = nativeResolve;
globalThis.__exactNativeModuleResolveMeta = nativeResolve;
(0, eval)(loader);
dispatch('reserve-entry', 'ibex-source-id-v1:entry', 'file:///project/entry.js', '/project/entry.js');
dispatch(
  'evaluate-commonjs-entry',
  'var a=require("./dep space.js?v=1");var b=require("./dep space.js#fragment");globalThis.__memoResult=[a===b,a.run,b.run,a.meta];',
  'file:///project/entry.js',
  '/project/entry.js',
  JSON.stringify(logical('/project/entry.js'))
);
dispatch('commit-entry');
var topOne = globalThis.require('./dep space.js?v=top');
var topTwo = globalThis.require('./dep space.js#top');
currentCwd = '/project/other';
var afterCwdChange = globalThis.require('./dep space.js?v=other-cwd');
var labelStack = '';
try { topOne.where(); } catch (error) { labelStack = String(error && error.stack || error); }
var cacheHitChecks = importChecks.filter(function(row) {
  return typeof row[2] === 'string';
});
if (dependencyResolves !== 3 || globalThis.__depRuns !== 1 ||
    String(globalThis.__memoResult) !== 'true,1,1,file:///project/dep%20space.js' ||
    topOne !== topTwo || topOne !== afterCwdChange ||
    JSON.stringify(cacheHitChecks) !== JSON.stringify([
      [0, './dep space.js', 'ibex-source-id-v1:dep', 0],
      [0, './dep space.js', 'ibex-source-id-v1:dep', 0]
    ]) ||
    labelStack.indexOf('file:///project/dep%20space.js') === -1) {
  throw new Error(JSON.stringify({
    dependencyResolves: dependencyResolves,
    runs: globalThis.__depRuns,
    result: globalThis.__memoResult,
    topSame: topOne === topTwo,
    cwdSame: topOne === afterCwdChange,
    importChecks: importChecks,
    labelStack: labelStack
  }));
}
fs.writeFileSync(__MARKER_PATH__, 'authenticated-cache-route-ok');
"#
        .replace("__LOADER_PATH__", &loader_path);
        let fixture = tempdir().unwrap();
        let script_path = fixture.path().join("authenticated-cache-route.cjs");
        let marker_path = fixture.path().join("authenticated-cache-route.ok");
        let marker_literal = serde_json::to_string(marker_path.to_str().unwrap()).unwrap();
        let script = script.replace("__MARKER_PATH__", &marker_literal);
        std::fs::write(&script_path, script).unwrap();
        let output = Command::new(&runner)
            .arg(&script_path)
            .output()
            .expect("run module-loader cache fixture");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "cache fixture failed with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            runner.display()
        );
        assert_eq!(
            std::fs::read_to_string(marker_path).unwrap(),
            "authenticated-cache-route-ok"
        );
    }

    #[test]
    fn dynamic_import_transform_does_not_copy_the_source_suffix_per_character() {
        let loader_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine/bootstrap/module-loader.js");
        let loader = std::fs::read_to_string(loader_path).expect("read module loader");
        assert!(
            !loader.contains("var lowered = source.slice(i).match("),
            "dynamic-import scanning must not materialize the remaining source at every index"
        );
        assert!(
            !loader.contains("var rest = source.slice(i);"),
            "dynamic-import scanning must not retain the quadratic suffix-copy path"
        );
        assert!(
            loader.contains("indexAfterLoweredDynamicImport")
                && loader.contains("indexAfterDynamicImport"),
            "dynamic-import scanning must use the index-based recognizers"
        );
    }

    #[test]
    fn dev_served_module_table_is_one_shot_gated_and_falls_back_to_native() {
        let (runner, _) = find_js_runner().expect("JavaScript runner");
        let loader_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine/bootstrap/module-loader.js");
        let loader_path = serde_json::to_string(loader_path.to_str().unwrap()).unwrap();
        let fixture = tempdir().unwrap();
        let scenarios = [
            "success",
            "non-frozen",
            "malformed",
            "repeated",
            "late",
            "unconsumed-finish",
            "hot-revision-retired",
        ];
        for scenario in scenarios {
            let script = r#"
const fs = require('fs');
const loader = fs.readFileSync(__LOADER_PATH__, 'utf8');
let nativeResolves = 0;
let importChecks = 0;
let quarantines = 0;
let lifecycle = null;
let hotRevisionInvalidator = null;
globalThis.__exactHasSharedRuntimeBundle = true;
globalThis.__exactCompatModes = Object.freeze(['dev-served']);
globalThis.__exactCaptureSessionStaticImport = function() {
  return { resolve: nativeResolve, resolveMeta: nativeResolve };
};
globalThis.__exactCheckImport = function(specifier, requester) {
  importChecks++;
  return specifier !== '.vite' &&
    (typeof specifier !== 'string' || specifier.indexOf('/chunk.js') === -1) &&
    (specifier !== './chunk.js' || requester === 0);
};
globalThis.__exactQuarantineDevServedModuleTable = function() { quarantines++; };
globalThis.__exactCaptureDevServedModuleTableLifecycle = function(value) {
  if (lifecycle !== null || typeof value !== 'function') return false;
  lifecycle = value;
  return true;
};
globalThis.__exactCaptureHotRevisionRecordInvalidator = function(value) {
  if (hotRevisionInvalidator !== null || typeof value !== 'function') return false;
  hotRevisionInvalidator = value;
  return true;
};
function nativeResolve(specifier) {
  nativeResolves++;
  if (specifier !== 'fallback') throw new Error('unexpected native resolve: ' + specifier);
  return JSON.stringify({
    schema: 'ibex/module-resolution/1',
    id: 'fallback',
    kind: 'builtin',
    source: 'module.exports=9;',
    sourceId: 'ibex-source-id-v1:fallback'
  });
}
globalThis.__exactNativeModuleResolve = nativeResolve;
globalThis.__exactNativeModuleResolveMeta = nativeResolve;
(0, eval)(loader);
if (typeof lifecycle !== 'function' || lifecycle('begin') !== true) {
  throw new Error('dev-served lifecycle did not begin');
}
const capture = globalThis.__ibexCaptureDevServedModuleTable;
const table = {
  '/src/entry.js': {id:'/src/entry.js',kind:'cjs',path:'/src/entry.js',source:'const dep=require("./dep");const optimized=require("/node_modules/.vite/native/react.js");const asset=require("./asset.txt?url");module.exports={value:dep.value,runs:dep.runs,optimized:optimized,asset:asset,lazy:function(){return import("./lazy");}};'},
  '/src/dep.ts': {id:'/src/dep.ts',kind:'cjs',path:'/src/dep.ts',source:'globalThis.__devRuns=(globalThis.__devRuns||0)+1;module.exports={value:41,runs:globalThis.__devRuns};'},
  '/src/lazy.ts': {id:'/src/lazy.ts',kind:'cjs',path:'/src/lazy.ts',source:'module.exports={value:42};'},
  '/src/asset.txt?url': {id:'/src/asset.txt?url',kind:'cjs',path:'/src/asset.txt?url',source:'module.exports="/src/asset.txt";'},
  '/node_modules/.vite/native/react.js': {id:'/node_modules/.vite/native/react.js',kind:'cjs',path:'/node_modules/.vite/native/react.js',source:'module.exports=require("/node_modules/.vite/native/chunk.js");'},
  '/node_modules/.vite/native/chunk.js': {id:'/node_modules/.vite/native/chunk.js',kind:'cjs',path:'/node_modules/.vite/native/chunk.js',source:'module.exports="optimized";'}
};
const scenario = __SCENARIO__;
function freezeTable(value) {
  Object.keys(value).forEach(function(id) { Object.freeze(value[id]); });
  return Object.freeze(value);
}
function expectQuarantine(action) {
  let threw = false;
  try { action(); } catch (_error) { threw = true; }
  if (!threw || quarantines !== 1) throw new Error('expected one quarantine');
}
if (scenario === 'success') {
  if (capture(freezeTable(table)) !== true) throw new Error('capture failed');
  const first = globalThis.require('/src/entry.js');
  const second = globalThis.require('/src/entry.js?v=123');
  const fallback = globalThis.require('fallback');
  if (first !== second || first.value !== 41 || first.runs !== 1 ||
      first.optimized !== 'optimized' || first.asset !== '/src/asset.txt' || fallback !== 9 ||
      nativeResolves !== 1 || importChecks < 5 ||
      typeof globalThis.__ibexCaptureDevServedModuleTable !== 'undefined') {
    throw new Error(JSON.stringify({first, second, fallback, nativeResolves, importChecks}));
  }
  first.lazy().then(function(lazy) {
    if (!lazy || !lazy.default || lazy.default.value !== 42 || nativeResolves !== 1) {
      throw new Error(JSON.stringify({lazy, nativeResolves}));
    }
  }).catch(function(error) {
    console.error(error && error.stack ? error.stack : error);
    process.exitCode = 1;
  });
} else if (scenario === 'non-frozen') {
  expectQuarantine(function() { capture(table); });
} else if (scenario === 'malformed') {
  table['/src/dep.ts'] = Object.freeze({id:'wrong',kind:'cjs',path:'/src/dep.ts',source:''});
  expectQuarantine(function() { capture(freezeTable(table)); });
} else if (scenario === 'repeated') {
  const frozen = freezeTable(table);
  capture(frozen);
  expectQuarantine(function() { capture(frozen); });
} else if (scenario === 'late') {
  lifecycle('mark-run-app');
  expectQuarantine(function() { capture(freezeTable(table)); });
} else if (scenario === 'unconsumed-finish') {
  lifecycle('finish');
  if (typeof globalThis.__ibexCaptureDevServedModuleTable !== 'undefined') {
    throw new Error('finish retained the unconsumed capture hook');
  }
} else if (scenario === 'hot-revision-retired') {
  if (capture(freezeTable(table)) !== true) throw new Error('capture failed');
  const cacheKey = '/src/dep.ts';
  const first = globalThis.require(cacheKey);
  if (first.value !== 41 || first.runs !== 1 ||
      typeof hotRevisionInvalidator !== 'function') {
    throw new Error('real dev-served record did not populate the loader cache');
  }
  if (hotRevisionInvalidator([cacheKey], [cacheKey]) !== true) {
    throw new Error('hot-revision invalidation failed');
  }
  let retiredError = null;
  try { globalThis.require(cacheKey); } catch (error) { retiredError = error; }
  if (!retiredError || retiredError.message !==
      'dev-served module was replaced by a hot revision and cannot re-serve boot bytes' ||
      quarantines !== 0 || globalThis.__devRuns !== 1 || nativeResolves !== 0) {
    throw new Error(JSON.stringify({
      retiredError: retiredError && retiredError.message,
      quarantines: quarantines,
      runs: globalThis.__devRuns,
      nativeResolves: nativeResolves
    }));
  }
}
"#
            .replace("__LOADER_PATH__", &loader_path)
            .replace("__SCENARIO__", &serde_json::to_string(scenario).unwrap());
            let script_path = fixture.path().join(format!("dev-served-{scenario}.cjs"));
            std::fs::write(&script_path, script).unwrap();
            let output = Command::new(&runner)
                .arg(&script_path)
                .output()
                .expect("run dev-served module-table fixture");
            assert!(
                output.status.success(),
                "dev-served fixture {scenario} failed with {}\nstdout:\n{}\nstderr:\n{}",
                runner.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn diagnostic_loader_observes_a_late_exact_resolver_replacement() {
        let (runner, _) = find_js_runner().expect("JavaScript runner");
        let loader_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine/bootstrap/module-loader.js");
        let loader_path = serde_json::to_string(loader_path.to_str().unwrap()).unwrap();
        let fixture = tempdir().unwrap();
        let script = r#"
const fs = require('fs');
const loader = fs.readFileSync(__LOADER_PATH__, 'utf8');
globalThis.__exactHasSharedRuntimeBundle = true;
globalThis.__exactModuleResolve = function() {
  return JSON.stringify({id:'old',kind:'cjs',source:'module.exports=1;'});
};
globalThis.__exactNativeModuleResolve = globalThis.__exactModuleResolve;
(0, eval)(loader);
let lateSpecifier = '';
globalThis.__exactModuleResolve = function(specifier) {
  lateSpecifier = specifier;
  if (specifier !== '/src/entry.js?url') {
    return JSON.stringify({error:'late resolver lost Vite query: ' + specifier});
  }
  return JSON.stringify({id:specifier,kind:'cjs',source:'module.exports=42;'});
};
if (globalThis.require('/src/entry.js?url') !== 42 ||
    lateSpecifier !== '/src/entry.js?url') {
  throw new Error('diagnostic loader retained the construction-time resolver or lost the Vite query');
}
"#
        .replace("__LOADER_PATH__", &loader_path);
        let script_path = fixture.path().join("diagnostic-late-resolver.cjs");
        std::fs::write(&script_path, script).unwrap();
        let output = Command::new(&runner)
            .arg(&script_path)
            .output()
            .expect("run diagnostic late-resolver fixture");
        assert!(
            output.status.success(),
            "diagnostic late-resolver fixture failed with {}\nstdout:\n{}\nstderr:\n{}",
            runner.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn resolves_directory_import_to_index_ts() {
        // @ref LLP 0004#resolution-order
        let dir = tempdir().unwrap();
        let native = dir.path().join("native");
        std::fs::create_dir_all(&native).unwrap();
        std::fs::write(native.join("index.ts"), "export const ok = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve_meta("./native", Some(&dir.path().join("entry.ts")))
            .unwrap();
        assert!(resolved.path.unwrap().ends_with("native/index.ts"));

        let abs = native.to_string_lossy().to_string();
        let resolved_abs = loader.resolve_meta(&abs, None).unwrap();
        assert!(resolved_abs.path.unwrap().ends_with("native/index.ts"));
    }

    #[test]
    fn resolves_referrer_relative_path_without_dot_prefix() {
        // Native hosts pass entry paths like "packages/ibex-runtime-js/src/native"
        // without a leading "./". @ref LLP 0004#resolution-order
        let dir = tempdir().unwrap();
        let nested = dir
            .path()
            .join("packages")
            .join("demo")
            .join("src")
            .join("native");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("index.ts"), "export const ok = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve_meta("packages/demo/src/native", Some(dir.path()))
            .unwrap();
        assert!(resolved
            .path
            .unwrap()
            .ends_with("packages/demo/src/native/index.ts"));

        // A genuinely-bare specifier still reports the original failure.
        let err = loader
            .resolve_meta("definitely-not-a-package", Some(dir.path()))
            .unwrap_err();
        assert!(err.to_string().contains("definitely-not-a-package"));
    }

    #[test]
    fn resolves_ts_style_js_specifier_to_ts_source() {
        // TS NodeNext convention: "../x.js" written in TS resolves to ../x.ts.
        // @ref LLP 0004#the-oxc_resolver-configuration
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("bootstrap.ts"), "export const b = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve_meta("./bootstrap.js", Some(&dir.path().join("entry.ts")))
            .unwrap();
        assert!(resolved.path.unwrap().ends_with("bootstrap.ts"));
    }

    #[test]
    fn extension_alias_prefers_real_js_over_ts() {
        // @ref LLP 0004#the-oxc_resolver-configuration
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("both.js"), "module.exports = 1;").unwrap();
        std::fs::write(dir.path().join("both.ts"), "export const b = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve_meta("./both.js", Some(&dir.path().join("entry.ts")))
            .unwrap();
        assert!(resolved.path.unwrap().ends_with("both.js"));
    }

    #[test]
    fn resolves_exports_import_only() {
        let dir = tempdir().unwrap();
        let node_modules = dir.path().join("node_modules");
        let pkg_dir = node_modules.join("exports-import-only");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{ "exports": { "import": "./esm.js" } }"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("esm.js"), "export const ok = true;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve_meta_typed(
                "exports-import-only",
                Some(&dir.path().join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .unwrap();
        assert!(resolved
            .path
            .unwrap()
            .ends_with("node_modules/exports-import-only/esm.js"));
    }

    #[test]
    fn bound_package_resolution_never_selects_an_ambient_package() {
        let dir = tempdir().unwrap();
        let authenticated = dir.path().join("authenticated/pkg");
        let ambient = dir.path().join("app/node_modules/pkg");
        std::fs::create_dir_all(&authenticated).unwrap();
        std::fs::create_dir_all(&ambient).unwrap();
        let authenticated = std::fs::canonicalize(authenticated).unwrap();
        std::fs::write(
            authenticated.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(authenticated.join("index.js"), "module.exports = 'auth';").unwrap();
        std::fs::write(
            ambient.join("package.json"),
            r#"{"name":"pkg","version":"9.0.0","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(ambient.join("index.js"), "module.exports = 'ambient';").unwrap();

        let resolved = test_loader()
            .resolve_meta_from_bound_package("pkg", "pkg", &authenticated)
            .unwrap();
        assert_eq!(
            resolved.path.as_deref(),
            Some(authenticated.join("index.js").as_path())
        );
        assert_eq!(
            resolved.package_root.as_deref(),
            Some(authenticated.as_path())
        );
        assert_eq!(resolved.package_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn bound_package_resolution_preserves_exports_encapsulation() {
        let dir = tempdir().unwrap();
        let authenticated = dir.path().join("pkg");
        std::fs::create_dir_all(&authenticated).unwrap();
        let authenticated = std::fs::canonicalize(authenticated).unwrap();
        std::fs::write(
            authenticated.join("package.json"),
            r#"{"name":"pkg","exports":{".":"./public.js"}}"#,
        )
        .unwrap();
        std::fs::write(
            authenticated.join("public.js"),
            "module.exports = 'public';",
        )
        .unwrap();
        std::fs::write(
            authenticated.join("private.js"),
            "module.exports = 'private';",
        )
        .unwrap();

        let loader = test_loader();
        let public = loader
            .resolve_meta_from_bound_package("pkg", "pkg", &authenticated)
            .unwrap();
        assert_eq!(
            public.path.as_deref(),
            Some(authenticated.join("public.js").as_path())
        );
        assert!(loader
            .resolve_meta_from_bound_package("pkg/private", "pkg", &authenticated)
            .is_err());
    }

    #[test]
    fn manifest_registrations_resolve_as_builtins() {
        let loader = test_loader();

        for registration in BUILTIN_MANIFEST_REGISTRATIONS {
            let resolved = loader.resolve(registration.specifier, None).unwrap();
            assert_eq!(
                resolved.kind,
                ModuleKind::Builtin,
                "{}",
                registration.specifier
            );
        }
    }

    #[test]
    fn builtin_debug_entries_cover_manifest_registrations() {
        assert_eq!(
            BUILTIN_MANIFEST_DEBUG_ENTRIES.len(),
            BUILTIN_MANIFEST_REGISTRATIONS.len()
        );

        for (debug, registration) in BUILTIN_MANIFEST_DEBUG_ENTRIES
            .iter()
            .zip(BUILTIN_MANIFEST_REGISTRATIONS.iter())
        {
            assert_eq!(debug.specifier, registration.specifier);
            assert_eq!(debug.source_key, registration.source_key);
        }
    }

    #[test]
    fn manifest_aliases_share_sources_and_keep_distinct_ids() {
        let loader = test_loader();
        let mut registrations_by_source: HashMap<&str, Vec<&str>> = HashMap::new();

        for registration in BUILTIN_MANIFEST_REGISTRATIONS {
            registrations_by_source
                .entry(registration.source_key)
                .or_default()
                .push(registration.specifier);
        }

        for specifiers in registrations_by_source.values() {
            if specifiers.len() < 2 {
                continue;
            }

            let first = loader.resolve(specifiers[0], None).unwrap();
            let first_source = first.source.clone();
            let first_source_id = first.source_id.clone();

            for specifier in &specifiers[1..] {
                let resolved = loader.resolve(specifier, None).unwrap();
                assert_ne!(resolved.id, first.id, "{}", specifier);
                assert_eq!(resolved.source, first_source, "{}", specifier);
                assert_eq!(resolved.source_id, first_source_id, "{}", specifier);
            }
        }
    }

    #[test]
    fn builtin_registry_aliases_borrow_one_embedded_source() {
        let loader = test_loader();
        let fs = loader.builtins.get("fs").unwrap();
        let node_fs = loader.builtins.get("node:fs").unwrap();
        let bun_fs = loader.builtins.get("bun:fs").unwrap();

        assert_eq!(fs.source_key, "node_fs");
        assert!(std::ptr::eq(fs.source, node_fs.source));
        assert!(std::ptr::eq(fs.source, bun_fs.source));
    }

    // @ref LLP 0014#the-grant-channel — package/root trust classification must
    // come from resolver/package metadata, not only the post-resolution path
    // shape: linked dependencies can resolve outside node_modules.
    #[cfg(unix)]
    #[test]
    fn symlinked_dependency_resolution_keeps_package_metadata() {
        let dir = tempdir().unwrap();
        let app = dir.path().join("app");
        let real_pkg = dir.path().join("workspace").join("linked-pkg");
        let nm = app.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::create_dir_all(&real_pkg).unwrap();
        std::fs::write(
            real_pkg.join("package.json"),
            r#"{ "name":"linked-pkg", "version":"1.2.3", "main":"index.js" }"#,
        )
        .unwrap();
        std::fs::write(
            real_pkg.join("index.js"),
            "module.exports = require('./lib');",
        )
        .unwrap();
        std::fs::write(real_pkg.join("lib.js"), "module.exports = 1;").unwrap();
        std::os::unix::fs::symlink(&real_pkg, nm.join("linked-pkg")).unwrap();

        let loader = test_loader();
        let entry = loader
            .resolve_meta("linked-pkg", Some(&app.join("entry.js")))
            .unwrap();
        assert_eq!(entry.package_name.as_deref(), Some("linked-pkg"));
        assert_eq!(entry.package_version.as_deref(), Some("1.2.3"));
        let entry_root = entry.package_root.clone().expect("package root");

        let internal = loader
            .resolve_meta("./lib.js", Some(entry.path.as_ref().unwrap()))
            .unwrap();
        assert_eq!(internal.package_root.as_deref(), Some(entry_root.as_path()));
        assert_eq!(internal.package_version.as_deref(), Some("1.2.3"));
    }

    // @ref LLP 0013#resolved-questions — (ENG-22621) — the package root for
    // version derivation is node_modules/<name>, so a nested versionless
    // package.json (e.g. dist/) doesn't degrade identity to the bare name.
    #[test]
    fn package_root_uses_the_node_modules_name_segment() {
        let p = Path::new("/app/node_modules/foo/dist/index.js");
        assert_eq!(
            package_root_in_node_modules(p),
            Some(PathBuf::from("/app/node_modules/foo"))
        );
        // @scope takes two segments.
        let s = Path::new("/app/node_modules/@acme/tool/lib/x.js");
        assert_eq!(
            package_root_in_node_modules(s),
            Some(PathBuf::from("/app/node_modules/@acme/tool"))
        );
        // Nested layout resolves to the deepest owning package.
        let nested = Path::new("/a/node_modules/uses/node_modules/foo/dist/i.js");
        assert_eq!(
            package_root_in_node_modules(nested),
            Some(PathBuf::from("/a/node_modules/uses/node_modules/foo"))
        );
        // First-party code has no package root.
        assert_eq!(
            package_root_in_node_modules(Path::new("/app/src/index.js")),
            None
        );
    }

    #[test]
    fn package_version_reads_the_outer_manifest_not_a_nested_versionless_one() {
        let dir = tempdir().unwrap();
        let pkg = dir.path().join("node_modules").join("foo");
        std::fs::create_dir_all(pkg.join("dist")).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{ "name": "foo", "version": "2.0.0", "main": "dist/index.js" }"#,
        )
        .unwrap();
        // A nested, versionless package.json (the common "type" marker) must NOT
        // shadow the package's real version.
        std::fs::write(
            pkg.join("dist").join("package.json"),
            r#"{ "type": "commonjs" }"#,
        )
        .unwrap();
        std::fs::write(pkg.join("dist").join("index.js"), "module.exports = 1;").unwrap();

        let loader = test_loader();
        let version = loader.package_version_for(&pkg.join("dist").join("index.js"));
        assert_eq!(version.as_deref(), Some("2.0.0"));
    }

    // ENG-22950: a module that needs no transpile/downlevel is served verbatim.
    // Resolution is metadata-only; the full `resolve` path performs the single
    // authorized source read in `load_source`. A pass-through module must still
    // round-trip unchanged rather than being needlessly transpiled. Package
    // scope classification remains metadata-only as well.
    #[test]
    fn serves_plain_module_source_verbatim() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("plain.js"), "module.exports = 1;\n").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("./plain.js", Some(&dir.path().join("entry.js")))
            .unwrap();
        assert_eq!(resolved.source.as_deref(), Some("module.exports = 1;\n"));
    }

    // ENG-22950: a TypeScript module loaded end-to-end must still be transpiled
    // to CommonJS. This exercises the source-threading path (the source read in
    // `load_module_source` is passed straight into the transpiler instead of the
    // file being read a second time) and, on the second load, the transpile
    // cache hit + memoized cache directory.
    #[test]
    fn loads_typescript_through_loader_and_caches() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("mod.ts"),
            "export const value: number = 41 + 1;\n",
        )
        .unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("./mod.ts", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let source = resolved.source.expect("transpiled source");
        // Type annotation stripped and the ESM export lowered to CommonJS.
        assert!(
            !source.contains(": number"),
            "type annotation not stripped: {source}"
        );
        assert!(source.contains("exports"), "not CommonJS output: {source}");

        // A second load hits the transpile cache (and the memoized cache dir)
        // and returns byte-identical output.
        let again = loader
            .resolve("./mod.ts", Some(&dir.path().join("entry.ts")))
            .unwrap();
        assert_eq!(again.source.as_deref(), Some(source.as_str()));
    }

    #[test]
    fn authenticated_package_source_rejects_post_arming_mutation() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("package");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        let source = root.join("index.js");
        std::fs::write(&source, "module.exports = 'armed';\n").unwrap();
        let integrity = package_tree_integrity(&root).unwrap();
        let root_object = test_object_identity(&root);

        assert_eq!(
            authenticated_package_source(&root, &source, &integrity, &root_object).unwrap(),
            b"module.exports = 'armed';\n"
        );
        std::fs::write(&source, "module.exports = 'mutated';\n").unwrap();
        let error =
            authenticated_package_source(&root, &source, &integrity, &root_object).unwrap_err();
        assert!(
            error.to_string().contains("changed after arming"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_package_source_reads_a_stable_internal_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let root = dir.path().join("package");
        std::fs::create_dir(&root).unwrap();
        let manifest = br#"{"name":"pkg","version":"1.0.0"}"#;
        std::fs::write(root.join("package.json"), manifest).unwrap();
        let target = root.join("index.js");
        let alias = root.join("alias.js");
        let source = b"module.exports = 'linked';\n";
        std::fs::write(&target, source).unwrap();
        symlink("index.js", &alias).unwrap();
        let integrity = package_tree_integrity(&root).unwrap();
        let explicit_records = vec![
            (
                "alias.js",
                format!(
                    "symlink-sha256-{}",
                    URL_SAFE_NO_PAD.encode(Sha256::digest(b"index.js"))
                ),
            ),
            (
                "index.js",
                format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(source))),
            ),
            (
                "package.json",
                format!(
                    "sha256-{}",
                    URL_SAFE_NO_PAD.encode(Sha256::digest(manifest))
                ),
            ),
        ];
        assert_eq!(
            integrity,
            format!(
                "sha256-{}",
                URL_SAFE_NO_PAD.encode(Sha256::digest(
                    serde_json::to_vec(&explicit_records).unwrap()
                ))
            ),
            "Rust must use the same sorted JSON link-record vector pinned by the JS generator test"
        );

        assert_eq!(
            authenticated_package_source(&root, &alias, &integrity, &test_object_identity(&root),)
                .unwrap(),
            b"module.exports = 'linked';\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_package_inventory_pins_each_exact_file_object_once() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("package");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        let source = root.join("index.js");
        std::fs::write(&source, "module.exports = 'authenticated';\n").unwrap();
        std::fs::hard_link(&source, root.join("index-alias.js")).unwrap();

        let integrity = package_tree_integrity(&root).unwrap();
        let membership =
            AuthenticatedPackageMembership::new(dir.path(), std::slice::from_ref(&root)).unwrap();
        let inventory =
            authenticated_package_inventory(&root, &test_object_identity(&root), &membership)
                .expect("the integrity walk must return its exact object set");
        assert_eq!(inventory.integrity, integrity);

        let source_object = test_object_identity(&source);
        let source_rows = inventory
            .objects
            .iter()
            .filter(|row| row.object == source_object)
            .collect::<Vec<_>>();
        assert_eq!(
            source_rows.len(),
            1,
            "hard-link spellings must not duplicate an exact object guard"
        );
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        assert!(
            matches!(
                source_rows[0].verification_generation.as_str(),
                "retained-descriptor-v1"
            ) || source_rows[0]
                .verification_generation
                .as_str()
                .starts_with("apple-st-gen:")
        );
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        assert_eq!(
            source_rows[0].verification_generation.as_str(),
            "retained-descriptor-v1"
        );
        assert_eq!(
            inventory.retained_descriptors.len(),
            inventory.objects.len(),
            "every unique package object needs a Host-lifetime descriptor"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_package_inventory_follows_defining_principal_for_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let project = dir.path().join("project");
        let root = project.join("node_modules/pkg");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        let package_source = root.join("index.js");
        std::fs::write(&package_source, "module.exports = 'package';\n").unwrap();
        let package_link = root.join("package-alias.js");
        symlink("index.js", &package_link).unwrap();
        let first_party_source = project.join("app.js");
        std::fs::write(&first_party_source, "module.exports = 'first-party';\n").unwrap();
        let first_party_link = root.join("first-party-alias.js");
        symlink("../../app.js", &first_party_link).unwrap();

        let membership =
            AuthenticatedPackageMembership::new(&project, std::slice::from_ref(&root)).unwrap();
        let inventory =
            authenticated_package_inventory(&root, &test_object_identity(&root), &membership)
                .unwrap();
        let guarded = inventory
            .objects
            .iter()
            .map(|object| object.object.clone())
            .collect::<std::collections::BTreeSet<_>>();

        assert!(guarded.contains(&test_object_identity(&package_source)));
        assert!(guarded.contains(&test_link_object_identity(&package_link)));
        assert!(guarded.contains(&test_link_object_identity(&first_party_link)));
        assert!(
            !guarded.contains(&test_object_identity(&first_party_source)),
            "reachability from a package must not freeze root-principal source"
        );
        assert_eq!(
            inventory.retained_descriptors.len(),
            inventory.objects.len()
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_package_inventory_refuses_a_symlink_cycle_at_fixed_resolution() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let root = dir.path().join("package");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        symlink("b.js", root.join("a.js")).unwrap();
        symlink("a.js", root.join("b.js")).unwrap();
        let membership =
            AuthenticatedPackageMembership::new(dir.path(), std::slice::from_ref(&root)).unwrap();

        let error =
            authenticated_package_inventory(&root, &test_object_identity(&root), &membership)
                .err()
                .expect("a package symlink cycle must be refused");
        assert!(error.to_string().contains("symlink cycle"), "{error:#}");
    }

    #[test]
    fn authenticated_package_source_closes_metadata_to_read_replacement_race() {
        let _race_guard = package_race_test_lock();

        let dir = tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        let source = root.join("index.js");
        std::fs::write(&source, "module.exports = 'authenticated';\n").unwrap();
        let integrity = package_tree_integrity(&root).unwrap();
        let root_object = test_object_identity(&root);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        *PACKAGE_SOURCE_OPEN_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((source.clone(), std::sync::Arc::clone(&barrier)));
        let _reset = PackageHookReset;

        let worker_root = root.clone();
        let worker_source = source.clone();
        let worker = std::thread::spawn(move || {
            authenticated_package_source(&worker_root, &worker_source, &integrity, &root_object)
        });
        barrier.wait();
        std::fs::write(&source, "module.exports = 'racing replacement';\n").unwrap();
        barrier.wait();

        let error = worker.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("changed"), "{error:#}");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_package_source_rejects_same_content_root_object_swap() {
        let _race_guard = package_race_test_lock();
        let _reset = PackageHookReset;
        let dir = tempdir().unwrap();
        let root = dir.path().join("package");
        let replacement = dir.path().join("replacement");
        for path in [&root, &replacement] {
            std::fs::create_dir(path).unwrap();
            std::fs::write(path.join("package.json"), r#"{"name":"pkg"}"#).unwrap();
            std::fs::write(path.join("index.js"), "module.exports = 1;\n").unwrap();
        }
        let root = std::fs::canonicalize(root).unwrap();
        let source = root.join("index.js");
        let integrity = package_tree_integrity(&root).unwrap();
        let expected_root = test_object_identity(&root);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        *PACKAGE_ROOT_OPEN_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((root.clone(), barrier.clone()));
        let worker_root = root.clone();
        let worker = std::thread::spawn(move || {
            authenticated_package_source(&worker_root, &source, &integrity, &expected_root)
        });
        barrier.wait();
        let original = dir.path().join("original");
        std::fs::rename(&root, &original).unwrap();
        std::fs::rename(&replacement, &root).unwrap();
        barrier.wait();
        let error = worker.join().unwrap().unwrap_err();
        assert!(
            error.to_string().contains("root object changed"),
            "{error:#}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_package_source_rejects_add_remove_and_directory_swap_between_passes() {
        for mutation in ["add", "remove", "directory-swap"] {
            let _race_guard = package_race_test_lock();
            let _reset = PackageHookReset;
            let dir = tempdir().unwrap();
            let root = std::fs::canonicalize(dir.path()).unwrap();
            std::fs::write(root.join("package.json"), r#"{"name":"pkg"}"#).unwrap();
            std::fs::create_dir(root.join("lib")).unwrap();
            std::fs::write(root.join("lib/index.js"), "module.exports = 1;\n").unwrap();
            if mutation == "remove" {
                std::fs::write(root.join("remove-me.js"), "present\n").unwrap();
            }
            let source = root.join("lib/index.js");
            let integrity = package_tree_integrity(&root).unwrap();
            let expected_root = test_object_identity(&root);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            *PACKAGE_INVENTORY_PASS_HOOK
                .get_or_init(|| std::sync::Mutex::new(None))
                .lock()
                .unwrap() = Some((root.clone(), barrier.clone()));
            let worker_root = root.clone();
            let worker = std::thread::spawn(move || {
                authenticated_package_source(&worker_root, &source, &integrity, &expected_root)
            });
            barrier.wait();
            match mutation {
                "add" => std::fs::write(root.join("added.js"), "new\n").unwrap(),
                "remove" => std::fs::remove_file(root.join("remove-me.js")).unwrap(),
                "directory-swap" => {
                    let old = root.join("old-lib");
                    let replacement = root.join("replacement-lib");
                    std::fs::create_dir(&replacement).unwrap();
                    std::fs::write(replacement.join("index.js"), "module.exports = 2;\n").unwrap();
                    std::fs::rename(root.join("lib"), old).unwrap();
                    std::fs::rename(replacement, root.join("lib")).unwrap();
                }
                _ => unreachable!(),
            }
            barrier.wait();
            let error = worker.join().unwrap().unwrap_err();
            assert!(
                error.to_string().contains("changed"),
                "{mutation}: {error:#}"
            );
            drop(_reset);
            drop(_race_guard);
        }
    }
}
