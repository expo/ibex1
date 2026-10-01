//! Public production-artifact preparation for native embedders.
//!
//! The caller supplies a paired authenticated snapshot template and expected
//! identity. This module binds the pair to the actually loaded engine and the
//! checked CapSec identities, validates protected files/package roots, replaces
//! the template nonce with OS randomness, and returns a new paired artifact.
//! Target advertisement remains enforced by `Host::new_armed` during install;
//! preparing bytes never promotes an unsupported target.
//! @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine

use anyhow::{Context as _, Result};
use base64::Engine as _;
use capsec_semantics::arming::{
    ArmedSnapshot, ExactCarrierBinding, ExactEmbedderBinding, ExactEmbedderBindingV1,
    ExactEmbedderBindingV2, ExactEmbedderEndowments, ExactEmbedderSchemaV1, ExactEmbedderSchemaV2,
    ExpectedArmingIdentity, ExpectedProtectedArtifact, ProtectedArtifactRole,
};
use capsec_semantics::digest::{
    compute_checked_contract_digest, compute_domain_digest, DigestKind,
};
use capsec_semantics::model::{
    ActionId, AuthoritySelector, Digest, LogicalPath, LogicalRoot, ObjectIdentity, ObjectPlatform,
    SelectorResource,
};
use capsec_semantics::path_alias::{BoundVolumePathCanonicalizer, PathAliasCanonicalizerIdentity};
use capsec_semantics::runtime_extensions::{
    RuntimeExtensionAuthorityCapsule, RuntimeExtensionAuthorityTemplate,
    RuntimeExtensionLinkedArtifactRange, RuntimeExtensionMappedExecutableAnchor,
    RuntimeExtensionMappedExecutableIdentity, RUNTIME_EXTENSION_MAPPED_EXECUTABLE_SCHEMA,
};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::Path;

const PRODUCTION_RUN_NONCE_BYTES: usize = 16;
const CONTRACT_FIXTURE_RUN_NONCE: &str = "AQIDBAUGBwgJCgsMDQ4PEA";

/// Build-time canonical bytes for the immutable CapSec registry protected
/// artifact. The CLI and native embedder share these constants so the checked
/// record is embedded once and startup does not reparse it.
#[doc(hidden)]
pub const CAPSEC_REGISTRY_RECORD_CONTENT_DIGEST: &str =
    include_str!(concat!(env!("OUT_DIR"), "/capsec-registry-record.digest"));
#[doc(hidden)]
pub const CAPSEC_REGISTRY_RECORD_CONTENT_LEN: &str =
    include_str!(concat!(env!("OUT_DIR"), "/capsec-registry-record.len"));
#[doc(hidden)]
pub const CAPSEC_REGISTRY_RECORD_JCS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/capsec-registry-record.jcs"));

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedEmbedderArtifacts {
    pub artifact_schema: &'static str,
    pub armed_snapshot_digest: String,
    pub snapshot: serde_json::Value,
    pub expected_identity: ExpectedArmingIdentity,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExactOperationManifest {
    #[serde(rename = "$schema")]
    schema_path: Option<String>,
    schema: String,
    schema_version: u32,
    operations: Vec<ExactOperation>,
    endowments: ExactOperationEndowments,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactOperation {
    id: u32,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExactOperationEndowments {
    app: Vec<u32>,
    agent_isolate: Vec<u32>,
    ui_worklet: Vec<u32>,
}

struct MaterializedArtifact {
    host_path: LogicalPath,
    object: capsec_semantics::model::ObjectIdentity,
    content_digest: Digest,
}

const RUNTIME_EXTENSION_LOADED_IMAGE_OBSERVATION_SCHEMA: &str =
    "exact/runtime-extension-loaded-image-observation/1";

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeExtensionLoadedImageObservation {
    schema: String,
    path: String,
    file_size: capsec_semantics::model::SafeUint,
    executable_object: capsec_semantics::model::ObjectIdentity,
    anchors: Vec<RuntimeExtensionMappedExecutableAnchor>,
}

fn hash_pinned_executable(file: &mut std::fs::File, path: &Path) -> Result<(u64, [u8; 32])> {
    file.rewind().with_context(|| {
        format!(
            "cannot rewind launcher-observed executable {}",
            path.display()
        )
    })?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes_read = 0_u64;
    loop {
        let read = file.read(&mut buffer).with_context(|| {
            format!(
                "cannot hash launcher-observed executable {}",
                path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .context("runtime-extension executable length overflow")?;
        hash.update(&buffer[..read]);
    }
    Ok((bytes_read, hash.finalize().into()))
}

#[cfg(unix)]
fn executable_metadata_version(metadata: &std::fs::Metadata) -> (i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt as _;
    (
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(windows)]
fn executable_metadata_version(metadata: &std::fs::Metadata) -> (u64, u64) {
    use std::os::windows::fs::MetadataExt as _;
    (metadata.creation_time(), metadata.last_write_time())
}

#[cfg(not(any(unix, windows)))]
fn executable_metadata_version(metadata: &std::fs::Metadata) -> Option<std::time::SystemTime> {
    metadata.modified().ok()
}

#[derive(Debug)]
pub struct FinalizedRuntimeExtensionAuthority {
    pub authority_capsule_bytes: Vec<u8>,
    pub authority_capsule_digest: String,
    pub executable_selection_identity: String,
    pub mapped_executable_bytes: Vec<u8>,
}

fn valid_operation_name(name: &str) -> bool {
    let mut segments = name.split('.');
    let valid_segment = |segment: &str| {
        let mut characters = segment.chars();
        characters
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic())
            && characters.all(|character| character.is_ascii_alphanumeric())
    };
    let Some(first) = segments.next() else {
        return false;
    };
    valid_segment(first) && segments.clone().next().is_some() && segments.all(valid_segment)
}

fn parse_exact_operation_manifest(bytes: &[u8]) -> Result<ExactEmbedderBinding> {
    let text = std::str::from_utf8(bytes).context("Exact operation manifest is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .context("Exact operation manifest is not strict JSON")?;
    let manifest: ExactOperationManifest =
        serde_json::from_value(value).context("invalid Exact operation manifest")?;
    anyhow::ensure!(
        manifest.schema == "exact.host-call-operations/v1" && manifest.schema_version == 1,
        "Exact operation manifest has an unsupported schema"
    );
    anyhow::ensure!(
        manifest
            .schema_path
            .as_deref()
            .is_none_or(|path| path == "./host-call-operations.schema.json"),
        "Exact operation manifest has an unexpected schema path"
    );
    anyhow::ensure!(
        !manifest.operations.is_empty(),
        "Exact operation manifest operations must not be empty"
    );

    let mut previous_id = 0_u32;
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut names_by_id = BTreeMap::new();
    for operation in &manifest.operations {
        anyhow::ensure!(
            operation.id > previous_id,
            "Exact operation IDs must be strictly increasing"
        );
        anyhow::ensure!(
            valid_operation_name(&operation.name),
            "Exact operation name is invalid: {}",
            operation.name
        );
        anyhow::ensure!(
            ids.insert(operation.id),
            "Exact operation ID is duplicated: {}",
            operation.id
        );
        anyhow::ensure!(
            names.insert(operation.name.clone()),
            "Exact operation name is duplicated: {}",
            operation.name
        );
        names_by_id.insert(operation.id, operation.name.as_str());
        previous_id = operation.id;
    }

    let mut endowed = BTreeSet::new();
    for (context, context_ids) in [
        ("app", &manifest.endowments.app),
        ("agentIsolate", &manifest.endowments.agent_isolate),
        ("uiWorklet", &manifest.endowments.ui_worklet),
    ] {
        anyhow::ensure!(
            context_ids.len() <= 4096,
            "Exact {context} endowment exceeds the 4096-operation limit"
        );
        let mut previous = 0_u32;
        for id in context_ids {
            anyhow::ensure!(
                ids.contains(id),
                "Exact {context} endowment references unknown operation ID {id}"
            );
            anyhow::ensure!(
                *id > previous,
                "Exact {context} endowment IDs must be strictly increasing"
            );
            anyhow::ensure!(
                endowed.insert(*id),
                "Exact operation ID {id} is endowed to multiple runtime contexts"
            );
            previous = *id;
        }
    }
    anyhow::ensure!(
        !manifest.endowments.app.is_empty(),
        "Exact app endowment must not be empty"
    );
    anyhow::ensure!(
        manifest.endowments.ui_worklet.is_empty(),
        "Exact UI worklet endowment must remain empty"
    );
    anyhow::ensure!(
        endowed == ids,
        "every Exact operation must have exactly one runtime endowment"
    );
    let agent_names = manifest
        .endowments
        .agent_isolate
        .iter()
        .filter_map(|id| names_by_id.get(id).copied())
        .collect::<BTreeSet<_>>();
    let expected_agent_names = [
        "agentIsolate.appRuntimeHealth",
        "agentIsolate.bindFailed",
        "agentIsolate.config",
        "agentIsolate.ready",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        agent_names == expected_agent_names,
        "Exact agent isolate must receive exactly its four control-plane operations"
    );

    let manifest_digest = Digest::new(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)?;
    Ok(ExactEmbedderBinding::V1(ExactEmbedderBindingV1 {
        schema: ExactEmbedderSchemaV1,
        operation_manifest_digest: manifest_digest,
        endowments: ExactEmbedderEndowments {
            app: manifest.endowments.app,
            agent_isolate: manifest.endowments.agent_isolate,
            ui_worklet: manifest.endowments.ui_worklet,
        },
    }))
}

/// Parse one strict `exact/carrier-binding/1` JSON object and upgrade the
/// manifest-derived /1 binding into the required-carrier /2 shape, running
/// the full arming-time validation (pin grammar, per-context >=1-pin rule)
/// before the caller embeds it. The upgraded binding is embedded before
/// nonce freshening and digest recomputation, so the pins are authenticated
/// inputs of the armed digest.
// @ref LLP 0053#r2-i2--carrier-identity-in-the-armed-snapshot
fn bind_exact_carrier(
    binding: ExactEmbedderBinding,
    carrier_binding_json: &[u8],
) -> Result<ExactEmbedderBinding> {
    let text =
        std::str::from_utf8(carrier_binding_json).context("Exact carrier binding is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .context("Exact carrier binding is not strict JSON")?;
    let carrier: ExactCarrierBinding =
        serde_json::from_value(value).context("invalid Exact carrier binding")?;
    let ExactEmbedderBinding::V1(v1) = binding else {
        anyhow::bail!("Exact carrier binding requires a manifest-derived /1 embedder binding");
    };
    let upgraded = ExactEmbedderBinding::V2(ExactEmbedderBindingV2 {
        schema: ExactEmbedderSchemaV2,
        operation_manifest_digest: v1.operation_manifest_digest,
        endowments: v1.endowments,
        carrier_binding: carrier,
    });
    upgraded
        .validate()
        .context("Exact carrier binding validation refused")?;
    Ok(upgraded)
}

fn absolute_artifact_path(path: &Path) -> Result<LogicalPath> {
    Ok(LogicalPath {
        root: LogicalRoot::Absolute,
        components: super::host_path_components(path)?,
        host_bound: Some(true),
    })
}

/// Select the same per-volume alias identity as the ordinary armed launcher.
/// The public Exact builder is target-local, so it must probe the authenticated
/// bound paths rather than inheriting canonicalizer rows from the template.
/// @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment
fn bound_volume_path_canonicalizers<'a>(
    bindings: impl IntoIterator<Item = (&'a Path, &'a ObjectIdentity)>,
) -> Result<Vec<BoundVolumePathCanonicalizer>> {
    let mut rows = BTreeMap::new();
    for (path, object) in bindings {
        let observed = super::object_identity_for_host_path(path)?;
        anyhow::ensure!(
            &observed == object,
            "bound-volume adapter object mismatch for {}",
            path.display()
        );
        let identity = match object.platform {
            ObjectPlatform::Apple => apple_volume_path_canonicalizer(path)?,
            ObjectPlatform::Windows => PathAliasCanonicalizerIdentity::WindowsAsciiCasefoldV1,
            ObjectPlatform::Unix | ObjectPlatform::Android => {
                PathAliasCanonicalizerIdentity::ByteIdentityV1
            }
        };
        let row = BoundVolumePathCanonicalizer {
            platform: object.platform,
            volume: object.volume.clone(),
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

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
fn apple_volume_path_canonicalizer(path: &Path) -> Result<PathAliasCanonicalizerIdentity> {
    use std::os::unix::ffi::OsStrExt as _;

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
    anyhow::ensure!(
        filesystem_name == "apfs",
        "armed Apple path canonicalization supports APFS only; bound volume uses {filesystem_name}"
    );
    let case_sensitive = unsafe { libc::pathconf(path.as_ptr(), libc::_PC_CASE_SENSITIVE) };
    match case_sensitive {
        0 => Ok(PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1),
        1 => Ok(PathAliasCanonicalizerIdentity::AppleApfsUnicode9NfdV1),
        _ => Err(std::io::Error::last_os_error())
            .context("cannot determine whether the bound APFS volume is case-sensitive"),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
fn apple_volume_path_canonicalizer(_path: &Path) -> Result<PathAliasCanonicalizerIdentity> {
    anyhow::bail!("an Apple object identity cannot be bound on this target")
}

// @ref LLP 0021#default-and-target-claim — artifact publication uses each
// target's supported durability boundary without weakening byte/object checks.
fn sync_published_artifact(directory: &Path, _artifact: &std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(directory)?
            .sync_all()
            .context("failed to sync protected artifact directory")?;
    }
    #[cfg(not(unix))]
    {
        // Windows does not let `std::fs::File` open a directory for `sync_all`.
        // The hard link names this same file object, so flush that pinned object
        // again after publication instead of treating the directory as a file.
        let _ = directory;
        _artifact
            .sync_all()
            .context("failed to sync published protected artifact")?;
    }
    Ok(())
}

fn materialize_protected_artifact(
    role: &str,
    bytes: &[u8],
    digest: &Digest,
) -> Result<MaterializedArtifact> {
    let cache_root = crate::runtime_cache_dir()?;
    let directory = cache_root.join("capsec-artifacts");
    std::fs::create_dir_all(&directory)?;
    let directory_metadata = std::fs::symlink_metadata(&directory)?;
    anyhow::ensure!(
        directory_metadata.is_dir() && !directory_metadata.file_type().is_symlink(),
        "protected artifact parent is not a stable directory"
    );
    let directory = std::fs::canonicalize(directory)?;
    let filename = format!(
        "{}.{}.json",
        digest.as_str().trim_start_matches("sha256-"),
        role,
    );
    let path = directory.join(filename);

    let open_existing = || -> Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        options
            .open(&path)
            .with_context(|| format!("failed to pin protected artifact {}", path.display()))
    };
    let validate = |file: &mut std::fs::File| -> Result<()> {
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file(),
            "protected artifact is not a regular file"
        );
        #[cfg(unix)]
        anyhow::ensure!(
            {
                use std::os::unix::fs::PermissionsExt as _;
                metadata.permissions().mode() & 0o222 == 0
            },
            "protected artifact is mutable"
        );
        #[cfg(not(unix))]
        anyhow::ensure!(
            metadata.permissions().readonly(),
            "protected artifact is mutable"
        );
        file.rewind()?;
        let mut observed = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut observed)?;
        anyhow::ensure!(observed == bytes, "protected artifact content mismatch");
        Ok(())
    };

    if path.exists() {
        let mut existing = open_existing()?;
        validate(&mut existing)?;
    } else {
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).context("failed to name protected staging artifact")?;
        let temporary = directory.join(format!(
            ".{role}.{}.tmp",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
        ));
        let mut staged = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let publish = (|| -> Result<()> {
            staged.write_all(bytes)?;
            staged.sync_all()?;
            let mut permissions = staged.metadata()?.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                permissions.set_mode(0o400);
            }
            #[cfg(not(unix))]
            permissions.set_readonly(true);
            staged.set_permissions(permissions)?;
            staged.sync_all()?;
            validate(&mut staged)?;
            match std::fs::hard_link(&temporary, &path) {
                Ok(()) => sync_published_artifact(&directory, &staged)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let mut existing = open_existing()?;
                    validate(&mut existing)?;
                }
                Err(error) => return Err(error.into()),
            }
            Ok(())
        })();
        let _ = std::fs::remove_file(&temporary);
        publish?;
    }

    let path = std::fs::canonicalize(path)?;
    let object = super::object_identity_for_host_path(&path)?;
    let content_digest = Digest::new(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)?;
    Ok(MaterializedArtifact {
        host_path: absolute_artifact_path(&path)?,
        object,
        content_digest,
    })
}

/// Authenticate an existing immutable registry artifact against the
/// build-time digest of the exact canonical bytes.
fn pin_precomputed_registry_artifact(
    cache_root: &Path,
    digest_name: &Digest,
) -> Result<Option<MaterializedArtifact>> {
    let Ok(expected_len) = CAPSEC_REGISTRY_RECORD_CONTENT_LEN.trim().parse::<u64>() else {
        return Ok(None);
    };
    let Ok(expected_digest) = Digest::new(CAPSEC_REGISTRY_RECORD_CONTENT_DIGEST.trim()) else {
        return Ok(None);
    };
    let Ok(directory) = std::fs::canonicalize(cache_root.join("capsec-artifacts")) else {
        return Ok(None);
    };
    let filename = format!(
        "{}.registry.json",
        digest_name.as_str().trim_start_matches("sha256-")
    );
    let path = directory.join(filename);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let Ok(mut file) = options.open(&path) else {
        return Ok(None);
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != expected_len {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o222 != 0 {
            return Ok(None);
        }
    }
    #[cfg(not(unix))]
    if !metadata.permissions().readonly() {
        return Ok(None);
    }
    let observed = crate::engine::hash_open_file_sha256(&mut file, expected_len)
        .map_err(anyhow::Error::msg)?;
    let observed_digest = Digest::new(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(observed)
    ))
    .map_err(anyhow::Error::msg)?;
    if observed_digest != expected_digest {
        return Ok(None);
    }
    let object = super::object_identity_for_open_file(&file).map_err(anyhow::Error::msg)?;
    let path = std::fs::canonicalize(path)?;
    Ok(Some(MaterializedArtifact {
        host_path: absolute_artifact_path(&path)?,
        object,
        content_digest: expected_digest,
    }))
}

fn runtime_target_triple() -> String {
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

fn checked_identity_digests() -> Result<(Digest, Digest)> {
    let checked: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    let digest_at = |field: &str| -> Result<Digest> {
        Digest::new(
            checked[field]
                .as_str()
                .with_context(|| format!("checked CapSec identity lacks {field}"))?,
        )
        .map_err(anyhow::Error::msg)
    };
    Ok((digest_at("vocabDigest")?, digest_at("registryDigest")?))
}

pub fn verify_expected_identity(
    supplied: ExpectedArmingIdentity,
) -> Result<ExpectedArmingIdentity> {
    let (vocab_digest, registry_digest) = checked_identity_digests()?;
    let engine = crate::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        supplied.profile == crate::capsec_registry_generated::CAPSEC_PROFILE,
        "expected identity profile does not match the checked Ibex profile"
    );
    anyhow::ensure!(
        supplied.semantic_core == crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE,
        "expected identity semantic core does not match the checked Ibex core"
    );
    anyhow::ensure!(
        supplied.vocab_digest == vocab_digest,
        "expected identity vocabulary digest does not match the checked vocabulary"
    );
    anyhow::ensure!(
        supplied.registry_digest == registry_digest,
        "expected identity registry digest does not match the checked registry"
    );
    anyhow::ensure!(
        supplied.target == runtime_target_triple(),
        "expected identity target does not match the running embedder"
    );
    anyhow::ensure!(
        supplied.features == engine.structural_features,
        "expected identity feature set does not match the loaded engine"
    );
    anyhow::ensure!(
        supplied.engine_binary_digest
            == Digest::new(engine.binary_digest).map_err(anyhow::Error::msg)?,
        "expected identity engine digest does not match the loaded engine"
    );
    Ok(supplied)
}

fn fresh_production_nonce() -> Result<String> {
    let mut bytes = [0_u8; PRODUCTION_RUN_NONCE_BYTES];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| anyhow::anyhow!("OS randomness unavailable for run nonce: {error}"))?;
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    anyhow::ensure!(
        nonce != CONTRACT_FIXTURE_RUN_NONCE,
        "OS randomness produced the reserved contract-fixture run nonce"
    );
    Ok(nonce)
}

fn freshen_document(document: &mut serde_json::Value, nonce: String) -> Result<Digest> {
    document["runNonce"] = serde_json::Value::String(nonce);
    let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, document)?;
    document["armedSnapshotDigest"] = serde_json::Value::String(digest.clone());
    Digest::new(digest).map_err(anyhow::Error::msg)
}

/// Authenticate, bind, and freshen one embedder artifact pair.
///
/// This validates everything that can be established before installation,
/// including the exact mapped engine object, checked semantic identities,
/// protected artifact bytes, package graph/root bindings, and a construction-
/// fresh nonce. `Host::new_armed` subsequently authenticates the report-derived
/// target advertisement; unsupported targets still refuse there.
pub fn prepare_embedder_artifacts(
    template_bytes: &[u8],
    expected_identity_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    super::reject_closed_startup_environment()?;
    let expected_text = std::str::from_utf8(expected_identity_bytes)
        .context("expected arming identity is not UTF-8")?;
    let expected_value = capsec_semantics::strict_json::parse_strict(expected_text)
        .context("expected arming identity is not strict JSON")?;
    let supplied: ExpectedArmingIdentity =
        serde_json::from_value(expected_value).context("invalid expected arming identity")?;
    let mut expected = verify_expected_identity(supplied)?;

    // Authenticate the caller's pair before mutating the nonce or digest. A
    // wrong target/engine/registry/graph/identity cannot be rewritten into a
    // valid artifact by this API.
    let template = ArmedSnapshot::load(template_bytes, &expected)
        .context("snapshot template authentication refused")?;
    super::validate_loaded_engine_identity(&template)?;
    super::validate_snapshot_protected_artifacts(&template)?;
    super::validate_snapshot_root_bindings(&template)?;

    let mut document = template.document().clone();
    // @ref LLP 0022#11-delegated-obligations — the public embedder output keeps
    // OBL-ENV-BASE explicit. ArmedSnapshot::load already refused any supplied
    // non-empty base; values are admitted only through principal overlays.
    document["environmentBase"] = serde_json::json!([]);
    let digest = freshen_document(&mut document, fresh_production_nonce()?)?;
    expected.armed_snapshot_digest = digest.clone();

    // Re-ingest the freshly serialized pair before returning it. This catches
    // any mismatch between the digest projection and the public output shape.
    let fresh_bytes = serde_json::to_vec(&document)?;
    let fresh = ArmedSnapshot::load(&fresh_bytes, &expected)
        .context("freshened snapshot authentication refused")?;
    super::validate_loaded_engine_identity(&fresh)?;
    super::validate_snapshot_protected_artifacts(&fresh)?;
    super::validate_snapshot_root_bindings(&fresh)?;

    Ok(PreparedEmbedderArtifacts {
        artifact_schema: "ibex/armed-embedder-artifacts/1",
        armed_snapshot_digest: digest.as_str().to_owned(),
        snapshot: document,
        expected_identity: expected,
    })
}

/// Build a complete Exact-bound artifact pair against the engine and project
/// roots installed on this target.
///
/// Exact's packaged application code is a single authenticated root bundle, so
/// this first public producer authors the canonical empty package policy and
/// graph rather than accepting a second, embedder-defined package inventory.
/// Package-bearing applications must use Ibex's canonical policy generator and
/// are refused by this API until that generated policy is an explicit input.
/// The resulting pair is still subject to report-derived target advertisement
/// during `ex_host_install_armed`.
/// @ref LLP 0021#default-and-target-claim — artifact production cannot promote
/// an unsupported target or create a weaker Exact claim plane.
pub fn build_exact_embedder_artifacts(
    project_root: &Path,
    dev_project_root: Option<&Path>,
    operation_manifest_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    build_exact_embedder_artifacts_inner(
        project_root,
        dev_project_root,
        operation_manifest_bytes,
        None,
        None,
        None,
    )
}

/// Carrier-bearing sibling of [`build_exact_embedder_artifacts`]: the strict
/// `exact/carrier-binding/1` JSON input is validated and embedded as the
/// required `carrierBinding` of a /2 binding before nonce freshening.
// @ref LLP 0053#r2-i2--carrier-identity-in-the-armed-snapshot
pub fn build_exact_embedder_artifacts_v2(
    project_root: &Path,
    dev_project_root: Option<&Path>,
    operation_manifest_bytes: &[u8],
    carrier_binding_json: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    build_exact_embedder_artifacts_inner(
        project_root,
        dev_project_root,
        operation_manifest_bytes,
        None,
        None,
        Some(carrier_binding_json),
    )
}

/// Combine one non-armable generated template with an independently observed
/// loaded executable. The observation is launcher-authored and contains no
/// digest: Ibex independently acquires a descriptor proven to back the mapped
/// main executable and hashes only through that descriptor before producing
/// the only capsule that an armed Host will accept. The observation pathname is
/// diagnostic and is never reopened. The historical mapped-executable wire
/// name does not claim a hash of relocated memory pages.
///
/// @ref LLP 0040#authenticated-construction-projection
pub fn finalize_runtime_extension_authority(
    authority_template_bytes: &[u8],
    loaded_image_observation_bytes: &[u8],
) -> Result<FinalizedRuntimeExtensionAuthority> {
    let pinned_image = crate::engine::open_pinned_self_image()
        .map_err(anyhow::Error::msg)
        .context("cannot pin the file object backing the mapped executable")?;
    finalize_runtime_extension_authority_with_pinned_image(
        authority_template_bytes,
        loaded_image_observation_bytes,
        pinned_image,
    )
}

fn finalize_runtime_extension_authority_with_pinned_image(
    authority_template_bytes: &[u8],
    loaded_image_observation_bytes: &[u8],
    mut file: std::fs::File,
) -> Result<FinalizedRuntimeExtensionAuthority> {
    let template = RuntimeExtensionAuthorityTemplate::parse_json(authority_template_bytes)
        .context("invalid runtime-extension authority template")?;
    let observation_text = std::str::from_utf8(loaded_image_observation_bytes)
        .context("runtime-extension loaded-image observation is not UTF-8")?;
    let observation_value = capsec_semantics::strict_json::parse_strict(observation_text)
        .context("runtime-extension loaded-image observation is not strict JSON")?;
    let observation: RuntimeExtensionLoadedImageObservation =
        serde_json::from_value(observation_value)
            .context("invalid runtime-extension loaded-image observation")?;
    anyhow::ensure!(
        observation.schema == RUNTIME_EXTENSION_LOADED_IMAGE_OBSERVATION_SCHEMA,
        "runtime-extension loaded-image observation schema is unsupported"
    );
    anyhow::ensure!(
        !observation.path.is_empty()
            && !observation.path.chars().any(char::is_control)
            && observation.file_size != capsec_semantics::model::SafeUint::ZERO,
        "runtime-extension loaded-image observation is incomplete"
    );

    let observed_path = Path::new(&observation.path);
    anyhow::ensure!(
        observed_path.is_absolute(),
        "runtime-extension loaded-image path is not absolute"
    );
    let before = file.metadata().with_context(|| {
        format!(
            "cannot inspect pinned mapped executable ({})",
            observed_path.display()
        )
    })?;
    anyhow::ensure!(
        before.is_file() && before.len() == observation.file_size.get(),
        "runtime-extension executable changed after launcher observation"
    );
    let executable_object = super::object_identity_for_open_file(&file)
        .map_err(anyhow::Error::msg)
        .context("cannot identify pinned mapped executable")?;
    anyhow::ensure!(
        executable_object == observation.executable_object,
        "runtime-extension executable object changed after launcher observation"
    );

    let before_version = executable_metadata_version(&before);
    let (bytes_read, first_hash) = hash_pinned_executable(&mut file, observed_path)?;
    anyhow::ensure!(
        bytes_read == observation.file_size.get(),
        "runtime-extension executable length changed while hashing"
    );
    let after = file.metadata().with_context(|| {
        format!(
            "cannot revalidate pinned mapped executable ({})",
            observed_path.display()
        )
    })?;
    let after_object = super::object_identity_for_open_file(&file)
        .map_err(anyhow::Error::msg)
        .context("cannot re-identify pinned mapped executable")?;
    anyhow::ensure!(
        after.len() == before.len()
            && after_object == executable_object
            && executable_metadata_version(&after) == before_version,
        "runtime-extension executable changed while it was authenticated"
    );
    let (second_bytes_read, second_hash) = hash_pinned_executable(&mut file, observed_path)?;
    let final_metadata = file.metadata().with_context(|| {
        format!(
            "cannot revalidate pinned mapped executable ({})",
            observed_path.display()
        )
    })?;
    let final_object = super::object_identity_for_open_file(&file)
        .map_err(anyhow::Error::msg)
        .context("cannot re-identify pinned mapped executable")?;
    anyhow::ensure!(
        second_bytes_read == bytes_read
            && second_hash == first_hash
            && final_metadata.len() == before.len()
            && final_object == executable_object
            && executable_metadata_version(&final_metadata) == before_version,
        "runtime-extension executable was not stable across authentication"
    );

    let content_digest = Digest::new(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(first_hash)
    ))
    .map_err(anyhow::Error::msg)?;
    let mapped_executable = RuntimeExtensionMappedExecutableIdentity {
        schema: RUNTIME_EXTENSION_MAPPED_EXECUTABLE_SCHEMA.into(),
        executable_object,
        range: RuntimeExtensionLinkedArtifactRange {
            offset: capsec_semantics::model::SafeUint::ZERO,
            length: observation.file_size,
        },
        content_digest,
        anchors: observation.anchors,
    };
    mapped_executable
        .validate()
        .map_err(anyhow::Error::msg)
        .context("invalid runtime-extension executable anchor inventory")?;
    let capsule = template
        .finalize(mapped_executable.clone())
        .map_err(anyhow::Error::msg)
        .context("cannot finalize runtime-extension authority capsule")?;
    let authority_capsule_bytes =
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(&capsule)?)?;
    let mapped_executable_bytes =
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(&mapped_executable)?)?;
    Ok(FinalizedRuntimeExtensionAuthority {
        authority_capsule_digest: capsule.authority_capsule_digest.as_str().to_owned(),
        executable_selection_identity: capsule.executable_selection_identity.as_str().to_owned(),
        authority_capsule_bytes,
        mapped_executable_bytes,
    })
}

/// Build a target-local Exact artifact pair with one statically selected
/// native runtime-extension authority capsule.
///
/// `launcher_mapped_executable_bytes` is the independently observed, strict
/// loaded-executable file identity returned by
/// `finalize_runtime_extension_authority` (under the historical
/// mapped-executable wire schema).
/// It is deliberately separate from the capsule: descriptor-authored labels
/// never authenticate their own code.
/// Both inputs are copied and validated before the armed snapshot is produced.
///
/// @ref LLP 0040#authenticated-construction-projection
pub fn build_exact_runtime_extension_embedder_artifacts(
    project_root: &Path,
    dev_project_root: Option<&Path>,
    operation_manifest_bytes: &[u8],
    authority_capsule_bytes: &[u8],
    launcher_mapped_executable_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    build_exact_embedder_artifacts_inner(
        project_root,
        dev_project_root,
        operation_manifest_bytes,
        Some(authority_capsule_bytes),
        Some(launcher_mapped_executable_bytes),
        None,
    )
}

/// Carrier-bearing sibling of
/// [`build_exact_runtime_extension_embedder_artifacts`].
// @ref LLP 0053#r2-i2--carrier-identity-in-the-armed-snapshot
pub fn build_exact_runtime_extension_embedder_artifacts_v2(
    project_root: &Path,
    dev_project_root: Option<&Path>,
    operation_manifest_bytes: &[u8],
    authority_capsule_bytes: &[u8],
    launcher_mapped_executable_bytes: &[u8],
    carrier_binding_json: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    build_exact_embedder_artifacts_inner(
        project_root,
        dev_project_root,
        operation_manifest_bytes,
        Some(authority_capsule_bytes),
        Some(launcher_mapped_executable_bytes),
        Some(carrier_binding_json),
    )
}

fn admit_exact_production_policy(
    policy: capsec_semantics::policy::CanonicalPolicy,
) -> Result<capsec_semantics::policy::CanonicalPolicy> {
    anyhow::ensure!(
        policy.principals.is_empty(),
        "target-local Exact builder refuses package-bearing production policies; only the canonical empty package policy is accepted"
    );
    Ok(policy)
}

fn build_exact_embedder_artifacts_inner(
    project_root: &Path,
    dev_project_root: Option<&Path>,
    operation_manifest_bytes: &[u8],
    runtime_extension_authority_capsule_bytes: Option<&[u8]>,
    launcher_mapped_executable_bytes: Option<&[u8]>,
    carrier_binding_json: Option<&[u8]>,
) -> Result<PreparedEmbedderArtifacts> {
    let mut phase = super::HostStartupPhaseTrace::begin();
    anyhow::ensure!(
        runtime_extension_authority_capsule_bytes.is_some()
            == launcher_mapped_executable_bytes.is_some(),
        "runtime-extension authority capsule and launcher mapped-executable identity must be supplied together"
    );
    let runtime_extension = match (
        runtime_extension_authority_capsule_bytes,
        launcher_mapped_executable_bytes,
    ) {
        (Some(capsule_bytes), Some(observed_bytes)) => {
            let capsule = RuntimeExtensionAuthorityCapsule::parse_json(capsule_bytes)
                .context("invalid runtime-extension authority capsule")?;
            let observed_text = std::str::from_utf8(observed_bytes)
                .context("runtime-extension mapped-executable identity is not UTF-8")?;
            let observed_value = capsec_semantics::strict_json::parse_strict(observed_text)
                .context("runtime-extension mapped-executable identity is not strict JSON")?;
            let observed: RuntimeExtensionMappedExecutableIdentity =
                serde_json::from_value(observed_value)
                    .context("invalid runtime-extension launcher mapped executable")?;
            capsule
                .validate_launcher_mapped_executable(&observed)
                .map_err(anyhow::Error::msg)?;
            let canonical_bytes =
                capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(&capsule)?)?;
            Some((capsule, observed, canonical_bytes))
        }
        (None, None) => None,
        _ => unreachable!("runtime-extension inputs were checked as a pair"),
    };
    super::reject_closed_startup_environment()?;
    phase.mark("builder_environment");
    let installed_project_root = std::fs::canonicalize(project_root).with_context(|| {
        format!(
            "failed to authenticate Exact project root {}",
            project_root.display()
        )
    })?;
    anyhow::ensure!(
        installed_project_root.is_dir(),
        "Exact project root is not a directory"
    );
    let dev_project_root = dev_project_root
        .map(|root| {
            std::fs::canonicalize(root).with_context(|| {
                format!(
                    "failed to authenticate Exact dev project root {}",
                    root.display()
                )
            })
        })
        .transpose()?;
    if let Some(root) = dev_project_root.as_ref() {
        anyhow::ensure!(root.is_dir(), "Exact dev project root is not a directory");
    }
    let project_root = dev_project_root.as_ref().unwrap_or(&installed_project_root);

    let (vocab_digest, registry_digest) = checked_identity_digests()?;
    let expected_policy_identity = capsec_semantics::policy::ExpectedPolicyIdentity {
        profile: crate::capsec_registry_generated::CAPSEC_PROFILE.into(),
        semantic_core: crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE.into(),
        vocab_digest: vocab_digest.clone(),
        registry_digest: registry_digest.clone(),
    };
    let policy_profile =
        capsec_semantics::registry::ValidatedProfile::from_json_with_runtime_extensions(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/capsec/registry/capability-definitions.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/capsec/registry/policy-rules.json"
            )),
            runtime_extension.is_some(),
        )?;
    phase.mark("builder_profile");
    let entry_identity = serde_json::json!({
        "root": "project",
        "components": [{"encoding": "utf8", "value": "exact-operation-manifest.json"}],
        "sourceIntegrity": format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(operation_manifest_bytes))
        ),
    });
    let graph_snapshot = serde_json::json!({
        "graphSnapshotSchema": "ibex/authenticated-graph-snapshot/1",
        "entryIdentity": entry_identity,
        "nodes": [{
            "principal": "<root>",
            "modulePath": "exact-operation-manifest.json",
            "sourceIntegrity": entry_identity["sourceIntegrity"],
        }],
        "packages": [],
        "edges": [],
        "candidateSets": [],
    });
    let graph_identity =
        compute_domain_digest("ibex/authenticated-graph-snapshot/1", &graph_snapshot, &[])?;
    let mut policy = serde_json::json!({
        "policySchema": "ibex/capsec-policy/2",
        "capsVocab": crate::capsec_registry_generated::CAPSEC_PROFILE,
        "semanticCore": crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE,
        "vocabDigest": vocab_digest,
        "registryDigest": registry_digest,
        "policyDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "purpose": "production",
        "mode": "enforce",
        "graphIdentity": graph_identity,
        "entryIdentity": entry_identity,
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
    let mut root_ceiling_rows = Vec::new();
    if dev_project_root.is_some() {
        root_ceiling_rows.push((
            super::exact_dev_served_agent_listener_selector().map_err(anyhow::Error::msg)?,
            "Exact dev-served agent listener",
        ));
    }
    if let Some((capsule, _, _)) = runtime_extension.as_ref() {
        for descriptor in &capsule.descriptors {
            for operation in &descriptor.authority_fragment.operations {
                root_ceiling_rows.push((
                    AuthoritySelector {
                        action: ActionId::new("runtime-extension:invoke")
                            .map_err(anyhow::Error::msg)?,
                        resource: SelectorResource::RuntimeExtension {
                            extension_id: descriptor.id.clone(),
                            authority_class: operation.authority_class.clone(),
                        },
                    },
                    "authenticated runtime-extension authority capsule",
                ));
            }
        }
    }
    let mut keyed_root_ceiling_rows = root_ceiling_rows
        .into_iter()
        .map(|(authority, source)| {
            let key =
                capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(&authority)?)?;
            Ok((key, authority, source))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed_root_ceiling_rows.sort_by(|left, right| left.0.cmp(&right.0));
    keyed_root_ceiling_rows.dedup_by(|left, right| left.0 == right.0);
    policy["rootCeiling"] = serde_json::Value::Array(
        keyed_root_ceiling_rows
            .into_iter()
            .map(|(_, authority, source)| {
                serde_json::json!({
                    "authority": authority,
                    "provenance": [{
                        "kind": "direct",
                        "source": source
                    }]
                })
            })
            .collect(),
    );
    let policy_digest = compute_checked_contract_digest(DigestKind::Policy, &policy)?;
    policy["policyDigest"] = serde_json::json!(policy_digest);
    let canonical_policy = capsec_semantics::policy::CanonicalPolicy::load(
        &serde_json::to_vec(&policy)?,
        &expected_policy_identity,
        &policy_profile.definitions,
    )
    .context("default Exact production policy failed typed validation")?;
    let canonical_policy = admit_exact_production_policy(canonical_policy)?;
    policy = serde_json::to_value(&canonical_policy)?;

    let engine = crate::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg)?;
    let mut binding = parse_exact_operation_manifest(operation_manifest_bytes)?;
    if let Some(carrier_binding_json) = carrier_binding_json {
        binding = bind_exact_carrier(binding, carrier_binding_json)?;
    }
    phase.mark("builder_manifests");
    let mut root_builtins = crate::module_loader::RUNTIME_GATED_NODE_BUILTINS
        .iter()
        .map(|name| format!("node:{name}"))
        .collect::<Vec<_>>();
    if let Some((capsule, _, _)) = runtime_extension.as_ref() {
        for descriptor in &capsule.descriptors {
            for module in &descriptor.modules {
                let specifier = module.specifier.as_str();
                anyhow::ensure!(
                    !crate::module_loader::is_registered_builtin_specifier(specifier),
                    "runtime-extension module specifier {specifier:?} collides with an Ibex core builtin"
                );
                root_builtins.push(specifier.to_owned());
            }
        }
    }
    root_builtins.sort();
    root_builtins.dedup();

    let mut document: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    document["workflow"] = serde_json::json!("production");
    document["effectiveMode"] = serde_json::json!("enforce");
    document["policyDigest"] = serde_json::to_value(&canonical_policy.policy_digest)?;
    let root_authorities = canonical_policy
        .root_ceiling
        .iter()
        .map(|row| row.authority.clone())
        .collect::<Vec<_>>();
    document["rootAuthorityCeiling"] = serde_json::json!({
        "kind": "bounded",
        "authorities": root_authorities.clone(),
    });
    // @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine — the
    // current bootstrap has no root-attributed capability effect, so its exact
    // least-authority floor is empty; future effects must add source-derived
    // selectors and retained-callback denial evidence together.
    document["bootstrapAuthorityFloor"] = serde_json::json!([]);
    document["engine"] = serde_json::json!({
        "target": runtime_target_triple(),
        "binaryDigest": engine.binary_digest,
        "features": engine.structural_features,
    });
    let root_floor = serde_json::to_value(&root_authorities)?;
    document["principals"] = serde_json::json!([{
        "principal": {"kind": "root", "identity": "project-root"},
        "floor": root_floor,
        "denials": [],
        "escalationCeiling": [],
        "imports": {"builtins": root_builtins, "packages": []},
        "endowments": [],
    }]);
    document["packageGraph"] = serde_json::json!({
        "digest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "nodes": [],
        "importEdges": [],
    });
    let graph_digest = compute_domain_digest(
        "ibex:capsec:package-graph:1",
        &document["packageGraph"],
        &["digest".to_owned()],
    )?;
    document["packageGraph"]["digest"] = serde_json::json!(graph_digest);
    let mut epoch = [0_u8; 8];
    getrandom::getrandom(&mut epoch).context("failed to generate CapSec channel epoch")?;
    document["channelEpoch"] = serde_json::json!(u64::from_le_bytes(epoch).max(1).to_string());

    let cache_root = crate::runtime_cache_dir()?;
    std::fs::create_dir_all(&cache_root)?;
    let cache_root = std::fs::canonicalize(cache_root)?;
    let project_host_path = absolute_artifact_path(project_root)?;
    let cache_host_path = absolute_artifact_path(&cache_root)?;
    let project_object = super::object_identity_for_host_path(project_root)?;
    let cache_object = super::object_identity_for_host_path(&cache_root)?;
    document["rootBindings"] = serde_json::json!([
        {
            "logicalRoot": "project",
            "hostPath": project_host_path,
            "object": project_object,
        },
        {
            "logicalRoot": "home",
            "hostPath": cache_host_path,
            "object": cache_object,
        },
    ]);
    document["projectRootDiscovery"] =
        serde_json::to_value(capsec_semantics::arming::ArmedProjectRootDiscovery {
            origin: project_host_path.clone(),
            selected_root: project_host_path.clone(),
            marker_kind: capsec_semantics::arming::ArmedProjectRootMarkerKind::ExplicitProject,
            marker_path: Some(project_host_path.clone()),
            marker_set_version: capsec_semantics::arming::PROJECT_ROOT_MARKER_SET_VERSION.into(),
        })?;
    if dev_project_root.is_some() {
        document["bootstrapCompatibilityModes"] = serde_json::json!(["dev-served"]);
        document["devServedProjectRoot"] = serde_json::to_value(&project_host_path)?;
    }
    document["pathCanonicalizers"] = serde_json::to_value(bound_volume_path_canonicalizers([
        (project_root.as_path(), &project_object),
        (cache_root.as_path(), &cache_object),
    ])?)?;
    document["exactEmbedder"] = serde_json::to_value(&binding)?;
    if let Some((capsule, _, _)) = runtime_extension.as_ref() {
        document["runtimeExtensions"] = serde_json::to_value(capsule)?;
    } else if let Some(document) = document.as_object_mut() {
        document.remove("runtimeExtensions");
    }

    let policy_bytes = capsec_semantics::canonical::to_jcs_bytes(&policy)?;
    let graph_bytes = capsec_semantics::canonical::to_jcs_bytes(&document["packageGraph"])?;
    let policy_artifact = materialize_protected_artifact(
        "armed-policy",
        &policy_bytes,
        &canonical_policy.policy_digest,
    )?;
    let graph_artifact = materialize_protected_artifact(
        "package-graph",
        &graph_bytes,
        &Digest::new(&graph_digest).map_err(anyhow::Error::msg)?,
    )?;
    let registry_artifact = match pin_precomputed_registry_artifact(&cache_root, &registry_digest)?
    {
        Some(artifact) => artifact,
        None => materialize_protected_artifact(
            "registry",
            CAPSEC_REGISTRY_RECORD_JCS,
            &registry_digest,
        )?,
    };
    let manifest_artifact = materialize_protected_artifact(
        "exact-operation-manifest",
        operation_manifest_bytes,
        binding.operation_manifest_digest(),
    )?;
    let runtime_extension_capsule_artifact =
        if let Some((capsule, _, canonical_bytes)) = runtime_extension.as_ref() {
            Some(materialize_protected_artifact(
                "runtime-extension-authority-capsule",
                canonical_bytes,
                &capsule.authority_capsule_digest,
            )?)
        } else {
            None
        };
    phase.mark("builder_materialize");
    let mut protected_objects = vec![
        serde_json::json!({"role": "armed-policy", "object": policy_artifact.object, "deniedActions": ["fs:write"]}),
        serde_json::json!({"role": "engine-binary", "object": engine.object, "deniedActions": ["fs:write"]}),
        serde_json::json!({"role": "package-graph", "object": graph_artifact.object, "deniedActions": ["fs:write"]}),
        serde_json::json!({"role": "registry", "object": registry_artifact.object, "deniedActions": ["fs:write"]}),
        serde_json::json!({"role": "exact-operation-manifest", "object": manifest_artifact.object, "deniedActions": ["fs:write"]}),
    ];
    if let Some(capsule_artifact) = runtime_extension_capsule_artifact.as_ref() {
        protected_objects.push(serde_json::json!({
            "role": "runtime-extension-authority-capsule",
            "object": capsule_artifact.object,
            "deniedActions": ["fs:write"],
        }));
    }
    document["protectedObjects"] = serde_json::Value::Array(protected_objects);
    let armed_digest = freshen_document(&mut document, fresh_production_nonce()?)?;

    let mut expected = ExpectedArmingIdentity {
        profile: crate::capsec_registry_generated::CAPSEC_PROFILE.into(),
        semantic_core: crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE.into(),
        vocab_digest,
        registry_digest,
        policy_digest: canonical_policy.policy_digest,
        armed_snapshot_digest: armed_digest.clone(),
        target: runtime_target_triple(),
        engine_binary_digest: Digest::new(&engine.binary_digest).map_err(anyhow::Error::msg)?,
        features: engine.structural_features,
        package_graph_digest: Digest::new(graph_digest).map_err(anyhow::Error::msg)?,
        entry: serde_json::from_value(document["entry"].clone())?,
        project_root_discovery: serde_json::from_value(document["projectRootDiscovery"].clone())?,
        path_canonicalizers: serde_json::from_value(document["pathCanonicalizers"].clone())?,
        protected_artifacts: vec![
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::ArmedPolicy,
                host_path: policy_artifact.host_path,
                object: policy_artifact.object,
                content_digest: policy_artifact.content_digest,
            },
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::EngineBinary,
                host_path: absolute_artifact_path(&engine.engine_artifact_path)?,
                object: engine.object,
                content_digest: Digest::new(&engine.binary_digest).map_err(anyhow::Error::msg)?,
            },
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::PackageGraph,
                host_path: graph_artifact.host_path,
                object: graph_artifact.object,
                content_digest: graph_artifact.content_digest,
            },
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::Registry,
                host_path: registry_artifact.host_path,
                object: registry_artifact.object,
                content_digest: registry_artifact.content_digest,
            },
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::ExactOperationManifest,
                host_path: manifest_artifact.host_path,
                object: manifest_artifact.object,
                content_digest: manifest_artifact.content_digest,
            },
        ],
        embedded_protected_artifacts: Vec::new(),
        runtime_extension_authority_digest: runtime_extension
            .as_ref()
            .map(|(capsule, _, _)| capsule.authority_capsule_digest.clone()),
        runtime_extension_mapped_executable: runtime_extension
            .as_ref()
            .map(|(_, observed, _)| observed.clone()),
    };
    if let Some(capsule_artifact) = runtime_extension_capsule_artifact {
        expected
            .protected_artifacts
            .push(ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::RuntimeExtensionAuthorityCapsule,
                host_path: capsule_artifact.host_path,
                object: capsule_artifact.object,
                // Protected file digests are raw SHA-256. The capsule's
                // domain-separated authority digest is authenticated
                // independently above.
                content_digest: capsule_artifact.content_digest,
            });
    }
    let snapshot_bytes = serde_json::to_vec(&document)?;
    let snapshot = ArmedSnapshot::load(&snapshot_bytes, &expected)
        .map_err(|error| anyhow::anyhow!("built Exact snapshot authentication refused: {error}"))?;
    super::validate_loaded_engine_identity(&snapshot)?;
    super::validate_snapshot_protected_artifacts(&snapshot)?;
    super::validate_snapshot_root_bindings(&snapshot)?;

    Ok(PreparedEmbedderArtifacts {
        artifact_schema: "ibex/armed-embedder-artifacts/1",
        armed_snapshot_digest: armed_digest.as_str().to_owned(),
        snapshot: document,
        expected_identity: expected,
    })
}

/// Authenticate a generic Ibex artifact pair, bind Exact's checked operation
/// manifest as the fifth protected artifact, and freshen the result.
///
/// This is target-local by design: materializing the protected manifest and
/// authenticating the engine/root objects must happen after application
/// installation, where their real filesystem identities exist. The caller
/// supplies no operation allowlist; all three context endowments are derived
/// from the one strict manifest byte string.
/// @ref LLP 0002#the-exact-embedder-ingress — the manifest digest and complete
/// context projection are authenticated before Exact can install its channel.
pub fn prepare_exact_embedder_artifacts(
    template_bytes: &[u8],
    expected_identity_bytes: &[u8],
    operation_manifest_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    prepare_exact_embedder_artifacts_inner(
        template_bytes,
        expected_identity_bytes,
        operation_manifest_bytes,
        None,
    )
}

/// Carrier-bearing sibling of [`prepare_exact_embedder_artifacts`]: the
/// strict `exact/carrier-binding/1` JSON input is validated and embedded as
/// the required `carrierBinding` of a /2 binding before nonce freshening.
// @ref LLP 0053#r2-i2--carrier-identity-in-the-armed-snapshot
pub fn prepare_exact_embedder_artifacts_v2(
    template_bytes: &[u8],
    expected_identity_bytes: &[u8],
    operation_manifest_bytes: &[u8],
    carrier_binding_json: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    prepare_exact_embedder_artifacts_inner(
        template_bytes,
        expected_identity_bytes,
        operation_manifest_bytes,
        Some(carrier_binding_json),
    )
}

fn prepare_exact_embedder_artifacts_inner(
    template_bytes: &[u8],
    expected_identity_bytes: &[u8],
    operation_manifest_bytes: &[u8],
    carrier_binding_json: Option<&[u8]>,
) -> Result<PreparedEmbedderArtifacts> {
    super::reject_closed_startup_environment()?;
    let expected_text = std::str::from_utf8(expected_identity_bytes)
        .context("expected arming identity is not UTF-8")?;
    let expected_value = capsec_semantics::strict_json::parse_strict(expected_text)
        .context("expected arming identity is not strict JSON")?;
    let supplied: ExpectedArmingIdentity =
        serde_json::from_value(expected_value).context("invalid expected arming identity")?;
    let mut expected = verify_expected_identity(supplied)?;

    let template = ArmedSnapshot::load(template_bytes, &expected)
        .context("snapshot template authentication refused")?;
    super::validate_loaded_engine_identity(&template)?;
    super::validate_snapshot_protected_artifacts(&template)?;
    super::validate_snapshot_root_bindings(&template)?;
    anyhow::ensure!(
        template.document().get("exactEmbedder").is_none(),
        "snapshot template already carries an Exact embedder binding"
    );
    anyhow::ensure!(
        !expected
            .protected_artifacts
            .iter()
            .any(|artifact| artifact.role == ProtectedArtifactRole::ExactOperationManifest),
        "expected identity already carries an Exact operation manifest"
    );

    let mut binding = parse_exact_operation_manifest(operation_manifest_bytes)?;
    if let Some(carrier_binding_json) = carrier_binding_json {
        binding = bind_exact_carrier(binding, carrier_binding_json)?;
    }
    let manifest = materialize_protected_artifact(
        "exact-operation-manifest",
        operation_manifest_bytes,
        binding.operation_manifest_digest(),
    )?;
    let mut document = template.document().clone();
    document["exactEmbedder"] = serde_json::to_value(binding)?;
    document["protectedObjects"]
        .as_array_mut()
        .context("snapshot protectedObjects must be an array")?
        .push(serde_json::json!({
            "role": "exact-operation-manifest",
            "object": manifest.object.clone(),
            "deniedActions": ["fs:write"],
        }));
    expected
        .protected_artifacts
        .push(ExpectedProtectedArtifact {
            role: ProtectedArtifactRole::ExactOperationManifest,
            host_path: manifest.host_path,
            object: manifest.object,
            content_digest: manifest.content_digest,
        });

    let digest = freshen_document(&mut document, fresh_production_nonce()?)?;
    expected.armed_snapshot_digest = digest.clone();
    let fresh_bytes = serde_json::to_vec(&document)?;
    let fresh = ArmedSnapshot::load(&fresh_bytes, &expected)
        .context("Exact-bound snapshot authentication refused")?;
    super::validate_loaded_engine_identity(&fresh)?;
    super::validate_snapshot_protected_artifacts(&fresh)?;
    super::validate_snapshot_root_bindings(&fresh)?;

    Ok(PreparedEmbedderArtifacts {
        artifact_schema: "ibex/armed-embedder-artifacts/1",
        armed_snapshot_digest: digest.as_str().to_owned(),
        snapshot: document,
        expected_identity: expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_semantics::arming::{ExpectedProtectedArtifact, ProtectedArtifactRole};
    use capsec_semantics::model::{LogicalPath, LogicalRoot};
    use sha2::Sha256;

    struct RealEmbedderFixture {
        _temp: tempfile::TempDir,
        project_root: std::path::PathBuf,
        snapshot: Vec<u8>,
        expected_identity: Vec<u8>,
    }

    fn content_digest(bytes: &[u8]) -> Digest {
        Digest::new(format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
        ))
        .unwrap()
    }

    fn absolute_host_path(path: &std::path::Path) -> LogicalPath {
        LogicalPath {
            root: LogicalRoot::Absolute,
            components: super::super::host_path_components(path).unwrap(),
            host_bound: Some(true),
        }
    }

    fn materialize_test_artifact(
        directory: &std::path::Path,
        name: &str,
        bytes: &[u8],
    ) -> (LogicalPath, capsec_semantics::model::ObjectIdentity, Digest) {
        let path = directory.join(name);
        std::fs::write(&path, bytes).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            permissions.set_mode(0o400);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        let path = std::fs::canonicalize(path).unwrap();
        (
            absolute_host_path(&path),
            super::super::object_identity_for_host_path(&path).unwrap(),
            content_digest(bytes),
        )
    }

    fn real_embedder_fixture() -> RealEmbedderFixture {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let artifacts = temp.path().join("artifacts");
        std::fs::create_dir(&project_root).unwrap();
        std::fs::create_dir(&artifacts).unwrap();
        let project_root = std::fs::canonicalize(project_root).unwrap();

        let engine = crate::engine::loaded_engine_binary_identity().unwrap();
        let mut snapshot: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        snapshot["workflow"] = serde_json::json!("production");
        snapshot["effectiveMode"] = serde_json::json!("enforce");
        snapshot["environmentBase"] = serde_json::json!([]);
        snapshot["engine"] = serde_json::json!({
            "target": runtime_target_triple(),
            "binaryDigest": engine.binary_digest,
            "features": engine.structural_features,
        });

        let root_identity = snapshot["rootIdentity"].clone();
        snapshot["principals"] = serde_json::json!([{
            "principal": root_identity,
            "floor": [],
            "denials": [],
            "escalationCeiling": [],
            "imports": {"builtins": [], "packages": []},
            "endowments": [],
        }]);
        snapshot["packageGraph"]["nodes"] = serde_json::json!([]);
        snapshot["packageGraph"]["importEdges"] = serde_json::json!([]);
        snapshot["packageGraph"]["digest"] =
            serde_json::json!(capsec_semantics::digest::compute_domain_digest(
                "ibex:capsec:package-graph:1",
                &snapshot["packageGraph"],
                &["digest".to_owned()],
            )
            .unwrap());
        snapshot["rootBindings"] = serde_json::json!([{
            "logicalRoot": "project",
            "hostPath": absolute_host_path(&project_root),
            "object": super::super::object_identity_for_host_path(&project_root).unwrap(),
        }]);
        let project_path = absolute_host_path(&project_root);
        snapshot["projectRootDiscovery"] = serde_json::json!({
            "origin": project_path,
            "selectedRoot": absolute_host_path(&project_root),
            "markerKind": "explicit-project",
            "markerPath": absolute_host_path(&project_root),
            "markerSetVersion": capsec_semantics::arming::PROJECT_ROOT_MARKER_SET_VERSION,
        });
        let fixture_bindings: Vec<capsec_semantics::arming::ArmedRootBinding> =
            serde_json::from_value(snapshot["rootBindings"].clone()).unwrap();
        snapshot["pathCanonicalizers"] = serde_json::to_value(
            capsec_semantics::path_alias::contract_fixture_canonicalizer_rows(
                fixture_bindings
                    .iter()
                    .map(|binding| (binding.object.platform, binding.object.volume.clone())),
            )
            .unwrap(),
        )
        .unwrap();

        let (policy_path, policy_object, policy_content) = materialize_test_artifact(
            &artifacts,
            "armed-policy.json",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/capsec/examples/canonical-policy.canonical.json"
            )),
        );
        let graph_bytes =
            capsec_semantics::canonical::to_jcs_bytes(&snapshot["packageGraph"]).unwrap();
        let (graph_path, graph_object, graph_content) =
            materialize_test_artifact(&artifacts, "package-graph.json", &graph_bytes);
        let (registry_path, registry_object, registry_content) =
            materialize_test_artifact(&artifacts, "registry.json", b"authenticated registry");
        let protected_objects = [
            ("armed-policy", &policy_object),
            ("engine-binary", &engine.object),
            ("package-graph", &graph_object),
            ("registry", &registry_object),
        ];
        for (role, object) in protected_objects {
            snapshot["protectedObjects"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["role"] == role)
                .unwrap()["object"] = serde_json::to_value(object).unwrap();
        }

        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &snapshot).unwrap();
        snapshot["armedSnapshotDigest"] = serde_json::json!(digest);
        let digest_at = |path: &[&str]| {
            let field = path
                .iter()
                .fold(&snapshot, |current, segment| &current[*segment]);
            Digest::new(field.as_str().unwrap()).unwrap()
        };
        let expected = ExpectedArmingIdentity {
            profile: snapshot["capsVocab"].as_str().unwrap().into(),
            semantic_core: snapshot["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest_at(&["vocabDigest"]),
            registry_digest: digest_at(&["registryDigest"]),
            policy_digest: digest_at(&["policyDigest"]),
            armed_snapshot_digest: digest_at(&["armedSnapshotDigest"]),
            target: snapshot["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: snapshot["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            entry: serde_json::from_value(snapshot["entry"].clone()).unwrap(),
            project_root_discovery: serde_json::from_value(
                snapshot["projectRootDiscovery"].clone(),
            )
            .unwrap(),
            path_canonicalizers: serde_json::from_value(snapshot["pathCanonicalizers"].clone())
                .unwrap(),
            protected_artifacts: vec![
                ExpectedProtectedArtifact {
                    role: ProtectedArtifactRole::ArmedPolicy,
                    host_path: policy_path,
                    object: policy_object,
                    content_digest: policy_content,
                },
                ExpectedProtectedArtifact {
                    role: ProtectedArtifactRole::EngineBinary,
                    host_path: absolute_host_path(&engine.engine_artifact_path),
                    object: engine.object,
                    content_digest: digest_at(&["engine", "binaryDigest"]),
                },
                ExpectedProtectedArtifact {
                    role: ProtectedArtifactRole::PackageGraph,
                    host_path: graph_path,
                    object: graph_object,
                    content_digest: graph_content,
                },
                ExpectedProtectedArtifact {
                    role: ProtectedArtifactRole::Registry,
                    host_path: registry_path,
                    object: registry_object,
                    content_digest: registry_content,
                },
            ],
            embedded_protected_artifacts: Vec::new(),
            runtime_extension_authority_digest: None,
            runtime_extension_mapped_executable: None,
        };

        RealEmbedderFixture {
            _temp: temp,
            project_root,
            snapshot: serde_json::to_vec(&snapshot).unwrap(),
            expected_identity: serde_json::to_vec(&expected).unwrap(),
        }
    }

    fn prepare_through_abi(fixture: &RealEmbedderFixture) -> serde_json::Value {
        let output = unsafe {
            crate::host::abi::ex_host_prepare_armed_embedder_artifacts(
                fixture.snapshot.as_ptr(),
                fixture.snapshot.len(),
                fixture.expected_identity.as_ptr(),
                fixture.expected_identity.len(),
            )
        };
        assert!(!output.is_null());
        let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
            .to_bytes()
            .to_vec();
        crate::host::abi::ex_host_free_string(output);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn exact_manifest() -> Vec<u8> {
        br#"{
          "$schema":"./host-call-operations.schema.json",
          "schema":"exact.host-call-operations/v1",
          "schemaVersion":1,
          "operations":[
            {"id":1000,"name":"app.render"},
            {"id":2200,"name":"agentIsolate.appRuntimeHealth"},
            {"id":2201,"name":"agentIsolate.bindFailed"},
            {"id":2202,"name":"agentIsolate.config"},
            {"id":2203,"name":"agentIsolate.ready"}
          ],
          "endowments":{
            "app":[1000],
            "agentIsolate":[2200,2201,2202,2203],
            "uiWorklet":[]
          }
        }"#
        .to_vec()
    }

    fn prepare_exact_through_abi(fixture: &RealEmbedderFixture) -> serde_json::Value {
        let manifest = exact_manifest();
        let output = unsafe {
            crate::host::abi::ex_host_prepare_exact_armed_embedder_artifacts(
                fixture.snapshot.as_ptr(),
                fixture.snapshot.len(),
                fixture.expected_identity.as_ptr(),
                fixture.expected_identity.len(),
                manifest.as_ptr(),
                manifest.len(),
            )
        };
        assert!(!output.is_null());
        let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
            .to_bytes()
            .to_vec();
        crate::host::abi::ex_host_free_string(output);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn build_exact_through_abi(project_root: &std::path::Path) -> serde_json::Value {
        let root = project_root.to_str().unwrap().as_bytes();
        let manifest = exact_manifest();
        let output = unsafe {
            crate::host::abi::ex_host_build_exact_armed_embedder_artifacts(
                root.as_ptr(),
                root.len(),
                std::ptr::null(),
                0,
                manifest.as_ptr(),
                manifest.len(),
            )
        };
        assert!(!output.is_null());
        let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
            .to_bytes()
            .to_vec();
        crate::host::abi::ex_host_free_string(output);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn build_exact_dev_through_abi(
        project_root: &std::path::Path,
        dev_project_root: &std::path::Path,
    ) -> serde_json::Value {
        let root = project_root.to_str().unwrap().as_bytes();
        let dev_root = dev_project_root.to_str().unwrap().as_bytes();
        let manifest = exact_manifest();
        let output = unsafe {
            crate::host::abi::ex_host_build_exact_armed_embedder_artifacts(
                root.as_ptr(),
                root.len(),
                dev_root.as_ptr(),
                dev_root.len(),
                manifest.as_ptr(),
                manifest.len(),
            )
        };
        assert!(!output.is_null());
        let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
            .to_bytes()
            .to_vec();
        crate::host::abi::ex_host_free_string(output);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn with_exact_embedder_binding(mut fixture: RealEmbedderFixture) -> RealEmbedderFixture {
        let mut snapshot: serde_json::Value = serde_json::from_slice(&fixture.snapshot).unwrap();
        let mut expected: ExpectedArmingIdentity =
            serde_json::from_slice(&fixture.expected_identity).unwrap();
        let manifest_bytes = br#"{"schema":"exact.host-call-operations/v1"}"#;
        let (host_path, object, manifest_digest) = materialize_test_artifact(
            &fixture._temp.path().join("artifacts"),
            "exact-host-call-operations.json",
            manifest_bytes,
        );
        snapshot["exactEmbedder"] = serde_json::json!({
            "schema": "exact/host-operation-endowments/1",
            "operationManifestDigest": manifest_digest,
            "endowments": {
                "app": [7, 11],
                "agentIsolate": [19],
                "uiWorklet": [],
            }
        });
        snapshot["protectedObjects"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "role": "exact-operation-manifest",
                "object": object,
                "deniedActions": ["fs:write"]
            }));
        expected
            .protected_artifacts
            .push(ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::ExactOperationManifest,
                host_path,
                object,
                content_digest: manifest_digest,
            });
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &snapshot).unwrap();
        snapshot["armedSnapshotDigest"] = serde_json::json!(digest);
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        fixture.snapshot = serde_json::to_vec(&snapshot).unwrap();
        fixture.expected_identity = serde_json::to_vec(&expected).unwrap();
        fixture
    }

    fn expected_for_static_verification() -> ExpectedArmingIdentity {
        let checked: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        let digest = |path: &[&str]| {
            let value = path
                .iter()
                .fold(&checked, |current, segment| &current[*segment]);
            Digest::new(value.as_str().unwrap()).unwrap()
        };
        let engine = crate::engine::loaded_engine_binary_identity().unwrap();
        ExpectedArmingIdentity {
            profile: checked["capsVocab"].as_str().unwrap().into(),
            semantic_core: checked["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest(&["vocabDigest"]),
            registry_digest: digest(&["registryDigest"]),
            policy_digest: digest(&["policyDigest"]),
            armed_snapshot_digest: digest(&["armedSnapshotDigest"]),
            target: runtime_target_triple(),
            engine_binary_digest: Digest::new(engine.binary_digest).unwrap(),
            features: engine.structural_features,
            package_graph_digest: digest(&["packageGraph", "digest"]),
            entry: serde_json::from_value(checked["entry"].clone()).unwrap(),
            project_root_discovery: serde_json::from_value(checked["projectRootDiscovery"].clone())
                .unwrap(),
            path_canonicalizers: serde_json::from_value(checked["pathCanonicalizers"].clone())
                .unwrap(),
            protected_artifacts: Vec::new(),
            embedded_protected_artifacts: Vec::new(),
            runtime_extension_authority_digest: None,
            runtime_extension_mapped_executable: None,
        }
    }

    #[test]
    fn expected_identity_verification_refuses_wrong_target_and_registry() {
        let expected = expected_for_static_verification();
        assert_eq!(
            verify_expected_identity(expected.clone()).unwrap(),
            expected
        );

        let mut wrong_target = expected.clone();
        wrong_target.target = if runtime_target_triple() == "x86_64-unknown-linux-gnu" {
            "aarch64-apple-darwin"
        } else {
            "x86_64-unknown-linux-gnu"
        }
        .into();
        assert!(verify_expected_identity(wrong_target)
            .unwrap_err()
            .to_string()
            .contains("target does not match"));

        let mut wrong_registry = expected;
        wrong_registry.registry_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(verify_expected_identity(wrong_registry)
            .unwrap_err()
            .to_string()
            .contains("registry digest does not match"));
    }

    #[test]
    fn freshening_replaces_reserved_nonce_and_is_replay_distinct() {
        let source = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        ));
        let original: serde_json::Value = serde_json::from_slice(source).unwrap();
        let mut first = original.clone();
        let mut second = original;
        let first_digest = freshen_document(&mut first, fresh_production_nonce().unwrap()).unwrap();
        let second_digest =
            freshen_document(&mut second, fresh_production_nonce().unwrap()).unwrap();
        assert_ne!(first["runNonce"], CONTRACT_FIXTURE_RUN_NONCE);
        assert_ne!(second["runNonce"], CONTRACT_FIXTURE_RUN_NONCE);
        assert_ne!(first["runNonce"], second["runNonce"]);
        assert_ne!(first_digest, second_digest);
    }

    #[test]
    fn freshening_binds_nonce_into_checked_digest() {
        let source = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        ));
        let mut document: serde_json::Value = serde_json::from_slice(source).unwrap();
        let digest = freshen_document(&mut document, "EREREREREREREREREREREQ".to_owned()).unwrap();
        assert_eq!(document["armedSnapshotDigest"], digest.as_str());
        assert_eq!(
            compute_checked_contract_digest(DigestKind::ArmedSnapshot, &document).unwrap(),
            digest.as_str()
        );
    }

    #[test]
    fn public_prepare_round_trips_a_real_authenticated_pair() {
        let fixture = real_embedder_fixture();
        let envelope = prepare_through_abi(&fixture);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["artifactSchema"],
            "ibex/armed-embedder-artifacts/1"
        );
        assert_ne!(
            artifacts["snapshot"]["runNonce"],
            CONTRACT_FIXTURE_RUN_NONCE
        );
        assert_eq!(
            artifacts["snapshot"]["armedSnapshotDigest"],
            artifacts["armedSnapshotDigest"]
        );

        let returned_expected: ExpectedArmingIdentity =
            serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap();
        let returned_snapshot = serde_json::to_vec(&artifacts["snapshot"]).unwrap();
        let reingested = ArmedSnapshot::load(&returned_snapshot, &returned_expected).unwrap();
        super::super::validate_loaded_engine_identity(&reingested).unwrap();
        super::super::validate_snapshot_protected_artifacts(&reingested).unwrap();
        super::super::validate_snapshot_root_bindings(&reingested).unwrap();
        assert_eq!(
            reingested.digest().as_str(),
            artifacts["armedSnapshotDigest"].as_str().unwrap()
        );
    }

    #[test]
    fn target_local_exact_builder_refuses_typed_package_bearing_production_policy() {
        let policy_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/canonical-policy.canonical.json"
        ));
        let (vocab_digest, registry_digest) = checked_identity_digests().unwrap();
        let expected_policy_identity = capsec_semantics::policy::ExpectedPolicyIdentity {
            profile: crate::capsec_registry_generated::CAPSEC_PROFILE.into(),
            semantic_core: crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE.into(),
            vocab_digest,
            registry_digest,
        };
        let policy_profile =
            capsec_semantics::registry::ValidatedProfile::from_json_with_runtime_extensions(
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/capsec/registry/capability-definitions.json"
                )),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/capsec/registry/policy-rules.json"
                )),
                false,
            )
            .unwrap();
        let package_policy = capsec_semantics::policy::CanonicalPolicy::load(
            policy_bytes,
            &expected_policy_identity,
            &policy_profile.definitions,
        )
        .expect("package-bearing fixture must be a typed production policy");
        assert_eq!(package_policy.purpose, "production");
        assert_eq!(package_policy.mode, "enforce");
        assert!(
            !package_policy.principals.is_empty()
                && package_policy
                    .principals
                    .iter()
                    .all(|row| row.principal.is_package()),
            "fixture must carry authenticated package principals"
        );

        let error = admit_exact_production_policy(package_policy).unwrap_err();
        assert_eq!(
            error.to_string(),
            "target-local Exact builder refuses package-bearing production policies; only the canonical empty package policy is accepted"
        );
    }

    #[test]
    fn target_local_exact_builder_authenticates_a_complete_pair() {
        let project = tempfile::tempdir().unwrap();
        let envelope = build_exact_through_abi(project.path());
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["artifactSchema"],
            "ibex/armed-embedder-artifacts/1"
        );
        assert_eq!(artifacts["snapshot"]["workflow"], "production");
        assert_eq!(artifacts["snapshot"]["effectiveMode"], "enforce");
        assert_eq!(
            artifacts["snapshot"]["packageGraph"]["nodes"],
            serde_json::json!([])
        );
        assert_eq!(
            artifacts["expectedIdentity"]["protectedArtifacts"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["endowments"]["agentIsolate"],
            serde_json::json!([2200, 2201, 2202, 2203])
        );
        let mut expected_root_builtins = crate::module_loader::RUNTIME_GATED_NODE_BUILTINS
            .iter()
            .map(|name| format!("node:{name}"))
            .collect::<Vec<_>>();
        expected_root_builtins.sort();
        assert_eq!(
            artifacts["snapshot"]["principals"][0]["imports"]["builtins"],
            serde_json::to_value(expected_root_builtins).unwrap(),
            "a no-extension build must retain the exact canonical builtin set"
        );
        let expected: ExpectedArmingIdentity =
            serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap();
        ArmedSnapshot::load(
            &serde_json::to_vec(&artifacts["snapshot"]).unwrap(),
            &expected,
        )
        .unwrap();
    }

    #[test]
    fn target_local_runtime_extension_builder_authenticates_capsule_and_mapped_executable() {
        let project = tempfile::tempdir().unwrap();
        let capsule = crate::host::tests::runtime_extension_test_capsule();
        let capsule_bytes =
            capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(&capsule).unwrap())
                .unwrap();
        let observed_bytes = capsec_semantics::canonical::to_jcs_bytes(
            &serde_json::to_value(&capsule.mapped_executable).unwrap(),
        )
        .unwrap();
        let artifacts = build_exact_runtime_extension_embedder_artifacts(
            project.path(),
            None,
            &exact_manifest(),
            &capsule_bytes,
            &observed_bytes,
        )
        .unwrap();

        assert_eq!(
            artifacts.snapshot["runtimeExtensions"]["authorityCapsuleDigest"],
            serde_json::to_value(&capsule.authority_capsule_digest).unwrap()
        );
        assert_eq!(
            artifacts
                .expected_identity
                .runtime_extension_authority_digest,
            Some(capsule.authority_capsule_digest.clone())
        );
        assert_eq!(
            artifacts
                .expected_identity
                .runtime_extension_mapped_executable,
            Some(capsule.mapped_executable.clone())
        );
        let root_builtins = artifacts.snapshot["principals"][0]["imports"]["builtins"]
            .as_array()
            .unwrap();
        assert_eq!(
            root_builtins
                .iter()
                .filter(|specifier| *specifier == "@ibex/conformance")
                .count(),
            1,
            "the authenticated selected extension module must be exact-allowlisted"
        );
        assert!(
            root_builtins
                .windows(2)
                .all(|pair| { pair[0].as_str().unwrap() < pair[1].as_str().unwrap() }),
            "the selected root builtin allowlist must be sorted and unique"
        );
        let protected = artifacts
            .expected_identity
            .protected_artifacts
            .iter()
            .find(|artifact| {
                artifact.role == ProtectedArtifactRole::RuntimeExtensionAuthorityCapsule
            })
            .unwrap();
        assert_eq!(protected.content_digest, content_digest(&capsule_bytes));
        assert_ne!(
            protected.content_digest,
            capsule.authority_capsule_digest,
            "raw protected-file SHA-256 and domain-separated semantic authority digest are distinct layers"
        );

        let snapshot = ArmedSnapshot::load(
            &serde_json::to_vec(&artifacts.snapshot).unwrap(),
            &artifacts.expected_identity,
        )
        .unwrap();
        let expected_extension_authorities = capsule
            .descriptors
            .iter()
            .flat_map(|descriptor| {
                descriptor
                    .authority_fragment
                    .operations
                    .iter()
                    .map(move |operation| AuthoritySelector {
                        action: ActionId::new("runtime-extension:invoke").unwrap(),
                        resource: SelectorResource::RuntimeExtension {
                            extension_id: descriptor.id.clone(),
                            authority_class: operation.authority_class.clone(),
                        },
                    })
            })
            .collect::<BTreeSet<_>>();
        let root_floor = serde_json::from_value::<Vec<AuthoritySelector>>(
            artifacts.snapshot["principals"][0]["floor"].clone(),
        )
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
        let root_ceiling = serde_json::from_value::<Vec<AuthoritySelector>>(
            artifacts.snapshot["rootAuthorityCeiling"]["authorities"].clone(),
        )
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(
            root_floor, expected_extension_authorities,
            "the owning root floor must contain every capsule-authenticated extension/authority-class selector exactly once"
        );
        assert_eq!(
            root_ceiling, expected_extension_authorities,
            "the immutable root ceiling must match the capsule-derived floor"
        );
        super::super::validate_snapshot_protected_artifacts(&snapshot).unwrap();
        let host = unsafe {
            super::super::Host::new_armed_for_test(
                super::super::HostConfig::default(),
                std::sync::Arc::new(snapshot),
            )
        }
        .unwrap();
        assert!(
            host.check_import("0", "@ibex/conformance"),
            "the production Host must classify and allow the selected extension module exactly"
        );
        assert!(
            !host.check_import("0", "@ibex/unselected"),
            "an unselected extension-like spelling must remain outside the builtin allowlist"
        );
        let root = host.typed_principal_for_module("0").unwrap();
        for descriptor in &capsule.descriptors {
            for operation in &descriptor.authority_fragment.operations {
                let stage = serde_json::to_value(operation.stage).unwrap();
                let stage = stage.as_str().unwrap();
                let resource_kinds = operation
                    .resource_kinds
                    .iter()
                    .map(capsec_semantics::model::NonEmptyString::as_str)
                    .collect::<Vec<_>>();
                host.authorize_runtime_extension_operation(
                    1,
                    1,
                    descriptor.id.as_str(),
                    operation.operation_id.as_str(),
                    operation.authority_class.as_str(),
                    operation.semantics.as_str(),
                    stage,
                    operation.atomicity_group.as_str(),
                    &resource_kinds,
                    r#"{"fixture":"production-builder"}"#,
                    root.clone(),
                    vec![root.clone()],
                    vec![],
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "production-builder selector did not authorize {}:{}: {error}",
                        descriptor.id.as_str(),
                        operation.operation_id.as_str()
                    )
                });
            }
        }
    }

    #[test]
    fn target_local_runtime_extension_builder_refuses_core_builtin_collision() {
        let project = tempfile::tempdir().unwrap();
        let mut capsule = crate::host::tests::runtime_extension_test_capsule();
        // Use the BARE builtin spelling, not `node:fs`. Runtime-extension
        // specifiers are bare package-style names by grammar (no scheme
        // colon), so a `node:`-prefixed specifier is refused by capsule
        // validation before the builder's collision fence is ever consulted —
        // which would make this test pass its setup and never reach its
        // subject. `fs` is both grammatical and a registered builtin, so it
        // exercises the collision refusal this test is named for. The
        // scheme-prefixed case is covered separately below.
        capsule.descriptors[0].modules[0].specifier =
            capsec_semantics::model::NonEmptyString::new("fs").unwrap();
        capsule.extension_set_digest = capsule.compute_extension_set_digest().unwrap();
        capsule.declared_executable_selection_identity = capsule
            .compute_declared_executable_selection_identity()
            .unwrap();
        capsule.executable_selection_identity =
            capsule.compute_executable_selection_identity().unwrap();
        capsule.authority_capsule_digest = capsule.compute_authority_capsule_digest().unwrap();
        capsule.validate().unwrap();
        let capsule_bytes =
            capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(&capsule).unwrap())
                .unwrap();
        let observed_bytes = capsec_semantics::canonical::to_jcs_bytes(
            &serde_json::to_value(&capsule.mapped_executable).unwrap(),
        )
        .unwrap();
        let error = build_exact_runtime_extension_embedder_artifacts(
            project.path(),
            None,
            &exact_manifest(),
            &capsule_bytes,
            &observed_bytes,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("collides with an Ibex core builtin"),
            "{error:#}"
        );
    }

    /// The fence that fires *before* the builder's collision check: a
    /// scheme-prefixed specifier is not canonical runtime-extension grammar,
    /// so capsule validation refuses `node:fs` outright. Pinning this keeps
    /// the two fences distinguishable — the collision test above depends on
    /// its specifier passing grammar.
    #[test]
    fn runtime_extension_capsule_refuses_scheme_prefixed_module_specifiers() {
        for specifier in ["node:fs", "bun:sqlite", "exact:process"] {
            let mut capsule = crate::host::tests::runtime_extension_test_capsule();
            capsule.descriptors[0].modules[0].specifier =
                capsec_semantics::model::NonEmptyString::new(specifier).unwrap();
            capsule.extension_set_digest = capsule.compute_extension_set_digest().unwrap();
            capsule.declared_executable_selection_identity = capsule
                .compute_declared_executable_selection_identity()
                .unwrap();
            capsule.executable_selection_identity =
                capsule.compute_executable_selection_identity().unwrap();
            capsule.authority_capsule_digest = capsule.compute_authority_capsule_digest().unwrap();
            let error = capsule
                .validate()
                .expect_err("a scheme-prefixed specifier is not canonical grammar");
            assert!(
                error
                    .to_string()
                    .contains("does not use canonical module-specifier grammar"),
                "{specifier}: {error:#}"
            );
        }
    }

    #[test]
    fn target_local_runtime_extension_builder_refuses_launcher_identity_laundering() {
        let project = tempfile::tempdir().unwrap();
        let capsule = crate::host::tests::runtime_extension_test_capsule();
        let capsule_bytes =
            serde_json::to_vec(&capsule).expect("serialize runtime-extension capsule");
        let mut observed = capsule.mapped_executable.clone();
        observed.anchors[0].image_offset = capsec_semantics::model::SafeUint::new(4097).unwrap();
        let error = build_exact_runtime_extension_embedder_artifacts(
            project.path(),
            None,
            &exact_manifest(),
            &capsule_bytes,
            &serde_json::to_vec(&observed).unwrap(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("launcher observation"),
            "{error:#}"
        );
    }

    #[test]
    fn finalizes_template_from_the_actual_current_executable_and_refuses_drift() {
        use capsec_semantics::runtime_extensions::{
            RuntimeExtensionAuthorityTemplate, RUNTIME_EXTENSION_AUTHORITY_TEMPLATE_SCHEMA,
        };

        let capsule = crate::host::tests::runtime_extension_test_capsule();
        let template = RuntimeExtensionAuthorityTemplate {
            schema: RUNTIME_EXTENSION_AUTHORITY_TEMPLATE_SCHEMA.into(),
            target: capsule.target,
            profile: capsule.profile,
            sdk_version: capsule.sdk_version,
            runtime_features: capsule.runtime_features.clone(),
            extension_set_digest: capsule.extension_set_digest.clone(),
            declared_executable_selection_identity: capsule
                .declared_executable_selection_identity
                .clone(),
            descriptors: capsule.descriptors.clone(),
            linked_artifacts: capsule.linked_artifacts.clone(),
        };
        let template_bytes =
            capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(template).unwrap())
                .unwrap();
        let executable = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let executable_size = executable.metadata().unwrap().len();
        let executable_object =
            super::super::object_identity_for_open_file(&std::fs::File::open(&executable).unwrap())
                .unwrap();
        let observation = serde_json::json!({
            "schema": RUNTIME_EXTENSION_LOADED_IMAGE_OBSERVATION_SCHEMA,
            "path": executable,
            "fileSize": executable_size,
            "executableObject": executable_object,
            "anchors": capsule.mapped_executable.anchors
        });
        let finalized = finalize_runtime_extension_authority(
            &template_bytes,
            &serde_json::to_vec(&observation).unwrap(),
        )
        .unwrap();
        let finalized_capsule =
            RuntimeExtensionAuthorityCapsule::parse_json(&finalized.authority_capsule_bytes)
                .unwrap();
        assert_eq!(
            finalized_capsule.authority_capsule_digest.as_str(),
            finalized.authority_capsule_digest
        );
        assert_eq!(
            finalized_capsule.executable_selection_identity.as_str(),
            finalized.executable_selection_identity
        );
        assert_eq!(
            finalized_capsule.mapped_executable.range.length.get(),
            executable_size
        );
        assert_eq!(
            finalized_capsule.mapped_executable.anchors,
            capsule.mapped_executable.anchors
        );

        let mut stale = observation.clone();
        stale["fileSize"] = serde_json::json!(executable_size - 1);
        assert!(finalize_runtime_extension_authority(
            &template_bytes,
            &serde_json::to_vec(&stale).unwrap(),
        )
        .unwrap_err()
        .to_string()
        .contains("changed after launcher observation"));

        let mut replaced = observation;
        replaced["executableObject"]["file"] = serde_json::json!("ino:0");
        assert!(finalize_runtime_extension_authority(
            &template_bytes,
            &serde_json::to_vec(&replaced).unwrap(),
        )
        .unwrap_err()
        .to_string()
        .contains("object changed after launcher observation"));
    }

    #[cfg(unix)]
    #[test]
    fn finalization_never_reopens_a_replaced_observation_path() {
        use capsec_semantics::runtime_extensions::{
            RuntimeExtensionAuthorityTemplate, RuntimeExtensionMappedExecutableIdentity,
            RUNTIME_EXTENSION_AUTHORITY_TEMPLATE_SCHEMA,
        };
        use sha2::{Digest as _, Sha256};

        let capsule = crate::host::tests::runtime_extension_test_capsule();
        let template = RuntimeExtensionAuthorityTemplate {
            schema: RUNTIME_EXTENSION_AUTHORITY_TEMPLATE_SCHEMA.into(),
            target: capsule.target,
            profile: capsule.profile,
            sdk_version: capsule.sdk_version,
            runtime_features: capsule.runtime_features.clone(),
            extension_set_digest: capsule.extension_set_digest.clone(),
            declared_executable_selection_identity: capsule
                .declared_executable_selection_identity
                .clone(),
            descriptors: capsule.descriptors.clone(),
            linked_artifacts: capsule.linked_artifacts.clone(),
        };
        let template_bytes =
            capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(template).unwrap())
                .unwrap();

        let directory = tempfile::tempdir().unwrap();
        let observed_path = directory.path().join("observed-executable");
        let mapped_path = directory.path().join("mapped-executable");
        let original_bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        std::fs::write(&observed_path, &original_bytes).unwrap();
        let pinned = std::fs::File::open(&observed_path).unwrap();
        let metadata = pinned.metadata().unwrap();
        let executable_object = super::super::object_identity_for_open_file(&pinned).unwrap();
        let observation = serde_json::json!({
            "schema": RUNTIME_EXTENSION_LOADED_IMAGE_OBSERVATION_SCHEMA,
            "path": observed_path,
            "fileSize": metadata.len(),
            "executableObject": executable_object,
            "anchors": capsule.mapped_executable.anchors
        });

        std::fs::rename(&observed_path, &mapped_path).unwrap();
        std::fs::write(&observed_path, b"replacement executable object").unwrap();
        let replacement = super::super::object_identity_for_open_file(
            &std::fs::File::open(&observed_path).unwrap(),
        )
        .unwrap();
        assert_ne!(replacement, executable_object);

        let finalized = finalize_runtime_extension_authority_with_pinned_image(
            &template_bytes,
            &serde_json::to_vec(&observation).unwrap(),
            pinned,
        )
        .unwrap();
        let mapped: RuntimeExtensionMappedExecutableIdentity =
            serde_json::from_slice(&finalized.mapped_executable_bytes).unwrap();
        assert_eq!(mapped.executable_object, executable_object);
        assert_eq!(
            mapped.content_digest.as_str(),
            format!(
                "sha256-{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(Sha256::digest(&original_bytes))
            )
        );
    }

    #[test]
    fn target_local_exact_dev_builder_pairs_mode_with_the_explicit_dev_root() {
        let installed = tempfile::tempdir().unwrap();
        let dev = tempfile::tempdir().unwrap();
        let envelope = build_exact_dev_through_abi(installed.path(), dev.path());
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["snapshot"]["bootstrapCompatibilityModes"],
            serde_json::json!(["dev-served"])
        );
        assert_eq!(
            artifacts["snapshot"]["devServedProjectRoot"],
            artifacts["snapshot"]["rootBindings"][0]["hostPath"]
        );
        assert_eq!(
            artifacts["snapshot"]["devServedProjectRoot"],
            artifacts["snapshot"]["projectRootDiscovery"]["selectedRoot"]
        );
        assert_eq!(
            artifacts["snapshot"]["principals"][0]["floor"],
            serde_json::json!([{
                "cap": "network:listen",
                "resource": {
                    "kind": "listen-inet",
                    "transport": "tcp",
                    "bind": {"kind": "loopback"},
                    "port": {"kind": "ephemeral"},
                    "dualStack": false,
                    "peerClasses": ["loopback"],
                },
            }]),
            "dev-served Exact grants only the loopback ephemeral listener used by the agent"
        );
        assert_eq!(
            artifacts["snapshot"]["rootAuthorityCeiling"]["authorities"],
            artifacts["snapshot"]["principals"][0]["floor"],
            "the immutable root ceiling admits exactly the scoped dev listener floor"
        );
        let mut expected: ExpectedArmingIdentity =
            serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap();
        let snapshot = ArmedSnapshot::load(
            &serde_json::to_vec(&artifacts["snapshot"]).unwrap(),
            &expected,
        )
        .unwrap();
        crate::host::abi::validate_dev_served_project_root_pairing(&snapshot).unwrap();

        let mut unpaired = artifacts["snapshot"].clone();
        unpaired
            .as_object_mut()
            .unwrap()
            .remove("devServedProjectRoot");
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &unpaired).unwrap();
        unpaired["armedSnapshotDigest"] = serde_json::json!(digest.clone());
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        let unpaired =
            ArmedSnapshot::load(&serde_json::to_vec(&unpaired).unwrap(), &expected).unwrap();
        assert!(
            crate::host::abi::validate_dev_served_project_root_pairing(&unpaired)
                .unwrap_err()
                .contains("requires an explicit dev project root binding")
        );
    }

    #[test]
    fn public_exact_prepare_derives_and_protects_manifest_endowments() {
        let fixture = real_embedder_fixture();
        let envelope = prepare_exact_through_abi(&fixture);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["schema"],
            "exact/host-operation-endowments/1"
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["endowments"]["app"],
            serde_json::json!([1000])
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["endowments"]["agentIsolate"],
            serde_json::json!([2200, 2201, 2202, 2203])
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["endowments"]["uiWorklet"],
            serde_json::json!([])
        );
        assert!(artifacts["snapshot"]["protectedObjects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["role"] == "exact-operation-manifest"));
        assert!(artifacts["expectedIdentity"]["protectedArtifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["role"] == "exact-operation-manifest"));
        let digest = artifacts["snapshot"]["exactEmbedder"]["operationManifestDigest"]
            .as_str()
            .unwrap();
        assert_eq!(
            artifacts["expectedIdentity"]["protectedArtifacts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["role"] == "exact-operation-manifest")
                .unwrap()["contentDigest"],
            digest
        );
    }

    fn prepare_exact_v2_through_abi(
        fixture: &RealEmbedderFixture,
        carrier_binding: &serde_json::Value,
    ) -> serde_json::Value {
        let manifest = exact_manifest();
        let carrier = serde_json::to_vec(carrier_binding).unwrap();
        let output = unsafe {
            crate::host::abi::ex_host_prepare_exact_armed_embedder_artifacts_v2(
                fixture.snapshot.as_ptr(),
                fixture.snapshot.len(),
                fixture.expected_identity.as_ptr(),
                fixture.expected_identity.len(),
                manifest.as_ptr(),
                manifest.len(),
                carrier.as_ptr(),
                carrier.len(),
            )
        };
        assert!(!output.is_null());
        let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
            .to_bytes()
            .to_vec();
        crate::host::abi::ex_host_free_string(output);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn v2_test_carrier_binding(root_grant_sets: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "schema": "exact/carrier-binding/1",
            "mappingDigest": "sha256-MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMA",
            "authorityCommitmentDigest": "sha256-QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQA",
            "rootGrantSets": root_grant_sets,
        })
    }

    // @ref LLP 0053#r2-i2--carrier-identity-in-the-armed-snapshot — the v2
    // producer embeds the validated carrier binding as a required /2 field
    // before nonce freshening, and the freshened pair re-authenticates.
    #[test]
    fn public_exact_prepare_v2_embeds_and_authenticates_carrier_binding() {
        let fixture = real_embedder_fixture();
        let carrier = v2_test_carrier_binding(serde_json::json!({
            "home": {
                "context": "app",
                "grantSetId": "grant-set-app",
                "grantSetDigest": "sha256-ccccccccccccccccccccccccccccccccccccccccccA"
            },
            "settings": {
                "context": "agentIsolate",
                "grantSetId": "grant-set-agent",
                "grantSetDigest": "sha256-ccccccccccccccccccccccccccccccccccccccccccA"
            }
        }));
        let envelope = prepare_exact_v2_through_abi(&fixture, &carrier);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["schema"],
            "exact/host-operation-endowments/2"
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["carrierBinding"]["schema"],
            "exact/carrier-binding/1"
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["carrierBinding"]["rootGrantSets"]["home"]
                ["context"],
            "app"
        );
        // The freshened /2 snapshot re-ingests through the strict arming path.
        let reingested = ArmedSnapshot::load(
            &serde_json::to_vec(&artifacts["snapshot"]).unwrap(),
            &serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap(),
        )
        .unwrap();
        let binding = reingested.exact_embedder_binding().unwrap().unwrap();
        assert!(binding.carrier_binding().is_some());
    }

    // The per-context >=1-pin arming rule refuses at production time: every
    // endowed context must hold a pin, so a carrier binding that covers only
    // the app context cannot be embedded.
    #[test]
    fn public_exact_prepare_v2_refuses_carrier_binding_missing_context_pin() {
        let fixture = real_embedder_fixture();
        let carrier = v2_test_carrier_binding(serde_json::json!({
            "home": {
                "context": "app",
                "grantSetId": "grant-set-app",
                "grantSetDigest": "sha256-ccccccccccccccccccccccccccccccccccccccccccA"
            }
        }));
        let envelope = prepare_exact_v2_through_abi(&fixture, &carrier);
        assert_eq!(envelope["ok"], false, "{envelope}");
        assert!(
            envelope["error"]
                .as_str()
                .unwrap()
                .contains("carrier binding validation refused"),
            "{envelope}"
        );
    }

    // Strict ingestion refuses unknown carrier-binding fields at the producer.
    #[test]
    fn public_exact_prepare_v2_refuses_unknown_carrier_fields() {
        let fixture = real_embedder_fixture();
        let mut carrier = v2_test_carrier_binding(serde_json::json!({
            "home": {
                "context": "app",
                "grantSetId": "grant-set-app",
                "grantSetDigest": "sha256-ccccccccccccccccccccccccccccccccccccccccccA"
            },
            "settings": {
                "context": "agentIsolate",
                "grantSetId": "grant-set-agent",
                "grantSetDigest": "sha256-ccccccccccccccccccccccccccccccccccccccccccA"
            }
        }));
        carrier["surprise"] = serde_json::json!(true);
        let envelope = prepare_exact_v2_through_abi(&fixture, &carrier);
        assert_eq!(envelope["ok"], false, "{envelope}");
        assert!(
            envelope["error"].as_str().unwrap().contains("carrier"),
            "{envelope}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_publishes_a_new_protected_artifact_without_opening_its_directory() {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).unwrap();
        let digest = content_digest(&bytes);
        let artifact =
            materialize_protected_artifact("windows-directory-sync-regression", &bytes, &digest)
                .unwrap();
        assert_eq!(artifact.content_digest, digest);
    }

    #[test]
    fn exact_manifest_validation_refuses_noncanonical_or_ambient_endowments() {
        let mut reordered: serde_json::Value = serde_json::from_slice(&exact_manifest()).unwrap();
        reordered["endowments"]["agentIsolate"] = serde_json::json!([2201, 2200, 2202, 2203]);
        assert!(
            parse_exact_operation_manifest(&serde_json::to_vec(&reordered).unwrap())
                .unwrap_err()
                .to_string()
                .contains("strictly increasing")
        );

        let mut worklet: serde_json::Value = serde_json::from_slice(&exact_manifest()).unwrap();
        worklet["operations"]
            .as_array_mut()
            .unwrap()
            .insert(1, serde_json::json!({"id": 1001, "name": "app.measure"}));
        worklet["endowments"]["uiWorklet"] = serde_json::json!([1001]);
        assert!(
            parse_exact_operation_manifest(&serde_json::to_vec(&worklet).unwrap())
                .unwrap_err()
                .to_string()
                .contains("UI worklet endowment must remain empty")
        );
    }

    #[test]
    fn public_prepare_preserves_the_protected_exact_endowment_binding() {
        let fixture = with_exact_embedder_binding(real_embedder_fixture());
        let envelope = prepare_through_abi(&fixture);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        let returned_expected: ExpectedArmingIdentity =
            serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap();
        let returned_snapshot = serde_json::to_vec(&artifacts["snapshot"]).unwrap();
        let reingested = ArmedSnapshot::load(&returned_snapshot, &returned_expected).unwrap();
        let binding = reingested.exact_embedder_binding().unwrap().unwrap();
        assert_eq!(binding.endowments().app, [7, 11]);
        assert_eq!(binding.endowments().agent_isolate, [19]);
        assert!(returned_expected
            .protected_artifacts
            .iter()
            .any(|artifact| artifact.role == ProtectedArtifactRole::ExactOperationManifest));
        super::super::validate_snapshot_protected_artifacts(&reingested).unwrap();
    }

    #[test]
    fn public_prepare_refuses_an_authenticated_root_replacement() {
        let fixture = real_embedder_fixture();
        let original_root = fixture._temp.path().join("original-project");
        std::fs::rename(&fixture.project_root, &original_root).unwrap();
        std::fs::create_dir(&fixture.project_root).unwrap();

        let envelope = prepare_through_abi(&fixture);
        assert_eq!(envelope["ok"], false, "{envelope}");
        assert!(
            envelope["error"]
                .as_str()
                .unwrap()
                .contains("armed root object changed after arming"),
            "{envelope}"
        );
    }
}
