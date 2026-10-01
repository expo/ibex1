use std::ffi::OsString;
use std::io::{BufRead, BufReader, ErrorKind};
use std::path::Path;
use std::path::PathBuf;

use ibex_windows_dll_staging::stage_runtime_dlls;

#[path = "build_support/hermes_profile_provenance.rs"]
mod hermes_profile_provenance;
#[path = "build_support/hermes_symbol_probe.rs"]
mod hermes_symbol_probe;
#[path = "build_support/hermesc_source_label.rs"]
mod hermesc_source_label;
#[path = "build_support/portable_engine_build_consumption.rs"]
mod portable_engine_build_consumption;
#[cfg(target_os = "macos")]
#[path = "build_support/portable_engine_build_preflight.rs"]
mod portable_engine_build_preflight;
#[cfg(not(target_os = "macos"))]
#[path = "build_support/portable_engine_build_preflight_unsupported.rs"]
mod portable_engine_build_preflight;
#[cfg(target_os = "macos")]
#[path = "build_support/portable_engine_promotion_report.rs"]
mod portable_engine_promotion_report;
#[path = "build_support/portable_host_tool_runner.rs"]
mod portable_host_tool_runner;
#[path = "build_support/windows_compile_only_profile.rs"]
mod windows_compile_only_profile;

#[derive(Clone)]
struct AppleFramework {
    search_dir: PathBuf,
    framework_name: String,
    binary_path: PathBuf,
}

fn env_path(var: &str) -> PathBuf {
    match std::env::var(var) {
        Ok(value) => PathBuf::from(value),
        Err(error) => panic!("Required environment variable {var} is not set: {error}"),
    }
}

fn optional_env_path(vars: &[&str]) -> Option<PathBuf> {
    vars.iter()
        .find_map(|var| std::env::var_os(var).map(PathBuf::from))
}

fn target_arch_to_hermes_dir(arch: &str) -> String {
    match arch {
        "x86_64" => "x64".to_string(),
        "aarch64" => "arm64".to_string(),
        "x86" | "i686" => "x86".to_string(),
        _ => arch.to_string(),
    }
}

fn target_arch_to_android_abi(arch: &str) -> &'static str {
    match arch {
        "aarch64" => "arm64-v8a",
        "arm" => "armeabi-v7a",
        "x86" | "i686" => "x86",
        "x86_64" => "x86_64",
        _ => panic!("Unsupported Android target architecture: {arch}"),
    }
}

fn android_prefab_module_root(root: &Path, module: &str) -> PathBuf {
    root.join("prefab").join("modules").join(module)
}

fn android_prefab_include_dir(root: &Path, module: &str) -> PathBuf {
    android_prefab_module_root(root, module).join("include")
}

fn android_prefab_lib_dir(root: &Path, module: &str, arch: &str) -> PathBuf {
    android_prefab_module_root(root, module)
        .join("libs")
        .join(format!("android.{}", target_arch_to_android_abi(arch)))
}

fn windows_hermes_root(repo_root: &Path, arch: &str) -> PathBuf {
    repo_root
        .join("tools")
        .join("hermes")
        .join(format!("windows-{}", target_arch_to_hermes_dir(arch)))
}

fn hermesc_path(repo_root: &Path, target_os: &str, target_arch: &str) -> PathBuf {
    if let Some(path) = optional_env_path(&["HERMESC", "HERMES_COMPILER"]) {
        return path;
    }
    if let Some(bin_dir) = optional_env_path(&["HERMES_BIN_DIR"]) {
        let binary_name = if target_os == "windows" {
            "hermesc.exe"
        } else {
            "hermesc"
        };
        return bin_dir.join(binary_name);
    }
    if target_os == "windows" {
        return windows_hermes_root(repo_root, target_arch)
            .join("bin")
            .join("hermesc.exe");
    }
    let hermes_dir = repo_root.join("tools").join("hermes");
    // The standalone Ibex repo ships a platform-suffixed compiler
    // (e.g. hermesc-linux-x64); the monorepo layout uses the bare name.
    let suffixed = hermes_dir.join(format!(
        "hermesc-{}-{}",
        target_os,
        target_arch_to_hermes_dir(target_arch)
    ));
    let bare = hermes_dir.join("hermesc");
    if !bare.exists() && suffixed.exists() {
        return suffixed;
    }
    bare
}

fn hermes_cli_path(repo_root: &Path, target_os: &str, target_arch: &str) -> PathBuf {
    if let Some(path) = optional_env_path(&["HERMES_CLI", "HERMES_BINARY"]) {
        return path;
    }
    if let Some(bin_dir) = optional_env_path(&["HERMES_BIN_DIR"]) {
        let binary_name = if target_os == "windows" {
            "hermes.exe"
        } else {
            "hermes"
        };
        return bin_dir.join(binary_name);
    }
    if target_os == "windows" {
        return windows_hermes_root(repo_root, target_arch)
            .join("bin")
            .join("hermes.exe");
    }
    let hermes_dir = repo_root.join("tools").join("hermes");
    let suffixed = hermes_dir.join(format!(
        "hermes-{}-{}",
        target_os,
        target_arch_to_hermes_dir(target_arch)
    ));
    let bare = hermes_dir.join("hermes");
    if !bare.exists() && suffixed.exists() {
        return suffixed;
    }
    bare
}

fn read_bytes_or_panic(path: &Path, context: &str) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|error| panic!("Failed to read {context} at {}: {error}", path.display()))
}

fn read_text_or_panic(path: &Path, context: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("Failed to read {context} at {}: {error}", path.display()))
}

fn file_contains_all(path: &Path, needles: &[&str]) -> bool {
    std::fs::read_to_string(path)
        .map(|text| needles.iter().all(|needle| text.contains(needle)))
        .unwrap_or(false)
}

fn write_file_or_panic(path: &Path, contents: impl AsRef<[u8]>, context: &str) {
    if let Err(error) = std::fs::write(path, contents) {
        panic!("Failed to write {context} at {}: {error}", path.display());
    }
}

fn read_dir_paths_or_panic(path: &Path, context: &str) -> Vec<PathBuf> {
    let entries = std::fs::read_dir(path).unwrap_or_else(|error| {
        panic!(
            "Failed to read directory for {context} at {}: {error}",
            path.display()
        )
    });
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "Failed to read directory entry for {context} under {}: {error}",
                path.display()
            )
        });
        paths.push(entry.path());
    }
    paths.sort();
    paths
}

const HERMES_PROFILE_PROVENANCE_SCHEMA: &str = "ibex/hermes-profile-provenance-receipt/2";

fn optional_unicode_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => panic!("{name} must be valid Unicode"),
    }
}

fn windows_compile_only_profile_plan(
    target_os: &str,
    target_triple: &str,
) -> Option<windows_compile_only_profile::CompileOnlyPlan> {
    println!(
        "cargo:rerun-if-env-changed={}",
        windows_compile_only_profile::MODE_ENV
    );
    let mode_value = optional_unicode_env(windows_compile_only_profile::MODE_ENV);
    mode_value.as_ref()?;

    for variable in [
        "HOST",
        "IBEX_LEGACY_HERMES_BLOCK_SCOPING",
        "IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE",
    ]
    .into_iter()
    .chain(
        windows_compile_only_profile::FORBIDDEN_SELECTOR_ENVS
            .iter()
            .copied(),
    )
    .chain(
        windows_compile_only_profile::REQUIRED_DIRECTORY_ENVS
            .iter()
            .copied(),
    ) {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    let host_triple = optional_unicode_env("HOST");
    let legacy_block_scoping = optional_unicode_env("IBEX_LEGACY_HERMES_BLOCK_SCOPING");
    let require_provenance = optional_unicode_env("IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE");
    let present_forbidden_selectors = windows_compile_only_profile::FORBIDDEN_SELECTOR_ENVS
        .iter()
        .copied()
        .filter(|variable| std::env::var_os(variable).is_some())
        .collect::<Vec<_>>();
    let missing_required_directories = windows_compile_only_profile::REQUIRED_DIRECTORY_ENVS
        .iter()
        .copied()
        .filter(|variable| {
            optional_unicode_env(variable)
                .as_deref()
                .is_none_or(str::is_empty)
        })
        .collect::<Vec<_>>();
    windows_compile_only_profile::select(windows_compile_only_profile::SelectorRequest {
        mode_value: mode_value.as_deref(),
        target_os,
        target_triple,
        host_triple: host_triple.as_deref(),
        legacy_block_scoping: legacy_block_scoping.as_deref(),
        require_provenance: require_provenance.as_deref(),
        present_forbidden_selectors: &present_forbidden_selectors,
        missing_required_directories: &missing_required_directories,
    })
    .unwrap_or_else(|error| panic!("{error}"))
}

fn validate_windows_compile_only_artifacts(hermes_bin_dir: &Path, import_library: &Path) {
    println!("cargo:rerun-if-changed={}", hermes_bin_dir.display());
    let entries = read_dir_paths_or_panic(
        hermes_bin_dir,
        "compile-only Windows Hermes binary directory",
    );
    let mut names = entries
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    names.sort();
    println!("cargo:rerun-if-changed={}", import_library.display());
    windows_compile_only_profile::validate_artifacts(
        &names,
        import_library.is_file(),
        &import_library.display().to_string(),
    )
    .unwrap_or_else(|error| panic!("{error}"));
}

fn exact_json_object_fields(value: &serde_json::Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected
}

struct HermesProfileProvenanceInstall<'a> {
    repo_root: &'a Path,
    out_dir: &'a Path,
    receipt_path: &'a Path,
    selected_binary: &'a Path,
    selected_linked_dependency: Option<&'a Path>,
    selected_link_artifact: Option<&'a Path>,
    target_os: &'a str,
    target_arch: &'a str,
}

fn install_hermes_profile_provenance(install: HermesProfileProvenanceInstall<'_>) {
    let HermesProfileProvenanceInstall {
        repo_root,
        out_dir,
        receipt_path,
        selected_binary,
        selected_linked_dependency,
        selected_link_artifact,
        target_os,
        target_arch,
    } = install;
    let output = out_dir.join("hermes_profile_provenance.json");
    println!("cargo:rerun-if-changed=build_support/hermes_profile_provenance.rs");
    for authority in [
        "scripts/hermes-version.sh",
        "scripts/apply-hermes-patches.sh",
        "scripts/build-hermes.sh",
        "scripts/build-hermes-linux.sh",
        "scripts/build-hermes-windows.ps1",
        "scripts/install-windows-hermes.ps1",
        "patches/hermes",
    ] {
        println!("cargo:rerun-if-changed={authority}");
    }
    println!("cargo:rerun-if-env-changed=HERMES_PROFILE_PROVENANCE_RECEIPT");
    println!("cargo:rerun-if-env-changed=IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE");
    println!("cargo:rerun-if-changed={}", receipt_path.display());
    println!("cargo:rerun-if-changed={}", selected_binary.display());
    if let Some(dependency) = selected_linked_dependency {
        println!("cargo:rerun-if-changed={}", dependency.display());
    }
    if let Some(link_artifact) = selected_link_artifact {
        println!("cargo:rerun-if-changed={}", link_artifact.display());
    }

    let required = std::env::var("IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE")
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false);
    if !receipt_path.exists() {
        if required || std::env::var_os("HERMES_PROFILE_PROVENANCE_RECEIPT").is_some() {
            panic!(
                "Hermes profile provenance receipt not found at {}. Re-run the platform Hermes installer; authenticated CapSec execution refuses an unbound linked engine.",
                receipt_path.display()
            );
        }
        std::fs::write(&output, b"null\n").unwrap_or_else(|error| {
            panic!(
                "Failed to write absent Hermes provenance marker {}: {error}",
                output.display()
            )
        });
        return;
    }

    let bytes = std::fs::read(receipt_path).unwrap_or_else(|error| {
        panic!(
            "Failed to read Hermes profile provenance receipt {}: {error}",
            receipt_path.display()
        )
    });
    let receipt: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "Hermes profile provenance receipt {} is not JSON: {error}",
            receipt_path.display()
        )
    });
    let exact_receipt_fields = if target_os == "windows" {
        &[
            "artifact",
            "linkArtifact",
            "origin",
            "profileId",
            "schema",
            "targetVariant",
        ][..]
    } else {
        &["artifact", "origin", "profileId", "schema", "targetVariant"][..]
    };
    if !exact_json_object_fields(&receipt, exact_receipt_fields)
        || receipt["schema"] != HERMES_PROFILE_PROVENANCE_SCHEMA
    {
        panic!(
            "Hermes profile provenance receipt {} has malformed exact fields",
            receipt_path.display()
        );
    }
    let (profile_id, target_variant, origin_kind) = match target_os {
        "android" => ("android-maven", "android", "maven-aar"),
        "windows" => ("windows-source-patched", "windows", "source-patched-build"),
        _ => ("source-patched", "default", "source-patched-cache"),
    };
    if receipt["profileId"] != profile_id
        || receipt["targetVariant"] != target_variant
        || receipt["origin"]["kind"] != origin_kind
    {
        panic!(
            "Hermes profile provenance receipt {} does not name the compiled target's reviewed profile",
            receipt_path.display()
        );
    }
    let expected_name = selected_binary
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| {
            panic!(
                "Selected Hermes artifact has no UTF-8 filename: {}",
                selected_binary.display()
            )
        });
    hermes_profile_provenance::validate_reviewed_profile_identity(
        repo_root,
        &receipt,
        target_os,
        expected_name,
    )
    .unwrap_or_else(|error| {
        panic!(
            "Hermes profile provenance receipt {} is not independently bound to the checked-in reviewed profile: {error}",
            receipt_path.display()
        )
    });
    hermes_profile_provenance::read_validated_artifact_binding(
        &receipt["artifact"],
        selected_binary,
        target_os,
        target_arch,
        "Hermes runtime artifact binding",
    )
    .unwrap_or_else(|error| {
        panic!(
            "Hermes profile provenance receipt {} does not bind {}: {error}",
            receipt_path.display(),
            selected_binary.display()
        )
    });

    if let Some(dependency_path) = selected_linked_dependency {
        let dependency = &receipt["origin"]["linkedDependency"];
        let dependency_artifact = &dependency["artifact"];
        if !exact_json_object_fields(
            dependency,
            &[
                "artifact",
                "packageCoordinate",
                "packageDigest",
                "packageRepository",
            ],
        ) {
            panic!(
                "Hermes profile provenance receipt {} has no exact linked dependency binding",
                receipt_path.display()
            );
        }
        hermes_profile_provenance::read_validated_artifact_binding(
            dependency_artifact,
            dependency_path,
            target_os,
            target_arch,
            "Hermes linked runtime dependency binding",
        )
        .unwrap_or_else(|error| {
            panic!(
                "Hermes profile provenance receipt {} does not bind {}: {error}",
                receipt_path.display(),
                dependency_path.display()
            )
        });
    }

    if let Some(link_artifact_path) = selected_link_artifact {
        if target_os != "windows" {
            panic!("a separate Hermes link artifact is supported only on Windows");
        }
        hermes_profile_provenance::read_validated_windows_link_artifact(
            &receipt,
            link_artifact_path,
            target_arch,
        )
        .unwrap_or_else(|error| {
            panic!(
                "Hermes profile provenance receipt {} does not bind {}: {error}",
                receipt_path.display(),
                link_artifact_path.display()
            )
        });
    }

    let normalized = serde_json::to_vec(&receipt)
        .expect("validated Hermes provenance receipt must serialize as JSON");
    std::fs::write(&output, normalized).unwrap_or_else(|error| {
        panic!(
            "Failed to embed Hermes profile provenance receipt {}: {error}",
            output.display()
        )
    });

    // Classification is an authenticated artifact property, not an OS probe.
    // This point is reached only after the receipt, reviewed profile identity,
    // selected runtime image, linked dependency, and link artifact (when any)
    // have all validated. Portable selection bypasses this function entirely.
    // @ref LLP 0050#2-decision-d1--artifact-bound-capability-classification
    let finalization_capable = match target_os {
        "macos" | "linux" => receipt["profileId"] == "source-patched",
        "windows" => receipt["profileId"] == "windows-source-patched",
        _ => false,
    };
    if finalization_capable {
        println!("cargo:rustc-cfg=ibex_hermes_finalization_capable");
    }
}

fn windows_import_library_for_link(
    out_dir: &Path,
    selected_import_library: &Path,
    target_arch: &str,
) -> PathBuf {
    let embedded_receipt_path = out_dir.join("hermes_profile_provenance.json");
    let receipt_bytes = std::fs::read(&embedded_receipt_path).unwrap_or_else(|error| {
        panic!(
            "Failed to read embedded Windows Hermes provenance {}: {error}",
            embedded_receipt_path.display()
        )
    });
    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_bytes).unwrap_or_else(|error| {
            panic!(
                "Embedded Windows Hermes provenance {} is not JSON: {error}",
                embedded_receipt_path.display()
            )
        });
    if receipt.is_null() {
        return if selected_import_library.is_absolute() {
            selected_import_library.to_path_buf()
        } else {
            std::env::current_dir()
                .expect("resolve current directory for Windows Hermes import library")
                .join(selected_import_library)
        };
    }

    // Capture the bytes which matched the reviewed receipt, then link that
    // immutable, content-addressed build copy under a digest-unique filename.
    // This closes both the HERMES_LIB_NAME substitution and the
    // validate-then-link race on the mutable installer directory while also
    // giving downstream rlib consumers an unambiguous propagating link name.
    let bytes = hermes_profile_provenance::read_validated_windows_link_artifact(
        &receipt,
        selected_import_library,
        target_arch,
    )
    .unwrap_or_else(|error| {
        panic!(
            "Windows Hermes import library {} is not receipt-bound: {error}",
            selected_import_library.display()
        )
    });
    let binding_digest = receipt["linkArtifact"]["binaryDigest"]
        .as_str()
        .unwrap_or_else(|| panic!("Windows Hermes linkArtifact digest is malformed"));
    let pinned_relative =
        hermes_profile_provenance::windows_pinned_import_library_relative_path(binding_digest)
            .unwrap_or_else(|error| {
                panic!("Windows Hermes linkArtifact digest is malformed: {error}")
            });
    let pinned_name = pinned_relative
        .file_name()
        .and_then(|name| name.to_str())
        .expect("validated pinned import-library name must be Unicode")
        .to_owned();
    // @ref LLP 0005#c-compilation — retain the full digest-bound verbatim
    // filename without exceeding link.exe's legacy path ceiling.
    let pinned = out_dir.join(pinned_relative);
    let pinned_dir = pinned
        .parent()
        .expect("reviewed Windows Hermes import library must have a parent");
    std::fs::create_dir_all(&pinned_dir).unwrap_or_else(|error| {
        panic!(
            "Failed to create reviewed Windows Hermes import directory {}: {error}",
            pinned_dir.display()
        )
    });
    if !pinned.exists() {
        use std::io::Write as _;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pinned)
            .unwrap_or_else(|error| {
                panic!(
                    "Failed to create reviewed Windows Hermes import library {}: {error}",
                    pinned.display()
                )
            });
        output.write_all(&bytes).unwrap_or_else(|error| {
            panic!(
                "Failed to write reviewed Windows Hermes import library {}: {error}",
                pinned.display()
            )
        });
        output.sync_all().unwrap_or_else(|error| {
            panic!(
                "Failed to sync reviewed Windows Hermes import library {}: {error}",
                pinned.display()
            )
        });
    }
    let mut pinned_binding = receipt["linkArtifact"].clone();
    pinned_binding["fileName"] = serde_json::Value::String(pinned_name);
    hermes_profile_provenance::read_validated_artifact_binding(
        &pinned_binding,
        &pinned,
        "windows",
        target_arch,
        "pinned Windows Hermes import-library binding",
    )
    .unwrap_or_else(|error| {
        panic!(
            "Pinned Windows Hermes import library {} failed revalidation: {error}",
            pinned.display()
        )
    });
    pinned
}

/// Precompute the armed registry-record content digest. The record —
/// registryDigest plus the capability definitions, coverage edges, target
/// cells, and policy rules — is fully determined by checked-in files, but the
/// runtime used to re-parse and re-canonicalize ~17 MB of JSON on every launch
/// just to authenticate the pinned cache artifact. Computing the JCS digest
/// here (with the same capsec-semantics code the runtime uses, so bytes are
/// identical by construction) lets a warm startup authenticate the pinned
/// artifact by digest and skip that work; a cold startup still constructs and
/// byte-verifies the record in full.
/// issues/20260724-insecure-startup-performance.md
fn precompute_capsec_registry_record_digest(manifest_dir: &Path) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    let inputs = [
        "capsec/examples/armed-snapshot.canonical.json",
        "capsec/registry/capability-definitions.json",
        "capsec/registry/coverage-edges.json",
        "capsec/registry/target-cells.json",
        "capsec/registry/policy-rules.json",
    ];
    for input in inputs {
        println!(
            "cargo:rerun-if-changed={}",
            manifest_dir.join(input).display()
        );
    }
    let read_json = |relative: &str| -> serde_json::Value {
        let path = manifest_dir.join(relative);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
    };
    let template = read_json("capsec/examples/armed-snapshot.canonical.json");
    // Field set and construction must mirror build_default_armed_host's
    // registry record exactly; the runtime's cold path byte-verifies against
    // the same pinned artifact, so a divergence here fails loudly there.
    let record = serde_json::json!({
        "registryDigest": template["registryDigest"],
        "capabilityDefinitions": read_json("capsec/registry/capability-definitions.json"),
        "coverageEdges": read_json("capsec/registry/coverage-edges.json"),
        "targetCells": read_json("capsec/registry/target-cells.json"),
        "policyRules": read_json("capsec/registry/policy-rules.json"),
    });
    let bytes = capsec_semantics::canonical::to_jcs_bytes(&record)
        .expect("canonicalizing the capsec registry record");
    let digest = format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes)));
    let out_dir = env_path("OUT_DIR");
    std::fs::write(out_dir.join("capsec-registry-record.jcs"), &bytes)
        .expect("writing precomputed registry record JCS");
    std::fs::write(out_dir.join("capsec-registry-record.digest"), &digest)
        .expect("writing precomputed registry record digest");
    std::fs::write(
        out_dir.join("capsec-registry-record.len"),
        bytes.len().to_string(),
    )
    .expect("writing precomputed registry record length");
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ibex_hermes_finalization_capable)");
    println!("cargo:rerun-if-env-changed=IBEX_LEGACY_HERMES_BLOCK_SCOPING");
    let manifest_dir = env_path("CARGO_MANIFEST_DIR");
    precompute_capsec_registry_record_digest(&manifest_dir);
    // Resolve the root that holds Hermes build inputs (linux/, tools/hermes/,
    // scripts/). Two supported layouts:
    //   - standalone ibex repo: the crate is the repo root.
    //   - legacy exact monorepo path: the crate was at packages/exact-runtime,
    //     so the root is two levels up.
    // Detect standalone by the presence of the Hermes build scripts at the
    // crate root; otherwise fall back to the legacy monorepo layout.
    let repo_root: PathBuf = if manifest_dir.join("scripts/build-hermes-linux.sh").exists()
        || manifest_dir.join("scripts/download-hermes.sh").exists()
    {
        manifest_dir.clone()
    } else {
        match manifest_dir.parent().and_then(|p| p.parent()) {
            Some(root) => root.to_path_buf(),
            None => panic!(
                "Failed to resolve repo root from CARGO_MANIFEST_DIR={}",
                manifest_dir.display()
            ),
        }
    };
    let repo_root = repo_root.as_path();

    let out_dir = env_path("OUT_DIR");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_triple = std::env::var("TARGET").unwrap_or_default();
    let windows_compile_only_plan = windows_compile_only_profile_plan(&target_os, &target_triple);
    let windows_compile_only_profile = windows_compile_only_plan.is_some();
    let capsec_simulator_performance_observer_enabled =
        std::env::var_os("CARGO_FEATURE_CAPSEC_SIMULATOR_PERFORMANCE_OBSERVER").is_some();
    for variable in [
        portable_engine_build_consumption::ARTIFACT_ID_ENV,
        portable_engine_build_consumption::STORE_ROOT_ENV,
        portable_engine_build_consumption::ARCHIVE_DIGEST_ENV,
        portable_engine_build_preflight::SOURCE_REVISION_ENV,
        portable_engine_build_preflight::CURRENT_REVISION_ENV,
        portable_engine_build_preflight::PREFLIGHT_RECEIPT_ENV,
        portable_engine_build_preflight::PREFLIGHT_NONCE_ENV,
        portable_engine_build_preflight::CHECKOUT_ROOT_ENV,
        portable_engine_build_preflight::CARGO_TARGET_MAP_ENV,
        portable_engine_build_preflight::CARGO_TARGET_MAP_DIGEST_ENV,
        portable_engine_build_preflight::PROMOTION_ADMISSION_ENV,
        portable_engine_build_preflight::PROMOTION_ADMISSION_DIGEST_ENV,
        "RUSTC_WRAPPER",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    let portable_selector_requested = [
        portable_engine_build_consumption::ARTIFACT_ID_ENV,
        portable_engine_build_consumption::STORE_ROOT_ENV,
        portable_engine_build_consumption::ARCHIVE_DIGEST_ENV,
        portable_engine_build_preflight::SOURCE_REVISION_ENV,
        portable_engine_build_preflight::CURRENT_REVISION_ENV,
        portable_engine_build_preflight::PREFLIGHT_RECEIPT_ENV,
        portable_engine_build_preflight::PREFLIGHT_NONCE_ENV,
        portable_engine_build_preflight::CHECKOUT_ROOT_ENV,
        portable_engine_build_preflight::CARGO_TARGET_MAP_ENV,
        portable_engine_build_preflight::CARGO_TARGET_MAP_DIGEST_ENV,
        portable_engine_build_preflight::PROMOTION_ADMISSION_ENV,
        portable_engine_build_preflight::PROMOTION_ADMISSION_DIGEST_ENV,
    ]
    .iter()
    .any(|variable| std::env::var_os(variable).is_some());
    let portable_engine = if portable_selector_requested {
        let required_selector = |variable: &str| match std::env::var(variable) {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => panic!("{variable} must not be empty in portable Hermes mode"),
            Err(std::env::VarError::NotPresent) => {
                panic!("{variable} is required in portable Hermes mode")
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("{variable} must be valid Unicode")
            }
        };
        let store_root = match std::env::var(portable_engine_build_consumption::STORE_ROOT_ENV) {
            Ok(value) if !value.is_empty() => Some(PathBuf::from(value)),
            Ok(_) => panic!(
                "{} must not be empty in portable Hermes mode",
                portable_engine_build_consumption::STORE_ROOT_ENV
            ),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => panic!(
                "{} must be valid Unicode",
                portable_engine_build_consumption::STORE_ROOT_ENV
            ),
        };
        let present_legacy_overrides =
            portable_engine_build_consumption::LEGACY_ENGINE_OVERRIDE_ENVS
                .iter()
                .filter(|variable| std::env::var_os(variable).is_some())
                .map(|variable| (*variable).to_owned())
                .collect();
        let artifact_id = required_selector(portable_engine_build_consumption::ARTIFACT_ID_ENV);
        let archive_digest =
            required_selector(portable_engine_build_consumption::ARCHIVE_DIGEST_ENV);
        let source_revision =
            required_selector(portable_engine_build_preflight::SOURCE_REVISION_ENV);
        let current_revision =
            required_selector(portable_engine_build_preflight::CURRENT_REVISION_ENV);
        let checkout_root = PathBuf::from(required_selector(
            portable_engine_build_preflight::CHECKOUT_ROOT_ENV,
        ));
        if checkout_root != repo_root {
            panic!(
                "{} must equal the resolved checkout root {}",
                portable_engine_build_preflight::CHECKOUT_ROOT_ENV,
                repo_root.display()
            );
        }
        let build_authorization =
            portable_engine_build_preflight::validate_portable_build_preflight(
                &portable_engine_build_preflight::PortableBuildPreflightRequest {
                    repo_root: repo_root.to_path_buf(),
                    artifact_id: artifact_id.clone(),
                    archive_digest: archive_digest.clone(),
                    source_revision,
                    current_revision,
                    target_triple: target_triple.clone(),
                    receipt_path: PathBuf::from(required_selector(
                        portable_engine_build_preflight::PREFLIGHT_RECEIPT_ENV,
                    )),
                    nonce: required_selector(portable_engine_build_preflight::PREFLIGHT_NONCE_ENV),
                    selected_rustc_wrapper: PathBuf::from(required_selector("RUSTC_WRAPPER")),
                    cargo_target_map_path: PathBuf::from(required_selector(
                        portable_engine_build_preflight::CARGO_TARGET_MAP_ENV,
                    )),
                    cargo_target_map_digest: required_selector(
                        portable_engine_build_preflight::CARGO_TARGET_MAP_DIGEST_ENV,
                    ),
                    promotion_admission_path: PathBuf::from(required_selector(
                        portable_engine_build_preflight::PROMOTION_ADMISSION_ENV,
                    )),
                    promotion_admission_digest: required_selector(
                        portable_engine_build_preflight::PROMOTION_ADMISSION_DIGEST_ENV,
                    ),
                },
            )
            .unwrap_or_else(|error| panic!("Portable Hermes build preflight refused: {error}"));
        let request = portable_engine_build_consumption::PortableEngineRequest {
            repo_root: repo_root.to_path_buf(),
            cargo_out_dir: out_dir.clone(),
            store_root,
            artifact_id,
            archive_digest,
            target_os: target_os.clone(),
            target_arch: target_arch.clone(),
            target_triple: target_triple.clone(),
            ibex_features: portable_engine_build_consumption::active_cargo_features(
                &manifest_dir.join("Cargo.toml"),
            )
            .unwrap_or_else(|error| panic!("Failed to enumerate Cargo features: {error}")),
            present_legacy_overrides,
            build_authorization,
        };
        let selection = portable_engine_build_consumption::consume_portable_engine(&request)
            .unwrap_or_else(|error| panic!("Portable Hermes build selection refused: {error}"));
        selection
            .write_embedded_outputs(&out_dir)
            .unwrap_or_else(|error| {
                panic!("Failed to write portable Hermes build evidence: {error}")
            });
        #[cfg(target_os = "macos")]
        {
            let promoted_report = portable_engine_promotion_report::select_embedded_report(
                repo_root,
                &selection.promotion_admission_bytes,
            )
            .unwrap_or_else(|error| {
                panic!("Portable Hermes promoted report selection refused: {error}")
            });
            std::fs::write(
                out_dir.join("portable_engine_promotion_report.json"),
                &promoted_report.report_bytes,
            )
            .unwrap_or_else(|error| {
                panic!("Failed to write embedded portable promotion report: {error}")
            });
            std::fs::write(
                out_dir.join("portable_engine_promotion_scope.json"),
                &promoted_report.scope_bytes,
            )
            .unwrap_or_else(|error| {
                panic!("Failed to write embedded portable promotion scope: {error}")
            });
            for path in promoted_report.rerun_if_changed {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
        if !selection
            .rerun_if_changed
            .contains(&selection.profile_receipt_path)
        {
            panic!("Portable Hermes profile receipt is missing from Cargo's input watch set");
        }
        for path in &selection.rerun_if_changed {
            println!("cargo:rerun-if-changed={}", path.display());
        }
        Some(selection)
    } else {
        portable_engine_build_consumption::write_absent_embedded_outputs(&out_dir).unwrap_or_else(
            |error| panic!("Failed to write absent portable Hermes markers: {error}"),
        );
        None
    };
    if windows_compile_only_profile && portable_engine.is_some() {
        panic!("compile-only Windows Hermes profile cannot select a portable engine");
    }
    let hermes_link_static = env_truthy("HERMES_LINK_STATIC");
    let static_hermes_lib = match std::env::var("HERMES_STATIC_LIB_NAME")
        .unwrap_or_else(|_| "hermesvm_a".into())
        .as_str()
    {
        "hermesvm_a" => "hermesvm_a",
        "hermesvmlean_a" => "hermesvmlean_a",
        other => panic!(
            "unsupported HERMES_STATIC_LIB_NAME={other:?}; expected hermesvm_a or hermesvmlean_a"
        ),
    };
    let default_ios_headers = repo_root
        .join("ios")
        .join("Frameworks")
        .join("hermes-headers");
    let default_linux_headers = repo_root.join("linux").join("hermes-headers");
    let default_android_hermes_root =
        optional_env_path(&["HERMES_ANDROID_DIR", "HERMES_ANDROID_ROOT"])
            .unwrap_or_else(|| repo_root.join("android").join("hermes-android"));
    let default_android_react_root =
        optional_env_path(&["REACT_ANDROID_DIR", "REACT_ANDROID_ROOT"])
            .unwrap_or_else(|| repo_root.join("android").join("react-android"));
    let default_android_hermes_headers =
        android_prefab_include_dir(&default_android_hermes_root, "hermesvm");
    let default_android_hermes_lib =
        android_prefab_lib_dir(&default_android_hermes_root, "hermesvm", &target_arch);
    let default_android_jsi_headers =
        android_prefab_include_dir(&default_android_react_root, "jsi");
    let default_android_jsi_lib =
        android_prefab_lib_dir(&default_android_react_root, "jsi", &target_arch);
    let default_windows_root = repo_root.join("tools").join("hermes").join(format!(
        "windows-{}",
        target_arch_to_hermes_dir(&target_arch)
    ));
    let default_windows_headers = default_windows_root.join("include");
    let hermes_include_dir = portable_engine
        .as_ref()
        .map(|selection| selection.include_dir.clone())
        .unwrap_or_else(|| {
            std::env::var("HERMES_INCLUDE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| match target_os.as_str() {
                    "linux" => default_linux_headers.clone(),
                    "android" => default_android_hermes_headers.clone(),
                    "windows" => default_windows_headers.clone(),
                    _ => default_ios_headers.clone(),
                })
        });
    let jsi_include_dir = portable_engine
        .as_ref()
        .map(|selection| selection.include_dir.clone())
        .unwrap_or_else(|| {
            std::env::var("JSI_INCLUDE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    if target_os == "android" {
                        default_android_jsi_headers.clone()
                    } else {
                        hermes_include_dir.clone()
                    }
                })
        });
    // Installed Hermes SDKs co-locate `hermes/Public` below the configured
    // include root. A source checkout instead splits it into the sibling
    // `public/` tree while keeping the JSI/API headers under `API/`. Detect
    // that layout once and use it for both compilation and feature probes.
    let hermes_source_public_include_dir = hermes_include_dir.parent().and_then(|parent| {
        let candidate = parent.join("public");
        candidate
            .join("hermes")
            .join("Public")
            .join("HermesExport.h")
            .exists()
            .then_some(candidate)
    });
    let default_ios_lib = repo_root.join("ios").join("Frameworks");
    let default_macos_static_lib = default_ios_lib.join("macos-static");
    let default_linux_lib = repo_root.join("linux").join("lib");
    let default_windows_lib = default_windows_root.join("lib");
    let default_windows_bin = default_windows_root.join("bin");
    let hermes_lib_dir = portable_engine
        .as_ref()
        .map(|selection| selection.framework_search_dir.clone())
        .unwrap_or_else(|| {
            std::env::var("HERMES_LIB_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| match target_os.as_str() {
                    "linux" => default_linux_lib.clone(),
                    "android" => default_android_hermes_lib.clone(),
                    "windows" => default_windows_lib.clone(),
                    "macos" if hermes_link_static => default_macos_static_lib.clone(),
                    _ => default_ios_lib.clone(),
                })
        });
    let hermes_bin_dir = portable_engine
        .as_ref()
        .and_then(|selection| selection.hermesc_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| {
            std::env::var("HERMES_BIN_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| match target_os.as_str() {
                    "windows" => default_windows_bin.clone(),
                    _ => hermes_lib_dir.clone(),
                })
        });
    let jsi_lib_dir = std::env::var("JSI_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if target_os == "android" {
                default_android_jsi_lib.clone()
            } else {
                hermes_lib_dir.clone()
            }
        });
    let macos_hermes_framework = if let Some(selection) = portable_engine.as_ref() {
        Some(AppleFramework {
            search_dir: selection.framework_search_dir.clone(),
            framework_name: selection.framework_name.clone(),
            binary_path: selection.runtime_path.clone(),
        })
    } else if target_os == "macos" && !hermes_link_static {
        resolve_macos_hermes_framework(&hermes_lib_dir)
    } else {
        None
    };
    let hermes_framework_dir = macos_hermes_framework
        .as_ref()
        .map(|framework| framework.search_dir.clone())
        .unwrap_or_else(|| hermes_lib_dir.clone());
    let hermes_framework_name = macos_hermes_framework
        .as_ref()
        .map(|framework| framework.framework_name.clone())
        .unwrap_or_else(|| "hermesvm".to_string());

    if target_os == "linux" {
        if !hermes_include_dir.exists() {
            panic!(
                "Linux Hermes headers not found at {}. Run ./scripts/build-hermes-linux.sh or set HERMES_INCLUDE_DIR.",
                hermes_include_dir.display()
            );
        }
        if !hermes_lib_dir.exists() {
            panic!(
                "Linux Hermes library dir not found at {}. Run ./scripts/build-hermes-linux.sh or set HERMES_LIB_DIR.",
                hermes_lib_dir.display()
            );
        }
    }
    if target_os == "android" {
        if !hermes_include_dir.join("hermes").join("hermes.h").exists() {
            panic!(
                "Android Hermes headers not found at {}. Run ./scripts/install-android-hermes.sh or set HERMES_INCLUDE_DIR.",
                hermes_include_dir.display()
            );
        }
        if !hermes_lib_dir.join("libhermesvm.so").exists() {
            panic!(
                "Android Hermes library not found at {}. Run ./scripts/install-android-hermes.sh or set HERMES_LIB_DIR.",
                hermes_lib_dir.display()
            );
        }
        if !jsi_include_dir.join("jsi").join("jsi.h").exists() {
            panic!(
                "Android JSI headers not found at {}. Run ./scripts/install-android-hermes.sh or set JSI_INCLUDE_DIR.",
                jsi_include_dir.display()
            );
        }
        if !jsi_lib_dir.join("libjsi.so").exists() {
            panic!(
                "Android JSI library not found at {}. Run ./scripts/install-android-hermes.sh or set JSI_LIB_DIR.",
                jsi_lib_dir.display()
            );
        }
    }
    if target_os == "windows" {
        if !hermes_include_dir.exists() {
            panic!(
                "Windows Hermes headers not found at {}. Run ./scripts/install-windows-hermes.ps1 or set HERMES_INCLUDE_DIR.",
                hermes_include_dir.display()
            );
        }
        if !hermes_lib_dir.exists() {
            panic!(
                "Windows Hermes library dir not found at {}. Run ./scripts/install-windows-hermes.ps1 or set HERMES_LIB_DIR.",
                hermes_lib_dir.display()
            );
        }
        if !hermes_bin_dir.exists() {
            panic!(
                "Windows Hermes binary dir not found at {}. Run ./scripts/install-windows-hermes.ps1 or set HERMES_BIN_DIR.",
                hermes_bin_dir.display()
            );
        }
        if windows_compile_only_profile {
            let import_library = hermes_lib_dir.join("hermes.lib");
            validate_windows_compile_only_artifacts(&hermes_bin_dir, &import_library);
        }
    }
    if target_os == "macos"
        && hermes_link_static
        && [
            format!("lib{static_hermes_lib}.a"),
            "libjsi.a".into(),
            "libboost_context.a".into(),
        ]
        .iter()
        .any(|name| !hermes_lib_dir.join(name).is_file())
    {
        panic!(
            "static macOS Hermes bundle is incomplete under {} (expected lib{}.a, libjsi.a, and libboost_context.a). Run ./scripts/build-hermes.sh --release or set HERMES_LIB_DIR.",
            hermes_lib_dir.display(),
            static_hermes_lib
        );
    }
    if target_os == "linux"
        && hermes_link_static
        && [
            format!("lib{static_hermes_lib}.a"),
            "libjsi.a".into(),
            "libboost_context.a".into(),
        ]
        .iter()
        .any(|name| !hermes_lib_dir.join(name).is_file())
    {
        panic!(
            "static Linux Hermes bundle is incomplete under {} (expected lib{}.a, libjsi.a, and libboost_context.a). Run ./scripts/build-hermes-linux.sh or set HERMES_LIB_DIR.",
            hermes_lib_dir.display(),
            static_hermes_lib
        );
    }
    if target_os == "macos" && !hermes_link_static && macos_hermes_framework.is_none() {
        panic!(
            "macOS Hermes framework not found under {}. The release xcframework only contains iOS/Catalyst slices; build or install a macOS hermes.framework under ios/Frameworks/macosx or set HERMES_LIB_DIR to its parent directory.",
            hermes_lib_dir.display()
        );
    }

    // The platform installer asserts the reviewed source/package identity and
    // hashes the extracted runtime. Re-hash the exact image this build selects
    // for linking before embedding that receipt; runtime evidence will compare
    // it with the current bytes of the device/inode object that contains the
    // mapped Hermes factory. This does not hash already-mapped executable pages.
    // @ref LLP 0013#upstream-tracking-and-re-derivation — release coordinates
    // and source pins are not loaded-image evidence without this byte binding.
    let provenance_selection = match target_os.as_str() {
        "macos" => macos_hermes_framework.as_ref().map(|framework| {
            (
                framework.binary_path.clone(),
                framework.search_dir.join("hermes-profile-provenance.json"),
                None,
                None,
            )
        }),
        "android" => Some((
            hermes_lib_dir.join("libhermesvm.so"),
            hermes_lib_dir.join("hermes-profile-provenance.json"),
            Some(jsi_lib_dir.join("libjsi.so")),
            None,
        )),
        "windows" => Some((
            hermes_bin_dir.join("hermesvm.dll"),
            hermes_bin_dir.join("hermes-profile-provenance.json"),
            None,
            Some(hermes_lib_dir.join("hermes.lib")),
        )),
        "linux" => Some((
            hermes_lib_dir.join("libhermesvm.so"),
            hermes_lib_dir.join("hermes-profile-provenance.json"),
            None,
            None,
        )),
        _ => None,
    };
    if portable_engine.is_some() {
        // The portable consumer already wrote the exact profile receipt after
        // joining it to the selected manifest/runtime bytes. Running the
        // legacy checkout-relative validator here would introduce a second,
        // unrelated selector.
    } else if let Some(plan) = windows_compile_only_plan.as_ref() {
        // This cross-target lint profile deliberately has no runtime image or
        // executable compiler. It is admitted only for type/code generation
        // checks and cannot make a runtime provenance claim.
        if !plan.embed_null_provenance {
            panic!("compile-only Windows Hermes plan must embed null provenance");
        }
        std::fs::write(out_dir.join("hermes_profile_provenance.json"), b"null\n")
            .expect("write compile-only absent Hermes provenance marker");
    } else if let Some((
        selected_binary,
        default_receipt,
        selected_linked_dependency,
        selected_link_artifact,
    )) = provenance_selection
    {
        let receipt_path = std::env::var("HERMES_PROFILE_PROVENANCE_RECEIPT")
            .map(PathBuf::from)
            .unwrap_or(default_receipt);
        install_hermes_profile_provenance(HermesProfileProvenanceInstall {
            repo_root,
            out_dir: &out_dir,
            receipt_path: &receipt_path,
            selected_binary: &selected_binary,
            selected_linked_dependency: selected_linked_dependency.as_deref(),
            selected_link_artifact: selected_link_artifact.as_deref(),
            target_os: &target_os,
            target_arch: &target_arch,
        });
    } else {
        println!("cargo:rerun-if-env-changed=HERMES_PROFILE_PROVENANCE_RECEIPT");
        println!("cargo:rerun-if-env-changed=IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE");
        let required = std::env::var("IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE")
            .map(|value| {
                matches!(
                    value.as_str(),
                    "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
                )
            })
            .unwrap_or(false);
        if required {
            panic!("Hermes profile provenance is not implemented for target OS {target_os}");
        }
        std::fs::write(out_dir.join("hermes_profile_provenance.json"), b"null\n")
            .expect("write absent Hermes provenance marker");
    }

    let windows_import_library = if target_os == "windows" {
        println!("cargo:rerun-if-env-changed=HERMES_LIB_NAME");
        let configured_name = match std::env::var("HERMES_LIB_NAME") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("HERMES_LIB_NAME is not valid Unicode")
            }
        };
        hermes_profile_provenance::validate_windows_link_library_name(configured_name.as_deref())
            .unwrap_or_else(|error| panic!("{error}"));
        Some(windows_import_library_for_link(
            &out_dir,
            &hermes_lib_dir.join("hermes.lib"),
            &target_arch,
        ))
    } else {
        None
    };

    println!("cargo:rerun-if-changed=src/engine/hermes_runtime.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_internal.h");
    println!("cargo:rerun-if-changed=src/engine/hermes_restricted_worker.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_plan_seam.cc");
    println!("cargo:rerun-if-changed=src/engine/restricted_worker_wrapper.inc");
    println!("cargo:rerun-if-changed=src/engine/hermes_app_bound_bridge.cc");
    println!("cargo:rerun-if-changed=src/engine/macho_mapping_proof.cc");
    println!("cargo:rerun-if-changed=src/engine/macho_mapping_proof.h");
    println!("cargo:rerun-if-changed=src/engine/hermes_module_runner.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_extension.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_extension_internal.h");
    println!("cargo:rerun-if-changed=tests/native/hermes_runtime_extension_conformance.cc");
    println!("cargo:rerun-if-changed=include/ibex_runtime_extension.h");
    println!("cargo:rerun-if-changed=include/ibex/runtime_extension.hpp");
    println!("cargo:rerun-if-changed=src/engine/self_image.cc");
    // @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory —
    // native registry IDs are committed generated input to the C++ archive.
    println!("cargo:rerun-if-changed=src/engine/capsec_registry_generated.h");
    println!("cargo:rerun-if-changed=src/engine/root_global_disposition.generated.h");
    println!("cargo:rerun-if-changed=src/engine/hermes_bootstrap.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_utils.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_dns.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_crypto.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_crypto_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_fs.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_fs_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_process.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_net.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_tls.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_http.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_sqlite.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_debugger.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_ios.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_kernel_bridge.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_console.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_timers.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_osinfo.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_process_setup.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_platform_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_websocket.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_fetch.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_ipc.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_worklet.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_android.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_templates.inl");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_internal.h");
    println!("cargo:rerun-if-changed=src/engine/exact_runtime_c_abi_check.c");
    println!("cargo:rerun-if-changed=src/engine/ibex_runtime_extension_c_abi_check.c");
    println!("cargo:rerun-if-changed=include/exact_runtime.h");
    println!("cargo:rerun-if-changed=src/host/mod.rs");
    println!("cargo:rerun-if-changed=src/sync.rs");
    println!("cargo:rerun-if-changed=src/cdp/mod.rs");
    println!("cargo:rerun-if-changed=src/cdp/network.rs");
    println!("cargo:rerun-if-changed=src/engine/native_fetch_macos.mm");
    println!("cargo:rerun-if-changed=src/engine/native_websocket_macos.mm");
    println!("cargo:rerun-if-changed=src/engine/native_fetch_linux.cc");
    println!("cargo:rerun-if-changed=src/engine/native_websocket_linux.cc");
    println!("cargo:rerun-if-changed=src/engine/native_android_networking.cc");
    println!("cargo:rerun-if-changed=src/engine/native_fetch_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/native_websocket_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/bootstrap");
    println!("cargo:rerun-if-changed=src/builtins");
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_script(repo_root, "build-builtins.mjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("modules.ts").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_script(repo_root, "generate-module-manifest.ts").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_script(repo_root, "transforms.mjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ibex_runtime_js_dir(repo_root).join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_script(repo_root, "rolldown-bundle.mjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ibex_runtime_js_dir(repo_root)
            .join("package.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_dir(repo_root).join("package.json").display()
    );
    println!("cargo:rerun-if-env-changed=HERMES_ENABLE_DEBUGGER");
    println!("cargo:rerun-if-env-changed=HERMESC");
    println!("cargo:rerun-if-env-changed=HERMES_COMPILER");
    println!("cargo:rerun-if-env-changed=HERMES_CLI");
    println!("cargo:rerun-if-env-changed=HERMES_BINARY");
    println!("cargo:rerun-if-env-changed=HERMES_ANDROID_DIR");
    println!("cargo:rerun-if-env-changed=HERMES_ANDROID_ROOT");
    println!("cargo:rerun-if-env-changed=HERMES_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=HERMES_LIB_DIR");
    println!("cargo:rerun-if-env-changed=HERMES_BIN_DIR");
    println!("cargo:rerun-if-env-changed=HERMES_LINK_STATIC");
    println!("cargo:rerun-if-env-changed=HERMES_STATIC_LIB_NAME");
    // Outer embedders that cache Ibex archives publish a digest over the
    // exact selected compiler/header/link/provenance inputs. Cargo otherwise
    // cannot detect a byte change restored with identical mtimes.
    println!("cargo:rerun-if-env-changed=IBEX_HERMES_INPUTS_SHA256");
    // Outer embedders may likewise bind the complete non-Hermes source closure
    // without touching shared checkout mtimes to perturb Cargo's fingerprints.
    println!("cargo:rerun-if-env-changed=IBEX_SOURCE_INPUTS_SHA256");
    println!("cargo:rerun-if-env-changed=IBEX_SFE_LINUX_RELEASE_STUB");
    println!("cargo:rerun-if-env-changed=REACT_ANDROID_DIR");
    println!("cargo:rerun-if-env-changed=REACT_ANDROID_ROOT");
    println!("cargo:rerun-if-env-changed=JSI_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=JSI_LIB_DIR");
    println!("cargo:rerun-if-env-changed=IBEX_REGENERATE_RUNTIME");
    println!("cargo:rerun-if-env-changed=IBEX_UPDATE_VENDORED_GENERATED");
    println!("cargo:rerun-if-env-changed=IBEX_ALLOW_CURL_CLI_FALLBACK");
    println!("cargo:rustc-check-cfg=cfg(hermes_debugger)");
    let host_http_server_enabled = std::env::var_os("CARGO_FEATURE_HOST_HTTP_SERVER").is_some();
    let app_host_enabled = std::env::var_os("CARGO_FEATURE_APP_HOST").is_some();
    let openssl_crypto_enabled = std::env::var_os("CARGO_FEATURE_OPENSSL_CRYPTO").is_some();
    let sfe_static_network_enabled = std::env::var_os("CARGO_FEATURE_SFE_STATIC_NETWORK").is_some();
    let plan_seam_benchmark_abi_enabled =
        std::env::var_os("CARGO_FEATURE_PLAN_SEAM_BENCHMARK_ABI").is_some();
    let dev_composition_abi_enabled =
        std::env::var_os("CARGO_FEATURE_DEV_COMMITTED_EMBEDDER").is_some();
    // @ref LLP 0047#the-linux-ambient-network-gap-must-be-decided-not-inherited —
    // the Linux SFE is a flagship Snapback CLI target, so its existing
    // libcurl Fetch/WebSocket backend must be linked into the final image.
    let linux_release_stub = target_os == "linux" && env_truthy("IBEX_SFE_LINUX_RELEASE_STUB");
    if linux_release_stub && !hermes_link_static {
        panic!("IBEX_SFE_LINUX_RELEASE_STUB requires HERMES_LINK_STATIC=1");
    }
    if linux_release_stub && !sfe_static_network_enabled {
        panic!(
            "IBEX_SFE_LINUX_RELEASE_STUB requires the sfe-static-network feature so Fetch/WebSocket are present in the release image"
        );
    }
    let hermes_macos_binary = if target_os == "macos" {
        let binary = if hermes_link_static {
            Some(hermes_lib_dir.join(format!("lib{static_hermes_lib}.a")))
        } else {
            macos_hermes_framework
                .as_ref()
                .map(|framework| framework.binary_path.clone())
        };
        if let Some(path) = binary.as_ref() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
        binary
    } else {
        None
    };
    // @ref LLP 0039#simulator-only-performance-observer — the feature-bound
    // Simulator lane must prove that the framework Xcode will link carries
    // the reviewed attribution symbols.
    let hermes_ios_observer_binary = if capsec_simulator_performance_observer_enabled {
        if target_os != "ios" || !(target_triple.ends_with("-ios-sim") || target_arch == "x86_64") {
            panic!("capsec-simulator-performance-observer requires an iOS Simulator target");
        }
        let binary = resolve_ios_simulator_hermes_binary(&hermes_lib_dir).unwrap_or_else(|| {
            panic!(
                "iOS Simulator observer Hermes framework not found under {}; install the pinned patched hermesvm.framework before building",
                hermes_lib_dir.display()
            )
        });
        println!("cargo:rerun-if-changed={}", binary.display());
        Some(binary)
    } else {
        None
    };
    let hermes_frame_attribution_binary = if windows_compile_only_profile {
        None
    } else {
        match target_os.as_str() {
            "macos" => hermes_macos_binary.clone(),
            "ios" => hermes_ios_observer_binary.clone(),
            "linux" => {
                if hermes_link_static {
                    [
                        hermes_lib_dir.join(format!("lib{static_hermes_lib}.a")),
                        hermes_lib_dir.join("libhermesvm.a"),
                    ]
                    .into_iter()
                    .find(|path| path.is_file())
                } else {
                    hermes_lib_dir
                        .join("libhermesvm.so")
                        .is_file()
                        .then(|| hermes_lib_dir.join("libhermesvm.so"))
                }
            }
            "windows" => [
                hermes_bin_dir.join("hermesvm.dll"),
                hermes_bin_dir.join("hermes.dll"),
            ]
            .into_iter()
            .find(|path| path.is_file()),
            _ => None,
        }
    };
    if let Some(path) = hermes_frame_attribution_binary.as_ref() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let allow_fallback = matches!(
        std::env::var("EXACT_ALLOW_FALLBACK")
            .ok()
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    );

    // Ibex keeps the default build hermetic: ordinary cargo builds copy the
    // committed generated JS artifacts from vendored-generated/. Native
    // regeneration is an explicit dev path, gated by IBEX_REGENERATE_RUNTIME=1.
    let vendored_generated_dir = manifest_dir.join("vendored-generated");
    let manifest_generator = exact_devtools_script(repo_root, "generate-module-manifest.ts");
    let regenerate_runtime = env_truthy("IBEX_REGENERATE_RUNTIME");
    let update_vendored_generated = env_truthy("IBEX_UPDATE_VENDORED_GENERATED");
    let standalone = !regenerate_runtime && vendored_generated_dir.exists();
    if standalone {
        // Re-run this check when a generated *source* changes, so editing a
        // builtin does not cache a green build over stale embedded bytes, and
        // when the strict flag flips. @ref LLP 0018#5-make-the-dev-build-loud-when-vendored-generated-is-stale
        println!("cargo:rerun-if-env-changed=IBEX_FAIL_ON_STALE_VENDORED");
        emit_rerun_for_tree(&manifest_dir.join("src").join("builtins"));
        emit_rerun_for_tree(
            &manifest_dir
                .join("packages")
                .join("ibex-runtime-js")
                .join("src"),
        );
        emit_rerun_for_tree(&vendored_generated_dir);
        emit_rerun_for_tree(&manifest_dir.join("src").join("identity_generated.rs"));

        // Replaces the old always-on "using vendored generated artifacts"
        // warning: fire a loud signal ONLY when the source fingerprint differs
        // from the committed snapshot. Unlike mtimes, this stays correct across
        // checkouts and Exact's cargo re-fingerprinting touches. Fatal under
        // IBEX_FAIL_ON_STALE_VENDORED (set by scripts/run-tests.sh) so an agent's
        // verification exits nonzero rather than testing stale bytes.
        if let Some(why) = vendored_generated_stale(&manifest_dir, &vendored_generated_dir) {
            let hint = "run `IBEX_REGENERATE_RUNTIME=1 cargo …` (iterate) or \
                        `bun run regenerate:vendored` + `bun run check:drift` (commit)";
            if env_truthy("IBEX_FAIL_ON_STALE_VENDORED") {
                panic!(
                    "Ibex build: embedded generated artifacts are STALE — {why}. \
                     The build would run last-committed bytes, not your edit. {hint}."
                );
            }
            // cargo:warning directives must go to STDOUT to be surfaced.
            println!(
                "cargo:warning=Ibex build: embedded generated artifacts are STALE — {why}. \
                 This build uses the committed bytes, NOT your edit. {hint}. \
                 Set IBEX_FAIL_ON_STALE_VENDORED=1 to make this fatal."
            );
        }
    } else if !regenerate_runtime {
        // The default ibex build is hermetic: it expects the committed
        // vendored-generated/ artifacts. If they are missing, fail loudly
        // rather than silently shelling out to the bun/node generators (which
        // now live in this repo, so `manifest_generator.exists()` would be true
        // and the build would quietly become non-hermetic). @ref LLP 0005#the-hermetic-default-invariant
        panic!(
            "Ibex default build is hermetic but vendored generated artifacts are missing at {}. \
             Restore the committed artifacts, or set IBEX_REGENERATE_RUNTIME=1 to regenerate from JS sources (requires bun).",
            vendored_generated_dir.display()
        );
    } else if !manifest_generator.exists() {
        panic!(
            "IBEX_REGENERATE_RUNTIME=1 requested, but the module manifest generator was not found at {}",
            manifest_generator.display()
        );
    }

    generate_builtin_manifest(repo_root, &out_dir, standalone, &vendored_generated_dir);

    // --- Build builtin JS modules via rolldown ---
    // Compiles src/builtins/*.js through the shared Hermes transforms and
    // writes the output to $OUT_DIR/builtins/ for include_str!() in mod.rs.
    let builtins_src = manifest_dir.join("src").join("builtins");
    let builtins_out = out_dir.join("builtins");
    clear_dir_if_exists(&builtins_out, "generated builtins output");
    if standalone {
        // Copy the vendored (already-transformed) builtin modules into OUT_DIR
        // so the manifest's include_str!(OUT_DIR/builtins/*.js) calls resolve.
        let vendored_builtins = vendored_generated_dir.join("builtins");
        copy_dir_files(&vendored_builtins, &builtins_out, &["js"]);
        // Plain note (not cargo:warning): the hermetic copy happens on every
        // build, so surfacing it as a warning would train readers to ignore
        // warnings — reserve cargo:warning for the stale signal above.
        eprintln!(
            "ibex build: copied vendored builtin modules → {}",
            builtins_out.display()
        );
    } else if builtins_src.exists() {
        let build_script = exact_devtools_script(repo_root, "build-builtins.mjs");
        if build_script.exists() {
            // Prefer bun when available, otherwise use node.
            let runner = which_js_runner();
            if let Some(runner_path) = runner {
                let runner_name = runner_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("js runner");
                let missing_js_deps_hint = missing_js_build_deps_hint(repo_root);
                let status = std::process::Command::new(&runner_path)
                    .arg(&build_script)
                    .arg("--src-dir")
                    .arg(&builtins_src)
                    .arg("--out-dir")
                    .arg(&builtins_out)
                    // Bun may mark an inherited stdout open-file description
                    // nonblocking. The build script's stdout is Cargo's
                    // directive channel, so give generators an isolated sink.
                    .stdout(std::process::Stdio::null())
                    .status();
                // The primary-checkout substitute exists for worktrees whose
                // JS deps were never installed. When the local pipeline is
                // *present* but fails (e.g. an in-progress transforms.mjs
                // edit broke it), substituting the primary's script would
                // embed artifacts built by different transforms and mask the
                // failure — the local pipeline is the authority under test
                // (LLP 0019), so that case must fail loud instead.
                let local_js_deps_missing = !missing_js_deps_hint.is_empty();
                match status {
                    Ok(s) if s.success() => {
                        eprintln!(
                            "ibex build: built builtin modules → {}",
                            builtins_out.display()
                        );
                    }
                    Ok(s) => {
                        if local_js_deps_missing
                            && try_build_builtins_via_primary_checkout(
                                repo_root,
                                &builtins_src,
                                &builtins_out,
                            )
                        {
                            println!(
                                "cargo:warning=Local JS deps missing; built builtin modules via primary checkout toolchain → {}",
                                builtins_out.display()
                            );
                        } else if !allow_fallback {
                            panic!(
                                "build-builtins.mjs failed with status {s} using {runner_name} and EXACT_ALLOW_FALLBACK is not set{missing_js_deps_hint}"
                            );
                        } else {
                            println!("cargo:warning=build-builtins.mjs exited with status {}, copying source files as fallback", s);
                            copy_builtins_fallback(&builtins_src, &builtins_out);
                        }
                    }
                    Err(e) => {
                        if local_js_deps_missing
                            && try_build_builtins_via_primary_checkout(
                                repo_root,
                                &builtins_src,
                                &builtins_out,
                            )
                        {
                            println!(
                                "cargo:warning=Local JS deps missing; built builtin modules via primary checkout toolchain → {}",
                                builtins_out.display()
                            );
                        } else if !allow_fallback {
                            panic!(
                                "Failed to run build-builtins.mjs with {runner_name} ({e}); build aborted because EXACT_ALLOW_FALLBACK is not set{missing_js_deps_hint}"
                            );
                        } else {
                            println!("cargo:warning=Failed to run build-builtins.mjs: {}, copying source files as fallback", e);
                            copy_builtins_fallback(&builtins_src, &builtins_out);
                        }
                    }
                }
            } else {
                if !allow_fallback {
                    panic!("Neither bun nor node found and EXACT_ALLOW_FALLBACK is not set");
                }
                println!("cargo:warning=Neither bun nor node found, copying builtin sources as-is");
                copy_builtins_fallback(&builtins_src, &builtins_out);
            }
        } else {
            if !allow_fallback {
                panic!("build-builtins.mjs not found and EXACT_ALLOW_FALLBACK is not set");
            }
            println!("cargo:warning=build-builtins.mjs not found, copying builtin sources as-is");
            copy_builtins_fallback(&builtins_src, &builtins_out);
        }
    }

    let hermesc = portable_engine
        .as_ref()
        .map(|selection| selection.hermesc_path.clone())
        .unwrap_or_else(|| hermesc_path(repo_root, &target_os, &target_arch));
    let hermes_binary = portable_engine
        .is_none()
        .then(|| hermes_cli_path(repo_root, &target_os, &target_arch));
    let portable_hermesc_runner = portable_engine.as_ref().map(|selection| {
        portable_host_tool_runner::PortableHostToolRunner::new(
            hermesc.clone(),
            selection.host_tool_contract.clone(),
            out_dir.join("portable-hermesc-invocations"),
        )
    });
    let runtime_hbc_version = portable_engine
        .as_ref()
        .map(|selection| selection.hermes_bytecode_version)
        .or_else(|| {
            hermes_binary
                .as_ref()
                .filter(|path| path.exists())
                .and_then(|path| extract_hbc_version(path))
        });

    generate_runtime_bundle_source_header(
        repo_root,
        &out_dir,
        allow_fallback,
        standalone,
        &vendored_generated_dir,
        &hermesc,
        runtime_hbc_version,
        portable_hermesc_runner.as_ref(),
    );
    if update_vendored_generated {
        if standalone {
            panic!(
                "IBEX_UPDATE_VENDORED_GENERATED=1 requires IBEX_REGENERATE_RUNTIME=1 so vendored artifacts come from a real regeneration"
            );
        }
        refresh_vendored_generated(&out_dir, &vendored_generated_dir);
    }

    // --- Precompile bootstrap JS to Hermes bytecode (HBC) ---
    // If hermesc is available and compatible, compile each bootstrap .js file to .hbc and
    // generate a C++ header (bootstrap_bytecode.h) with static byte arrays.
    // This makes JS startup faster by loading bytecode directly from static storage.
    let bootstrap_dir = manifest_dir.join("src").join("engine").join("bootstrap");
    println!("cargo:rerun-if-changed={}", hermesc.display());
    if let Some(hermes_binary) = hermes_binary.as_ref().filter(|path| path.exists()) {
        println!("cargo:rerun-if-changed={}", hermes_binary.display());
    }

    let bootstrap_hbc_header = out_dir.join("bootstrap_bytecode.h");
    let bootstrap_source_header = out_dir.join("bootstrap_source.h");
    safe_remove_file(&bootstrap_hbc_header);
    safe_remove_file(&bootstrap_source_header);

    let hermesc_hbc_version = if let Some(runner) = portable_hermesc_runner.as_ref() {
        Some(
            extract_portable_hbc_version(runner)
                .unwrap_or_else(|error| panic!("Portable hermesc version probe refused: {error}")),
        )
    } else {
        extract_hbc_version(&hermesc)
    };
    // @ref LLP 0005#bytecode-precompilation-hermesc — ReactNative.Hermes.Windows
    // hermesc rejects modern optional bootstrap syntax; Windows uses source
    // headers as the supported startup artifact.
    let mut precompile_bootstrap_hbc = target_os != "windows";

    if target_os == "windows" {
        println!(
            "cargo:warning=Skipping bootstrap HBC precompilation on Windows; using generated source headers"
        );
    } else if !hermesc.exists() {
        precompile_bootstrap_hbc = false;
        if !allow_fallback {
            panic!(
                "hermesc not found at {} and EXACT_ALLOW_FALLBACK is not set",
                hermesc.display()
            );
        }
        println!(
            "cargo:warning=hermesc not found at {}, skipping HBC precompilation",
            hermesc.display()
        );
    } else if hermesc_hbc_version.is_none() {
        precompile_bootstrap_hbc = false;
        if !allow_fallback {
            panic!("Failed to read hermesc HBC version and EXACT_ALLOW_FALLBACK is not set");
        }
        println!(
            "cargo:warning=Cannot read hermesc HBC version; skipping bootstrap HBC precompilation"
        );
    } else if let (Some(compiler_version), Some(runtime_version)) =
        (hermesc_hbc_version, runtime_hbc_version)
    {
        if compiler_version != runtime_version {
            if portable_hermesc_runner.is_some() {
                panic!(
                    "Portable hermesc HBC version {} differs from authenticated runtime {}",
                    compiler_version, runtime_version
                );
            }
            precompile_bootstrap_hbc = false;
            if !allow_fallback {
                panic!(
                    "Hermes bytecode version mismatch: hermesc {} vs hermes {} and EXACT_ALLOW_FALLBACK is not set",
                    compiler_version, runtime_version
                );
            }
            println!(
                "cargo:warning=Skipping bootstrap HBC precompilation due version mismatch (hermesc {} vs hermes {})",
                compiler_version,
                runtime_version
            );
        }
    }

    let bootstrap_files = [
        ("import-grant-keys.generated.js", "IMPORT_GRANT_KEYS"),
        ("module-loader.js", "MODULE_LOADER"),
        ("bootstrap-globals.js", "BOOTSTRAP_GLOBALS"),
        ("console-enhance.js", "CONSOLE_ENHANCE"),
        ("stream-enhance.js", "STREAM_ENHANCE"),
        ("web-crypto.js", "WEB_CRYPTO"),
        ("web-storage.js", "WEB_STORAGE"),
        ("form-data.js", "FORM_DATA"),
        ("lazy-getters.js", "LAZY_GETTERS"),
        ("compat-polyfills.js", "COMPAT_POLYFILLS"),
        ("web-streams-polyfill.js", "WEB_STREAMS_POLYFILL"),
        ("exact-global.js", "EXACT_GLOBAL"),
        ("process-compat-fix.js", "PROCESS_COMPAT_FIX"),
        ("ipc-listener.js", "IPC_LISTENER"),
    ];

    for (js_file, _) in &bootstrap_files {
        let js_path = bootstrap_dir.join(js_file);
        println!("cargo:rerun-if-changed={}", js_path.display());
    }

    if precompile_bootstrap_hbc {
        let mut header = String::from(
            "// Auto-generated by build.rs — do not edit\n\
             #pragma once\n\n",
        );
        let mut all_ok = true;
        let Some(expected_version) = hermesc_hbc_version else {
            panic!(
                "Internal build.rs invariant failed: missing hermesc HBC version after precompile_bootstrap_hbc gate"
            );
        };

        for (js_file, array_name) in &bootstrap_files {
            let js_path = bootstrap_dir.join(js_file);
            let hbc_path = out_dir.join(js_file.replace(".js", ".hbc"));
            let optional_source_fallback = bootstrap_hbc_source_fallback_allowed(js_file);

            if !js_path.exists() {
                if !allow_fallback {
                    panic!(
                        "Bootstrap JS file not found: {} and EXACT_ALLOW_FALLBACK is not set",
                        js_path.display()
                    );
                }
                println!(
                    "cargo:warning=Bootstrap JS file not found: {}",
                    js_path.display()
                );
                all_ok = false;
                break;
            }

            let compile_succeeded = if let Some(runner) = portable_hermesc_runner.as_ref() {
                run_portable_hermesc_compile(runner, &js_path, &hbc_path)
                    .unwrap_or_else(|error| panic!("Portable bootstrap hermesc refused: {error}"));
                true
            } else {
                run_checkout_independent_hermesc_compile(&hermesc, &js_path, &hbc_path)
            };

            match compile_succeeded {
                true => {
                    let file_version = if portable_hermesc_runner.is_some() {
                        Some(
                            portable_bytecode_file_version(&hbc_path).unwrap_or_else(|error| {
                                panic!("Portable bootstrap HBC validation refused: {error}")
                            }),
                        )
                    } else {
                        bytecode_file_version(&hermesc, &hbc_path)
                    };
                    match file_version {
                        Some(actual_version) if actual_version == expected_version => {}
                        Some(actual_version) => {
                            if portable_hermesc_runner.is_some() {
                                panic!(
                                    "Portable bootstrap HBC version mismatch for {}: compiled {} expected {}",
                                    js_file, actual_version, expected_version
                                );
                            }
                            if optional_source_fallback {
                                println!(
                                    "cargo:warning=Bootstrap HBC version mismatch for optional {}: compiled {} expected {}; using source fallback for this file",
                                    js_file, actual_version, expected_version
                                );
                                push_empty_bootstrap_hbc_entry(&mut header, array_name);
                                continue;
                            }
                            if !allow_fallback {
                                panic!(
                                    "Bootstrap hbc version mismatch for {}: compiled {} expected {}",
                                    js_file, actual_version, expected_version
                                );
                            }
                            println!(
                                "cargo:warning=Bootstrap hbc version mismatch for {}: compiled {} expected {}; skipping precompiled bootstrap",
                                js_file, actual_version, expected_version
                            );
                            all_ok = false;
                            break;
                        }
                        None => {
                            if optional_source_fallback {
                                println!(
                                    "cargo:warning=Cannot read HBC version for optional {}; using source fallback for this file",
                                    js_file
                                );
                                push_empty_bootstrap_hbc_entry(&mut header, array_name);
                                continue;
                            }
                            if !allow_fallback {
                                panic!(
                                    "Failed to read hbc version for {} and EXACT_ALLOW_FALLBACK is not set",
                                    js_file
                                );
                            }
                            println!(
                                "cargo:warning=Cannot read hbc version for {}; skipping precompiled bootstrap",
                                js_file
                            );
                            all_ok = false;
                            break;
                        }
                    }

                    let bytes = read_bytes_or_panic(&hbc_path, "compiled bootstrap HBC");
                    header.push_str(&format!(
                        "alignas(8) static const uint8_t {}_HBC[] = {{\n",
                        array_name
                    ));
                    for (i, byte) in bytes.iter().enumerate() {
                        if i % 16 == 0 && i > 0 {
                            header.push('\n');
                        }
                        header.push_str(&format!("0x{:02X},", byte));
                    }
                    header.push_str(&format!(
                        "\n}};\nstatic const size_t {}_HBC_LEN = sizeof({}_HBC);\n\n",
                        array_name, array_name
                    ));
                }
                false => {
                    if optional_source_fallback {
                        println!(
                            "cargo:warning=hermesc failed for optional {}; using source fallback for this file",
                            js_file
                        );
                        push_empty_bootstrap_hbc_entry(&mut header, array_name);
                        continue;
                    }
                    if !allow_fallback {
                        panic!(
                            "hermesc failed for {} and EXACT_ALLOW_FALLBACK is not set",
                            js_file
                        );
                    }
                    println!("cargo:warning=hermesc failed for {}", js_file);
                    all_ok = false;
                    break;
                }
            }
        }

        if all_ok {
            write_file_or_panic(&bootstrap_hbc_header, &header, "bootstrap_bytecode.h");
            eprintln!("ibex build: generated bootstrap_bytecode.h with precompiled HBC");
        } else if !allow_fallback {
            panic!("HBC precompilation failed and EXACT_ALLOW_FALLBACK is not set");
        } else {
            println!("cargo:warning=HBC precompilation failed, falling back to source parsing");
        }
    }
    if !bootstrap_hbc_header.exists() {
        write_empty_bootstrap_hbc_header(&bootstrap_hbc_header, &bootstrap_files);
    }

    // --- Generate bootstrap_source.h with JS source as C++ string literals ---
    // This keeps fallback loading aligned with the same bootstrap files used for HBC.
    {
        let mut src_header = String::from(
            "// Auto-generated by build.rs — do not edit\n\
             #pragma once\n\n",
        );
        let mut all_ok = true;

        for (js_file, const_name) in &bootstrap_files {
            let js_path = bootstrap_dir.join(js_file);
            if !js_path.exists() {
                if !allow_fallback {
                    panic!(
                        "Bootstrap JS file not found for source header: {} and EXACT_ALLOW_FALLBACK is not set",
                        js_path.display()
                    );
                }
                println!(
                    "cargo:warning=Bootstrap JS file not found for source header: {}",
                    js_path.display()
                );
                all_ok = false;
                break;
            }

            let source = read_text_or_panic(&js_path, "bootstrap source");
            push_cpp_raw_string_literal(&mut src_header, &format!("{}_SRC", const_name), &source);
        }

        if all_ok {
            write_file_or_panic(&bootstrap_source_header, &src_header, "bootstrap_source.h");
            eprintln!("ibex build: generated bootstrap_source.h with JS source literals");
        } else if !allow_fallback {
            panic!("bootstrap_source.h generation failed because EXACT_ALLOW_FALLBACK is not set");
        } else {
            println!("cargo:warning=bootstrap_source.h generation failed — missing JS files");
        }
    }

    // Compile the public header as an independent C11 consumer before the C++
    // adapter. This catches accidental C++-only declarations and freezes the
    // structured-evaluation field layout at the language boundary.
    // @ref LLP 0024#6-evaluation-outcomes-and-the-abi
    let mut c_abi_consumer = cc::Build::new();
    c_abi_consumer
        .file("src/engine/exact_runtime_c_abi_check.c")
        .file("src/engine/ibex_runtime_extension_c_abi_check.c")
        .include("include")
        .std("c11")
        .warnings(true)
        .warnings_into_errors(true);
    if std::env::var_os("CARGO_FEATURE_CAPSEC_CONFORMANCE_OBSERVER").is_some() {
        // The runtime probe and its deterministic controls must be absent from
        // ordinary artifacts; the always-built declaration/layout half stays.
        c_abi_consumer.define("IBEX_CAPSEC_CONFORMANCE_OBSERVER", None);
    }
    if std::env::var_os("CARGO_FEATURE_RUNTIME_EXTENSION_CONFORMANCE").is_some() {
        c_abi_consumer.define("IBEX_RUNTIME_EXTENSION_CONFORMANCE", None);
    }
    c_abi_consumer.compile("exact_runtime_c_abi_check");

    // Compile Hermes runtime adapter sources.
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("src/engine/hermes_runtime.cc")
        .file("src/engine/hermes_module_runner.cc")
        .file("src/engine/hermes_runtime_extension.cc")
        .file("src/engine/self_image.cc")
        .file("src/engine/hermes_bootstrap.cc")
        .file("src/engine/hermes_runtime_utils.cc")
        .file("src/engine/hermes_runtime_sqlite.cc")
        .file("src/engine/hermes_runtime_console.cc")
        .file("src/engine/hermes_runtime_timers.cc")
        .file("src/engine/hermes_runtime_websocket.cc")
        .file("src/engine/hermes_runtime_fetch.cc")
        .file("src/engine/hermes_runtime_ipc.cc")
        .file("src/engine/hermes_runtime_worklet.cc")
        .file("src/engine/hermes_restricted_worker.cc")
        .file("src/engine/hermes_plan_seam.cc")
        .file("src/engine/hermes_app_bound_bridge.cc")
        .include(&hermes_include_dir)
        .include(&jsi_include_dir)
        .include("include")
        .include(&out_dir); // For bootstrap_bytecode.h

    if let Some(public_include_dir) = hermes_source_public_include_dir.as_ref() {
        build.include(public_include_dir);
    }

    build.std("c++17");

    if std::env::var_os("CARGO_FEATURE_CAPSEC_CONFORMANCE_OBSERVER").is_some() {
        build.define("IBEX_CAPSEC_CONFORMANCE_OBSERVER", None);
        build.file("src/engine/hermes_session_conformance.cc");
    }
    if std::env::var_os("CARGO_FEATURE_RUNTIME_EXTENSION_CONFORMANCE").is_some() {
        build.define("IBEX_RUNTIME_EXTENSION_CONFORMANCE", None);
        build.file("tests/native/hermes_runtime_extension_conformance.cc");
    }
    if plan_seam_benchmark_abi_enabled {
        build.define("IBEX_PLAN_SEAM_BENCHMARK_ABI", None);
    }
    if dev_composition_abi_enabled {
        build.define("IBEX_DEV_COMPOSITION_ABI", None);
    }
    if target_os == "ios" || target_os == "tvos" {
        // iOS and tvOS have no public libproc mapped-vnode query. The helper parses the
        // exact O_NOFOLLOW descriptor and compares its selected Mach-O slice
        // to the mapped r-x segments containing the Hermes factory.
        // @ref LLP 0035#platform-mapping-requirements
        build.file("src/engine/macho_mapping_proof.cc");
    }
    if capsec_simulator_performance_observer_enabled {
        build.define("IBEX_CAPSEC_SIMULATOR_PERFORMANCE_OBSERVER", None);
    }
    if std::env::var_os("CARGO_FEATURE_INSECURE").is_some() {
        build.define("IBEX_INSECURE_BUILD", None);
    }
    if std::env::var_os("CARGO_FEATURE_SFE_COMPILED_RUNTIME").is_some() {
        build.define("IBEX_SFE_COMPILED_RUNTIME", None);
    }

    if target_os == "windows" {
        let hermes_jsi_cpp = hermes_include_dir.join("jsi").join("jsi.cpp");
        let hermes_jsilib_windows_cpp = hermes_include_dir.join("jsi").join("jsilib-windows.cpp");
        let hermes_rtti_cpp = hermes_include_dir
            .join("hermes")
            .join("Public")
            .join("rtti.cpp");

        if !hermes_jsi_cpp.exists() {
            panic!(
                "Windows Hermes package is missing {}; run scripts/install-windows-hermes.ps1",
                hermes_jsi_cpp.display()
            );
        }
        if !hermes_rtti_cpp.exists() {
            panic!(
                "Windows Hermes package is missing {}; run scripts/install-windows-hermes.ps1",
                hermes_rtti_cpp.display()
            );
        }

        build.file("src/engine/hermes_runtime_fs_windows.cc");
        build.file("src/engine/hermes_runtime_crypto_windows.cc");
        build.file("src/engine/hermes_runtime_http.cc");
        // Native TLS bridge JSI shims (ENG-23526). Windows now has TCP host
        // functions in hermes_runtime_platform_windows.cc, so the same
        // sans-IO rustls engine can be driven from src/builtins/tls.js.
        build.file("src/engine/hermes_runtime_tls.cc");
        // Despite the historical filename, this file owns the platform-neutral
        // exact.dispatch/module C ABI that native hosts install.
        build.file("src/engine/hermes_runtime_ios.cc");
        // @ref LLP 0003#app-host-kernel-bridge-is-a-separate-archive-member —
        // keep optional kernel-host imports out of standalone link closure.
        build.file("src/engine/hermes_runtime_kernel_bridge.cc");
        // This file also provides the non-Android no-op definitions for the
        // Android host hooks that installGlobals()/destroy() call unconditionally.
        build.file("src/engine/hermes_runtime_android.cc");
        build.file("src/engine/hermes_runtime_platform_windows.cc");
        build.file(&hermes_jsi_cpp);
        if hermes_jsilib_windows_cpp.exists() {
            build.file(&hermes_jsilib_windows_cpp);
        }
        build.file(&hermes_rtti_cpp);
        build.define("EXACT_PLATFORM_WINDOWS", None);
        build.define("EXACT_NO_OPENSSL", None);
        build.define("_WINDOWS", None);
        build.flag("/EHsc");
        build.flag("/Zc:__cplusplus");
    } else {
        build
            .file("src/engine/hermes_runtime_crypto.cc")
            .file("src/engine/hermes_runtime_dns.cc")
            .file("src/engine/hermes_runtime_fs.cc")
            .file("src/engine/hermes_runtime_process.cc")
            .file("src/engine/hermes_runtime_net.cc")
            // Native TLS bridge JSI shims (ENG-23492).
            .file("src/engine/hermes_runtime_tls.cc")
            .file("src/engine/hermes_runtime_http.cc")
            .file("src/engine/hermes_runtime_debugger.cc")
            .file("src/engine/hermes_runtime_ios.cc")
            // @ref LLP 0003#app-host-kernel-bridge-is-a-separate-archive-member —
            // keep optional kernel-host imports out of standalone link closure.
            .file("src/engine/hermes_runtime_kernel_bridge.cc")
            .file("src/engine/hermes_runtime_android.cc")
            .file("src/engine/hermes_runtime_osinfo.cc")
            .file("src/engine/hermes_runtime_process_setup.cc")
            .flag_if_supported("-stdlib=libc++")
            .flag_if_supported("-fPIC");
    }

    // Set minimum deployment targets to match Xcode project settings.
    // This avoids "was built for newer version" linker warnings for our C++ files.
    // Note: bundled C deps (e.g. rusqlite's sqlite3) need the env var set before
    // cargo runs — see build-kernel.sh which exports MACOSX_DEPLOYMENT_TARGET.
    match target_os.as_str() {
        "macos" | "ios" | "tvos" => {
            build.flag(apple_min_version_flag(&target_os));
        }
        "android" => {
            build.flag_if_supported("-fexceptions");
            build.flag_if_supported("-frtti");
        }
        _ => {}
    }

    // Platform-specific includes and defines
    match target_os.as_str() {
        "macos" => {
            // OpenSSL include path from vendored openssl-sys crate
            if openssl_crypto_enabled {
                if let Ok(openssl_include) = std::env::var("DEP_OPENSSL_INCLUDE") {
                    build.include(&openssl_include);
                }
            } else {
                build.define("EXACT_NO_OPENSSL", None);
            }

            // Brotli include path from vendored source
            let brotli_include = manifest_dir.join("vendor").join("brotli").join("include");
            build.include(&brotli_include);
        }
        "windows" => {
            // @ref LLP 0001#current-buildrs-support-honest-status — Windows is
            // an active target; use the target libz-sys build for zlib headers
            // instead of assuming a machine-wide C zlib install.
            let zlib_include = std::env::var("DEP_Z_INCLUDE").unwrap_or_else(|_| {
                panic!("Windows zlib host functions require libz-sys DEP_Z_INCLUDE metadata")
            });
            for include in zlib_include.split(',').filter(|p| !p.is_empty()) {
                build.include(include);
            }
            let brotli_include = manifest_dir.join("vendor").join("brotli").join("include");
            build.include(&brotli_include);
        }
        "ios" | "tvos" => {
            // On iOS and tvOS, CommonCrypto is available via the SDK (no OpenSSL needed)
            // Brotli is not available on iOS by default, so we disable it
            build.define("EXACT_NO_BROTLI", None);
            build.define("EXACT_NO_OPENSSL", None);
            build.define("EXACT_PLATFORM_IOS", None);
        }
        "linux" => {
            if openssl_crypto_enabled {
                if let Ok(openssl_include) = std::env::var("DEP_OPENSSL_INCLUDE") {
                    build.include(&openssl_include);
                }
            } else {
                build.define("EXACT_NO_OPENSSL", None);
            }
            let brotli_include = manifest_dir.join("vendor").join("brotli").join("include");
            build.include(&brotli_include);
        }
        "android" => {
            // @ref LLP 0001#2-the-axes-that-matter-beyond-os — Android's first
            // supported crypto profile is vendored OpenSSL until a native
            // Android backend exists.
            if !openssl_crypto_enabled {
                panic!(
                    "Android builds require --features openssl-crypto until Ibex has an Android-native crypto backend."
                );
            }
            let openssl_include = std::env::var("DEP_OPENSSL_INCLUDE").unwrap_or_else(|_| {
                panic!("Android openssl-crypto is enabled, but DEP_OPENSSL_INCLUDE was not set")
            });
            build.include(openssl_include);
            build.define("EXACT_PLATFORM_ANDROID", None);
            let brotli_include = manifest_dir.join("vendor").join("brotli").join("include");
            build.include(&brotli_include);
        }
        _ => {}
    }

    // App-host profile uses the same reduced crypto shape as Windows for now.
    // An explicitly requested OpenSSL backend wins over the reduced app-host
    // profile. `--all-features` must remain a coherent linkable profile: the
    // OpenSSL integration tests and their C ABI hooks are enabled whenever
    // `openssl-crypto` is enabled (ENG-24266).
    if app_host_enabled && target_os != "android" && !openssl_crypto_enabled {
        build.define("EXACT_NO_OPENSSL", None);
    }

    let jsi_header = jsi_include_dir.join("jsi").join("jsi.h");
    let hermes_interfaces_header = jsi_include_dir.join("jsi").join("hermes-interfaces.h");
    println!(
        "cargo:rerun-if-changed={}",
        hermes_interfaces_header.display()
    );
    let hermes_interfaces_header = jsi_include_dir.join("jsi").join("hermes-interfaces.h");
    let hermes_header = hermes_include_dir.join("hermes").join("hermes.h");
    let installed_runtime_config_header = hermes_include_dir
        .join("hermes")
        .join("Public")
        .join("RuntimeConfig.h");
    // A Hermes source checkout keeps public VM headers beside `API/`, while
    // installed SDKs place them under the configured include root. Probe both
    // layouts so a separate JSI include root cannot enable queueMicrotask
    // without also enabling the VM queue it requires.
    let runtime_config_header = if installed_runtime_config_header.exists() {
        installed_runtime_config_header
    } else {
        hermes_source_public_include_dir
            .as_ref()
            .map(|public| public.join("hermes").join("Public").join("RuntimeConfig.h"))
            .unwrap_or(installed_runtime_config_header)
    };
    for probed_header in [
        &jsi_header,
        &hermes_interfaces_header,
        &hermes_header,
        &runtime_config_header,
    ] {
        println!("cargo:rerun-if-changed={}", probed_header.display());
    }
    // @ref LLP 0005#c-compilation — Ibex supports both Hermes 0.11 headers
    // and newer ReactNative.Hermes.Windows headers; probe the vendored SDK
    // surface instead of keying these C++ code paths on target OS.
    if file_contains_all(&jsi_header, &["MutableBuffer", "createArrayBuffer"]) {
        build.define("EXACT_HAVE_JSI_MUTABLE_BUFFER", None);
    }
    if file_contains_all(
        &hermes_interfaces_header,
        &[
            "class JSI_EXPORT IKeyedExternalArrayBuffer",
            "createKeyedExternalRangeAlias(",
            "detachKeyedExternalRange(",
        ],
    ) {
        build.define("IBEX_HAVE_KEYED_EXTERNAL_ARRAY_BUFFER", None);
    }
    if file_contains_all(&jsi_header, &["queueMicrotask("]) {
        build.define("EXACT_HAVE_JSI_QUEUE_MICROTASK", None);
    }
    if file_contains_all(&runtime_config_header, &["MicrotaskQueue"]) {
        build.define("EXACT_HAVE_HERMES_MICROTASK_CONFIG", None);
    }
    if file_contains_all(&runtime_config_header, &["ES6BlockScoping"]) {
        build.define("EXACT_HAVE_HERMES_ES6_BLOCK_SCOPING_CONFIG", None);
    } else if file_contains_all(&runtime_config_header, &["EnableBlockScoping"]) {
        // Hermes 0.11 used the older builder spelling. Keep the semantic mode
        // explicit on that SDK rather than silently falling back to its false
        // default. @ref LLP 0034#decision
        build.define("EXACT_HAVE_HERMES_ENABLE_BLOCK_SCOPING_CONFIG", None);
    } else if hermes_es6_block_scoping_enabled() {
        panic!(
            "Hermes RuntimeConfig at {} has no block-scoping setting. Set IBEX_LEGACY_HERMES_BLOCK_SCOPING=1 for the temporary legacy profile or install a supported Hermes SDK.",
            runtime_config_header.display()
        );
    }
    if file_contains_all(&hermes_header, &["static bool hermesBytecodeSanityCheck"]) {
        build.define("EXACT_HAVE_HERMES_RUNTIME_BYTECODE_SANITY_CHECK", None);
    } else if file_contains_all(
        &hermes_header,
        &[
            "class HERMES_EXPORT IHermesRootAPI",
            "virtual bool hermesBytecodeSanityCheck(",
            "makeHermesRootAPI()",
        ],
    ) {
        build.define("EXACT_HAVE_HERMES_ROOT_BYTECODE_SANITY_CHECK", None);
    }
    if file_contains_all(&hermes_interfaces_header, &["asyncTriggerTimeout("])
        || file_contains_all(&hermes_header, &["asyncTriggerTimeout("])
    {
        // The pinned source-patched profile exposes Hermes' any-thread
        // immediate break used by structured lifecycle/cancellation. Older
        // compile-only SDK headers do not; keep those builds fail-closed
        // instead of calling an API they cannot provide.
        build.define("EXACT_HAVE_HERMES_ASYNC_TRIGGER_TIMEOUT", None);
    }

    // Debugger support is derived from the exact linked desktop artifact so a
    // lean static Hermes archive cannot make the adapter compile calls to
    // symbols that are absent at final link.
    // @ref LLP 0029#7-phases-gates-and-the-author-decision-register — both
    // eligible engine variants must remain mechanically honest until the
    // measured lean-vs-full release choice is ratified.
    let enable_debugger = portable_engine.is_none()
        && target_os != "windows"
        && should_enable_hermes_debugger(&target_os, hermes_frame_attribution_binary.as_deref());

    if enable_debugger {
        build.define("HERMES_ENABLE_DEBUGGER", None);
        println!("cargo:rustc-cfg=hermes_debugger");
    }

    // @ref LLP 0013#mechanism-3 — frame-derived capability attribution is only
    // available when the linked Hermes library carries the bridge exports from
    // the carried patch stack (patches/hermes/0003). Probe the exact macOS,
    // Linux, or Windows link artifact for the exported symbol. Android/iOS and
    // an explicitly supplied legacy desktop engine retain the compatibility
    // fallback; the managed Windows artifact must be patched and fails loud.
    let enable_frame_attribution = hermes_frame_attribution_binary
        .as_deref()
        .is_some_and(|path| hermes_has_frame_attribution(&target_os, path));
    if target_os == "windows"
        && hermes_frame_attribution_binary.is_some()
        && !enable_frame_attribution
    {
        panic!(
            "Windows Hermes DLL does not expose ex_hermes_vm_current_package_id; install the pinned patched artifact with scripts/install-windows-hermes.ps1 and run Cargo from an MSVC developer shell"
        );
    }
    if enable_frame_attribution {
        build.define("EXACT_HAVE_FRAME_ATTRIBUTION", None);
        println!("cargo:rustc-cfg=exact_frame_attribution");
    }
    println!("cargo:rustc-check-cfg=cfg(exact_frame_attribution)");
    // Patch 0014 exposes a one-way latch used only after trusted bootstrap.
    // Require both its declaration and the exact linked artifact's export.
    // Mixed headers/artifacts and unsupported targets therefore compile the
    // restricted constructor as a fail-closed NULL result rather than leaving
    // an undefined symbol or an eval-capable runtime.
    let dynamic_code_latch_declared =
        file_contains_all(&hermes_header, &["ex_hermes_vm_disable_eval"]);
    let dynamic_code_latch_linkable = hermes_frame_attribution_binary
        .as_deref()
        .is_some_and(|path| hermes_has_dynamic_code_latch(&target_os, path));
    if dynamic_code_latch_declared && dynamic_code_latch_linkable {
        build.define("EXACT_HAVE_HERMES_DYNAMIC_CODE_LATCH", None);
    } else if dynamic_code_latch_declared {
        println!(
            "cargo:warning=Hermes headers declare ex_hermes_vm_disable_eval, but the linked target artifact does not export it; ex_hermes_create_no_eval will fail closed"
        );
    }
    // Patches 0003/0008 and 0011 are intentionally probed separately. An
    // engine may carry package attribution while predating the structured
    // async-provenance exports; compiling direct calls from newer headers
    // against that engine would otherwise link weakly and jump through null.
    // @ref LLP 0024#9-asynchronous-failures
    let enable_structured_async_provenance = enable_frame_attribution
        && hermes_frame_attribution_binary
            .as_deref()
            .is_some_and(|path| hermes_has_structured_async_provenance(&target_os, path));
    if capsec_simulator_performance_observer_enabled && !enable_structured_async_provenance {
        panic!(
            "iOS Simulator observer Hermes framework does not expose the complete structured async provenance bridge; install the pinned patched observer artifact"
        );
    }
    if enable_structured_async_provenance {
        build.define("EXACT_HAVE_STRUCTURED_ASYNC_PROVENANCE", None);
        println!("cargo:rustc-cfg=exact_structured_async_provenance");
    }
    println!("cargo:rustc-check-cfg=cfg(exact_structured_async_provenance)");
    // Patch 0013 extends, but does not replace, patch 0011's structured
    // failure provenance. Keep the feature probes independent so a compatible
    // older engine retains scheduler/job failure context while a non-empty
    // runtime-extension registry still refuses without the stronger carrier.
    let enable_job_constrained_principals = enable_structured_async_provenance
        && hermes_frame_attribution_binary
            .as_deref()
            .is_some_and(|path| hermes_has_job_constrained_principals(&target_os, path));
    if enable_job_constrained_principals {
        build.define("EXACT_HAVE_JOB_CONSTRAINED_PRINCIPALS", None);
        println!("cargo:rustc-cfg=exact_job_constrained_principals");
    }
    println!("cargo:rustc-check-cfg=cfg(exact_job_constrained_principals)");
    // No-op `ex_host_http_*` stubs are compiled exactly when no real
    // implementation is linked, i.e. when the `host-http-server` feature is
    // off. Non-MSVC builds mark them weak so an external strong implementation
    // can override them; MSVC gets strong stubs only in this feature-off build.
    // @ref LLP 0005#c-compilation — keep the default build linkable while the
    // real HTTP server remains feature-gated.
    if !host_http_server_enabled {
        build.define("EXACT_RUNTIME_USE_HTTP_STUBS", None);
    }

    build.compile("exact_hermes_runtime");

    // Compile native fetch and websocket (Objective-C++ using NSURLSession)
    // These work on macOS, iOS, and tvOS since they use Foundation
    if target_os == "macos" || target_os == "ios" || target_os == "tvos" {
        let mut fetch_build = cc::Build::new();
        fetch_build
            .file("src/engine/native_fetch_macos.mm")
            .flag("-fobjc-arc")
            .flag("-std=c++17")
            .flag("-stdlib=libc++");
        fetch_build.flag(apple_min_version_flag(&target_os));
        fetch_build.compile("exact_native_fetch");

        let mut ws_build = cc::Build::new();
        ws_build
            .file("src/engine/native_websocket_macos.mm")
            .flag("-fobjc-arc")
            .flag("-std=c++17")
            .flag("-stdlib=libc++");
        ws_build.flag(apple_min_version_flag(&target_os));
        ws_build.compile("exact_native_websocket");

        // Link frameworks
        if target_os == "macos" {
            if hermes_link_static {
                println!(
                    "cargo:rustc-link-search=native={}",
                    hermes_lib_dir.display()
                );
                println!("cargo:rustc-link-lib=static={static_hermes_lib}");
                println!("cargo:rustc-link-lib=static=boost_context");
                println!("cargo:rustc-link-lib=static=jsi");
            } else {
                println!(
                    "cargo:rustc-link-search=framework={}",
                    hermes_framework_dir.display()
                );
                // Portable selection has already revalidated the complete
                // framework compatibility-symlink chain and proved that its
                // linker resolution reaches the exact runtime record. Preserve
                // Cargo's framework metadata for downstream embedders.
                // @ref LLP 0035#build-consumption-and-post-link-contracts
                println!("cargo:rustc-link-lib=framework={}", hermes_framework_name);
                if portable_engine.is_none() {
                    println!(
                        "cargo:rustc-link-arg=-Wl,-rpath,{}",
                        hermes_framework_dir.display()
                    );
                }
            }
        }
        // On iOS and tvOS, Hermes is linked by Xcode (via hermes.xcframework dependency)

        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=c++");
        println!("cargo:rustc-link-lib=z");

        if target_os == "macos" {
            // Link vendored OpenSSL (compiled by openssl-sys crate)
            // We must emit link directives here to ensure correct link order,
            // since hermes_runtime.cc references OpenSSL symbols directly.
            if let Ok(lib_dir) = std::env::var("DEP_OPENSSL_LIB_DIR") {
                println!("cargo:rustc-link-search=native={}", lib_dir);
            }
            if openssl_crypto_enabled {
                println!("cargo:rustc-link-lib=static=ssl");
                println!("cargo:rustc-link-lib=static=crypto");
            }
            // Link libresolv for DNS res_query()
            println!("cargo:rustc-link-lib=resolv");

            // Compile vendored Brotli from source
            let brotli_dir = manifest_dir.join("vendor").join("brotli");
            let mut brotli_build = cc::Build::new();
            brotli_build
                .include(brotli_dir.join("include"))
                .flag("-mmacosx-version-min=14.0");

            // Add all brotli C sources
            for subdir in &["common", "dec", "enc"] {
                let dir = brotli_dir.join(subdir);
                for path in read_dir_paths_or_panic(&dir, "vendored Brotli source discovery") {
                    if path.extension().is_some_and(|e| e == "c") {
                        brotli_build.file(&path);
                    }
                }
            }
            brotli_build.compile("brotli");
        }

        if target_os == "ios" || target_os == "tvos" {
            // Link libresolv for DNS on iOS and tvOS too
            println!("cargo:rustc-link-lib=resolv");
        }
    }

    if target_os == "windows" {
        let mut fetch_build = cc::Build::new();
        fetch_build
            .cpp(true)
            .file("src/engine/native_fetch_windows.cc")
            .include(&hermes_include_dir)
            .include(&out_dir)
            .std("c++17")
            .flag("/EHsc")
            .flag("/Zc:__cplusplus");
        fetch_build.compile("exact_native_fetch");

        let mut ws_build = cc::Build::new();
        ws_build
            .cpp(true)
            .file("src/engine/native_websocket_windows.cc")
            .include(&hermes_include_dir)
            .include(&out_dir)
            .std("c++17")
            .flag("/EHsc")
            .flag("/Zc:__cplusplus");
        ws_build.compile("exact_native_websocket");

        // @ref LLP 0005#c-compilation — linkable Windows test/run binaries need
        // the Hermes runtime DLLs beside the executable; link-search paths
        // alone do not make Cargo-launched tests find the runtime bin
        // directory. The explicit metadata-only profile below is deliberately
        // non-linkable and therefore stages no runtime image.
        if let Some(plan) = windows_compile_only_plan.as_ref() {
            // Cargo check/clippy consumes native-library metadata without
            // invoking the target linker. Propagate an intentionally absent
            // native dependency so any attempt to turn this header/import-lib
            // fixture into a final executable fails at link time.
            if plan.stage_runtime_dlls || plan.add_runtime_bin_search || !plan.poison_codegen_link {
                panic!("compile-only Windows Hermes plan reopened a runtime/link path");
            }
            println!(
                "cargo:rustc-link-lib=static={}",
                windows_compile_only_profile::POISON_LIBRARY
            );
            eprintln!("ibex build: admitted non-linkable compile-only Windows Hermes profile");
        } else {
            stage_windows_runtime_dlls(&out_dir, &hermes_bin_dir);
            // @ref LLP 0005#c-compilation — Cargo adds native link-search
            // paths to the DLL search path for `cargo test`, so include the
            // Hermes runtime DLL directory as well as the import-library
            // directory.
            println!(
                "cargo:rustc-link-search=native={}",
                hermes_bin_dir.display()
            );
        }

        println!(
            "cargo:rustc-link-search=native={}",
            hermes_lib_dir.display()
        );
        // Link the exact selected import library. Runtime profiles use the
        // digest-unique copy captured after receipt validation; the narrow
        // compile-only path uses its profile-digest-checked fixture path and
        // remains poisoned against codegen/link above.
        let import_library = windows_import_library
            .as_ref()
            .expect("Windows Hermes import library must be selected");
        let (link_search, link_library) =
            hermes_profile_provenance::windows_import_library_link_directives(import_library)
                .unwrap_or_else(|error| panic!("{error}"));
        println!("cargo:rustc-link-search={link_search}");
        println!("cargo:rustc-link-lib={link_library}");
        // Keep the absolute argument for this package's own bins/tests. The
        // native-library directive above is the propagating rlib dependency.
        println!("cargo:rustc-link-arg={}", import_library.display());
        println!("cargo:rustc-link-lib=winhttp");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ncrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=iphlpapi");
    }

    if target_os == "android" {
        // @ref LLP 0008#android-backend-matrix — Android Fetch/WebSocket use
        // OkHttp through JNI, not vendored libcurl.
        let mut networking_build = cc::Build::new();
        networking_build
            .cpp(true)
            .file("src/engine/native_android_networking.cc")
            .std("c++17")
            .flag_if_supported("-fPIC")
            .flag_if_supported("-fexceptions")
            .flag_if_supported("-frtti");
        networking_build.compile("exact_native_android_networking");

        println!(
            "cargo:rustc-link-search=native={}",
            hermes_lib_dir.display()
        );
        println!("cargo:rustc-link-lib=dylib=hermesvm");
        println!("cargo:rustc-link-search=native={}", jsi_lib_dir.display());
        println!("cargo:rustc-link-lib=dylib=jsi");
        if let Ok(lib_dir) = std::env::var("DEP_OPENSSL_LIB_DIR") {
            println!("cargo:rustc-link-search=native={}", lib_dir);
        }
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=c++_shared");
        println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=log");
        println!("cargo:rustc-link-lib=android");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=m");

        let brotli_dir = manifest_dir.join("vendor").join("brotli");
        let mut brotli_build = cc::Build::new();
        brotli_build
            .include(brotli_dir.join("include"))
            .flag_if_supported("-fPIC");
        for subdir in &["common", "dec", "enc"] {
            let dir = brotli_dir.join(subdir);
            for path in read_dir_paths_or_panic(&dir, "vendored Brotli source discovery") {
                if path.extension().is_some_and(|e| e == "c") {
                    brotli_build.file(&path);
                }
            }
        }
        brotli_build.compile("brotli");
    }

    if target_os == "linux" {
        const MIN_LIBCURL_VERSION: &str = "7.86.0";
        // @ref LLP 0008#linux-networking — libcurl is the supported Linux
        // Fetch/WebSocket backend. SFE builds use Cargo's pinned static curl
        // closure; ordinary source-runtime builds retain the distro backend.
        let static_curl_include = if sfe_static_network_enabled {
            Some(std::env::var_os("DEP_CURL_INCLUDE").unwrap_or_else(|| {
                panic!("sfe-static-network requires curl-sys to publish DEP_CURL_INCLUDE")
            }))
        } else {
            None
        };
        let allow_curl_cli_fallback = !sfe_static_network_enabled
            && std::env::var("IBEX_ALLOW_CURL_CLI_FALLBACK")
                .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false);
        let detected_libcurl_version = if sfe_static_network_enabled {
            None
        } else {
            std::process::Command::new("pkg-config")
                .args(["--modversion", "libcurl"])
                .output()
                .ok()
                .and_then(|out| {
                    if out.status.success() {
                        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
                    } else {
                        None
                    }
                })
        };
        let has_minimum_system_libcurl = !sfe_static_network_enabled
            && std::process::Command::new("pkg-config")
                .args(["--atleast-version", MIN_LIBCURL_VERSION, "libcurl"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

        let mut fetch_build = cc::Build::new();
        fetch_build
            .cpp(true)
            .file("src/engine/native_fetch_linux.cc")
            .flag_if_supported("-std=c++17")
            .flag_if_supported("-fPIC");
        if let Some(include) = static_curl_include.as_ref() {
            fetch_build
                .include(include)
                .define("CURL_STATICLIB", Some("1"))
                .define("IBEX_STATIC_CURL", Some("1"))
                .define("EXACT_HAS_CURL", Some("1"));
        } else if has_minimum_system_libcurl {
            fetch_build.define("EXACT_HAS_CURL", Some("1"));
        } else if allow_curl_cli_fallback {
            fetch_build.define("EXACT_ALLOW_CURL_CLI_FALLBACK", Some("1"));
            match detected_libcurl_version.as_deref() {
                Some(version) => println!(
                    "cargo:warning=libcurl {version} detected, but >= {MIN_LIBCURL_VERSION} is required for native Linux networking; using degraded curl CLI fetch fallback and disabling native websocket support because IBEX_ALLOW_CURL_CLI_FALLBACK=1"
                ),
                None => println!(
                    "cargo:warning=libcurl dev package not detected; using degraded curl CLI fetch fallback and disabling native websocket support because IBEX_ALLOW_CURL_CLI_FALLBACK=1"
                ),
            }
        } else {
            match detected_libcurl_version.as_deref() {
                Some(version) => panic!(
                    "Linux native networking requires libcurl >= {MIN_LIBCURL_VERSION}; detected {version}. Install a newer libcurl development package or set IBEX_ALLOW_CURL_CLI_FALLBACK=1 for a degraded fetch-only fallback."
                ),
                None => panic!(
                    "Linux native networking requires pkg-config and libcurl >= {MIN_LIBCURL_VERSION}. Install the libcurl development package (for example libcurl4-openssl-dev on Debian/Ubuntu) or set IBEX_ALLOW_CURL_CLI_FALLBACK=1 for a degraded fetch-only fallback."
                ),
            }
        }
        fetch_build.compile("exact_native_fetch");

        let mut ws_build = cc::Build::new();
        ws_build
            .cpp(true)
            .file("src/engine/native_websocket_linux.cc")
            .flag_if_supported("-std=c++17")
            .flag_if_supported("-fPIC");
        if let Some(include) = static_curl_include.as_ref() {
            ws_build
                .include(include)
                .define("CURL_STATICLIB", Some("1"))
                .define("IBEX_STATIC_CURL", Some("1"))
                .define("EXACT_HAS_CURL", Some("1"));
        } else if has_minimum_system_libcurl {
            ws_build.define("EXACT_HAS_CURL", Some("1"));
        }
        ws_build.compile("exact_native_websocket");

        println!(
            "cargo:rustc-link-search=native={}",
            hermes_lib_dir.display()
        );
        if hermes_link_static {
            println!("cargo:rustc-link-lib=static={static_hermes_lib}");
            // libhermesvm_a deliberately remains a CMake archive bundle, not
            // a flattened opaque .a. Keep its private Boost.Context member in
            // the authenticated Hermes artifact and close ICU statically so
            // the SFE has no versioned ICU DT_NEEDED entries.
            println!("cargo:rustc-link-lib=static=jsi");
            println!("cargo:rustc-link-lib=static=boost_context");
            let icu_lib_dir = std::process::Command::new("pkg-config")
                .args(["--variable=libdir", "icu-i18n"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
                .filter(|path| !path.is_empty())
                .unwrap_or_else(|| {
                    panic!(
                        "static Linux Hermes requires pkg-config metadata and static archives for icu-i18n"
                    )
                });
            println!("cargo:rustc-link-search=native={icu_lib_dir}");
            println!("cargo:rustc-link-lib=static=icui18n");
            println!("cargo:rustc-link-lib=static=icuuc");
            println!("cargo:rustc-link-lib=static=icudata");
        } else {
            println!("cargo:rustc-link-lib=dylib=hermesvm");
            println!(
                "cargo:rustc-link-arg=-Wl,-rpath,{}",
                hermes_lib_dir.display()
            );
        }

        if openssl_crypto_enabled {
            if let Ok(lib_dir) = std::env::var("DEP_OPENSSL_LIB_DIR") {
                println!("cargo:rustc-link-search=native={}", lib_dir);
            }
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=crypto");
        }
        println!("cargo:rustc-link-lib=stdc++");
        if static_curl_include.is_some() {
            // curl-sys is present to build and pin the native archive, but all
            // of Ibex's curl references originate in C++. Name the archive
            // explicitly after those cc-produced objects so rust-lld retains
            // it; curl-sys's Cargo metadata supplies its vendored OpenSSL
            // closure after this archive.
            let curl_root = std::env::var_os("DEP_CURL_ROOT")
                .unwrap_or_else(|| panic!("sfe-static-network requires DEP_CURL_ROOT"));
            println!(
                "cargo:rustc-link-search=native={}",
                std::path::Path::new(&curl_root).join("build").display()
            );
            println!("cargo:rustc-link-lib=static=curl");
        } else if has_minimum_system_libcurl {
            println!("cargo:rustc-link-lib=curl");
        }
        println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=resolv");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");

        let brotli_dir = manifest_dir.join("vendor").join("brotli");
        let mut brotli_build = cc::Build::new();
        brotli_build
            .include(brotli_dir.join("include"))
            .flag_if_supported("-fPIC");
        for subdir in &["common", "dec", "enc"] {
            let dir = brotli_dir.join(subdir);
            for path in read_dir_paths_or_panic(&dir, "vendored Brotli source discovery") {
                if path.extension().is_some_and(|e| e == "c") {
                    brotli_build.file(&path);
                }
            }
        }
        brotli_build.compile("brotli");
    }
}

fn which_js_runner() -> Option<PathBuf> {
    let names: &[&str] = if cfg!(target_os = "windows") {
        &["node", "bun"]
    } else {
        &["bun", "node"]
    };
    for name in names {
        for candidate in js_runner_candidates(name) {
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn bun_runner() -> Option<PathBuf> {
    js_runner_candidates("bun")
        .into_iter()
        .find(|candidate| candidate.exists())
}

fn env_truthy(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Emit `cargo:rerun-if-changed` for every file under `path` (recursing, skipping
/// node_modules). A directory-level rerun-if-changed does NOT reliably fire when
/// a file *inside* it is edited, so the staleness check below would miss the very
/// case it exists for — enumerate the files so any edit re-runs build.rs.
/// @ref LLP 0018#5-make-the-dev-build-loud-when-vendored-generated-is-stale
fn emit_rerun_for_tree(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => {
            if let Ok(entries) = std::fs::read_dir(path) {
                let mut entries = entries.flatten().collect::<Vec<_>>();
                // Cargo retains directive order in the build fingerprint.
                // Filesystem enumeration order must therefore never choose
                // Rust metadata or final native bytes.
                // @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
                entries.sort_by_key(|entry| entry.file_name());
                for entry in entries {
                    if entry.file_name() == "node_modules" {
                        continue;
                    }
                    emit_rerun_for_tree(&entry.path());
                }
            }
        }
        Ok(_) => println!("cargo:rerun-if-changed={}", path.display()),
        Err(_) => {}
    }
}

fn collect_fingerprint_files(path: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_name() == "node_modules" {
                continue;
            }
            collect_fingerprint_files(&entry.path(), files)?;
        }
    } else if metadata.file_type().is_file() {
        files.push(path.to_path_buf());
    }
    Ok(())
}

fn update_fnv1a(hash: &mut u64, bytes: &[u8]) {
    const FNV_PRIME: u64 = 1_099_511_628_211;
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

/// Hash the exact source trees covered by the original LLP 0018 stale gate.
/// Paths are checkout-relative and slash-normalized so the committed value is
/// portable across platforms. FNV-1a is used as a compact drift checksum, not
/// as a security boundary.
fn vendored_source_fingerprint(manifest_dir: &Path) -> std::io::Result<String> {
    let roots = [
        manifest_dir.join("src").join("builtins"),
        manifest_dir
            .join("packages")
            .join("ibex-runtime-js")
            .join("src"),
        manifest_dir.join("modules.ts"),
    ];
    let mut files = Vec::new();
    for root in roots {
        collect_fingerprint_files(&root, &mut files)?;
    }
    files.sort_by_key(|path| {
        path.strip_prefix(manifest_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    });

    let mut hash = 14_695_981_039_346_656_037_u64;
    for file in files {
        let relative = file
            .strip_prefix(manifest_dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        update_fnv1a(&mut hash, relative.as_bytes());
        update_fnv1a(&mut hash, &[0]);
        update_fnv1a(&mut hash, &std::fs::read(file)?);
        update_fnv1a(&mut hash, &[0xff]);
    }
    Ok(format!("{hash:016x}"))
}

/// If the generated-source fingerprint differs from the one committed with the
/// vendored snapshot, return a human description of the staleness; otherwise
/// None. This is content-based and cheap — no bun/node, no network, and no mtime
/// false positives after checkout or build-system `touch` operations.
/// @ref LLP 0018#5-make-the-dev-build-loud-when-vendored-generated-is-stale
fn vendored_generated_stale(manifest_dir: &Path, vendored_generated_dir: &Path) -> Option<String> {
    let fingerprint_path = vendored_generated_dir.join("source-fingerprint.generated.txt");
    let committed_contents = match std::fs::read_to_string(&fingerprint_path) {
        Ok(contents) => contents,
        Err(error) => {
            return Some(format!(
                "the committed source fingerprint at {} cannot be read: {error}",
                fingerprint_path.display()
            ))
        }
    };
    let committed = match committed_contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
    {
        Some(fingerprint) => fingerprint,
        None => {
            return Some(format!(
                "the committed source fingerprint at {} is malformed",
                fingerprint_path.display()
            ))
        }
    };
    let current = match vendored_source_fingerprint(manifest_dir) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            return Some(format!(
                "generated sources cannot be fingerprinted: {error}"
            ))
        }
    };
    (current != committed).then(|| {
        format!(
            "generated source content differs from the fingerprint committed at {}",
            fingerprint_path.display()
        )
    })
}

fn generate_builtin_manifest(
    repo_root: &Path,
    out_dir: &Path,
    standalone: bool,
    vendored_generated_dir: &Path,
) {
    let script = exact_devtools_script(repo_root, "generate-module-manifest.ts");
    if standalone {
        // Copy the vendored, pre-generated manifest into OUT_DIR so the
        // include!(OUT_DIR/builtin_manifest.generated.rs) in module_loader works.
        let vendored_manifest = vendored_generated_dir.join("builtin_manifest.generated.rs");
        let dest = out_dir.join("builtin_manifest.generated.rs");
        let contents = read_text_or_panic(&vendored_manifest, "vendored builtin manifest");
        write_file_or_panic(&dest, &contents, "builtin_manifest.generated.rs");
        eprintln!(
            "ibex build: copied vendored builtin manifest → {}",
            dest.display()
        );
        return;
    }
    if !script.exists() {
        panic!(
            "Module manifest generator not found at {}",
            script.display()
        );
    }

    let Some(bun) = bun_runner() else {
        panic!(
            "bun is required to generate builtin module manifests from {}",
            script.display()
        );
    };

    let output = std::process::Command::new(&bun)
        .current_dir(repo_root)
        .arg(&script)
        .arg("--rust-out-dir")
        .arg(out_dir)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "Failed to run {} with {}: {error}",
                script.display(),
                bun.display()
            )
        });

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "Module manifest generator failed with status {}.\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        );
    }
}

fn js_runner_candidates(name: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for env_var in js_runner_env_vars(name) {
        if let Ok(value) = std::env::var(env_var) {
            if !value.trim().is_empty() {
                push_js_runner_candidate(&mut candidates, PathBuf::from(value));
            }
        }
    }

    let path_var = std::env::var("PATH").unwrap_or_default();
    let path_entries: Vec<&str> = if cfg!(target_os = "windows") {
        path_var.split(';').collect()
    } else {
        path_var.split(':').collect()
    };
    for dir in path_entries {
        if dir.is_empty() {
            continue;
        }
        push_js_runner_candidate(&mut candidates, PathBuf::from(dir).join(name));
    }

    candidates.extend(common_js_runner_locations(name));
    dedupe_paths(candidates)
}

fn push_js_runner_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    candidates.push(path.clone());

    if cfg!(target_os = "windows") && path.extension().is_none() {
        for extension in ["exe", "cmd", "bat"] {
            candidates.push(path.with_extension(extension));
        }
    }
}

fn js_runner_env_vars(name: &str) -> &'static [&'static str] {
    match name {
        "bun" => &["EXACT_BUN", "BUN"],
        "node" => &["EXACT_NODE", "NODE"],
        _ => &[],
    }
}

fn common_js_runner_locations(name: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        push_js_runner_candidate(&mut candidates, home.join(".bun").join("bin").join(name));
        push_js_runner_candidate(&mut candidates, home.join(".volta").join("bin").join(name));
        push_js_runner_candidate(&mut candidates, home.join(".asdf").join("shims").join(name));

        if let Ok(nvm_bin) = std::env::var("NVM_BIN") {
            if !nvm_bin.trim().is_empty() {
                push_js_runner_candidate(&mut candidates, PathBuf::from(nvm_bin).join(name));
            }
        }

        if let Ok(asdf_dir) = std::env::var("ASDF_DIR") {
            if !asdf_dir.trim().is_empty() {
                push_js_runner_candidate(
                    &mut candidates,
                    PathBuf::from(asdf_dir).join("shims").join(name),
                );
            }
        }
    }

    push_js_runner_candidate(
        &mut candidates,
        PathBuf::from("/opt/homebrew/bin").join(name),
    );
    push_js_runner_candidate(&mut candidates, PathBuf::from("/usr/local/bin").join(name));

    candidates
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut unique = Vec::new();
    for path in paths {
        let key = path.as_os_str().to_os_string();
        if seen.insert(key) {
            unique.push(path);
        }
    }
    unique
}

fn exact_devtools_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("packages").join("ibex-devtools")
}

fn exact_devtools_script(repo_root: &Path, script_name: &str) -> PathBuf {
    exact_devtools_dir(repo_root)
        .join("src")
        .join("scripts")
        .join(script_name)
}

fn ibex_runtime_js_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("packages").join("ibex-runtime-js")
}

fn generate_runtime_bundle_source_header(
    repo_root: &Path,
    out_dir: &Path,
    allow_fallback: bool,
    standalone: bool,
    vendored_generated_dir: &Path,
    hermesc: &Path,
    runtime_hbc_version: Option<u32>,
    portable_hermesc_runner: Option<&portable_host_tool_runner::PortableHostToolRunner>,
) {
    let devtools_dir = exact_devtools_dir(repo_root);
    // @ref LLP 0005#3-the-runtime-bundles — standalone Ibex embeds only its
    // core runtime graph. Realm extensions own and authenticate their own
    // optional bootstrap payloads through the runtime-extension registry.
    let runtime_entry_name = "runtime-entry.ts";
    let runtime_entry = ibex_runtime_js_dir(repo_root)
        .join("src")
        .join(runtime_entry_name);
    let build_script = exact_devtools_script(repo_root, "rolldown-bundle.mjs");
    let bundled_runtime = out_dir.join("embedded_runtime_bundle.js");
    let header_path = out_dir.join("runtime_bundle_source.h");
    let bytecode_header_path = out_dir.join("runtime_bundle_bytecode.h");
    safe_remove_file(&header_path);
    safe_remove_file(&bytecode_header_path);
    safe_remove_file(&out_dir.join("embedded_runtime.rs"));
    write_empty_embedded_runtime_rs(out_dir);

    // Standalone: the monorepo runtime entry/bundler are absent. Use the
    // vendored pre-bundled runtime, emit the source header from it, and compile
    // bytecode via the present hermesc (same as the monorepo path's tail).
    if standalone {
        let vendored_bundle_name = "embedded_runtime_bundle.js";
        let vendored_bundle = vendored_generated_dir.join(vendored_bundle_name);
        let source = read_text_or_panic(&vendored_bundle, vendored_bundle_name);
        if !source.contains("ExactBundle") || !source.contains("__exactRuntimeLoaded") {
            panic!(
                "Vendored runtime bundle at {} does not look like an Ibex runtime bundle",
                vendored_bundle.display()
            );
        }
        write_file_or_panic(&bundled_runtime, &source, "embedded_runtime_bundle.js");
        write_embedded_runtime_rs(
            out_dir,
            &format!("vendored-generated/{vendored_bundle_name}"),
        );
        let mut header = format!(
            "// Generated by build.rs from vendored-generated/{vendored_bundle_name}\n\
             // Do not edit by hand.\n"
        );
        push_cpp_raw_string_literal(&mut header, "SHARED_RUNTIME_BUNDLE_SRC", &source);
        write_file_or_panic(&header_path, header, "runtime_bundle_source.h");
        eprintln!("ibex build: generated runtime_bundle_source.h from vendored runtime bundle");
        generate_runtime_bundle_bytecode_header(
            out_dir,
            &bundled_runtime,
            hermesc,
            runtime_hbc_version,
            portable_hermesc_runner,
            "embedded_runtime_bundle",
            "runtime_bundle_bytecode.h",
            "SHARED_RUNTIME_BUNDLE_HBC",
            "shared runtime bundle",
        );
        return;
    }

    if !runtime_entry.exists() || !build_script.exists() {
        if !allow_fallback {
            panic!(
                "Runtime bundle source files are missing (expected {} and {}) and EXACT_ALLOW_FALLBACK is not set",
                runtime_entry.display(),
                build_script.display()
            );
        }
        println!(
            "cargo:warning=Runtime bundle source files are missing; Ibex will keep the legacy bootstrap fallback"
        );
        return;
    }

    if !build_runtime_bundle_source(repo_root, &devtools_dir, &runtime_entry, &bundled_runtime) {
        let missing_js_deps_hint = missing_js_build_deps_hint(repo_root);
        if !allow_fallback {
            panic!(
                "Failed to build the shared runtime bundle for Ibex and EXACT_ALLOW_FALLBACK is not set{missing_js_deps_hint}"
            );
        }
        println!(
            "cargo:warning=Failed to build the shared runtime bundle for Ibex; keeping the legacy bootstrap fallback"
        );
        return;
    }

    let source = match std::fs::read_to_string(&bundled_runtime) {
        Ok(source) => source,
        Err(err) => {
            if !allow_fallback {
                panic!(
                    "Failed to read shared runtime bundle {} ({}) and EXACT_ALLOW_FALLBACK is not set",
                    bundled_runtime.display(),
                    err
                );
            }
            println!(
                "cargo:warning=Failed to read shared runtime bundle {}: {}",
                bundled_runtime.display(),
                err
            );
            return;
        }
    };

    if !source.contains("ExactBundle") || !source.contains("__exactRuntimeLoaded") {
        if !allow_fallback {
            panic!(
                "Shared runtime bundle at {} does not look like an Ibex runtime bundle and EXACT_ALLOW_FALLBACK is not set",
                bundled_runtime.display()
            );
        }
        println!(
            "cargo:warning=Shared runtime bundle at {} does not look like an Ibex runtime bundle; keeping legacy bootstrap fallback",
            bundled_runtime.display()
        );
        return;
    }

    let mut header = format!(
        "// Generated by build.rs from packages/ibex-runtime-js/src/{runtime_entry_name}\n\
         // Do not edit by hand.\n"
    );
    push_cpp_raw_string_literal(&mut header, "SHARED_RUNTIME_BUNDLE_SRC", &source);
    write_file_or_panic(&header_path, header, "runtime_bundle_source.h");
    write_embedded_runtime_rs(
        out_dir,
        &format!("packages/ibex-runtime-js/src/{runtime_entry_name}"),
    );
    eprintln!("ibex build: generated runtime_bundle_source.h from shared runtime bundle");

    generate_runtime_bundle_bytecode_header(
        out_dir,
        &bundled_runtime,
        hermesc,
        runtime_hbc_version,
        portable_hermesc_runner,
        "embedded_runtime_bundle",
        "runtime_bundle_bytecode.h",
        "SHARED_RUNTIME_BUNDLE_HBC",
        "shared runtime bundle",
    );
}

fn write_embedded_runtime_rs(out_dir: &Path, source_name: &str) {
    let generated = format!(
        "/// Auto-generated by build.rs; do not edit.\n\
         pub mod embedded_runtime {{\n\
             pub const EMBEDDED_RUNTIME: &[u8] = include_bytes!(\"embedded_runtime_bundle.js\");\n\
             pub const EMBEDDED_RUNTIME_IS_BYTECODE: bool = false;\n\
             pub const EMBEDDED_RUNTIME_NAME: &str = \"{}\";\n\
         }}\n",
        source_name
    );
    write_file_or_panic(
        &out_dir.join("embedded_runtime.rs"),
        generated,
        "embedded_runtime.rs",
    );
}

fn write_empty_embedded_runtime_rs(out_dir: &Path) {
    let generated = "/// Auto-generated by build.rs; do not edit.\n\
         pub mod embedded_runtime {\n\
             pub const EMBEDDED_RUNTIME: &[u8] = &[];\n\
             pub const EMBEDDED_RUNTIME_IS_BYTECODE: bool = false;\n\
             pub const EMBEDDED_RUNTIME_NAME: &str = \"\";\n\
         }\n";
    write_file_or_panic(
        &out_dir.join("embedded_runtime.rs"),
        generated,
        "embedded_runtime.rs",
    );
}

fn build_runtime_bundle_source(
    repo_root: &Path,
    devtools_dir: &Path,
    runtime_entry: &Path,
    bundled_runtime: &Path,
) -> bool {
    let build_script = devtools_dir
        .join("src")
        .join("scripts")
        .join("rolldown-bundle.mjs");
    let Some(parent) = bundled_runtime.parent() else {
        return false;
    };
    let _ = std::fs::create_dir_all(parent);

    // --lower-classes must match package.json's build:runtime (rolldown
    // defaults it off): the pinned Hermes rejects `class` syntax, and without
    // it refresh:vendored / IBEX_REGENERATE_RUNTIME builds would write a
    // non-lowered bundle that breaks the regenerate-vendored "same bytes"
    // invariant and fails HBC compilation. (ENG-23131)
    let mut ran_local_runner = false;
    if let Some(runner_path) = which_js_runner() {
        ran_local_runner = true;
        let status = std::process::Command::new(&runner_path)
            .arg(&build_script)
            .arg("--entry")
            .arg(runtime_entry)
            .arg("--out")
            .arg(bundled_runtime)
            .arg("--format")
            .arg("iife")
            .arg("--lower-classes")
            .current_dir(devtools_dir)
            // Keep JS-runner descriptor flag changes away from Cargo's
            // build-script protocol stream; build.rs reports status itself.
            .stdout(std::process::Stdio::null())
            .status();

        if matches!(status, Ok(result) if result.success()) {
            return true;
        }
    }

    // Same policy as the builtins path: the primary-checkout substitute is
    // for worktrees with no local runner or JS deps. A present local pipeline
    // that fails must surface as a failure (LLP 0019), not be papered over by
    // the primary's (possibly older) bundler.
    if !ran_local_runner || !missing_js_build_deps_hint(repo_root).is_empty() {
        try_build_runtime_bundle_via_primary_checkout(repo_root, runtime_entry, bundled_runtime)
    } else {
        false
    }
}

fn push_cpp_raw_string_literal(out: &mut String, const_name: &str, source: &str) {
    const CHUNK_SIZE: usize = 16 * 1024;
    out.push_str(&format!("static const char* {const_name} =\n"));

    if source.is_empty() {
        out.push_str("R\"JSSRC()JSSRC\"");
    } else {
        let mut start = 0;
        while start < source.len() {
            let mut end = (start + CHUNK_SIZE).min(source.len());
            while end > start && !source.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                end = source.len();
            }
            out.push_str("R\"JSSRC(");
            out.push_str(&source[start..end]);
            out.push_str(")JSSRC\"");
            if end < source.len() {
                out.push('\n');
            }
            start = end;
        }
    }

    out.push_str(";\n\n");
}

fn write_empty_bootstrap_hbc_header(path: &Path, bootstrap_files: &[(&str, &str)]) {
    let mut header = String::from(
        "// Auto-generated by build.rs — empty fallback bytecode placeholders\n\
         #pragma once\n\n",
    );
    for (_, array_name) in bootstrap_files {
        push_empty_bootstrap_hbc_entry(&mut header, array_name);
    }
    write_file_or_panic(path, header, "empty bootstrap_bytecode.h");
}

fn push_empty_bootstrap_hbc_entry(header: &mut String, array_name: &str) {
    header.push_str(&format!(
        "alignas(8) static const uint8_t {}_HBC[] = {{0}};\n\
         static const size_t {}_HBC_LEN = 0;\n\n",
        array_name, array_name
    ));
}

fn bootstrap_hbc_source_fallback_allowed(js_file: &str) -> bool {
    // @ref LLP 0005#bytecode-precompilation-hermesc — The web streams polyfill
    // is opt-in bootstrap code, and older hermesc builds reject its syntax.
    js_file == "web-streams-polyfill.js"
}

fn profile_dir_from_out_dir(out_dir: &Path) -> PathBuf {
    out_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| {
            panic!(
                "Could not derive Cargo profile directory from OUT_DIR={}",
                out_dir.display()
            )
        })
}

fn stage_windows_runtime_dlls(out_dir: &Path, hermes_bin_dir: &Path) {
    let profile_dir = profile_dir_from_out_dir(out_dir);
    // @ref LLP 0005#c-compilation — bundle-wide interprocess serialization
    // and atomic digest-checked publication prevent concurrent builds from
    // mixing DLLs selected from different Hermes sources (ENG-24264).
    let report = stage_runtime_dlls(&profile_dir, hermes_bin_dir).unwrap_or_else(|error| {
        panic!(
            "Failed to stage Windows Hermes runtime DLLs from {}: {error}. Stop any process locking a stale destination and rebuild; a successful build never reuses mismatched runtime code.",
            hermes_bin_dir.display()
        )
    });
    for path in &report.source_paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    eprintln!(
        "ibex build: staged {} Windows runtime DLLs from {} (bundle {}, {} published, {} reused)",
        report.dll_count,
        hermes_bin_dir.display(),
        report.bundle_digest,
        report.published_files,
        report.reused_files,
    );
}

fn generate_runtime_bundle_bytecode_header(
    out_dir: &Path,
    bundled_runtime: &Path,
    hermesc: &Path,
    runtime_hbc_version: Option<u32>,
    portable_hermesc_runner: Option<&portable_host_tool_runner::PortableHostToolRunner>,
    output_stem: &str,
    header_file_name: &str,
    symbol: &str,
    artifact_label: &str,
) {
    let bundled_runtime_hbc = out_dir.join(format!("{output_stem}.hbc"));
    let header_path = out_dir.join(header_file_name);

    if let Some(runner) = portable_hermesc_runner {
        // The current reviewed compatibility contract permits at most 1 MiB
        // of declared output, while optional runtime HBCs may be larger.
        // Do not widen authority to fit an optimization: portable builds use
        // the generated source bundle and leave no stale/partial HBC artifact.
        // A future performance change must review a new bound and artifact
        // identity before enabling this compilation.
        // @ref LLP 0035#build-consumption-and-post-link-contracts
        remove_portable_optional_hbc(&bundled_runtime_hbc);
        remove_portable_optional_hbc(&header_path);
        println!(
            "cargo:warning=Portable Hermes uses the generated {artifact_label} source; the optional HBC is disabled under the reviewed {}-byte host-tool output bound",
            runner.max_output_bytes()
        );
        return;
    }

    safe_remove_file(&bundled_runtime_hbc);
    safe_remove_file(&header_path);

    if !hermesc.exists() {
        println!(
            "cargo:warning=Skipping {artifact_label} HBC generation: hermesc not found at {}",
            hermesc.display()
        );
        return;
    }

    let compiler_version = if let Some(runner) = portable_hermesc_runner {
        extract_portable_hbc_version(runner).unwrap_or_else(|error| {
            panic!("Portable runtime-bundle hermesc version probe refused: {error}")
        })
    } else {
        let Some(version) = extract_hbc_version(hermesc) else {
            println!(
                "cargo:warning=Skipping {artifact_label} HBC generation: could not read hermesc HBC version"
            );
            return;
        };
        version
    };

    let Some(runtime_version) = runtime_hbc_version else {
        if portable_hermesc_runner.is_some() {
            panic!("Portable runtime-bundle build has no authenticated runtime HBC version");
        }
        println!(
            "cargo:warning=Skipping {artifact_label} HBC generation: no selected Hermes runtime HBC version"
        );
        return;
    };

    if compiler_version != runtime_version {
        if portable_hermesc_runner.is_some() {
            panic!(
                "Portable runtime-bundle hermesc HBC version {} differs from runtime {}",
                compiler_version, runtime_version
            );
        }
        println!(
            "cargo:warning=Skipping {artifact_label} HBC generation: hermesc HBC version {} != hermes HBC version {}",
            compiler_version,
            runtime_version
        );
        return;
    }

    let compile_succeeded = if let Some(runner) = portable_hermesc_runner {
        run_portable_hermesc_compile(runner, bundled_runtime, &bundled_runtime_hbc)
            .unwrap_or_else(|error| panic!("Portable runtime-bundle hermesc refused: {error}"));
        true
    } else {
        run_checkout_independent_hermesc_compile(hermesc, bundled_runtime, &bundled_runtime_hbc)
    };

    if !compile_succeeded {
        println!("cargo:warning=Skipping {artifact_label} HBC generation: hermesc failed");
        safe_remove_file(&bundled_runtime_hbc);
        return;
    }

    let file_version = if portable_hermesc_runner.is_some() {
        Some(
            portable_bytecode_file_version(&bundled_runtime_hbc).unwrap_or_else(|error| {
                panic!("Portable runtime-bundle HBC validation refused: {error}")
            }),
        )
    } else {
        bytecode_file_version(hermesc, &bundled_runtime_hbc)
    };
    match file_version {
        Some(file_version) if file_version == compiler_version => {}
        Some(file_version) => {
            if portable_hermesc_runner.is_some() {
                panic!(
                    "Portable runtime-bundle HBC version mismatch: compiled {} expected {}",
                    file_version, compiler_version
                );
            }
            println!(
                "cargo:warning=Skipping {artifact_label} HBC generation: file HBC version {} != expected {}",
                file_version,
                compiler_version
            );
            safe_remove_file(&bundled_runtime_hbc);
            return;
        }
        None => {
            println!(
                "cargo:warning=Skipping {artifact_label} HBC generation: could not read generated HBC version"
            );
            safe_remove_file(&bundled_runtime_hbc);
            return;
        }
    }

    let bytes = read_bytes_or_panic(&bundled_runtime_hbc, &format!("{artifact_label} HBC"));
    let mut header = format!(
        "// Generated by build.rs for {artifact_label}\n\
         // Do not edit by hand.\n\
         #pragma once\n\n\
         alignas(8) static const uint8_t {symbol}[] = {{\n"
    );

    for (index, byte) in bytes.iter().enumerate() {
        if index % 16 == 0 && index > 0 {
            header.push('\n');
        }
        header.push_str(&format!("0x{:02X},", byte));
    }

    header.push_str(&format!(
        "\n}};\n\
         static const size_t {symbol}_LEN = sizeof({symbol});\n"
    ));

    write_file_or_panic(&header_path, header, header_file_name);
    eprintln!("ibex build: generated {header_file_name} from {artifact_label}");
}

fn try_build_builtins_via_primary_checkout(
    repo_root: &Path,
    builtins_src: &Path,
    builtins_out: &Path,
) -> bool {
    let Some(primary_root) = resolve_primary_worktree_root(repo_root) else {
        return false;
    };
    if primary_root == repo_root {
        return false;
    }

    let primary_devtools_dir = exact_devtools_dir(&primary_root);
    let primary_script = primary_devtools_dir
        .join("src")
        .join("scripts")
        .join("build-builtins.mjs");
    let primary_node_modules = primary_devtools_dir.join("node_modules");

    if !primary_script.exists() || !primary_node_modules.exists() || !builtins_src.exists() {
        return false;
    }

    let _ = std::fs::create_dir_all(builtins_out);
    let status = std::process::Command::new("node")
        .arg(primary_script)
        .arg("--src-dir")
        .arg(builtins_src)
        .arg("--out-dir")
        .arg(builtins_out)
        .current_dir(&primary_devtools_dir)
        .status();

    matches!(status, Ok(result) if result.success())
}

fn try_build_runtime_bundle_via_primary_checkout(
    repo_root: &Path,
    runtime_entry: &Path,
    bundled_runtime: &Path,
) -> bool {
    let Some(primary_root) = resolve_primary_worktree_root(repo_root) else {
        return false;
    };
    if primary_root == repo_root {
        return false;
    }

    let primary_devtools_dir = exact_devtools_dir(&primary_root);
    let primary_script = primary_devtools_dir
        .join("src")
        .join("scripts")
        .join("rolldown-bundle.mjs");
    let primary_node_modules = primary_devtools_dir.join("node_modules");

    if !primary_script.exists() || !primary_node_modules.exists() || !runtime_entry.exists() {
        return false;
    }

    if let Some(parent) = bundled_runtime.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let status = std::process::Command::new("node")
        .arg(primary_script)
        .arg("--entry")
        .arg(runtime_entry)
        .arg("--out")
        .arg(bundled_runtime)
        .arg("--format")
        .arg("iife")
        .arg("--lower-classes")
        .current_dir(&primary_devtools_dir)
        .status();

    matches!(status, Ok(result) if result.success())
}

fn resolve_primary_worktree_root(repo_root: &Path) -> Option<PathBuf> {
    let dot_git_path = repo_root.join(".git");
    let dot_git_contents = std::fs::read_to_string(&dot_git_path).ok()?;
    let gitdir = dot_git_contents
        .lines()
        .find_map(|line| line.trim().strip_prefix("gitdir:"))
        .map(str::trim)?;
    let gitdir_path = resolve_git_path(repo_root, Path::new(gitdir));
    let commondir_contents = std::fs::read_to_string(gitdir_path.join("commondir")).ok()?;
    let commondir = commondir_contents.lines().next()?.trim();
    let common_git_dir = resolve_git_path(&gitdir_path, Path::new(commondir));
    common_git_dir.parent().map(|path| path.to_path_buf())
}

fn resolve_git_path(base: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        return candidate.to_path_buf();
    }

    match std::fs::canonicalize(base.join(candidate)) {
        Ok(path) => path,
        Err(_) => base.join(candidate),
    }
}

fn missing_js_build_deps_hint(repo_root: &Path) -> String {
    let devtools_dir = exact_devtools_dir(repo_root);
    let node_modules_dir = devtools_dir.join("node_modules");
    let rolldown_dir = node_modules_dir.join("rolldown");
    let acorn_dir = node_modules_dir.join("acorn");

    if node_modules_dir.exists() && rolldown_dir.exists() && acorn_dir.exists() {
        String::new()
    } else {
        format!(
            "\nJS build dependencies look missing under {}.\nRun `bun install` from {} and retry.",
            node_modules_dir.display(),
            repo_root.display()
        )
    }
}

fn copy_builtins_fallback(src: &std::path::Path, dst: &std::path::Path) {
    let _ = std::fs::create_dir_all(dst);
    if let Ok(entries) = std::fs::read_dir(src) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "js" || e == "ts") {
                let Some(file_name) = path.file_name() else {
                    println!(
                        "cargo:warning=Skipping builtin copy for {} because it has no file name",
                        path.display()
                    );
                    continue;
                };
                let dest = dst.join(file_name);
                let _ = std::fs::copy(&path, &dest);
            }
        }
    }
}

/// Copy every file in `src` whose extension is in `extensions` into `dst`,
/// creating `dst` if needed. Used to stage vendored generated artifacts into
/// OUT_DIR for the standalone Ibex build.
fn copy_dir_files(src: &Path, dst: &Path, extensions: &[&str]) {
    if let Err(error) = std::fs::create_dir_all(dst) {
        panic!("Failed to create OUT_DIR subdir {}: {error}", dst.display());
    }
    for path in read_dir_paths_or_panic(src, "vendored artifact copy") {
        let matches_ext = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| extensions.contains(&e));
        if !matches_ext {
            continue;
        }
        let Some(file_name) = path.file_name() else {
            continue;
        };
        let dest = dst.join(file_name);
        if let Err(error) = std::fs::copy(&path, &dest) {
            panic!(
                "Failed to copy vendored artifact {} -> {}: {error}",
                path.display(),
                dest.display()
            );
        }
    }
}

fn clear_dir_if_exists(path: &Path, context: &str) {
    if !path.exists() {
        return;
    }
    std::fs::remove_dir_all(path).unwrap_or_else(|error| {
        panic!(
            "Failed to clear {context} directory {}: {error}",
            path.display()
        )
    });
}

fn refresh_vendored_generated(out_dir: &Path, vendored_generated_dir: &Path) {
    if let Err(error) = std::fs::create_dir_all(vendored_generated_dir) {
        panic!(
            "Failed to create vendored generated dir {}: {error}",
            vendored_generated_dir.display()
        );
    }

    for file_name in ["builtin_manifest.generated.rs"] {
        let src = out_dir.join(file_name);
        let dst = vendored_generated_dir.join(file_name);
        let contents = read_bytes_or_panic(&src, file_name);
        write_file_or_panic(&dst, contents, file_name);
        eprintln!("ibex build: refreshed vendored artifact {}", dst.display());
    }
    let runtime_src = out_dir.join("embedded_runtime_bundle.js");
    let runtime_dst = vendored_generated_dir.join("embedded_runtime_bundle.js");
    let runtime_contents = read_bytes_or_panic(&runtime_src, "embedded_runtime_bundle.js");
    write_file_or_panic(&runtime_dst, runtime_contents, "embedded_runtime_bundle.js");
    eprintln!(
        "ibex build: refreshed vendored artifact {}",
        runtime_dst.display()
    );
    let src_builtins = out_dir.join("builtins");
    let dst_builtins = vendored_generated_dir.join("builtins");
    clear_dir_if_exists(&dst_builtins, "vendored builtins");
    copy_dir_files(&src_builtins, &dst_builtins, &["js"]);
    eprintln!(
        "ibex build: refreshed vendored builtin modules in {}",
        dst_builtins.display()
    );
}

fn safe_remove_file(path: &Path) {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != ErrorKind::NotFound {
            println!("cargo:warning=Failed to remove {}: {}", path.display(), err);
        }
    }
}

fn remove_portable_optional_hbc(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => panic!(
            "Could not remove stale portable optional HBC artifact {}: {error}",
            path.display()
        ),
    }
    if std::fs::symlink_metadata(path).is_ok() {
        panic!(
            "Stale portable optional HBC artifact remains at {}",
            path.display()
        );
    }
}

fn run_tool_output(path: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(path).args(args).output().ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    if text.trim().is_empty() {
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    if !output.status.success() {
        return None;
    }
    Some(text)
}

fn extract_portable_hbc_version(
    runner: &portable_host_tool_runner::PortableHostToolRunner,
) -> Result<u32, String> {
    let output = runner
        .run(&[OsString::from("--version")], &[])
        .map_err(|error| {
            format!(
                "compatibility {} version invocation failed: {error}",
                runner.compatibility_digest()
            )
        })?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    if text.trim().is_empty() {
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    extract_u32_after_prefix(&text, "HBC bytecode version:").ok_or_else(|| {
        format!(
            "compatibility {} version output omitted the HBC version",
            runner.compatibility_digest()
        )
    })
}

fn run_portable_hermesc_compile(
    runner: &portable_host_tool_runner::PortableHostToolRunner,
    source: &Path,
    output: &Path,
) -> Result<(), String> {
    safe_remove_file(output);
    let mut args = Vec::<OsString>::new();
    if hermes_es6_block_scoping_enabled() {
        args.push(OsString::from("-Xes6-block-scoping"));
    }
    args.extend([
        OsString::from("-emit-binary"),
        OsString::from("-O"),
        OsString::from("-out"),
        output.as_os_str().to_owned(),
        source.as_os_str().to_owned(),
    ]);
    runner
        .run(&args, &[output.to_path_buf()])
        .map(|_| ())
        .map_err(|error| {
            format!(
                "compatibility {} compile invocation failed: {error}",
                runner.compatibility_digest()
            )
        })
}

fn portable_bytecode_file_version(path: &Path) -> Result<u32, String> {
    const HERMES_HBC_MAGIC: u64 = 0x1f19_03c1_03bc_1fc6;
    let bytes = std::fs::read(path)
        .map_err(|error| format!("read portable hermesc output {}: {error}", path.display()))?;
    if bytes.len() < 36 {
        return Err("portable hermesc output has a truncated bytecode header".to_owned());
    }
    let magic = u64::from_le_bytes(bytes[0..8].try_into().expect("eight-byte HBC magic"));
    if magic != HERMES_HBC_MAGIC {
        return Err("portable hermesc output has the wrong bytecode magic".to_owned());
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().expect("four-byte HBC version"));
    let declared_length =
        u32::from_le_bytes(bytes[32..36].try_into().expect("four-byte HBC length")) as usize;
    if declared_length != bytes.len() {
        return Err(format!(
            "portable hermesc output declares {declared_length} bytes but contains {}",
            bytes.len()
        ));
    }
    Ok(version)
}

fn extract_u32_after_prefix(line_iter: &str, prefix: &str) -> Option<u32> {
    for line in line_iter.lines() {
        if let Some(rest) = line.trim().strip_prefix(prefix) {
            if let Ok(value) = rest.trim().parse::<u32>() {
                return Some(value);
            }
        }
    }
    None
}

fn extract_hbc_version(binary_path: &Path) -> Option<u32> {
    run_tool_output(binary_path, &["--version"])
        .and_then(|text| extract_u32_after_prefix(&text, "HBC bytecode version:"))
}

fn bytecode_file_version(hermesc: &Path, hbc_path: &Path) -> Option<u32> {
    let mut child = std::process::Command::new(hermesc)
        .arg("-dump-bytecode")
        .arg(hbc_path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };
    let mut reader = BufReader::new(stdout);

    for _ in 0..128 {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if let Some(version) =
                    extract_u32_after_prefix(line.trim(), "Bytecode version number:")
                {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Some(version);
                }
            }
            Err(_) => break,
        }
    }

    drop(reader);
    let _ = child.kill();
    let _ = child.wait();
    None
}

fn parse_env_flag(name: &str) -> Option<bool> {
    std::env::var(name).ok().map(|value| {
        matches!(
            value.as_str(),
            "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
        )
    })
}

fn hermes_es6_block_scoping_enabled() -> bool {
    !parse_env_flag("IBEX_LEGACY_HERMES_BLOCK_SCOPING").unwrap_or(false)
}

fn hermesc_command(hermesc: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(hermesc);
    if hermes_es6_block_scoping_enabled() {
        command.arg("-Xes6-block-scoping");
    }
    command
}

fn run_checkout_independent_hermesc_compile(hermesc: &Path, source: &Path, output: &Path) -> bool {
    let mut command = hermesc_command(hermesc);
    command
        .arg("-emit-binary")
        .arg("-O")
        .arg("-out")
        .arg(output);
    hermesc_source_label::append_checkout_independent_source(&mut command, source).unwrap_or_else(
        |error| panic!("Cannot construct checkout-independent hermesc input: {error}"),
    );
    matches!(command.status(), Ok(status) if status.success())
}

fn resolve_macos_hermes_framework(lib_root: &Path) -> Option<AppleFramework> {
    let search_dirs = [
        lib_root.to_path_buf(),
        lib_root.join("macosx"),
        lib_root
            .join("hermes.xcframework")
            .join("macos-arm64_x86_64"),
        lib_root.join("hermes.xcframework").join("macos-arm64"),
    ];

    for search_dir in search_dirs {
        for framework_name in ["hermesvm", "hermes"] {
            let framework_dir = search_dir.join(format!("{framework_name}.framework"));
            if let Some(binary_path) = find_framework_binary(&framework_dir, framework_name) {
                return Some(AppleFramework {
                    search_dir,
                    framework_name: framework_name.to_string(),
                    binary_path,
                });
            }
        }
    }

    None
}

fn resolve_ios_simulator_hermes_binary(lib_root: &Path) -> Option<PathBuf> {
    let framework_roots = [
        lib_root.to_path_buf(),
        lib_root
            .join("hermes.xcframework")
            .join("ios-arm64_x86_64-simulator"),
        lib_root
            .join("hermesvm.xcframework")
            .join("ios-arm64_x86_64-simulator"),
    ];

    for root in framework_roots {
        for framework_name in ["hermesvm", "hermes"] {
            let framework_dir = root.join(format!("{framework_name}.framework"));
            if let Some(binary_path) = find_framework_binary(&framework_dir, framework_name) {
                return Some(binary_path);
            }
        }
    }

    None
}

fn find_framework_binary(framework_dir: &Path, framework_name: &str) -> Option<PathBuf> {
    let candidates = [
        framework_dir
            .join("Versions")
            .join("Current")
            .join(framework_name),
        framework_dir
            .join("Versions")
            .join("1")
            .join(framework_name),
        framework_dir
            .join("Versions")
            .join("0")
            .join(framework_name),
        framework_dir.join(framework_name),
    ];

    candidates.into_iter().find(|path| path.exists())
}

fn hermes_has_debugger_symbols(target_os: &str, binary_path: &Path) -> bool {
    let mut command = std::process::Command::new("nm");
    configure_defined_nm_command(&mut command, target_os, binary_path);
    command.arg(binary_path);
    let output = command.output().or_else(|_| {
        let mut command = std::process::Command::new("xcrun");
        command.arg("nm");
        configure_defined_nm_command(&mut command, target_os, binary_path);
        command.arg(binary_path).output()
    });

    let Ok(output) = output else {
        return false;
    };

    if !output.status.success() {
        return false;
    }

    let symbols = String::from_utf8_lossy(&output.stdout);
    // A no-debugger Hermes still retains RuntimeTaskRunner definitions whose
    // signatures mention AsyncDebuggerAPI. Require the exact constructor and
    // loaded-script query that the adapter calls so those stubs cannot create
    // a false-positive link profile.
    symbols.contains("AsyncDebuggerAPIC") && symbols.contains("getLoadedScripts")
}

/// Minimum-OS flag for Apple C/C++/Objective-C++ sources, matching the
/// deployment targets in the Exact Xcode project.
fn apple_min_version_flag(target_os: &str) -> &'static str {
    match target_os {
        "macos" => "-mmacosx-version-min=14.0",
        "tvos" => "-mtvos-version-min=17.0",
        _ => "-mios-version-min=17.0",
    }
}

// @ref LLP 0013#mechanism-3 — detect whether the exact linked desktop Hermes
// artifact exports the capability-attribution bridge from patches/hermes/0003.
// An unpatched engine degrades to the thread-local module id instead of failing
// to link. Linux shared objects need the dynamic symbol table; macOS frameworks
// use the same global/undefined filter as the debugger-symbol probe above.
fn configure_defined_nm_command(
    command: &mut std::process::Command,
    target_os: &str,
    binary_path: &Path,
) {
    match target_os {
        "macos" | "ios" | "tvos" => {
            // Apple nm spells "external definitions only" as -g -U.
            command.args(["-g", "-U"]);
        }
        "linux" if binary_path.extension().is_some_and(|value| value == "so") => {
            command.args(["-D", "-g", "--defined-only"]);
        }
        "linux" => {
            command.args(["-g", "--defined-only"]);
        }
        _ => {}
    }
    command.arg(binary_path);
}

fn hermes_exports_exact_symbols(target_os: &str, binary_path: &Path, required: &[&str]) -> bool {
    use hermes_symbol_probe::{has_exact_defined_symbols, SymbolListingFormat};

    let (format, output) = if target_os == "windows" {
        let output = std::process::Command::new("dumpbin")
            .arg("/exports")
            .arg(binary_path)
            .output();
        let Ok(output) = output else {
            return false;
        };
        (SymbolListingFormat::DumpbinExports, output)
    } else {
        let format = SymbolListingFormat::Nm {
            strip_leading_underscore: target_os == "macos",
        };
        let mut command = std::process::Command::new("nm");
        configure_defined_nm_command(&mut command, target_os, binary_path);
        let output = command.output().or_else(|_| {
            let mut command = std::process::Command::new("xcrun");
            command.arg("nm");
            configure_defined_nm_command(&mut command, target_os, binary_path);
            command.output()
        });
        let Ok(output) = output else {
            return false;
        };
        (format, output)
    };

    has_exact_defined_symbols(format, output.status.success(), &output.stdout, required)
}

fn hermes_has_frame_attribution(target_os: &str, binary_path: &Path) -> bool {
    hermes_exports_exact_symbols(target_os, binary_path, &["ex_hermes_vm_current_package_id"])
}

fn hermes_has_dynamic_code_latch(target_os: &str, binary_path: &Path) -> bool {
    hermes_exports_exact_symbols(target_os, binary_path, &["ex_hermes_vm_disable_eval"])
}

fn hermes_has_structured_async_provenance(target_os: &str, binary_path: &Path) -> bool {
    use hermes_symbol_probe::STRUCTURED_ASYNC_PROVENANCE_SYMBOLS;

    hermes_exports_exact_symbols(target_os, binary_path, STRUCTURED_ASYNC_PROVENANCE_SYMBOLS)
}

fn hermes_has_job_constrained_principals(target_os: &str, binary_path: &Path) -> bool {
    use hermes_symbol_probe::JOB_CONSTRAINED_PRINCIPAL_SYMBOLS;

    hermes_exports_exact_symbols(target_os, binary_path, JOB_CONSTRAINED_PRINCIPAL_SYMBOLS)
}

fn should_enable_hermes_debugger(target_os: &str, hermes_binary: Option<&Path>) -> bool {
    match parse_env_flag("HERMES_ENABLE_DEBUGGER") {
        Some(false) => false,
        Some(true) => {
            if matches!(target_os, "macos" | "linux") {
                let Some(binary_path) = hermes_binary else {
                    panic!(
                        "HERMES_ENABLE_DEBUGGER=1 was requested, but no {target_os} Hermes binary was found."
                    );
                };
                if !hermes_has_debugger_symbols(target_os, binary_path) {
                    panic!(
                        "HERMES_ENABLE_DEBUGGER=1 was requested, but {} does not export Hermes debugger symbols. Rebuild Hermes with debugger support or unset HERMES_ENABLE_DEBUGGER.",
                        binary_path.display()
                    );
                }
            }
            true
        }
        None => match target_os {
            "ios" | "tvos" | "android" => false,
            "macos" | "linux" => match hermes_binary {
                Some(binary_path) if hermes_has_debugger_symbols(target_os, binary_path) => true,
                Some(binary_path) => {
                    println!(
                        "cargo:warning=Hermes debugger disabled: {} does not export debugger symbols.",
                        binary_path.display()
                    );
                    false
                }
                None => {
                    println!(
                        "cargo:warning=Hermes debugger disabled: could not locate the linked {target_os} Hermes binary."
                    );
                    false
                }
            },
            _ => true,
        },
    }
}
