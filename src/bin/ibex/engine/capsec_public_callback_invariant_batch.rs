use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
#[cfg(not(feature = "host-http-server"))]
use std::io::Write as _;

const CALLBACK_INVOCATION_SCHEMA: &str = "ibex/capsec-callback-invariant-invocation/1";
const ENV_AUXILIARY_EDGE_ID: &str = "surface.native.op.exactgetenv.0k6bv7a";
const EXACT_OPERATION_MANIFEST_DIGEST: &str = "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA";
const EXACT_APP_OPERATION_IDS: [u32; 2] = [7, 11];
const CALLBACK_BATCH_COMMAND: [&str; 10] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--no-default-features",
    "--features",
    "standard,capsec-conformance-observer,openssl-crypto",
    "capsec_public_callback_invariant_batch",
    "--",
    "--test-threads=1",
];
const INTERNAL_INVARIANT_COMMAND: [&str; 11] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--no-default-features",
    "--features",
    "standard,capsec-conformance-observer,openssl-crypto",
    "capsec_internal_invariant_evidence_batch",
    "--",
    "--test-threads=1",
    "--nocapture",
];
const INTERNAL_INVARIANT_EXECUTOR: &str = "ibex-internal-invariant-proof-harness-v1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecipeCatalog {
    recipe_catalog_schema: String,
    recipe_catalog_digest: String,
    target: CatalogTarget,
    recipes: Vec<Recipe>,
}

#[derive(Debug, Deserialize)]
struct CatalogTarget {
    triple: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipe {
    fixture_id: String,
    plan_digest: String,
    classification: String,
    scenario: String,
    edge_ids: Vec<String>,
    implementation_branch_ids: Vec<String>,
    enforcement_branch_ids: Vec<String>,
    action_ids: Vec<String>,
    terminal_observed_key: String,
    expected_observation: serde_json::Value,
    route: PublicRoute,
    status: String,
    public_surface_probe: Option<PublicSurfaceProbe>,
    internal_invariant_proof: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicRoute {
    surface_observed_keys: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicSurfaceProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: CallbackInvariantInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CallbackInvariantInvocation {
    invocation_schema: String,
    kind: String,
    #[serde(default)]
    scenario: String,
    #[serde(default)]
    surface_kind: String,
    #[serde(default)]
    surface_name: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    expected_result: String,
    expected_typed_decision_count: usize,
    expected_typed_stages: Vec<String>,
    #[serde(default)]
    expected_typed_outcomes: Vec<String>,
    #[serde(default)]
    expected_typed_reasons: Vec<String>,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicBatchArtifact {
    public_batch_evidence_schema: &'static str,
    recipe_catalog_digest: String,
    loaded_engine_identity: ibex_runtime::engine::LoadedEngineBinaryIdentity,
    executions: Vec<serde_json::Value>,
}

struct PackageFixture {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    package_root: std::path::PathBuf,
    principal_value: serde_json::Value,
    principal: capsec_semantics::model::Principal,
}

struct EmbedderArtifactFixture {
    _directory: tempfile::TempDir,
    snapshot: Vec<u8>,
    expected_identity: Vec<u8>,
    source_nonce: String,
    source_digest: String,
}

struct ScenarioExecution {
    result: serde_json::Value,
    typed_decisions: Vec<serde_json::Value>,
    legacy_observation_count: usize,
}

/// Test-only armed engine facade. Its `eval_immediate` spelling preserves the
/// existing conformance harness shape, but every call consumes a closed,
/// authenticated REPL submission; it never reaches Hermes' sealed bare
/// evaluator. Short-lived sequence claims remain one monotonic stream because
/// the Host caches the exact session token and its ordinal state.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry —
/// armed project source enters only through authenticated session submission.
/// @ref LLP 0025#11-delegated-obligations — every authenticated callback work
/// unit is paired and delivered to the evidence controller before teardown.
struct AuthenticatedCallbackEngine {
    host: crate::host::Host,
    engine: HermesEngine,
    publications: std::sync::Mutex<AuthenticatedPublicationTracker>,
}

impl std::ops::Deref for AuthenticatedCallbackEngine {
    type Target = HermesEngine;

    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}

impl AuthenticatedCallbackEngine {
    fn drain_publications(&self, context: &str) -> anyhow::Result<()> {
        self.publications
            .lock()
            .map_err(|_| anyhow::anyhow!("{context} publication tracker mutex was poisoned"))?
            .drain(&self.engine, context)
    }

    fn require_no_due_schedules(&self, context: &str) -> anyhow::Result<()> {
        self.publications
            .lock()
            .map_err(|_| anyhow::anyhow!("{context} publication tracker mutex was poisoned"))?
            .require_no_due_schedules(context)
    }

    async fn eval_immediate(&self, source: &str) -> anyhow::Result<Option<String>> {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};

        self.drain_publications("before authenticated callback evaluation")?;
        let session = self.host.mint_armed_session_token()?;
        let mut sequence =
            ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())?;
        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })?
            .authorize_inline()
            .bind_bytes(source.as_bytes().to_vec())
            .into_request()?;
        let ordinal = request.submission_ordinal();
        let evaluation = self
            .engine
            .evaluate_authenticated(&session, request)
            .await
            .map_err(|error| {
                anyhow::anyhow!("authenticated callback submission {ordinal} failed: {error:#}")
            });
        let publications = self.drain_publications("after authenticated callback evaluation");
        let evaluation = evaluation?;
        publications?;
        match evaluation {
            AuthenticatedEvaluation::Empty => Ok(None),
            AuthenticatedEvaluation::Value { display, receipt } => {
                let release = self
                    .engine
                    .release_undisplayed_value(receipt.ok_or_else(|| {
                        anyhow::anyhow!(
                            "authenticated callback submission {ordinal} lost its value receipt"
                        )
                    })?)
                    .await;
                let publications =
                    self.drain_publications("after authenticated callback value release");
                release?;
                publications?;
                match display.kind {
                    AuthenticatedDisplayKind::Undefined => Ok(None),
                    AuthenticatedDisplayKind::String => serde_json::from_str(&display.text)
                        .map(Some)
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "authenticated callback submission {ordinal} returned an invalid string display: {error}"
                            )
                        }),
                    _ => Ok(Some(display.text)),
                }
            }
            AuthenticatedEvaluation::Throw(thrown) => {
                anyhow::bail!("authenticated callback submission {ordinal} threw: {thrown:?}")
            }
            AuthenticatedEvaluation::Cancelled => {
                anyhow::bail!("authenticated callback submission {ordinal} was cancelled")
            }
            AuthenticatedEvaluation::Lifecycle(code) => anyhow::bail!(
                "authenticated callback submission {ordinal} exited with lifecycle code {code}"
            ),
        }
    }

    async fn drive_event_loop(&self) -> anyhow::Result<()> {
        self.drain_publications("before authenticated callback event-loop drive")?;
        let drive = self.engine.drive_event_loop().await;
        let publications = self.drain_publications("after authenticated callback event-loop drive");
        drive?;
        publications?;
        self.require_no_due_schedules("authenticated callback event-loop drive")
    }

    fn finish(&self) -> anyhow::Result<()> {
        self.drain_publications("authenticated callback engine finish")?;
        self.require_no_due_schedules("authenticated callback engine finish")
    }
}

impl Drop for AuthenticatedCallbackEngine {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.finish()
                .expect("authenticated callback engine must finish every publication");
        }
    }
}

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("callback invariant evidence must have canonical JSON bytes");
    let digest = sha2::Sha256::digest(bytes);
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn load_strict_json(path: &std::path::Path, label: &str) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("read {label}: {error}"));
    let text = std::str::from_utf8(&bytes)
        .unwrap_or_else(|error| panic!("{label} must be UTF-8: {error}"));
    capsec_semantics::strict_json::parse_strict(text)
        .unwrap_or_else(|error| panic!("{label} must be strict JSON: {error}"))
}

fn assert_exact_keys(value: &serde_json::Value, keys: &[&str], label: &str) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{label} must be an object"));
    let actual = object
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = keys
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected, "{label} has unexpected or missing fields");
}

fn load_catalog(path: &std::path::Path) -> RecipeCatalog {
    let bytes = std::fs::read(path).expect("read CapSec executable recipe catalog");
    let text = std::str::from_utf8(&bytes).expect("recipe catalog must be UTF-8");
    let value = capsec_semantics::strict_json::parse_strict(text)
        .expect("recipe catalog must be strict JSON");
    let expected_digest = value["recipeCatalogDigest"]
        .as_str()
        .expect("recipe catalog has no digest");
    let mut projected = value.clone();
    projected
        .as_object_mut()
        .expect("recipe catalog must be an object")
        .remove("recipeCatalogDigest");
    assert_eq!(tagged_jcs_digest(&projected), expected_digest);
    let catalog: RecipeCatalog =
        serde_json::from_value(value).expect("recipe catalog shape must be valid");
    assert_eq!(
        catalog.recipe_catalog_schema,
        "ibex/capsec-executable-recipes/1"
    );
    assert_eq!(
        catalog.target.triple,
        embedder_runtime_target_triple(),
        "recipe catalog target triple does not describe this binary"
    );
    assert!(
        catalog
            .recipes
            .windows(2)
            .all(|pair| pair[0].fixture_id < pair[1].fixture_id),
        "recipe fixture ids must be a strictly sorted set"
    );
    catalog
}

fn checked_registry_rows() -> (
    BTreeMap<String, serde_json::Value>,
    BTreeMap<String, serde_json::Value>,
) {
    let implementation: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/generated/implementation-manifest.json"
    )))
    .expect("checked implementation manifest must be JSON");
    let coverage: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/registry/coverage-edges.json"
    )))
    .expect("checked coverage registry must be JSON");
    let branches = implementation["surfaces"]
        .as_array()
        .expect("implementation manifest has no surfaces")
        .iter()
        .map(|row| {
            (
                row["branchId"]
                    .as_str()
                    .expect("implementation row has no branch id")
                    .to_owned(),
                row.clone(),
            )
        })
        .collect();
    let edges = coverage["edges"]
        .as_array()
        .expect("coverage registry has no edges")
        .iter()
        .map(|edge| {
            (
                edge["id"]
                    .as_str()
                    .expect("coverage edge has no id")
                    .to_owned(),
                edge.clone(),
            )
        })
        .collect();
    (branches, edges)
}

fn expected_invariant(
    scenario: &str,
    surface_observed_key: &str,
) -> (
    &'static str,
    &'static str,
    Vec<&'static str>,
    Vec<&'static str>,
    Vec<&'static str>,
) {
    match scenario {
        "attribution-missing-deny" => (
            "callback-attribution-carrier",
            "scheduled-public-attribution-guard",
            vec!["requested", "commit"],
            vec!["allow", "allow"],
            vec!["ambient-root", "ambient-root"],
        ),
        "generation-recheck" => (
            "callback-attribution-carrier",
            "scheduled-public-environment-revocation-recheck",
            vec!["requested", "commit", "requested"],
            vec!["allow", "allow", "deny"],
            vec!["dynamic-session", "dynamic-session", "missing-authority"],
        ),
        "principal-restore" => (
            "callback-attribution-carrier",
            "scheduled-package-principal-scope",
            vec!["requested", "commit", "requested", "commit"],
            vec!["allow", "allow", "allow", "allow"],
            vec!["static-floor", "static-floor", "ambient-root", "ambient-root"],
        ),
        "snapshot-mismatch-deny" => (
            "callback-attribution-carrier",
            "cross-snapshot-public-handle-reattenuation",
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
        "cannot-widen-authority" => (
            "authority-control-plane",
            "typed-grant-ceiling-refusal",
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
        "post-lockdown-invariant" => (
            "authority-control-plane",
            "lockdown-tamper-and-grant-refusal",
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
        "non-capability" => match surface_observed_key {
            "callback:exact-host-call-async-resolve"
            | "callback:producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_exact_host_call:pushRuntimeCallback"
            | "host-abi:ex_hermes_resolve_exact_host_call" => (
                "callback-attribution-carrier",
                "exact-host-call-round-trip",
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            "host-abi:ex_hermes_set_exact_host_call_async" => (
                "authority-control-plane",
                "exact-endowment-install",
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            "host-abi:ex_host_authorize_exact_endowment" => (
                "authority-control-plane",
                "exact-endowment-authorize",
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            "host-abi:ex_host_build_exact_armed_embedder_artifacts"
            | "host-abi:ex_host_prepare_armed_embedder_artifacts"
            | "host-abi:ex_host_prepare_exact_armed_embedder_artifacts" => (
                "authority-control-plane",
                "exact-artifact-prepare-round-trip",
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            other => panic!("unsupported exact embedder non-capability surface {other}"),
        },
        other => panic!("unsupported callback invariant scenario {other}"),
    }
}

fn callback_recipes(catalog: &RecipeCatalog) -> Vec<&Recipe> {
    catalog
        .recipes
        .iter()
        .filter(|recipe| {
            recipe.status == "fully-executable"
                && recipe.public_surface_probe.as_ref().is_some_and(|probe| {
                    probe.invocation.invocation_schema == CALLBACK_INVOCATION_SCHEMA
                })
        })
        .collect()
}

fn validate_recipe_source_binding(
    recipe: &Recipe,
    branches: &BTreeMap<String, serde_json::Value>,
    edges: &BTreeMap<String, serde_json::Value>,
) {
    let probe = recipe
        .public_surface_probe
        .as_ref()
        .expect("callback invariant recipe has no public probe");
    let invocation = &probe.invocation;
    let descriptor = &invocation.source_descriptor;
    let (rationale, mechanism, stages, outcomes, reasons) =
        expected_invariant(&recipe.scenario, &probe.surface_observed_key);
    assert_eq!(recipe.classification, "non-capability");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(recipe.implementation_branch_ids.len(), 1);
    assert_eq!(recipe.enforcement_branch_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CALLBACK_BATCH_COMMAND));
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert!(recipe
        .route
        .surface_observed_keys
        .contains(&probe.surface_observed_key));
    assert_eq!(invocation.invocation_schema, CALLBACK_INVOCATION_SCHEMA);
    assert_eq!(invocation.kind, "callback-security-invariant");
    assert_eq!(invocation.scenario, recipe.scenario);
    assert_eq!(invocation.expected_result, "invariant-passed");
    assert_eq!(invocation.expected_typed_decision_count, outcomes.len());
    assert_eq!(
        invocation.expected_typed_stages,
        stages
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        invocation.expected_typed_outcomes,
        outcomes
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        invocation.expected_typed_reasons,
        reasons
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    );
    if outcomes.is_empty() {
        assert!(invocation.allowed_coverage_edge_ids.is_empty());
        assert!(invocation.expected_action_ids.is_empty());
    } else {
        assert_eq!(
            invocation.allowed_coverage_edge_ids,
            [ENV_AUXILIARY_EDGE_ID]
        );
        assert_eq!(invocation.expected_action_ids, ["env:read"]);
    }
    assert_eq!(
        tagged_jcs_digest(descriptor),
        invocation.source_descriptor_digest
    );
    assert_eq!(descriptor["kind"], "callback-security-invariant");
    assert_eq!(descriptor["proofScope"], "source-bound-exact-mechanism");
    assert_eq!(descriptor["scenario"], recipe.scenario);
    assert_eq!(descriptor["rationaleId"], rationale);
    assert_eq!(descriptor["executionMechanism"], mechanism);
    assert_eq!(descriptor["surfaceObservedKey"], probe.surface_observed_key);
    assert_eq!(descriptor["edgeId"], recipe.edge_ids[0]);
    assert_eq!(descriptor["branchId"], recipe.implementation_branch_ids[0]);
    let edge = edges
        .get(&recipe.edge_ids[0])
        .expect("callback invariant names unknown coverage edge");
    let branch = branches
        .get(&recipe.implementation_branch_ids[0])
        .expect("callback invariant names unknown implementation branch");
    assert_eq!(&descriptor["coverageEdge"], edge);
    assert_eq!(&descriptor["implementationBranch"], branch);
    assert_eq!(edge["classification"], "non-capability");
    assert_eq!(edge["rationaleId"], rationale);
    assert_eq!(edge["surface"]["kind"], invocation.surface_kind);
    assert_eq!(edge["surface"]["name"], invocation.surface_name);
    assert_eq!(
        probe.surface_observed_key,
        format!("{}:{}", invocation.surface_kind, invocation.surface_name)
    );
    assert_eq!(branch["edgeId"], recipe.edge_ids[0]);
    assert_eq!(branch["branchId"], recipe.implementation_branch_ids[0]);
    assert_eq!(
        branch["enforcementBranchId"],
        recipe.enforcement_branch_ids[0]
    );
    assert_eq!(
        descriptor["liveSurface"]["observedKey"],
        probe.surface_observed_key
    );
    assert_eq!(descriptor["liveSurface"]["kind"], invocation.surface_kind);
    assert_eq!(descriptor["liveSurface"]["name"], invocation.surface_name);
    let descriptor_refs = descriptor["sourceRefs"]
        .as_array()
        .expect("callback invariant descriptor has no source refs");
    assert!(!descriptor_refs.is_empty());
    assert_eq!(descriptor_refs, branch["sourceRefs"].as_array().unwrap());
    assert!(descriptor_refs.iter().any(|source_ref| {
        descriptor["liveSurface"]["sourceRefs"]
            .as_array()
            .unwrap()
            .contains(source_ref)
    }));
    assert_eq!(
        recipe.expected_observation["branchId"],
        recipe.implementation_branch_ids[0]
    );
}

fn invariant_selector() -> serde_json::Value {
    serde_json::json!({
        "cap": "env:read",
        "resource": {
            "kind": "environment-name",
            "target": "principal-overlay",
            "name": "PATH",
        },
    })
}

fn snapshot_selector() -> serde_json::Value {
    serde_json::json!({
        "cap": "fs:read",
        "resource": {
            "kind": "path-exact",
            "path": {
                "root": "project",
                "components": [{"encoding": "utf8", "value": "callback-data.txt"}]
            }
        },
    })
}

fn root_principal_value() -> serde_json::Value {
    serde_json::json!({"kind": "root", "identity": "project-root"})
}

fn generations_value(generations: capsec_semantics::cache::GenerationSet) -> serde_json::Value {
    serde_json::to_value(generations).expect("typed generations must serialize")
}

fn package_components(path: &std::path::Path) -> serde_json::Value {
    serde_json::to_value(
        ibex_runtime::host::host_path_components(path)
            .expect("encode production-equivalent callback package path"),
    )
    .expect("serialize callback package path components")
}

fn object_identity(path: &std::path::Path) -> serde_json::Value {
    serde_json::to_value(
        ibex_runtime::host::object_identity_for_host_path(path)
            .expect("pin production-equivalent callback package root"),
    )
    .expect("serialize callback package object identity")
}

fn prepare_package_fixture() -> PackageFixture {
    let directory = tempfile::tempdir().expect("create callback package fixture");
    let root = std::fs::canonicalize(directory.path()).expect("canonicalize callback fixture root");
    let package_root = root.join("node_modules/image-lib");
    let project_file = root.join("callback-data.txt");
    std::fs::write(&project_file, b"callback invariant\n").expect("write callback project file");
    std::fs::create_dir_all(&package_root).expect("create callback package root");
    std::fs::write(
        package_root.join("package.json"),
        r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
    )
    .expect("write callback package manifest");
    std::fs::write(
        package_root.join("index.js"),
        r#"module.exports = function(sink, observer, env) {
  var sloppyThis = (function() { return this; })();
  var result = {
    context: observer(),
    globals: {
      processType: typeof process,
      ibexType: typeof Ibex,
      functionType: typeof Function,
      evalType: typeof eval,
      sloppyThisProcessType: sloppyThis == null ? 'nullish' : typeof sloppyThis.process
    }
  };
  try {
    result.value = typeof env.PATH === 'string';
  }
  catch (error) { result.threw = String(error && error.message || error); }
  sink(result);
};
"#,
    )
    .expect("write callback package source");
    let integrity = crate::module_loader::package_tree_integrity(&package_root)
        .expect("digest callback package tree");
    let principal_value = serde_json::json!({
        "kind": "package",
        "name": "image-lib",
        "integrity": integrity,
        "locator": "image-lib@2.4.1",
    });
    let principal = serde_json::from_value(principal_value.clone())
        .expect("callback package principal must be valid");
    PackageFixture {
        _directory: directory,
        root,
        package_root,
        principal_value,
        principal,
    }
}

fn artifact_content_digest(bytes: &[u8]) -> capsec_semantics::model::Digest {
    capsec_semantics::model::Digest::new(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(<sha2::Sha256 as sha2::Digest>::digest(bytes))
    ))
    .expect("artifact content digest must be valid")
}

fn artifact_host_path(path: &std::path::Path) -> capsec_semantics::model::LogicalPath {
    use capsec_semantics::model::{LogicalPath, LogicalRoot, PathComponent};
    use std::path::Component;

    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Prefix(prefix) => Some(prefix.as_os_str()),
            Component::Normal(value) => Some(value),
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir => panic!("canonical artifact path contains parent traversal"),
        })
        .map(|component| {
            PathComponent::utf8(
                component
                    .to_str()
                    .expect("artifact path components must be UTF-8"),
            )
            .expect("artifact path component must be canonical")
        })
        .collect();
    LogicalPath {
        root: LogicalRoot::Absolute,
        components,
        host_bound: Some(true),
    }
}

fn artifact_object_identity(path: &std::path::Path) -> capsec_semantics::model::ObjectIdentity {
    use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000 | 0x0200_0000);
    }
    let file = options.open(path).expect("open embedder artifact identity");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata().expect("inspect embedder artifact identity");
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
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
        assert_ne!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) },
            0,
            "identify embedder artifact on Windows"
        );
        let file_index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
        ObjectIdentity {
            platform: ObjectPlatform::Windows,
            volume: NonEmptyString::new(format!("volume:{}", info.dwVolumeSerialNumber)).unwrap(),
            file: NonEmptyString::new(format!("file:{file_index}")).unwrap(),
        }
    }
}

fn materialize_embedder_artifact(
    directory: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> (
    capsec_semantics::model::LogicalPath,
    capsec_semantics::model::ObjectIdentity,
    capsec_semantics::model::Digest,
) {
    let path = directory.join(name);
    std::fs::write(&path, bytes).expect("write embedder artifact");
    let mut permissions = std::fs::metadata(&path)
        .expect("inspect embedder artifact")
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o400);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions).expect("protect embedder artifact");
    let path = std::fs::canonicalize(path).expect("canonicalize embedder artifact");
    (
        artifact_host_path(&path),
        artifact_object_identity(&path),
        artifact_content_digest(bytes),
    )
}

fn embedder_runtime_target_triple() -> String {
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

fn prepare_embedder_artifact_fixture() -> EmbedderArtifactFixture {
    use capsec_semantics::arming::{ExpectedArmingIdentity, ExpectedProtectedArtifact};
    use capsec_semantics::digest::{compute_checked_contract_digest, DigestKind};
    use capsec_semantics::model::Digest;

    let directory = tempfile::tempdir().expect("create embedder artifact fixture");
    let project_root = directory.path().join("project");
    let artifacts = directory.path().join("artifacts");
    std::fs::create_dir(&project_root).expect("create embedder project root");
    std::fs::create_dir(&artifacts).expect("create embedder artifacts root");
    let project_root =
        std::fs::canonicalize(project_root).expect("canonicalize embedder project root");

    let engine = HermesEngine::loaded_engine_identity()
        .expect("load exact engine identity for embedder artifact fixture");
    let mut snapshot: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))
    .expect("checked armed snapshot fixture must be JSON");
    snapshot["workflow"] = serde_json::json!("production");
    snapshot["effectiveMode"] = serde_json::json!("enforce");
    snapshot["environmentBase"] = serde_json::json!([]);
    snapshot["engine"] = serde_json::json!({
        "target": embedder_runtime_target_triple(),
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
        .expect("digest embedder package graph"));
    snapshot["rootBindings"] = serde_json::json!([{
        "logicalRoot": "project",
        "hostPath": artifact_host_path(&project_root),
        "object": artifact_object_identity(&project_root),
    }]);
    let project_path = artifact_host_path(&project_root);
    snapshot["projectRootDiscovery"] = serde_json::json!({
        "origin": project_path,
        "selectedRoot": artifact_host_path(&project_root),
        "markerKind": "explicit-project",
        "markerPath": artifact_host_path(&project_root),
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
        .expect("derive embedder fixture path canonicalizers"),
    )
    .expect("serialize embedder fixture path canonicalizers");

    let policy_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/canonical-policy.canonical.json"
    ));
    let (policy_path, policy_object, policy_content) =
        materialize_embedder_artifact(&artifacts, "armed-policy.json", policy_bytes);
    let graph_bytes = capsec_semantics::canonical::to_jcs_bytes(&snapshot["packageGraph"])
        .expect("canonicalize embedder package graph");
    let (graph_path, graph_object, graph_content) =
        materialize_embedder_artifact(&artifacts, "package-graph.json", &graph_bytes);
    let registry_bytes = b"authenticated checked registry";
    let (registry_path, registry_object, registry_content) =
        materialize_embedder_artifact(&artifacts, "registry.json", registry_bytes);
    for (role, object) in [
        ("armed-policy", &policy_object),
        ("engine-binary", &engine.object),
        ("package-graph", &graph_object),
        ("registry", &registry_object),
    ] {
        snapshot["protectedObjects"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["role"] == role)
            .expect("checked snapshot lacks protected role")["object"] =
            serde_json::to_value(object).unwrap();
    }

    let source_nonce = snapshot["runNonce"].as_str().unwrap().to_owned();
    let source_digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &snapshot)
        .expect("digest embedder snapshot template");
    snapshot["armedSnapshotDigest"] = serde_json::json!(source_digest);
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
        project_root_discovery: serde_json::from_value(snapshot["projectRootDiscovery"].clone())
            .unwrap(),
        path_canonicalizers: serde_json::from_value(snapshot["pathCanonicalizers"].clone())
            .unwrap(),
        protected_artifacts: vec![
            ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::ArmedPolicy,
                host_path: policy_path,
                object: policy_object,
                content_digest: policy_content,
            },
            ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::EngineBinary,
                host_path: artifact_host_path(&engine.engine_artifact_path),
                object: engine.object,
                content_digest: digest_at(&["engine", "binaryDigest"]),
            },
            ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::PackageGraph,
                host_path: graph_path,
                object: graph_object,
                content_digest: graph_content,
            },
            ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::Registry,
                host_path: registry_path,
                object: registry_object,
                content_digest: registry_content,
            },
        ],
        embedded_protected_artifacts: Vec::new(),
        runtime_extension_authority_digest: None,
        runtime_extension_mapped_executable: None,
    };
    EmbedderArtifactFixture {
        _directory: directory,
        snapshot: serde_json::to_vec(&snapshot).unwrap(),
        expected_identity: serde_json::to_vec(&expected).unwrap(),
        source_nonce,
        source_digest,
    }
}

fn build_callback_host(
    package: Option<&PackageFixture>,
    package_floor: Option<&str>,
    package_ceiling: bool,
    run_nonce: Option<&str>,
) -> (crate::host::Host, String) {
    build_armed_test_host_control(
        package.map(|fixture| fixture.root.as_path()),
        false,
        false,
        false,
        Vec::new(),
        Vec::new(),
        false,
        0,
        None,
        |snapshot| {
            if let Some(run_nonce) = run_nonce {
                snapshot["runNonce"] = serde_json::Value::String(run_nonce.to_owned());
            }
            let Some(package) = package else {
                return;
            };
            snapshot["rootBindings"][0]["owner"] = package.principal_value.clone();
            snapshot["rootBindings"][0]["hostPath"] = serde_json::json!({
                "root": "absolute",
                "components": package_components(&package.package_root),
                "hostBound": true,
            });
            snapshot["rootBindings"][0]["object"] = object_identity(&package.package_root);
            snapshot["principals"][1]["principal"] = package.principal_value.clone();
            snapshot["principals"][1]["floor"] = match package_floor {
                Some("environment") => serde_json::json!([invariant_selector()]),
                Some("filesystem") => serde_json::json!([snapshot_selector()]),
                None => serde_json::json!([]),
                Some(other) => panic!("unknown callback package floor {other}"),
            };
            snapshot["principals"][1]["escalationCeiling"] = if package_ceiling {
                serde_json::json!([invariant_selector()])
            } else {
                serde_json::json!([])
            };
            snapshot["principals"][1]["imports"]["builtins"] = serde_json::json!([]);
            snapshot["packageGraph"]["nodes"][0]["principal"] = package.principal_value.clone();
            snapshot["packageGraph"]["importEdges"][0]["imported"] =
                package.principal_value.clone();
        },
    )
}

struct ObservedInvocation {
    result: serde_json::Value,
    typed_decisions: Vec<serde_json::Value>,
}

fn begin_observation(session_id: &str) {
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(session_id),
        "install callback conformance observation {session_id}"
    );
}

fn finish_observation(session_id: &str) -> Vec<serde_json::Value> {
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(
        legacy.is_empty(),
        "rev2 public path consulted the legacy plane"
    );
    typed
        .into_iter()
        .map(|observation| {
            let mut decision = serde_json::to_value(observation)
                .expect("typed callback observation must serialize");
            assert_eq!(decision["terminalBranchId"], session_id);
            decision
                .as_object_mut()
                .expect("typed callback observation must be an object")
                .remove("terminalBranchId");
            decision
        })
        .collect()
}

fn assert_context_principal(
    result: &serde_json::Value,
    host: &crate::host::Host,
    expected_principal: &capsec_semantics::model::Principal,
) {
    let principal_id = result["context"]["principalId"]
        .as_str()
        .expect("context observer returned no principal id")
        .strip_prefix("u64:")
        .expect("context observer principal id is not tagged");
    assert_eq!(
        host.typed_principal_for_module(principal_id).as_ref(),
        Some(expected_principal),
        "public operation did not run under the observed Hermes principal"
    );
    assert!(result["context"]["runtimeNonce"]
        .as_str()
        .is_some_and(|value| value
            .strip_prefix("u64:")
            .is_some_and(|raw| raw.parse::<u64>().is_ok())));
}

fn callback_module_id(result: &serde_json::Value) -> u64 {
    result["context"]["principalId"]
        .as_str()
        .expect("callback context has no principal id")
        .strip_prefix("u64:")
        .expect("callback context principal id is not tagged")
        .parse()
        .expect("callback context principal id is not numeric")
}

/// Exercise the same principal-authenticating Host boundary captured by the
/// sealed `Ibex.permissions` bootstrap facade. The facade itself is
/// deliberately absent after arming, so the conformance harness carries the
/// one-shot callback observation into the native boundary instead of making a
/// bare-eval exception or restoring a session-wide authority surface.
/// @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence —
/// typed grant mutation authenticates the executing principal at the Host ABI.
fn request_typed_dynamic_for_callback(
    result: &serde_json::Value,
    request: &serde_json::Value,
) -> std::result::Result<bool, String> {
    let request = capsec_semantics::canonical::to_jcs_bytes(request)
        .map_err(|error| format!("cannot encode typed permission request: {error}"))?;
    let outcome = unsafe {
        crate::host::abi::ex_host_typed_dynamic_grant(
            callback_module_id(result),
            request.as_ptr(),
            request.len(),
        )
    };
    match outcome {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("Typed permission request refused".into()),
    }
}

/// Re-attenuate through the production Host ABI using the principal observed
/// inside the scheduled callback. Root callback scenarios have a one-principal
/// constrained stack; the ABI still resolves that opaque engine id through the
/// installed armed Host before it accepts the request.
/// @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence —
/// bearer minting is actor- and constrained-stack-authenticated.
fn mint_typed_handle_for_callback(
    result: &serde_json::Value,
    request: &serde_json::Value,
) -> std::result::Result<String, String> {
    let module_id = callback_module_id(result);
    let module_ids = [module_id];
    let request = capsec_semantics::canonical::to_jcs_bytes(request)
        .map_err(|error| format!("cannot encode typed handle request: {error}"))?;
    let output = unsafe {
        crate::host::abi::ex_host_typed_handle_mint(
            module_id,
            module_ids.as_ptr(),
            module_ids.len(),
            request.as_ptr(),
            request.len(),
        )
    };
    if output.is_null() {
        return Err("typed handle host is unavailable".into());
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
        .to_bytes()
        .to_vec();
    crate::host::abi::ex_host_free_string(output);
    let envelope: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("typed handle response is not JSON: {error}"))?;
    if let Some(error) = envelope["error"].as_str() {
        return Err(error.to_owned());
    }
    envelope["handleId"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "Typed handle mint returned no handleId".into())
}

fn assert_package_global_withholding(result: &serde_json::Value) {
    assert_eq!(
        result["globals"],
        serde_json::json!({
            "processType": "undefined",
            "ibexType": "undefined",
            "functionType": "undefined",
            "evalType": "undefined",
            "sloppyThisProcessType": "undefined",
        }),
        "package callback escaped its armed compartment globals: {result}"
    );
}

fn typed_actor_reason(decision: &serde_json::Value) -> Option<&str> {
    let actor = &decision["decisionSet"]["context"]["actor"];
    decision["evidence"]["evidence"]
        .as_array()?
        .iter()
        .find(|entry| entry["principal"] == *actor)?["reason"]
        .as_str()
}

fn assert_typed_decisions(
    decisions: &[serde_json::Value],
    expected_principal: &capsec_semantics::model::Principal,
    expected_stages: &[&str],
    expected_outcomes: &[&str],
    expected_reasons: &[&str],
    expected_edge_id: &str,
    expected_action: &str,
) {
    assert_eq!(
        decisions.len(),
        expected_stages.len(),
        "unexpected typed decision count: {decisions:#?}"
    );
    assert_eq!(decisions.len(), expected_outcomes.len());
    assert_eq!(decisions.len(), expected_reasons.len());
    let expected_principal =
        serde_json::to_value(expected_principal).expect("expected principal must serialize");
    for (index, decision) in decisions.iter().enumerate() {
        assert_eq!(
            decision["decisionSet"]["context"]["actor"], expected_principal,
            "public decision actor drifted: {decision}"
        );
        assert_eq!(
            decision["decisionSet"]["context"]["stage"],
            expected_stages[index]
        );
        assert_eq!(
            decision["decisionSet"]["effects"][0]["cap"],
            expected_action
        );
        assert_eq!(decision["gates"][0]["coverageEdgeId"], expected_edge_id);
        assert_eq!(decision["gates"][0]["targetCell"], "complete");
        assert_eq!(
            decision["gates"][0]["definitionAndEdgePredicatesSatisfied"],
            true
        );
        assert_eq!(
            decision["evidence"]["outcome"], expected_outcomes[index],
            "unexpected callback invariant decision: {decision}"
        );
        assert_eq!(
            typed_actor_reason(decision),
            Some(expected_reasons[index]),
            "callback decision has no actor-bound reason: {decision}"
        );
    }
}

async fn read_callback_result(engine: &AuthenticatedCallbackEngine) -> serde_json::Value {
    let encoded = engine
        .eval_immediate("JSON.stringify(globalThis.__capsecCallbackResult)")
        .await
        .expect("read callback public-operation result")
        .expect("callback public operation returned no result");
    serde_json::from_str(&encoded).expect("callback public-operation result must be JSON")
}

async fn prewarm_package_public_operation(engine: &AuthenticatedCallbackEngine) {
    engine
        .eval_immediate("require('image-lib'); 'ready'")
        .await
        .expect("load callback package before observation");
}

async fn invoke_package_environment_read(
    engine: &AuthenticatedCallbackEngine,
    session_id: &str,
) -> ObservedInvocation {
    prewarm_package_public_operation(engine).await;
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install immediate package context observer");
    let invocation = format!(
        r#"globalThis.__capsecCallbackResult = null;
var observer = globalThis[{0}];
var removed = delete globalThis[{0}];
if (typeof observer !== 'function' || !removed || ({0} in globalThis)) throw new Error('CapSec context observer was project-reachable');
require('image-lib')(function(result) {{ globalThis.__capsecCallbackResult = result; }}, observer, process.env);"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    begin_observation(session_id);
    engine
        .eval_immediate(&invocation)
        .await
        .expect("invoke package public environment read");
    let typed_decisions = finish_observation(session_id);
    let result = read_callback_result(engine).await;
    ObservedInvocation {
        result,
        typed_decisions,
    }
}

async fn schedule_package_environment_read(engine: &AuthenticatedCallbackEngine) {
    prewarm_package_public_operation(engine).await;
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install scheduled package context observer");
    let invocation = format!(
        r#"globalThis.__capsecCallbackResult = null;
var observer = globalThis[{0}];
var removed = delete globalThis[{0}];
if (typeof observer !== 'function' || !removed || ({0} in globalThis)) throw new Error('CapSec context observer was project-reachable');
setTimeout(require('image-lib'), 0, function(result) {{ globalThis.__capsecCallbackResult = result; }}, observer, process.env);"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    engine
        .eval_immediate(&invocation)
        .await
        .expect("schedule package public environment read");
}

async fn take_scheduled_package_operation(
    engine: &AuthenticatedCallbackEngine,
    session_id: &str,
) -> ObservedInvocation {
    begin_observation(session_id);
    engine
        .drive_event_loop()
        .await
        .expect("drive package public operation");
    let typed_decisions = finish_observation(session_id);
    let result = read_callback_result(engine).await;
    ObservedInvocation {
        result,
        typed_decisions,
    }
}

async fn invoke_root_environment_read(
    engine: &AuthenticatedCallbackEngine,
    session_id: &str,
) -> ObservedInvocation {
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install root context observer");
    let script = format!(
        r#"JSON.stringify((function(name) {{
  var observer = globalThis[name];
  var removed = delete globalThis[name];
  if (typeof observer !== 'function' || !removed || (name in globalThis)) throw new Error('CapSec context observer was project-reachable');
  var result = {{context: observer()}};
  try {{ result.value = typeof process.env.PATH === 'string'; }}
  catch (error) {{ result.threw = String(error && error.message || error); }}
  return result;
}})({0}))"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    begin_observation(session_id);
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("invoke root public environment read")
        .expect("root public environment read returned no result");
    let typed_decisions = finish_observation(session_id);
    let result =
        serde_json::from_str(&encoded).expect("root public environment result must be JSON");
    ObservedInvocation {
        result,
        typed_decisions,
    }
}

async fn observe_root_authority_seal(engine: &AuthenticatedCallbackEngine) -> serde_json::Value {
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install root authority-seal context observer");
    let script = format!(
        r#"JSON.stringify((function(name) {{
  var observer = globalThis[name];
  var removed = delete globalThis[name];
  if (typeof observer !== 'function' || !removed || (name in globalThis)) throw new Error('CapSec context observer was project-reachable');
  return {{
    context: observer(),
    facadeWithheld: typeof Ibex === 'object' && typeof Ibex.permissions === 'undefined' && typeof Ibex.authority === 'undefined'
  }};
}})({0}))"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("observe armed root authority seal")
        .expect("root authority-seal observer returned no result");
    serde_json::from_str(&encoded).expect("root authority-seal observation must be JSON")
}

async fn invoke_attribution_guard_callback(
    engine: &AuthenticatedCallbackEngine,
    session_id: &str,
    request: &serde_json::Value,
) -> ObservedInvocation {
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install attribution context observer");
    let script = format!(
        r#"globalThis.__capsecCallbackResult = null;
var observer = globalThis[{0}];
var removed = delete globalThis[{0}];
if (typeof observer !== 'function' || !removed || ({0} in globalThis)) throw new Error('CapSec context observer was project-reachable');
setTimeout(function(observer) {{
  var result = {{context: observer()}};
  try {{ result.value = typeof process.env.PATH === 'string'; }}
  catch (error) {{ result.threw = String(error && error.message || error); }}
  globalThis.__capsecCallbackResult = result;
}}, 0, observer);"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    engine
        .eval_immediate(&script)
        .await
        .expect("schedule public attribution-guard callback");
    begin_observation(session_id);
    engine
        .drive_event_loop()
        .await
        .expect("drive public attribution-guard callback");
    let typed_decisions = finish_observation(session_id);
    let mut result = read_callback_result(engine).await;
    match request_typed_dynamic_for_callback(&result, request) {
        Ok(granted) => {
            result["requestRefused"] = serde_json::Value::Bool(!granted);
            result["errorMessage"] = serde_json::Value::Null;
        }
        Err(error) => {
            result["requestRefused"] = serde_json::Value::Bool(true);
            result["errorMessage"] = serde_json::Value::String(error);
        }
    }
    ObservedInvocation {
        result,
        typed_decisions,
    }
}

async fn invoke_root_handle_mint_callback(
    engine: &AuthenticatedCallbackEngine,
    session_id: &str,
    request: &serde_json::Value,
) -> ObservedInvocation {
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install handle callback context observer");
    let script = format!(
        r#"globalThis.__capsecCallbackResult = null;
var observer = globalThis[{0}];
var removed = delete globalThis[{0}];
if (typeof observer !== 'function' || !removed || ({0} in globalThis)) throw new Error('CapSec context observer was project-reachable');
setTimeout(function(observer) {{
  globalThis.__capsecCallbackResult = {{context: observer()}};
}}, 0, observer);"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    engine
        .eval_immediate(&script)
        .await
        .expect("schedule public handle-mint callback");
    begin_observation(session_id);
    engine
        .drive_event_loop()
        .await
        .expect("drive public handle-mint callback");
    let typed_decisions = finish_observation(session_id);
    let mut result = read_callback_result(engine).await;
    match mint_typed_handle_for_callback(&result, request) {
        Ok(handle_id) => {
            result["value"] = serde_json::Value::String(handle_id);
            result["threw"] = serde_json::Value::Null;
        }
        Err(error) => {
            result["value"] = serde_json::Value::Null;
            result["threw"] = serde_json::Value::String(error);
        }
    }
    ObservedInvocation {
        result,
        typed_decisions,
    }
}

fn install_armed_host(host: &crate::host::Host) -> HostResetGuard {
    assert_ne!(
        crate::host::abi::install_host(host.clone()),
        0,
        "callback invariant Host context token allocation"
    );
    HostResetGuard
}

async fn armed_engine_before_submission(
    host: &crate::host::Host,
    digest: &str,
) -> AuthenticatedCallbackEngine {
    let digest_c = std::ffi::CString::new(digest).unwrap();
    assert_eq!(
        unsafe { crate::host::abi::ex_host_matches_armed_snapshot_digest(digest_c.as_ptr()) },
        1,
        "installed callback-invariant Host must authenticate the selected snapshot"
    );
    let engine = HermesEngine::new_with_armed_snapshot(Some(digest))
        .expect("create exact callback invariant engine");
    if let Err(error) = engine.load_runtime().await {
        crate::host::abi::ex_host_console_flush(1_000);
        panic!("load exact callback invariant runtime: {error:#}");
    }
    let engine = AuthenticatedCallbackEngine {
        host: host.clone(),
        engine,
        publications: std::sync::Mutex::new(AuthenticatedPublicationTracker::default()),
    };
    engine
}

async fn armed_engine(host: &crate::host::Host, digest: &str) -> AuthenticatedCallbackEngine {
    let engine = armed_engine_before_submission(host, digest).await;
    assert_eq!(
        engine
            .eval_immediate("typeof __hostCall + '/' + typeof __hostCallAsync")
            .await
            .expect("inspect generic host bridges")
            .as_deref(),
        Some("undefined/undefined"),
        "armed callback evidence must not reopen the generic host bridge"
    );
    engine
}

async fn execute_attribution_missing(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_callback_host(None, None, false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&host, &digest).await;
    let before = host.typed_generations().unwrap();
    let session = format!("callback-attribution:{}", recipe.plan_digest);
    let request = serde_json::json!({
        "grantId": format!("missing-attribution-{}", recipe.plan_digest.trim_start_matches("sha256-")),
        "principal": {"kind": "root", "identity": "forged-callback-root"},
        "authority": invariant_selector(),
    });
    let invocation = invoke_attribution_guard_callback(&engine, &session, &request).await;
    let root: capsec_semantics::model::Principal =
        serde_json::from_value(root_principal_value()).unwrap();
    assert_context_principal(&invocation.result, &host, &root);
    assert_eq!(invocation.result["requestRefused"], true);
    assert!(
        invocation.result["errorMessage"]
            .as_str()
            .is_some_and(|message| message.contains("refused")),
        "unexpected attribution-refusal result: {}",
        invocation.result
    );
    assert!(invocation.result["threw"].is_null());
    assert_typed_decisions(
        &invocation.typed_decisions,
        &root,
        &["requested", "commit"],
        &["allow", "allow"],
        &["ambient-root", "ambient-root"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    assert_eq!(host.typed_generations().unwrap(), before);
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "callbackExecuted": true,
                "actualPrincipal": root_principal_value(),
                "invalidAttributionDenied": true,
                "runtimeNonce": invocation.result["context"]["runtimeNonce"],
            },
        }),
        typed_decisions: invocation.typed_decisions,
        legacy_observation_count: 0,
    }
}

async fn execute_generation_recheck(
    recipe: &Recipe,
    package: &PackageFixture,
) -> ScenarioExecution {
    use capsec_semantics::model::{AuthoritySelector, NonEmptyString};

    let (host, digest) = build_callback_host(Some(package), None, true, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&host, &digest).await;
    let selector: AuthoritySelector = serde_json::from_value(invariant_selector()).unwrap();
    let grant_id = NonEmptyString::new(format!(
        "callback-generation-{}",
        recipe.plan_digest.trim_start_matches("sha256-")
    ))
    .unwrap();
    assert!(host
        .grant_typed_dynamic(grant_id.clone(), package.principal.clone(), selector)
        .expect("publish callback dynamic environment grant"));
    let granted_generations = host.typed_generations().unwrap();
    let allow_session = format!("callback-generation-allow:{}", recipe.plan_digest);
    let allow = invoke_package_environment_read(&engine, &allow_session).await;
    assert_context_principal(&allow.result, &host, &package.principal);
    assert_package_global_withholding(&allow.result);
    assert!(
        allow.result["threw"].is_null(),
        "authorized package environment read threw: {}",
        allow.result
    );
    assert_typed_decisions(
        &allow.typed_decisions,
        &package.principal,
        &["requested", "commit"],
        &["allow", "allow"],
        &["dynamic-session", "dynamic-session"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    let deny_session = format!("callback-generation-deny:{}", recipe.plan_digest);
    schedule_package_environment_read(&engine).await;
    assert!(host
        .revoke_typed_dynamic(&grant_id)
        .expect("revoke callback dynamic environment grant"));
    let revoked_generations = host.typed_generations().unwrap();
    assert!(revoked_generations.negative > granted_generations.negative);
    assert!(revoked_generations.dynamic > granted_generations.dynamic);
    assert_eq!(revoked_generations.handle, granted_generations.handle);
    let deny = take_scheduled_package_operation(&engine, &deny_session).await;
    assert_context_principal(&deny.result, &host, &package.principal);
    assert!(deny.result["threw"].is_null());
    assert_typed_decisions(
        &deny.typed_decisions,
        &package.principal,
        &["requested"],
        &["deny"],
        &["missing-authority"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    for decision in &allow.typed_decisions {
        assert_eq!(
            decision["evidence"]["generations"],
            generations_value(granted_generations)
        );
    }
    assert_eq!(
        deny.typed_decisions[0]["evidence"]["generations"],
        generations_value(revoked_generations)
    );
    assert_eq!(
        allow.result["context"]["runtimeNonce"],
        deny.result["context"]["runtimeNonce"]
    );
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "callbackExecuted": true,
                "actualPrincipal": package.principal_value,
                "generationsBefore": generations_value(granted_generations),
                "generationsAfter": generations_value(revoked_generations),
                "generationAdvanced": true,
                "scheduledDecisionRechecked": true,
                "runtimeNonce": deny.result["context"]["runtimeNonce"],
            },
        }),
        typed_decisions: allow
            .typed_decisions
            .into_iter()
            .chain(deny.typed_decisions)
            .collect(),
        legacy_observation_count: 0,
    }
}

async fn execute_principal_restore(recipe: &Recipe, package: &PackageFixture) -> ScenarioExecution {
    let (host, digest) = build_callback_host(Some(package), Some("environment"), false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&host, &digest).await;
    let package_session = format!("callback-package-principal:{}", recipe.plan_digest);
    schedule_package_environment_read(&engine).await;
    let package_invocation = take_scheduled_package_operation(&engine, &package_session).await;
    assert_context_principal(&package_invocation.result, &host, &package.principal);
    assert_package_global_withholding(&package_invocation.result);
    assert!(package_invocation.result["threw"].is_null());
    assert_typed_decisions(
        &package_invocation.typed_decisions,
        &package.principal,
        &["requested", "commit"],
        &["allow", "allow"],
        &["static-floor", "static-floor"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    let root_value = root_principal_value();
    let root: capsec_semantics::model::Principal =
        serde_json::from_value(root_value.clone()).unwrap();
    let root_session = format!("callback-restored-root:{}", recipe.plan_digest);
    let root_invocation = invoke_root_environment_read(&engine, &root_session).await;
    assert_context_principal(&root_invocation.result, &host, &root);
    assert!(root_invocation.result["threw"].is_null());
    assert_typed_decisions(
        &root_invocation.typed_decisions,
        &root,
        &["requested", "commit"],
        &["allow", "allow"],
        &["ambient-root", "ambient-root"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    assert_ne!(
        package_invocation.result["context"]["principalId"],
        root_invocation.result["context"]["principalId"]
    );
    assert_eq!(
        package_invocation.result["context"]["runtimeNonce"],
        root_invocation.result["context"]["runtimeNonce"]
    );
    let mut typed_decisions = package_invocation.typed_decisions;
    typed_decisions.extend(root_invocation.typed_decisions);
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "callbackExecuted": true,
                "callbackPrincipal": package.principal_value,
                "restoredPrincipal": root_value,
                "principalRestored": true,
                "runtimeNonce": root_invocation.result["context"]["runtimeNonce"],
            },
        }),
        typed_decisions,
        legacy_observation_count: 0,
    }
}

async fn execute_snapshot_mismatch(recipe: &Recipe, package: &PackageFixture) -> ScenarioExecution {
    use capsec_semantics::model::AuthoritySelector;

    let (source_host, source_digest) = build_callback_host(
        Some(package),
        Some("filesystem"),
        false,
        Some("AQIDBAUGBwgJCgsMDQ4PEA"),
    );
    let selector: AuthoritySelector = serde_json::from_value(snapshot_selector()).unwrap();
    let root: capsec_semantics::model::Principal =
        serde_json::from_value(root_principal_value()).unwrap();
    let handle_id = source_host
        .mint_typed_handle(
            package.principal.clone(),
            std::slice::from_ref(&package.principal),
            root.clone(),
            selector,
            None,
            None,
        )
        .expect("mint source-snapshot bearer");
    let request = serde_json::json!({
        "actor": root_principal_value(),
        "holder": root_principal_value(),
        "authority": snapshot_selector(),
        "parentHandleId": handle_id.as_str(),
        "operationId": format!("snapshot-recheck-{}", recipe.plan_digest.trim_start_matches("sha256-")),
    });
    let source_invocation = {
        let _reset = install_armed_host(&source_host);
        let engine = armed_engine(&source_host, &source_digest).await;
        let session = format!("callback-source-snapshot:{}", recipe.plan_digest);
        let invocation = invoke_root_handle_mint_callback(&engine, &session, &request).await;
        assert_context_principal(&invocation.result, &source_host, &root);
        assert!(invocation.result["threw"].is_null());
        assert!(invocation.result["value"]
            .as_str()
            .is_some_and(|value| !value.is_empty() && value != handle_id.as_str()));
        assert!(invocation.typed_decisions.is_empty());
        invocation
    };
    let (target_host, target_digest) = build_callback_host(
        Some(package),
        Some("filesystem"),
        false,
        Some("AQIDBAUGBwgJCgsMDQ4PEQ"),
    );
    assert_ne!(source_digest, target_digest);
    let target_invocation = {
        let _reset = install_armed_host(&target_host);
        let engine = armed_engine(&target_host, &target_digest).await;
        let session = format!("callback-target-snapshot:{}", recipe.plan_digest);
        let invocation = invoke_root_handle_mint_callback(&engine, &session, &request).await;
        assert_context_principal(&invocation.result, &target_host, &root);
        assert!(invocation.result["threw"]
            .as_str()
            .is_some_and(|message| message.contains("parent handle is absent or revoked")));
        assert!(invocation.typed_decisions.is_empty());
        invocation
    };
    assert_ne!(
        source_invocation.result["context"]["runtimeNonce"],
        target_invocation.result["context"]["runtimeNonce"]
    );
    assert!(source_invocation.typed_decisions.is_empty());
    assert!(target_invocation.typed_decisions.is_empty());
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "callbackExecuted": true,
                "actualPrincipal": root_principal_value(),
                "sourceSnapshotDigest": source_digest,
                "targetSnapshotDigest": target_digest,
                "snapshotDigestsDiffer": true,
                "foreignBearerDenied": true,
                "sourceRuntimeNonce": source_invocation.result["context"]["runtimeNonce"],
                "targetRuntimeNonce": target_invocation.result["context"]["runtimeNonce"],
            },
        }),
        typed_decisions: Vec::new(),
        legacy_observation_count: 0,
    }
}

async fn execute_cannot_widen(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_callback_host(None, None, false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&host, &digest).await;
    let before = host.typed_generations().unwrap();
    let request = serde_json::json!({
        "grantId": format!("cannot-widen-{}", recipe.plan_digest.trim_start_matches("sha256-")),
        "principal": root_principal_value(),
        "authority": invariant_selector(),
    });
    let session = format!("callback-cannot-widen:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session));
    let mut boundary = observe_root_authority_seal(&engine).await;
    match request_typed_dynamic_for_callback(&boundary, &request) {
        Ok(granted) => {
            boundary["requestRefused"] = serde_json::Value::Bool(!granted);
            boundary["errorMessage"] = serde_json::Value::Null;
        }
        Err(error) => {
            boundary["requestRefused"] = serde_json::Value::Bool(true);
            boundary["errorMessage"] = serde_json::Value::String(error);
        }
    }
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());
    assert_eq!(boundary["facadeWithheld"], true);
    assert_eq!(boundary["requestRefused"], true);
    assert!(boundary["errorMessage"]
        .as_str()
        .is_some_and(|message| message.contains("refused")));
    let after = host.typed_generations().unwrap();
    assert_eq!(after, before);
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "bridgeExecuted": true,
                "requestRefused": true,
                "generationsBefore": generations_value(before),
                "generationsAfter": generations_value(after),
                "generationsUnchanged": true,
            },
        }),
        typed_decisions: Vec::new(),
        legacy_observation_count: 0,
    }
}

async fn execute_post_lockdown(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_callback_host(None, None, false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&host, &digest).await;
    let before = host.typed_generations().unwrap();
    let request = serde_json::json!({
        "grantId": format!("post-lockdown-{}", recipe.plan_digest.trim_start_matches("sha256-")),
        "principal": root_principal_value(),
        "authority": invariant_selector(),
    });
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install post-lockdown context observer");
    let script = format!(
        r#"JSON.stringify((function(name) {{
  var observer = globalThis[name];
  var removed = delete globalThis[name];
  if (typeof observer !== 'function' || !removed || (name in globalThis)) throw new Error('CapSec context observer was project-reachable');
  var descriptor = Object.getOwnPropertyDescriptor(globalThis, '__ibexLockedDown');
  var hatches = ['__exactSetActiveModuleId','__exactGrantCapability','__exactSetPendingPackageId','__exactRegisterPackage','__exactCheckImport','__exactSetCompartmentFor','__exactDeepFreeze','__exactNativeFreeze','__exactCaptureHotRevisionRecordInvalidator'];
  var hatchesAbsent = hatches.every(function(name) {{ return !(name in globalThis); }});
  var compartment = globalThis.__compartments['image-lib@2.4.1'];
  var compartmentWithholdsAuthority = compartment.Ibex === undefined && compartment.__exactTypedPermissionRequest === undefined;
  var rootWithholdsAuthority = typeof Ibex === 'object' && typeof Ibex.permissions === 'undefined' && typeof Ibex.authority === 'undefined';
  var prototypeMutationBlocked = false;
  try {{ Object.defineProperty(Object.prototype, '__capsecLockdownMutation', {{value: true}}); }} catch (_) {{}}
  prototypeMutationBlocked = Object.prototype.__capsecLockdownMutation !== true;
  // The ingress scanner closes direct global evaluator spellings. Retain this
  // runtime lockdown assertion through a dataflow alias, which structural
  // taming must contain independently of the syntax gate.
  var realm = globalThis;
  var functionTamed = realm['Function'].__ibexTamed === true;
  var evalTamed = realm['eval'].__ibexTamed === true;
  return {{
    context: observer(),
    structuralLockdown: globalThis.__ibexLockedDown === true && descriptor && descriptor.writable === false && descriptor.configurable === false,
    intrinsicsFrozen: Object.isFrozen(Object.prototype) && Object.isFrozen(realm['Function'].prototype),
    evaluatorsTamed: functionTamed && evalTamed,
    hatchesAbsent: hatchesAbsent,
    compartmentWithholdsAuthority: compartmentWithholdsAuthority,
    rootWithholdsAuthority: rootWithholdsAuthority,
    prototypeMutationBlocked: prototypeMutationBlocked,
    authorityRequestRefused: false
  }};
}})({0}))"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    let session = format!("callback-post-lockdown:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session));
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("execute post-lockdown invariant")
        .expect("post-lockdown invariant returned no result");
    let mut checks: serde_json::Value =
        serde_json::from_str(&encoded).expect("post-lockdown result must be JSON");
    let eval_refusal = engine
        .eval_immediate("(0, eval)('1')")
        .await
        .expect_err("persistent authenticated source must reject eval syntax");
    assert!(
        eval_refusal
            .to_string()
            .contains("eval syntax is closed in a persistent session"),
        "unexpected persistent-eval refusal: {eval_refusal:#}"
    );
    checks["authorityRequestRefused"] =
        serde_json::Value::Bool(request_typed_dynamic_for_callback(&checks, &request).is_err());
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());
    for name in [
        "structuralLockdown",
        "intrinsicsFrozen",
        "evaluatorsTamed",
        "hatchesAbsent",
        "compartmentWithholdsAuthority",
        "rootWithholdsAuthority",
        "prototypeMutationBlocked",
        "authorityRequestRefused",
    ] {
        assert_eq!(
            checks[name], true,
            "post-lockdown check {name} failed: {checks}"
        );
    }
    let after = host.typed_generations().unwrap();
    assert_eq!(after, before);
    checks
        .as_object_mut()
        .expect("post-lockdown checks must be an object")
        .remove("context");
    checks
        .as_object_mut()
        .expect("post-lockdown checks must be an object")
        .remove("rootWithholdsAuthority");
    checks["bridgeExecuted"] = serde_json::Value::Bool(true);
    checks["generationsBefore"] = generations_value(before);
    checks["generationsAfter"] = generations_value(after);
    checks["generationsUnchanged"] = serde_json::Value::Bool(true);
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": checks,
        }),
        typed_decisions: Vec::new(),
        legacy_observation_count: 0,
    }
}

fn reset_exact_abi_probe() {
    EXACT_ABI_PROBE_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    EXACT_ABI_PROBE_OPERATION.store(0, std::sync::atomic::Ordering::SeqCst);
    EXACT_ABI_PROBE_PAYLOAD_LEN.store(0, std::sync::atomic::Ordering::SeqCst);
}

async fn install_exact_endowment(engine: &AuthenticatedCallbackEngine) -> serde_json::Value {
    let runtime = engine
        .ensure_runtime()
        .await
        .expect("load exact embedder runtime handle");
    let manifest_digest = std::ffi::CString::new(EXACT_OPERATION_MANIFEST_DIGEST).unwrap();
    runtime
        .with_runtime(|raw| unsafe {
            assert_eq!(
                ex_hermes_set_exact_host_call_async(
                    raw,
                    1,
                    EXACT_APP_OPERATION_IDS.as_ptr(),
                    EXACT_APP_OPERATION_IDS.len(),
                    manifest_digest.as_ptr(),
                    abi_probe_exact_host_call,
                    std::ptr::null_mut(),
                ),
                0,
                "install authenticated Exact app endowment"
            );
        })
        .expect("invoke Exact endowment setter on the runtime owner thread");
    let encoded = engine
        .eval_immediate(
            r#"JSON.stringify((function () {
  var descriptor = Object.getOwnPropertyDescriptor(exact, 'invokeHostAsync');
  return {
    genericBridgeAbsent: typeof __hostCall === 'undefined' && typeof __hostCallAsync === 'undefined',
    methodInstalled: typeof exact.invokeHostAsync === 'function',
    writable: descriptor && descriptor.writable,
    configurable: descriptor && descriptor.configurable,
    enumerable: descriptor && descriptor.enumerable,
    baselineFinalized: __ibexCompartmentBaselineFinalized === true,
    refreshHookRemoved: typeof __ibexRefreshCompartmentBaseline === 'undefined'
  };
})())"#,
        )
        .await
        .expect("inspect Exact endowment installation")
        .expect("Exact endowment installation returned no descriptor");
    let descriptor: serde_json::Value =
        serde_json::from_str(&encoded).expect("Exact endowment descriptor must be JSON");
    assert_eq!(descriptor["genericBridgeAbsent"], true);
    assert_eq!(descriptor["methodInstalled"], true);
    assert_eq!(descriptor["writable"], false);
    assert_eq!(descriptor["configurable"], false);
    assert_eq!(descriptor["enumerable"], false);
    assert_eq!(descriptor["baselineFinalized"], true);
    assert_eq!(descriptor["refreshHookRemoved"], true);
    descriptor
}

async fn execute_exact_host_call_round_trip(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_armed_exact_test_host();
    let _reset = install_armed_host(&host);
    reset_exact_abi_probe();
    unsafe { ibex_test_reset_exact_host_completion_observer() };
    // Exact endowments are a one-shot bootstrap publication. The first
    // authenticated session submission installs the runtime-owned `$_`
    // binding and closes the root-global disposition, so the endowment must
    // be installed before even a diagnostic submission.
    // @ref LLP 0002#the-exact-embedder-ingress — publish the authenticated
    // operation endowment before finalizing the package baseline.
    let engine = armed_engine_before_submission(&host, &digest).await;
    let session = format!("exact-host-call-round-trip:{}", recipe.plan_digest);
    begin_observation(&session);
    let descriptor = install_exact_endowment(&engine).await;
    assert_eq!(
        engine
            .eval_immediate(
                "globalThis.__exactConformanceResult = 'pending'; \
                 exact.invokeHostAsync(7, new Uint8Array([1,2,3])).then(\
                   function(value) { globalThis.__exactConformanceResult = Array.from(value).join(','); },\
                   function(error) { globalThis.__exactConformanceResult = 'rejected:' + error.message; }); \
                 'kicked'",
            )
            .await
            .expect("invoke endowed Exact host operation")
            .as_deref(),
        Some("kicked")
    );
    engine
        .drive_event_loop()
        .await
        .expect("deliver Exact host operation completion");
    let completion = engine
        .eval_immediate("globalThis.__exactConformanceResult")
        .await
        .expect("read Exact host operation completion")
        .expect("Exact host operation completion was undefined");
    let typed_decisions = finish_observation(&session);
    assert_eq!(completion, "9,8");
    assert_eq!(
        EXACT_ABI_PROBE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        EXACT_ABI_PROBE_OPERATION.load(std::sync::atomic::Ordering::SeqCst),
        7
    );
    assert_eq!(
        EXACT_ABI_PROBE_PAYLOAD_LEN.load(std::sync::atomic::Ordering::SeqCst),
        3
    );
    assert!(typed_decisions.is_empty());
    let mut completion_targets_consumed = 0;
    let mut completion_callbacks_queued = 0;
    let mut completion_callbacks_delivered = 0;
    assert_eq!(
        unsafe {
            ibex_test_exact_host_completion_observation(
                &mut completion_targets_consumed,
                &mut completion_callbacks_queued,
                &mut completion_callbacks_delivered,
            )
        },
        1
    );
    assert_eq!(completion_targets_consumed, 1);
    assert_eq!(completion_callbacks_queued, 1);
    assert_eq!(completion_callbacks_delivered, 1);
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "executionMechanism": "exact-host-call-round-trip",
                "setterInstalled": descriptor["methodInstalled"],
                "immutableCapability": descriptor["writable"] == false
                    && descriptor["configurable"] == false,
                "genericBridgeAbsent": descriptor["genericBridgeAbsent"],
                "callbackExecuted": true,
                "operationId": 7,
                "payloadLength": 3,
                "completion": completion,
                "completionTargetsConsumed": completion_targets_consumed,
                "completionCallbacksQueued": completion_callbacks_queued,
                "completionCallbacksDelivered": completion_callbacks_delivered,
                "singleUseCompletion": completion_targets_consumed == 1
                    && completion_callbacks_queued == 1
                    && completion_callbacks_delivered == 1,
            },
        }),
        typed_decisions,
        legacy_observation_count: 0,
    }
}

async fn execute_exact_endowment_install(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_armed_exact_test_host();
    let _reset = install_armed_host(&host);
    reset_exact_abi_probe();
    // @ref LLP 0002#the-exact-embedder-ingress — the one-shot endowment
    // publication precedes any authenticated session submission.
    let engine = armed_engine_before_submission(&host, &digest).await;
    let session = format!("exact-endowment-install:{}", recipe.plan_digest);
    begin_observation(&session);
    let descriptor = install_exact_endowment(&engine).await;
    let typed_decisions = finish_observation(&session);
    assert_eq!(
        EXACT_ABI_PROBE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "installing an endowment must not invoke the embedder callback"
    );
    assert!(typed_decisions.is_empty());
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "executionMechanism": "exact-endowment-install",
                "setterInstalled": descriptor["methodInstalled"],
                "immutableCapability": descriptor["writable"] == false
                    && descriptor["configurable"] == false,
                "genericBridgeAbsent": descriptor["genericBridgeAbsent"],
                "baselineFinalized": descriptor["baselineFinalized"],
                "refreshHookRemoved": descriptor["refreshHookRemoved"],
                "callbackExecuted": false,
            },
        }),
        typed_decisions,
        legacy_observation_count: 0,
    }
}

async fn execute_exact_endowment_authorize(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_armed_exact_test_host();
    let context_id = crate::host::abi::install_host(host);
    assert_ne!(context_id, 0, "install Exact authorization Host context");
    let _reset = HostResetGuard;
    let session = format!("exact-endowment-authorize:{}", recipe.plan_digest);
    begin_observation(&session);
    let digest_c = std::ffi::CString::new(digest).unwrap();
    let manifest_digest = std::ffi::CString::new(EXACT_OPERATION_MANIFEST_DIGEST).unwrap();
    let claimed = unsafe { crate::host::abi::ex_host_claim_armed_context(digest_c.as_ptr()) };
    assert_eq!(claimed, context_id, "claim exact installed Host context");
    let authorized = unsafe {
        crate::host::abi::ex_host_authorize_exact_endowment(
            claimed,
            1,
            manifest_digest.as_ptr(),
            EXACT_APP_OPERATION_IDS.as_ptr(),
            EXACT_APP_OPERATION_IDS.len(),
        )
    };
    let narrowed = [EXACT_APP_OPERATION_IDS[0]];
    let narrowed_authorized = unsafe {
        crate::host::abi::ex_host_authorize_exact_endowment(
            claimed,
            1,
            manifest_digest.as_ptr(),
            narrowed.as_ptr(),
            narrowed.len(),
        )
    };
    let typed_decisions = finish_observation(&session);
    crate::host::abi::ex_host_release_context(claimed);
    assert_eq!(authorized, 1);
    assert_eq!(narrowed_authorized, 0);
    assert!(typed_decisions.is_empty());
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "executionMechanism": "exact-endowment-authorize",
                "contextClaimed": true,
                "endowmentAuthorized": true,
                "narrowedEndowmentRejected": true,
                "contextKind": "app",
                "operationIds": EXACT_APP_OPERATION_IDS,
                "operationManifestDigest": EXACT_OPERATION_MANIFEST_DIGEST,
            },
        }),
        typed_decisions,
        legacy_observation_count: 0,
    }
}

async fn execute_exact_artifact_prepare(recipe: &Recipe) -> ScenarioExecution {
    let fixture = prepare_embedder_artifact_fixture();
    assert_ne!(
        crate::host::abi::install_host(crate::host::Host::strict()),
        0,
        "install observer Host for embedder artifact preparation"
    );
    let _reset = HostResetGuard;
    let session = format!("exact-artifact-prepare:{}", recipe.plan_digest);
    begin_observation(&session);
    let manifest = br#"{"schema":"exact.host-call-operations/v1","schemaVersion":1,"operations":[{"id":1000,"name":"app.render"},{"id":2200,"name":"agentIsolate.appRuntimeHealth"},{"id":2201,"name":"agentIsolate.bindFailed"},{"id":2202,"name":"agentIsolate.config"},{"id":2203,"name":"agentIsolate.ready"}],"endowments":{"app":[1000],"agentIsolate":[2200,2201,2202,2203],"uiWorklet":[]}}"#;
    let output = if recipe.terminal_observed_key
        == "host-abi:ex_host_build_exact_armed_embedder_artifacts"
    {
        let root = fixture
            ._directory
            .path()
            .to_str()
            .expect("Exact builder fixture root must be UTF-8")
            .as_bytes();
        unsafe {
            crate::host::abi::ex_host_build_exact_armed_embedder_artifacts(
                root.as_ptr(),
                root.len(),
                std::ptr::null(),
                0,
                manifest.as_ptr(),
                manifest.len(),
            )
        }
    } else if recipe.terminal_observed_key
        == "host-abi:ex_host_prepare_exact_armed_embedder_artifacts"
    {
        unsafe {
            crate::host::abi::ex_host_prepare_exact_armed_embedder_artifacts(
                fixture.snapshot.as_ptr(),
                fixture.snapshot.len(),
                fixture.expected_identity.as_ptr(),
                fixture.expected_identity.len(),
                manifest.as_ptr(),
                manifest.len(),
            )
        }
    } else {
        unsafe {
            crate::host::abi::ex_host_prepare_armed_embedder_artifacts(
                fixture.snapshot.as_ptr(),
                fixture.snapshot.len(),
                fixture.expected_identity.as_ptr(),
                fixture.expected_identity.len(),
            )
        }
    };
    assert!(
        !output.is_null(),
        "artifact preparation returned a null envelope"
    );
    let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
        .to_bytes()
        .to_vec();
    crate::host::abi::ex_host_free_string(output);
    let typed_decisions = finish_observation(&session);
    assert!(typed_decisions.is_empty());
    let envelope: serde_json::Value =
        serde_json::from_slice(&bytes).expect("artifact preparation envelope must be JSON");
    assert_eq!(
        envelope["ok"], true,
        "artifact preparation refused: {envelope}"
    );
    let artifacts = &envelope["artifacts"];
    assert_eq!(
        artifacts["artifactSchema"],
        "ibex/armed-embedder-artifacts/1"
    );
    let fresh_nonce = artifacts["snapshot"]["runNonce"]
        .as_str()
        .expect("prepared artifact has no run nonce");
    let fresh_digest = artifacts["armedSnapshotDigest"]
        .as_str()
        .expect("prepared artifact has no digest");
    assert_ne!(fresh_nonce, fixture.source_nonce);
    assert_ne!(fresh_digest, fixture.source_digest);
    assert_eq!(artifacts["snapshot"]["armedSnapshotDigest"], fresh_digest);
    assert_eq!(
        artifacts["expectedIdentity"]["armedSnapshotDigest"],
        fresh_digest
    );
    let expected: capsec_semantics::arming::ExpectedArmingIdentity =
        serde_json::from_value(artifacts["expectedIdentity"].clone())
            .expect("prepared expected identity must deserialize");
    let snapshot = serde_json::to_vec(&artifacts["snapshot"]).unwrap();
    let reloaded = capsec_semantics::arming::ArmedSnapshot::load(&snapshot, &expected)
        .expect("prepared artifact pair must authenticate");
    assert_eq!(reloaded.digest().as_str(), fresh_digest);
    let checks = serde_json::json!({
        "executionMechanism": "exact-artifact-prepare-round-trip",
        "artifactPrepared": true,
        "artifactSchema": artifacts["artifactSchema"],
        "nonceFreshened": true,
        "digestRebound": true,
        "sourceDigest": fixture.source_digest,
        "preparedDigest": fresh_digest,
        "preparedPairAuthenticated": true,
    });
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": checks,
        }),
        typed_decisions,
        legacy_observation_count: 0,
    }
}

async fn execute_mechanism(
    recipe: &Recipe,
    package: &PackageFixture,
    mechanism: &str,
) -> ScenarioExecution {
    match mechanism {
        "scheduled-public-attribution-guard" => execute_attribution_missing(recipe).await,
        "scheduled-public-environment-revocation-recheck" => {
            execute_generation_recheck(recipe, package).await
        }
        "scheduled-package-principal-scope" => execute_principal_restore(recipe, package).await,
        "cross-snapshot-public-handle-reattenuation" => {
            execute_snapshot_mismatch(recipe, package).await
        }
        "typed-grant-ceiling-refusal" => execute_cannot_widen(recipe).await,
        "lockdown-tamper-and-grant-refusal" => execute_post_lockdown(recipe).await,
        "exact-host-call-round-trip" => execute_exact_host_call_round_trip(recipe).await,
        "exact-endowment-install" => execute_exact_endowment_install(recipe).await,
        "exact-endowment-authorize" => execute_exact_endowment_authorize(recipe).await,
        "exact-artifact-prepare-round-trip" => execute_exact_artifact_prepare(recipe).await,
        other => panic!("unsupported callback invariant execution mechanism {other}"),
    }
}

async fn execute_scenario(recipe: &Recipe, package: &PackageFixture) -> ScenarioExecution {
    let mechanism = recipe
        .public_surface_probe
        .as_ref()
        .unwrap()
        .invocation
        .source_descriptor["executionMechanism"]
        .as_str()
        .expect("callback invariant recipe has no execution mechanism");
    execute_mechanism(recipe, package, mechanism).await
}

fn build_runtime_observation(recipe: &Recipe, scenario: &ScenarioExecution) -> serde_json::Value {
    let probe = recipe.public_surface_probe.as_ref().unwrap();
    serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": probe.invocation.invocation_schema,
            "kind": probe.invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "surfaceKind": probe.invocation.surface_kind,
            "surfaceName": probe.invocation.surface_name,
            "scenario": probe.invocation.scenario,
            "sourceDescriptorDigest": probe.invocation.source_descriptor_digest,
            "result": scenario.result,
        },
        "legacyObservationCount": scenario.legacy_observation_count,
        "typedDecisions": scenario.typed_decisions,
    })
}

pub(super) async fn execute_exact_fixture_runtime_observation(
    recipe_value: &serde_json::Value,
) -> serde_json::Value {
    let recipe: Recipe = serde_json::from_value(recipe_value.clone())
        .expect("Exact fixture recipe must match the executable recipe schema");
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.scenario, "non-capability");
    let mechanism = recipe
        .public_surface_probe
        .as_ref()
        .unwrap()
        .invocation
        .source_descriptor["executionMechanism"]
        .as_str()
        .expect("Exact fixture recipe has no execution mechanism");
    assert!(matches!(
        mechanism,
        "exact-host-call-round-trip"
            | "exact-endowment-install"
            | "exact-endowment-authorize"
            | "exact-artifact-prepare-round-trip"
    ));
    let (branches, edges) = checked_registry_rows();
    validate_recipe_source_binding(&recipe, &branches, &edges);
    let package = prepare_package_fixture();
    let scenario = execute_scenario(&recipe, &package).await;
    build_runtime_observation(&recipe, &scenario)
}

fn build_execution(
    recipe: &Recipe,
    scenario: ScenarioExecution,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let probe = recipe.public_surface_probe.as_ref().unwrap();
    assert_eq!(
        scenario.typed_decisions.len(),
        probe.invocation.expected_typed_decision_count
    );
    assert_eq!(scenario.legacy_observation_count, 0);
    let observed_stages = scenario
        .typed_decisions
        .iter()
        .map(|decision| decision["decisionSet"]["context"]["stage"].clone())
        .collect::<Vec<_>>();
    let observed_outcomes = scenario
        .typed_decisions
        .iter()
        .map(|decision| decision["evidence"]["outcome"].clone())
        .collect::<Vec<_>>();
    let observed_reasons = scenario
        .typed_decisions
        .iter()
        .map(|decision| {
            serde_json::Value::String(
                typed_actor_reason(decision)
                    .expect("callback decision has no actor-bound reason")
                    .to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        observed_stages,
        probe
            .invocation
            .expected_typed_stages
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        observed_outcomes,
        probe
            .invocation
            .expected_typed_outcomes
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        observed_reasons,
        probe
            .invocation
            .expected_typed_reasons
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>()
    );
    let runtime_observation = build_runtime_observation(recipe, &scenario);
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected callback observation must be an object")
        .insert("result".into(), serde_json::Value::String("passed".into()));
    let mut evidence = serde_json::json!({
        "evidenceSchema": "ibex/capsec-public-surface-fixture-evidence/2",
        "fixtureId": recipe.fixture_id,
        "planDigest": recipe.plan_digest,
        "engineBinaryDigest": engine_binary_digest,
        "probe": probe,
        "terminalObservedKey": probe.surface_observed_key,
        "exitCode": 0,
        "resultMarker": format!("ibex-capsec-public-fixture:{}:passed", recipe.fixture_id),
        "observation": observation,
        "runtimeObservation": runtime_observation,
    });
    let evidence_digest = tagged_jcs_digest(&evidence);
    evidence
        .as_object_mut()
        .unwrap()
        .insert("evidenceDigest".into(), evidence_digest.into());
    serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-callback-invariant-public-harness",
        "evidence": evidence,
    })
}

fn smoke_recipe(scenario: &str) -> Recipe {
    Recipe {
        fixture_id: format!("callback-smoke.{scenario}"),
        plan_digest: format!("smoke-{scenario}"),
        classification: "non-capability".into(),
        scenario: scenario.into(),
        edge_ids: Vec::new(),
        implementation_branch_ids: Vec::new(),
        enforcement_branch_ids: Vec::new(),
        action_ids: Vec::new(),
        terminal_observed_key: "callback:smoke".into(),
        expected_observation: serde_json::json!({}),
        route: PublicRoute {
            surface_observed_keys: Vec::new(),
        },
        status: "diagnostic".into(),
        public_surface_probe: None,
        internal_invariant_proof: None,
    }
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(feature = "insecure"))]
async fn capsec_callback_invariant_mechanisms_smoke() {
    let _lock = hermes_engine_test_lock().lock().await;
    let package = prepare_package_fixture();
    for scenario in [
        "attribution-missing-deny",
        "generation-recheck",
        "principal-restore",
        "snapshot-mismatch-deny",
        "cannot-widen-authority",
        "post-lockdown-invariant",
    ] {
        let recipe = smoke_recipe(scenario);
        let (_, mechanism, _, outcomes, _) =
            expected_invariant(scenario, &recipe.terminal_observed_key);
        let execution = execute_mechanism(&recipe, &package, mechanism).await;
        assert_eq!(execution.result["outcome"], "passed");
        assert_eq!(execution.legacy_observation_count, 0);
        assert_eq!(execution.typed_decisions.len(), outcomes.len());
    }
    for (surface_observed_key, mechanism) in [
        (
            "callback:exact-host-call-async-resolve",
            "exact-host-call-round-trip",
        ),
        (
            "host-abi:ex_hermes_set_exact_host_call_async",
            "exact-endowment-install",
        ),
        (
            "host-abi:ex_host_authorize_exact_endowment",
            "exact-endowment-authorize",
        ),
        (
            "host-abi:ex_host_build_exact_armed_embedder_artifacts",
            "exact-artifact-prepare-round-trip",
        ),
        (
            "host-abi:ex_host_prepare_armed_embedder_artifacts",
            "exact-artifact-prepare-round-trip",
        ),
        (
            "host-abi:ex_host_prepare_exact_armed_embedder_artifacts",
            "exact-artifact-prepare-round-trip",
        ),
    ] {
        let mut recipe = smoke_recipe("non-capability");
        recipe.terminal_observed_key = surface_observed_key.to_owned();
        let execution = execute_mechanism(&recipe, &package, mechanism).await;
        assert_eq!(execution.result["outcome"], "passed");
        assert_eq!(execution.result["checks"]["executionMechanism"], mechanism);
        assert_eq!(execution.legacy_observation_count, 0);
        assert!(execution.typed_decisions.is_empty());
    }
}

fn expected_internal_proof(scenario: &str) -> (&'static str, &'static str) {
    match scenario {
        "attribution-missing-deny" => (
            "scheduled-public-attribution-guard",
            "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_attribution_missing",
        ),
        "cannot-widen-authority" => (
            "typed-grant-ceiling-refusal",
            "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_cannot_widen",
        ),
        "generation-recheck" => (
            "scheduled-public-environment-revocation-recheck",
            "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_generation_recheck",
        ),
        "post-lockdown-invariant" => (
            "lockdown-tamper-and-grant-refusal",
            "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_post_lockdown",
        ),
        "principal-restore" => (
            "scheduled-package-principal-scope",
            "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_principal_restore",
        ),
        "snapshot-mismatch-deny" => (
            "cross-snapshot-public-handle-reattenuation",
            "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_snapshot_mismatch",
        ),
        other => panic!("unsupported internally verified scenario {other}"),
    }
}

fn internal_recipes(catalog: &RecipeCatalog) -> Vec<&Recipe> {
    let recipes = catalog
        .recipes
        .iter()
        .filter(|recipe| recipe.status == "internally-verified")
        .collect::<Vec<_>>();
    assert!(!recipes.is_empty(), "internal invariant catalog is empty");
    for recipe in &recipes {
        assert!(
            recipe.public_surface_probe.is_none(),
            "{}: internal invariant must not carry a public probe",
            recipe.fixture_id
        );
        let proof = recipe.internal_invariant_proof.as_ref().unwrap_or_else(|| {
            panic!(
                "{}: internal invariant has no proof plan",
                recipe.fixture_id
            )
        });
        assert_exact_keys(
            proof,
            &[
                "proofPlanSchema",
                "scenario",
                "mechanism",
                "sourceRef",
                "executor",
                "command",
                "proofPlanDigest",
            ],
            "internal invariant proof plan",
        );
        let (mechanism, source_ref) = expected_internal_proof(&recipe.scenario);
        assert_eq!(
            proof["proofPlanSchema"],
            "ibex/capsec-internal-invariant-proof-plan/1"
        );
        assert_eq!(proof["scenario"], recipe.scenario);
        assert_eq!(proof["mechanism"], mechanism);
        assert_eq!(proof["sourceRef"], source_ref);
        assert_eq!(proof["executor"], INTERNAL_INVARIANT_EXECUTOR);
        assert_eq!(
            proof["command"],
            serde_json::json!(INTERNAL_INVARIANT_COMMAND)
        );
        let mut proof_payload = proof.clone();
        proof_payload
            .as_object_mut()
            .unwrap()
            .remove("proofPlanDigest");
        assert_eq!(
            proof["proofPlanDigest"],
            tagged_jcs_digest(&proof_payload),
            "{}: internal proof-plan digest is stale",
            recipe.fixture_id
        );
    }
    recipes
}

fn validate_internal_binding(
    binding: &serde_json::Value,
    catalog: &RecipeCatalog,
    recipes: &[&Recipe],
    loaded_engine: &ibex_runtime::engine::LoadedEngineBinaryIdentity,
) -> (serde_json::Value, String, Vec<serde_json::Value>) {
    assert_exact_keys(
        binding,
        &[
            "internalInvariantEvidenceBindingSchema",
            "executionBinding",
            "bindingDigest",
            "fixturePlans",
        ],
        "internal invariant binding artifact",
    );
    assert_eq!(
        binding["internalInvariantEvidenceBindingSchema"],
        "ibex/capsec-internal-invariant-evidence-binding/1"
    );
    let execution_binding = binding["executionBinding"].clone();
    assert_exact_keys(
        &execution_binding,
        &[
            "sourceRevision",
            "sourceTreeDigest",
            "target",
            "engine",
            "vocabularyDigest",
            "registryDigest",
            "implementationManifestDigest",
            "fixtureCatalogDigest",
            "recipeCatalogDigest",
            "publicSurfaceExecutionDigest",
        ],
        "internal invariant execution binding",
    );
    assert_eq!(
        execution_binding["target"]["triple"],
        embedder_runtime_target_triple()
    );
    assert_eq!(
        execution_binding["engine"],
        serde_json::to_value(loaded_engine).expect("serialize loaded engine identity")
    );
    assert_eq!(
        execution_binding["recipeCatalogDigest"],
        catalog.recipe_catalog_digest
    );
    let binding_digest = binding["bindingDigest"]
        .as_str()
        .expect("internal invariant binding has no digest")
        .to_owned();
    assert_eq!(tagged_jcs_digest(&execution_binding), binding_digest);
    let plans = binding["fixturePlans"]
        .as_array()
        .expect("internal invariant binding has no fixture plans")
        .clone();
    assert_eq!(plans.len(), recipes.len());
    assert!(recipes.iter().zip(&plans).all(|(recipe, plan)| {
        recipe.fixture_id == plan["fixtureId"] && recipe.plan_digest == tagged_jcs_digest(plan)
    }));
    (execution_binding, binding_digest, plans)
}

// One executed runtime transition proves each tightly enumerated internal
// scenario class. Every fixture row still receives an exact plan-bound evidence
// record; only the runtime observation is shared by rows naming that same
// invariant.
// @ref LLP 0036#correctness-owed-the-deliberately-deferred-verification
#[tokio::test(flavor = "current_thread")]
async fn capsec_internal_invariant_evidence_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!(
            "IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping internal invariant evidence batch"
        );
        return;
    };
    let binding_path = std::env::var("IBEX_CAPSEC_INTERNAL_INVARIANT_BINDING")
        .expect("internal invariant evidence requires an owned binding input");
    let output_path = std::env::var("IBEX_CAPSEC_INTERNAL_INVARIANT_EVIDENCE_OUTPUT").ok();
    let catalog_path =
        std::fs::canonicalize(recipe_path).expect("canonicalize internal invariant recipe catalog");
    let binding_path = std::fs::canonicalize(binding_path)
        .expect("canonicalize internal invariant evidence binding");
    let catalog = load_catalog(&catalog_path);
    let recipes = internal_recipes(&catalog);
    let binding = load_strict_json(&binding_path, "internal invariant evidence binding");

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest loaded Hermes before internal invariant evidence");
    let (execution_binding, binding_digest, plans) =
        validate_internal_binding(&binding, &catalog, &recipes, &identity_before);
    let portable = super::capsec_portable_public_batch::PortablePublicBatchContext::begin_internal(
        INTERNAL_INVARIANT_EXECUTOR,
    );
    assert_ne!(
        output_path.is_some(),
        portable.is_some(),
        "internal invariant batch requires exactly one legacy output or portable plan"
    );
    let package = prepare_package_fixture();
    let mut observations = BTreeMap::new();
    for scenario in [
        "attribution-missing-deny",
        "cannot-widen-authority",
        "generation-recheck",
        "post-lockdown-invariant",
        "principal-restore",
        "snapshot-mismatch-deny",
    ] {
        let recipe = smoke_recipe(scenario);
        let (mechanism, _) = expected_internal_proof(scenario);
        let execution = execute_mechanism(&recipe, &package, mechanism).await;
        assert_eq!(execution.result["outcome"], "passed");
        assert_eq!(execution.legacy_observation_count, 0);
        observations.insert(
            scenario,
            serde_json::json!({
                "observationSchema": "ibex/capsec-runtime-internal-invariant-observation/1",
                "scenario": scenario,
                "mechanism": mechanism,
                "proofPlanDigest": recipes
                    .iter()
                    .find(|candidate| candidate.scenario == scenario)
                    .unwrap()
                    .internal_invariant_proof
                    .as_ref()
                    .unwrap()["proofPlanDigest"],
                "result": execution.result,
                "legacyObservationCount": execution.legacy_observation_count,
                "typedDecisions": execution.typed_decisions,
            }),
        );
    }
    assert_eq!(observations.len(), 6);

    let mut executions = Vec::with_capacity(recipes.len());
    for (recipe, plan) in recipes.iter().zip(&plans) {
        let mut observation = plan["expectedObservation"].clone();
        observation
            .as_object_mut()
            .expect("internal fixture expected observation must be an object")
            .insert("result".into(), "passed".into());
        let proof_plan = recipe.internal_invariant_proof.as_ref().unwrap();
        let evidence = serde_json::json!({
            "evidenceSchema": "ibex/capsec-internal-invariant-fixture-evidence/1",
            "fixtureId": recipe.fixture_id,
            "command": INTERNAL_INVARIANT_COMMAND,
            "exitCode": 0,
            "resultMarker": format!(
                "ibex-capsec-internal-invariant:{}:passed",
                recipe.fixture_id
            ),
            "planDigest": recipe.plan_digest,
            "engineBinaryDigest": identity_before.binary_digest,
            "fixturePlan": plan,
            "executionBinding": execution_binding,
            "observation": observation,
            "proofPlan": proof_plan,
            "runtimeObservation": observations[recipe.scenario.as_str()],
        });
        executions.push(serde_json::json!({
            "fixtureId": recipe.fixture_id,
            "outcome": "passed",
            "executor": INTERNAL_INVARIANT_EXECUTOR,
            "artifactDigest": tagged_jcs_digest(&evidence),
            "bindingDigest": binding_digest,
            "evidence": evidence,
        }));
    }

    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest loaded Hermes after internal invariant evidence");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after internal invariant evidence");
    if let Some(portable) = portable {
        portable.finish_internal(&executions);
        return;
    }
    let artifact = serde_json::json!({
        "internalInvariantExecutionArtifactSchema":
            "ibex/capsec-internal-invariant-executions/1",
        "executionBinding": execution_binding,
        "bindingDigest": binding_digest,
        "executions": executions,
    });
    let output_path =
        std::path::PathBuf::from(output_path.expect("legacy internal evidence has no output path"));
    assert!(
        output_path.is_absolute(),
        "internal invariant output must be absolute"
    );
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .unwrap_or_else(|error| {
            panic!(
                "create internal invariant evidence {}: {error}",
                output_path.display()
            )
        });
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize internal invariant evidence");
    output
        .write_all(b"\n")
        .expect("finish internal invariant evidence");
    output.sync_all().expect("sync internal invariant evidence");
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn capsec_public_callback_invariant_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping callback invariant batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT").ok();
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = callback_recipes(&catalog);
    let mut by_scenario = BTreeMap::new();
    for recipe in &recipes {
        *by_scenario
            .entry(recipe.scenario.as_str())
            .or_insert(0usize) += 1;
    }
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // this public batch executes only exact authored public mechanisms.
    // Runtime-owned scenario classes have a distinct source-bound evidence
    // producer and cannot be credited through public callback bookkeeping.
    let non_capability_scenario_count = 8;
    assert_eq!(recipes.len(), non_capability_scenario_count);
    assert_eq!(by_scenario.len(), 1);
    assert_eq!(
        by_scenario.get("non-capability"),
        Some(&non_capability_scenario_count)
    );
    let (branches, edges) = checked_registry_rows();
    for recipe in &recipes {
        validate_recipe_source_binding(recipe, &branches, &edges);
    }

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before callback invariant recipes");
    let portable = super::capsec_portable_public_batch::PortablePublicBatchContext::begin(
        "ibex-callback-invariant-public-harness",
    );
    assert_ne!(
        output_path.is_some(),
        portable.is_some(),
        "callback invariant batch requires exactly one legacy output or portable plan"
    );
    let package = prepare_package_fixture();
    let mut executions = Vec::with_capacity(recipes.len());
    for recipe in recipes {
        let scenario = execute_scenario(recipe, &package).await;
        executions.push(build_execution(
            recipe,
            scenario,
            &identity_before.binary_digest,
        ));
    }
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after callback invariant recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after callback invariant recipes");
    if let Some(portable) = portable {
        portable.finish(&executions);
        return;
    }
    let artifact = PublicBatchArtifact {
        public_batch_evidence_schema: "ibex/capsec-public-batch-evidence/1",
        recipe_catalog_digest: catalog.recipe_catalog_digest,
        loaded_engine_identity: identity_before,
        executions,
    };
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path.expect("legacy callback invariant batch has no output path"))
        .expect("create owned callback invariant evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize callback invariant evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish callback invariant evidence artifact");
    output
        .sync_all()
        .expect("sync callback invariant evidence artifact");
}
