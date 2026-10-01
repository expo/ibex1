//! Hermes JavaScript engine adapter
//!
//! This module implements the Engine trait for the Hermes JS engine.
//! Hermes is embedded via a C++/JSI adapter compiled in build.rs.

use super::{
    async_trait, AuthenticatedAsyncFailure, AuthenticatedAsyncFailureOwner,
    AuthenticatedCancellationEvent, AuthenticatedCancellationResolution,
    AuthenticatedCancellationStatus, AuthenticatedCapabilityStratum, AuthenticatedDisplay,
    AuthenticatedDisplayKind, AuthenticatedErrorClass, AuthenticatedEvaluation,
    AuthenticatedGeneratedEntry, AuthenticatedProgramDrainFailure, AuthenticatedSourcePosition,
    AuthenticatedThrow, AuthenticatedThrowMetadata, AuthenticatedWorkUnitEvent,
    AuthenticatedWorkUnitKind, AuthenticatedWorkUnitPhase, DisplayDisposition, Engine,
    EngineFeature,
};
use crate::cdp::{self, BreakpointInfo, CdpBackend, DebugCommand, ScriptInfo};
use crate::subprocess::{output_with_timeout, parse_timeout_ms, DEFAULT_HERMESC_TIMEOUT_MS};
use anyhow::{anyhow, Context, Result};
use ibex_runtime::engine::evaluation::{
    ArmedSessionToken, CapabilityStratum, EngineFault, NativeErrorClass, SourceRequest,
    ThrowMetadata,
};
#[cfg(feature = "capsec-conformance-observer")]
use ibex_runtime::engine::hermes_structured::evaluate_authenticated_stage1_with_constrained_principals;
use ibex_runtime::engine::hermes_structured::{
    acknowledge_stage1_display, consume_authenticated_json,
    evaluate_authenticated_generated_stage1, evaluate_authenticated_stage1,
    render_and_release_async_failure_value, resume_authenticated_stage1, Stage1Display,
    Stage1DisplayReceipt, Stage1Evaluation, Stage1EvaluationOutcome, Stage1EvaluationProgress,
    ValueKind,
};
#[cfg(feature = "module-runner")]
use ibex_runtime::engine::hermes_structured::{
    admit_prepare_authenticated_module_graph, materialize_authenticated_progress_stage1,
    AuthenticatedModuleGraphAdmission,
    AuthenticatedModuleGraphPreparation as StructuredModuleGraphPreparation,
    ModuleGraphExecutionOutcome, ModuleGraphSuspension,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::process::Stdio;
#[cfg(feature = "module-runner")]
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::process::Command;
use tokio::sync::Mutex;
use {std::sync::OnceLock, tokio::sync::Notify};

const REQUIRED_RUNTIME_MARKERS: &[&[u8]] = &[b"globalThis.__exactRuntime", b"ExactBundle"];

/// Project the trusted bootstrap's temporary process wires onto the standard
/// public objects, then remove every raw root before the armed posture sweep.
/// Direct file argv is replaced later from its authenticated native request;
/// this establishes the no-file baseline used by the other session modes.
/// @ref LLP 0023#6-path-bearing-observables
const CLOSE_ARMED_PROCESS_BOOTSTRAP_WIRES: &str = r#"(function () {
  var g = globalThis;
  var processObject = g.process;
  if (!processObject || typeof processObject !== 'object') {
    throw new Error('armed process bootstrap has no process object');
  }

  var syntheticRuntime = 'ibex:runtime';
  var copiedExecArgv = Array.isArray(g.__exactExecArgv)
    ? g.__exactExecArgv.slice()
    : [];
  var descriptor = function (value) {
    return {
      value: value,
      writable: true,
      enumerable: true,
      configurable: true
    };
  };
  Object.defineProperty(processObject, 'argv', descriptor([syntheticRuntime]));
  Object.defineProperty(processObject, 'execArgv', descriptor(copiedExecArgv));
  Object.defineProperty(processObject, 'argv0', descriptor(syntheticRuntime));
  Object.defineProperty(processObject, 'execPath', descriptor(syntheticRuntime));

  var projectFacade = function (facade) {
    if (!facade || typeof facade !== 'object') return;
    Object.defineProperty(facade, 'argv', descriptor(processObject.argv));
    Object.defineProperty(facade, 'main', descriptor(''));
  };
  projectFacade(g.Exact);
  if (g.Bun !== g.Exact) projectFacade(g.Bun);

  var temporaryRoots = [
    '__exactArgv',
    '__exactExecArgv',
    '__exactExecPath',
    '__exactRawArgv0',
    '__exactCompatModes',
    '__exactProcessIpcBootstrap'
  ];
  for (var index = 0; index < temporaryRoots.length; index++) {
    var key = temporaryRoots[index];
    if (!Reflect.deleteProperty(g, key) ||
        Object.prototype.hasOwnProperty.call(g, key)) {
      throw new Error('armed process bootstrap could not delete ' + key);
    }
  }
})();"#;

/// The compatibility tuple and private child-process IPC input are needed until
/// the shared runtime bundle has captured them. Diagnostic runtimes do not run
/// the broader armed posture sweep, so close these temporary roots explicitly
/// after bundle evaluation and compartment-baseline finalization.
/// @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
/// @ref LLP 0022#7-capabilities-principals-and-affordance-parity
const CLOSE_UNARMED_COMPATIBILITY_BOOTSTRAP_WIRE: &str = r#"(function () {
  var g = globalThis;
  var temporaryRoots = [
    '__exactCompatModes',
    '__exactProcessIpcBootstrap'
  ];
  for (var index = 0; index < temporaryRoots.length; index++) {
    var key = temporaryRoots[index];
    if (!Reflect.deleteProperty(g, key) ||
        Object.prototype.hasOwnProperty.call(g, key)) {
      throw new Error('diagnostic process bootstrap could not delete ' + key);
    }
  }
})();"#;

fn authenticated_display(value: Stage1Display) -> AuthenticatedDisplay {
    let kind = match value.kind {
        ValueKind::Undefined => AuthenticatedDisplayKind::Undefined,
        ValueKind::Null => AuthenticatedDisplayKind::Null,
        ValueKind::Boolean => AuthenticatedDisplayKind::Boolean,
        ValueKind::Number => AuthenticatedDisplayKind::Number,
        ValueKind::String => AuthenticatedDisplayKind::String,
        ValueKind::Symbol => AuthenticatedDisplayKind::Symbol,
        ValueKind::BigInt => AuthenticatedDisplayKind::BigInt,
        ValueKind::Function => AuthenticatedDisplayKind::Function,
        ValueKind::Object => AuthenticatedDisplayKind::Object,
        ValueKind::Array => AuthenticatedDisplayKind::Array,
    };
    AuthenticatedDisplay {
        kind,
        text: value.text.to_string(),
        truncated: value.truncated,
    }
}

fn authenticated_capability_stratum(stratum: CapabilityStratum) -> AuthenticatedCapabilityStratum {
    match stratum {
        CapabilityStratum::Base => AuthenticatedCapabilityStratum::Base,
        CapabilityStratum::SafeThrow => AuthenticatedCapabilityStratum::SafeThrow,
        CapabilityStratum::SourcePositions => AuthenticatedCapabilityStratum::SourcePositions,
        CapabilityStratum::RichInspection => AuthenticatedCapabilityStratum::RichInspection,
    }
}

fn authenticated_error_class(error_class: NativeErrorClass) -> AuthenticatedErrorClass {
    match error_class {
        NativeErrorClass::Unclassified => AuthenticatedErrorClass::Unclassified,
        NativeErrorClass::Error => AuthenticatedErrorClass::Error,
        NativeErrorClass::AggregateError => AuthenticatedErrorClass::AggregateError,
        NativeErrorClass::EvalError => AuthenticatedErrorClass::EvalError,
        NativeErrorClass::RangeError => AuthenticatedErrorClass::RangeError,
        NativeErrorClass::ReferenceError => AuthenticatedErrorClass::ReferenceError,
        NativeErrorClass::SyntaxError => AuthenticatedErrorClass::SyntaxError,
        NativeErrorClass::TypeError => AuthenticatedErrorClass::TypeError,
        NativeErrorClass::UriError => AuthenticatedErrorClass::UriError,
        NativeErrorClass::TimeoutError => AuthenticatedErrorClass::TimeoutError,
        NativeErrorClass::QuitError => AuthenticatedErrorClass::QuitError,
    }
}

fn authenticated_throw_metadata(metadata: ThrowMetadata) -> AuthenticatedThrowMetadata {
    match metadata {
        ThrowMetadata::Unavailable { required_stratum } => {
            AuthenticatedThrowMetadata::Unavailable {
                required_stratum: authenticated_capability_stratum(required_stratum),
            }
        }
        ThrowMetadata::Captured {
            error_class,
            message,
            message_truncated,
            stack,
            stack_truncated,
            positions,
        } => AuthenticatedThrowMetadata::Captured {
            error_class: authenticated_error_class(error_class),
            message: message.map(|message| message.to_string()),
            message_truncated,
            stack: stack.map(|stack| stack.to_string()),
            stack_truncated,
            positions: positions
                .into_iter()
                .map(|position| AuthenticatedSourcePosition {
                    source_label: position.source_label.as_str().to_owned(),
                    line: position.line,
                    column: position.column,
                })
                .collect(),
        },
    }
}

fn authenticated_evaluation(evaluation: Stage1Evaluation) -> AuthenticatedEvaluation {
    match evaluation.outcome {
        Stage1EvaluationOutcome::Empty => AuthenticatedEvaluation::Empty,
        Stage1EvaluationOutcome::Value { display, receipt } => AuthenticatedEvaluation::Value {
            display: authenticated_display(display),
            receipt: Some(receipt),
        },
        Stage1EvaluationOutcome::Throw { value, metadata } => {
            AuthenticatedEvaluation::Throw(AuthenticatedThrow {
                value: authenticated_display(value),
                metadata: authenticated_throw_metadata(metadata),
            })
        }
        Stage1EvaluationOutcome::Cancelled => AuthenticatedEvaluation::Cancelled,
        Stage1EvaluationOutcome::Lifecycle { exit_code } => {
            AuthenticatedEvaluation::Lifecycle(exit_code)
        }
    }
}

#[cfg(feature = "module-runner")]
struct NativeModuleSourceMap {
    source_label: String,
    bundle_path: String,
    map: super::sourcemap::SourceMap,
}

#[cfg(feature = "module-runner")]
fn native_module_source_maps(
    plan: &ibex_runtime::module_loader::graph::SynchronousGraphPlan<'_>,
    configs: &std::collections::BTreeMap<
        ibex_runtime::module_loader::identity::SourceId,
        ibex_runtime::engine::module_runner::NativeModuleRecordConfig,
    >,
) -> Result<std::collections::BTreeMap<String, NativeModuleSourceMap>> {
    let mut maps = std::collections::BTreeMap::new();
    for (source_id, config) in configs {
        let artifact = plan.artifact(source_id)?;
        let source_map = &artifact.artifact().semantics.source_map;
        let source_labels = source_map
            .source_ids
            .iter()
            .map(|source| {
                configs
                    .get(&source.0)
                    .map(|source_config| source_config.source_label.clone())
                    .ok_or_else(|| {
                        anyhow!(
                            "native module source map names a source outside its authenticated graph"
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let map =
            super::sourcemap::SourceMap::from_parts(source_labels, source_map.mappings.as_str())
                .ok_or_else(|| anyhow!("native module source map has no authenticated sources"))?;
        let bundle_path = config
            .virtual_path
            .clone()
            .unwrap_or_else(|| config.source_label.clone());
        maps.insert(
            config.source_label.clone(),
            NativeModuleSourceMap {
                source_label: config.source_label.clone(),
                bundle_path,
                map,
            },
        );
    }
    Ok(maps)
}

#[cfg(feature = "module-runner")]
fn rewrite_native_module_source_positions(
    mut evaluation: AuthenticatedEvaluation,
    source_maps: &std::collections::BTreeMap<String, NativeModuleSourceMap>,
) -> AuthenticatedEvaluation {
    let AuthenticatedEvaluation::Throw(thrown) = &mut evaluation else {
        return evaluation;
    };
    let AuthenticatedThrowMetadata::Captured {
        stack, positions, ..
    } = &mut thrown.metadata
    else {
        return evaluation;
    };

    if let Some(stack) = stack {
        for source_map in source_maps.values() {
            if stack.contains(source_map.source_label.as_str())
                || stack.contains(source_map.bundle_path.as_str())
            {
                *stack = super::sourcemap::rewrite_error(
                    stack,
                    &source_map.map,
                    source_map.bundle_path.as_str(),
                );
            }
        }
    }
    for position in positions {
        let Some(source_map) = source_maps.get(position.source_label.as_str()) else {
            continue;
        };
        let Some((source_label, line, column)) = source_map.map.lookup(
            position.line.saturating_sub(1),
            position.column.saturating_sub(1),
        ) else {
            continue;
        };
        position.source_label = source_label.to_owned();
        position.line = line;
        position.column = column;
    }
    evaluation
}

// The native bootstrap installs this one-shot trusted hook before any bundled
// runtime code executes. Rust invokes it only after the embedded/disk runtime
// path is complete, then removes the hook so application code cannot recapture
// or replace the package-global baseline. @ref LLP 0013#mechanism-2
pub(crate) const FINALIZE_COMPARTMENT_BASELINE: &str = r#"(function(){
  var g = globalThis;
  var hasOwn = Object.prototype.hasOwnProperty;
  function owns(name) {
    return hasOwn.call(g, name);
  }

  var hasRegistry = owns('__compartments');
  var hasRefresh = owns('__ibexRefreshCompartmentBaseline');
  var hasReady = owns('__ibexCompartmentRegistryReady');
  var hasFinalized = owns('__ibexCompartmentBaselineFinalized');

  // Native compartment support is disabled only when the entire handshake is
  // absent. Any partial state is malformed and must fail closed.
  if (!hasRegistry && !hasRefresh && !hasReady && !hasFinalized) return true;

  function discardRefresh() {
    if (hasRefresh) {
      try { delete g.__ibexRefreshCompartmentBaseline; } catch (_) {}
    }
  }
  function validFinalizedMarker() {
    if (!owns('__ibexCompartmentBaselineFinalized') ||
        g.__ibexCompartmentBaselineFinalized !== true) return false;
    var descriptor = Object.getOwnPropertyDescriptor(
      g,
      '__ibexCompartmentBaselineFinalized'
    );
    return descriptor &&
      descriptor.value === true &&
      descriptor.writable === false &&
      descriptor.enumerable === false &&
      descriptor.configurable === false;
  }
  function validRegistry(expected) {
    return owns('__compartments') &&
      g.__compartments === expected &&
      typeof expected === 'object' && expected !== null &&
      owns('__ibexCompartmentRegistryReady') &&
      g.__ibexCompartmentRegistryReady === true;
  }

  if (!hasRegistry || !hasReady || !hasFinalized) {
    discardRefresh();
    return false;
  }

  var registry = g.__compartments;

  // A completed handshake is the idempotent path used by a repeated Windows
  // Runtime::load_runtime call. The native hook owns the final marker so Rust
  // never infers completion from mutable environment state.
  if (!hasRefresh) {
    return validRegistry(registry) && validFinalizedMarker();
  }

  var refresh = g.__ibexRefreshCompartmentBaseline;
  if ((typeof registry !== 'object' || registry === null) ||
      typeof refresh !== 'function' ||
      g.__ibexCompartmentRegistryReady !== true ||
      g.__ibexCompartmentBaselineFinalized !== false) {
    discardRefresh();
    return false;
  }

  try {
    refresh();
  } finally {
    try { delete g.__ibexRefreshCompartmentBaseline; } catch (_) {}
  }
  return validRegistry(registry) &&
    !owns('__ibexRefreshCompartmentBaseline') &&
    validFinalizedMarker();
})()"#;

pub(crate) async fn finalize_compartment_baseline(engine: &dyn Engine) -> Result<()> {
    let finalized = engine
        .eval_immediate(FINALIZE_COMPARTMENT_BASELINE)
        .await
        .context("trusted compartment baseline refresh failed")?;
    if !matches!(finalized.as_deref().map(str::trim), Some("true")) {
        anyhow::bail!(
            "compartment registry state was malformed or its trusted baseline was not finalized"
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn hermes_engine_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(Mutex::default)
}

fn contains_any_marker(bytes: &[u8], markers: &[&[u8]]) -> bool {
    markers
        .iter()
        .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

fn looks_like_ibex_runtime_bundle(bytes: &[u8]) -> bool {
    contains_any_marker(bytes, REQUIRED_RUNTIME_MARKERS)
}

fn normalize_hashbang_bytes(bytes: &[u8]) -> Cow<'_, [u8]> {
    if !bytes.starts_with(b"#!") {
        return Cow::Borrowed(bytes);
    }

    let mut normalized = bytes.to_vec();
    normalized[0] = b'/';
    normalized[1] = b'/';
    Cow::Owned(normalized)
}

// Embed the runtime bundle (HBC or JS) as static bytes compiled into the binary.
// Generated by build.rs — see embed_runtime_bundle() for details.
include!(concat!(env!("OUT_DIR"), "/embedded_runtime.rs"));

#[repr(C)]
struct HermesRuntimeOpaque {
    _private: [u8; 0],
}

#[cfg(all(test, feature = "module-runner"))]
#[repr(C)]
#[derive(Default)]
struct ExactModuleRunnerTestHandle {
    opaque: [u64; 3],
}

const WORK_UNIT_EVENT_ABI_VERSION: u32 = 1;
const CANCELLATION_EVENT_ABI_VERSION: u32 = 1;
const ASYNC_FAILURE_EVENT_ABI_VERSION: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NativeWorkUnitEvent {
    abi_version: u32,
    struct_size: u32,
    kind: u32,
    phase: u32,
    target_id: u64,
    scheduling_id: u64,
}

impl NativeWorkUnitEvent {
    fn current() -> Self {
        Self {
            abi_version: WORK_UNIT_EVENT_ABI_VERSION,
            struct_size: std::mem::size_of::<Self>() as u32,
            kind: 0,
            phase: 0,
            target_id: 0,
            scheduling_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NativeCancellationEvent {
    abi_version: u32,
    struct_size: u32,
    resolution: u32,
    reserved: u32,
    target_id: u64,
}

impl NativeCancellationEvent {
    fn current() -> Self {
        Self {
            abi_version: CANCELLATION_EVENT_ABI_VERSION,
            struct_size: std::mem::size_of::<Self>() as u32,
            resolution: 0,
            reserved: 0,
            target_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NativeAsyncFailureEvent {
    abi_version: u32,
    struct_size: u32,
    kind: u32,
    principal_status: u32,
    value_runtime_nonce: u64,
    value_handle_id: u64,
    host_context_id: u64,
    owning_principal_id: u64,
    event_id: u64,
    associated_evaluation: u64,
    dropped_count: u64,
}

impl NativeAsyncFailureEvent {
    fn current() -> Self {
        Self {
            abi_version: ASYNC_FAILURE_EVENT_ABI_VERSION,
            struct_size: std::mem::size_of::<Self>() as u32,
            kind: 0,
            principal_status: 0,
            value_runtime_nonce: 0,
            value_handle_id: 0,
            host_context_id: 0,
            owning_principal_id: 0,
            event_id: 0,
            associated_evaluation: 0,
            dropped_count: 0,
        }
    }
}

/// Mirror of the engine's `ExHermesExactIngressAttribution` (LLP 0053 §I1);
/// field order/widths must match include/exact_runtime.h exactly.
#[cfg(test)]
#[repr(C)]
#[derive(Clone, Copy)]
struct ExHermesExactIngressAttribution {
    abi_version: u32,
    struct_size: u32,
    context_kind: u32,
    carrier_status: u32,
    root_status: u32,
    principal_status: u32,
    runtime_nonce: u64,
    principal_id: u64,
    root_id: *const std::os::raw::c_char,
    root_id_len: usize,
}

extern "C" {
    fn ex_hermes_create_diagnostic() -> *mut HermesRuntimeOpaque;
    fn ex_hermes_create_armed(
        armed_snapshot_digest: *const std::os::raw::c_char,
    ) -> *mut HermesRuntimeOpaque;
    #[cfg(test)]
    fn ex_hermes_begin_embedder_capabilities_v1(runtime: *mut HermesRuntimeOpaque) -> i32;
    #[cfg(test)]
    fn ex_hermes_finalize_embedder_capabilities_v1(runtime: *mut HermesRuntimeOpaque) -> i32;
    #[cfg(test)]
    fn ex_hermes_begin_app_bundle_evaluation_v1(
        runtime: *mut HermesRuntimeOpaque,
        expected_prepared_disposition: u32,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_finish_app_bundle_evaluation_v1(
        runtime: *mut HermesRuntimeOpaque,
        evaluation_succeeded: u32,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_classify_prepared_native_startup_v1(
        runtime: *mut HermesRuntimeOpaque,
        expected_disposition: u32,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_stage_prepared_native_startup_v1(
        runtime: *mut HermesRuntimeOpaque,
        out_error: *mut *mut std::os::raw::c_char,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_run_prepared_app_v1(
        runtime: *mut HermesRuntimeOpaque,
        out_error: *mut *mut std::os::raw::c_char,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_verify_prepared_native_startup_absent_v1(runtime: *mut HermesRuntimeOpaque)
        -> i32;
    #[cfg(test)]
    fn ex_hermes_quarantine_runtime_v1(runtime: *mut HermesRuntimeOpaque) -> i32;
    #[cfg(test)]
    fn ex_hermes_runtime_is_quarantined_v1(runtime: *const HermesRuntimeOpaque) -> u32;
    fn ex_hermes_seal_armed_shared_runtime_globals_v1(runtime: *mut HermesRuntimeOpaque) -> u32;
    fn ibex_private_hermes_shared_runtime_bundle_installed_v1(
        runtime: *mut HermesRuntimeOpaque,
    ) -> i32;
    fn ex_hermes_finish_bootstrap(runtime: *mut HermesRuntimeOpaque) -> u32;
    fn ex_hermes_runtime_nonce(runtime: *mut HermesRuntimeOpaque) -> u64;
    #[cfg(feature = "module-runner")]
    fn ex_hermes_module_pin_generation(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        graph_generation: u64,
    ) -> i32;
    #[cfg(feature = "module-runner")]
    #[allow(dead_code)]
    fn ex_hermes_module_commit_hot_revision(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        graph_generation: u64,
        pair_count: u32,
        prior_record_ids: *const u64,
        successor_record_ids: *const u64,
        cache_keys: *const *const u8,
        cache_key_lengths: *const usize,
        cache_key_count: usize,
        retired_dev_served_ids: *const *const u8,
        retired_dev_served_id_lengths: *const usize,
        retired_dev_served_id_count: usize,
    ) -> i32;
    #[cfg(all(test, feature = "module-runner"))]
    fn ex_hermes_module_compile_factory(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        source_goal: u32,
        principal_id: u32,
        graph_generation: u64,
        compartment_identity: *const u8,
        compartment_identity_len: usize,
        semantic_digest: *const u8,
        semantic_digest_len: usize,
        source_id: *const u8,
        source_id_len: usize,
        factory_source: *const u8,
        factory_source_len: usize,
        source_label: *const u8,
        source_label_len: usize,
        out_factory: *mut ExactModuleRunnerTestHandle,
        out_error: *mut *mut std::os::raw::c_char,
        out_error_token: *mut u64,
    ) -> i32;
    #[cfg(all(test, feature = "module-runner"))]
    fn ex_hermes_commonjs_record_evaluate(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        record: ExactModuleRunnerTestHandle,
        out_evicted: *mut i32,
        out_error: *mut *mut std::os::raw::c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_destroy(runtime: *mut HermesRuntimeOpaque);
    fn ex_hermes_set_host_call(
        runtime: *mut HermesRuntimeOpaque,
        callback: extern "C" fn(
            op: *const std::os::raw::c_char,
            args_json: *const std::os::raw::c_char,
        ) -> *mut std::os::raw::c_char,
    );
    fn ex_hermes_set_host_call_async(
        runtime: *mut HermesRuntimeOpaque,
        callback: extern "C" fn(
            runtime: *mut HermesRuntimeOpaque,
            call_id: u64,
            op: *const std::os::raw::c_char,
            args_json: *const std::os::raw::c_char,
        ),
    );
    fn ex_hermes_resolve_host_call(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        payload: *const std::os::raw::c_char,
    );
    #[cfg(test)]
    fn ex_hermes_set_exact_host_call_async(
        runtime: *mut HermesRuntimeOpaque,
        context_kind: i32,
        allowed_operation_ids: *const u32,
        allowed_operation_count: usize,
        operation_manifest_digest: *const std::os::raw::c_char,
        callback: extern "C" fn(
            runtime: *mut HermesRuntimeOpaque,
            call_id: u64,
            operation_id: u32,
            payload: *const u8,
            payload_len: usize,
            context: *mut std::ffi::c_void,
        ),
        context: *mut std::ffi::c_void,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_set_exact_host_call_async_v2(
        runtime: *mut HermesRuntimeOpaque,
        context_kind: i32,
        allowed_operation_ids: *const u32,
        allowed_operation_count: usize,
        operation_manifest_digest: *const std::os::raw::c_char,
        callback: extern "C" fn(
            runtime: *mut HermesRuntimeOpaque,
            call_id: u64,
            operation_id: u32,
            payload: *const u8,
            payload_len: usize,
            carrier: *const u8,
            carrier_len: usize,
            attribution: *const ExHermesExactIngressAttribution,
            context: *mut std::ffi::c_void,
        ),
        context: *mut std::ffi::c_void,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_resolve_exact_host_call(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        status: i32,
        payload: *const u8,
        payload_len: usize,
    );
    fn ex_hermes_eval(
        runtime: *mut HermesRuntimeOpaque,
        data: *const u8,
        len: usize,
        source_url: *const std::os::raw::c_char,
        is_bytecode: i32,
        out_value: *mut *mut std::os::raw::c_char,
    ) -> i32;
    fn ex_hermes_free_string(value: *mut std::os::raw::c_char);
    fn ex_hermes_poll(runtime: *mut HermesRuntimeOpaque, now_ms: u64) -> i32;
    #[cfg(test)]
    fn ex_hermes_dispatch_event(
        runtime: *mut HermesRuntimeOpaque,
        handler_id: u32,
        payload_json: *const std::os::raw::c_char,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_callback_backlog(runtime: *mut HermesRuntimeOpaque) -> u32;
    #[cfg(test)]
    fn ex_hermes_schedule_watchdog_heartbeat_for_generation(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        callback: extern "C" fn(*mut std::ffi::c_void),
        context: *mut std::ffi::c_void,
    );
    fn ex_hermes_poll_with_external_keep_alive(
        runtime: *mut HermesRuntimeOpaque,
        now_ms: u64,
    ) -> i32;
    // Monotonic timer clock shared with the C++ scheduler (nowMs). See
    // current_time_ms() for why the Rust loop must not use its own clock.
    fn ex_hermes_now_ms() -> u64;
    fn ex_hermes_next_timer(runtime: *mut HermesRuntimeOpaque) -> i64;
    fn ex_hermes_has_pending_tasks(runtime: *mut HermesRuntimeOpaque) -> i32;
    fn ex_hermes_take_work_unit_event(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        event: *mut NativeWorkUnitEvent,
    ) -> u32;
    fn ex_hermes_take_cancellation_event(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        event: *mut NativeCancellationEvent,
    ) -> u32;
    fn ex_hermes_take_async_failure_event(
        runtime: *mut HermesRuntimeOpaque,
        event: *mut NativeAsyncFailureEvent,
    ) -> u32;
    fn ex_hermes_structured_active_work_target(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
    ) -> u64;
    fn ex_hermes_cancel_structured_work_target(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        work_target_id: u64,
    ) -> u32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ex_hermes_current_runtime_nonce() -> u64;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ex_hermes_current_principal_id() -> u64;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_private_test_reset_fs_conformance_observer();
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_private_test_set_requested_fs_authorization_result(result: i32);
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_private_test_set_requested_fs_authorization_result_for_path(
        result: i32,
        path: *const std::ffi::c_char,
    );
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_private_test_armed_path_lookup_count() -> u64;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_private_test_armed_path_lookup_after_refusal_count() -> u64;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_private_test_cancel_queued_fs_operations(runtime: *mut HermesRuntimeOpaque) -> u64;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_enable_work_unit_publication(runtime: *mut HermesRuntimeOpaque) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_fail_next_work_begin_after_cancellation(runtime: *mut HermesRuntimeOpaque) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_begin_module_graph_transition_probe(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
        scheduling_id: u64,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_begin_callback_during_module_graph_gap(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
        scheduling_id: u64,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_end_callback_during_module_graph_gap(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
        scheduling_id: u64,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_end_module_graph_transition_probe(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
        cooperative_cancellation: i32,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ex_hermes_structured_module_graph_suspend(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
    ) -> u32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ex_hermes_structured_module_graph_resume(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
    ) -> u32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_native_freeze_observation(
        runtime: *mut HermesRuntimeOpaque,
        out_mask: *mut u32,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_arm_builtin_source_observation(
        runtime: *mut HermesRuntimeOpaque,
        observation_id: *const std::os::raw::c_char,
        expected_alias: *const std::os::raw::c_char,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_take_builtin_source_observation(
        runtime: *mut HermesRuntimeOpaque,
    ) -> *mut std::os::raw::c_char;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_arm_loader_point_observation(
        runtime: *mut HermesRuntimeOpaque,
        observation_id: *const std::os::raw::c_char,
        expected_point: *const std::os::raw::c_char,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_take_loader_point_observation(
        runtime: *mut HermesRuntimeOpaque,
    ) -> *mut std::os::raw::c_char;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_enqueue_blocking_native_work(runtime: *mut HermesRuntimeOpaque) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_enqueue_runtime_principal_throw(runtime: *mut HermesRuntimeOpaque) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_structured_async_root_count(
        runtime: *mut HermesRuntimeOpaque,
        selector: u32,
    ) -> u64;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_direct_session_async_boundary(runtime: *mut HermesRuntimeOpaque) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_set_pending_promise_rejection_drop_count(
        runtime: *mut HermesRuntimeOpaque,
        count: u64,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_exact_runtime_c_abi_probe_cancel_then_release(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        target_id: u64,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_exact_runtime_c_abi_probe_release_blocking_work(
        runtime: *mut HermesRuntimeOpaque,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_exact_runtime_c_abi_probe_cancel_terminal(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        target_id: u64,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_arm_structured_control_lease_pause() -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_structured_control_lease_paused() -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_structured_control_teardown_wait_observed() -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_release_structured_control_lease_pause() -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_install_capsec_context_observer(
        runtime: *mut HermesRuntimeOpaque,
        global_name: *const std::os::raw::c_char,
        compartment_identity: *const std::os::raw::c_char,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_set_armed_startup_failure_stage(stage: *const std::os::raw::c_char);
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_set_diagnostic_startup_failure_stage(stage: *const std::os::raw::c_char);
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_set_root_global_disposition_key(key: *const std::os::raw::c_char);
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_fail_next_structured_safe_metadata_capture_allocation();
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_fail_next_structured_safe_metadata_copy_allocation();
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_root_global_disposition_getter_calls() -> u32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_root_global_disposition_last_failure() -> *const std::os::raw::c_char;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_embedder_capability_state_v1(runtime: *mut HermesRuntimeOpaque) -> u32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_root_global_logical_path_absent(
        runtime: *mut HermesRuntimeOpaque,
        path: *const std::os::raw::c_char,
    ) -> u32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_compartment_logical_path_absent(
        runtime: *mut HermesRuntimeOpaque,
        locator: *const std::os::raw::c_char,
        path: *const std::os::raw::c_char,
    ) -> u32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_observe_session_metadata(
        runtime: *mut HermesRuntimeOpaque,
        requested_names: *const *const std::os::raw::c_char,
        requested_name_count: usize,
    ) -> *mut std::os::raw::c_char;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_reset_exact_host_completion_observer();
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_exact_host_completion_observation(
        targets_consumed: *mut u64,
        callbacks_queued: *mut u64,
        callbacks_delivered: *mut u64,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_begin_module_runner_abi_observation();
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_take_module_runner_abi_observation() -> *mut std::os::raw::c_char;
    fn ex_hermes_debugger_enable(runtime: *mut HermesRuntimeOpaque) -> i32;
    fn ex_hermes_debugger_get_scripts(
        runtime: *mut HermesRuntimeOpaque,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_debugger_get_script_source(
        runtime: *mut HermesRuntimeOpaque,
        script_id: u32,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_debugger_set_breakpoint(
        runtime: *mut HermesRuntimeOpaque,
        script_id: u32,
        line_number: u32,
        column_number: u32,
        condition: *const std::os::raw::c_char,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_debugger_remove_breakpoint(runtime: *mut HermesRuntimeOpaque, breakpoint_id: u64);
    fn ex_hermes_debugger_pause(runtime: *mut HermesRuntimeOpaque);
    fn ex_hermes_debugger_resume(runtime: *mut HermesRuntimeOpaque, command: i32);
    fn ex_hermes_debugger_next_event(
        runtime: *mut HermesRuntimeOpaque,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_debugger_eval(
        runtime: *mut HermesRuntimeOpaque,
        expression: *const std::os::raw::c_char,
        frame_index: u32,
    ) -> *mut std::os::raw::c_char;
    fn ex_host_http_has_referenced() -> i32;
    fn ex_host_http_has_pending_requests() -> i32;
    fn native_ws_has_active() -> i32;
}

fn decode_work_unit_event(native: NativeWorkUnitEvent) -> Result<AuthenticatedWorkUnitEvent> {
    let kind = match native.kind {
        1 => AuthenticatedWorkUnitKind::Evaluation,
        2 => AuthenticatedWorkUnitKind::Callback,
        3 => AuthenticatedWorkUnitKind::Timer,
        4 => AuthenticatedWorkUnitKind::MicrotaskDrain,
        5 => AuthenticatedWorkUnitKind::CompletionQuery,
        value => anyhow::bail!("Hermes published unknown work-unit kind {value}"),
    };
    let phase = match native.phase {
        1 => AuthenticatedWorkUnitPhase::Due,
        2 => AuthenticatedWorkUnitPhase::Undue,
        3 => AuthenticatedWorkUnitPhase::Begin,
        4 => AuthenticatedWorkUnitPhase::Suspended,
        5 => AuthenticatedWorkUnitPhase::End,
        value => anyhow::bail!("Hermes published unknown work-unit phase {value}"),
    };
    match phase {
        AuthenticatedWorkUnitPhase::Due | AuthenticatedWorkUnitPhase::Undue => {
            if kind != AuthenticatedWorkUnitKind::Timer
                || native.target_id != 0
                || native.scheduling_id == 0
            {
                anyhow::bail!("Hermes published a malformed timer scheduling transition");
            }
        }
        AuthenticatedWorkUnitPhase::Begin
        | AuthenticatedWorkUnitPhase::Suspended
        | AuthenticatedWorkUnitPhase::End => {
            if native.target_id == 0 {
                anyhow::bail!("Hermes published a targetless work-unit transition");
            }
        }
    }
    Ok(AuthenticatedWorkUnitEvent {
        target_id: native.target_id,
        scheduling_id: native.scheduling_id,
        kind,
        phase,
    })
}

fn decode_cancellation_event(
    native: NativeCancellationEvent,
) -> Result<AuthenticatedCancellationEvent> {
    anyhow::ensure!(
        native.abi_version == CANCELLATION_EVENT_ABI_VERSION
            && native.struct_size == std::mem::size_of::<NativeCancellationEvent>() as u32
            && native.reserved == 0
            && native.target_id != 0,
        "Hermes published a malformed terminal cancellation record"
    );
    let resolution = match native.resolution {
        1 => AuthenticatedCancellationResolution::Accepted,
        3 => AuthenticatedCancellationResolution::Failed,
        4 => AuthenticatedCancellationResolution::Defeated,
        value => anyhow::bail!("Hermes published unknown cancellation resolution {value}"),
    };
    Ok(AuthenticatedCancellationEvent {
        target_id: native.target_id,
        resolution,
    })
}

fn async_failure_event_identity(kind: u32, event_id: u64) -> Result<String> {
    let label = match kind {
        1 => "timer",
        2 => "next-tick",
        3 => "microtask",
        4 => "native-completion",
        5 => "native-task",
        value => anyhow::bail!("Hermes published unknown asynchronous failure kind {value}"),
    };
    Ok(if event_id == 0 {
        format!("{label}:unavailable")
    } else {
        format!("{label}:{event_id}")
    })
}

fn async_failure_owner(native: &NativeAsyncFailureEvent) -> Result<AuthenticatedAsyncFailureOwner> {
    match native.principal_status {
        1 => Ok(
            ibex_runtime::host::abi::authenticated_principal_for_host_context(
                native.host_context_id,
                native.value_runtime_nonce,
                native.owning_principal_id,
            )
            .map(|principal| AuthenticatedAsyncFailureOwner::Authenticated { principal })
            .unwrap_or(AuthenticatedAsyncFailureOwner::Unavailable),
        ),
        2 => Ok(AuthenticatedAsyncFailureOwner::Unavailable),
        3 => Ok(AuthenticatedAsyncFailureOwner::Ambiguous),
        value => {
            anyhow::bail!("Hermes published unknown asynchronous failure principal status {value}")
        }
    }
}

// Event loop notification: wakes the event loop when a callback is pushed
// from C++ (e.g. HTTP request arrives, timer fires, etc.)
static CALLBACK_NOTIFY: OnceLock<Arc<Notify>> = OnceLock::new();

fn callback_notify() -> &'static Arc<Notify> {
    CALLBACK_NOTIFY.get_or_init(|| Arc::new(Notify::new()))
}

// (ENG-23234/ENG-24265) The library owns the sole
// ex_hermes_notify_callback symbol in every feature profile. The CLI
// registers this runtime hook to bridge it to tokio; a cross-thread
// callback push (fetch/WS completion, HTTP request — and now signal
// dispatch) sat queued until the next due timer expired, so an external
// SIGINT to a parked runtime was not delivered until that timer fired.
// Runtime registration avoids mutually-exclusive global definitions and is
// link-safe for library, CLI, unit, integration, and all-feature builds.
extern "C" fn cli_wake_hook(_context: *mut std::ffi::c_void) {
    callback_notify().notify_one();
}

fn register_default_profile_wake_hook() {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        ibex_runtime::engine::ex_hermes_set_host_wake_hook(
            Some(cli_wake_hook),
            std::ptr::null_mut(),
        );
    });
}

async fn wait_for_callback_or_sleep(duration: std::time::Duration) {
    tokio::select! {
        _ = callback_notify().notified() => {},
        _ = tokio::time::sleep(duration) => {},
    }
}

// How long the event loop parks when host work is pending but no timer is due
// (e.g. an idle `Bun.serve` server waiting for the next request). There is no
// deadline to wait for here, only an external event, so the park duration is a
// wakeup-safety fallback rather than a poll cadence.
//
// With `cli-notify` every cross-thread callback push signals the loop
// (pushRuntimeCallback + the HTTP server both call ex_hermes_notify_callback),
// so we park until notified and only re-poll after a long safety interval in the
// (should-be-impossible) case a notification was missed. Parking a fixed 5 ms
// here instead made an idle server re-poll ~200×/sec forever, each iteration
// taking the tokio Mutex, the ffi_lock, and four FFI calls.
//
// Without `cli-notify` the wakeup source is the host wake hook registered by
// register_default_profile_wake_hook (ENG-23234) — every callback push still
// signals the parked select! — but the short interval is kept as a
// conservative safety net for that profile.
#[cfg(feature = "cli-notify")]
const IDLE_PARK: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(not(feature = "cli-notify"))]
const IDLE_PARK: std::time::Duration = std::time::Duration::from_millis(5);

// Upper bound on how long the REPL-EOF drain (`drain_event_loop`) runs before
// giving up. At EOF we flush work that is ready now and one-shots already due,
// but a referenced perpetual `setInterval`/a self-rescheduling 0-delay timer
// stays "pending" forever; this deadline stops Ctrl+D from hanging on it.
// @ref LLP 0003#the-event-loop — the host drives Hermes by polling; at EOF that
// drive must be bounded. (ENG-23030 #1)
const EOF_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_millis(200);

// Maximum `ex_hermes_poll` calls per idle pump (`pump_ready_tasks`). A
// self-rescheduling 0-delay timer (`setInterval(fn,0)` / `setTimeout(tick,0)`)
// is due on every poll, so without a bound the pump never returns and starves
// the REPL select! of the chance to read the next line. The next idle tick
// pumps again, so the timer still runs — it just no longer locks out input.
// (ENG-23030 #3)
const PUMP_MAX_POLLS_PER_TICK: usize = 1024;

// Floor for the REPL idle park so a due-soon (or 0-delay) timer cannot make the
// prompt busy-spin; mirrors the pre-ENG-23030 fixed pump cadence. (ENG-23030 #5)
const REPL_PARK_FLOOR: std::time::Duration = std::time::Duration::from_millis(50);

fn host_call_response(payload: String) -> *mut std::os::raw::c_char {
    match CString::new(payload) {
        Ok(value) => value.into_raw(),
        Err(_) => CString::new("-Host call response contained interior nulls")
            .expect("valid fallback host-call error")
            .into_raw(),
    }
}

#[cfg(all(test, feature = "capsec-conformance-observer"))]
/// Test-only in-process typed adapter. It is deliberately not routed through
/// `exact_agent_host_call` or exposed as a JavaScript global.
fn evaluate_capsec_conformance_adapter(args: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Request {
        terminal_branch_id: String,
        decision_set_json: String,
        gates_json: String,
    }

    let request_value = capsec_semantics::strict_json::parse_strict(args)
        .map_err(|error| anyhow!("invalid conformance adapter request: {error}"))?;
    let request: Request =
        serde_json::from_value(request_value).context("malformed conformance adapter request")?;
    if request.terminal_branch_id.is_empty() {
        anyhow::bail!("conformance adapter request has no terminal branch id");
    }
    if !ibex_runtime::host::abi::begin_installed_conformance_observation(
        &request.terminal_branch_id,
    ) {
        anyhow::bail!("conformance adapter has no installed host");
    }
    let response = unsafe {
        ibex_runtime::host::abi::ex_host_evaluate_typed_decision(
            request.decision_set_json.as_ptr(),
            request.decision_set_json.len(),
            request.gates_json.as_ptr(),
            request.gates_json.len(),
        )
    };
    if response.is_null() {
        let _ = ibex_runtime::host::abi::take_installed_conformance_observations();
        anyhow::bail!("typed decision adapter returned no response");
    }
    let response_text = unsafe { CStr::from_ptr(response) }
        .to_string_lossy()
        .into_owned();
    ibex_runtime::host::abi::ex_host_free_string(response);
    let (legacy_observations, typed_observations) =
        ibex_runtime::host::abi::take_installed_conformance_observations();
    // Read these on the runtime thread while the host call's exact JS frame and
    // any scoped native callback principal are still live. Callback-invariant
    // public evidence uses them to bind the typed request to the actual engine
    // execution context instead of trusting the actor encoded in JSON.
    // @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence
    let execution_context = unsafe {
        serde_json::json!({
            "principalId": format!("u64:{}", ex_hermes_current_principal_id()),
            "runtimeNonce": format!("u64:{}", ex_hermes_current_runtime_nonce()),
        })
    };
    let adapter = capsec_semantics::strict_json::parse_strict(&response_text)
        .map_err(|error| anyhow!("typed decision adapter returned invalid JSON: {error}"))?;
    serde_json::to_string(&serde_json::json!({
        "adapter": adapter,
        "legacyObservations": legacy_observations,
        "typedObservations": typed_observations,
        "executionContext": execution_context,
    }))
    .context("conformance adapter response serialization failed")
}

/// Generic string-dispatch handler retained for unarmed diagnostic runtimes.
/// Armed runtimes reject its installation at the native ABI boundary.
extern "C" fn exact_agent_host_call(
    op: *const std::os::raw::c_char,
    args_json: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    if op.is_null() {
        return host_call_response("-Missing host call operation".to_string());
    }

    let operation = unsafe { CStr::from_ptr(op) }.to_string_lossy().into_owned();
    let args = if args_json.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(args_json) }
            .to_string_lossy()
            .into_owned()
    };

    match crate::agent_logs::handle_host_call(&operation, &args) {
        Ok(json) => host_call_response(format!("+{json}")),
        Err(message) => host_call_response(format!("-{message}")),
    }
}

/// Async host-call handler for unarmed diagnostic runtimes (LLP 0297 W3). The
/// CLI host has no cross-thread hop to make, so it services the same op table
/// as the sync bridge and resolves inline; resolution still flows through the
/// runtime callback queue. Armed runtimes reject installation and resolution
/// at the C++ ABI boundary.
extern "C" fn exact_agent_host_call_async(
    runtime: *mut HermesRuntimeOpaque,
    call_id: u64,
    op: *const std::os::raw::c_char,
    args_json: *const std::os::raw::c_char,
) {
    let payload = if op.is_null() {
        "-Missing host call operation".to_string()
    } else {
        let operation = unsafe { CStr::from_ptr(op) }.to_string_lossy().into_owned();
        let args = if args_json.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(args_json) }
                .to_string_lossy()
                .into_owned()
        };
        match crate::agent_logs::handle_host_call(&operation, &args) {
            Ok(json) => format!("+{json}"),
            Err(message) => format!("-{message}"),
        }
    };

    let payload_c = CString::new(payload).unwrap_or_else(|_| {
        CString::new("-Host call response contained interior nulls")
            .expect("valid fallback host-call error")
    });
    unsafe { ex_hermes_resolve_host_call(runtime, call_id, payload_c.as_ptr()) };
}

fn workspace_root_from(start: &Path) -> Option<PathBuf> {
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
            Some(ancestor.to_path_buf())
        } else {
            None
        }
    })
}

fn runtime_workspace_roots() -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();

    if let Some(raw) =
        std::env::var_os("IBEX_REPO_ROOT").or_else(|| std::env::var_os("EXACT_REPO_ROOT"))
    {
        let candidate = PathBuf::from(raw);
        if !candidate.is_absolute() {
            anyhow::bail!("IBEX_REPO_ROOT must be an absolute authenticated directory");
        }
        let root = workspace_root_from(&candidate)
            .and_then(|root| std::fs::canonicalize(root).ok())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "IBEX_REPO_ROOT does not identify an Ibex checkout: {}",
                    candidate.display()
                )
            })?;
        return Ok(vec![root]);
    }

    // The compile-time checkout is authenticated by the build. Never inspect
    // the application cwd or its ancestors: a project can create a lookalike
    // workspace and otherwise select executable runtime bootstrap code.
    if let Some(found) = workspace_root_from(Path::new(env!("CARGO_MANIFEST_DIR")))
        .and_then(|root| std::fs::canonicalize(root).ok())
    {
        roots.push(found);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(found) =
            workspace_root_from(&exe_path).and_then(|root| std::fs::canonicalize(root).ok())
        {
            if !roots.contains(&found) {
                roots.push(found);
            }
        }
    }

    if roots.is_empty() {
        anyhow::bail!(
            "Failed to resolve an authenticated Ibex runtime root. Set IBEX_REPO_ROOT to an absolute trusted checkout"
        );
    }
    Ok(roots)
}

fn target_arch_to_hermes_dir(arch: &str) -> &str {
    match arch {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" | "i686" => "x86",
        other => other,
    }
}

fn local_hermes_tool_candidates(tools: &Path, tool: &str) -> Vec<PathBuf> {
    let target_os = std::env::consts::OS;
    let target_arch = target_arch_to_hermes_dir(std::env::consts::ARCH);
    let mut candidates = vec![tools.join(tool)];
    if target_os == "windows" {
        candidates.push(tools.join(format!("{tool}.exe")));
        candidates.push(
            tools
                .join(format!("windows-{target_arch}"))
                .join("bin")
                .join(format!("{tool}.exe")),
        );
    } else {
        candidates.push(tools.join(format!("{tool}-{target_os}-{target_arch}")));
    }
    candidates
}

/// Directories from which production may execute an external Hermes tool.
/// An explicit operator-selected directory takes precedence. Otherwise only
/// the Ibex build checkout and executable-relative installation locations are
/// considered; the application cwd, its ancestors, PATH, and HOME are never
/// executable discovery roots (ENG-24254).
fn trusted_hermes_tool_roots() -> Result<Vec<PathBuf>> {
    if let Some(raw) = std::env::var_os("IBEX_HERMES_TOOL_DIR")
        .or_else(|| std::env::var_os("EXACT_HERMES_TOOL_DIR"))
    {
        let root = PathBuf::from(raw);
        if !root.is_absolute() {
            anyhow::bail!("IBEX_HERMES_TOOL_DIR must be an absolute directory");
        }
        let canonical = std::fs::canonicalize(&root).with_context(|| {
            format!(
                "Failed to authenticate explicit Hermes tool directory {}",
                root.display()
            )
        })?;
        if !canonical.is_dir() {
            anyhow::bail!(
                "IBEX_HERMES_TOOL_DIR is not a directory: {}",
                canonical.display()
            );
        }
        return Ok(vec![canonical]);
    }

    let mut roots = Vec::new();
    let build_tools = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tools")
        .join("hermes");
    if let Ok(root) = std::fs::canonicalize(build_tools) {
        roots.push(root);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            for candidate in [
                bin_dir.join("hermes-tools"),
                bin_dir.join("../libexec/ibex"),
            ] {
                if let Ok(root) = std::fs::canonicalize(candidate) {
                    if !roots.contains(&root) {
                        roots.push(root);
                    }
                }
            }
        }
    }
    Ok(roots)
}

fn discover_hermes_tool_in_roots(tool: &str, roots: &[PathBuf]) -> Result<PathBuf> {
    let mut matches = Vec::new();
    for root in roots {
        let canonical_root = std::fs::canonicalize(root).with_context(|| {
            format!("Failed to authenticate Hermes tool root {}", root.display())
        })?;
        for candidate in local_hermes_tool_candidates(&canonical_root, tool) {
            if !candidate.is_file() {
                continue;
            }
            let canonical = std::fs::canonicalize(&candidate).with_context(|| {
                format!("Failed to authenticate Hermes tool {}", candidate.display())
            })?;
            if !canonical.starts_with(&canonical_root) {
                anyhow::bail!(
                    "Hermes tool {} escapes authenticated root {}",
                    canonical.display(),
                    canonical_root.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if std::fs::metadata(&canonical)?.permissions().mode() & 0o111 == 0 {
                    anyhow::bail!("Hermes tool is not executable: {}", canonical.display());
                }
            }
            if !matches.contains(&canonical) {
                matches.push(canonical);
            }
        }
    }
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => anyhow::bail!(
            "Hermes {tool} not found in an authenticated install location. Run ./scripts/download-hermes.sh or set IBEX_HERMES_TOOL_DIR to an absolute trusted directory"
        ),
        paths => anyhow::bail!(
            "Ambiguous Hermes {tool} installation; refusing to choose among: {}",
            paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Find the Hermes binary
pub(crate) fn find_hermes_binary() -> Result<PathBuf> {
    discover_hermes_tool_in_roots("hermes", &trusted_hermes_tool_roots()?)
}

/// Find the hermesc compiler
fn find_hermesc_binary() -> Result<PathBuf> {
    discover_hermes_tool_in_roots("hermesc", &trusted_hermes_tool_roots()?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HermesToolIdentity {
    path: PathBuf,
    bytes: Arc<Vec<u8>>,
    sha256: String,
    length: u64,
    modified_nanos: u128,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl HermesToolIdentity {
    fn capture(path: &Path) -> Result<Self> {
        let path = std::fs::canonicalize(path)
            .with_context(|| format!("Failed to authenticate Hermes tool {}", path.display()))?;
        path.to_str()
            .context("Hermes tool paths must be valid UTF-8")?;
        // Bind bytes and metadata to one opened file object. Reading the path
        // and then stat'ing it allowed a replacement between those syscalls to
        // produce a mixed identity.
        let mut file = std::fs::File::open(&path)
            .with_context(|| format!("Failed to open Hermes tool {}", path.display()))?;
        let metadata = file.metadata()?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        std::io::Read::read_to_end(&mut file, &mut bytes)?;
        let modified_nanos = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            path,
            bytes: Arc::new(bytes.clone()),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            length: metadata.len(),
            modified_nanos,
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        })
    }

    fn verify_selected_path(&self) -> Result<()> {
        let current = Self::capture(&self.path)?;
        if &current != self {
            anyhow::bail!(
                "Hermes tool changed after selection: {}",
                self.path.display()
            );
        }
        Ok(())
    }

    fn cache_fingerprint(&self) -> String {
        #[cfg(unix)]
        let object = format!("{}:{}", self.device, self.inode);
        #[cfg(not(unix))]
        let object = String::new();
        format!(
            "{}\0{}\0{}\0{}\0{}",
            self.path
                .to_str()
                .expect("HermesToolIdentity rejects non-UTF-8 paths"),
            self.sha256,
            self.length,
            self.modified_nanos,
            object
        )
    }
}

struct StagedHermesTool(PathBuf);

impl Drop for StagedHermesTool {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn stage_authenticated_hermes_tool(identity: &HermesToolIdentity) -> Result<StagedHermesTool> {
    let stage_dir = temporary_output_path(&std::env::temp_dir().join("ibex-hermes-tool"));
    std::fs::create_dir(&stage_dir)
        .with_context(|| format!("Failed to create Hermes tool stage {}", stage_dir.display()))?;
    let staged_path = stage_dir.join(if cfg!(windows) {
        "hermes.exe"
    } else {
        "hermes"
    });
    std::fs::write(&staged_path, identity.bytes.as_slice())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(0o700))?;
    }
    let staged_digest = format!("{:x}", Sha256::digest(std::fs::read(&staged_path)?));
    if staged_digest != identity.sha256 {
        anyhow::bail!("Hermes runtime tool changed while staging authenticated bytes");
    }
    Ok(StagedHermesTool(stage_dir))
}

fn find_hermesc_identity() -> Result<HermesToolIdentity> {
    HermesToolIdentity::capture(&find_hermesc_binary()?)
}

/// Find the runtime bundle
fn find_runtime_bundle() -> Result<PathBuf> {
    // Use the committed Ibex runtime bundle by default.
    let candidates = ["vendored-generated/embedded_runtime_bundle.js"];

    for base_path in runtime_workspace_roots()? {
        for search_root in runtime_bundle_search_roots(&base_path) {
            for candidate in &candidates {
                let path = search_root.join(candidate);
                if !path.exists() {
                    continue;
                }
                let authenticated = std::fs::canonicalize(&path).with_context(|| {
                    format!("Failed to authenticate runtime bundle {}", path.display())
                })?;
                if !authenticated.starts_with(&base_path) || !authenticated.is_file() {
                    anyhow::bail!(
                        "Runtime bundle {} escapes authenticated root {}",
                        authenticated.display(),
                        base_path.display()
                    );
                }
                return Ok(authenticated);
            }
        }
    }

    anyhow::bail!(
        "Runtime bundle not found. Please build it:\n  \
        IBEX_REGENERATE_RUNTIME=1 IBEX_UPDATE_VENDORED_GENERATED=1 cargo build"
    )
}

fn runtime_bundle_search_roots(base_path: &Path) -> Vec<PathBuf> {
    vec![base_path.to_path_buf()]
}

const ARMED_INSPECTOR_CLOSED_MESSAGE: &str =
    "armed capability runtime closes inspector activation and configuration";

/// Proof that an inspector start originated from an unarmed diagnostic
/// engine. The private field prevents another production module from calling
/// the CDP listener directly without first passing Hermes's armed-state guard.
pub(crate) struct UnarmedInspectorAuthorization(());

#[cfg(test)]
pub(crate) const fn unarmed_inspector_authorization_for_test() -> UnarmedInspectorAuthorization {
    UnarmedInspectorAuthorization(())
}

/// The Hermes engine implementation
pub struct HermesEngine {
    runtime_loaded: Mutex<bool>,
    runtime: Mutex<Option<RuntimeHandle>>,
    cancellation_runtime: std::sync::Mutex<Option<std::sync::Weak<SharedRuntime>>>,
    cdp_handle: Mutex<Option<cdp::CdpServerHandle>>,
    bytecode_compile_tasks: std::sync::Mutex<Vec<JoinHandle<()>>>,
    thread_id: std::thread::ThreadId,
    debugger_requested: Arc<AtomicBool>,
    debugger_enabled: AtomicBool,
    debugger_warned: AtomicBool,
    process_bootstrap_wires_closed: AtomicBool,
    armed_snapshot_digest: Option<String>,
    loop_trace_enabled: bool,
    startup_trace_enabled: bool,
}

struct RuntimeHandle {
    shared: Arc<SharedRuntime>,
}

#[cfg(feature = "module-runner")]
struct RetainedModuleActivationState {
    // Drop the native callback registration before its borrowed state.
    commonjs_require_provider:
        Option<ibex_runtime::engine::module_runner::NativeCommonJsRequireProviderRegistration>,
    source_graph: ibex_runtime::module_loader::runner_pipeline::SourceModuleGraphV1,
    native_graph: ibex_runtime::engine::module_runner::NativePublishedGraphIndex,
}

#[cfg(feature = "module-runner")]
fn activate_retained_commonjs_require(
    state: &mut RetainedModuleActivationState,
    native_runtime: &ibex_runtime::engine::module_runner::NativeModuleRuntime<'_>,
    request: ibex_runtime::engine::module_runner::CommonJsRequireActivationRequest,
) -> Result<ibex_runtime::engine::module_runner::NativeCommonJsRequireActivationTarget> {
    use ibex_runtime::module_loader::security::ModuleGraphAuthorizer;

    let generation = request.graph_generation();
    let checkpoint = state.source_graph.activation_checkpoint();
    let activation = (|| {
        let target = state.source_graph.activate_commonjs_require_target(
            &request.requester,
            &request.specifier,
            generation,
        )?;
        let plan = state.source_graph.plan()?;
        let (configs, contexts) = state.source_graph.native_execution_inputs(generation)?;
        let deferred = state.source_graph.deferred_dynamic_links();
        let prepared = state.source_graph.available_prepared_entries()?;
        let authorizer = ModuleGraphAuthorizer::new(state.source_graph.snapshot());
        state.native_graph.publish_authorized_require_activation(
            native_runtime,
            &plan,
            &request,
            &target,
            configs,
            &authorizer,
            &contexts,
            &deferred,
            Some(&prepared),
        )
    })();
    if activation.is_err() {
        state.source_graph.rollback_activation(checkpoint);
    }
    activation
}

#[cfg(feature = "module-runner")]
impl RetainedModuleActivationState {
    fn install_commonjs_require_provider(
        &mut self,
        native_runtime: &ibex_runtime::engine::module_runner::NativeModuleRuntime<'_>,
    ) -> Result<()> {
        let deferred = self.source_graph.deferred_dynamic_links();
        if !deferred
            .values()
            .any(|bindings| !bindings.commonjs_require_specifiers.is_empty())
        {
            return Ok(());
        }
        let generation = self.native_graph.graph_generation();
        let state = NonNull::from(&mut *self);
        // SAFETY: this state is already inside a stable Box before
        // registration, owns the returned token as its first field, and is
        // retained until that token clears the native callback.
        self.commonjs_require_provider = Some(unsafe {
            native_runtime.install_commonjs_require_provider(
                generation,
                state,
                activate_retained_commonjs_require,
            )?
        });
        Ok(())
    }
}

struct SharedRuntime {
    raw: AtomicPtr<HermesRuntimeOpaque>,
    // Native structured controls and Rust-owned session ingress carry the
    // generation captured while this handle was live. Never recover a nonce
    // from `raw` at call time: after allocator reuse that would authenticate a
    // stale pointer as its successor.
    // @ref LLP 0025#6-interruption-and-cancellation — control identity is the
    // captured pointer-plus-generation pair, retained for the handle lifetime.
    // @ref LLP 0023#71-identity-not-text--and-a-runtime-handle — VFS state is
    // selected by the exact authenticated runtime generation, never spelling.
    runtime_nonce: std::num::NonZeroU64,
    // Native graph records belong to the runtime/session generation, not one
    // initial quiescence pass. Keep generation 1 pinned until runtime teardown
    // so `--keep-alive` can later run unref'd timers and delayed imports.
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    module_generation_pinned: AtomicU64,
    #[cfg(feature = "module-runner")]
    retained_module_activations: std::sync::Mutex<Vec<Box<RetainedModuleActivationState>>>,
    // Hermes/JSI values have thread-affine destruction. Keep the creator here
    // as a Rust-side fail-safe so a legal `Arc<dyn Engine + Send + Sync>` last
    // drop on another thread leaks the native runtime instead of crossing the
    // C ABI and terminating the process. Full reclamation still requires an
    // explicit owner-thread teardown handoff.
    // @ref LLP 0003#the-event-loop — Hermes is driven and destroyed on one owner thread.
    owner_thread: std::thread::ThreadId,
    // Serializes runtime-thread FFI (`ex_hermes_eval`/`ex_hermes_poll`) and
    // gates destruction against it. CDP debugger ops deliberately do NOT take
    // this lock — see `with_debugger`.
    ffi_lock: std::sync::Mutex<()>,
    // Count of in-flight CDP debugger-thread FFI calls. Debugger ops run without
    // `ffi_lock` (so they can't deadlock against a JS thread parked at a
    // breakpoint while holding `ffi_lock`, or against the runtime thread they
    // must interrupt); `shutdown` instead nulls the pointer and drains this
    // counter before freeing, so no debugger op ever touches a freed runtime.
    // (ENG-22958)
    debugger_inflight: AtomicUsize,
}

/// Owner-thread lease over the live runtime pointer. The native graph future
/// deliberately retains this lease across TLA waits: its local (non-Send)
/// future cannot migrate threads, and abort drops graph handles plus the
/// structured guard before releasing the FFI serialization lock.
struct OwnerRuntimeLease<'a> {
    raw: *mut HermesRuntimeOpaque,
    _guard: std::sync::MutexGuard<'a, ()>,
}

impl OwnerRuntimeLease<'_> {
    fn raw(&self) -> *mut HermesRuntimeOpaque {
        self.raw
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "runtime shutdown may be rejected when called off the owner thread"]
enum RuntimeShutdown {
    Destroyed,
    NotLive,
    WrongThread,
}

/// Decrements the in-flight debugger counter on scope exit (incl. early return
/// through `?`), so a bailing or failing debugger op can never leave `shutdown`
/// spinning forever.
struct DebuggerInflightGuard<'a>(&'a AtomicUsize);

impl Drop for DebuggerInflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl SharedRuntime {
    fn new(armed_snapshot_digest: Option<&str>) -> Result<Self> {
        let digest = armed_snapshot_digest
            .map(CString::new)
            .transpose()
            .context("armed snapshot digest contains an interior NUL")?;
        let raw = unsafe {
            match digest.as_ref() {
                Some(digest) => ex_hermes_create_armed(digest.as_ptr()),
                None => ex_hermes_create_diagnostic(),
            }
        };
        if raw.is_null() {
            if armed_snapshot_digest.is_some() {
                anyhow::bail!(
                    "Failed to create Hermes runtime: armed snapshot handshake was rejected"
                );
            }
            anyhow::bail!("Failed to create Hermes runtime");
        }
        let Some(runtime_nonce) =
            std::num::NonZeroU64::new(unsafe { ex_hermes_runtime_nonce(raw) })
        else {
            unsafe { ex_hermes_destroy(raw) };
            anyhow::bail!("Failed to create Hermes runtime: live generation nonce was unavailable");
        };
        unsafe {
            ex_hermes_set_host_call(raw, exact_agent_host_call);
            ex_hermes_set_host_call_async(raw, exact_agent_host_call_async);
        }
        Ok(Self {
            raw: AtomicPtr::new(raw),
            runtime_nonce,
            module_generation_pinned: AtomicU64::new(0),
            #[cfg(feature = "module-runner")]
            retained_module_activations: std::sync::Mutex::new(Vec::new()),
            owner_thread: std::thread::current().id(),
            ffi_lock: std::sync::Mutex::new(()),
            debugger_inflight: AtomicUsize::new(0),
        })
    }

    /// Runtime-thread FFI (eval/poll/enable). Serialized by `ffi_lock`; only
    /// ever called from the runtime's owning thread.
    fn with_runtime<T>(&self, f: impl FnOnce(*mut HermesRuntimeOpaque) -> T) -> Result<T> {
        if std::thread::current().id() != self.owner_thread {
            anyhow::bail!("Hermes runtime operation must run on its owner thread");
        }
        let _guard = match self.ffi_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let raw = self.raw.load(Ordering::SeqCst);
        if raw.is_null() {
            anyhow::bail!("Hermes runtime has been shut down");
        }
        Ok(f(raw))
    }

    fn owner_runtime_lease(&self) -> Result<OwnerRuntimeLease<'_>> {
        if std::thread::current().id() != self.owner_thread {
            anyhow::bail!("Hermes runtime operation must run on its owner thread");
        }
        let guard = match self.ffi_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let raw = self.raw.load(Ordering::SeqCst);
        if raw.is_null() {
            anyhow::bail!("Hermes runtime has been shut down");
        }
        Ok(OwnerRuntimeLease { raw, _guard: guard })
    }

    fn finish_bootstrap(&self) -> Result<()> {
        let fault = self.with_runtime(|raw| unsafe { ex_hermes_finish_bootstrap(raw) })?;
        if fault != 0 {
            anyhow::bail!("Hermes refused to seal armed bootstrap (fault {fault})");
        }
        Ok(())
    }

    fn seal_armed_shared_runtime_globals(&self) -> Result<()> {
        let fault = self
            .with_runtime(|raw| unsafe { ex_hermes_seal_armed_shared_runtime_globals_v1(raw) })?;
        if fault != 0 {
            anyhow::bail!(
                "Hermes refused the named armed shared-runtime global seal (fault {fault})"
            );
        }
        Ok(())
    }

    #[cfg(feature = "module-runner")]
    fn ensure_module_generation_pinned(
        &self,
        lease: &OwnerRuntimeLease<'_>,
        nonce: u64,
        generation: u64,
    ) -> Result<()> {
        let pinned = self.module_generation_pinned.load(Ordering::Acquire);
        if pinned != 0 {
            anyhow::ensure!(
                pinned == generation,
                "Hermes runtime already owns module generation {pinned}, not {generation}"
            );
            return Ok(());
        }
        let raw = lease.raw();
        anyhow::ensure!(
            self.raw.load(Ordering::Acquire) == raw,
            "Hermes runtime changed before module generation pin"
        );
        let status = unsafe { ex_hermes_module_pin_generation(raw, nonce, generation) };
        if status != 0 {
            anyhow::bail!("native module graph generation pin refused ({status})");
        }
        self.module_generation_pinned
            .store(generation, Ordering::Release);
        Ok(())
    }

    #[cfg(feature = "module-runner")]
    fn retain_module_activation_state(
        &self,
        state: Box<RetainedModuleActivationState>,
    ) -> Result<()> {
        let pinned = self.module_generation_pinned.load(Ordering::Acquire);
        anyhow::ensure!(
            pinned != 0 && pinned == state.native_graph.graph_generation(),
            "retained module activation graph does not belong to the pinned generation"
        );
        let mut retained = self
            .retained_module_activations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retained.push(state);
        Ok(())
    }

    /// Resolve and publish requests minted by graphs whose foreground
    /// evaluation has already settled. The caller holds `ffi_lock`; this
    /// routine never reacquires it and routes each request by its exact native
    /// requester handle before touching the retained resolver state.
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    #[cfg(feature = "module-runner")]
    fn drive_retained_module_activations_locked(
        &self,
        raw: *mut HermesRuntimeOpaque,
    ) -> Result<usize> {
        use ibex_runtime::engine::module_runner::NativeModuleRuntime;
        use ibex_runtime::module_loader::security::ModuleGraphAuthorizer;

        const ACTIVATION_BUDGET: usize = 1024;

        let generation = self.module_generation_pinned.load(Ordering::Acquire);
        if generation == 0 {
            return Ok(0);
        }
        let raw_module_runtime =
            NonNull::new(raw.cast()).ok_or_else(|| anyhow!("Hermes module runtime is null"))?;
        let native_runtime =
            unsafe { NativeModuleRuntime::from_raw(raw_module_runtime, self.runtime_nonce.get())? };
        let mut retained = self
            .retained_module_activations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut processed = 0usize;

        while processed < ACTIVATION_BUDGET {
            let Some(request) = native_runtime.take_dynamic_activation_request(generation)? else {
                break;
            };
            processed += 1;
            let Some(state) = retained
                .iter_mut()
                .find(|state| state.native_graph.owns_activation(&request))
            else {
                native_runtime.refuse_dynamic_activation(
                    &request,
                    "dynamic module activation has no retained authenticated graph",
                )?;
                continue;
            };
            let state = state.as_mut();
            let RetainedModuleActivationState {
                commonjs_require_provider: _,
                source_graph,
                native_graph,
            } = state;
            let checkpoint = source_graph.activation_checkpoint();
            let activation = source_graph
                .activate_dynamic_target(&request)
                .and_then(|target| {
                    let plan = source_graph.plan()?;
                    let (configs, contexts) = source_graph.native_execution_inputs(generation)?;
                    let deferred = source_graph.deferred_dynamic_links();
                    let prepared = source_graph.available_prepared_entries()?;
                    let authorizer = ModuleGraphAuthorizer::new(source_graph.snapshot());
                    native_graph.publish_authorized_activation(
                        &native_runtime,
                        &plan,
                        &request,
                        &target,
                        configs,
                        &authorizer,
                        &contexts,
                        &deferred,
                        Some(&prepared),
                    )
                });
            if let Err(error) = activation {
                source_graph.rollback_activation(checkpoint);
                let diagnostic = format!("dynamic module activation refused: {error}");
                if let Err(refusal_error) =
                    native_runtime.refuse_dynamic_activation(&request, &diagnostic)
                {
                    return Err(error.context(format!(
                        "activation refusal completion failed: {refusal_error}"
                    )));
                }
            }
        }
        Ok(processed)
    }

    #[cfg(not(feature = "module-runner"))]
    fn drive_retained_module_activations_locked(
        &self,
        _raw: *mut HermesRuntimeOpaque,
    ) -> Result<usize> {
        Ok(0)
    }

    /// Debugger-thread FFI (CDP: pause/resume/eval/breakpoints/…). Runs WITHOUT
    /// `ffi_lock`: the Hermes async debugger API is built to be driven from a
    /// thread other than the runtime thread, and taking `ffi_lock` here would
    /// deadlock — the JS thread holds it for the whole of `ex_hermes_eval` while
    /// parked at a breakpoint, and some debugger ops interrupt the runtime
    /// thread and wait for it (which itself needs `ffi_lock` to poll). Liveness
    /// of `raw` is protected by the in-flight counter, which `shutdown` drains
    /// before freeing. (ENG-22958)
    fn with_debugger<T>(&self, f: impl FnOnce(*mut HermesRuntimeOpaque) -> T) -> Result<T> {
        self.debugger_inflight.fetch_add(1, Ordering::SeqCst);
        let _guard = DebuggerInflightGuard(&self.debugger_inflight);
        // Load AFTER registering as in-flight: if the load sees a non-null
        // pointer it was read before `shutdown`'s swap, so `shutdown` is
        // guaranteed to observe this increment and wait for us before freeing.
        let raw = self.raw.load(Ordering::SeqCst);
        if raw.is_null() {
            anyhow::bail!("Hermes runtime has been shut down");
        }
        Ok(f(raw))
    }

    /// The terminal-session control ABI is any-thread and shares the debugger
    /// port's Rust pointer-lifetime pin without exposing debugger power. The
    /// native boundary independently authenticates `runtime_nonce` and retains
    /// its teardown-counted lease for the complete operation, so non-Rust C
    /// consumers receive the same generation and lifetime guarantees.
    /// @ref LLP 0025#6-interruption-and-cancellation — controller operations
    /// carry the captured runtime generation and drain before deletion.
    fn with_session_control<T>(
        &self,
        f: impl FnOnce(*mut HermesRuntimeOpaque, u64) -> T,
    ) -> Result<T> {
        self.with_debugger(|raw| f(raw, self.runtime_nonce.get()))
    }

    /// Rejecting before swapping `raw` leaves an owner-held clone able to
    /// reclaim it. An off-owner final drop intentionally leaks rather than
    /// running thread-affine JSI destruction or aborting the host process.
    fn shutdown(&self) -> RuntimeShutdown {
        if self.raw.load(Ordering::SeqCst).is_null() {
            return RuntimeShutdown::NotLive;
        }
        if std::thread::current().id() != self.owner_thread {
            return RuntimeShutdown::WrongThread;
        }
        // Null the pointer under `ffi_lock` so no runtime-thread op is mid-call
        // and later runtime-thread ops bail instead of using a freed pointer.
        let raw = {
            let _guard = match self.ffi_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            #[cfg(feature = "module-runner")]
            {
                // Provider registrations contain native callback contexts.
                // Clear them while the owner-thread runtime is still live;
                // dropping them after `ex_hermes_destroy` would call the
                // provider-clear ABI through a stale pointer.
                // @ref LLP 0026#6-top-level-await-and-dynamic-import
                self.retained_module_activations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clear();
            }
            self.raw.swap(std::ptr::null_mut(), Ordering::SeqCst)
        };
        // Drain in-flight debugger-thread ops WITHOUT holding `ffi_lock`, so a
        // debugger op that needs the runtime thread to make progress can't
        // deadlock against us. New debugger ops now observe null and bail. This
        // is normally a no-op: the CDP thread is joined (stop_inspector) before
        // the runtime is dropped, so no debugger op is in flight here.
        while self.debugger_inflight.load(Ordering::SeqCst) != 0 {
            std::thread::yield_now();
        }
        if raw.is_null() {
            return RuntimeShutdown::NotLive;
        }
        unsafe { ex_hermes_destroy(raw) };
        RuntimeShutdown::Destroyed
    }
}

impl RuntimeHandle {
    fn new(armed_snapshot_digest: Option<&str>) -> Result<Self> {
        Ok(Self {
            shared: Arc::new(SharedRuntime::new(armed_snapshot_digest)?),
        })
    }

    fn shared(&self) -> Arc<SharedRuntime> {
        self.shared.clone()
    }

    fn with_runtime<T>(&self, f: impl FnOnce(*mut HermesRuntimeOpaque) -> T) -> Result<T> {
        self.shared.with_runtime(f)
    }
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        match self.shared.shutdown() {
            RuntimeShutdown::Destroyed
            | RuntimeShutdown::NotLive
            | RuntimeShutdown::WrongThread => {}
        }
    }
}

struct HermesCdpBackend {
    runtime: Arc<SharedRuntime>,
    debugger_requested: Arc<AtomicBool>,
}

impl HermesCdpBackend {
    fn new(runtime: Arc<SharedRuntime>, debugger_requested: Arc<AtomicBool>) -> Self {
        Self {
            runtime,
            debugger_requested,
        }
    }

    unsafe fn take_c_string(ptr: *mut std::os::raw::c_char) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let message = CStr::from_ptr(ptr).to_string_lossy().to_string();
        ex_hermes_free_string(ptr);
        Some(message)
    }
}

impl CdpBackend for HermesCdpBackend {
    fn enable(&self) -> bool {
        self.debugger_requested.store(true, Ordering::SeqCst);
        true
    }

    fn get_scripts(&self) -> Result<Vec<ScriptInfo>> {
        let json = self
            .runtime
            .with_debugger(|runtime| unsafe {
                Self::take_c_string(ex_hermes_debugger_get_scripts(runtime))
            })?
            .unwrap_or_else(|| "[]".to_string());
        let value: Value = serde_json::from_str(&json).unwrap_or(Value::Array(Vec::new()));
        let mut scripts = Vec::new();
        if let Value::Array(items) = value {
            for item in items {
                if let Value::Object(map) = item {
                    if let (Some(id), Some(url)) = (
                        map.get("id").and_then(|v| v.as_u64()),
                        map.get("url").and_then(|v| v.as_str()),
                    ) {
                        scripts.push(ScriptInfo {
                            id: id as u32,
                            url: url.to_string(),
                        });
                    }
                }
            }
        }
        Ok(scripts)
    }

    fn get_script_source(&self, script_id: &str) -> Result<Option<String>> {
        let id = script_id.parse::<u32>().unwrap_or(0);
        self.runtime.with_debugger(|runtime| unsafe {
            Self::take_c_string(ex_hermes_debugger_get_script_source(runtime, id))
        })
    }

    fn set_breakpoint(
        &self,
        script_id: u32,
        line: u32,
        column: u32,
        condition: Option<&str>,
    ) -> Result<BreakpointInfo> {
        let condition = condition.unwrap_or("");
        let condition_c = CString::new(condition)?;
        let json = self
            .runtime
            .with_debugger(|runtime| unsafe {
                Self::take_c_string(ex_hermes_debugger_set_breakpoint(
                    runtime,
                    script_id,
                    line,
                    column,
                    condition_c.as_ptr(),
                ))
            })?
            .ok_or_else(|| anyhow::anyhow!("Failed to set breakpoint"))?;

        let value: Value = serde_json::from_str(&json)?;
        let id = value
            .get("id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing breakpoint id"))?;
        let script_id = value
            .get("scriptId")
            .and_then(|v| v.as_u64())
            .unwrap_or(script_id as u64);
        let line = value
            .get("line")
            .and_then(|v| v.as_u64())
            .unwrap_or(line as u64);
        let column = value
            .get("column")
            .and_then(|v| v.as_u64())
            .unwrap_or(column as u64);

        Ok(BreakpointInfo {
            id,
            script_id: script_id as u32,
            line: line as u32,
            column: column as u32,
        })
    }

    fn remove_breakpoint(&self, breakpoint_id: u64) {
        let _ = self.runtime.with_debugger(|runtime| unsafe {
            ex_hermes_debugger_remove_breakpoint(runtime, breakpoint_id);
        });
    }

    fn pause(&self) {
        let _ = self.runtime.with_debugger(|runtime| unsafe {
            ex_hermes_debugger_pause(runtime);
        });
    }

    fn resume(&self, command: DebugCommand) {
        let cmd = match command {
            DebugCommand::Continue => 0,
            DebugCommand::StepInto => 1,
            DebugCommand::StepOver => 2,
            DebugCommand::StepOut => 3,
        };
        let _ = self.runtime.with_debugger(|runtime| unsafe {
            ex_hermes_debugger_resume(runtime, cmd);
        });
    }

    fn next_event(&self) -> Option<String> {
        self.runtime
            .with_debugger(|runtime| unsafe {
                Self::take_c_string(ex_hermes_debugger_next_event(runtime))
            })
            .ok()
            .flatten()
    }

    fn eval(&self, expression: &str, frame_index: u32) -> Result<Value> {
        let expression_c = CString::new(expression)?;
        let json = self
            .runtime
            .with_debugger(|runtime| unsafe {
                Self::take_c_string(ex_hermes_debugger_eval(
                    runtime,
                    expression_c.as_ptr(),
                    frame_index,
                ))
            })?
            .ok_or_else(|| anyhow::anyhow!("Eval failed"))?;
        Ok(serde_json::from_str(&json)?)
    }
}

impl HermesEngine {
    #[allow(dead_code)] // Used by secure profiles and direct identity tests.
    pub(crate) fn loaded_engine_identity(
    ) -> Result<ibex_runtime::engine::LoadedEngineBinaryIdentity> {
        ibex_runtime::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg)
    }

    #[cfg(feature = "insecure")]
    pub(crate) fn loaded_engine_identity_insecure(
    ) -> Result<ibex_runtime::engine::LoadedEngineBinaryIdentity> {
        ibex_runtime::engine::loaded_engine_binary_identity_insecure().map_err(anyhow::Error::msg)
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    pub(crate) fn loaded_engine_portable_identity(
    ) -> Result<ibex_runtime::engine::portable_identity::PortableEngineArtifactIdentity> {
        ibex_runtime::engine::portable_identity::loaded_engine_portable_identity()
            .map_err(anyhow::Error::msg)
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    pub(crate) fn loaded_engine_portable_identity_if_present(
    ) -> Result<Option<ibex_runtime::engine::portable_identity::PortableEngineArtifactIdentity>>
    {
        ibex_runtime::engine::portable_identity::loaded_engine_portable_identity_if_present()
            .map_err(anyhow::Error::msg)
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    pub(crate) fn begin_loaded_engine_mapped_observation(
    ) -> Result<ibex_runtime::engine::portable_identity::LoadedEngineMappedObservation> {
        ibex_runtime::engine::portable_identity::begin_loaded_engine_mapped_observation()
            .map_err(anyhow::Error::msg)
    }

    /// Create a new Hermes engine instance
    #[cfg(test)]
    pub fn new() -> Result<Self> {
        Self::new_with_armed_snapshot(None)
    }

    /// Create Hermes bound to the exact immutable snapshot already installed
    /// in the host. Runtime allocation fails if the host does not authenticate
    /// this digest.
    pub fn new_with_armed_snapshot(armed_snapshot_digest: Option<&str>) -> Result<Self> {
        // (ENG-23234) Must run before the first event-loop park so callback
        // pushes wake the select! in wait_for_callback_or_sleep even without
        // the `cli-notify` feature. No-op under `cli-notify`.
        register_default_profile_wake_hook();
        // Trace controls are diagnostic startup configuration. Capture once
        // while constructing the engine so authenticated program drains never
        // reread a mutable host environment after project execution begins.
        // @ref LLP 0025#2-startup-configuration-is-captured-before-arming
        let loop_trace_enabled = std::env::var("IBEX_LOOP_TRACE")
            .or_else(|_| std::env::var("EXACT_LOOP_TRACE"))
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let startup_trace_enabled = std::env::var("IBEX_STARTUP_TRACE")
            .or_else(|_| std::env::var("EX_STARTUP_TRACE"))
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        Ok(Self {
            runtime_loaded: Mutex::new(false),
            runtime: Mutex::new(None),
            cancellation_runtime: std::sync::Mutex::new(None),
            cdp_handle: Mutex::new(None),
            bytecode_compile_tasks: std::sync::Mutex::new(Vec::new()),
            thread_id: std::thread::current().id(),
            debugger_requested: Arc::new(AtomicBool::new(false)),
            debugger_enabled: AtomicBool::new(false),
            debugger_warned: AtomicBool::new(false),
            process_bootstrap_wires_closed: AtomicBool::new(false),
            armed_snapshot_digest: armed_snapshot_digest.map(str::to_owned),
            loop_trace_enabled,
            startup_trace_enabled,
        })
    }

    fn unarmed_inspector_authorization(&self) -> Result<UnarmedInspectorAuthorization> {
        // Runtime owns the ordinary sink guard. Repeat it at the engine boundary
        // because worker/controller code can retain an Engine directly. This
        // check precedes runtime allocation, debugger-backend construction, and
        // the token required by `cdp::start_server`.
        // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
        if self.armed_snapshot_digest.is_some() {
            anyhow::bail!(ARMED_INSPECTOR_CLOSED_MESSAGE);
        }
        Ok(UnarmedInspectorAuthorization(()))
    }

    fn ensure_thread(&self) -> Result<()> {
        if std::thread::current().id() != self.thread_id {
            anyhow::bail!("Hermes runtime must be used from the creating thread");
        }
        Ok(())
    }

    fn publish_cancellation_runtime(&self, runtime: &Arc<SharedRuntime>) {
        let mut published = self
            .cancellation_runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *published = Some(Arc::downgrade(runtime));
    }

    fn cancellation_runtime(&self) -> Option<Arc<SharedRuntime>> {
        self.cancellation_runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
    }

    fn track_bytecode_compile_task(&self, task: JoinHandle<()>) {
        let mut tasks = match self.bytecode_compile_tasks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut pending = Vec::with_capacity(tasks.len() + 1);
        for handle in tasks.drain(..) {
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                pending.push(handle);
            }
        }

        pending.push(task);
        *tasks = pending;
    }

    async fn ensure_runtime(&self) -> Result<Arc<SharedRuntime>> {
        self.ensure_thread()?;
        let mut runtime = self.runtime.lock().await;
        if runtime.is_none() {
            *runtime = Some(RuntimeHandle::new(self.armed_snapshot_digest.as_deref())?);
        }
        let shared = runtime
            .as_ref()
            .map(RuntimeHandle::shared)
            .ok_or_else(|| anyhow!("Hermes runtime missing after initialization"))?;
        self.publish_cancellation_runtime(&shared);
        Ok(shared)
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    async fn native_freeze_observation(&self) -> Result<u32> {
        let mut mask = 0;
        let status = self
            .ensure_runtime()
            .await?
            .with_runtime(|raw| unsafe { ibex_test_native_freeze_observation(raw, &mut mask) })?;
        anyhow::ensure!(status == 1, "native-freeze observation is unavailable");
        anyhow::ensure!(
            mask & !0x1f == 0,
            "native-freeze observation has unknown bits"
        );
        anyhow::ensure!(
            mask & 0x10 != 0,
            "native-freeze observation did not complete"
        );
        Ok(mask)
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    pub(super) async fn arm_builtin_source_observation(
        &self,
        observation_id: &str,
        expected_alias: &str,
    ) -> Result<()> {
        let observation_id = CString::new(observation_id)
            .context("builtin source observation id contains an interior NUL")?;
        let expected_alias = CString::new(expected_alias)
            .context("builtin source observation alias contains an interior NUL")?;
        let status = self.ensure_runtime().await?.with_runtime(|raw| unsafe {
            ibex_test_arm_builtin_source_observation(
                raw,
                observation_id.as_ptr(),
                expected_alias.as_ptr(),
            )
        })?;
        anyhow::ensure!(status == 1, "builtin source observation could not be armed");
        Ok(())
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    pub(super) async fn take_builtin_source_observation(&self) -> Result<Value> {
        let output = self
            .ensure_runtime()
            .await?
            .with_runtime(|raw| unsafe { ibex_test_take_builtin_source_observation(raw) })?;
        anyhow::ensure!(
            !output.is_null(),
            "builtin source observation is unavailable"
        );
        let json = unsafe { CStr::from_ptr(output) }
            .to_str()
            .context("builtin source observation returned invalid UTF-8")?
            .to_owned();
        unsafe { ex_hermes_free_string(output) };
        capsec_semantics::strict_json::parse_strict(&json)
            .map_err(|error| anyhow!("builtin source observation returned invalid JSON: {error}"))
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    pub(super) async fn arm_loader_point_observation(
        &self,
        observation_id: &str,
        expected_point: &str,
    ) -> Result<()> {
        let observation_id = CString::new(observation_id)
            .context("loader source-point observation id contains an interior NUL")?;
        let expected_point = CString::new(expected_point)
            .context("loader source-point expectation contains an interior NUL")?;
        let status = self.ensure_runtime().await?.with_runtime(|raw| unsafe {
            ibex_test_arm_loader_point_observation(
                raw,
                observation_id.as_ptr(),
                expected_point.as_ptr(),
            )
        })?;
        anyhow::ensure!(
            status == 1,
            "loader source-point observation could not be armed"
        );
        Ok(())
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    pub(super) async fn take_loader_point_observation(&self) -> Result<Value> {
        let output = self
            .ensure_runtime()
            .await?
            .with_runtime(|raw| unsafe { ibex_test_take_loader_point_observation(raw) })?;
        anyhow::ensure!(
            !output.is_null(),
            "loader source-point observation is unavailable"
        );
        let json = unsafe { CStr::from_ptr(output) }
            .to_str()
            .context("loader source-point observation returned invalid UTF-8")?
            .to_owned();
        unsafe { ex_hermes_free_string(output) };
        capsec_semantics::strict_json::parse_strict(&json).map_err(|error| {
            anyhow!("loader source-point observation returned invalid JSON: {error}")
        })
    }

    async fn finish_armed_bootstrap(&self) -> Result<()> {
        self.ensure_thread()?;
        if !self.process_bootstrap_wires_closed.load(Ordering::Acquire) {
            let (source, source_name, failure) = if self.armed_snapshot_digest.is_some() {
                (
                    CLOSE_ARMED_PROCESS_BOOTSTRAP_WIRES,
                    "<armed-process-bootstrap-close>",
                    "failed to close armed process bootstrap wires",
                )
            } else {
                (
                    CLOSE_UNARMED_COMPATIBILITY_BOOTSTRAP_WIRE,
                    "<diagnostic-process-bootstrap-close>",
                    "failed to close diagnostic process bootstrap compatibility wire",
                )
            };
            self.eval_str(source, source_name).await.context(failure)?;
            self.process_bootstrap_wires_closed
                .store(true, Ordering::Release);
        }
        if self.armed_snapshot_digest.is_some() {
            self.ensure_runtime().await?.finish_bootstrap()
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "module-runner")]
    async fn evaluate_native_module_graph(
        &self,
        session: &ArmedSessionToken,
        request: SourceRequest,
        prepare: super::AuthenticatedModuleGraphPreparer<'_>,
    ) -> Result<AuthenticatedEvaluation> {
        use ibex_runtime::engine::module_runner::{
            AsyncGraphPoll, NativeAsynchronousGraph, NativeModuleRuntime, NativeSynchronousGraph,
        };
        use ibex_runtime::module_loader::security::ModuleGraphAuthorizer;

        let native_test_profile = crate::runtime::native_runner_test_profile()?;
        let mut phase = crate::runtime::StartupPhaseTrace::begin();
        self.load_runtime().await?;
        phase.mark("graph_runtime_load");
        self.maybe_enable_debugger().await?;
        self.ensure_thread()?;
        let runtime = self.ensure_runtime().await?;
        // This local, owner-thread future holds the runtime lease across TLA
        // waits. Aborting it drops native graph records and the structured
        // evaluation guard on the owner thread before releasing the FFI lock;
        // no graph handle is made Send and no cleanup ticket can be stranded.
        let lease = runtime.owner_runtime_lease()?;
        let raw = lease.raw();
        let armed_snapshot_digest = self.armed_snapshot_digest.clone();
        let admitted = unsafe {
            admit_prepare_authenticated_module_graph(raw.cast(), session, request, |request| {
                let preparation = prepare(request).map_err(|error| {
                    // The preparer has already consumed an authenticated
                    // request, so its source-labelled producer diagnostic is
                    // safe and necessary for the native diagnostics contract.
                    // @ref LLP 0026#10-diagnostics-and-source-maps
                    EngineFault::Rejected(Arc::from(format!(
                        "authenticated module graph preparation failed: {error:#}"
                    )))
                })?;
                match preparation {
                    super::AuthenticatedModuleGraphPreparation::Native(graph) => {
                        if armed_snapshot_digest.as_deref()
                            != Some(request.authenticated_snapshot_digest().as_str())
                        {
                            return Err(EngineFault::Rejected(Arc::from(
                                "authenticated module graph does not belong to its admitted request",
                            )));
                        }
                        graph
                            .validate_authenticated_entry_request(request)
                            .map_err(|_| {
                                EngineFault::Rejected(Arc::from(
                                    "authenticated module graph does not belong to its admitted request",
                                ))
                            })?;
                        Ok(StructuredModuleGraphPreparation::Native(graph))
                    }
                    super::AuthenticatedModuleGraphPreparation::LegacyRequired => {
                        Ok(StructuredModuleGraphPreparation::LegacyRequired)
                    }
                }
            })
        }
        .map_err(anyhow::Error::new)?;
        phase.mark("graph_admit_prepare");

        let (graph, mut structured) = match admitted {
            AuthenticatedModuleGraphAdmission::Native {
                preparation,
                evaluation,
            } => (preparation, evaluation),
            AuthenticatedModuleGraphAdmission::Legacy(progress) => {
                let mut progress =
                    unsafe { materialize_authenticated_progress_stage1(raw.cast(), progress) }
                        .map_err(anyhow::Error::new)?;
                let evaluation = loop {
                    match progress {
                        Stage1EvaluationProgress::Settled(evaluation) => break evaluation,
                        Stage1EvaluationProgress::Suspended(suspension) => {
                            let now = current_time_ms();
                            let executed = unsafe { ex_hermes_poll(raw, now) };
                            let next_timer = unsafe { ex_hermes_next_timer(raw) };
                            progress =
                                unsafe { resume_authenticated_stage1(raw.cast(), suspension) }
                                    .map_err(anyhow::Error::new)?;
                            if executed < -2 || executed == -1 {
                                return Err(anyhow::anyhow!(
                                    "Hermes failed while driving a legacy authenticated module evaluation"
                                ));
                            }
                            if matches!(progress, Stage1EvaluationProgress::Suspended(_))
                                && executed == 0
                            {
                                wait_for_callback_or_sleep(structured_settlement_wait(
                                    next_timer, now,
                                ))
                                .await;
                            }
                        }
                    }
                };
                drop(lease);
                return Ok(authenticated_evaluation(evaluation));
            }
        };
        // @ref LLP 0055#1-the-hotrevision-counter-and-successor-law — execution coordinate is session-minted, never the authority counter.
        let generation = graph.execution_generation().get();
        let nonce = unsafe { ex_hermes_runtime_nonce(raw) };
        runtime.ensure_module_generation_pinned(&lease, nonce, generation)?;
        let raw_module_runtime = NonNull::new(raw.cast())
            .ok_or_else(|| anyhow!("Hermes module runtime pointer is null"))?;
        let native_runtime = unsafe { NativeModuleRuntime::from_raw(raw_module_runtime, nonce)? };
        let mut forced_terminal = None;
        let mut retained_activation_state = None;
        let mut source_maps = std::collections::BTreeMap::new();

        let graph_result: Result<()> = async {
            let plan = graph.plan()?;
            phase.mark("graph_plan");
            let (configs, authority_contexts) = graph.native_execution_inputs(generation)?;
            source_maps = native_module_source_maps(&plan, &configs)?;
            phase.mark("graph_execution_inputs");
            let authorizer = ModuleGraphAuthorizer::new(graph.snapshot());
            let prepared_entries = graph.prepared_entries()?;
            phase.mark("graph_prepared_entries");
            let deferred = graph.deferred_dynamic_links();
            let has_top_level_await = plan.evaluation_order(graph.entry())?.iter().try_fold(
                false,
                |found, source_id| {
                    Ok::<_, anyhow::Error>(found || plan.has_top_level_await(source_id)?)
                },
            )?;

            if !has_top_level_await {
                let mut linked = match (prepared_entries.as_ref(), deferred.is_empty()) {
                    (Some(entries), false) => {
                        NativeSynchronousGraph::link_authorized_deferred_prepared(
                            &native_runtime,
                            &plan,
                            graph.entry(),
                            configs,
                            &authorizer,
                            &authority_contexts,
                            &deferred,
                            entries,
                        )?
                    }
                    (None, false) => NativeSynchronousGraph::link_authorized_deferred(
                        &native_runtime,
                        &plan,
                        graph.entry(),
                        configs,
                        &authorizer,
                        &authority_contexts,
                        &deferred,
                    )?,
                    (Some(entries), true) => NativeSynchronousGraph::link_authorized_prepared(
                        &native_runtime,
                        &plan,
                        graph.entry(),
                        configs,
                        &authorizer,
                        &authority_contexts,
                        entries,
                    )?,
                    (None, true) => NativeSynchronousGraph::link_authorized(
                        &native_runtime,
                        &plan,
                        graph.entry(),
                        configs,
                        &authorizer,
                        &authority_contexts,
                    )?,
                };
                phase.mark("graph_link");
                let native_graph = linked.published_activation_index()?;
                drop(plan);
                drop(authorizer);
                drop(prepared_entries);
                let mut activation_state = Box::new(RetainedModuleActivationState {
                    commonjs_require_provider: None,
                    source_graph: graph,
                    native_graph,
                });
                activation_state.install_commonjs_require_provider(&native_runtime)?;
                linked.evaluate()?;
                phase.mark("graph_evaluate");

                let mut activation_count = 0usize;
                loop {
                    let mut processed = false;
                    while let Some(request) =
                        native_runtime.take_dynamic_activation_request(generation)?
                    {
                        processed = true;
                        activation_count += 1;
                        if activation_count > 1024 {
                            native_runtime.refuse_dynamic_activation(
                                &request,
                                "dynamic module activation budget exhausted",
                            )?;
                            anyhow::bail!("dynamic module activation budget exhausted");
                        }
                        let checkpoint = activation_state.source_graph.activation_checkpoint();
                        let activation = activation_state
                            .source_graph
                            .activate_dynamic_target(&request)
                            .and_then(|target| {
                                let expanded_plan = activation_state.source_graph.plan()?;
                                let (configs, contexts) =
                                    activation_state.source_graph.native_execution_inputs(generation)?;
                                let expanded_source_maps =
                                    native_module_source_maps(&expanded_plan, &configs)?;
                                let expanded_deferred =
                                    activation_state.source_graph.deferred_dynamic_links();
                                let available_prepared =
                                    activation_state.source_graph.available_prepared_entries()?;
                                let authorizer = ModuleGraphAuthorizer::new(
                                    activation_state.source_graph.snapshot(),
                                );
                                activation_state.native_graph.publish_authorized_activation(
                                    &native_runtime,
                                    &expanded_plan,
                                    &request,
                                    &target,
                                    configs,
                                    &authorizer,
                                    &contexts,
                                    &expanded_deferred,
                                    Some(&available_prepared),
                                )?;
                                Ok(expanded_source_maps)
                            });
                        match activation {
                            Ok(expanded_source_maps) => source_maps = expanded_source_maps,
                            Err(error) => {
                                activation_state
                                    .source_graph
                                    .rollback_activation(checkpoint);
                                let diagnostic = format!(
                                    "dynamic module activation refused: {error}"
                                );
                                if let Err(refusal_error) = native_runtime
                                    .refuse_dynamic_activation(&request, &diagnostic)
                                {
                                    return Err(error.context(format!(
                                        "activation refusal completion failed: {refusal_error}"
                                    )));
                                }
                            }
                        }
                    }
                    if !processed {
                        break;
                    }
                    let executed = unsafe { ex_hermes_poll(raw, current_time_ms()) };
                    if executed < 0 {
                        anyhow::bail!(
                            "Hermes task execution failed while completing dynamic module activation"
                        );
                    }
                }
                retained_activation_state = Some(activation_state);
                return Ok(());
            }

            let mut linked = match (prepared_entries.as_ref(), deferred.is_empty()) {
                (Some(entries), false) => {
                    NativeAsynchronousGraph::link_authorized_deferred_prepared(
                        &native_runtime,
                        &plan,
                        graph.entry(),
                        configs,
                        &authorizer,
                        &authority_contexts,
                        &deferred,
                        entries,
                    )?
                }
                (None, false) => NativeAsynchronousGraph::link_authorized_deferred(
                    &native_runtime,
                    &plan,
                    graph.entry(),
                    configs,
                    &authorizer,
                    &authority_contexts,
                    &deferred,
                )?,
                (Some(entries), true) => NativeAsynchronousGraph::link_authorized_prepared(
                    &native_runtime,
                    &plan,
                    graph.entry(),
                    configs,
                    &authorizer,
                    &authority_contexts,
                    entries,
                )?,
                (None, true) => NativeAsynchronousGraph::link_authorized(
                    &native_runtime,
                    &plan,
                    graph.entry(),
                    configs,
                    &authorizer,
                    &authority_contexts,
                )?,
            };
            let native_graph = linked.published_activation_index()?;
            drop(plan);
            drop(authorizer);
            drop(prepared_entries);
            let mut activation_state = Box::new(RetainedModuleActivationState {
                commonjs_require_provider: None,
                source_graph: graph,
                native_graph,
            });
            activation_state.install_commonjs_require_provider(&native_runtime)?;
            // `ex_hermes_poll` always drains the Hermes job queue, but its
            // return value counts host callbacks/timers rather than Promise
            // jobs. Give the suspended graph one advancement attempt after
            // each poll/wake epoch before deciding that quiescence means an
            // unresolved TLA. The flag stays false across an unchanged graph
            // suspension, preventing a no-work retry loop.
            // @ref LLP 0026#6-top-level-await-and-dynamic-import
            let mut retry_graph_after_runtime_poll = true;
            let trace_graph = self.loop_trace_enabled;
            let mut graph_poll_iteration = 0usize;
            let mut activation_count = 0usize;

            loop {
                graph_poll_iteration += 1;
                let graph_poll = linked.poll()?;
                if trace_graph {
                    eprintln!(
                        "[module-graph] graph_poll iteration={graph_poll_iteration} state={}",
                        match &graph_poll {
                            AsyncGraphPoll::Evaluated => "evaluated",
                            AsyncGraphPoll::Suspended => "suspended",
                        }
                    );
                }
                let mut processed_activation = false;
                while let Some(request) =
                    native_runtime.take_dynamic_activation_request(generation)?
                {
                    processed_activation = true;
                    activation_count += 1;
                    if activation_count > 1024 {
                        native_runtime.refuse_dynamic_activation(
                            &request,
                            "dynamic module activation budget exhausted",
                        )?;
                        anyhow::bail!("dynamic module activation budget exhausted");
                    }
                    let checkpoint = activation_state.source_graph.activation_checkpoint();
                    let activation = activation_state
                        .source_graph
                        .activate_dynamic_target(&request)
                        .and_then(|target| {
                            let expanded_plan = activation_state.source_graph.plan()?;
                            let (configs, contexts) =
                                activation_state.source_graph.native_execution_inputs(generation)?;
                            let expanded_source_maps =
                                native_module_source_maps(&expanded_plan, &configs)?;
                            let expanded_deferred =
                                activation_state.source_graph.deferred_dynamic_links();
                            let available_prepared =
                                activation_state.source_graph.available_prepared_entries()?;
                            let authorizer = ModuleGraphAuthorizer::new(
                                activation_state.source_graph.snapshot(),
                            );
                            activation_state.native_graph.publish_authorized_activation(
                                &native_runtime,
                                &expanded_plan,
                                &request,
                                &target,
                                configs,
                                &authorizer,
                                &contexts,
                                &expanded_deferred,
                                Some(&available_prepared),
                            )?;
                            Ok(expanded_source_maps)
                        });
                    match activation {
                        Ok(expanded_source_maps) => source_maps = expanded_source_maps,
                        Err(error) => {
                            activation_state
                                .source_graph
                                .rollback_activation(checkpoint);
                            let diagnostic =
                                format!("dynamic module activation refused: {error}");
                            if let Err(refusal_error) = native_runtime
                                .refuse_dynamic_activation(&request, &diagnostic)
                            {
                                return Err(error.context(format!(
                                    "activation refusal completion failed: {refusal_error}"
                                )));
                            }
                        }
                    }
                }
                if processed_activation {
                    let executed = unsafe { ex_hermes_poll(raw, current_time_ms()) };
                    if executed < 0 {
                        anyhow::bail!(
                            "Hermes task execution failed while completing dynamic module activation"
                        );
                    }
                    continue;
                }
                match graph_poll {
                    AsyncGraphPoll::Evaluated => {
                        retained_activation_state = Some(activation_state);
                        return Ok(());
                    }
                    AsyncGraphPoll::Suspended => match unsafe { structured.suspend() }? {
                        ModuleGraphSuspension::Suspended => {}
                        ModuleGraphSuspension::CancellationPending => {
                            forced_terminal =
                                Some(ModuleGraphExecutionOutcome::CooperativeCancellation);
                            return Ok(());
                        }
                    },
                }

                // The graph target is absent while host work runs. Timers,
                // callbacks, and I/O completions therefore publish and receive
                // cancellation under their own exact work-target identities.
                loop {
                    let now = current_time_ms();
                    if trace_graph {
                        eprintln!("[module-graph] runtime_poll_start now={now}");
                    }
                    let executed = unsafe { ex_hermes_poll(raw, now) };
                    if trace_graph {
                        eprintln!("[module-graph] runtime_poll_end executed={executed}");
                    }
                    if executed == -2 {
                        // Native lifecycle state outranks this provisional
                        // completion when the structured result is finished.
                        forced_terminal = Some(ModuleGraphExecutionOutcome::Completed);
                        return Ok(());
                    }
                    if executed < 0 {
                        anyhow::bail!("Hermes task execution failed while evaluating module graph");
                    }
                    if executed > 0 {
                        retry_graph_after_runtime_poll = true;
                    }
                    if retry_graph_after_runtime_poll {
                        retry_graph_after_runtime_poll = false;
                        unsafe { structured.resume() }?;
                        break;
                    }

                    // This guarded runtime query already includes Host I/O.
                    // Calling the raw Host helpers here would run after the
                    // native drive scope has been restored, where nonce 0 is a
                    // process-wide query and another runtime could keep this
                    // graph alive indefinitely.
                    // @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
                    let runtime_pending = unsafe { ex_hermes_has_pending_tasks(raw) } != 0;
                    if trace_graph {
                        eprintln!("[module-graph] pending runtime={runtime_pending}");
                    }
                    if !runtime_pending {
                        forced_terminal =
                            Some(ModuleGraphExecutionOutcome::UnresolvedTopLevelAwait);
                        return Ok(());
                    }

                    let next = unsafe { ex_hermes_next_timer(raw) };
                    if next < 0 {
                        // Host I/O and callback-only waits have no timer. The
                        // wake hook interrupts this park as soon as work lands.
                        wait_for_callback_or_sleep(IDLE_PARK).await;
                        retry_graph_after_runtime_poll = true;
                    } else {
                        let delay = (next as u64).saturating_sub(now);
                        if delay > 0 {
                            wait_for_callback_or_sleep(std::time::Duration::from_millis(delay))
                                .await;
                            retry_graph_after_runtime_poll = true;
                        }
                    }
                }
            }
        }
        .await;

        let terminal = forced_terminal.unwrap_or_else(|| match &graph_result {
            Ok(()) => ModuleGraphExecutionOutcome::Completed,
            Err(error) => ibex_runtime::engine::module_runner::execution_error_token(error)
                .map(ModuleGraphExecutionOutcome::JavaScriptThrow)
                .unwrap_or(ModuleGraphExecutionOutcome::EngineFault),
        });
        let settled = unsafe { structured.finish(terminal) }.map_err(anyhow::Error::new);
        if graph_result.is_ok() && settled.is_ok() {
            if let Some(state) = retained_activation_state {
                if let Some(profile) = native_test_profile {
                    crate::runtime::emit_native_runner_execution_receipt(
                        &state.source_graph,
                        profile,
                    )?;
                }
                if state.source_graph.has_call_time_activation_links() {
                    runtime.retain_module_activation_state(state)?;
                }
            }
        }
        drop(lease);

        // Foreground graph settlement is immediate. The outer authenticated
        // file-program owner performs quiescence, while the runtime-lifetime
        // generation pin preserves records for delayed `--keep-alive` imports.
        match (graph_result, settled) {
            (Ok(()), Ok(evaluation)) => Ok(rewrite_native_module_source_positions(
                authenticated_evaluation(evaluation),
                &source_maps,
            )),
            (Ok(()), Err(error)) => Err(error),
            (Err(_graph_error), Ok(evaluation))
                if matches!(
                    &evaluation.outcome,
                    Stage1EvaluationOutcome::Throw { .. }
                        | Stage1EvaluationOutcome::Cancelled
                        | Stage1EvaluationOutcome::Lifecycle { .. }
                ) =>
            {
                Ok(rewrite_native_module_source_positions(
                    authenticated_evaluation(evaluation),
                    &source_maps,
                ))
            }
            (Err(graph_error), Ok(_)) => Err(graph_error),
            (Err(graph_error), Err(settlement_error)) => Err(graph_error.context(format!(
                "structured native module graph settlement failed: {settlement_error}"
            ))),
        }
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    async fn install_capsec_context_test_observer(&self) -> Result<String> {
        self.ensure_thread()?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .context("failed to generate an ephemeral CapSec context-observer name")?;
        let suffix = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let name = format!("__ibexCapsecContextObserver_{suffix}");
        let name_c = CString::new(name.as_str()).expect("hex observer name has no interior NUL");
        let runtime = self.ensure_runtime().await?;
        let installed = runtime.with_runtime(|raw| unsafe {
            ibex_test_install_capsec_context_observer(raw, name_c.as_ptr(), std::ptr::null())
        })?;
        if installed != 1 {
            anyhow::bail!("armed Hermes refused the ephemeral CapSec context observer");
        }
        Ok(name)
    }

    async fn maybe_enable_debugger(&self) -> Result<()> {
        if !self.debugger_requested.load(Ordering::SeqCst) {
            return Ok(());
        }
        if self.debugger_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.ensure_thread()?;
        let runtime = self.ensure_runtime().await?;
        let ok = runtime.with_runtime(|raw| unsafe { ex_hermes_debugger_enable(raw) != 0 })?;
        if ok {
            self.debugger_enabled.store(true, Ordering::SeqCst);
        } else if !self.debugger_warned.swap(true, Ordering::SeqCst) {
            eprintln!("Debugger not available in this Hermes build. Rebuild Hermes with debugger enabled.");
        }
        Ok(())
    }

    async fn eval_bytes(
        &self,
        data: &[u8],
        source_url: &str,
        is_bytecode: bool,
    ) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        self.ensure_thread()?;
        let mut runtime = self.runtime.lock().await;
        if runtime.is_none() {
            *runtime = Some(RuntimeHandle::new(self.armed_snapshot_digest.as_deref())?);
        }
        let handle = runtime
            .as_ref()
            .ok_or_else(|| anyhow!("Hermes runtime missing after initialization"))?;
        self.publish_cancellation_runtime(&handle.shared);

        let source_c = CString::new(source_url)?;
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let status = handle.with_runtime(|raw| unsafe {
            ex_hermes_eval(
                raw,
                data.as_ptr(),
                data.len(),
                source_c.as_ptr(),
                if is_bytecode { 1 } else { 0 },
                &mut out,
            )
        })?;

        if status != 0 {
            let message = if out.is_null() {
                "Hermes evaluation failed".to_string()
            } else {
                let msg = unsafe { CStr::from_ptr(out) }.to_string_lossy().to_string();
                unsafe { ex_hermes_free_string(out) };
                msg
            };
            if status == 2 {
                return Err(anyhow::Error::new(BytecodeLoadError(message)));
            }
            // Try to apply source map to rewrite stack traces
            let message = Self::apply_source_map(&message, source_url);
            anyhow::bail!(message);
        }

        if out.is_null() {
            Ok(None)
        } else {
            let msg = unsafe { CStr::from_ptr(out) }.to_string_lossy().to_string();
            unsafe { ex_hermes_free_string(out) };
            Ok(Some(msg))
        }
    }

    async fn eval_str(&self, code: &str, source_url: &str) -> Result<Option<String>> {
        self.eval_bytes(code.as_bytes(), source_url, false).await
    }

    async fn runtime_bundle_installed(&self) -> Result<bool> {
        if self.armed_snapshot_digest.is_some() {
            let installed = self.ensure_runtime().await?.with_runtime(|raw| unsafe {
                ibex_private_hermes_shared_runtime_bundle_installed_v1(raw)
            })?;
            return match installed {
                1 => Ok(true),
                0 => Ok(false),
                status => {
                    anyhow::bail!("native shared-runtime bundle state is unavailable ({status})")
                }
            };
        }

        #[cfg(windows)]
        let probe = r#"(function(){
  return (
    typeof globalThis === 'object' &&
    globalThis &&
    globalThis.__exactRuntimeLoaded === true
  ) ? 'true' : 'false';
})();"#;

        #[cfg(not(windows))]
        let probe = r#"(function(){
  return (
    typeof globalThis === 'object' &&
    globalThis &&
    globalThis.__exactRuntimeLoaded === true &&
    typeof globalThis.ExactBundle === 'object' &&
    globalThis.ExactBundle !== null
  ) ? 'true' : 'false';
})();"#;
        let result = self.eval_str(probe, "<runtime-installed>").await?;
        Ok(matches!(result.as_deref().map(str::trim), Some("true")))
    }

    async fn ensure_runtime_bundle_installed(&self) -> Result<()> {
        let bootstrap = r#"(function(){
  if (typeof globalThis === 'object' && globalThis) {
    var g = globalThis;
    if (g.__exactRuntimeLoaded === true) {
      return;
    }
    if (g.ExactBundle && typeof g.ExactBundle.installGlobals === 'function') {
      g.ExactBundle.installGlobals();
      return;
    }
  }

  if (
    typeof ExactBundle !== 'undefined' &&
    ExactBundle &&
    typeof ExactBundle.installGlobals === 'function' &&
    (typeof globalThis !== 'object' || !globalThis || globalThis.__exactRuntimeLoaded !== true)
  ) {
    ExactBundle.installGlobals();
  }
})();"#;
        let _ = self.eval_str(bootstrap, "<bootstrap>").await?;
        Ok(())
    }

    async fn finalize_runtime_setup(&self) -> Result<()> {
        if cfg!(windows) {
            return Ok(());
        }

        if !self.runtime_bundle_installed().await? {
            self.ensure_runtime_bundle_installed().await?;
        }
        if !self.runtime_bundle_installed().await? {
            self.ensure_crypto_fallback().await?;
        }
        Ok(())
    }

    async fn seal_armed_shared_runtime_globals(&self) -> Result<()> {
        if self.armed_snapshot_digest.is_none() {
            return Ok(());
        }
        // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
        // @ref LLP 0022#7-capabilities-principals-and-affordance-parity
        // The native named transition owns the reviewed program and the full
        // owner-thread/armed/bootstrap gate; embedders never duplicate its
        // ambient-root list.
        self.ensure_runtime()
            .await?
            .seal_armed_shared_runtime_globals()
    }

    async fn ensure_crypto_fallback(&self) -> Result<()> {
        if cfg!(windows) {
            return Ok(());
        }

        let fallback = r#"(function(){
  const hasCrypto = typeof globalThis.crypto !== 'undefined' && globalThis.crypto !== null;
  const hasGetRandomValues = hasCrypto && typeof globalThis.crypto.getRandomValues === 'function';
  const hasRandomUUID = hasCrypto && typeof globalThis.crypto.randomUUID === 'function';
  if ((!hasCrypto || !hasGetRandomValues || !hasRandomUUID) && typeof __exactRandomBytes === 'function') {
    const cryptoObj = hasCrypto ? globalThis.crypto : {};
    if (!hasGetRandomValues) {
      cryptoObj.getRandomValues = function(arr) {
        const bytes = __exactRandomBytes(arr.byteLength);
        arr.set(bytes);
        return arr;
      };
    }
    if (!hasRandomUUID) {
      cryptoObj.randomUUID = function() {
        const bytes = __exactRandomBytes(16);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        const hex = Array.from(bytes, function(b) { return b.toString(16).padStart(2, '0'); });
        return hex.slice(0, 4).join('') + '-' +
               hex.slice(4, 6).join('') + '-' +
               hex.slice(6, 8).join('') + '-' +
               hex.slice(8, 10).join('') + '-' +
               hex.slice(10).join('');
      };
    }
    globalThis.crypto = cryptoObj;
  }
})();"#;
        let _ = self.eval_str(fallback, "<crypto-fallback>").await?;
        Ok(())
    }

    async fn drive_event_loop_typed(
        &self,
    ) -> std::result::Result<(), AuthenticatedProgramDrainFailure> {
        self.ensure_thread()
            .map_err(AuthenticatedProgramDrainFailure::EngineFault)?;
        let trace_loop = self.loop_trace_enabled;
        let mut trace_iterations = 0usize;
        loop {
            let (pending, next_due, executed, activated) = {
                let runtime = self.runtime.lock().await;
                let handle = match runtime.as_ref() {
                    Some(handle) => handle,
                    None => return Ok(()),
                };
                let now = current_time_ms();
                let (executed, pending, next, activated) = handle
                    .with_runtime(|raw| -> Result<_> {
                        let executed = unsafe { ex_hermes_poll(raw, now) };
                        let activated = handle
                            .shared
                            .drive_retained_module_activations_locked(raw)?;
                        let host_pending = unsafe {
                            ex_host_http_has_referenced() != 0
                                || ex_host_http_has_pending_requests() != 0
                                || native_ws_has_active() != 0
                        };
                        let pending = if host_pending {
                            1
                        } else {
                            unsafe { ex_hermes_has_pending_tasks(raw) }
                        };
                        let next = unsafe { ex_hermes_next_timer(raw) };
                        Ok((executed, pending, next, activated))
                    })
                    .map_err(AuthenticatedProgramDrainFailure::EngineFault)?
                    .map_err(AuthenticatedProgramDrainFailure::EngineFault)?;
                if executed == -2 {
                    return Ok(());
                }
                if executed < 0 {
                    return Err(AuthenticatedProgramDrainFailure::Unhandled(
                        anyhow::anyhow!("Hermes asynchronous task execution failed"),
                    ));
                }
                if trace_loop && trace_iterations < 200 {
                    eprintln!(
                        "[loop] iteration={} executed={} pending={} next={} now={}",
                        trace_iterations, executed, pending, next, now
                    );
                    trace_iterations += 1;
                }
                (pending, (next, now), executed, activated)
            };

            if executed > 0 || activated > 0 {
                continue;
            }
            if pending == 0 {
                break;
            }

            let (next, now) = next_due;
            if next < 0 {
                // No timers but tasks pending (HTTP server, callbacks, etc.)
                // Wait for a callback notification. The HTTP server and every
                // cross-thread callback push signal this via
                // ex_hermes_notify_callback(), so requests wake the event loop
                // with zero latency. IDLE_PARK is only a wakeup-safety fallback
                // (see its definition), NOT a busy-poll cadence — parking a
                // fixed 5ms here made an idle server re-poll ~200×/sec. (Item 7)
                wait_for_callback_or_sleep(IDLE_PARK).await;
                continue;
            }
            let delay = (next as u64).saturating_sub(now);
            if delay > 0 {
                // Also wake on callback notification (e.g., HTTP request
                // arrives) rather than sleeping the full timer duration when
                // the CLI notify feature is enabled.
                wait_for_callback_or_sleep(std::time::Duration::from_millis(delay)).await;
            }
        }

        Ok(())
    }

    async fn drive_event_loop(&self) -> Result<()> {
        self.drive_event_loop_typed()
            .await
            .map_err(anyhow::Error::new)
    }

    /// Execute all runtime work that is ready *right now* — timers already due,
    /// drained microtasks/callbacks, and any pending debugger interrupts — then
    /// return without blocking to wait for future timers.
    ///
    /// The keep-alive / inspector loop calls this on its own cadence so that a
    /// `--keep-alive` (or `--inspect`) session actually pumps the event loop:
    /// DevTools `Runtime.evaluate` needs the runtime thread to service its
    /// interrupt, and timers scheduled from DevTools need the loop to run. The
    /// old loop only ticked a counter and never polled, so both hung. Unlike
    /// `drive_event_loop`, this never parks on a future timer, leaving the
    /// caller in charge of the wait cadence and shutdown handling. The caller
    /// itself is the live reference for these turns, so already-due unref'd
    /// timers remain eligible without becoming part of ordinary quiescence.
    /// @ref LLP 0003#the-event-loop — the host drives Hermes by polling
    /// the owner thread; host-held liveness is explicit. (ENG-22958)
    /// @ref LLP 0024#1-the-in-memory-source-api — ready-only modes run
    /// scheduled work on their idle pump without letting it hold the prompt.
    async fn pump_ready_tasks(&self) -> Result<()> {
        self.ensure_thread()?;
        // Bounded: a self-rescheduling 0-delay timer is due on every poll, so an
        // unbounded `while executed != 0` loop would never return control to the
        // caller — wedging the REPL prompt (and the keep-alive loop). Cap the
        // polls per pump; the next tick pumps again, so the timer still runs but
        // no longer starves input. (ENG-23030 #3)
        for _ in 0..PUMP_MAX_POLLS_PER_TICK {
            let (executed, activated) = {
                let runtime = self.runtime.lock().await;
                let handle = match runtime.as_ref() {
                    Some(handle) => handle,
                    None => return Ok(()),
                };
                let now = current_time_ms();
                handle.with_runtime(|raw| -> Result<_> {
                    let executed = unsafe { ex_hermes_poll_with_external_keep_alive(raw, now) };
                    let activated = handle
                        .shared
                        .drive_retained_module_activations_locked(raw)?;
                    Ok((executed, activated))
                })??
            };
            if executed < 0 {
                return Err(anyhow::anyhow!("Hermes task execution failed"));
            }
            if executed == 0 && activated == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Read and evaluate a JS/HBC file WITHOUT driving the event loop to
    /// quiescence afterwards. `run_file` adds that drive (for `ibex <file>`);
    /// the REPL's `.load` uses this directly (via `run_file_immediate`) so a
    /// loaded `Bun.serve`/`setInterval` returns control to the prompt instead of
    /// wedging, with the idle pump driving background work. (ENG-23030 #2)
    async fn eval_file(&self, path: &str) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        let path_buf = PathBuf::from(path);
        let is_bytecode = path_buf.extension().and_then(|s| s.to_str()) == Some("hbc");
        let bytes = tokio::fs::read(&path_buf)
            .await
            .with_context(|| format!("Failed to read file {}", path))?;
        let bytes = if is_bytecode {
            Cow::Borrowed(bytes.as_slice())
        } else {
            normalize_hashbang_bytes(&bytes)
        };
        let source = path_buf.to_string_lossy().to_string();
        self.eval_bytes(bytes.as_ref(), &source, is_bytecode).await
    }

    /// Try to apply source map to rewrite stack traces in error messages.
    /// Returns the rewritten message if a source map is found, otherwise the original.
    fn apply_source_map(message: &str, source_url: &str) -> String {
        use std::path::Path;

        // Extract bundle paths from stack trace lines.
        // Stack frames look like: at funcName (/path/to/bundle.js:line:col)
        // We look for .bundle.js paths in the Ibex cache directory.
        let mut bundle_path: Option<String> = None;

        // First try: the source_url itself (direct file execution)
        if source_url != "<eval>" && source_url != "<module-loader>" {
            let map_path = format!("{}.map", source_url);
            if Path::new(&map_path).exists() {
                let source_map = if Path::new(source_url)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    == Some("hbc")
                {
                    verified_bytecode_source_map(Path::new(source_url), Path::new(&map_path))
                } else {
                    super::sourcemap::SourceMap::load_cached(Path::new(&map_path))
                };
                if let Some(sm) = source_map {
                    return super::sourcemap::rewrite_error(message, &sm, source_url);
                }
            }
        }

        // Second try: extract bundle path from stack trace lines
        for line in message.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("at ") {
                continue;
            }
            if let (Some(paren_start), Some(paren_end)) = (trimmed.find('('), trimmed.rfind(')')) {
                let location = &trimmed[paren_start + 1..paren_end];
                // Extract filename from filename:line:col
                let parts: Vec<&str> = location.rsplitn(3, ':').collect();
                if parts.len() >= 3 && !parts[2].is_empty() {
                    let filename = parts[2];
                    // Skip internal frames
                    if filename == "<module-loader>" || filename == "<eval>" {
                        continue;
                    }
                    let map_file = format!("{}.map", filename);
                    if Path::new(&map_file).exists() {
                        bundle_path = Some(filename.to_string());
                        break;
                    }
                }
            }
        }

        if let Some(bp) = bundle_path {
            let map_file = format!("{}.map", bp);
            let source_map =
                if Path::new(&bp).extension().and_then(|ext| ext.to_str()) == Some("hbc") {
                    verified_bytecode_source_map(Path::new(&bp), Path::new(&map_file))
                } else {
                    super::sourcemap::SourceMap::load_cached(Path::new(&map_file))
                };
            if let Some(sm) = source_map {
                return super::sourcemap::rewrite_error(message, &sm, &bp);
            }
        }

        message.to_string()
    }

    fn is_bytecode_version_error(message: &str) -> bool {
        message.contains("Wrong bytecode version")
    }

    /// Load the runtime bundle from disk (fallback when no embedded runtime is available
    /// or when the embedded runtime fails to load).
    async fn load_runtime_from_disk(&self) -> Result<()> {
        anyhow::ensure!(
            self.armed_snapshot_digest.is_none(),
            "armed runtime disk fallback is closed"
        );
        let trace_startup = self.startup_trace_enabled;
        if trace_startup {
            eprintln!("[startup] load_runtime_from_disk_start");
        }
        match find_runtime_bundle() {
            Ok(runtime_path) => {
                if trace_startup {
                    eprintln!(
                        "[startup] load_runtime_from_disk_found {}",
                        runtime_path.display()
                    );
                }
                let is_already_bytecode =
                    runtime_path.extension().and_then(|s| s.to_str()) == Some("hbc");

                if is_already_bytecode {
                    // Already a bytecode file, load directly
                    let bytes = tokio::fs::read(&runtime_path).await.with_context(|| {
                        format!("Failed to read runtime bundle {}", runtime_path.display())
                    })?;
                    let source = runtime_path.to_string_lossy();
                    match self.eval_bytes(&bytes, &source, true).await {
                        Ok(_) => {}
                        Err(err) => {
                            let js_path = runtime_path.with_extension("js");
                            let _ = tokio::fs::remove_file(&runtime_path).await;
                            crate::runtime::mark_bytecode_incompatible();
                            if js_path.exists() {
                                let source = js_path.to_string_lossy();
                                let bytes = tokio::fs::read(&js_path).await.with_context(|| {
                                    format!("Failed to read runtime source {}", js_path.display())
                                })?;
                                let _ = self.eval_bytes(&bytes, &source, false).await?;
                            } else if Self::is_bytecode_version_error(&err.to_string()) {
                                // If no JS fallback exists, keep the existing behavior for
                                // bytecode-version mismatch so the caller can surface the exact failure.
                                return Err(err);
                            } else {
                                anyhow::bail!("{}", err);
                            }
                        }
                    }
                } else {
                    // JS source — try to load a cached .hbc alongside it
                    let hbc_path = runtime_path.with_extension("hbc");
                    let use_cached = if hbc_path.exists() {
                        // Use cached bytecode only if it's newer than the JS source
                        match (
                            tokio::fs::metadata(&hbc_path)
                                .await
                                .and_then(|m| m.modified()),
                            tokio::fs::metadata(&runtime_path)
                                .await
                                .and_then(|m| m.modified()),
                        ) {
                            (Ok(hbc_time), Ok(js_time)) => hbc_time >= js_time,
                            _ => false,
                        }
                    } else {
                        false
                    };

                    let mut loaded_from_cache = false;
                    let mut cache_failed = false;
                    if use_cached {
                        match tokio::fs::read(&hbc_path).await {
                            Ok(bytes) => {
                                let source = runtime_path.to_string_lossy();
                                match self.eval_bytes(&bytes, &source, true).await {
                                    Ok(_) => {
                                        loaded_from_cache = true;
                                    }
                                    Err(_e) => {
                                        // Bytecode version mismatch or other error.
                                        // Delete stale cache file and fall through to JS source.
                                        let _ = tokio::fs::remove_file(&hbc_path).await;
                                        cache_failed = true;
                                        crate::runtime::mark_bytecode_incompatible();
                                    }
                                }
                            }
                            Err(_) => {
                                // Can't read cache file, fall through
                            }
                        }
                    }

                    if !loaded_from_cache {
                        // Authenticate every environment-selected compiler
                        // input synchronously, before evaluating even the
                        // trusted runtime bundle. The detached cache warmer
                        // receives only this immutable capture and never
                        // consults a mutable process environment after project
                        // execution can begin.
                        // @ref LLP 0025#2-startup-configuration-is-captured-before-arming
                        let background_compile_environment = if cache_failed {
                            None
                        } else {
                            CapturedHbcCompileEnvironment::capture().ok()
                        };
                        // Load JS source
                        let bytes = tokio::fs::read(&runtime_path).await.with_context(|| {
                            format!("Failed to read runtime bundle {}", runtime_path.display())
                        })?;
                        if runtime_path.extension().and_then(|s| s.to_str()) == Some("js")
                            && !looks_like_ibex_runtime_bundle(&bytes)
                        {
                            anyhow::bail!(
                                "runtime.js at {} is not an Ibex runtime bundle",
                                runtime_path.display()
                            );
                        }
                        let source = runtime_path.to_string_lossy();
                        let _ = self.eval_bytes(&bytes, &source, false).await?;

                        // Try to compile to .hbc in the background for next startup.
                        // Skip if we just deleted a stale .hbc (version mismatch),
                        // since recompiling would produce the same incompatible bytecode.
                        if !cache_failed {
                            let js_path = runtime_path.clone();
                            let hbc_out = hbc_path.clone();
                            let compile_task = std::thread::spawn(move || {
                                let Some(environment) = background_compile_environment else {
                                    return;
                                };
                                if !bytecode_versions_compatible_with_compiler(
                                    &environment.compiler_identity,
                                ) {
                                    return;
                                }
                                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                else {
                                    return;
                                };

                                let _ = runtime.block_on(async {
                                    compile_attested_cache_bytecode_with_environment(
                                        &js_path.to_string_lossy(),
                                        &hbc_out,
                                        None,
                                        &environment,
                                    )
                                    .await
                                    .ok()
                                });
                            });
                            self.track_bytecode_compile_task(compile_task);
                        }
                    }
                }
                #[cfg(not(windows))]
                self.finalize_runtime_setup().await?;
            }
            Err(_) => {
                if trace_startup {
                    eprintln!("[startup] load_runtime_from_disk_missing");
                }
                // Only print the note if not in a child process context
                if std::env::var("IBEX_QUIET")
                    .or_else(|_| std::env::var("EXACT_QUIET"))
                    .is_err()
                {
                    eprintln!("Note: Runtime bundle not found. Running without Ibex runtime.");
                    eprintln!(
                        "      Build it with: IBEX_REGENERATE_RUNTIME=1 IBEX_UPDATE_VENDORED_GENERATED=1 cargo build"
                    );
                }
                if trace_startup {
                    eprintln!("[startup] ensure_crypto_fallback_start");
                }
                self.ensure_crypto_fallback().await?;
                if trace_startup {
                    eprintln!("[startup] ensure_crypto_fallback_end");
                }
            }
        }
        if trace_startup {
            eprintln!("[startup] load_runtime_from_disk_end");
        }
        Ok(())
    }

    #[cfg(feature = "capsec-conformance-observer")]
    pub(crate) async fn evaluate_authenticated_with_constrained_principals(
        &self,
        session: &ArmedSessionToken,
        request: SourceRequest,
        constrained_principals: &[u64],
    ) -> Result<AuthenticatedEvaluation> {
        self.evaluate_authenticated_for_principals(session, request, Some(constrained_principals))
            .await
    }

    async fn evaluate_authenticated_for_principals(
        &self,
        session: &ArmedSessionToken,
        request: SourceRequest,
        constrained_principals: Option<&[u64]>,
    ) -> Result<AuthenticatedEvaluation> {
        self.load_runtime().await?;
        self.maybe_enable_debugger().await?;
        self.ensure_thread()?;
        let runtime = self.ensure_runtime().await?;
        if matches!(&request, SourceRequest::JsonData(_)) {
            if constrained_principals.is_some() {
                anyhow::bail!(
                    "conformance principal constraints require an executable source request"
                );
            }
            let rendered = runtime
                .with_runtime(|raw| unsafe {
                    consume_authenticated_json(raw.cast(), session, request)
                })?
                .map_err(anyhow::Error::new)?;
            return Ok(AuthenticatedEvaluation::Value {
                display: AuthenticatedDisplay {
                    kind: AuthenticatedDisplayKind::JsonData,
                    text: rendered.to_string(),
                    truncated: false,
                },
                receipt: None,
            });
        }

        // Retained-handle conformance uses the same authenticated admission,
        // lowering, ordinal, suspension, and receipt path. Only the native
        // execution frame receives the extra principal intersection.
        // @ref LLP 0021#decision-staging-and-principal-semantics
        // @ref LLP 0049#6-phase-2--the-authoring-campaign-parallel-with-phase-1
        let mut progress = runtime
            .with_runtime(|raw| unsafe {
                #[cfg(feature = "capsec-conformance-observer")]
                if let Some(principals) = constrained_principals {
                    return evaluate_authenticated_stage1_with_constrained_principals(
                        raw.cast(),
                        session,
                        request,
                        principals,
                    );
                }
                #[cfg(not(feature = "capsec-conformance-observer"))]
                debug_assert!(constrained_principals.is_none());
                evaluate_authenticated_stage1(raw.cast(), session, request)
            })?
            .map_err(anyhow::Error::new)?;
        let evaluation = loop {
            match progress {
                Stage1EvaluationProgress::Settled(evaluation) => break evaluation,
                Stage1EvaluationProgress::Suspended(suspension) => {
                    let (next_progress, executed, next_timer, now) =
                        runtime.with_runtime(|raw| {
                            let now = current_time_ms();
                            let executed = unsafe { ex_hermes_poll(raw, now) };
                            let next_timer = unsafe { ex_hermes_next_timer(raw) };
                            let progress =
                                unsafe { resume_authenticated_stage1(raw.cast(), suspension) };
                            (progress, executed, next_timer, now)
                        })?;
                    progress = next_progress.map_err(anyhow::Error::new)?;
                    if executed < -2 || executed == -1 {
                        return Err(anyhow::anyhow!(
                            "Hermes failed while driving a suspended authenticated evaluation"
                        ));
                    }
                    if matches!(progress, Stage1EvaluationProgress::Suspended(_)) && executed == 0 {
                        let wait = structured_settlement_wait(next_timer, now);
                        wait_for_callback_or_sleep(wait).await;
                    }
                }
            }
        };
        Ok(match evaluation.outcome {
            Stage1EvaluationOutcome::Empty => AuthenticatedEvaluation::Empty,
            Stage1EvaluationOutcome::Value { display, receipt } => AuthenticatedEvaluation::Value {
                display: authenticated_display(display),
                receipt: Some(receipt),
            },
            Stage1EvaluationOutcome::Throw { value, metadata } => {
                AuthenticatedEvaluation::Throw(AuthenticatedThrow {
                    value: authenticated_display(value),
                    metadata: authenticated_throw_metadata(metadata),
                })
            }
            Stage1EvaluationOutcome::Cancelled => AuthenticatedEvaluation::Cancelled,
            Stage1EvaluationOutcome::Lifecycle { exit_code } => {
                AuthenticatedEvaluation::Lifecycle(exit_code)
            }
        })
    }
}

impl Drop for HermesEngine {
    fn drop(&mut self) {
        let mut tasks = match self.bytecode_compile_tasks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Do not block process teardown on background hermesc compiles. These
        // threads only warm a next-startup bytecode cache and publish it via an
        // atomic rename, so abandoning an in-flight compile can never leave a
        // partial or corrupt `.hbc`. Reap any that already finished; detach the
        // rest by dropping their handles, so a short-lived invocation
        // (e.g. `ibex -e '1+1'`) exits immediately instead of stalling in Drop
        // for the duration of the compile (up to the hermesc timeout). (ENG-22958)
        for handle in tasks.drain(..) {
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
    }
}

#[async_trait]
impl Engine for HermesEngine {
    fn name(&self) -> &str {
        "hermes"
    }

    fn version(&self) -> Result<String> {
        get_version()
    }

    async fn authenticated_runtime_vfs(
        &self,
        host: &ibex_runtime::host::Host,
    ) -> Result<ibex_runtime::vfs::AuthenticatedRuntimeVfs> {
        self.ensure_thread()?;
        let runtime = self.ensure_runtime().await?;
        host.authenticated_runtime_vfs(runtime.runtime_nonce)
            .map_err(anyhow::Error::new)
    }

    async fn load_runtime(&self) -> Result<()> {
        let mut loaded = self.runtime_loaded.lock().await;
        if *loaded {
            return Ok(());
        }
        let trace_startup = self.startup_trace_enabled;

        self.maybe_enable_debugger().await?;
        self.ensure_runtime().await?;

        if trace_startup {
            eprintln!("[startup] runtime_bundle_installed_probe_start");
        }
        let already_installed = self.runtime_bundle_installed().await?;
        if trace_startup {
            eprintln!(
                "[startup] runtime_bundle_installed_probe_end installed={}",
                already_installed
            );
        }
        if already_installed {
            let phase = std::time::Instant::now();
            self.seal_armed_shared_runtime_globals().await?;
            if trace_startup {
                eprintln!(
                    "[startup] {:<30} {:>6} us ({:>5.1} ms)",
                    "runtime_seal_globals",
                    phase.elapsed().as_micros(),
                    phase.elapsed().as_micros() as f64 / 1000.0
                );
            }
            let phase = std::time::Instant::now();
            finalize_compartment_baseline(self).await?;
            if trace_startup {
                eprintln!(
                    "[startup] {:<30} {:>6} us ({:>5.1} ms)",
                    "runtime_finalize_compartments",
                    phase.elapsed().as_micros(),
                    phase.elapsed().as_micros() as f64 / 1000.0
                );
            }
            let phase = std::time::Instant::now();
            self.finish_armed_bootstrap().await?;
            if trace_startup {
                eprintln!(
                    "[startup] {:<30} {:>6} us ({:>5.1} ms)",
                    "runtime_finish_bootstrap",
                    phase.elapsed().as_micros(),
                    phase.elapsed().as_micros() as f64 / 1000.0
                );
            }
            *loaded = true;
            return Ok(());
        }

        // An armed engine may evaluate only the runtime bytes embedded in the
        // authenticated engine. Disk fallback would otherwise admit mutable
        // checkout JavaScript or a sibling `.hbc` selected only by mtime, and
        // its background warmer would write beside that tooling source.
        // Diagnostic engines retain the explicit benchmark escape hatch.
        // @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
        let armed_runtime = self.armed_snapshot_digest.is_some();
        let no_disk_fallback = armed_runtime
            || std::env::var("IBEX_NO_DISK_RUNTIME_FALLBACK")
                .or_else(|_| std::env::var("EX_NO_DISK_RUNTIME_FALLBACK"))
                .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false);

        // Try embedded runtime first (compiled into binary by build.rs).
        // This eliminates ~2.3ms of disk I/O on every startup.
        // Windows armed startup consumes the native bundle installed during
        // construction above. This fallback remains disabled there so a failed
        // native install cannot select a second evaluation path.
        let use_embedded_runtime = !embedded_runtime::EMBEDDED_RUNTIME.is_empty() && !cfg!(windows);
        if use_embedded_runtime {
            match self
                .eval_bytes(
                    embedded_runtime::EMBEDDED_RUNTIME,
                    embedded_runtime::EMBEDDED_RUNTIME_NAME,
                    embedded_runtime::EMBEDDED_RUNTIME_IS_BYTECODE,
                )
                .await
            {
                Ok(_) => {
                    self.finalize_runtime_setup().await?;
                }
                Err(e) => {
                    // Embedded runtime failed (e.g. bytecode version mismatch).
                    if no_disk_fallback {
                        if armed_runtime {
                            anyhow::bail!(
                                "Armed runtime rejected disk fallback after embedded runtime failure: {e}"
                            );
                        }
                        anyhow::bail!("Embedded runtime failed and IBEX_NO_DISK_RUNTIME_FALLBACK=1 prevents disk fallback: {e}");
                    }
                    // Fall through to disk-based loading below.
                    if embedded_runtime::EMBEDDED_RUNTIME_IS_BYTECODE
                        && Self::is_bytecode_version_error(&e.to_string())
                    {
                        crate::runtime::mark_bytecode_incompatible();
                    }
                    self.load_runtime_from_disk().await?;
                }
            }
        } else {
            if no_disk_fallback {
                if armed_runtime {
                    anyhow::bail!(
                        "Armed runtime requires authenticated embedded runtime bytes; disk fallback is closed"
                    );
                }
                anyhow::bail!(
                    "No embedded runtime available and IBEX_NO_DISK_RUNTIME_FALLBACK=1 \
                     prevents disk fallback. Build with embedded runtime support."
                );
            }
            // No embedded runtime — fall back to disk-based loading
            self.load_runtime_from_disk().await?;
        }
        self.seal_armed_shared_runtime_globals().await?;
        finalize_compartment_baseline(self).await?;
        self.finish_armed_bootstrap().await?;
        *loaded = true;
        Ok(())
    }

    async fn finish_bootstrap(&self) -> Result<()> {
        self.finish_armed_bootstrap().await
    }

    async fn eval(&self, code: &str) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        let result = self.eval_str(code, "<eval>").await?;
        self.drive_event_loop().await?;
        Ok(result)
    }

    async fn eval_immediate(&self, code: &str) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        self.eval_str(code, "<eval>").await
    }

    async fn evaluate_authenticated(
        &self,
        session: &ArmedSessionToken,
        request: SourceRequest,
    ) -> Result<AuthenticatedEvaluation> {
        self.evaluate_authenticated_for_principals(session, request, None)
            .await
    }

    async fn evaluate_authenticated_generated(
        &self,
        session: &ArmedSessionToken,
        request: SourceRequest,
        entry: AuthenticatedGeneratedEntry,
    ) -> Result<AuthenticatedEvaluation> {
        if entry.bytecode.is_some() {
            anyhow::bail!("authenticated provenance-bearing HBC is not an admitted wrapper form");
        }
        self.load_runtime().await?;
        self.maybe_enable_debugger().await?;
        self.ensure_thread()?;
        let runtime = self.ensure_runtime().await?;
        let mut progress = runtime
            .with_runtime(|raw| unsafe {
                evaluate_authenticated_generated_stage1(
                    raw.cast(),
                    session,
                    request,
                    &entry.source,
                    &entry.record,
                )
            })?
            .map_err(anyhow::Error::new)?;
        let evaluation = loop {
            match progress {
                Stage1EvaluationProgress::Settled(evaluation) => break evaluation,
                Stage1EvaluationProgress::Suspended(suspension) => {
                    let (next_progress, executed, next_timer, now) =
                        runtime.with_runtime(|raw| {
                            let now = current_time_ms();
                            let executed = unsafe { ex_hermes_poll(raw, now) };
                            let next_timer = unsafe { ex_hermes_next_timer(raw) };
                            let progress =
                                unsafe { resume_authenticated_stage1(raw.cast(), suspension) };
                            (progress, executed, next_timer, now)
                        })?;
                    progress = next_progress.map_err(anyhow::Error::new)?;
                    if executed < -2 || executed == -1 {
                        return Err(anyhow::anyhow!(
                            "Hermes failed while driving a suspended authenticated generated evaluation"
                        ));
                    }
                    if matches!(progress, Stage1EvaluationProgress::Suspended(_)) && executed == 0 {
                        let wait = structured_settlement_wait(next_timer, now);
                        wait_for_callback_or_sleep(wait).await;
                    }
                }
            }
        };
        Ok(match evaluation.outcome {
            Stage1EvaluationOutcome::Empty => AuthenticatedEvaluation::Empty,
            Stage1EvaluationOutcome::Value { display, receipt } => AuthenticatedEvaluation::Value {
                display: authenticated_display(display),
                receipt: Some(receipt),
            },
            Stage1EvaluationOutcome::Throw { value, metadata } => {
                AuthenticatedEvaluation::Throw(AuthenticatedThrow {
                    value: authenticated_display(value),
                    metadata: authenticated_throw_metadata(metadata),
                })
            }
            Stage1EvaluationOutcome::Cancelled => AuthenticatedEvaluation::Cancelled,
            Stage1EvaluationOutcome::Lifecycle { exit_code } => {
                AuthenticatedEvaluation::Lifecycle(exit_code)
            }
        })
    }

    async fn acknowledge_display(
        &self,
        receipt: Stage1DisplayReceipt,
        disposition: DisplayDisposition,
    ) -> Result<()> {
        self.ensure_thread()?;
        let runtime = self.ensure_runtime().await?;
        runtime
            .with_runtime(|raw| unsafe {
                acknowledge_stage1_display(
                    raw.cast(),
                    receipt,
                    disposition == DisplayDisposition::Displayed,
                )
            })?
            .map_err(|error| anyhow!(error.to_string()))
    }

    async fn release_undisplayed_value(&self, receipt: Stage1DisplayReceipt) -> Result<()> {
        self.ensure_thread()?;
        let runtime = self.ensure_runtime().await?;
        runtime
            .with_runtime(|raw| unsafe { acknowledge_stage1_display(raw.cast(), receipt, false) })?
            .map_err(anyhow::Error::new)
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    async fn session_conformance_metadata(&self, requested_own_names: &[&str]) -> Result<Value> {
        self.load_runtime().await?;
        self.ensure_thread()?;
        let runtime = self.ensure_runtime().await?;
        let names = requested_own_names
            .iter()
            .map(|name| CString::new(*name).context("observer name contains an interior NUL"))
            .collect::<Result<Vec<_>>>()?;
        let pointers = names.iter().map(|name| name.as_ptr()).collect::<Vec<_>>();
        let output = runtime.with_runtime(|raw| unsafe {
            ibex_test_observe_session_metadata(raw, pointers.as_ptr(), pointers.len())
        })?;
        if output.is_null() {
            anyhow::bail!("Hermes session conformance observer rejected the request");
        }
        let json = unsafe { CStr::from_ptr(output) }
            .to_str()
            .context("Hermes session conformance observer returned invalid UTF-8")?
            .to_owned();
        unsafe { ex_hermes_free_string(output) };
        serde_json::from_str(&json)
            .context("Hermes session conformance observer returned invalid JSON")
    }

    fn active_authenticated_target(&self) -> Option<u64> {
        let runtime = self.cancellation_runtime()?;
        runtime
            .with_session_control(|raw, nonce| unsafe {
                ex_hermes_structured_active_work_target(raw, nonce)
            })
            .ok()
            .filter(|target| *target != 0)
    }

    fn authenticated_cancellation_available(&self) -> bool {
        self.cancellation_runtime().is_some()
    }

    fn next_authenticated_work_unit(&self) -> Result<Option<AuthenticatedWorkUnitEvent>> {
        let Some(runtime) = self.cancellation_runtime() else {
            return Ok(None);
        };
        let mut native = NativeWorkUnitEvent::current();
        let status = runtime.with_session_control(|raw, nonce| unsafe {
            ex_hermes_take_work_unit_event(raw, nonce, &mut native)
        })?;
        match status {
            0 => Ok(None),
            1 => decode_work_unit_event(native).map(Some),
            2 => anyhow::bail!("Hermes work-unit publication queue overflowed"),
            _ => anyhow::bail!("Hermes work-unit publication failed"),
        }
    }

    fn next_authenticated_cancellation(&self) -> Result<Option<AuthenticatedCancellationEvent>> {
        let Some(runtime) = self.cancellation_runtime() else {
            return Ok(None);
        };
        let mut native = NativeCancellationEvent::current();
        let status = runtime.with_session_control(|raw, nonce| unsafe {
            ex_hermes_take_cancellation_event(raw, nonce, &mut native)
        })?;
        match status {
            0 => Ok(None),
            1 => decode_cancellation_event(native).map(Some),
            2 => anyhow::bail!("Hermes terminal-cancellation publication queue overflowed"),
            _ => anyhow::bail!("Hermes terminal-cancellation publication failed"),
        }
    }

    async fn take_authenticated_async_failures(&self) -> Result<Vec<AuthenticatedAsyncFailure>> {
        self.ensure_thread()?;
        let runtime = self.runtime.lock().await;
        let Some(handle) = runtime.as_ref() else {
            return Ok(Vec::new());
        };
        handle.with_runtime(|raw| {
            let mut failures = Vec::new();
            loop {
                let mut native = NativeAsyncFailureEvent::current();
                let status = unsafe { ex_hermes_take_async_failure_event(raw, &mut native) };
                match status {
                    0 => return Ok(failures),
                    1 => {
                        let rendered = unsafe {
                            render_and_release_async_failure_value(
                                raw.cast(),
                                native.value_runtime_nonce,
                                native.value_handle_id,
                            )
                        };
                        let (display, metadata) = match rendered {
                            Ok((display, metadata)) => (
                                authenticated_display(display),
                                authenticated_throw_metadata(metadata),
                            ),
                            Err(error) => {
                                failures.push(AuthenticatedAsyncFailure::capture_unavailable(
                                    format!(
                                        "failed to materialize rooted asynchronous throw: {error}"
                                    ),
                                ));
                                continue;
                            }
                        };
                        failures.push(AuthenticatedAsyncFailure::Captured {
                            thrown: AuthenticatedThrow {
                                value: display,
                                metadata,
                            },
                            owning_principal: async_failure_owner(&native)?,
                            event_identity: async_failure_event_identity(
                                native.kind,
                                native.event_id,
                            )?,
                            associated_evaluation: (native.associated_evaluation != 0)
                                .then_some(native.associated_evaluation),
                        });
                    }
                    2 => {
                        anyhow::ensure!(
                            native.dropped_count != 0,
                            "Hermes published an empty asynchronous failure drop marker"
                        );
                        failures.push(AuthenticatedAsyncFailure::PreReceiptLoss {
                            count: native.dropped_count,
                        });
                    }
                    _ => anyhow::bail!("Hermes asynchronous failure publication failed"),
                }
            }
        })?
    }

    fn cancel_authenticated_target(&self, target_id: u64) -> AuthenticatedCancellationStatus {
        let Some(runtime) = self.cancellation_runtime() else {
            return AuthenticatedCancellationStatus::Unavailable;
        };
        match runtime.with_session_control(|raw, nonce| unsafe {
            ex_hermes_cancel_structured_work_target(raw, nonce, target_id)
        }) {
            Ok(1) => AuthenticatedCancellationStatus::Accepted,
            Ok(0) => AuthenticatedCancellationStatus::Unavailable,
            Ok(2) => AuthenticatedCancellationStatus::StaleTarget,
            Ok(_) | Err(_) => AuthenticatedCancellationStatus::Failed,
        }
    }

    async fn drive_ready_tasks(&self) -> Result<()> {
        self.pump_ready_tasks().await
    }

    async fn wait_for_pending_tasks(&self) {
        // Size the idle wait from the soonest scheduled timer and park until it
        // is due — or, with nothing scheduled, park for IDLE_PARK, waking early
        // on a background-callback notification (an HTTP request, a cross-thread
        // callback). This replaces the REPL's fixed 20 Hz poll: an idle prompt no
        // longer runs an FFI poll 20×/s, and a scheduled timer is serviced when
        // it comes due rather than on the next fixed tick. (ENG-23030 #5)
        let wait = {
            let runtime = self.runtime.lock().await;
            match runtime.as_ref() {
                None => IDLE_PARK,
                Some(handle) => {
                    let now = current_time_ms();
                    let next_timer = handle
                        .with_runtime(|raw| unsafe { ex_hermes_next_timer(raw) })
                        .unwrap_or(-1);
                    repl_idle_wait(next_timer, now, REPL_PARK_FLOOR, IDLE_PARK)
                }
            }
        };
        wait_for_callback_or_sleep(wait).await;
    }

    async fn drain_event_loop(&self) -> Result<()> {
        // At EOF, flush work that is ready now and one-shots already due, then
        // stop — do NOT drive to quiescence. A referenced perpetual `setInterval`
        // (or a self-rescheduling 0-delay timer) keeps the loop pending forever,
        // which hung Ctrl+D with the tty in raw mode (Ctrl+C dead, external kill
        // required). Poll only while something ran or a timer is already due,
        // never sleep-waiting for a future timer, and cap the whole drain with a
        // deadline as a hard backstop against a 0-delay self-reschedule.
        // (ENG-23030 #1)
        self.ensure_thread()?;
        let deadline = std::time::Instant::now() + EOF_DRAIN_BUDGET;
        loop {
            let (executed, activated, next_timer, now) = {
                let runtime = self.runtime.lock().await;
                let handle = match runtime.as_ref() {
                    Some(handle) => handle,
                    None => return Ok(()),
                };
                let now = current_time_ms();
                let (executed, activated, next_timer) =
                    handle.with_runtime(|raw| -> Result<_> {
                        let executed = unsafe { ex_hermes_poll(raw, now) };
                        let activated = handle
                            .shared
                            .drive_retained_module_activations_locked(raw)?;
                        let next_timer = unsafe { ex_hermes_next_timer(raw) };
                        Ok((executed, activated, next_timer))
                    })??;
                (executed, activated, next_timer, now)
            };
            if executed < 0 {
                return Err(anyhow::anyhow!("Hermes task execution failed"));
            }
            if activated == 0 && eof_drain_complete(executed, next_timer, now) {
                break;
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
        }
        Ok(())
    }

    async fn drive_authenticated_program_to_quiescence(
        &self,
    ) -> std::result::Result<(), AuthenticatedProgramDrainFailure> {
        // Program and one-shot authenticated ingress have the same keep-alive
        // boundary as file execution. Unlike `drain_event_loop`, this waits for
        // future referenced timers/native completions until no work remains.
        self.drive_event_loop_typed().await
    }

    async fn run_file(&self, path: &str) -> Result<Option<String>> {
        let result = self.eval_file(path).await?;
        self.drive_event_loop().await?;
        Ok(result)
    }

    async fn run_bytecode_bytes(&self, bytes: &[u8], source_url: &str) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        let result = self.eval_bytes(bytes, source_url, true).await?;
        self.drive_event_loop().await?;
        Ok(result)
    }

    #[cfg(feature = "module-runner")]
    fn evaluate_authenticated_module_graph<'a>(
        &'a self,
        session: &'a ArmedSessionToken,
        request: SourceRequest,
        prepare: super::AuthenticatedModuleGraphPreparer<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<AuthenticatedEvaluation>> + 'a>>
    {
        Box::pin(self.evaluate_native_module_graph(session, request, prepare))
    }

    async fn run_file_immediate(&self, path: &str) -> Result<Option<String>> {
        // Like `run_file` but without driving the event loop to quiescence, so a
        // `.load server.js` that starts a long-lived server/timer returns to the
        // prompt. Background work runs via the REPL idle pump. (ENG-23030 #2)
        self.eval_file(path).await
    }

    async fn start_inspector(&self, host: &str, port: u16) -> Result<()> {
        let authorization = self.unarmed_inspector_authorization()?;
        let mut handle = self.cdp_handle.lock().await;
        if handle.is_some() {
            return Ok(());
        }

        let runtime = self.ensure_runtime().await?;
        let backend: Arc<dyn CdpBackend> = Arc::new(HermesCdpBackend::new(
            runtime,
            self.debugger_requested.clone(),
        ));
        let server = cdp::start_server(&authorization, host, port, backend)?;
        *handle = Some(server);
        Ok(())
    }

    async fn stop_inspector(&self) -> Result<()> {
        let mut handle = self.cdp_handle.lock().await;
        if let Some(server) = handle.take() {
            server.stop();
        }
        Ok(())
    }

    async fn pause_inspector(&self) -> Result<()> {
        self.maybe_enable_debugger().await?;
        let runtime = self.ensure_runtime().await?;
        runtime.with_debugger(|raw| unsafe {
            ex_hermes_debugger_pause(raw);
        })?;
        Ok(())
    }

    async fn wait_for_inspector(&self) -> Result<()> {
        let waiter = {
            let handle = self.cdp_handle.lock().await;
            handle.as_ref().map(|server| server.connection_waiter())
        };
        if let Some(waiter) = waiter {
            waiter.wait().await;
        }
        Ok(())
    }

    async fn wait_for_debugger(&self) -> Result<()> {
        let waiter = {
            let handle = self.cdp_handle.lock().await;
            handle.as_ref().map(|server| server.debugger_waiter())
        };
        if let Some(waiter) = waiter {
            waiter.wait().await;
        }
        self.maybe_enable_debugger().await?;
        Ok(())
    }

    fn supports_feature(&self, feature: EngineFeature) -> bool {
        match feature {
            EngineFeature::BytecodeCompilation => true,
            EngineFeature::CdpDebugging => true,
            EngineFeature::SourceMaps => true,
            EngineFeature::TopLevelAwait => false, // Hermes doesn't support this natively
            EngineFeature::EsmModules => false,    // Not in standalone Hermes
            EngineFeature::CommonJsModules => false,
        }
    }
}

/// Get the Hermes version
pub fn get_version() -> Result<String> {
    let identity = HermesToolIdentity::capture(&find_hermes_binary()?)?;
    let staged = stage_authenticated_hermes_tool(&identity)?;
    let hermes_path = staged.0.join(if cfg!(windows) {
        "hermes.exe"
    } else {
        "hermes"
    });

    let mut command = std::process::Command::new(&hermes_path);
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC");
    let output = command
        .arg("--version")
        .output()
        .context("Failed to get Hermes version")?;
    identity.verify_selected_path()?;

    let version = String::from_utf8_lossy(&output.stdout);
    // Parse the version from output like "Hermes JavaScript compiler version 0.12.0"
    Ok(version.trim().to_string())
}

#[cfg(test)]
fn get_hermesc_version() -> Result<String> {
    let identity = find_hermesc_identity()?;

    let version = get_hermesc_version_at(&identity.path)?;
    identity.verify_selected_path()?;
    Ok(version)
}

fn get_hermesc_version_at(path: &Path) -> Result<String> {
    let mut command = std::process::Command::new(path);
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC");
    let output = command
        .arg("--version")
        .output()
        .context("Failed to get hermesc version")?;

    let version = String::from_utf8_lossy(&output.stdout);
    Ok(version.trim().to_string())
}

/// Extract the `HBC bytecode version: N` from hermesc --version output.
fn extract_hbc_version(version_output: &str) -> Option<u32> {
    for line in version_output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("HBC bytecode version:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Check whether the hermesc compiler produces bytecode compatible with
/// the embedded Hermes runtime. Returns false if hermesc is unavailable
/// or the bytecode versions don't match.
#[cfg(test)]
fn bytecode_versions_compatible() -> bool {
    let Ok(compiler_identity) = find_hermesc_identity() else {
        return false;
    };
    bytecode_versions_compatible_with_compiler(&compiler_identity)
}

fn bytecode_versions_compatible_with_compiler(compiler_identity: &HermesToolIdentity) -> bool {
    // Query the already-selected compiler rather than discovering tools again;
    // detached cache warming receives this identity from bootstrap capture.
    let hermesc_hbc = get_hermesc_version_at(&compiler_identity.path)
        .ok()
        .and_then(|v| extract_hbc_version(&v));
    if compiler_identity.verify_selected_path().is_err() {
        return false;
    }

    // Query the root API exported by the engine binary that is actually mapped
    // into this process. A neighboring `hermes --version` executable can be a
    // different build and is never runtime compatibility truth.
    let hermes_hbc = ibex_runtime::engine::loaded_engine_bytecode_version().ok();

    match (hermesc_hbc, hermes_hbc) {
        (Some(compiler), Some(runtime)) => compiler == runtime,
        // If we can't determine versions, don't attempt compilation
        _ => false,
    }
}

fn current_time_ms() -> u64 {
    // Read the SAME monotonic clock the C++ timer scheduler uses to compute
    // due_ms (nowMs). The value we return is fed to ex_hermes_poll as `now_ms`
    // and subtracted from ex_hermes_next_timer's due_ms to size the park
    // duration, so it must share a clock domain with due_ms. Using a Rust
    // wall clock (SystemTime) made timers vulnerable to NTP steps, and a Rust
    // monotonic clock (Instant) is not guaranteed to share an epoch with the
    // C++ steady_clock — so we route through the one C++ source of truth.
    unsafe { ex_hermes_now_ms() }
}

/// Whether the REPL-EOF drain has run out of work that is ready *now*. Keep
/// draining while a poll executed something (`executed > 0`) or a timer is
/// already due (`next_timer <= now`); stop otherwise so a future/perpetual timer
/// (a referenced `setInterval`) cannot block process exit. `next_timer < 0` means
/// no timers scheduled. (ENG-23030 #1)
fn eof_drain_complete(executed: i32, next_timer: i64, now: u64) -> bool {
    if executed > 0 {
        return false;
    }
    next_timer < 0 || (next_timer as u64) > now
}

/// How long the idle REPL should park before pumping ready event-loop work,
/// given the soonest scheduled timer (`next_timer`, ms on the shared clock; < 0
/// when none) and `now`. Nothing scheduled parks for `idle_park` (waking early on
/// a background-callback notification); a scheduled timer parks until it is due,
/// floored so a 0-delay timer cannot busy-spin the prompt and capped at
/// `idle_park`. Replaces the fixed 20 Hz poll. (ENG-23030 #5)
fn repl_idle_wait(
    next_timer: i64,
    now: u64,
    floor: std::time::Duration,
    idle_park: std::time::Duration,
) -> std::time::Duration {
    if next_timer < 0 {
        return idle_park;
    }
    let delay = std::time::Duration::from_millis((next_timer as u64).saturating_sub(now));
    // `floor.min(idle_park)` keeps the lower bound <= the cap even when a build
    // configures a very short IDLE_PARK (non-`cli-notify`), so the clamp is well
    // formed.
    delay.max(floor.min(idle_park)).min(idle_park)
}

/// Park interval for a suspended top-level-await unit. A future timer sets the
/// deadline and callback notification wakes the park early. `IDLE_PARK` is a
/// lost-wakeup fallback when no timer exists, never a settlement timeout: the
/// caller repeats until native settlement or supervisor shutdown.
fn structured_settlement_wait(next_timer: i64, now: u64) -> std::time::Duration {
    if next_timer < 0 {
        return IDLE_PARK;
    }
    let delay = std::time::Duration::from_millis((next_timer as u64).saturating_sub(now));
    delay
        .max(std::time::Duration::from_millis(1))
        .min(IDLE_PARK)
}

fn temporary_output_path(path: &std::path::Path) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let mut file_name = std::ffi::OsString::from(".");
    file_name.push(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("ibex-bytecode")),
    );
    file_name.push(format!(".{}.{seq}.tmp", std::process::id()));
    path.with_file_name(file_name)
}

struct CachePublishLock(std::fs::File);

impl Drop for CachePublishLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

async fn acquire_cache_publish_lock(output: &Path) -> Result<CachePublishLock> {
    let lock_path = path_with_suffix(output, ".lock");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("Failed to open bytecode cache lock {}", lock_path.display()))?;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(CachePublishLock(file)),
            Err(std::fs::TryLockError::WouldBlock) => {
                if std::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "Timed out waiting to publish bytecode cache {}",
                        output.display()
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).with_context(|| {
                    format!("Failed to lock bytecode cache {}", output.display())
                });
            }
        }
    }
}

#[derive(Debug)]
struct BytecodeLoadError(String);

impl std::fmt::Display for BytecodeLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BytecodeLoadError {}

/// A cached entry may be retried from source only when the native engine
/// returned its dedicated pre-execution bytecode-rejection status. Exception
/// messages are user-controlled and are never classification input.
pub(crate) fn is_bytecode_load_error(error: &anyhow::Error) -> bool {
    error.is::<BytecodeLoadError>()
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BytecodeArtifactManifest {
    version: u32,
    source_path: String,
    source_sha256: String,
    bytecode_sha256: String,
    source_map_path: Option<String>,
    source_map_sha256: Option<String>,
    toolchain_identity: String,
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn bytecode_manifest_path(bytecode: &Path) -> PathBuf {
    path_with_suffix(bytecode, ".meta.json")
}

fn hermesc_source_map_path(bytecode: &Path) -> PathBuf {
    path_with_suffix(bytecode, ".map")
}

fn configure_hermesc_compile_command(
    cmd: &mut Command,
    output: &Path,
    emit_source_map: bool,
    input: &Path,
) {
    if crate::hermes_es6_block_scoping_enabled() {
        cmd.arg("-Xes6-block-scoping");
    }
    cmd.arg("-emit-binary");
    cmd.arg("-out");
    cmd.arg(output);
    if emit_source_map {
        // hermesc's -output-source-map is a boolean flag. It always writes to
        // `<-out>.map`; a following pathname is parsed as another input.
        cmd.arg("-output-source-map");
    }
    cmd.arg(input);
}

#[cfg(test)]
fn bytecode_source_map_is_fresh(bytecode: &Path, source_map: &Path) -> bool {
    verified_bytecode_source_map(bytecode, source_map).is_some()
}

fn verified_bytecode_source_map(
    bytecode: &Path,
    source_map: &Path,
) -> Option<std::sync::Arc<super::sourcemap::SourceMap>> {
    // No attestation means no generated-code trust, irrespective of what a
    // cache manifest claims its toolchain identity was.
    ibex_runtime::engine::loaded_engine_binary_identity().ok()?;
    let Ok(raw) = std::fs::read(bytecode_manifest_path(bytecode)) else {
        return None;
    };
    let Ok(manifest) = serde_json::from_slice::<BytecodeArtifactManifest>(&raw) else {
        return None;
    };
    if manifest.version != 2 || manifest.toolchain_identity != bytecode_cache_identity() {
        return None;
    }
    let expected_map = std::fs::canonicalize(source_map).ok()?;
    let expected_map_utf8 = expected_map.to_str()?;
    if manifest.source_map_path.as_deref() != Some(expected_map_utf8) {
        return None;
    }
    let source_path = std::fs::canonicalize(&manifest.source_path).ok()?;
    if source_path.to_str()? != manifest.source_path {
        return None;
    }

    // Verify the exact vectors consumed below rather than hashing each path
    // and reopening the map afterwards. This closes the verify/use race for
    // both the HBC buffer and its source map.
    let source_bytes = std::fs::read(source_path).ok()?;
    let bytecode_bytes = std::fs::read(bytecode).ok()?;
    let map_bytes = std::fs::read(expected_map).ok()?;
    let expected_map_digest = manifest.source_map_sha256.as_deref()?;
    if format!("{:x}", Sha256::digest(&source_bytes)) != manifest.source_sha256
        || format!("{:x}", Sha256::digest(&bytecode_bytes)) != manifest.bytecode_sha256
        || format!("{:x}", Sha256::digest(&map_bytes)) != expected_map_digest
    {
        return None;
    }
    super::sourcemap::SourceMap::from_bytes(&map_bytes)
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

fn canonical_publication_path(path: &Path) -> Result<PathBuf> {
    let absolute = absolute_path(path);
    let file_name = absolute
        .file_name()
        .context("generated artifact path has no file name")?;
    let parent = absolute
        .parent()
        .context("generated artifact path has no parent directory")?;
    let canonical_parent = std::fs::canonicalize(parent).with_context(|| {
        format!(
            "failed to authenticate generated artifact directory {}",
            parent.display()
        )
    })?;
    Ok(canonical_parent.join(file_name))
}

async fn sha256_path(path: &Path) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(tokio::fs::read(path).await?)
    ))
}

pub(crate) fn bytecode_cache_identity() -> String {
    let compiler = find_hermesc_identity().ok();
    bytecode_cache_identity_for(compiler.as_ref())
}

fn bytecode_cache_identity_for(compiler: Option<&HermesToolIdentity>) -> String {
    // Bind generated HBC to the engine artifact that is actually mapped, not a
    // separately discovered `hermes` executable. Path/inode are deliberately
    // excluded: identical verified engine bytes may move between installs,
    // while digest + architecture + structural features capture every input
    // that changes the runtime's bytecode contract.
    let runtime =
        match ibex_runtime::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg) {
            Ok(identity) => {
                let mut structural_features = identity.structural_features;
                structural_features.sort();
                structural_features.dedup();
                serde_json::to_vec(&(
                    "ibex-loaded-hermes-v1",
                    identity.kind,
                    identity.binary_digest,
                    identity.target_architecture,
                    structural_features,
                ))
                .expect("loaded Hermes identity contains only serializable strings")
            }
            Err(error) => {
                // Cache consumers independently require mapped-engine
                // attestation. Keep fallback keys distinct within this process
                // as a second guard and to avoid converging failed publishers.
                static UNATTESTED_SEQUENCE: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let sequence = UNATTESTED_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                format!(
                    "ibex-unattested-hermes\0{}\0{sequence}\0{error}",
                    std::process::id()
                )
                .into_bytes()
            }
        };
    let compiler = compiler
        .map(HermesToolIdentity::cache_fingerprint)
        .unwrap_or_else(|| "compiler-identity-unavailable".into());
    let mut digest = Sha256::new();
    digest.update(b"ibex-hbc-toolchain-v4\0");
    digest.update(runtime);
    digest.update(b"\0");
    digest.update(compiler.as_bytes());
    digest.update(b"\0es6-block-scoping\0");
    let block_scoping_mode: &[u8] = if crate::hermes_es6_block_scoping_enabled() {
        b"enabled"
    } else {
        b"legacy"
    };
    digest.update(block_scoping_mode);
    format!("{:x}", digest.finalize())
}

pub(crate) struct VerifiedBytecodeArtifact {
    pub(crate) bytes: Vec<u8>,
    pub(crate) source_path: PathBuf,
}

pub(crate) async fn load_verified_bytecode_artifact(
    expected_source: Option<&Path>,
    bytecode: &Path,
) -> Result<VerifiedBytecodeArtifact> {
    ibex_runtime::engine::loaded_engine_binary_identity()
        .map_err(anyhow::Error::msg)
        .context("cannot authenticate the loaded Hermes engine for bytecode cache use")?;
    let Ok(raw) = tokio::fs::read(bytecode_manifest_path(bytecode)).await else {
        anyhow::bail!("bytecode cache manifest is missing");
    };
    let manifest = serde_json::from_slice::<BytecodeArtifactManifest>(&raw)
        .context("invalid bytecode cache manifest")?;
    if manifest.version != 2 || manifest.toolchain_identity != bytecode_cache_identity() {
        anyhow::bail!("bytecode cache toolchain identity mismatch");
    }
    let source_path = std::fs::canonicalize(&manifest.source_path)
        .with_context(|| format!("bytecode source is missing: {}", manifest.source_path))?;
    let source_path_utf8 = source_path
        .to_str()
        .context("bytecode cache does not support non-UTF-8 source paths")?;
    if source_path_utf8 != manifest.source_path {
        anyhow::bail!("bytecode source path is not canonical");
    }
    if let Some(expected_source) = expected_source {
        let expected_source = std::fs::canonicalize(expected_source).with_context(|| {
            format!("bytecode source is missing: {}", expected_source.display())
        })?;
        if expected_source != source_path {
            anyhow::bail!("bytecode cache source identity mismatch");
        }
    }
    if manifest.source_map_path.is_some() || manifest.source_map_sha256.is_some() {
        anyhow::bail!("entry bytecode cache unexpectedly contains a source map");
    }
    // Read each selected object once. The byte vector returned below is the
    // same vector whose digest is checked, so pathname replacement after this
    // point cannot change what Hermes executes.
    let source_bytes = tokio::fs::read(&source_path).await?;
    let bytecode_bytes = tokio::fs::read(bytecode).await?;
    if format!("{:x}", Sha256::digest(&source_bytes)) != manifest.source_sha256
        || format!("{:x}", Sha256::digest(&bytecode_bytes)) != manifest.bytecode_sha256
    {
        anyhow::bail!("bytecode cache digest mismatch");
    }
    Ok(VerifiedBytecodeArtifact {
        bytes: bytecode_bytes,
        source_path,
    })
}

pub(crate) async fn bytecode_artifact_is_fresh(source: &Path, bytecode: &Path) -> bool {
    load_verified_bytecode_artifact(Some(source), bytecode)
        .await
        .is_ok()
}

async fn replace_file_atomically(staged: &Path, final_path: &Path) -> Result<()> {
    #[cfg(not(windows))]
    {
        tokio::fs::rename(staged, final_path).await?;
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        extern "system" {
            fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
        }
        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
        let mut from: Vec<u16> = staged.as_os_str().encode_wide().collect();
        let mut to: Vec<u16> = final_path.as_os_str().encode_wide().collect();
        from.push(0);
        to.push(0);
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

struct TemporaryCompileDirectory(PathBuf);

impl Drop for TemporaryCompileDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn rewrite_staged_source_map(
    source_map: &Path,
    staged_source: &Path,
    original_source: &Path,
) -> Result<()> {
    let bytes = std::fs::read(source_map)?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("Invalid hermesc source map {}", source_map.display()))?;
    if let Some(sources) = value
        .get_mut("sources")
        .and_then(serde_json::Value::as_array_mut)
    {
        let staged = staged_source.to_string_lossy();
        let staged_name = staged_source.file_name().and_then(|name| name.to_str());
        let original = absolute_path(original_source)
            .to_string_lossy()
            .into_owned();
        for source in sources {
            let Some(text) = source.as_str() else {
                continue;
            };
            if text == staged || staged_name.is_some_and(|name| text == name) {
                *source = serde_json::Value::String(original.clone());
            }
        }
    }
    std::fs::write(source_map, serde_json::to_vec(&value)?)?;
    Ok(())
}

#[derive(Clone)]
struct CapturedHbcCompileEnvironment {
    compiler_identity: HermesToolIdentity,
    timeout: std::time::Duration,
    test_barrier: Option<PathBuf>,
}

impl CapturedHbcCompileEnvironment {
    fn capture() -> Result<Self> {
        let timeout = std::env::var("IBEX_HERMESC_TIMEOUT_MS")
            .ok()
            .or_else(|| std::env::var("EXACT_HERMESC_TIMEOUT_MS").ok());
        Ok(Self {
            compiler_identity: find_hermesc_identity()?,
            timeout: parse_timeout_ms(timeout.as_deref(), DEFAULT_HERMESC_TIMEOUT_MS),
            test_barrier: std::env::var_os("IBEX_TEST_HBC_COMPILE_BARRIER").map(PathBuf::from),
        })
    }
}

async fn wait_for_hbc_test_barrier(
    name: &str,
    output: &Path,
    barrier: Option<&Path>,
) -> Result<()> {
    let Some(dir) = barrier else {
        return Ok(());
    };
    tokio::fs::create_dir_all(dir).await?;
    if let Ok(target) = tokio::fs::read_to_string(dir.join("target")).await {
        if target != output.to_string_lossy() {
            return Ok(());
        }
    }
    tokio::fs::write(dir.join(format!("{name}.ready")), []).await?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !dir.join(format!("{name}.release")).exists() {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for HBC {name} test barrier");
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    Ok(())
}

/// Compile a JavaScript file to Hermes bytecode
pub async fn compile_to_bytecode(
    input: &str,
    output: &std::path::Path,
    source_map: Option<&std::path::Path>,
) -> Result<()> {
    let input_path = std::fs::canonicalize(input)
        .with_context(|| format!("Failed to authenticate bytecode source {input}"))?;
    let source = tokio::fs::read(&input_path)
        .await
        .with_context(|| format!("Failed to read bytecode source {input}"))?;
    compile_source_to_bytecode_with_attestation(
        &input_path,
        &source,
        output,
        source_map,
        BytecodeOutputKind::ExplicitBuild,
    )
    .await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BytecodeOutputKind {
    ExplicitBuild,
    GeneratedCache,
}

impl BytecodeOutputKind {
    fn requires_runtime_attestation(self) -> bool {
        matches!(self, Self::GeneratedCache)
    }
}

struct BytecodeCompileConfig<'a> {
    compiler_identity: &'a HermesToolIdentity,
    output_kind: BytecodeOutputKind,
    timeout: std::time::Duration,
    test_barrier: Option<&'a Path>,
}

pub(crate) async fn compile_source_to_bytecode(
    input_path: &Path,
    source: &[u8],
    output: &Path,
    source_map: Option<&Path>,
) -> Result<()> {
    compile_source_to_bytecode_with_attestation(
        input_path,
        source,
        output,
        source_map,
        BytecodeOutputKind::GeneratedCache,
    )
    .await
}

async fn compile_attested_cache_bytecode_with_environment(
    input: &str,
    output: &Path,
    source_map: Option<&Path>,
    environment: &CapturedHbcCompileEnvironment,
) -> Result<()> {
    let input_path = std::fs::canonicalize(input)
        .with_context(|| format!("Failed to authenticate bytecode source {input}"))?;
    let source = tokio::fs::read(&input_path)
        .await
        .with_context(|| format!("Failed to read bytecode source {input}"))?;
    compile_source_to_bytecode_with_captured_environment(
        &input_path,
        &source,
        output,
        source_map,
        BytecodeCompileConfig {
            compiler_identity: &environment.compiler_identity,
            output_kind: BytecodeOutputKind::GeneratedCache,
            timeout: environment.timeout,
            test_barrier: environment.test_barrier.as_deref(),
        },
    )
    .await
}

async fn compile_source_to_bytecode_with_attestation(
    input_path: &Path,
    source: &[u8],
    output: &Path,
    source_map: Option<&Path>,
    output_kind: BytecodeOutputKind,
) -> Result<()> {
    let environment = CapturedHbcCompileEnvironment::capture()?;
    compile_source_to_bytecode_with_captured_environment(
        input_path,
        source,
        output,
        source_map,
        BytecodeCompileConfig {
            compiler_identity: &environment.compiler_identity,
            output_kind,
            timeout: environment.timeout,
            test_barrier: environment.test_barrier.as_deref(),
        },
    )
    .await
}

#[cfg(test)]
async fn compile_source_to_bytecode_with_compiler(
    input_path: &Path,
    source: &[u8],
    output: &Path,
    source_map: Option<&Path>,
    compiler_identity: &HermesToolIdentity,
    output_kind: BytecodeOutputKind,
) -> Result<()> {
    let timeout = std::env::var("IBEX_HERMESC_TIMEOUT_MS")
        .ok()
        .or_else(|| std::env::var("EXACT_HERMESC_TIMEOUT_MS").ok());
    let timeout = parse_timeout_ms(timeout.as_deref(), DEFAULT_HERMESC_TIMEOUT_MS);
    let test_barrier = std::env::var_os("IBEX_TEST_HBC_COMPILE_BARRIER").map(PathBuf::from);
    compile_source_to_bytecode_with_captured_environment(
        input_path,
        source,
        output,
        source_map,
        BytecodeCompileConfig {
            compiler_identity,
            output_kind,
            timeout,
            test_barrier: test_barrier.as_deref(),
        },
    )
    .await
}

async fn compile_source_to_bytecode_with_captured_environment(
    input_path: &Path,
    source: &[u8],
    output: &Path,
    source_map: Option<&Path>,
    config: BytecodeCompileConfig<'_>,
) -> Result<()> {
    let BytecodeCompileConfig {
        compiler_identity,
        output_kind,
        timeout,
        test_barrier,
    } = config;
    if output_kind.requires_runtime_attestation() {
        ibex_runtime::engine::loaded_engine_binary_identity()
            .map_err(anyhow::Error::msg)
            .context("cannot authenticate the loaded Hermes engine for bytecode cache use")?;
    }
    // Select/canonicalize the source identity before any async compile work.
    // Callers read the exact bytes through this canonical path, so the
    // manifest never canonicalizes a different pathname object after compile.
    let source_path = std::fs::canonicalize(input_path)
        .with_context(|| format!("Failed to authenticate source {}", input_path.display()))?;
    let source_path_string = source_path
        .to_str()
        .context("bytecode cache does not support non-UTF-8 source paths")?
        .to_owned();
    let _publish_lock = acquire_cache_publish_lock(output).await?;
    // Gate on the `HBC bytecode version:` line both tools print — the version
    // that actually determines whether the runtime can load hermesc's output.
    // Comparing an arbitrary token of the multi-line `--version` output
    // (previously: the LAST whitespace token, which is `input` from hermes'
    // trailing "Zip file input" feature line vs `99` from hermesc) made this
    // gate a false positive on every call and silently disabled entry-bytecode
    // caching (ENG-23495). When either version line is absent we proceed, as
    // before: a genuinely incompatible buffer is caught at load time and falls
    // back to source (`is_bytecode_load_error`, ENG-23484).
    // @ref LLP 0005#bytecode-precompilation-hermesc — run-time entry cache gates on HBC version
    let compile_dir = temporary_output_path(&output.with_extension("compile"));
    tokio::fs::create_dir(&compile_dir)
        .await
        .with_context(|| format!("Failed to create compile stage {}", compile_dir.display()))?;
    let _compile_dir = TemporaryCompileDirectory(compile_dir.clone());
    let compiler_name = if cfg!(windows) {
        "hermesc.exe"
    } else {
        "hermesc"
    };
    let staged_compiler = compile_dir.join(compiler_name);
    tokio::fs::write(&staged_compiler, compiler_identity.bytes.as_slice()).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&staged_compiler, std::fs::Permissions::from_mode(0o700))
            .await?;
    }
    if sha256_path(&staged_compiler).await? != compiler_identity.sha256 {
        anyhow::bail!("Hermes compiler changed while staging authenticated binary");
    }
    compiler_identity.verify_selected_path()?;

    let source_name = source_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("entry.js"));
    let staged_input = compile_dir.join(source_name);
    tokio::fs::write(&staged_input, source).await?;
    let source_digest = format!("{:x}", Sha256::digest(source));
    wait_for_hbc_test_barrier("input-staged", output, test_barrier).await?;

    let runtime_hbc = ibex_runtime::engine::loaded_engine_bytecode_version().ok();
    let compiler_hbc = get_hermesc_version_at(&staged_compiler)
        .ok()
        .and_then(|v| extract_hbc_version(&v));
    if let (Some(runtime), Some(compiler)) = (runtime_hbc, compiler_hbc) {
        if runtime != compiler {
            anyhow::bail!(
                "Hermes bytecode version mismatch: runtime HBC {} vs hermesc HBC {}. Rebuild bytecode with matching Hermes.",
                runtime,
                compiler
            );
        }
    }

    let temp_output = temporary_output_path(output);
    // @ref LLP 0005#bytecode-precompilation-hermesc — hermesc derives the
    // source-map path from `-out`; only publication uses the caller's path.
    let temp_source_map = source_map.map(|_| hermesc_source_map_path(&temp_output));

    let mut cmd = Command::new(&staged_compiler);
    cmd.env_clear()
        .env("TMPDIR", &compile_dir)
        .env("TMP", &compile_dir)
        .env("TEMP", &compile_dir)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .current_dir(&compile_dir);
    configure_hermesc_compile_command(
        &mut cmd,
        &temp_output,
        temp_source_map.is_some(),
        &staged_input,
    );

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let result = output_with_timeout(&mut cmd, timeout, "hermesc")
        .await
        .context("Failed to run hermesc")?;

    if !result.status.success() {
        let _ = tokio::fs::remove_file(&temp_output).await;
        if let Some(map_path) = temp_source_map.as_ref() {
            let _ = tokio::fs::remove_file(map_path).await;
        }
        let stderr = String::from_utf8_lossy(&result.stderr);
        anyhow::bail!("Bytecode compilation failed:\n{}", stderr);
    }

    wait_for_hbc_test_barrier("compile-finished", output, test_barrier).await?;
    compiler_identity.verify_selected_path()?;
    if let Some(map_path) = temp_source_map.as_ref() {
        rewrite_staged_source_map(map_path, &staged_input, &source_path)?;
    }

    let source_map_path = source_map
        .map(|path| {
            // The final map does not exist until publication, so authenticate
            // its existing parent and append only the selected file name.
            // This also normalizes macOS `/var` -> `/private/var` aliases to
            // the same identity verified by the consumer after publication.
            let path = canonical_publication_path(path)?;
            path.to_str()
                .context("bytecode cache does not support non-UTF-8 source-map paths")
                .map(str::to_owned)
        })
        .transpose()?;
    let source_map_sha256 = match temp_source_map.as_ref() {
        Some(path) => Some(sha256_path(path).await?),
        None => None,
    };
    let manifest = BytecodeArtifactManifest {
        version: 2,
        source_path: source_path_string,
        source_sha256: source_digest,
        bytecode_sha256: sha256_path(&temp_output).await?,
        source_map_path,
        source_map_sha256,
        toolchain_identity: bytecode_cache_identity_for(Some(compiler_identity)),
    };
    let final_manifest = bytecode_manifest_path(output);
    let temp_manifest = temporary_output_path(&final_manifest);
    tokio::fs::write(&temp_manifest, serde_json::to_vec(&manifest)?)
        .await
        .with_context(|| format!("Failed to stage {}", final_manifest.display()))?;

    // The manifest is the completion marker for the HBC+map unit. Invalidate
    // the old marker before replacing either member, then publish a new marker
    // only after both digest-bound files are in place.
    tokio::fs::remove_file(&final_manifest).await.ok();

    if let (Some(final_map), Some(temp_map)) = (source_map, temp_source_map.as_ref()) {
        replace_file_atomically(temp_map, final_map)
            .await
            .with_context(|| {
                format!("Failed to publish source map cache {}", final_map.display())
            })?;
    }

    replace_file_atomically(&temp_output, output)
        .await
        .with_context(|| format!("Failed to publish bytecode cache {}", output.display()))?;
    replace_file_atomically(&temp_manifest, &final_manifest)
        .await
        .with_context(|| format!("Failed to publish {}", final_manifest.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "capsec-conformance-observer")]
    struct CAbiBlockingWorkReleaseGuard(Arc<SharedRuntime>);

    #[cfg(feature = "capsec-conformance-observer")]
    impl Drop for CAbiBlockingWorkReleaseGuard {
        fn drop(&mut self) {
            let _ = self.0.with_session_control(|raw, _nonce| unsafe {
                ibex_exact_runtime_c_abi_probe_release_blocking_work(raw)
            });
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    struct StructuredControlLeasePauseReleaseGuard;

    #[cfg(feature = "capsec-conformance-observer")]
    impl Drop for StructuredControlLeasePauseReleaseGuard {
        fn drop(&mut self) {
            unsafe {
                ibex_test_release_structured_control_lease_pause();
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn armed_engine_refuses_inspector_before_runtime_or_listener_allocation() {
        let engine = HermesEngine::new_with_armed_snapshot(Some(
            "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ))
        .unwrap();

        let error = engine
            .start_inspector("127.0.0.1", 0)
            .await
            .expect_err("an armed engine must close the inspector sink");

        assert_eq!(error.to_string(), ARMED_INSPECTOR_CLOSED_MESSAGE);
        assert!(engine.runtime.lock().await.is_none());
        assert!(engine.cdp_handle.lock().await.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn armed_engine_refuses_disk_runtime_fallback_before_lookup() {
        let engine = HermesEngine::new_with_armed_snapshot(Some(
            "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ))
        .unwrap();
        let error = engine
            .load_runtime_from_disk()
            .await
            .expect_err("armed runtime must never inspect disk fallback");
        assert_eq!(error.to_string(), "armed runtime disk fallback is closed");
        assert!(engine.runtime.lock().await.is_none());
    }

    #[test]
    fn hermes_job_identity_patch_saturates_at_unavailable() {
        const PATCH: &str = include_str!(
            "../../../../patches/hermes/0011-structured-async-failure-provenance.patch"
        );
        assert!(PATCH.contains(
            "+  const uint64_t identity = nextJobIdentity_;\n+  if (nextJobIdentity_ != 0) {\n+    ++nextJobIdentity_;\n+  }"
        ));
        assert!(
            !PATCH.contains("nextJobIdentity_++"),
            "job identities must fail closed at zero instead of wrapping to 1"
        );
    }

    #[test]
    fn native_work_unit_layout_and_identity_validation_are_pinned() {
        assert_eq!(std::mem::size_of::<NativeWorkUnitEvent>(), 32);
        assert_eq!(std::mem::offset_of!(NativeWorkUnitEvent, target_id), 16);
        assert_eq!(std::mem::offset_of!(NativeWorkUnitEvent, scheduling_id), 24);

        let due = decode_work_unit_event(NativeWorkUnitEvent {
            abi_version: WORK_UNIT_EVENT_ABI_VERSION,
            struct_size: std::mem::size_of::<NativeWorkUnitEvent>() as u32,
            kind: 3,
            phase: 1,
            target_id: 0,
            scheduling_id: 17,
        })
        .unwrap();
        assert_eq!(due.kind, AuthenticatedWorkUnitKind::Timer);
        assert_eq!(due.phase, AuthenticatedWorkUnitPhase::Due);
        assert_eq!(due.scheduling_id, 17);

        let malformed = NativeWorkUnitEvent {
            target_id: 99,
            ..NativeWorkUnitEvent::current()
        };
        assert!(decode_work_unit_event(malformed).is_err());

        assert_eq!(std::mem::size_of::<NativeCancellationEvent>(), 24);
        assert_eq!(std::mem::offset_of!(NativeCancellationEvent, target_id), 16);
        let accepted = decode_cancellation_event(NativeCancellationEvent {
            abi_version: CANCELLATION_EVENT_ABI_VERSION,
            struct_size: std::mem::size_of::<NativeCancellationEvent>() as u32,
            resolution: 1,
            reserved: 0,
            target_id: 42,
        })
        .unwrap();
        assert_eq!(accepted.target_id, 42);
        assert_eq!(
            accepted.resolution,
            AuthenticatedCancellationResolution::Accepted
        );
        assert!(decode_cancellation_event(NativeCancellationEvent {
            target_id: 0,
            ..NativeCancellationEvent::current()
        })
        .is_err());

        assert_eq!(std::mem::size_of::<NativeAsyncFailureEvent>(), 72);
        assert_eq!(
            std::mem::offset_of!(NativeAsyncFailureEvent, value_runtime_nonce),
            16
        );
        assert_eq!(
            std::mem::offset_of!(NativeAsyncFailureEvent, host_context_id),
            32
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn native_timer_unit_is_published_and_exactly_cancellable_from_another_thread() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let engine = Arc::new(HermesEngine::new().unwrap());
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ibex_test_enable_work_unit_publication(raw) })
                .unwrap(),
            1
        );

        engine
            .eval_immediate(
                "setTimeout(function () { var end = Date.now() + 3000; while (Date.now() < end) {} }, 0); void 0",
            )
            .await
            .unwrap();

        let controller_engine = Arc::clone(&engine);
        let controller = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                while let Some(event) = controller_engine
                    .next_authenticated_work_unit()
                    .expect("native work-unit queue must remain valid")
                {
                    if event.kind == AuthenticatedWorkUnitKind::Timer
                        && event.phase == AuthenticatedWorkUnitPhase::Begin
                    {
                        let stale = event.target_id.checked_add(1).unwrap();
                        assert_eq!(
                            controller_engine.cancel_authenticated_target(stale),
                            AuthenticatedCancellationStatus::StaleTarget,
                            "a wrong target must not interrupt the executing timer"
                        );
                        assert_eq!(
                            controller_engine.cancel_authenticated_target(event.target_id),
                            AuthenticatedCancellationStatus::Accepted
                        );
                        assert_eq!(
                            controller_engine.cancel_authenticated_target(event.target_id),
                            AuthenticatedCancellationStatus::Accepted,
                            "duplicate requests for one target must share one native break"
                        );
                        return event;
                    }
                }
                std::thread::yield_now();
            }
            panic!("timer Begin was not observable from the controller thread");
        });

        let started = std::time::Instant::now();
        engine.drive_ready_tasks().await.unwrap();
        let timer = controller.join().unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "exact cancellation did not stop the executing timer"
        );

        let mut saw_end = false;
        while let Some(event) = engine.next_authenticated_work_unit().unwrap() {
            if event.target_id == timer.target_id
                && event.kind == AuthenticatedWorkUnitKind::Timer
                && event.phase == AuthenticatedWorkUnitPhase::End
            {
                saw_end = true;
            }
        }
        assert!(saw_end, "cancelled timer did not publish its exact End");
        let terminal = engine
            .next_authenticated_cancellation()
            .unwrap()
            .expect("cancelled timer did not publish a terminal result");
        assert_eq!(terminal.target_id, timer.target_id);
        assert_eq!(
            terminal.resolution,
            AuthenticatedCancellationResolution::Accepted
        );
        assert!(engine.next_authenticated_cancellation().unwrap().is_none());
        assert!(
            engine
                .take_authenticated_async_failures()
                .await
                .unwrap()
                .is_empty(),
            "an accepted engine timeout must not be reported as a user throw"
        );
        assert_eq!(
            engine.eval_immediate("1 + 1").await.unwrap().as_deref(),
            Some("2")
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn module_graph_gap_publishes_callback_target_and_cooperates_with_cancellation() {
        const GRAPH_TARGET: u64 = 0x7001;
        const CALLBACK_TARGET: u64 = 0x7002;
        const GRAPH_SCHEDULE: u64 = 41;
        const CALLBACK_SCHEDULE: u64 = 42;

        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(ibex_test_enable_work_unit_publication(raw), 1);
                assert_eq!(
                    ibex_test_begin_module_graph_transition_probe(
                        raw,
                        GRAPH_TARGET,
                        GRAPH_SCHEDULE,
                    ),
                    1
                );
            })
            .unwrap();
        assert_eq!(engine.active_authenticated_target(), Some(GRAPH_TARGET));

        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe {
                    ex_hermes_structured_module_graph_suspend(raw, GRAPH_TARGET)
                })
                .unwrap(),
            0
        );
        assert_eq!(engine.active_authenticated_target(), None);
        assert_eq!(
            engine.cancel_authenticated_target(GRAPH_TARGET),
            AuthenticatedCancellationStatus::Unavailable,
            "a suspended graph must not remain the cancellation target"
        );

        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe {
                    ibex_test_begin_callback_during_module_graph_gap(
                        raw,
                        CALLBACK_TARGET,
                        CALLBACK_SCHEDULE,
                    )
                })
                .unwrap(),
            1
        );
        assert_eq!(
            engine.active_authenticated_target(),
            Some(CALLBACK_TARGET),
            "host work did not receive an independent exact target"
        );
        assert_eq!(
            engine.cancel_authenticated_target(GRAPH_TARGET),
            AuthenticatedCancellationStatus::StaleTarget,
            "the suspended graph target must not alias its callback"
        );
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe {
                    ibex_test_end_callback_during_module_graph_gap(
                        raw,
                        CALLBACK_TARGET,
                        CALLBACK_SCHEDULE,
                    )
                })
                .unwrap(),
            1
        );

        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe {
                    ex_hermes_structured_module_graph_resume(raw, GRAPH_TARGET)
                })
                .unwrap(),
            0
        );
        assert_eq!(engine.active_authenticated_target(), Some(GRAPH_TARGET));
        assert_eq!(
            engine.cancel_authenticated_target(GRAPH_TARGET),
            AuthenticatedCancellationStatus::Accepted
        );
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe {
                    ex_hermes_structured_module_graph_suspend(raw, GRAPH_TARGET)
                })
                .unwrap(),
            1,
            "an executing graph did not observe its pending cancellation boundary"
        );
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe {
                    ibex_test_end_module_graph_transition_probe(raw, GRAPH_TARGET, 1)
                })
                .unwrap(),
            1
        );

        let mut events = Vec::new();
        while let Some(event) = engine.next_authenticated_work_unit().unwrap() {
            events.push((
                event.kind,
                event.phase,
                event.target_id,
                event.scheduling_id,
            ));
        }
        assert_eq!(
            events,
            vec![
                (
                    AuthenticatedWorkUnitKind::Evaluation,
                    AuthenticatedWorkUnitPhase::Begin,
                    GRAPH_TARGET,
                    GRAPH_SCHEDULE,
                ),
                (
                    AuthenticatedWorkUnitKind::Evaluation,
                    AuthenticatedWorkUnitPhase::Suspended,
                    GRAPH_TARGET,
                    GRAPH_SCHEDULE,
                ),
                (
                    AuthenticatedWorkUnitKind::Callback,
                    AuthenticatedWorkUnitPhase::Begin,
                    CALLBACK_TARGET,
                    CALLBACK_SCHEDULE,
                ),
                (
                    AuthenticatedWorkUnitKind::Callback,
                    AuthenticatedWorkUnitPhase::End,
                    CALLBACK_TARGET,
                    CALLBACK_SCHEDULE,
                ),
                (
                    AuthenticatedWorkUnitKind::Evaluation,
                    AuthenticatedWorkUnitPhase::Begin,
                    GRAPH_TARGET,
                    GRAPH_SCHEDULE,
                ),
                (
                    AuthenticatedWorkUnitKind::Evaluation,
                    AuthenticatedWorkUnitPhase::End,
                    GRAPH_TARGET,
                    GRAPH_SCHEDULE,
                ),
            ]
        );
        let cancellation = engine
            .next_authenticated_cancellation()
            .unwrap()
            .expect("cooperative graph cancellation omitted its terminal record");
        assert_eq!(cancellation.target_id, GRAPH_TARGET);
        assert_eq!(
            cancellation.resolution,
            AuthenticatedCancellationResolution::Accepted
        );
        assert!(engine.next_authenticated_cancellation().unwrap().is_none());
        assert_eq!(
            engine.eval_immediate("6 * 7").await.unwrap().as_deref(),
            Some("42"),
            "graph cancellation left the runtime unusable"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn module_graph_resume_publication_failure_rolls_back_racing_cancellation() {
        const GRAPH_TARGET: u64 = 0x7101;
        const GRAPH_SCHEDULE: u64 = 51;

        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(ibex_test_enable_work_unit_publication(raw), 1);
                assert_eq!(
                    ibex_test_begin_module_graph_transition_probe(
                        raw,
                        GRAPH_TARGET,
                        GRAPH_SCHEDULE,
                    ),
                    1
                );
                assert_eq!(
                    ex_hermes_structured_module_graph_suspend(raw, GRAPH_TARGET),
                    0
                );
                assert_eq!(ibex_test_fail_next_work_begin_after_cancellation(raw), 1);
                assert_eq!(
                    ex_hermes_structured_module_graph_resume(raw, GRAPH_TARGET),
                    2,
                    "the injected publication failure was not reported"
                );
            })
            .unwrap();

        assert_eq!(
            engine.active_authenticated_target(),
            None,
            "failed resume left the graph published as an active target"
        );
        assert_eq!(
            engine.cancel_authenticated_target(GRAPH_TARGET),
            AuthenticatedCancellationStatus::Unavailable,
            "failed resume left its cancellation request active"
        );
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe {
                    ibex_test_end_module_graph_transition_probe(raw, GRAPH_TARGET, 0)
                })
                .unwrap(),
            1,
            "failed resume left the cancellation state unusable"
        );
        assert_eq!(
            engine.eval_immediate("6 * 7").await.unwrap().as_deref(),
            Some("42"),
            "failed resume left an armed timeout for the successor"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn independent_c11_consumer_observes_normal_return_cancellation_as_defeated() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let engine = Arc::new(HermesEngine::new().unwrap());
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ibex_test_enable_work_unit_publication(raw) })
                .unwrap(),
            1
        );
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ibex_test_enqueue_blocking_native_work(raw) })
                .unwrap(),
            1
        );

        let controller_engine = Arc::clone(&engine);
        let controller_runtime = Arc::clone(&runtime);
        let controller = std::thread::spawn(move || {
            // Arm cleanup before observing the publication. The C-owned probe
            // releases on its ordinary path; this idempotent guard also
            // releases if publication, queue decoding, or an assertion fails.
            let _release = CAbiBlockingWorkReleaseGuard(Arc::clone(&controller_runtime));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                while let Some(event) = controller_engine
                    .next_authenticated_work_unit()
                    .expect("native work-unit queue must remain valid")
                {
                    if event.kind == AuthenticatedWorkUnitKind::Callback
                        && event.phase == AuthenticatedWorkUnitPhase::Begin
                    {
                        assert_eq!(
                            controller_runtime
                                .with_session_control(|raw, nonce| unsafe {
                                    ibex_exact_runtime_c_abi_probe_cancel_then_release(
                                        raw,
                                        nonce,
                                        event.target_id,
                                    )
                                })
                                .unwrap(),
                            0,
                            "C11 consumer failed to deliver the exact cancellation race"
                        );
                        return event.target_id;
                    }
                }
                std::thread::yield_now();
            }
            panic!("blocking native callback Begin was not observable");
        });

        engine.drive_ready_tasks().await.unwrap();
        let target_id = controller.join().unwrap();
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe {
                    ibex_exact_runtime_c_abi_probe_cancel_terminal(
                        raw,
                        runtime.runtime_nonce.get(),
                        target_id,
                    )
                })
                .unwrap(),
            0,
            "C11 consumer did not observe one Defeated terminal record"
        );
        assert_eq!(
            engine.eval_immediate("6 * 7").await.unwrap().as_deref(),
            Some("42")
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn runtime_internal_async_scheduler_is_raw_unavailable_not_authenticated() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ibex_test_enable_work_unit_publication(raw) })
                .unwrap(),
            1
        );
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ibex_test_enqueue_runtime_principal_throw(raw) })
                .unwrap(),
            1
        );
        engine.drive_ready_tasks().await.unwrap();

        let (native, display, metadata) = runtime
            .with_runtime(|raw| {
                let mut native = NativeAsyncFailureEvent::current();
                assert_eq!(
                    unsafe { ex_hermes_take_async_failure_event(raw, &mut native) },
                    1
                );
                let (display, metadata) = unsafe {
                    render_and_release_async_failure_value(
                        raw.cast(),
                        native.value_runtime_nonce,
                        native.value_handle_id,
                    )
                }
                .expect("materialize runtime-principal throw through the native adapter");
                (native, display, metadata)
            })
            .unwrap();
        assert_eq!(
            native.principal_status, 2,
            "the runtime sentinel must be unavailable in the raw native record"
        );
        assert_eq!(native.owning_principal_id, u32::MAX as u64);
        assert_eq!(native.kind, 5);
        assert_ne!(native.event_id, 0);
        assert_eq!(native.associated_evaluation, 0);
        assert_eq!(
            async_failure_owner(&native).unwrap(),
            AuthenticatedAsyncFailureOwner::Unavailable
        );
        assert_eq!(display.kind, ValueKind::Object);
        assert_eq!(display.text.as_ref(), "[Object]");
        let ThrowMetadata::Captured {
            error_class,
            message,
            stack: _,
            ..
        } = metadata
        else {
            panic!("runtime-principal throw lost safe metadata")
        };
        assert_eq!(error_class, NativeErrorClass::Error);
        assert_eq!(message.as_deref(), Some("runtime-principal-unavailable"));
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn native_due_timer_cleared_before_begin_publishes_undue() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ibex_test_enable_work_unit_publication(raw) })
                .unwrap(),
            1
        );

        engine
            .eval_immediate(
                "var second; setTimeout(function () { clearTimeout(second); }, 0); second = setTimeout(function () {}, 0); void 0",
            )
            .await
            .unwrap();
        engine.drive_ready_tasks().await.unwrap();

        let mut due = Vec::new();
        let mut begun = Vec::new();
        let mut undue = Vec::new();
        while let Some(event) = engine.next_authenticated_work_unit().unwrap() {
            if event.kind != AuthenticatedWorkUnitKind::Timer {
                continue;
            }
            match event.phase {
                AuthenticatedWorkUnitPhase::Due => due.push(event.scheduling_id),
                AuthenticatedWorkUnitPhase::Undue => undue.push(event.scheduling_id),
                AuthenticatedWorkUnitPhase::Begin => begun.push(event.scheduling_id),
                _ => {}
            }
        }
        assert_eq!(due.len(), 2, "both ready timers need distinct Due records");
        assert_eq!(begun, vec![due[0]], "only the first due timer may begin");
        assert_eq!(
            undue,
            vec![due[1]],
            "the cleared ready timer must become Undue"
        );
        assert_ne!(due[0], due[1]);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn native_work_unit_queue_overflow_is_explicit() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ibex_test_enable_work_unit_publication(raw) })
                .unwrap(),
            1
        );
        engine
            .eval_immediate(
                "for (var i = 0; i < 600; i++) { setTimeout(function () {}, 0); } void 0",
            )
            .await
            .unwrap();
        engine.drive_ready_tasks().await.unwrap();
        let error = engine
            .next_authenticated_work_unit()
            .expect_err("bounded publication loss must be fail-loud");
        assert!(error.to_string().contains("overflowed"));
    }

    /// Exercise the worker-private safe-throw ABI through the same native
    /// event drain and Rust adapter used by production asynchronous-failure
    /// reporting. The returned record is deliberately an observation, not an
    /// expected-value fixture: the output-shape executor binds it to the exact
    /// loaded engine identity independently.
    /// @ref LLP 0024#9-asynchronous-failures
    /// @ref LLP 0025#11-delegated-obligations — async failure evidence is read
    /// only after its authenticated work publications have been consumed.
    #[cfg(feature = "capsec-conformance-observer")]
    async fn loaded_engine_safe_throw_metadata_observation(
        engine: &HermesEngine,
        host: &crate::host::Host,
        publications: &mut AuthenticatedPublicationTracker,
    ) -> Value {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let root = host
            .typed_principal_for_module("0")
            .expect("safe-throw fixture must authenticate its root principal");
        let session = host
            .mint_armed_session_token()
            .expect("mint safe-throw fixture session");
        let mut sequence = SubmissionSequence::new(session.clone())
            .expect("create safe-throw fixture submission sequence");
        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .expect("mint safe-throw fixture submission")
            .authorize_inline()
            .bind_bytes(
                br#"Error.prepareStackTrace = function hostilePrepareStackTrace() {
  throw new Error('the safe metadata adapter invoked Error.prepareStackTrace');
};
Promise.resolve().then(function capsecSafeThrowMetadataFixture() {
  var error = new Error('safe-throw-metadata-fixture');
  Object.defineProperty(error, 'stack', {
    configurable: true,
    get: function unsafeStackGetter() {
      throw new Error('the safe metadata adapter invoked Error.stack');
    }
  });
  throw error;
});
0
//# sourceURL=/host-looking/forged.js"#
                    .to_vec(),
            )
            .into_request()
            .expect("construct safe-throw fixture request");
        let source_label = request.source_label().as_str().to_owned();

        let evaluation = engine.evaluate_authenticated(&session, request).await;
        publications
            .drain(engine, "safe-throw authenticated evaluation")
            .expect("drain safe-throw evaluation publications");
        let AuthenticatedEvaluation::Value { receipt, .. } =
            evaluation.expect("evaluate safe-throw fixture")
        else {
            panic!("safe-throw fixture did not settle normally")
        };
        let release = engine
            .release_undisplayed_value(
                receipt.expect("safe-throw fixture value must retain a receipt"),
            )
            .await;
        publications
            .drain(engine, "safe-throw authenticated value release")
            .expect("drain safe-throw value-release publications");
        release.expect("release safe-throw fixture result");
        let drive = engine.drive_ready_tasks().await;
        publications
            .drain(engine, "safe-throw Promise-job drive")
            .expect("drain safe-throw Promise-job publications");
        publications
            .require_no_due_schedules("safe-throw Promise-job drive")
            .expect("safe-throw Promise job left a due timer");
        drive.expect("drain safe-throw fixture Promise job");

        let failures = engine
            .take_authenticated_async_failures()
            .await
            .expect("drain safe-throw fixture failure through the Rust/native adapter");
        assert_eq!(
            failures.len(),
            1,
            "safe-throw fixture must publish one exact failure"
        );
        let AuthenticatedAsyncFailure::Captured {
            thrown,
            owning_principal,
            event_identity,
            associated_evaluation,
        } = &failures[0]
        else {
            panic!("safe-throw fixture did not retain its rooted thrown value")
        };
        assert_eq!(thrown.value.kind, AuthenticatedDisplayKind::Object);
        assert_eq!(thrown.value.text, "[Object]");
        let AuthenticatedThrowMetadata::Captured {
            error_class,
            message,
            stack,
            positions,
            ..
        } = &thrown.metadata
        else {
            panic!("safe-throw fixture did not invoke the safe metadata ABI")
        };
        assert_eq!(*error_class, AuthenticatedErrorClass::Error);
        assert_eq!(message.as_deref(), Some("safe-throw-metadata-fixture"));
        let stack = stack
            .as_deref()
            .expect("safe-throw fixture must return an engine-captured stack");
        assert!(
            stack.contains("capsecSafeThrowMetadataFixture") && stack.contains(&source_label),
            "safe-throw fixture lost its authenticated source: {stack:?}"
        );
        assert!(
            !stack.contains("the safe metadata adapter invoked Error.stack")
                && !stack.contains("the safe metadata adapter invoked Error.prepareStackTrace")
                && !stack.contains("unsafeStackGetter")
                && !stack.contains("hostilePrepareStackTrace")
                && !stack.contains("/host-looking/forged.js"),
            "safe metadata consulted hostile stack hooks or accepted a sourceURL spoof: {stack:?}"
        );
        assert!(
            positions.is_empty(),
            "source-position support is a later stratum"
        );
        assert_eq!(
            owning_principal,
            &AuthenticatedAsyncFailureOwner::Authenticated {
                principal: root.clone()
            }
        );
        let job_identity = event_identity
            .strip_prefix("microtask:")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .expect("safe-throw fixture must retain its Hermes job identity");
        assert_eq!(*associated_evaluation, Some(1));

        serde_json::json!({
            "schema": "ibex/capsec-safe-throw-metadata-observation/1",
            "symbol": "ex_hermes_value_safe_throw_metadata",
            "value": {
                "kind": thrown.value.kind,
                "text": thrown.value.text,
            },
            "metadata": {
                "errorClass": error_class,
                "message": message,
                "stack": stack,
                "sourceLabel": source_label,
                "positions": positions,
            },
            "provenance": {
                "owningPrincipal": root,
                "eventKind": "microtask",
                "eventIdentity": job_identity,
                "associatedEvaluation": associated_evaluation,
            },
        })
    }

    #[test]
    fn hermesc_source_map_flag_is_boolean_and_uses_derived_output_path() {
        let mut command = Command::new("hermesc");
        let output = Path::new("bundle.hbc");
        let input = Path::new("bundle.js");
        configure_hermesc_compile_command(&mut command, output, true, input);
        let args = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let mut expected = Vec::new();
        if crate::hermes_es6_block_scoping_enabled() {
            expected.push("-Xes6-block-scoping");
        }
        expected.extend([
            "-emit-binary",
            "-out",
            "bundle.hbc",
            "-output-source-map",
            "bundle.js",
        ]);
        assert_eq!(args, expected);
        assert_eq!(
            hermesc_source_map_path(output),
            PathBuf::from("bundle.hbc.map")
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_conformance_batch {
        include!("capsec_conformance_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_portable_public_batch {
        include!("capsec_portable_public_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_builtin_batch {
        include!("capsec_public_builtin_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_closed_batch {
        include!("capsec_public_closed_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    // Keep the module name disjoint from each contained test's Cargo substring
    // filter. Otherwise the public callback command also selects the separately
    // bound internal-evidence producer merely because its module path matches.
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    mod capsec_callback_invariant_evidence {
        include!("capsec_public_callback_invariant_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_exact_fixture_evidence_batch {
        include!("capsec_exact_fixture_evidence_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_target_absence_batch {
        include!("capsec_public_target_absence_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_noncap_builtin_batch {
        include!("capsec_public_noncap_builtin_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_startup_batch {
        include!("capsec_public_startup_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_startup_environment_batch {
        include!("capsec_public_startup_environment_batch.test.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_cwd_facade_batch {
        include!("capsec_cwd_facade_batch.test.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_closed_control_output_batch {
        include!("capsec_closed_control_output_batch.test.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_builtin_noncap_closed_output_batch {
        include!("capsec_builtin_noncap_closed_output_batch.test.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_builtin_effects_output_batch {
        include!("capsec_builtin_effects_output_batch.test.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_host_abi_output_batch {
        include!("capsec_host_abi_output_batch.test.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_output_shape_sweep_batch {
        include!("capsec_output_shape_sweep_batch.test.rs");
    }

    use std::fs;
    #[cfg(feature = "host-http-server")]
    use std::io::{Read, Write};
    #[cfg(feature = "host-http-server")]
    use std::net::TcpStream;
    #[cfg(feature = "host-http-server")]
    use std::sync::mpsc;
    #[cfg(feature = "host-http-server")]
    use std::time::{Duration as StdDuration, Instant};
    #[cfg(feature = "host-http-server")]
    use tokio::time::{sleep, timeout, Duration};

    #[test]
    fn only_generated_bytecode_caches_require_mapped_engine_attestation() {
        assert!(BytecodeOutputKind::GeneratedCache.requires_runtime_attestation());
        assert!(
            !BytecodeOutputKind::ExplicitBuild.requires_runtime_attestation(),
            "explicit ibex build output must remain available on Windows"
        );
    }

    struct TestEnvVar {
        name: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl TestEnvVar {
        fn set(name: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(name);
            std::env::set_var(name, value);
            Self { name, previous }
        }

        fn remove(name: &'static str) -> Self {
            let previous = std::env::var_os(name);
            std::env::remove_var(name);
            Self { name, previous }
        }
    }

    impl Drop for TestEnvVar {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    #[cfg(feature = "host-http-server")]
    async fn eval_json(engine: &HermesEngine, code: &str) -> serde_json::Value {
        let raw = engine
            .eval_immediate(code)
            .await
            .expect("Hermes eval should succeed")
            .unwrap_or_default();
        serde_json::from_str(&raw).expect("Hermes eval should return valid JSON")
    }

    #[cfg(feature = "host-http-server")]
    async fn wait_for_exact_wait_status(engine: &HermesEngine) -> serde_json::Value {
        let deadline = Instant::now() + StdDuration::from_secs(2);
        let mut status = serde_json::json!({ "status": "pending" });
        while Instant::now() < deadline {
            match timeout(Duration::from_millis(250), engine.drive_event_loop()).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => panic!("event loop pump should succeed: {err:?}"),
                Err(_) => {}
            }
            status = eval_json(
                engine,
                r#"(function() {
                    return JSON.stringify({ status: globalThis.__exactWaitStatus });
                })()"#,
            )
            .await;
            if status.get("status").and_then(serde_json::Value::as_str) != Some("pending") {
                return status;
            }
            sleep(Duration::from_millis(25)).await;
        }
        status
    }

    #[cfg(feature = "host-http-server")]
    fn blocking_http_get(port: u16, path: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes())?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    #[cfg(feature = "host-http-server")]
    fn blocking_http_get_with_retry(
        port: u16,
        path: &str,
        attempts: usize,
    ) -> std::io::Result<String> {
        let mut last_err = None;
        for _ in 0..attempts {
            match blocking_http_get(port, path) {
                Ok(response) if !response.is_empty() => return Ok(response),
                Ok(_) => {
                    last_err = Some(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "empty HTTP response",
                    ));
                }
                Err(err) => last_err = Some(err),
            }
            std::thread::sleep(StdDuration::from_millis(25));
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP response did not arrive")
        }))
    }

    #[cfg(feature = "host-http-server")]
    async fn close_server(engine: &HermesEngine, server_id_global: &str) {
        let script = format!(
            r#"(function() {{
                var serverId = globalThis[{server_id_global:?}];
                if (typeof serverId === 'number') {{
                  __exactHttpClose(serverId, 1);
                }}
                return JSON.stringify({{ closed: true }});
            }})()"#
        );
        let _ = engine.eval_immediate(&script).await;
        sleep(Duration::from_millis(25)).await;
        let _ = timeout(Duration::from_secs(1), engine.drive_event_loop()).await;
    }

    #[test]
    fn test_find_hermes_binary() {
        // This test will fail if Hermes isn't installed, which is expected
        // in CI environments without Hermes
        let result = find_hermes_binary();
        println!("Hermes binary search result: {:?}", result);
    }

    #[cfg(unix)]
    #[test]
    fn hermes_tool_discovery_rejects_ambiguity_and_root_escape() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root =
            std::env::temp_dir().join(format!("ibex-hermes-tool-roots-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let first = root.join("first");
        let second = root.join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        for directory in [&first, &second] {
            let tool = directory.join("hermes");
            fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
            let mut permissions = fs::metadata(&tool).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&tool, permissions).unwrap();
        }
        let ambiguous =
            discover_hermes_tool_in_roots("hermes", &[first.clone(), second.clone()]).unwrap_err();
        assert!(ambiguous.to_string().contains("Ambiguous"));

        fs::remove_file(first.join("hermes")).unwrap();
        symlink(second.join("hermes"), first.join("hermes")).unwrap();
        let escaped = discover_hermes_tool_in_roots("hermes", &[first]).unwrap_err();
        assert!(escaped.to_string().contains("escapes authenticated root"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_bundle_search_roots_stay_local() {
        let temp_root = std::env::temp_dir().join("ibex-hermes-runtime-roots-local");
        let _ = fs::remove_dir_all(&temp_root);
        fs::create_dir_all(&temp_root).unwrap();

        let roots = runtime_bundle_search_roots(&temp_root);
        assert_eq!(roots, vec![temp_root.clone()]);

        let _ = fs::remove_dir_all(&temp_root);
    }

    // @ref LLP 0005#c-compilation — Windows cargo test binaries load the
    // digest-checked copy staged beside the executable, while other targets
    // load the selected artifact at its canonical path.
    fn loaded_engine_matches_selected_artifact(
        loaded_path: &std::path::Path,
        loaded_digest: &str,
        selected_path: &std::path::Path,
        selected_digest: &str,
        content_staging_permitted: bool,
    ) -> bool {
        loaded_digest == selected_digest
            && (loaded_path == selected_path
                || (content_staging_permitted
                    && loaded_path.file_name() == selected_path.file_name()))
    }

    #[test]
    fn loaded_engine_selection_allows_only_digest_bound_windows_staging() {
        let selected = std::path::Path::new("C:/ibex/hermes/bin/hermesvm.dll");
        let staged = std::path::Path::new("C:/ibex/target/debug/deps/hermesvm.dll");
        let other_name = std::path::Path::new("C:/ibex/target/debug/deps/other.dll");

        assert!(loaded_engine_matches_selected_artifact(
            staged,
            "sha256-selected",
            selected,
            "sha256-selected",
            true,
        ));
        assert!(!loaded_engine_matches_selected_artifact(
            staged,
            "sha256-selected",
            selected,
            "sha256-selected",
            false,
        ));
        assert!(!loaded_engine_matches_selected_artifact(
            staged,
            "sha256-other",
            selected,
            "sha256-selected",
            true,
        ));
        assert!(!loaded_engine_matches_selected_artifact(
            other_name,
            "sha256-selected",
            selected,
            "sha256-selected",
            true,
        ));
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn capsec_loaded_engine_identity_attestation() {
        let Ok(output_path) = std::env::var("IBEX_CAPSEC_ENGINE_IDENTITY_OUTPUT") else {
            // The normal unit suite still compiles and exercises all helpers;
            // the conformance runner supplies this path for the exact-artifact
            // execution and requires the resulting record.
            return;
        };
        let expected_path = std::fs::canonicalize(
            std::env::var("IBEX_CAPSEC_ENGINE_ARTIFACT")
                .expect("conformance attestation requires the named engine artifact"),
        )
        .expect("named conformance engine artifact must be canonicalizable");
        let expected_digest = std::env::var("IBEX_CAPSEC_ENGINE_DIGEST")
            .expect("conformance attestation requires the named artifact digest");

        let _lock = hermes_engine_test_lock().lock().await;
        let identity = HermesEngine::loaded_engine_identity()
            .expect("the linked Hermes object must expose a loaded identity");
        assert!(
            loaded_engine_matches_selected_artifact(
                &identity.engine_artifact_path,
                &identity.binary_digest,
                &expected_path,
                &expected_digest,
                cfg!(windows),
            ),
            "loaded engine must be the selected artifact or its digest-bound Windows staging copy"
        );

        let (host, snapshot_digest) =
            build_armed_test_host_at(None, false, false, false, Vec::new());
        assert_ne!(
            crate::host::abi::install_host(host.clone()),
            0,
            "install authenticated engine-attestation Host"
        );
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
            .expect("exact armed Hermes engine must initialize");
        engine
            .load_runtime()
            .await
            .expect("exact Hermes runtime bundle must load");
        // The marker is project source, so even this identity-only executor
        // must prove the mapped engine through the armed authenticated ingress.
        // @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        let marker = evaluator
            .eval_string(&engine, "'IBEX_CAPSEC_EXACT_ENGINE_EXECUTED'")
            .await;
        assert_eq!(marker, "IBEX_CAPSEC_EXACT_ENGINE_EXECUTED");
        evaluator
            .finish(&engine, "loaded-engine identity attestation")
            .expect("finish authenticated engine-attestation publications");
        let verified = ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity)
            .expect("loaded Hermes object changed during exact-artifact execution");
        assert_eq!(verified, identity);

        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .expect("identity output must be a new runner-owned file");
        serde_json::to_writer(&mut output, &verified)
            .expect("loaded engine identity must serialize");
        use std::io::Write as _;
        output
            .write_all(b"\n")
            .expect("loaded engine identity must be written completely");
        output
            .sync_all()
            .expect("loaded engine identity must be durable before success");

        if let Ok(portable_output_path) =
            std::env::var("IBEX_CAPSEC_PORTABLE_ENGINE_IDENTITY_OUTPUT")
        {
            let portable = HermesEngine::loaded_engine_portable_identity_if_present()
                .expect("portable engine markers must be all absent or authenticated");
            let mut portable_output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(portable_output_path)
                .expect("portable identity marker output must be a new runner-owned file");
            serde_json::to_writer(&mut portable_output, &portable)
                .expect("portable identity marker must serialize");
            portable_output
                .write_all(b"\n")
                .expect("portable identity marker must be written completely");
            portable_output
                .sync_all()
                .expect("portable identity marker must be durable before success");
        }
    }

    #[tokio::test]
    async fn application_cwd_cannot_select_lookalike_runtime_bundle() {
        let _lock = hermes_engine_test_lock().lock().await;

        struct RestoreProcessState {
            cwd: PathBuf,
            ibex_repo_root: Option<std::ffi::OsString>,
            exact_repo_root: Option<std::ffi::OsString>,
        }
        impl Drop for RestoreProcessState {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.cwd);
                match self.ibex_repo_root.take() {
                    Some(value) => std::env::set_var("IBEX_REPO_ROOT", value),
                    None => std::env::remove_var("IBEX_REPO_ROOT"),
                }
                match self.exact_repo_root.take() {
                    Some(value) => std::env::set_var("EXACT_REPO_ROOT", value),
                    None => std::env::remove_var("EXACT_REPO_ROOT"),
                }
            }
        }
        let _restore = RestoreProcessState {
            cwd: std::env::current_dir().unwrap(),
            ibex_repo_root: std::env::var_os("IBEX_REPO_ROOT"),
            exact_repo_root: std::env::var_os("EXACT_REPO_ROOT"),
        };
        std::env::remove_var("IBEX_REPO_ROOT");
        std::env::remove_var("EXACT_REPO_ROOT");

        let fake = tempfile::tempdir().unwrap();
        fs::create_dir_all(fake.path().join("vendored-generated")).unwrap();
        fs::create_dir_all(fake.path().join("packages/ibex-runtime-js")).unwrap();
        fs::create_dir_all(fake.path().join("packages/ibex-devtools")).unwrap();
        fs::write(
            fake.path().join("packages/ibex-runtime-js/package.json"),
            "{}",
        )
        .unwrap();
        fs::write(
            fake.path().join("packages/ibex-devtools/package.json"),
            "{}",
        )
        .unwrap();
        fs::write(
            fake.path()
                .join("vendored-generated/embedded_runtime_bundle.js"),
            "throw new Error('application-controlled runtime executed');",
        )
        .unwrap();

        std::env::set_current_dir(fake.path()).unwrap();
        let fake_root = fs::canonicalize(fake.path()).unwrap();
        let roots = runtime_workspace_roots().unwrap();
        assert!(roots.iter().all(|root| root != &fake_root));
        assert!(!find_runtime_bundle().unwrap().starts_with(fake_root));
    }

    #[test]
    fn eof_drain_stops_on_future_or_perpetual_timer() {
        let now = 1_000u64;
        // Something ran this poll: keep draining ready work.
        assert!(!eof_drain_complete(1, -1, now));
        assert!(!eof_drain_complete(3, (now + 5000) as i64, now));
        // Nothing ran and no timers scheduled: done.
        assert!(eof_drain_complete(0, -1, now));
        // Nothing ran and only a FUTURE timer (a referenced setInterval that
        // rescheduled to now+1000): done — must not hang Ctrl+D. (ENG-23030 #1)
        assert!(eof_drain_complete(0, (now + 1000) as i64, now));
        // Nothing ran but a one-shot is already due: keep draining it.
        assert!(!eof_drain_complete(0, (now - 1) as i64, now));
        assert!(!eof_drain_complete(0, now as i64, now));
    }

    // Real (verbatim) multi-line `--version` outputs of the checked-in
    // toolchain. The runtime binary appends a `Features:` block after the
    // version lines, so any "last token" parse reads `input` instead of a
    // version — the misparse that disabled entry-bytecode caching (ENG-23495).
    const HERMES_RUNTIME_VERSION_OUTPUT: &str = "LLVM (http://llvm.org/):\n  \
        LLVH version 8.0.0svn\n  Optimized build\n\n\
        Hermes JavaScript compiler and Virtual Machine.\n  \
        Hermes release version: 1.0.0\n  \
        HBC bytecode version: 99\n\n  \
        Features:\n    Unicode RegExp Property Escapes\n    Zip file input";
    const HERMESC_VERSION_OUTPUT: &str = "LLVM (http://llvm.org/):\n  \
        LLVH version 8.0.0svn\n  Optimized build\n\n\
        Hermes JavaScript compiler.\n  \
        Hermes release version: 1.0.0\n  \
        HBC bytecode version: 99";

    #[test]
    fn extract_hbc_version_parses_real_multiline_outputs() {
        // Both tools expose the HBC line; the runtime's trailing Features
        // block must not confuse the parse.
        assert_eq!(extract_hbc_version(HERMES_RUNTIME_VERSION_OUTPUT), Some(99));
        assert_eq!(extract_hbc_version(HERMESC_VERSION_OUTPUT), Some(99));
        // The gate in compile_to_bytecode compares exactly these two values,
        // so the checked-in toolchain must gate as compatible.
        assert_eq!(
            extract_hbc_version(HERMES_RUNTIME_VERSION_OUTPUT),
            extract_hbc_version(HERMESC_VERSION_OUTPUT)
        );
    }

    #[test]
    fn extract_hbc_version_rejects_output_without_hbc_line() {
        // No HBC line -> None (gate then proceeds and defers to load-time
        // rejection rather than comparing junk tokens).
        assert_eq!(
            extract_hbc_version("Hermes JavaScript compiler.\n  Hermes release version: 1.0.0"),
            None
        );
        assert_eq!(extract_hbc_version(""), None);
        // Non-numeric version value -> None.
        assert_eq!(extract_hbc_version("HBC bytecode version: abc"), None);
    }

    #[test]
    fn extract_hbc_version_detects_real_mismatch() {
        let older = "Hermes JavaScript compiler.\n  Hermes release version: 0.12.0\n  \
            HBC bytecode version: 96";
        assert_eq!(extract_hbc_version(older), Some(96));
        assert_ne!(
            extract_hbc_version(older),
            extract_hbc_version(HERMES_RUNTIME_VERSION_OUTPUT)
        );
    }

    #[test]
    fn compiler_identity_changes_for_same_version_binary_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("hermesc");
        fs::write(&tool, b"same version binary A").unwrap();
        let first = HermesToolIdentity::capture(&tool).unwrap();
        fs::write(&tool, b"same version binary B").unwrap();
        let second = HermesToolIdentity::capture(&tool).unwrap();
        assert_ne!(first.sha256, second.sha256);
        assert_ne!(first.cache_fingerprint(), second.cache_fingerprint());
        assert!(first.verify_selected_path().is_err());
    }

    /// The live gate must compare the checked-in compiler to the HBC version
    /// reported by the mapped engine's root API. The standalone `hermes`
    /// executable is intentionally not consulted: it may be a different build.
    #[test]
    fn checked_in_toolchain_gates_as_compatible() {
        let (Ok(runtime), Ok(compiler_out)) = (
            ibex_runtime::engine::loaded_engine_bytecode_version(),
            get_hermesc_version(),
        ) else {
            // Toolchain not present in this environment; the fixture tests
            // above still cover the parse.
            return;
        };
        let compiler = extract_hbc_version(&compiler_out);
        assert_eq!(
            Some(runtime),
            compiler,
            "checked-in hermes/hermesc HBC versions must match"
        );
        assert!(bytecode_versions_compatible());
    }

    #[tokio::test]
    async fn bytecode_and_source_map_manifest_rejects_mixed_or_tampered_unit() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("entry.js");
        let bytecode = dir.path().join("entry.hbc");
        let source_map = dir.path().join("entry.hbc.map");
        fs::write(&source, "function answer() { return 42; }\nanswer();\n").unwrap();
        if compile_to_bytecode(&source.to_string_lossy(), &bytecode, Some(&source_map))
            .await
            .is_err()
        {
            return; // optional checked-in toolchain in minimal environments
        }
        assert!(bytecode.is_file());
        assert!(source_map.is_file());
        assert!(bytecode_manifest_path(&bytecode).is_file());
        assert!(bytecode_source_map_is_fresh(&bytecode, &source_map));

        let mut tampered = fs::read(&source_map).unwrap();
        if let Some(first) = tampered.first_mut() {
            *first ^= 1;
        }
        fs::write(&source_map, tampered).unwrap();
        assert!(!bytecode_source_map_is_fresh(&bytecode, &source_map));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bytecode_compile_uses_staged_source_across_two_barrier_aba_mutations() {
        use std::os::unix::fs::PermissionsExt;

        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var("IBEX_TEST_HBC_COMPILE_BARRIER");
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let compiler = dir.path().join("hermesc");
        let compiler_script = "#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then\n\
  printf 'HBC bytecode version: 99\\n'\n\
  exit 0\n\
fi\n\
out=''\n\
input=''\n\
while [ \"$#\" -gt 0 ]; do\n\
  case \"$1\" in\n\
    -out) shift; out=\"$1\" ;;\n\
    -emit-binary) ;;\n\
    *) input=\"$1\" ;;\n\
  esac\n\
  shift\n\
done\n\
cp \"$input\" \"$out\"\n";
        fs::write(&compiler, compiler_script).unwrap();
        let mut permissions = fs::metadata(&compiler).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&compiler, permissions).unwrap();
        let identity = HermesToolIdentity::capture(&compiler).unwrap();

        let source_path = dir.path().join("entry.js");
        let output = dir.path().join("entry.hbc");
        let source_a = b"console.log('A');\n".to_vec();
        let source_b = b"console.log('B');\n";
        fs::write(&source_path, &source_a).unwrap();
        let barrier = dir.path().join("barrier");
        fs::create_dir(&barrier).unwrap();
        fs::write(barrier.join("target"), output.to_string_lossy().as_bytes()).unwrap();
        std::env::set_var("IBEX_TEST_HBC_COMPILE_BARRIER", &barrier);
        let _env = EnvGuard;

        let task_source = source_path.clone();
        let task_output = output.clone();
        let compile = tokio::spawn(async move {
            compile_source_to_bytecode_with_compiler(
                &task_source,
                &source_a,
                &task_output,
                None,
                &identity,
                BytecodeOutputKind::ExplicitBuild,
            )
            .await
        });

        async fn wait_for(path: &Path) {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !path.exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap();
        }

        wait_for(&barrier.join("input-staged.ready")).await;
        fs::write(&source_path, source_b).unwrap();
        fs::write(&source_path, b"console.log('A');\n").unwrap();
        fs::write(barrier.join("input-staged.release"), []).unwrap();

        wait_for(&barrier.join("compile-finished.ready")).await;
        fs::write(&source_path, source_b).unwrap();
        fs::write(&source_path, b"console.log('A');\n").unwrap();
        fs::write(barrier.join("compile-finished.release"), []).unwrap();

        compile.await.unwrap().unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"console.log('A');\n");
        let manifest: BytecodeArtifactManifest =
            serde_json::from_slice(&fs::read(bytecode_manifest_path(&output)).unwrap()).unwrap();
        assert_eq!(
            manifest.source_sha256,
            format!("{:x}", Sha256::digest(b"console.log('A');\n"))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bytecode_publish_lock_never_steals_from_slow_live_writer() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("entry.hbc");
        let first = acquire_cache_publish_lock(&output).await.unwrap();
        let second_output = output.clone();
        let second = tokio::spawn(async move { acquire_cache_publish_lock(&second_output).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !second.is_finished(),
            "a live writer lock must not be stolen based on elapsed time"
        );
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(2), second)
            .await
            .expect("OS lock should release when its owner drops")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn bytecode_retry_classification_is_structured_not_message_based() {
        let user_throw =
            anyhow::anyhow!("Compiling JS failed: user-controlled throw after SIDE_EFFECT");
        assert!(
            !is_bytecode_load_error(&user_throw),
            "user exception text must never authorize a source retry"
        );

        let native_rejection = anyhow::Error::new(BytecodeLoadError(
            "Bytecode sanity check failed: wrong version".to_string(),
        ));
        assert!(is_bytecode_load_error(&native_rejection));
    }

    #[test]
    fn repl_idle_wait_parks_when_idle_and_tracks_timers() {
        use std::time::Duration;
        let floor = Duration::from_millis(50);
        let idle = Duration::from_secs(1);
        let now = 10_000u64;
        // Nothing scheduled -> park the full idle interval (wake on notify).
        assert_eq!(repl_idle_wait(-1, now, floor, idle), idle);
        // A far-future timer is capped at the idle interval.
        assert_eq!(repl_idle_wait((now + 5000) as i64, now, floor, idle), idle);
        // A timer due soon waits until it is due.
        assert_eq!(
            repl_idle_wait((now + 200) as i64, now, floor, idle),
            Duration::from_millis(200)
        );
        // A 0-delay / already-due timer is floored so the prompt cannot busy-spin.
        assert_eq!(repl_idle_wait(now as i64, now, floor, idle), floor);
        assert_eq!(repl_idle_wait((now - 100) as i64, now, floor, idle), floor);
        // A very short IDLE_PARK (non-cli-notify) keeps the clamp well formed.
        let tiny = Duration::from_millis(5);
        assert_eq!(repl_idle_wait(now as i64, now, floor, tiny), tiny);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn install_armed_test_host() -> (HostResetGuard, String) {
        install_armed_test_host_at(None, false, false, false, vec![])
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_exact_test_host() -> (crate::host::Host, String) {
        let manifest_digest = "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA";
        build_armed_test_host_custom(None, false, false, false, vec![], None, |value| {
            value["exactEmbedder"] = serde_json::json!({
                "schema": "exact/host-operation-endowments/1",
                "operationManifestDigest": manifest_digest,
                "endowments": {
                    "app": [7, 11],
                    "agentIsolate": [19],
                    "uiWorklet": [],
                }
            });
            value["protectedObjects"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "role": "exact-operation-manifest",
                    "object": {
                        "platform": "unix",
                        "volume": "fixture-volume",
                        "file": "exact-operation-manifest"
                    },
                    "deniedActions": ["fs:write"]
                }));
        })
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn install_armed_exact_test_host() -> (HostResetGuard, String) {
        let (host, digest) = build_armed_exact_test_host();
        assert_ne!(crate::host::abi::install_host(host), 0);
        (HostResetGuard, digest)
    }

    /// Armed host whose snapshot binds the carrier-bearing
    /// exact/host-operation-endowments/2 shape (LLP 0053 §I2) with the given
    /// rootGrantSets pins.
    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_exact_carrier_test_host(
        root_grant_sets: serde_json::Value,
    ) -> (crate::host::Host, String) {
        let manifest_digest = "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA";
        build_armed_test_host_custom(None, false, false, false, vec![], None, move |value| {
            value["exactEmbedder"] = serde_json::json!({
                "schema": "exact/host-operation-endowments/2",
                "operationManifestDigest": manifest_digest,
                "endowments": {
                    "app": [7, 11],
                    "agentIsolate": [19],
                    "uiWorklet": [],
                },
                "carrierBinding": {
                    "schema": "exact/carrier-binding/1",
                    "mappingDigest": "sha256-MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMA",
                    "authorityCommitmentDigest":
                        "sha256-QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQA",
                    "rootGrantSets": root_grant_sets,
                }
            });
            value["protectedObjects"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "role": "exact-operation-manifest",
                    "object": {
                        "platform": "unix",
                        "volume": "fixture-volume",
                        "file": "exact-operation-manifest"
                    },
                    "deniedActions": ["fs:write"]
                }));
        })
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn exact_carrier_test_pin(context: &str) -> serde_json::Value {
        serde_json::json!({
            "context": context,
            "grantSetId": format!("grant-set-{context}"),
            "grantSetDigest": "sha256-ccccccccccccccccccccccccccccccccccccccccccA"
        })
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn install_armed_test_host_at(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
    ) -> (HostResetGuard, String) {
        let (host, digest) = build_armed_test_host_at(
            project_root,
            allow_write,
            allow_read,
            allow_list,
            extra_floor,
        );
        assert_ne!(
            crate::host::abi::install_host(host),
            0,
            "test Host context token allocation"
        );
        (HostResetGuard, digest)
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_test_host_at(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
    ) -> (crate::host::Host, String) {
        build_armed_test_host_at_with_protected(
            project_root,
            allow_write,
            allow_read,
            allow_list,
            extra_floor,
            None,
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_test_host_at_with_protected(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
        protected_objects: Option<Vec<serde_json::Value>>,
    ) -> (crate::host::Host, String) {
        build_armed_test_host_custom(
            project_root,
            allow_write,
            allow_read,
            allow_list,
            extra_floor,
            protected_objects,
            |_| {},
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_test_host_custom(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
        protected_objects: Option<Vec<serde_json::Value>>,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> (crate::host::Host, String) {
        build_armed_test_host_control(
            project_root,
            allow_write,
            allow_read,
            allow_list,
            extra_floor,
            Vec::new(),
            true,
            0,
            protected_objects,
            mutate,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_test_host_control(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
        extra_escalation_ceiling: Vec<serde_json::Value>,
        deny_ungranted_fs: bool,
        fs_principal_index: usize,
        protected_objects: Option<Vec<serde_json::Value>>,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> (crate::host::Host, String) {
        use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
        use capsec_semantics::model::Digest;

        // Observer batches that do not exercise a caller-supplied filesystem
        // still need one real, retained `/project` object now that armed
        // startup binds the runtime VFS before bootstrap. Keep that shared
        // fixture under ignored build output so conformance never mounts or
        // mutates the source checkout.
        // @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
        let default_project_root = project_root.is_none().then(|| {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/capsec-conformance-observer-project-v1");
            std::fs::create_dir_all(root.join("node_modules/image-lib"))
                .expect("create default armed observer project fixture");
            std::fs::canonicalize(root)
                .expect("canonicalize default armed observer project fixture")
        });
        let project_root = project_root
            .or(default_project_root.as_deref())
            .expect("armed observer project fixture");
        let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        value["workflow"] = serde_json::Value::String("production".into());
        value["effectiveMode"] = serde_json::Value::String("enforce".into());
        if let Some(protected_objects) = protected_objects {
            value["protectedObjects"] = serde_json::Value::Array(protected_objects);
        }
        {
            let components = ibex_runtime::host::host_path_components(project_root)
                .expect("encode default armed observer project fixture")
                .into_iter()
                .map(|component| {
                    serde_json::to_value(component)
                        .expect("serialize default armed observer project component")
                })
                .collect::<Vec<_>>();
            // The canonical armed fixture carries image-lib beneath its
            // original project root. A custom project mount must rebase that
            // authenticated package binding too; otherwise the runtime-local
            // VFS correctly rejects the snapshot as a package escape before
            // bootstrap.
            // @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
            let mut package_components = components.clone();
            package_components.extend([
                serde_json::json!({"encoding": "utf8", "value": "node_modules"}),
                serde_json::json!({"encoding": "utf8", "value": "image-lib"}),
            ]);
            let project_path = serde_json::json!({
                "root": "absolute",
                "components": components,
                "hostBound": true,
            });
            value["rootBindings"][0]["hostPath"]["components"] =
                serde_json::Value::Array(package_components);
            value["rootBindings"][1]["hostPath"] = project_path.clone();
            value["projectRootDiscovery"] = serde_json::json!({
                "origin": project_path,
                "selectedRoot": value["rootBindings"][1]["hostPath"].clone(),
                "markerKind": "explicit-project",
                "markerPath": value["rootBindings"][1]["hostPath"].clone(),
                "markerSetVersion": capsec_semantics::arming::PROJECT_ROOT_MARKER_SET_VERSION,
            });
            value["rootBindings"][1]["object"] = serde_json::to_value(
                ibex_runtime::host::object_identity_for_host_path(project_root)
                    .expect("identify default armed observer project fixture"),
            )
            .expect("serialize default armed observer project identity");
            let mut floor = Vec::new();
            let mut denials = Vec::new();
            if allow_list {
                floor.push(serde_json::json!({
                    "cap":"fs:list",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            } else if deny_ungranted_fs {
                denials.push(serde_json::json!({
                    "cap":"fs:list",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            }
            if allow_read {
                floor.push(serde_json::json!({
                    "cap":"fs:read",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            } else if deny_ungranted_fs {
                denials.push(serde_json::json!({
                    "cap":"fs:read",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            }
            if allow_write {
                floor.push(serde_json::json!({
                    "cap":"fs:write",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            } else if deny_ungranted_fs {
                denials.push(serde_json::json!({
                    "cap":"fs:write",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            }
            value["principals"][fs_principal_index]["floor"] = serde_json::Value::Array(floor);
            value["principals"][fs_principal_index]["denials"] = serde_json::Value::Array(denials);
        }
        value["principals"][fs_principal_index]["floor"]
            .as_array_mut()
            .unwrap()
            .extend(extra_floor);
        value["principals"][fs_principal_index]["escalationCeiling"]
            .as_array_mut()
            .unwrap()
            .extend(extra_escalation_ceiling);
        value["principals"][fs_principal_index]["floor"]
            .as_array_mut()
            .unwrap()
            .sort_by(|left, right| {
                let left = capsec_semantics::canonical::to_jcs_bytes(left).unwrap();
                let right = capsec_semantics::canonical::to_jcs_bytes(right).unwrap();
                left.cmp(&right)
            });
        value["principals"][fs_principal_index]["floor"]
            .as_array_mut()
            .unwrap()
            .dedup();
        mutate(&mut value);

        // Production snapshots require the package graph's location and
        // typed-edge provenance. The checked-in canonical snapshot is a
        // contract fixture, so materialize those production-only fields after
        // the caller has replaced any principals or bindings.
        let project_components = value["rootBindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["logicalRoot"] == "project")
            .expect("production test snapshot must bind the project root")["hostPath"]
            ["components"]
            .as_array()
            .unwrap()
            .clone();
        for binding in value["rootBindings"].as_array_mut().unwrap() {
            let Some(owner) = binding.get("owner") else {
                continue;
            };
            let components = binding["hostPath"]["components"]
                .as_array()
                .expect("test package binding must have path components");
            if components.starts_with(&project_components) {
                continue;
            }
            let package_name = owner["name"]
                .as_str()
                .expect("test package binding owner must have a name");
            let mut relocated = project_components.clone();
            relocated.extend([
                serde_json::json!({"encoding": "utf8", "value": "node_modules"}),
                serde_json::json!({"encoding": "utf8", "value": package_name}),
            ]);
            binding["hostPath"]["components"] = serde_json::Value::Array(relocated);
        }
        let root_bindings = value["rootBindings"].as_array().unwrap().clone();
        for node in value["packageGraph"]["nodes"].as_array_mut().unwrap() {
            let principal = node["principal"].clone();
            let binding = root_bindings
                .iter()
                .find(|binding| binding.get("owner") == Some(&principal))
                .expect("package graph node must have a test root binding");
            let package_name = principal["name"]
                .as_str()
                .expect("test package principal must have a name");
            node["resolvingSpecifier"] = serde_json::json!(package_name);
            node["rootObject"] = binding["object"].clone();
            let package_components = binding["hostPath"]["components"]
                .as_array()
                .expect("test package binding must have path components");
            let virtual_components = package_components
                .strip_prefix(project_components.as_slice())
                .expect("normalized package binding must be below the project root");
            node["virtualAliases"] = serde_json::json!([{
                "root": "project",
                "components": virtual_components
            }]);
            node["platformDisposition"] = serde_json::json!("required");
        }
        let authored_edges = value["packageGraph"]["importEdges"]
            .as_array()
            .unwrap()
            .clone();
        let mut typed_edges = Vec::new();
        for edge in authored_edges {
            if edge.get("requestSpecifier").is_some() {
                typed_edges.push(edge);
                continue;
            }
            let request = edge["imported"]["name"]
                .as_str()
                .expect("test imported principal must have a name");
            for (kind, conditions) in [
                ("common-js-require", vec!["node", "require"]),
                ("dynamic-import", vec!["import", "node"]),
                ("esm-static", vec!["import", "node"]),
            ] {
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
        let fixture_bindings: Vec<capsec_semantics::arming::ArmedRootBinding> =
            serde_json::from_value(value["rootBindings"].clone()).unwrap();
        value["pathCanonicalizers"] = serde_json::to_value(
            capsec_semantics::path_alias::contract_fixture_canonicalizer_rows(
                fixture_bindings
                    .iter()
                    .map(|binding| (binding.object.platform, binding.object.volume.clone())),
            )
            .unwrap(),
        )
        .unwrap();
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
            protected_artifacts: value["protectedObjects"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let role: capsec_semantics::arming::ProtectedArtifactRole =
                        serde_json::from_value(row["role"].clone()).unwrap();
                    let content_digest = match role {
                        capsec_semantics::arming::ProtectedArtifactRole::EngineBinary => {
                            digest_at(&["engine", "binaryDigest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::ExactOperationManifest => {
                            digest_at(&["exactEmbedder", "operationManifestDigest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::ArmedPolicy => {
                            digest_at(&["policyDigest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::PackageGraph => {
                            digest_at(&["packageGraph", "digest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::Registry => {
                            digest_at(&["registryDigest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::RuntimeExtensionAuthorityCapsule => {
                            digest_at(&["runtimeExtensions", "authorityCapsuleDigest"])
                        }
                    };
                    capsec_semantics::arming::ExpectedProtectedArtifact {
                        role,
                        host_path: serde_json::from_value(serde_json::json!({
                            "root": "absolute",
                            "components": [
                                {"encoding": "utf8", "value": "fixture"},
                                {"encoding": "utf8", "value": row["role"].as_str().unwrap()}
                            ],
                            "hostBound": true
                        }))
                        .unwrap(),
                        object: serde_json::from_value(row["object"].clone()).unwrap(),
                        content_digest,
                    }
                })
                .collect(),
            embedded_protected_artifacts: Vec::new(),
            runtime_extension_authority_digest: None,
            runtime_extension_mapped_executable: None,
        };
        let snapshot =
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();
        let host = unsafe {
            let config = crate::host::HostConfig {
                mode: crate::host::SecurityMode::Enforce,
                ..Default::default()
            };
            crate::host::Host::new_armed_for_test(config, Arc::new(snapshot))
        }
        .unwrap();
        (host, digest)
    }

    struct HostResetGuard;

    impl Drop for HostResetGuard {
        fn drop(&mut self) {
            crate::host::abi::install_host(crate::host::Host::strict());
        }
    }

    /// Test-only lifecycle controller for authenticated source helpers. Tests
    /// must consume the same bounded, paired publication stream as a session
    /// worker; ignoring it eventually converts valid source into fail-loud
    /// queue overflow.
    /// @ref LLP 0025#11-delegated-obligations — OBL-UNIT-PUBLICATION requires
    /// every authenticated unit to be published exactly once to its controller.
    #[cfg(feature = "capsec-conformance-observer")]
    #[derive(Default)]
    struct AuthenticatedPublicationTracker {
        active_work_units: std::collections::BTreeMap<u64, AuthenticatedWorkUnitEvent>,
        due_schedules: std::collections::BTreeSet<u64>,
    }

    #[cfg(feature = "capsec-conformance-observer")]
    impl AuthenticatedPublicationTracker {
        fn drain(&mut self, engine: &HermesEngine, context: &str) -> anyhow::Result<()> {
            while let Some(event) = engine.next_authenticated_work_unit()? {
                match event.phase {
                    AuthenticatedWorkUnitPhase::Due => {
                        anyhow::ensure!(
                            event.kind == AuthenticatedWorkUnitKind::Timer
                                && event.target_id == 0
                                && event.scheduling_id != 0,
                            "{context} published malformed Due identities"
                        );
                        anyhow::ensure!(
                            self.due_schedules.insert(event.scheduling_id),
                            "{context} published duplicate Due for scheduling identity {}",
                            event.scheduling_id
                        );
                    }
                    AuthenticatedWorkUnitPhase::Undue => {
                        anyhow::ensure!(
                            event.kind == AuthenticatedWorkUnitKind::Timer
                                && event.target_id == 0
                                && event.scheduling_id != 0,
                            "{context} published malformed Undue identities"
                        );
                        anyhow::ensure!(
                            self.due_schedules.remove(&event.scheduling_id),
                            "{context} published Undue for unknown scheduling identity {}",
                            event.scheduling_id
                        );
                    }
                    AuthenticatedWorkUnitPhase::Begin => {
                        if event.kind == AuthenticatedWorkUnitKind::Timer
                            && event.scheduling_id != 0
                        {
                            self.due_schedules.remove(&event.scheduling_id);
                        }
                        anyhow::ensure!(
                            self.active_work_units
                                .insert(event.target_id, event)
                                .is_none(),
                            "{context} published duplicate Begin for target {}",
                            event.target_id
                        );
                    }
                    AuthenticatedWorkUnitPhase::Suspended => {
                        let begin =
                            self.active_work_units
                                .get(&event.target_id)
                                .ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "{context} suspended target {} without Begin",
                                        event.target_id
                                    )
                                })?;
                        anyhow::ensure!(
                            begin.kind == event.kind && begin.scheduling_id == event.scheduling_id,
                            "{context} changed target {} identity at suspension",
                            event.target_id
                        );
                    }
                    AuthenticatedWorkUnitPhase::End => {
                        let begin =
                            self.active_work_units
                                .remove(&event.target_id)
                                .ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "{context} ended target {} without Begin",
                                        event.target_id
                                    )
                                })?;
                        anyhow::ensure!(
                            begin.kind == event.kind && begin.scheduling_id == event.scheduling_id,
                            "{context} changed target {} identity between Begin and End",
                            event.target_id
                        );
                    }
                }
            }
            anyhow::ensure!(
                self.active_work_units.is_empty(),
                "{context} left {} work unit(s) without End",
                self.active_work_units.len()
            );
            if let Some(event) = engine.next_authenticated_cancellation()? {
                anyhow::bail!(
                    "{context} published unexpected cancellation for target {}: {:?}",
                    event.target_id,
                    event.resolution
                );
            }
            Ok(())
        }

        fn require_no_due_schedules(&self, context: &str) -> anyhow::Result<()> {
            anyhow::ensure!(
                self.due_schedules.is_empty(),
                "{context} finished with ready timer scheduling identities {:?}",
                self.due_schedules
            );
            Ok(())
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    struct AuthenticatedReplTestEvaluator {
        session: ibex_runtime::engine::evaluation::ArmedSessionToken,
        sequence: ibex_runtime::engine::evaluation::SubmissionSequence,
        publications: AuthenticatedPublicationTracker,
    }

    #[cfg(feature = "capsec-conformance-observer")]
    impl AuthenticatedReplTestEvaluator {
        fn new(host: &crate::host::Host) -> Self {
            let session = host
                .mint_armed_session_token()
                .expect("mint authenticated test session");
            let sequence =
                ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
                    .expect("create authenticated test submission sequence");
            Self {
                session,
                sequence,
                publications: AuthenticatedPublicationTracker::default(),
            }
        }

        async fn evaluate(
            &mut self,
            engine: &HermesEngine,
            source: &str,
        ) -> AuthenticatedEvaluation {
            use capsec_semantics::model::{LogicalPath, LogicalRoot};

            self.publications
                .drain(engine, "authenticated REPL test source")
                .expect("drain authenticated REPL publications before evaluation");
            let request = self
                .sequence
                .mint_repl(LogicalPath {
                    root: LogicalRoot::Project,
                    components: Vec::new(),
                    host_bound: None,
                })
                .expect("mint authenticated test submission")
                .authorize_inline()
                .bind_bytes(source.as_bytes().to_vec())
                .into_request()
                .expect("bind authenticated test source");
            let evaluation = engine.evaluate_authenticated(&self.session, request).await;
            self.publications
                .drain(engine, "authenticated REPL test source")
                .expect("drain authenticated REPL publications after evaluation");
            evaluation.expect("evaluate authenticated test source")
        }

        async fn eval_string(&mut self, engine: &HermesEngine, source: &str) -> String {
            let evaluation = self.evaluate(engine, source).await;
            let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
                panic!("authenticated test source did not return a value: {evaluation:?}")
            };
            assert_eq!(
                display.kind,
                AuthenticatedDisplayKind::String,
                "authenticated test source did not return a string"
            );
            engine
                .release_undisplayed_value(
                    receipt.expect("authenticated test value must retain a receipt"),
                )
                .await
                .expect("release authenticated test value");
            self.publications
                .drain(engine, "authenticated REPL test value release")
                .expect("drain authenticated REPL publications after value release");
            serde_json::from_str(&display.text)
                .expect("authenticated string display must be valid JSON")
        }

        async fn eval_stage1(
            &mut self,
            engine: &HermesEngine,
            source: &str,
        ) -> AuthenticatedDisplay {
            let evaluation = self.evaluate(engine, source).await;
            let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
                panic!("authenticated Stage-1 fixture did not return a value: {evaluation:?}")
            };
            engine
                .release_undisplayed_value(
                    receipt.expect("authenticated Stage-1 value must retain a receipt"),
                )
                .await
                .expect("release authenticated Stage-1 fixture value");
            self.publications
                .drain(engine, "authenticated Stage-1 test value release")
                .expect("drain authenticated Stage-1 publications after value release");
            display
        }

        async fn eval_throw(&mut self, engine: &HermesEngine, source: &str) -> AuthenticatedThrow {
            let evaluation = self.evaluate(engine, source).await;
            let AuthenticatedEvaluation::Throw(thrown) = evaluation else {
                panic!("authenticated throw fixture did not throw: {evaluation:?}")
            };
            thrown
        }

        async fn eval_load_throw(
            &mut self,
            engine: &HermesEngine,
            virtual_path: &str,
            source: &str,
        ) -> AuthenticatedThrow {
            use capsec_semantics::model::{LogicalPath, LogicalRoot};

            let request = self
                .sequence
                .mint_load(
                    Arc::from(virtual_path),
                    LogicalPath {
                        root: LogicalRoot::Project,
                        components: Vec::new(),
                        host_bound: None,
                    },
                )
                .expect("mint authenticated .load fixture")
                .authorize_inline()
                .bind_bytes(source.as_bytes().to_vec())
                .into_request()
                .expect("bind authenticated .load fixture");
            self.publications
                .drain(engine, "authenticated .load test source")
                .expect("drain authenticated .load publications before evaluation");
            let evaluation = engine.evaluate_authenticated(&self.session, request).await;
            self.publications
                .drain(engine, "authenticated .load test source")
                .expect("drain authenticated .load publications after evaluation");
            let evaluation = evaluation.expect("evaluate authenticated .load fixture");
            let AuthenticatedEvaluation::Throw(thrown) = evaluation else {
                panic!("authenticated .load fixture did not throw: {evaluation:?}")
            };
            thrown
        }

        fn finish(&mut self, engine: &HermesEngine, context: &str) -> anyhow::Result<()> {
            self.publications.drain(engine, context)?;
            self.publications.require_no_due_schedules(context)
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn captured_metadata(
        thrown: &AuthenticatedThrow,
    ) -> (
        AuthenticatedErrorClass,
        Option<&str>,
        bool,
        Option<&str>,
        bool,
    ) {
        let AuthenticatedThrowMetadata::Captured {
            error_class,
            message,
            message_truncated,
            stack,
            stack_truncated,
            positions,
        } = &thrown.metadata
        else {
            panic!("production Hermes did not advertise bounded safe metadata")
        };
        assert!(
            positions.is_empty(),
            "safe metadata must not impersonate the source-position stratum"
        );
        (
            *error_class,
            message.as_deref(),
            *message_truncated,
            stack.as_deref(),
            *stack_truncated,
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn captured_async_throw(failures: Vec<AuthenticatedAsyncFailure>) -> AuthenticatedThrow {
        assert_eq!(failures.len(), 1, "fixture must publish one failure");
        let AuthenticatedAsyncFailure::Captured { thrown, .. } = failures
            .into_iter()
            .next()
            .expect("one asynchronous failure")
        else {
            panic!("fixture failure lost its rooted throw")
        };
        thrown
    }

    /// Exercise the loaded, production Hermes primitive renderer rather than
    /// a Rust-only decoder fixture. The typed flag is authoritative even when
    /// hostile text itself ends in the shared marker.
    /// @ref LLP 0024#8-safe-inspection
    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn production_hermes_stage1_bounds_unicode_symbol_and_bigint() {
        use ibex_runtime::engine::hermes_structured::{
            SAFE_TEXT_MAX_BYTES, SAFE_TEXT_TRUNCATION_MARKER,
        };

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        let content_bound = SAFE_TEXT_MAX_BYTES - SAFE_TEXT_TRUNCATION_MARKER.len();

        let exact = evaluator.eval_stage1(&engine, "'a'.repeat(16384)").await;
        assert_eq!(exact.kind, AuthenticatedDisplayKind::String);
        assert!(!exact.truncated);
        let exact_text: String = serde_json::from_str(&exact.text).unwrap();
        assert_eq!(exact_text.len(), SAFE_TEXT_MAX_BYTES);

        let over = evaluator.eval_stage1(&engine, "'a'.repeat(16385)").await;
        assert!(over.truncated);
        let over_text: String = serde_json::from_str(&over.text).unwrap();
        assert_eq!(over_text.len(), content_bound);
        assert!(over_text.bytes().all(|byte| byte == b'a'));

        for (scalar, scalar_bytes) in [("é", 2usize), ("€", 3), ("😀", 4)] {
            let prefix_bytes = content_bound - (scalar_bytes - 1);
            let source = format!("'a'.repeat({prefix_bytes}) + {scalar:?} + 'z'.repeat(64)");
            let display = evaluator.eval_stage1(&engine, &source).await;
            assert!(display.truncated, "{scalar_bytes}-byte cut lost its flag");
            let text: String = serde_json::from_str(&display.text).unwrap();
            assert_eq!(
                text.len(),
                prefix_bytes,
                "{scalar_bytes}-byte scalar was split at the bound"
            );
            assert!(text.bytes().all(|byte| byte == b'a'));
        }

        let hostile_marker_source = format!(
            "'a'.repeat({}) + {:?}",
            SAFE_TEXT_MAX_BYTES - SAFE_TEXT_TRUNCATION_MARKER.len(),
            SAFE_TEXT_TRUNCATION_MARKER
        );
        let hostile_marker = evaluator.eval_stage1(&engine, &hostile_marker_source).await;
        assert!(!hostile_marker.truncated);
        let hostile_marker_text: String = serde_json::from_str(&hostile_marker.text).unwrap();
        assert_eq!(hostile_marker_text.len(), SAFE_TEXT_MAX_BYTES);
        assert!(hostile_marker_text.ends_with(SAFE_TEXT_TRUNCATION_MARKER));

        let symbol = evaluator
            .eval_stage1(&engine, "Symbol('λ'.repeat(9000))")
            .await;
        assert_eq!(symbol.kind, AuthenticatedDisplayKind::Symbol);
        assert!(symbol.truncated);
        assert!(symbol.text.starts_with("Symbol(λλ"));
        assert!(symbol.text.ends_with(')'));
        assert!(!symbol.text.ends_with(SAFE_TEXT_TRUNCATION_MARKER));
        assert!(symbol.text.len() <= content_bound);

        let bigint = evaluator.eval_stage1(&engine, "1n << 50000n").await;
        assert_eq!(bigint.kind, AuthenticatedDisplayKind::BigInt);
        assert!(bigint.truncated);
        assert_eq!(bigint.text, "[BigInt]");
    }

    /// Allocation failure while enriching a rooted Throw is metadata loss,
    /// not loss of the Throw. Both the potentially-throwing capture and the
    /// fallible owned-byte copy have deterministic production-wrapper seams.
    /// @ref LLP 0024#8-safe-inspection
    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn safe_metadata_allocation_failure_preserves_throw_outcome() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

        unsafe { ibex_test_fail_next_structured_safe_metadata_capture_allocation() };
        let capture_failure = evaluator
            .eval_throw(&engine, "throw new Error('capture-allocation')")
            .await;
        assert_eq!(capture_failure.value.kind, AuthenticatedDisplayKind::Object);
        assert_eq!(
            captured_metadata(&capture_failure),
            (
                AuthenticatedErrorClass::Unclassified,
                None,
                false,
                None,
                false
            )
        );

        unsafe { ibex_test_fail_next_structured_safe_metadata_copy_allocation() };
        let copy_failure = evaluator
            .eval_throw(&engine, "throw new Error('copy-allocation')")
            .await;
        assert_eq!(copy_failure.value.kind, AuthenticatedDisplayKind::Object);
        assert_eq!(
            captured_metadata(&copy_failure),
            (
                AuthenticatedErrorClass::Unclassified,
                None,
                false,
                None,
                false
            )
        );

        let recovered = evaluator
            .eval_throw(&engine, "throw new Error('metadata-recovered')")
            .await;
        let (class, message, message_truncated, stack, stack_truncated) =
            captured_metadata(&recovered);
        assert_eq!(class, AuthenticatedErrorClass::Error);
        assert_eq!(message, Some("metadata-recovered"));
        assert!(!message_truncated && !stack_truncated);
        assert!(stack.is_some());
    }

    /// Direct throws, pending Promise rejections, and native callback throws
    /// all pass through the same bounded metadata contract.
    /// @ref LLP 0024#9-asynchronous-failures
    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn production_hermes_error_bound_and_async_route_parity() {
        use ibex_runtime::engine::hermes_structured::{
            SAFE_TEXT_MAX_BYTES, SAFE_TEXT_TRUNCATION_MARKER,
        };

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

        let exact = evaluator
            .eval_throw(&engine, "throw new Error('m'.repeat(16384))")
            .await;
        let (_, exact_message, exact_truncated, _, _) = captured_metadata(&exact);
        assert_eq!(exact_message.unwrap().len(), SAFE_TEXT_MAX_BYTES);
        assert!(!exact_truncated);

        let hostile_marker = evaluator
            .eval_throw(&engine, "throw new Error('attacker...[truncated]')")
            .await;
        let (_, hostile_message, hostile_truncated, _, _) = captured_metadata(&hostile_marker);
        assert_eq!(hostile_message, Some("attacker...[truncated]"));
        assert!(!hostile_truncated);

        let direct = evaluator
            .eval_throw(&engine, "throw new Error('p'.repeat(17000))")
            .await;

        let pending_value = evaluator
            .evaluate(
                &engine,
                "Promise.resolve().then(function parityPromise() { throw new Error('p'.repeat(17000)); }); 0",
            )
            .await;
        let AuthenticatedEvaluation::Value { receipt, .. } = pending_value else {
            panic!("pending rejection fixture did not return normally")
        };
        engine
            .release_undisplayed_value(receipt.expect("pending fixture value receipt"))
            .await
            .unwrap();
        engine.drive_ready_tasks().await.unwrap();
        let pending =
            captured_async_throw(engine.take_authenticated_async_failures().await.unwrap());

        let callback_value = evaluator
            .evaluate(
                &engine,
                "setTimeout(function parityCallback() { throw new Error('p'.repeat(17000)); }, 0); 0",
            )
            .await;
        let AuthenticatedEvaluation::Value { receipt, .. } = callback_value else {
            panic!("callback fixture did not return normally")
        };
        engine
            .release_undisplayed_value(receipt.expect("callback fixture value receipt"))
            .await
            .unwrap();
        engine.drive_ready_tasks().await.unwrap();
        let callback =
            captured_async_throw(engine.take_authenticated_async_failures().await.unwrap());

        let project = |thrown: &AuthenticatedThrow| {
            let (class, message, message_truncated, stack, stack_truncated) =
                captured_metadata(thrown);
            assert_eq!(message.unwrap().len(), SAFE_TEXT_MAX_BYTES);
            assert!(message.unwrap().ends_with(SAFE_TEXT_TRUNCATION_MARKER));
            assert!(stack.is_some());
            (
                class,
                message.map(str::to_owned),
                message_truncated,
                stack_truncated,
            )
        };
        let direct_projection = project(&direct);
        assert_eq!(project(&pending), direct_projection);
        assert_eq!(project(&callback), direct_projection);
        assert_eq!(direct_projection.0, AuthenticatedErrorClass::Error);
        assert!(direct_projection.2);
    }

    /// Hermes string-table extraction remains source-bounded for deep stacks,
    /// UTF-16 function names, and authenticated non-ASCII source labels.
    /// @ref LLP 0024#8-safe-inspection
    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn production_hermes_stack_bounds_frames_and_unicode_string_tables() {
        use ibex_runtime::engine::hermes_structured::{
            SAFE_TEXT_MAX_BYTES, SAFE_TEXT_TRUNCATION_MARKER,
        };

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

        let deep = evaluator
            .eval_throw(
                &engine,
                "function deepFrames(n) { if (n === 0) throw new Error('deep'); return 1 + deepFrames(n - 1); } deepFrames(130)",
            )
            .await;
        let (_, _, _, deep_stack, deep_truncated) = captured_metadata(&deep);
        let deep_stack = deep_stack.expect("deep Error stack");
        assert!(deep_truncated);
        assert!(deep_stack.len() <= SAFE_TEXT_MAX_BYTES);
        assert!(deep_stack.ends_with(SAFE_TEXT_TRUNCATION_MARKER));
        assert!(deep_stack.matches("deepFrames").count() <= 100);

        let huge_function_name = "λ".repeat(9000);
        let huge_function_source = format!(
            "var f = function {huge_function_name}() {{ throw new Error('huge-function'); }}; f()"
        );
        let huge_function = evaluator.eval_throw(&engine, &huge_function_source).await;
        let (_, _, _, function_stack, function_truncated) = captured_metadata(&huge_function);
        let function_stack = function_stack.expect("huge-function Error stack");
        assert!(function_truncated);
        assert!(function_stack.len() <= SAFE_TEXT_MAX_BYTES);
        assert!(function_stack.ends_with(SAFE_TEXT_TRUNCATION_MARKER));
        assert!(function_stack.contains("λλ"));

        let huge_source_label = format!("/{}.ts", "é".repeat(9000));
        let huge_source = evaluator
            .eval_load_throw(
                &engine,
                &huge_source_label,
                "throw new Error('huge-source-label')",
            )
            .await;
        let (_, _, _, source_stack, source_truncated) = captured_metadata(&huge_source);
        let source_stack = source_stack.expect("huge-source-label Error stack");
        assert!(source_truncated);
        assert!(source_stack.len() <= SAFE_TEXT_MAX_BYTES);
        assert!(source_stack.ends_with(SAFE_TEXT_TRUNCATION_MARKER));
        assert!(source_stack.contains("éé"));
    }

    fn install_test_host_with_allow(allow: &[&str]) -> HostResetGuard {
        // This helper predates the typed snapshot plane. Its capability names
        // only document the host effects exercised by broad Hermes integration
        // tests; they must never recreate the retired HostConfig allowlist.
        debug_assert!(allow.iter().all(|capability| !capability.is_empty()));
        crate::host::abi::install_host(crate::host::Host::new(crate::host::HostConfig {
            mode: crate::host::SecurityMode::Enforce,
            ..Default::default()
        }));
        HostResetGuard
    }

    #[cfg(all(feature = "capsec-conformance-observer", unix))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_file_ingress_unifies_entry_self_and_relative_import_identity() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _bun_compat = TestEnvVar::set("EXACT_COMPAT_BUN", "1");
        let project = tempfile::tempdir().unwrap();
        // macOS exposes `/var` through `/private/var`; bind the same canonical
        // host spelling that authenticated module resolution revalidates.
        let project_root = fs::canonicalize(project.path()).unwrap();
        let entry_path = project_root.join("entry.mjs");
        fs::write(
            project_root.join("dep.mjs"),
            r#"globalThis.__authenticatedDepRuns = (globalThis.__authenticatedDepRuns || 0) + 1;
export const runs = globalThis.__authenticatedDepRuns;
export const metaUrl = import.meta.url;
export const metaMain = import.meta.main;
"#,
        )
        .unwrap();
        fs::write(
            &entry_path,
            r#"import './entry.mjs';
import { runs as firstDepRuns, metaUrl as depUrl, metaMain as depMain } from './dep.mjs';
import { runs as secondDepRuns } from './dep.mjs';
globalThis.__authenticatedEntryRuns = (globalThis.__authenticatedEntryRuns || 0) + 1;
JSON.stringify({
              argv: process.argv,
              argv0: process.argv0,
              execPath: process.execPath,
              exactArgv: Exact.argv,
              exactMain: Exact.main,
              bunArgv: Bun.argv,
              bunMain: Bun.main,
              bunIsExact: Bun === Exact,
              entryRuns: globalThis.__authenticatedEntryRuns,
              firstDepRuns,
              secondDepRuns,
              entryUrl: import.meta.url,
              entryMain: import.meta.main,
              depUrl,
              depMain
            });"#,
        )
        .unwrap();

        let entry_identity = "file:///project/entry.mjs";
        let (host, digest) = build_armed_test_host_custom(
            Some(&project_root),
            false,
            true,
            true,
            Vec::new(),
            None,
            |snapshot| {
                snapshot["bootstrapCompatibilityModes"] = serde_json::json!(["bun"]);
                snapshot["entry"] = serde_json::json!({
                    "kind": "file",
                    "identity": entry_identity,
                    "mode": "program",
                });
                // The canonical fixture carries one package binding beneath
                // its original project root. Rebase that authenticated virtual
                // prefix beneath this test's temporary project so VFS mount
                // construction does not inherit an unrelated host spelling.
                let mut package_components = snapshot["rootBindings"][1]["hostPath"]["components"]
                    .as_array()
                    .unwrap()
                    .clone();
                package_components.extend([
                    serde_json::json!({"encoding": "utf8", "value": "node_modules"}),
                    serde_json::json!({"encoding": "utf8", "value": "image-lib"}),
                ]);
                snapshot["rootBindings"][0]["hostPath"]["components"] =
                    serde_json::Value::Array(package_components);
            },
        );
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let vfs = host.virtual_file_system().unwrap();
        let entry = vfs.resolve_root_file_url(entry_identity, None).unwrap();
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence =
            ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone()).unwrap();
        let submission = sequence
            .mint_file(
                entry.logical_referrer().unwrap(),
                &["--operator-data".to_owned(), String::new()],
            )
            .unwrap();
        let request = host
            .authenticated_vfs_file_read(&vfs, entry, submission)
            .unwrap()
            .into_capsule()
            .into_request()
            .unwrap();

        let evaluation = engine
            .evaluate_authenticated(&session, request)
            .await
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
            panic!("authenticated file entry did not return its completion value: {evaluation:?}")
        };
        assert_eq!(display.kind, AuthenticatedDisplayKind::String);
        let rendered_json: String = serde_json::from_str(&display.text).unwrap();
        let observed: serde_json::Value = serde_json::from_str(&rendered_json).unwrap();
        let expected_argv =
            serde_json::json!(["ibex:runtime", "/project/entry.mjs", "--operator-data", ""]);
        assert_eq!(observed["argv"], expected_argv);
        assert_eq!(observed["exactArgv"], expected_argv);
        assert_eq!(observed["argv0"], "ibex:runtime");
        assert_eq!(observed["execPath"], "ibex:runtime");
        assert_eq!(observed["exactMain"], "/project/entry.mjs");
        assert_eq!(observed["bunArgv"], expected_argv);
        assert_eq!(observed["bunMain"], "/project/entry.mjs");
        assert_eq!(observed["bunIsExact"], true);
        assert_eq!(observed["entryRuns"], 1);
        assert_eq!(observed["firstDepRuns"], 1);
        assert_eq!(observed["secondDepRuns"], 1);
        assert_eq!(observed["entryUrl"], "file:///project/entry.mjs");
        assert_eq!(observed["entryMain"], true);
        assert_eq!(observed["depUrl"], "file:///project/dep.mjs");
        assert_eq!(observed["depMain"], false);

        engine
            .release_undisplayed_value(receipt.expect("program value must retain a receipt"))
            .await
            .unwrap();
        engine
            .drive_authenticated_program_to_quiescence()
            .await
            .unwrap();
        vfs.close();
    }

    #[cfg(all(feature = "capsec-conformance-observer", unix))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_commonjs_file_uses_wrapper_cache_and_virtual_require_semantics() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _bun_compat = TestEnvVar::set("EXACT_COMPAT_BUN", "1");
        let project = tempfile::tempdir().unwrap();
        let project_root = fs::canonicalize(project.path()).unwrap();
        let entry_path = project_root.join("entry.cjs");
        fs::write(
            project_root.join("dep.cjs"),
            r#"globalThis.__authenticatedCjsDepRuns =
  (globalThis.__authenticatedCjsDepRuns || 0) + 1;
module.exports = {
  runs: globalThis.__authenticatedCjsDepRuns,
  filename: __filename,
  dirname: __dirname
};
"#,
        )
        .unwrap();
        fs::write(
            &entry_path,
            r#"const await = 7;
const initialExports = module.exports;
const depA = require('./dep.cjs');
const depB = module.require('./dep.cjs');
module.exports = JSON.stringify({
  sloppyThis: this === initialExports,
  exportsAlias: exports === initialExports,
  awaitIdentifier: await,
  filename: __filename,
  dirname: __dirname,
  moduleId: module.id,
  moduleParent: module.parent,
  moduleLoadedDuringBody: module.loaded,
  resolved: require.resolve('./dep.cjs'),
  sameDependency: depA === depB,
  depRuns: depA.runs,
  depFilename: depA.filename,
  depDirname: depA.dirname,
  requireMainType: typeof require.main,
  processMainModuleType: typeof process.mainModule,
  argv: process.argv
});
"#,
        )
        .unwrap();

        let entry_identity = "file:///project/entry.cjs";
        let (host, digest) = build_armed_test_host_custom(
            Some(&project_root),
            false,
            true,
            true,
            Vec::new(),
            None,
            |snapshot| {
                snapshot["bootstrapCompatibilityModes"] = serde_json::json!(["bun"]);
                snapshot["entry"] = serde_json::json!({
                    "kind": "file",
                    "identity": entry_identity,
                    "mode": "program",
                });
                let mut package_components = snapshot["rootBindings"][1]["hostPath"]["components"]
                    .as_array()
                    .unwrap()
                    .clone();
                package_components.extend([
                    serde_json::json!({"encoding": "utf8", "value": "node_modules"}),
                    serde_json::json!({"encoding": "utf8", "value": "image-lib"}),
                ]);
                snapshot["rootBindings"][0]["hostPath"]["components"] =
                    serde_json::Value::Array(package_components);
            },
        );
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let vfs = host.virtual_file_system().unwrap();
        let entry = vfs.resolve_root_file_url(entry_identity, None).unwrap();
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence =
            ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone()).unwrap();
        let submission = sequence
            .mint_file(
                entry.logical_referrer().unwrap(),
                &["--operator-data".to_owned()],
            )
            .unwrap();
        let request = host
            .authenticated_vfs_file_read(&vfs, entry, submission)
            .unwrap()
            .into_capsule()
            .into_request()
            .unwrap();

        let evaluation = engine
            .evaluate_authenticated(&session, request)
            .await
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
            panic!("authenticated CommonJS entry did not return module.exports: {evaluation:?}")
        };
        assert_eq!(display.kind, AuthenticatedDisplayKind::String);
        let rendered_json: String = serde_json::from_str(&display.text).unwrap();
        let observed: serde_json::Value = serde_json::from_str(&rendered_json).unwrap();
        assert_eq!(observed["sloppyThis"], true);
        assert_eq!(observed["exportsAlias"], true);
        assert_eq!(observed["awaitIdentifier"], 7);
        assert_eq!(observed["filename"], "/project/entry.cjs");
        assert_eq!(observed["dirname"], "/project");
        assert_eq!(observed["moduleId"], "/project/entry.cjs");
        assert!(observed["moduleParent"].is_null());
        assert_eq!(observed["moduleLoadedDuringBody"], false);
        assert_eq!(observed["resolved"], "/project/dep.cjs");
        assert_eq!(observed["sameDependency"], true);
        assert_eq!(observed["depRuns"], 1);
        assert_eq!(observed["depFilename"], "/project/dep.cjs");
        assert_eq!(observed["depDirname"], "/project");
        assert_eq!(observed["requireMainType"], "undefined");
        assert_eq!(observed["processMainModuleType"], "undefined");
        assert_eq!(
            observed["argv"],
            serde_json::json!(["ibex:runtime", "/project/entry.cjs", "--operator-data"])
        );

        engine
            .release_undisplayed_value(receipt.expect("CommonJS value must retain a receipt"))
            .await
            .unwrap();
        engine
            .drive_authenticated_program_to_quiescence()
            .await
            .unwrap();
        vfs.close();
    }

    static ABI_PROBE_SYNC_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static ABI_PROBE_ASYNC_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static EXACT_ABI_PROBE_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static EXACT_ABI_PROBE_OPERATION: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static EXACT_ABI_PROBE_PAYLOAD_LEN: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static EMBEDDER_QUEUED_CALLBACK_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    extern "C" fn count_embedder_queued_callback(_context: *mut std::ffi::c_void) {
        EMBEDDER_QUEUED_CALLBACK_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    const EX_HERMES_EVAL_FAULT_ENGINE: u32 = 4;
    const EX_HERMES_EVAL_FAULT_WRONG_THREAD: u32 = 6;
    const EX_HERMES_EVAL_FAULT_ARMED_RUNTIME_REQUIRED: u32 = 16;

    #[cfg(feature = "capsec-conformance-observer")]
    unsafe fn assert_root_global_paths_absent(
        raw: *mut HermesRuntimeOpaque,
        paths: &[&str],
        expected_absent: u32,
    ) {
        for path in paths {
            let path = CString::new(*path).unwrap();
            assert_eq!(
                ibex_test_root_global_logical_path_absent(raw, path.as_ptr()),
                expected_absent,
                "unexpected root-global reachability for {}",
                path.to_string_lossy()
            );
        }
    }

    extern "C" fn abi_probe_sync_host_call(
        _op: *const std::os::raw::c_char,
        _args_json: *const std::os::raw::c_char,
    ) -> *mut std::os::raw::c_char {
        ABI_PROBE_SYNC_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        host_call_response(r#"+{"bridge":"sync"}"#.to_string())
    }

    extern "C" fn abi_probe_async_host_call(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        _op: *const std::os::raw::c_char,
        _args_json: *const std::os::raw::c_char,
    ) {
        ABI_PROBE_ASYNC_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let payload = b"+{\"bridge\":\"async\"}\0";
        unsafe {
            ex_hermes_resolve_host_call(runtime, call_id, payload.as_ptr().cast());
        }
    }

    extern "C" fn abi_probe_exact_host_call(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        operation_id: u32,
        payload: *const u8,
        payload_len: usize,
        _context: *mut std::ffi::c_void,
    ) {
        EXACT_ABI_PROBE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_OPERATION.store(operation_id as usize, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_PAYLOAD_LEN.store(payload_len, std::sync::atomic::Ordering::SeqCst);
        if payload_len > 0 {
            assert!(!payload.is_null());
            let bytes = unsafe { std::slice::from_raw_parts(payload, payload_len) };
            assert_eq!(bytes, [1, 2, 3]);
        }
        let response = [9_u8, 8_u8];
        unsafe {
            ex_hermes_resolve_exact_host_call(
                runtime,
                call_id,
                0,
                response.as_ptr(),
                response.len(),
            );
            // Completion IDs are single-use capabilities. A replay must be a
            // no-op and cannot replace the first result.
            let replay = [7_u8];
            ex_hermes_resolve_exact_host_call(runtime, call_id, 0, replay.as_ptr(), replay.len());
        }
    }

    /// One captured v2 ingress invocation: the engine-attributed record plus
    /// the delivered payload/carrier shapes (LLP 0053 §I1/§I3).
    #[derive(Clone, Debug, Default)]
    struct CapturedExactIngressInvocation {
        operation: u32,
        payload_len: usize,
        carrier: Option<Vec<u8>>,
        abi_version: u32,
        struct_size: u32,
        context_kind: u32,
        carrier_status: u32,
        root_status: u32,
        principal_status: u32,
        runtime_nonce: u64,
        principal_id: u64,
        root_id: Option<String>,
    }

    static EXACT_V2_PROBE_INVOCATIONS: std::sync::Mutex<Vec<CapturedExactIngressInvocation>> =
        std::sync::Mutex::new(Vec::new());

    extern "C" fn abi_probe_exact_host_call_v2(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        operation_id: u32,
        payload: *const u8,
        payload_len: usize,
        carrier: *const u8,
        carrier_len: usize,
        attribution: *const ExHermesExactIngressAttribution,
        _context: *mut std::ffi::c_void,
    ) {
        assert!(!attribution.is_null());
        let attribution = unsafe { &*attribution };
        if payload_len > 0 {
            assert!(!payload.is_null());
        }
        let carrier_bytes = if carrier_len > 0 {
            assert!(!carrier.is_null());
            assert_eq!(
                attribution.carrier_status, 1,
                "carrier bytes require CARRIER_PRESENT"
            );
            Some(unsafe { std::slice::from_raw_parts(carrier, carrier_len) }.to_vec())
        } else {
            assert!(carrier.is_null());
            assert_eq!(
                attribution.carrier_status, 2,
                "no carrier bytes require CARRIER_ABSENT"
            );
            None
        };
        let root_id = if attribution.root_id.is_null() {
            assert_eq!(attribution.root_id_len, 0);
            None
        } else {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    attribution.root_id.cast::<u8>(),
                    attribution.root_id_len,
                )
            };
            Some(String::from_utf8(bytes.to_vec()).unwrap())
        };
        EXACT_V2_PROBE_INVOCATIONS
            .lock()
            .unwrap()
            .push(CapturedExactIngressInvocation {
                operation: operation_id,
                payload_len,
                carrier: carrier_bytes,
                abi_version: attribution.abi_version,
                struct_size: attribution.struct_size,
                context_kind: attribution.context_kind,
                carrier_status: attribution.carrier_status,
                root_status: attribution.root_status,
                principal_status: attribution.principal_status,
                runtime_nonce: attribution.runtime_nonce,
                principal_id: attribution.principal_id,
                root_id,
            });
        let response = [9_u8, 8_u8];
        unsafe {
            ex_hermes_resolve_exact_host_call(
                runtime,
                call_id,
                0,
                response.as_ptr(),
                response.len(),
            );
        }
    }

    extern "C" fn abi_probe_exact_malformed_completion(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        _operation_id: u32,
        _payload: *const u8,
        _payload_len: usize,
        _context: *mut std::ffi::c_void,
    ) {
        unsafe {
            ex_hermes_resolve_exact_host_call(runtime, call_id, 0, std::ptr::null(), 1);
        }
    }

    extern "C" fn abi_probe_exact_pending_call(
        _runtime: *mut HermesRuntimeOpaque,
        _call_id: u64,
        _operation_id: u32,
        _payload: *const u8,
        _payload_len: usize,
        _context: *mut std::ffi::c_void,
    ) {
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_exact_ingress_activation_requires_finalized_transaction() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_exact_test_host();
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32, 11_u32];
        let manifest_digest =
            CString::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA").unwrap();

        runtime
            .with_runtime(|raw| unsafe {
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 1);
                assert_eq!(ex_hermes_begin_embedder_capabilities_v1(raw), 0);
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 0);
                assert_eq!(ibex_test_embedder_capability_state_v1(raw), 1);
            })
            .unwrap();

        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        let unfinalized_request = evaluator
            .sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"globalThis.__unfinalizedIngressRan = true; 'unfinalized-ingress-ran'".to_vec(),
            )
            .into_request()
            .unwrap();
        let unfinalized_outcome = engine
            .evaluate_authenticated(&evaluator.session, unfinalized_request)
            .await;
        assert!(
            !matches!(
                unfinalized_outcome,
                Ok(AuthenticatedEvaluation::Value { .. })
            ),
            "a Configuring Exact ingress reopened user execution: {unfinalized_outcome:?}"
        );
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(ibex_test_embedder_capability_state_v1(raw), 1);
            })
            .unwrap();

        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(ex_hermes_finalize_embedder_capabilities_v1(raw), 0);
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 0);
            })
            .unwrap();
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "(function(){ var d = Object.getOwnPropertyDescriptor(exact, 'invokeHostAsync'); return typeof globalThis.__unfinalizedIngressRan + '/' + typeof d.value + '/' + d.writable + '/' + d.enumerable + '/' + d.configurable; })()",
                )
                .await,
            "undefined/function/false/false/false",
            "the finalized source-specific projection must survive the closed-bootstrap re-sweep"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_exact_ingress_activation_rejects_forged_js_projection() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        assert_eq!(
            engine
                .eval_immediate(
                    r#"Object.defineProperty(exact, "invokeHostAsync", {
                      value: function invokeHostAsync() {},
                      writable: false,
                      enumerable: false,
                      configurable: true
                    }); "forged""#,
                )
                .await
                .unwrap()
                .as_deref(),
            Some("forged")
        );

        let error = engine
            .load_runtime()
            .await
            .expect_err("an unauthenticated same-spelling projection must fail armed finalization");
        assert!(error.to_string().contains("fault"));
        let detail = unsafe {
            CStr::from_ptr(ibex_test_root_global_disposition_last_failure())
                .to_string_lossy()
                .into_owned()
        };
        assert!(
            detail.contains("inactive conditional path remains reachable: exact.invokeHostAsync"),
            "forged Exact ingress failed for the wrong reason: {detail}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn off_owner_runtime_handle_drop_is_fail_safe_and_owner_can_reclaim() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = HostResetGuard;
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let handle = RuntimeHandle::new(None).expect("diagnostic runtime");
        let shared = handle.shared();

        std::thread::spawn(move || {
            assert!(
                handle.with_runtime(|_| ()).is_err(),
                "runtime-thread FFI must reject a non-owner caller"
            );
            drop(handle);
        })
        .join()
        .unwrap();
        let raw = shared.raw.load(Ordering::SeqCst);
        assert!(
            !raw.is_null(),
            "off-owner drop must retain the runtime pointer for its owner"
        );

        assert_eq!(shared.shutdown(), RuntimeShutdown::Destroyed);
        assert_eq!(shared.shutdown(), RuntimeShutdown::NotLive);
        assert!(shared.raw.load(Ordering::SeqCst).is_null());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn structured_control_rejects_stale_runtime_generations() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = HostResetGuard;
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let runtime = SharedRuntime::new(None).expect("diagnostic runtime");
        let raw = runtime.raw.load(Ordering::SeqCst);
        let live_nonce = runtime.runtime_nonce.get();
        let stale_nonce = match live_nonce.wrapping_add(1) {
            0 => 1,
            candidate => candidate,
        };
        assert_ne!(stale_nonce, live_nonce);

        let mut work_event = NativeWorkUnitEvent::current();
        work_event.kind = 0xA5;
        let mut cancellation_event = NativeCancellationEvent::current();
        cancellation_event.resolution = 0x5A;
        unsafe {
            assert_eq!(
                ex_hermes_take_work_unit_event(raw, stale_nonce, &mut work_event),
                3
            );
            assert_eq!(work_event.kind, 0xA5);
            assert_eq!(
                ex_hermes_take_cancellation_event(raw, stale_nonce, &mut cancellation_event),
                3
            );
            assert_eq!(cancellation_event.resolution, 0x5A);
            assert_eq!(ex_hermes_structured_active_work_target(raw, stale_nonce), 0);
            assert_eq!(
                ex_hermes_cancel_structured_work_target(raw, stale_nonce, 1),
                3
            );
        }

        let stale_address = raw as usize;
        assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
        let stale_raw = stale_address as *mut HermesRuntimeOpaque;
        unsafe {
            assert_eq!(
                ex_hermes_take_work_unit_event(stale_raw, live_nonce, &mut work_event),
                3
            );
            assert_eq!(
                ex_hermes_take_cancellation_event(stale_raw, live_nonce, &mut cancellation_event),
                3
            );
            assert_eq!(
                ex_hermes_structured_active_work_target(stale_raw, live_nonce),
                0
            );
            assert_eq!(
                ex_hermes_cancel_structured_work_target(stale_raw, live_nonce, 1),
                3
            );
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_creation_requires_exact_installed_snapshot_digest() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();

        let error = match SharedRuntime::new(Some("sha256:wrong")) {
            Ok(_) => panic!("mismatched digest must reject Hermes allocation"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("handshake was rejected"));

        let diagnostic_error = match SharedRuntime::new(None) {
            Ok(_) => panic!("diagnostic creation must not consume an armed Host context"),
            Err(error) => error,
        };
        assert!(diagnostic_error
            .to_string()
            .contains("Failed to create Hermes runtime"));

        let runtime =
            SharedRuntime::new(Some(&digest)).expect("matching digest must create Hermes");
        assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn top_level_await_keeps_direct_microtask_throw_in_background_channel() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        let root = host
            .typed_principal_for_module("0")
            .expect("armed fixture must authenticate its root principal");
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"queueMicrotask(function tlaDetachedMicrotask() { throw new Error('tla-background-only'); }); await Promise.resolve(); 42"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, request)
            .await
            .expect("top-level await evaluation must settle independently")
        else {
            panic!("a detached microtask throw became the top-level-await outcome")
        };
        assert_eq!(display.kind, AuthenticatedDisplayKind::Number);
        assert_eq!(display.text, "42");
        engine
            .release_undisplayed_value(receipt.expect("TLA value must retain a receipt"))
            .await
            .unwrap();

        let failures = engine.take_authenticated_async_failures().await.unwrap();
        assert_eq!(
            failures.len(),
            1,
            "the detached microtask must report exactly once in the background channel"
        );
        let AuthenticatedAsyncFailure::Captured {
            thrown,
            owning_principal,
            event_identity,
            associated_evaluation,
        } = &failures[0]
        else {
            panic!("the detached TLA microtask lost its structured capture")
        };
        assert_eq!(thrown.metadata.message(), Some("tla-background-only"));
        assert!(
            thrown.metadata.stack().is_some_and(|stack| {
                stack.contains("tlaDetachedMicrotask") && stack.contains("repl:1")
            }),
            "the detached TLA microtask lost its safe source stack"
        );
        assert_eq!(
            owning_principal,
            &AuthenticatedAsyncFailureOwner::Authenticated { principal: root }
        );
        event_identity
            .strip_prefix("microtask:")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .unwrap_or_else(|| {
                panic!("the detached TLA microtask must retain its Hermes job id: {event_identity}")
            });
        assert_eq!(*associated_evaluation, Some(1));

        engine.drive_ready_tasks().await.unwrap();
        assert!(
            engine
                .take_authenticated_async_failures()
                .await
                .unwrap()
                .is_empty(),
            "the detached TLA microtask was duplicated after settlement"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn direct_session_background_throws_preserve_success_state_and_reuse() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        let root = host
            .typed_principal_for_module("0")
            .expect("armed fixture must authenticate its root principal");
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        // Bind the production session before the observer calls the real
        // direct-session ABI with its next two native ordinals.
        let bind_request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"0".to_vec())
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { receipt, .. } = engine
            .evaluate_authenticated(&session, bind_request)
            .await
            .expect("session-binding input must succeed")
        else {
            panic!("session-binding input did not return a value")
        };
        engine
            .release_undisplayed_value(receipt.expect("binding value must retain a receipt"))
            .await
            .unwrap();
        assert!(engine
            .take_authenticated_async_failures()
            .await
            .unwrap()
            .is_empty());

        let runtime = engine.ensure_runtime().await.unwrap();
        let observer_status = runtime
            .with_runtime(|raw| unsafe { ibex_test_direct_session_async_boundary(raw) })
            .unwrap();
        assert_eq!(
            observer_status, 0,
            "direct-session boundary observer failed at step {observer_status}"
        );

        let failures = engine.take_authenticated_async_failures().await.unwrap();
        assert_eq!(
            failures.len(),
            2,
            "one nextTick throw and one microtask throw must publish exactly once"
        );
        let mut saw_next_tick = false;
        let mut saw_microtask = false;
        for failure in &failures {
            let AuthenticatedAsyncFailure::Captured {
                thrown,
                owning_principal,
                event_identity,
                associated_evaluation,
            } = failure
            else {
                panic!("direct-session background throw lost its structured capture")
            };
            assert_eq!(
                owning_principal,
                &AuthenticatedAsyncFailureOwner::Authenticated {
                    principal: root.clone()
                }
            );
            assert_eq!(*associated_evaluation, Some(2));
            assert_eq!(thrown.value.kind, AuthenticatedDisplayKind::String);
            match thrown.value.text.as_str() {
                "\"direct-next-tick\"" => {
                    assert!(event_identity.starts_with("next-tick:"));
                    saw_next_tick = true;
                }
                "\"direct-microtask\"" => {
                    assert!(event_identity.starts_with("microtask:"));
                    saw_microtask = true;
                }
                other => panic!("unexpected direct-session failure value {other}"),
            }
        }
        assert!(saw_next_tick && saw_microtask);

        engine.drive_ready_tasks().await.unwrap();
        assert!(
            engine
                .take_authenticated_async_failures()
                .await
                .unwrap()
                .is_empty(),
            "direct-session background throws were duplicated after settlement"
        );
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_vfs_bind_accepts_rebased_custom_project_fixture() {
        let _lock = hermes_engine_test_lock().lock().await;
        let project = tempfile::tempdir().unwrap();
        let project_root = std::fs::canonicalize(project.path()).unwrap();
        let (_reset, digest) =
            install_armed_test_host_at(Some(&project_root), false, false, false, vec![]);

        let runtime = SharedRuntime::new(Some(&digest))
            .expect("coherent custom project and package bindings must create Hermes");
        assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_creation_refuses_every_injected_startup_failure() {
        struct ResetInjectedFailure;
        impl Drop for ResetInjectedFailure {
            fn drop(&mut self) {
                unsafe { ibex_test_set_armed_startup_failure_stage(std::ptr::null()) };
            }
        }

        let _lock = hermes_engine_test_lock().lock().await;
        let _reset_failure = ResetInjectedFailure;
        for stage in [
            "install-globals",
            "module-loader",
            "process-setup",
            "capability-hardening",
            "eager-install-seal",
            "lockdown",
            "compartment-registry",
        ] {
            // A runtime claim consumes its installed host context even when
            // startup subsequently refuses, so each injected construction gets
            // an independently installed context just like a fresh launch.
            let (_reset_host, digest) = install_armed_test_host();
            let stage = CString::new(stage).unwrap();
            unsafe { ibex_test_set_armed_startup_failure_stage(stage.as_ptr()) };
            assert!(
                SharedRuntime::new(Some(&digest)).is_err(),
                "armed runtime survived injected startup failure at {}",
                stage.to_string_lossy()
            );
        }
        unsafe { ibex_test_set_armed_startup_failure_stage(std::ptr::null()) };
        let (_reset_host, digest) = install_armed_test_host();
        let runtime = SharedRuntime::new(Some(&digest))
            .expect("clearing injection must restore armed runtime creation");
        assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn named_armed_shared_runtime_global_seal_is_owner_only_and_idempotent() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine
            .eval_immediate(
                r#"Object.defineProperty(globalThis, "BroadcastChannel", {
                  value: function BroadcastChannel() {},
                  writable: true,
                  enumerable: false,
                  configurable: true
                }); "installed""#,
            )
            .await
            .unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let raw_address = runtime.raw.load(Ordering::SeqCst) as usize;
        let off_owner = std::thread::spawn(move || unsafe {
            ex_hermes_seal_armed_shared_runtime_globals_v1(raw_address as *mut HermesRuntimeOpaque)
        })
        .join()
        .unwrap();
        assert_eq!(off_owner, EX_HERMES_EVAL_FAULT_WRONG_THREAD);
        assert_eq!(
            engine
                .eval_immediate("typeof BroadcastChannel === 'function'")
                .await
                .unwrap()
                .as_deref(),
            Some("true"),
            "off-owner refusal must not run any part of the seal program"
        );

        runtime.seal_armed_shared_runtime_globals().unwrap();
        runtime.seal_armed_shared_runtime_globals().unwrap();
        assert_eq!(
            engine
                .eval_immediate("typeof BroadcastChannel === 'undefined'")
                .await
                .unwrap()
                .as_deref(),
            Some("true"),
            "the owner transition must remove the reviewed ambient root"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn named_armed_shared_runtime_global_seal_refuses_diagnostic_runtime() {
        let _lock = hermes_engine_test_lock().lock().await;
        let engine = HermesEngine::new().unwrap();
        engine
            .eval_immediate(
                r#"Object.defineProperty(globalThis, "BroadcastChannel", {
                  value: function BroadcastChannel() {},
                  writable: true,
                  enumerable: false,
                  configurable: true
                }); "installed""#,
            )
            .await
            .unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let fault = runtime
            .with_runtime(|raw| unsafe { ex_hermes_seal_armed_shared_runtime_globals_v1(raw) })
            .unwrap();
        assert_eq!(fault, EX_HERMES_EVAL_FAULT_ARMED_RUNTIME_REQUIRED);
        assert_eq!(
            engine
                .eval_immediate("typeof BroadcastChannel === 'function'")
                .await
                .unwrap()
                .as_deref(),
            Some("true"),
            "diagnostic refusal must not run any part of the seal program"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn named_armed_shared_runtime_global_seal_failure_quarantines_runtime() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine
            .eval_immediate(
                r#"Object.defineProperty(globalThis, "MessageChannel", {
                  value: function MessageChannel() {},
                  writable: false,
                  enumerable: false,
                  configurable: false
                }); "installed""#,
            )
            .await
            .unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let fault = runtime
            .with_runtime(|raw| unsafe { ex_hermes_seal_armed_shared_runtime_globals_v1(raw) })
            .unwrap();
        assert_eq!(fault, EX_HERMES_EVAL_FAULT_ENGINE);
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ex_hermes_runtime_is_quarantined_v1(raw) })
                .unwrap(),
            1,
            "a partial or failed seal must terminally quarantine the generation"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_root_global_disposition_seals_private_bridges() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        if let Err(error) = engine.load_runtime().await {
            let detail = unsafe {
                CStr::from_ptr(ibex_test_root_global_disposition_last_failure())
                    .to_string_lossy()
                    .into_owned()
            };
            panic!(
                "generated root-global disposition must accept the conformant runtime: {error}; {detail}"
            );
        }
        let private_paths = [
            "__exactExit",
            "__exactFsMutationGuard",
            "__exactStdinRead",
            "__exactArgv",
            "__exactExecArgv",
            "__exactExecPath",
            "__exactRawArgv0",
            "__exactCompatModes",
            "__exactProcessIpcBootstrap",
            "Ibex.permissions",
            "Ibex.authority",
            "Exact.setModuleCapabilities",
        ];
        let assert_private_paths_absent = || async {
            let runtime = {
                let runtime = engine.runtime.lock().await;
                runtime
                    .as_ref()
                    .expect("loaded engine must retain its runtime")
                    .shared
                    .clone()
            };
            for path in private_paths {
                let path = CString::new(path).unwrap();
                let absent = runtime
                    .with_runtime(|raw| unsafe {
                        ibex_test_root_global_logical_path_absent(raw, path.as_ptr())
                    })
                    .unwrap();
                assert_eq!(
                    absent,
                    1,
                    "private bridge {} must be absent without evaluating script",
                    path.to_string_lossy()
                );
            }
        };
        assert_private_paths_absent().await;

        // Engine initialization is idempotent; a second call may not recreate
        // any bootstrap-only rendezvous global after the armed seal.
        engine.load_runtime().await.unwrap();
        assert_private_paths_absent().await;
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_process_umask_is_pinned_deny_only_without_backing_state() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, vec![], None, |snapshot| {
                snapshot["principals"][0]["imports"]["builtins"] =
                    serde_json::json!(["node:process"]);
            });
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        // Load the compatibility builtin first. Its import authorization emits
        // its own typed decisions; the assertion below isolates the subsequent
        // deny-only operation from that separate boundary.
        let preload = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"require('node:process'); true".to_vec())
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { receipt, .. } = engine
            .evaluate_authenticated(&session, preload)
            .await
            .expect("process compatibility builtin must preload")
        else {
            panic!("process compatibility preload did not return normally")
        };
        engine
            .release_undisplayed_value(receipt.expect("preload value must retain a receipt"))
            .await
            .unwrap();
        let typed_before = host.typed_decision_count();

        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                br#"(function () {
                  var imported = process;
                  function denied(fn) {
                    try { fn(); return false; }
                    catch (error) {
                      return error && error.code === 'ERR_ACCESS_DENIED' &&
                        error.permission === 'ProcessUmask';
                    }
                  }
                  var descriptor = Object.getOwnPropertyDescriptor(process, 'umask');
                  var first = denied(function () { process.umask(); });
                  try { process.umask = function () { return 7; }; } catch (_) {}
                  var second = denied(function () { imported.umask(0); });
                  return imported === process && first && second &&
                    descriptor && descriptor.writable === false &&
                    descriptor.configurable === false &&
                    !('_umask' in process);
                })()"#
                    .to_vec(),
            )
            .into_request()
            .unwrap();

        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, request)
            .await
            .expect("deny-only umask probe must evaluate")
        else {
            panic!("deny-only umask probe did not return its boolean verdict")
        };
        assert_eq!(display.kind, AuthenticatedDisplayKind::Boolean);
        assert_eq!(display.text, "true");
        engine
            .release_undisplayed_value(receipt.expect("probe value must retain a receipt"))
            .await
            .unwrap();
        assert_eq!(
            host.typed_decision_count(),
            typed_before,
            "deny-only process.umask must close before the typed authority evaluator"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_process_event_registry_is_closed_with_lifecycle_no_effect_branches() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, vec![], None, |snapshot| {
                snapshot["principals"][0]["imports"]["builtins"] =
                    serde_json::json!(["node:process"]);
            });
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                br#"(function () {
                  var listener = function () {};
                  var proto = Object.getPrototypeOf(process);
                  var lifecycleMethods = [
                    'addListener', 'listenerCount', 'listeners', 'off', 'on',
                    'once', 'prependListener', 'prependOnceListener',
                    'rawListeners', 'removeAllListeners', 'removeListener'
                  ];
                  var closedMethods = [
                    ['emit', ['warning']],
                    ['emitWarning', ['ibex-capsec-warning']],
                    ['eventNames', []],
                    ['getMaxListeners', []],
                    ['hasUncaughtExceptionCaptureCallback', []],
                    ['setMaxListeners', [17]],
                    ['setUncaughtExceptionCaptureCallback', [null]]
                  ];
                  function denied(fn) {
                    try { fn(); return false; }
                    catch (error) {
                      return error && error.code === 'ERR_ACCESS_DENIED' &&
                        error.permission === 'ProcessEvents';
                    }
                  }
                  function argumentsFor(name, event) {
                    if (name === 'listenerCount' || name === 'listeners' ||
                        name === 'rawListeners' || name === 'removeAllListeners') {
                      return [event];
                    }
                    return [event, listener];
                  }
                  function lifecycleResultIsNoEffect(name, event) {
                    var result = process[name].apply(process, argumentsFor(name, event));
                    if (name === 'listenerCount') return result === 0;
                    if (name === 'listeners' || name === 'rawListeners') {
                      return Array.isArray(result) && result.length === 0;
                    }
                    return result === process;
                  }
                  for (var i = 0; i < lifecycleMethods.length; i++) {
                    var name = lifecycleMethods[i];
                    var descriptor = Object.getOwnPropertyDescriptor(process, name);
                    var prototypeDescriptor = Object.getOwnPropertyDescriptor(proto, name);
                    if (!descriptor || descriptor.writable !== false ||
                        descriptor.configurable !== false ||
                        !prototypeDescriptor ||
                        prototypeDescriptor.writable !== false ||
                        prototypeDescriptor.configurable !== false ||
                        descriptor.value !== prototypeDescriptor.value) {
                      return false;
                    }
                    if (!lifecycleResultIsNoEffect(name, 'exit') ||
                        !lifecycleResultIsNoEffect(name, 'beforeExit')) {
                      return false;
                    }
                    var args = argumentsFor(name, 'ibex-capsec-shared-event');
                    if (!denied(function () {
                      return process[name].apply(process, args);
                    }) || !denied(function () {
                      return proto[name].apply(process, args);
                    })) {
                      return false;
                    }
                    try { process[name] = function () {}; } catch (_) {}
                    if (!denied(function () {
                      return process[name].apply(process, args);
                    })) {
                      return false;
                    }
                  }
                  for (var j = 0; j < closedMethods.length; j++) {
                    var entry = closedMethods[j];
                    var closedName = entry[0];
                    var closedArgs = entry[1];
                    if (!denied(function () {
                      return process[closedName].apply(process, closedArgs);
                    }) || !denied(function () {
                      return proto[closedName].apply(process, closedArgs);
                    })) {
                      return false;
                    }
                  }
                  return !('_events' in process) &&
                    !('_maxListeners' in process) &&
                    !('_uncaughtCaptureCb' in process) &&
                    !('_uncaughtExceptionHooked' in process) &&
                    !('_unhandledRejectionHooked' in process);
                })()"#
                    .to_vec(),
            )
            .into_request()
            .unwrap();

        let typed_before = host.typed_decision_count();
        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, request)
            .await
            .expect("armed process event-registry probe must evaluate")
        else {
            panic!("armed process event-registry probe did not return its boolean verdict")
        };
        assert_eq!(display.kind, AuthenticatedDisplayKind::Boolean);
        assert_eq!(display.text, "true");
        engine
            .release_undisplayed_value(receipt.expect("probe value must retain a receipt"))
            .await
            .unwrap();
        assert_eq!(
            host.typed_decision_count(),
            typed_before,
            "closed process events and lifecycle no-effect branches must not enter the typed evaluator"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_process_shared_state_methods_are_pinned_closed() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, vec![], None, |_| {});
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                br#"(function () {
                  var proto = Object.getPrototypeOf(process);
                  var methods = [
                    ['_getActiveHandles', 'ProcessInspection', []],
                    ['_getActiveRequests', 'ProcessInspection', []],
                    ['_kill', 'ProcessSignals', [process.pid, 0]],
                    ['abort', 'ProcessLifecycle', []],
                    ['binding', 'ProcessBinding', ['util']],
                    ['kill', 'ProcessSignals', [process.pid, 0]],
                    ['setegid', 'ProcessCredentials', [0]],
                    ['seteuid', 'ProcessCredentials', [0]],
                    ['setgid', 'ProcessCredentials', [0]],
                    ['setuid', 'ProcessCredentials', [0]]
                  ];
                  function denied(fn, permission) {
                    try { fn(); return false; }
                    catch (error) {
                      return error && error.code === 'ERR_ACCESS_DENIED' &&
                        error.permission === permission;
                    }
                  }
                  for (var i = 0; i < methods.length; i++) {
                    var name = methods[i][0];
                    var permission = methods[i][1];
                    var args = methods[i][2];
                    var descriptor =
                      Object.getOwnPropertyDescriptor(process, name);
                    var prototypeDescriptor =
                      Object.getOwnPropertyDescriptor(proto, name);
                    if (!descriptor || descriptor.writable !== false ||
                        descriptor.configurable !== false ||
                        !prototypeDescriptor ||
                        prototypeDescriptor.writable !== false ||
                        prototypeDescriptor.configurable !== false ||
                        descriptor.value !== prototypeDescriptor.value ||
                        !denied(function () {
                          return process[name].apply(process, args);
                        }, permission) ||
                        !denied(function () {
                          return proto[name].apply(process, args);
                        }, permission)) {
                      return false;
                    }
                    try { process[name] = function () {}; } catch (_) {}
                    if (!denied(function () {
                      return process[name].apply(process, args);
                    }, permission)) {
                      return false;
                    }
                  }
                  var properties = [
                    ['title', 'ProcessTitle', 'ibex', true],
                    ['report', 'ProcessReport', {}, false]
                  ];
                  for (var j = 0; j < properties.length; j++) {
                    var property = properties[j];
                    var propertyName = property[0];
                    var propertyPermission = property[1];
                    var propertyDescriptor =
                      Object.getOwnPropertyDescriptor(process, propertyName);
                    var prototypePropertyDescriptor =
                      Object.getOwnPropertyDescriptor(proto, propertyName);
                    if (!propertyDescriptor ||
                        typeof propertyDescriptor.get !== 'function' ||
                        typeof propertyDescriptor.set !== 'function' ||
                        propertyDescriptor.configurable !== false ||
                        (!!prototypePropertyDescriptor !== property[3]) ||
                        (prototypePropertyDescriptor &&
                          (prototypePropertyDescriptor.get !==
                              propertyDescriptor.get ||
                            prototypePropertyDescriptor.set !==
                              propertyDescriptor.set ||
                            prototypePropertyDescriptor.configurable !==
                              false)) ||
                        !denied(function () {
                          return process[propertyName];
                        }, propertyPermission) ||
                        !denied(function () {
                          process[propertyName] = property[2];
                        }, propertyPermission) ||
                        (prototypePropertyDescriptor &&
                          (!denied(function () {
                            return prototypePropertyDescriptor.get.call(
                              process);
                          }, propertyPermission) ||
                            !denied(function () {
                              return prototypePropertyDescriptor.set.call(
                                process,
                                property[2]);
                            }, propertyPermission)))) {
                      return false;
                    }
                  }
                  return typeof process.getuid() === 'number' &&
                    typeof process.getgid() === 'number' &&
                    typeof process.geteuid() === 'number' &&
                    typeof process.getegid() === 'number' &&
                    !('_uid' in process) &&
                    !('_gid' in process) &&
                    !('_euid' in process) &&
                    !('_egid' in process) &&
                    !('_title' in process);
                })()"#
                    .to_vec(),
            )
            .into_request()
            .unwrap();

        let typed_before = host.typed_decision_count();
        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, request)
            .await
            .expect("armed process shared-state closure probe must evaluate")
        else {
            panic!("armed process shared-state closure probe did not return its boolean verdict")
        };
        assert_eq!(display.kind, AuthenticatedDisplayKind::Boolean);
        assert_eq!(display.text, "true");
        engine
            .release_undisplayed_value(receipt.expect("probe value must retain a receipt"))
            .await
            .unwrap();
        assert_eq!(
            host.typed_decision_count(),
            typed_before,
            "closed process shared-state surfaces must not enter the typed evaluator"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_loader_proof_counters_are_live_and_unforgeable() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, vec![], None, |_| {});
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                br#"(function () {
                  var stats = globalThis.__ibexCompatLoaderStats;
                  var rootDescriptor = Object.getOwnPropertyDescriptor(
                    globalThis, '__ibexCompatLoaderStats');
                  var sourceDescriptor = Object.getOwnPropertyDescriptor(
                    stats, 'sourceTransformCount');
                  var compileDescriptor = Object.getOwnPropertyDescriptor(
                    stats, 'dynamicFunctionCompileCount');
                  if (!stats || !rootDescriptor ||
                      rootDescriptor.value !== stats ||
                      rootDescriptor.writable !== false ||
                      rootDescriptor.configurable !== false ||
                      !Object.isFrozen(stats) ||
                      !sourceDescriptor || !compileDescriptor ||
                      typeof sourceDescriptor.get !== 'function' ||
                      typeof compileDescriptor.get !== 'function' ||
                      sourceDescriptor.set !== undefined ||
                      compileDescriptor.set !== undefined ||
                      sourceDescriptor.configurable !== false ||
                      compileDescriptor.configurable !== false ||
                      !Number.isSafeInteger(stats.sourceTransformCount) ||
                      !Number.isSafeInteger(stats.dynamicFunctionCompileCount) ||
                      stats.sourceTransformCount < 0 ||
                      stats.dynamicFunctionCompileCount < 0) {
                    return false;
                  }
                  var sourceCount = stats.sourceTransformCount;
                  var compileCount = stats.dynamicFunctionCompileCount;
                  try { stats.sourceTransformCount = 999; } catch (_) {}
                  try {
                    Object.defineProperty(
                      stats, 'dynamicFunctionCompileCount', { value: 999 });
                  } catch (_) {}
                  try {
                    globalThis.__ibexCompatLoaderStats = {
                      sourceTransformCount: 999,
                      dynamicFunctionCompileCount: 999
                    };
                  } catch (_) {}
                  return globalThis.__ibexCompatLoaderStats === stats &&
                    stats.sourceTransformCount === sourceCount &&
                    stats.dynamicFunctionCompileCount === compileCount;
                })()"#
                    .to_vec(),
            )
            .into_request()
            .unwrap();

        let typed_before = host.typed_decision_count();
        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, request)
            .await
            .expect("armed loader proof counter probe must evaluate")
        else {
            panic!("armed loader proof counter probe did not return its boolean verdict")
        };
        assert_eq!(display.kind, AuthenticatedDisplayKind::Boolean);
        assert_eq!(display.text, "true");
        engine
            .release_undisplayed_value(receipt.expect("probe value must retain a receipt"))
            .await
            .unwrap();
        assert_eq!(
            host.typed_decision_count(),
            typed_before,
            "loader proof counters are authority-free bootstrap state"
        );
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_fs_builtin_uses_sealed_bootstrap_mutation_guard() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-private-fs-guard-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let missing = root.join("closed-missing");
        let virtual_missing = "/project/closed-missing";
        let (host, digest) =
            build_armed_test_host_custom(Some(&root), true, true, true, vec![], None, |snapshot| {
                snapshot["principals"][0]["imports"]["builtins"] = serde_json::json!(["node:fs"]);
            });
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let source = format!(
            r#"(function() {{
                  var rootGuardAbsent = typeof globalThis.__exactFsMutationGuard === 'undefined';
                  var replacementCalls = 0;
                  var replacement = function() {{ replacementCalls++; }};
                  globalThis.__exactFsMutationGuard = replacement;
                  var replacementInstalled = globalThis.__exactFsMutationGuard === replacement;
                  var fs = require('node:fs');
                  var outcome;
                  try {{
                    fs.rmSync({missing:?}, {{ recursive: true, force: true }});
                    outcome = {{ allowed: true }};
                  }} catch (error) {{
                    outcome = {{
                      allowed: false,
                      code: error && error.code,
                      syscall: error && error.syscall
                    }};
                  }}
                  delete globalThis.__exactFsMutationGuard;
                  return JSON.stringify({{
                    rootGuardAbsent: rootGuardAbsent,
                    replacementInstalled: replacementInstalled,
                    replacementCalls: replacementCalls,
                    outcome: outcome
                  }});
                }})()"#,
            missing = virtual_missing,
        );
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
            .bind_bytes(source.into_bytes())
            .into_request()
            .unwrap();
        let evaluation = engine
            .evaluate_authenticated(&session, request)
            .await
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
            panic!("authenticated fs probe did not return normally: {evaluation:?}")
        };
        let rendered: String = serde_json::from_str(&display.text).unwrap();
        let result: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        engine
            .release_undisplayed_value(receipt.expect("fs probe value must retain a receipt"))
            .await
            .unwrap();
        assert_eq!(result["rootGuardAbsent"], true, "{result}");
        assert_eq!(result["replacementInstalled"], true, "{result}");
        assert_eq!(result["replacementCalls"], 0, "{result}");
        assert_eq!(result["outcome"]["allowed"], false, "{result}");
        assert_eq!(result["outcome"]["code"], "EPERM", "{result}");
        assert_eq!(result["outcome"]["syscall"], "rm", "{result}");
        assert!(!missing.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_throwing_timer_preserves_value_owner_and_evaluation() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        let root = host
            .typed_principal_for_module("0")
            .expect("armed fixture must authenticate its root principal");
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let first = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"var asyncAfter = false; var badTimer = setTimeout(function () { throw 'timer-value'; }, 0); setTimeout(function () { asyncAfter = true; }, 0); badTimer"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, first)
            .await
            .unwrap()
        else {
            panic!("timer scheduling input did not return its timer identity")
        };
        let timer_id = display
            .text
            .parse::<u64>()
            .expect("timer scheduling identity must render as an integer");
        engine
            .release_undisplayed_value(receipt.expect("timer id must retain a receipt"))
            .await
            .unwrap();

        engine.drive_ready_tasks().await.unwrap();
        let failures = engine.take_authenticated_async_failures().await.unwrap();
        assert_eq!(failures.len(), 1, "one throwing timer must report once");
        let AuthenticatedAsyncFailure::Captured {
            thrown,
            owning_principal,
            event_identity,
            associated_evaluation,
        } = &failures[0]
        else {
            panic!(
                "throwing timer lost its structured capture: {:?}",
                failures[0]
            )
        };
        assert_eq!(thrown.value.kind, AuthenticatedDisplayKind::String);
        assert_eq!(
            thrown.value.text,
            serde_json::to_string("timer-value").unwrap()
        );
        assert_eq!(
            owning_principal,
            &AuthenticatedAsyncFailureOwner::Authenticated {
                principal: root.clone()
            }
        );
        assert_eq!(event_identity, &format!("timer:{timer_id}"));
        assert_eq!(*associated_evaluation, Some(1));

        let second = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"asyncAfter ? 42 : -1".to_vec())
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, second)
            .await
            .unwrap()
        else {
            panic!("runtime was not reusable after a background throw")
        };
        assert_eq!(display.kind, AuthenticatedDisplayKind::Number);
        assert_eq!(display.text, "42");
        engine
            .release_undisplayed_value(receipt.expect("successor value must retain a receipt"))
            .await
            .unwrap();
        assert!(engine
            .take_authenticated_async_failures()
            .await
            .unwrap()
            .is_empty());

        let third = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"var tickAfter = false; process.nextTick(function () { throw 'tick-value'; }); process.nextTick(function () { tickAfter = true; }); tickAfter"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { receipt, .. } = engine
            .evaluate_authenticated(&session, third)
            .await
            .unwrap()
        else {
            panic!("next-tick scheduling input did not settle normally")
        };
        engine
            .release_undisplayed_value(receipt.expect("tick value must retain a receipt"))
            .await
            .unwrap();
        engine.drive_ready_tasks().await.unwrap();
        let failures = engine.take_authenticated_async_failures().await.unwrap();
        assert_eq!(failures.len(), 1, "one throwing next-tick must report once");
        let AuthenticatedAsyncFailure::Captured {
            thrown,
            owning_principal,
            event_identity,
            associated_evaluation,
        } = &failures[0]
        else {
            panic!("throwing next-tick lost its structured capture")
        };
        assert_eq!(thrown.value.kind, AuthenticatedDisplayKind::String);
        assert_eq!(
            thrown.value.text,
            serde_json::to_string("tick-value").unwrap()
        );
        assert_eq!(
            owning_principal,
            &AuthenticatedAsyncFailureOwner::Authenticated { principal: root }
        );
        event_identity
            .strip_prefix("next-tick:")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .expect("next-tick event identity must be a nonzero schedule-time id");
        assert_eq!(*associated_evaluation, Some(3));

        let fourth = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"tickAfter ? 43 : -1".to_vec())
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, fourth)
            .await
            .unwrap()
        else {
            panic!("runtime was not reusable after a next-tick throw")
        };
        assert_eq!(display.text, "43");
        engine
            .release_undisplayed_value(receipt.expect("successor value must retain a receipt"))
            .await
            .unwrap();
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_promise_checkpoint_preserves_provenance_and_tla_is_not_duplicated() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        let root = host
            .typed_principal_for_module("0")
            .expect("armed fixture must authenticate its root principal");
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let rejection = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"var promiseAfter = false; var priorPrepareStackTrace = Error.prepareStackTrace; Error.prepareStackTrace = function hostilePrepareStackTrace() { throw new Error('prepareStackTrace consulted'); }; Promise.resolve().then(function promiseOwner() { var error = new Error('promise-owned'); Object.defineProperty(error, 'stack', { get: function hostileStackGetter() { throw new Error('stack getter consulted'); } }); throw error; }); queueMicrotask(function () { promiseAfter = true; Error.prepareStackTrace = priorPrepareStackTrace; }); 0\n//# sourceURL=/host-looking/forged.js"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { receipt, .. } = engine
            .evaluate_authenticated(&session, rejection)
            .await
            .unwrap()
        else {
            panic!("Promise scheduling input did not settle normally")
        };
        engine
            .release_undisplayed_value(receipt.expect("fixture value must retain a receipt"))
            .await
            .unwrap();
        engine.drive_ready_tasks().await.unwrap();

        let failures = engine.take_authenticated_async_failures().await.unwrap();
        assert_eq!(
            failures.len(),
            1,
            "one rejected continuation must report once"
        );
        let AuthenticatedAsyncFailure::Captured {
            thrown,
            owning_principal,
            event_identity,
            associated_evaluation,
        } = &failures[0]
        else {
            panic!("Promise rejection lost its structured capture")
        };
        assert_eq!(thrown.value.kind, AuthenticatedDisplayKind::Object);
        assert_eq!(thrown.value.text, "[Object]");
        let AuthenticatedThrowMetadata::Captured {
            error_class,
            message,
            stack,
            positions,
            ..
        } = &thrown.metadata
        else {
            panic!("Promise rejection did not carry engine-safe metadata")
        };
        assert_eq!(*error_class, AuthenticatedErrorClass::Error);
        assert_eq!(message.as_deref(), Some("promise-owned"));
        assert!(
            stack.as_deref().is_some_and(|stack| {
                stack.contains("promiseOwner")
                    && stack.contains("repl:1")
                    && !stack.contains("/host-looking/forged.js")
                    && !stack.contains("hostilePrepareStackTrace")
                    && !stack.contains("hostileStackGetter")
            }),
            "safe stack did not retain the authenticated source label: {stack:?}"
        );
        assert!(
            positions.is_empty(),
            "source-position stratum remains separate"
        );
        assert_eq!(
            owning_principal,
            &AuthenticatedAsyncFailureOwner::Authenticated {
                principal: root.clone()
            }
        );
        event_identity
            .strip_prefix("microtask:")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .expect("Promise event identity must be its nonzero Hermes job id");
        assert_eq!(*associated_evaluation, Some(1));

        let state = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"JSON.stringify({ after: promiseAfter, exitCode: process.exitCode || 0 })"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, state)
            .await
            .unwrap()
        else {
            panic!("runtime was not reusable after a rejected continuation")
        };
        let state_json: String = serde_json::from_str(&display.text).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&state_json).unwrap(),
            serde_json::json!({"after": true, "exitCode": 0}),
            "the engine must report without deciding process fatality"
        );
        engine
            .release_undisplayed_value(receipt.expect("state value must retain a receipt"))
            .await
            .unwrap();

        let listener = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"var listenerReason = ''; process.once('unhandledRejection', function (reason) { listenerReason = reason.message; }); Promise.reject(new Error('listener-owned')); 0"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Throw(thrown) = engine
            .evaluate_authenticated(&session, listener)
            .await
            .unwrap()
        else {
            panic!("armed unhandledRejection listener registration was not refused")
        };
        assert_eq!(
            thrown.metadata.error_class(),
            Some(AuthenticatedErrorClass::Error)
        );
        assert_eq!(
            thrown.metadata.message(),
            Some("process.once is disabled for this event in an armed runtime")
        );
        engine.drive_ready_tasks().await.unwrap();
        assert!(
            engine
                .take_authenticated_async_failures()
                .await
                .unwrap()
                .is_empty(),
            "a refused unhandledRejection listener must not schedule a rejection"
        );

        let handled = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"var handledBeforeCheckpoint = Promise.reject(new Error('checkpoint-cancelled')); queueMicrotask(function () { handledBeforeCheckpoint.catch(function () {}); }); listenerReason"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = engine
            .evaluate_authenticated(&session, handled)
            .await
            .unwrap()
        else {
            panic!("checkpoint-cancellation fixture did not settle normally")
        };
        assert_eq!(
            display.text,
            serde_json::to_string("").unwrap(),
            "the phase-6 listener denial did not preserve the committed var binding"
        );
        engine
            .release_undisplayed_value(receipt.expect("handled value must retain a receipt"))
            .await
            .unwrap();
        engine.drive_ready_tasks().await.unwrap();
        assert!(
            engine
                .take_authenticated_async_failures()
                .await
                .unwrap()
                .is_empty(),
            "a handler attached before the poll checkpoint must cancel by Promise identity"
        );

        let top_level_await = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"await Promise.reject(new Error('tla-only'));".to_vec())
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Throw(thrown) = engine
            .evaluate_authenticated(&session, top_level_await)
            .await
            .unwrap()
        else {
            panic!("rejected top-level await did not become a Throw outcome")
        };
        assert_eq!(thrown.value.kind, AuthenticatedDisplayKind::Object);
        assert_eq!(thrown.metadata.message(), Some("tla-only"));
        assert!(
            thrown
                .metadata
                .stack()
                .is_some_and(|stack| stack.contains("repl:5")),
            "top-level-await throw did not keep its engine-safe source label"
        );
        engine.drive_ready_tasks().await.unwrap();
        assert!(
            engine
                .take_authenticated_async_failures()
                .await
                .unwrap()
                .is_empty(),
            "one rejected top-level-await Promise must not also report as background work"
        );
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn authenticated_package_promise_and_native_completion_never_launder_to_root() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot, Principal};
        use ibex_runtime::engine::evaluation::SubmissionSequence;
        use std::os::unix::fs::MetadataExt;

        let _lock = hermes_engine_test_lock().lock().await;
        let project = tempfile::tempdir().unwrap();
        let project_root = fs::canonicalize(project.path()).unwrap();
        let package_root = project_root.join("node_modules/image-lib");
        fs::create_dir_all(&package_root).unwrap();
        fs::create_dir_all(project_root.join("images")).unwrap();
        fs::write(project_root.join("images/native.txt"), b"native").unwrap();
        fs::write(
            package_root.join("package.json"),
            r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
        )
        .unwrap();
        fs::write(
            package_root.join("index.js"),
            r#"module.exports = function schedulePackageFailures() {
  Promise.resolve().then(function packagePromiseFailure() {
    throw new Error('package-promise');
  });
  require('node:fs').readFile('/project/images/native.txt', function packageNativeFailure(error) {
    if (error) throw error;
    throw new Error('package-native');
  });
};
"#,
        )
        .unwrap();

        let integrity = crate::module_loader::package_tree_integrity(&package_root).unwrap();
        let package_principal: Principal = serde_json::from_value(serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": integrity,
            "locator": "image-lib@2.4.1",
        }))
        .unwrap();
        let principal_json = serde_json::to_value(&package_principal).unwrap();
        let package_components = package_root
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(value) => Some(serde_json::json!({
                    "encoding": "utf8",
                    "value": value.to_str().unwrap(),
                })),
                _ => None,
            })
            .collect::<Vec<_>>();
        let package_metadata = fs::metadata(&package_root).unwrap();
        let (host, digest) = build_armed_test_host_control(
            Some(&project_root),
            false,
            true,
            true,
            vec![],
            vec![],
            true,
            1,
            None,
            move |snapshot| {
                snapshot["principals"][1]["principal"] = principal_json.clone();
                snapshot["packageGraph"]["nodes"][0]["principal"] = principal_json.clone();
                snapshot["packageGraph"]["importEdges"][0]["imported"] = principal_json.clone();
                snapshot["rootBindings"][0] = serde_json::json!({
                    "logicalRoot": "package",
                    "owner": principal_json,
                    "hostPath": {
                        "root": "absolute",
                        "components": package_components,
                        "hostBound": true,
                    },
                    "object": {
                        "platform": if cfg!(any(target_os = "macos", target_os = "ios", target_os = "tvos")) {
                            "apple"
                        } else {
                            "unix"
                        },
                        "volume": format!("dev:{}", package_metadata.dev()),
                        "file": format!("ino:{}", package_metadata.ino()),
                    },
                });
            },
        );
        let root_principal = host
            .typed_principal_for_module("0")
            .expect("armed fixture must authenticate root");
        assert_ne!(root_principal, package_principal);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"require('image-lib')(); 0".to_vec())
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { receipt, .. } = engine
            .evaluate_authenticated(&session, request)
            .await
            .unwrap()
        else {
            panic!("package scheduling input did not settle normally")
        };
        engine
            .release_undisplayed_value(receipt.expect("fixture value must retain a receipt"))
            .await
            .unwrap();
        engine
            .drive_authenticated_program_to_quiescence()
            .await
            .unwrap();

        let failures = engine.take_authenticated_async_failures().await.unwrap();
        assert_eq!(
            failures.len(),
            2,
            "both package chains must report exactly once"
        );
        let mut messages = Vec::new();
        for failure in failures {
            let AuthenticatedAsyncFailure::Captured {
                thrown,
                owning_principal,
                event_identity,
                associated_evaluation,
            } = failure
            else {
                panic!("package failure lost its structured capture")
            };
            assert_eq!(
                owning_principal,
                AuthenticatedAsyncFailureOwner::Authenticated {
                    principal: package_principal.clone(),
                },
                "a package-scheduled failure was laundered to root"
            );
            event_identity
                .strip_prefix("microtask:")
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value != 0)
                .expect("package Promise failure must carry a Hermes job identity");
            assert_eq!(associated_evaluation, Some(1));
            let message = thrown
                .metadata
                .message()
                .expect("package Error must carry safe metadata")
                .to_owned();
            assert!(
                thrown.metadata.stack().is_some_and(|stack| {
                    stack.contains("packagePromiseFailure")
                        || stack.contains("packageNativeFailure")
                }),
                "package Error stack lost its defining function"
            );
            messages.push(message);
        }
        messages.sort();
        assert_eq!(messages, ["package-native", "package-promise"]);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_session_package_compartment_withholds_all_late_global_spellings() {
        use capsec_semantics::model::Principal;
        use std::os::unix::fs::MetadataExt;

        let _lock = hermes_engine_test_lock().lock().await;
        let project = tempfile::tempdir().unwrap();
        let project_root = fs::canonicalize(project.path()).unwrap();
        let package_root = project_root.join("node_modules/image-lib");
        fs::create_dir_all(&package_root).unwrap();
        fs::write(
            package_root.join("package.json"),
            r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
        )
        .unwrap();
        fs::write(
            package_root.join("index.js"),
            r#"module.exports = function observeLateSessionGlobals() {
  function bareVarRead() {
    try { return { kind: 'value', value: String(packageSessionVarSecret) }; }
    catch (error) { return { kind: String(error && error.name || error) }; }
  }
  function bareSloppyRead() {
    try { return { kind: 'value', value: String(packageSloppySessionSecret) }; }
    catch (error) { return { kind: String(error && error.name || error) }; }
  }
  function reflected(name) {
    return {
      has: name in globalThis,
      descriptorType: typeof Object.getOwnPropertyDescriptor(globalThis, name),
      enumerated: Object.getOwnPropertyNames(globalThis).indexOf(name) !== -1
    };
  }
  return {
    package_compartment_withholds_session_var_binding: {
      bareRead: bareVarRead(),
      reflected: reflected('packageSessionVarSecret')
    },
    package_compartment_withholds_sloppy_created_global: {
      bareRead: bareSloppyRead(),
      reflected: reflected('packageSloppySessionSecret')
    },
    package_compartment_withholds_adopted_then_assigned_global: {
      bareRead: {
        isSessionValue: TextEncoder === 417,
        type: typeof TextEncoder
      },
      reflected: reflected('TextEncoder')
    }
  };
};
"#,
        )
        .unwrap();

        let integrity = crate::module_loader::package_tree_integrity(&package_root).unwrap();
        let package_principal: Principal = serde_json::from_value(serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": integrity,
            "locator": "image-lib@2.4.1",
        }))
        .unwrap();
        let principal_json = serde_json::to_value(&package_principal).unwrap();
        let package_components = package_root
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(value) => Some(serde_json::json!({
                    "encoding": "utf8",
                    "value": value.to_str().unwrap(),
                })),
                _ => None,
            })
            .collect::<Vec<_>>();
        let package_metadata = fs::metadata(&package_root).unwrap();
        let (host, digest) = build_armed_test_host_control(
            Some(&project_root),
            false,
            true,
            true,
            vec![],
            vec![],
            true,
            1,
            None,
            move |snapshot| {
                snapshot["principals"][1]["principal"] = principal_json.clone();
                snapshot["packageGraph"]["nodes"][0]["principal"] = principal_json.clone();
                snapshot["packageGraph"]["importEdges"][0]["imported"] = principal_json.clone();
                snapshot["rootBindings"][0] = serde_json::json!({
                    "logicalRoot": "package",
                    "owner": principal_json,
                    "hostPath": {
                        "root": "absolute",
                        "components": package_components,
                        "hostBound": true,
                    },
                    "object": {
                        "platform": if cfg!(any(target_os = "macos", target_os = "ios", target_os = "tvos")) {
                            "apple"
                        } else {
                            "unix"
                        },
                        "volume": format!("dev:{}", package_metadata.dev()),
                        "file": format!("ino:{}", package_metadata.ino()),
                    },
                });
            },
        );
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

        let expected_package_observation = serde_json::json!({
            "package_compartment_withholds_session_var_binding": {
                "bareRead": {"kind": "value", "value": "undefined"},
                "reflected": {
                    "has": false,
                    "descriptorType": "undefined",
                    "enumerated": false,
                },
            },
            "package_compartment_withholds_sloppy_created_global": {
                "bareRead": {"kind": "value", "value": "undefined"},
                "reflected": {
                    "has": false,
                    "descriptorType": "undefined",
                    "enumerated": false,
                },
            },
            "package_compartment_withholds_adopted_then_assigned_global": {
                "bareRead": {
                    "isSessionValue": false,
                    "type": "function",
                },
                "reflected": {
                    "has": true,
                    "descriptorType": "undefined",
                    "enumerated": false,
                },
            },
        });
        // The baseline is finalized before any of these persistent-session
        // writes. Each spelling exercises LLP 0024's distinct leakage route:
        // created `var`, sloppy-created global, and adopted builtin slot.
        // @ref LLP 0024#77-deviations-and-the-four-gates-that-prove-them —
        // package modules resolve against the arming baseline, never live
        // session-authored realm state.
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "var packageSessionVarSecret = 'VAR-SECRET'; 'var-ready'",
                )
                .await,
            "var-ready"
        );
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "packageSloppySessionSecret = 'SLOPPY-SECRET'; 'sloppy-ready'",
                )
                .await,
            "sloppy-ready"
        );
        assert_eq!(
            evaluator
                .eval_string(&engine, "var TextEncoder = 417; 'adopted-ready'")
                .await,
            "adopted-ready"
        );

        // First-load the package only after all three root writes. This catches
        // a lazy compartment implementation that snapshots the live realm when
        // `require` first creates a package module instead of using the
        // bootstrap-finalized baseline.
        let encoded = evaluator
            .eval_string(
                &engine,
                r#"JSON.stringify({
  package: require('image-lib')(),
  root: {
    varValue: packageSessionVarSecret,
    sloppyValue: packageSloppySessionSecret,
    adoptedValue: TextEncoder
  }
})"#,
            )
            .await;
        let observed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            observed,
            serde_json::json!({
                "package": expected_package_observation,
                "root": {
                    "varValue": "VAR-SECRET",
                    "sloppyValue": "SLOPPY-SECRET",
                    "adoptedValue": 417,
                },
            })
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_async_failure_overflow_is_an_explicit_loss_window() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"for (var asyncFailureIndex = 0; asyncFailureIndex < 1025; asyncFailureIndex++) { process.nextTick(function () { throw 'overflow-value'; }); } 0"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { receipt, .. } = engine
            .evaluate_authenticated(&session, request)
            .await
            .expect("overflow fixture must schedule normally")
        else {
            panic!("overflow fixture did not return normally")
        };
        engine
            .release_undisplayed_value(receipt.expect("fixture result must retain a receipt"))
            .await
            .unwrap();
        engine.drive_ready_tasks().await.unwrap();

        let failures = engine.take_authenticated_async_failures().await.unwrap();
        assert_eq!(failures.len(), 1025);
        assert!(failures[..1024].iter().all(|failure| matches!(
            failure,
            AuthenticatedAsyncFailure::Captured { thrown, .. }
                if thrown.value.kind == AuthenticatedDisplayKind::String
                    && thrown.value.text == serde_json::to_string("overflow-value").unwrap()
        )));
        assert_eq!(
            failures.last(),
            Some(&AuthenticatedAsyncFailure::PreReceiptLoss { count: 1 })
        );
        assert!(engine
            .take_authenticated_async_failures()
            .await
            .unwrap()
            .is_empty());
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_promise_rejection_burst_is_bounded_and_releases_roots() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let root_count = |selector| {
            runtime
                .with_runtime(|raw| unsafe { ibex_test_structured_async_root_count(raw, selector) })
                .unwrap()
        };

        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(
                b"for (var rejectionIndex = 0; rejectionIndex < 1025; rejectionIndex++) { Promise.reject('pending-burst'); } 0"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { receipt, .. } = engine
            .evaluate_authenticated(&session, request)
            .await
            .expect("Promise burst must schedule normally")
        else {
            panic!("Promise burst did not settle normally")
        };
        engine
            .release_undisplayed_value(receipt.expect("burst result must retain a receipt"))
            .await
            .unwrap();

        assert_eq!(
            root_count(1),
            1024,
            "pending Promise roots exceeded their cap"
        );
        assert_eq!(root_count(4), 1, "pending collection loss was not exact");
        assert_eq!(
            root_count(2),
            0,
            "pending reasons must not mint value handles"
        );
        assert_eq!(
            root_count(3),
            0,
            "pending reasons must not mint metadata handles"
        );

        engine.drive_ready_tasks().await.unwrap();
        assert_eq!(
            root_count(1),
            0,
            "checkpoint did not release pending Promise roots"
        );
        assert_eq!(root_count(4), 0, "pending loss was not transferred");
        assert_eq!(
            root_count(5),
            1024,
            "the first retained window was not preserved"
        );
        assert_eq!(root_count(6), 1, "the later loss marker was not exact");
        assert_eq!(
            root_count(2),
            1024,
            "published values were not rooted exactly once"
        );
        assert_eq!(
            root_count(3),
            1024,
            "safe metadata roots did not match values"
        );

        let failures = engine.take_authenticated_async_failures().await.unwrap();
        assert_eq!(failures.len(), 1025);
        assert!(failures[..1024].iter().all(|failure| matches!(
            failure,
            AuthenticatedAsyncFailure::Captured { thrown, .. }
                if thrown.value.kind == AuthenticatedDisplayKind::String
                    && thrown.value.text == serde_json::to_string("pending-burst").unwrap()
        )));
        assert_eq!(
            failures.last(),
            Some(&AuthenticatedAsyncFailure::PreReceiptLoss { count: 1 })
        );
        for selector in 1..=6 {
            assert_eq!(
                root_count(selector),
                0,
                "async root/counter selector {selector} was not released"
            );
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_pending_promise_rejection_loss_saturates_fail_closed() {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};
        use ibex_runtime::engine::evaluation::SubmissionSequence;

        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe {
                    ibex_test_set_pending_promise_rejection_drop_count(raw, u64::MAX)
                })
                .unwrap(),
            1
        );

        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"Promise.reject('saturated-pending-loss'); 0".to_vec())
            .into_request()
            .unwrap();
        let AuthenticatedEvaluation::Value { receipt, .. } = engine
            .evaluate_authenticated(&session, request)
            .await
            .expect("saturation fixture must finish its foreground evaluation")
        else {
            panic!("saturation fixture did not settle normally")
        };
        engine
            .release_undisplayed_value(receipt.expect("fixture result must retain a receipt"))
            .await
            .unwrap();

        let error = engine
            .take_authenticated_async_failures()
            .await
            .expect_err("an unrepresentable loss count must fail closed");
        assert!(error
            .to_string()
            .contains("asynchronous failure publication failed"));
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ibex_test_structured_async_root_count(raw, 1) })
                .unwrap(),
            0,
            "saturation must not retain a rejected Promise"
        );
        assert_eq!(
            runtime
                .with_runtime(|raw| unsafe { ibex_test_structured_async_root_count(raw, 2) })
                .unwrap(),
            0,
            "saturation must not mint a rooted value handle"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_root_global_disposition_rejects_extra_accessor_without_get() {
        struct ResetDispositionInjection;
        impl Drop for ResetDispositionInjection {
            fn drop(&mut self) {
                unsafe { ibex_test_set_root_global_disposition_key(std::ptr::null()) };
            }
        }

        let _lock = hermes_engine_test_lock().lock().await;
        let _reset_injection = ResetDispositionInjection;
        let (_reset_host, digest) = install_armed_test_host();
        let key = CString::new("__ibexUndispositionedGetterBomb").unwrap();
        unsafe { ibex_test_set_root_global_disposition_key(key.as_ptr()) };
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let error = engine
            .load_runtime()
            .await
            .expect_err("an extra live root must fail armed finalization");
        assert!(error.to_string().contains("fault"));
        assert_eq!(
            unsafe { ibex_test_root_global_disposition_getter_calls() },
            0,
            "descriptor sweep must not invoke an accessor"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_random_bytes_is_a_zero_decision_non_capability() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        // This is a native-boundary conformance probe. Project source cannot
        // name private __exact* bridges after the one-shot armed seal.

        let typed_before = crate::host::abi::installed_typed_decision_count();
        let legacy_before = crate::host::abi::installed_legacy_authorization_check_count();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.exactrandombytes.non-capability"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  var bytes = __exactRandomBytes(16);
                  return String(bytes instanceof Uint8Array) + '/' + String(bytes.byteLength);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("true/16"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "random bytes must not consult the legacy oracle"
        );
        assert!(
            typed.is_empty(),
            "random bytes must not emit a typed decision"
        );
        assert_eq!(
            crate::host::abi::installed_legacy_authorization_check_count() - legacy_before,
            0
        );
        assert_eq!(
            crate::host::abi::installed_typed_decision_count() - typed_before,
            0
        );
        engine.load_runtime().await.unwrap();
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_network_release_calls_require_only_ownership() {
        let _lock = hermes_engine_test_lock().lock().await;
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let floor = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "tcp",
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let (_reset, digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let setup = engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                  globalThis.__releaseClose = __exactTcpConnect('127.0.0.1', {port});
                  globalThis.__releaseReset = __exactTcpConnect('127.0.0.1', {port});
                  globalThis.__releaseShutdown = __exactTcpConnect('127.0.0.1', {port});
                  return 'ready';
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(setup.as_deref(), Some("ready"));

        let typed_before = crate::host::abi::installed_typed_decision_count();
        let legacy_before = crate::host::abi::installed_legacy_authorization_check_count();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.network.authority-release"
        ));
        let released = engine
            .eval_immediate(
                r#"(function() {
                  __exactTcpClose(globalThis.__releaseClose);
                  __exactTcpReset(globalThis.__releaseReset);
                  __exactTcpClose(globalThis.__releaseReset);
                  __exactTcpShutdown(globalThis.__releaseShutdown, 1);
                  __exactTcpClose(globalThis.__releaseShutdown);
                  return 'released';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(released.as_deref(), Some("released"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "release must not consult the legacy oracle"
        );
        assert!(typed.is_empty(), "release must not emit a typed decision");
        assert_eq!(
            crate::host::abi::installed_legacy_authorization_check_count() - legacy_before,
            0
        );
        assert_eq!(
            crate::host::abi::installed_typed_decision_count() - typed_before,
            0
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_exact_memory_sqlite_is_a_zero_decision_non_capability() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        // Exercise the private native ABI only during trusted bootstrap; the
        // public SQLite wrapper retains this binding across the armed seal.

        let prefixed_uri = engine
            .eval_immediate(
                r#"(function() {
                  try { __exactSqliteOpen('file::memory:?cache=shared', null); }
                  catch (_) { return 'denied'; }
                  return 'allowed';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(
            prefixed_uri.as_deref(),
            Some("denied"),
            "a URI-looking disk filename must not inherit the :memory: exemption"
        );

        let typed_before = crate::host::abi::installed_typed_decision_count();
        let legacy_before = crate::host::abi::installed_legacy_authorization_check_count();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.sqlite.memory.non-capability"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  var db = __exactSqliteOpen(':memory:', null);
                  var inTransaction = __exactSqliteInTransaction(db);
                  __exactSqliteClose(db);
                  return typeof inTransaction + '/' + String(inTransaction);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("boolean/false"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "in-memory SQLite must not consult the legacy oracle"
        );
        assert!(
            typed.is_empty(),
            "in-memory SQLite must not emit a typed decision"
        );
        assert_eq!(
            crate::host::abi::installed_legacy_authorization_check_count() - legacy_before,
            0
        );
        assert_eq!(
            crate::host::abi::installed_typed_decision_count() - typed_before,
            0
        );
        engine.load_runtime().await.unwrap();
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_host_call_abi_rejects_post_lockdown_install_and_resolution() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        ABI_PROBE_SYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        ABI_PROBE_ASYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "String(typeof __hostCall + '/' + typeof __hostCallAsync)",
                )
                .await,
            "undefined/undefined"
        );

        // The setters are invoked after armed creation has completed its
        // structural lockdown checks. Both replacement attempts and a forged
        // async completion must be silent no-ops at the native ABI boundary.
        let runtime = engine.ensure_runtime().await.unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                ex_hermes_set_host_call(raw, abi_probe_sync_host_call);
                ex_hermes_set_host_call_async(raw, abi_probe_async_host_call);
                let payload = b"+{\"forged\":true}\0";
                ex_hermes_resolve_host_call(raw, u64::MAX, payload.as_ptr().cast());
            })
            .unwrap();

        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "String(typeof __hostCall + '/' + typeof __hostCallAsync)",
                )
                .await,
            "undefined/undefined"
        );
        assert_eq!(
            ABI_PROBE_SYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            ABI_PROBE_ASYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_exact_embedder_ingress_is_binary_endowed_and_single_use() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_exact_test_host();
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        EXACT_ABI_PROBE_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_OPERATION.store(0, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_PAYLOAD_LEN.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32, 11_u32];
        let manifest_digest =
            std::ffi::CString::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA").unwrap();
        let wrong_manifest_digest =
            std::ffi::CString::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        wrong_manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -8,
                    "an armed runtime must reject the wrong manifest before JSI mutation"
                );
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 1);
                let narrowed = [7_u32];
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        narrowed.as_ptr(),
                        narrowed.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -8,
                    "an armed runtime must reject a caller-selected endowment"
                );
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 1);
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 0);
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -5,
                    "an embedder cannot replace an installed endowment"
                );
            })
            .unwrap();

        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "typeof __hostCall + '/' + typeof __hostCallAsync + '/' + \
                     typeof exact.invokeHostAsync",
                )
                .await,
            "undefined/undefined/function"
        );
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "globalThis.__exactTypedResult = 'pending'; \
                     exact.invokeHostAsync(7, new Uint8Array([1,2,3])).then(\
                       function(value) { globalThis.__exactTypedResult = Array.from(value).join(','); },\
                       function(error) { globalThis.__exactTypedResult = 'rejected:' + error.message; }); \
                     'kicked'",
                )
                .await,
            "kicked"
        );
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            evaluator
                .eval_string(&engine, "String(globalThis.__exactTypedResult)")
                .await,
            "9,8"
        );
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "try { exact.invokeHostAsync(7, {}); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await,
            "exact.invokeHostAsync payload must be an ArrayBuffer or view"
        );
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "try { exact.invokeHostAsync(8, new Uint8Array()); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await,
            "exact.invokeHostAsync operation is not endowed"
        );
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
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_embedder_ingress_finalizes_immutable_package_capability() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let _compartments = TestEnvVar::set("IBEX_COMPARTMENTS", "1");
        EXACT_ABI_PROBE_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new().unwrap();
        // Touch the native runtime without running the CLI finalizer. This is
        // the embedder posture: the compartment hook is pending until the
        // typed ingress becomes the last package-visible native capability.
        assert!(engine.runtime_bundle_installed().await.unwrap());
        assert_eq!(
            engine
                .eval_immediate(
                    "typeof __ibexRefreshCompartmentBaseline + '/' + \
                     __ibexCompartmentBaselineFinalized",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("function/false")
        );

        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32];
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate(
                    r#"(function () {
                      var a = __compartments['alpha@1.0.0'];
                      var b = __compartments['beta@1.0.0'];
                      var original = a.exact.invokeHostAsync;
                      try { a.exact.invokeHostAsync = function () { return 'intercepted'; }; }
                      catch (_) {}
                      try { delete a.exact.invokeHostAsync; } catch (_) {}
                      var descriptor = Object.getOwnPropertyDescriptor(
                        a.exact, 'invokeHostAsync'
                      );
                      return JSON.stringify([
                        typeof __ibexRefreshCompartmentBaseline,
                        __ibexCompartmentBaselineFinalized,
                        typeof a.exact.invokeHostAsync,
                        original === b.exact.invokeHostAsync,
                        descriptor.writable,
                        descriptor.configurable,
                        descriptor.enumerable
                      ]);
                    })()"#,
                )
                .await
                .unwrap()
                .as_deref(),
            Some(r#"["undefined",true,"function",true,false,false,false]"#)
        );

        engine
            .eval_immediate(
                "globalThis.__exactPackageResult = 'pending'; \
                 __compartments['alpha@1.0.0'].exact.invokeHostAsync(\
                   7, new Uint8Array([1,2,3])\
                 ).then(function(value) { \
                   globalThis.__exactPackageResult = Array.from(value).join(','); \
                 });",
            )
            .await
            .unwrap();
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("globalThis.__exactPackageResult")
                .await
                .unwrap()
                .as_deref(),
            Some("9,8")
        );
        assert_eq!(
            EXACT_ABI_PROBE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_embedder_ingress_rolls_back_when_package_finalization_fails() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let _compartments = TestEnvVar::set("IBEX_COMPARTMENTS", "1");

        let engine = HermesEngine::new().unwrap();
        assert!(engine.runtime_bundle_installed().await.unwrap());
        engine
            .eval_immediate("delete globalThis.__ibexRefreshCompartmentBaseline")
            .await
            .unwrap();

        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32];
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -6
                );
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate(
                    "typeof exact.invokeHostAsync + '/' + \
                     __ibexCompartmentBaselineFinalized",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("undefined/false")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_embedder_ingress_rejects_malformed_completion_and_pending_flood() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);

        let malformed_engine = HermesEngine::new().unwrap();
        malformed_engine.load_runtime().await.unwrap();
        let malformed_runtime = malformed_engine.ensure_runtime().await.unwrap();
        let operations = [7_u32];
        malformed_runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_malformed_completion,
                        std::ptr::null_mut(),
                    ),
                    0
                );
            })
            .unwrap();
        malformed_engine
            .eval_immediate(
                "globalThis.__exactMalformed = 'pending'; \
                 exact.invokeHostAsync(7, new Uint8Array()).then(\
                   function() { globalThis.__exactMalformed = 'resolved'; },\
                   function(error) { globalThis.__exactMalformed = error.message; });",
            )
            .await
            .unwrap();
        malformed_engine.drive_event_loop().await.unwrap();
        assert_eq!(
            malformed_engine
                .eval_immediate("globalThis.__exactMalformed")
                .await
                .unwrap()
                .as_deref(),
            Some("Exact host operation completion payload is invalid or exceeds 16 MiB")
        );
        drop(malformed_runtime);
        drop(malformed_engine);

        let flood_engine = HermesEngine::new().unwrap();
        flood_engine.load_runtime().await.unwrap();
        let flood_runtime = flood_engine.ensure_runtime().await.unwrap();
        flood_runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_pending_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
            })
            .unwrap();
        flood_engine
            .eval_immediate(
                "globalThis.__exactFlood = 'pending'; \
                 for (var i = 0; i < 1025; i += 1) { \
                   exact.invokeHostAsync(7, new Uint8Array()).catch(\
                     function(error) { globalThis.__exactFlood = error.message; }); \
                 }",
            )
            .await
            .unwrap();
        flood_engine.drive_event_loop().await.unwrap();
        assert_eq!(
            flood_engine
                .eval_immediate("globalThis.__exactFlood")
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync pending-call budget exhausted")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn diagnostic_exact_embedder_ingress_exercises_binary_completion() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        EXACT_ABI_PROBE_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_OPERATION.store(0, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_PAYLOAD_LEN.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32, 11_u32];
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate(
                    "globalThis.__exactTypedResult = 'pending'; \
                     exact.invokeHostAsync(7, new Uint8Array([1,2,3])).then(\
                       function(value) { globalThis.__exactTypedResult = Array.from(value).join(','); },\
                       function(error) { globalThis.__exactTypedResult = 'rejected:' + error.message; }); \
                     'kicked'",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("kicked")
        );
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("globalThis.__exactTypedResult")
                .await
                .unwrap()
                .as_deref(),
            Some("9,8")
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "try { exact.invokeHostAsync(7, new Uint8Array(16777217)); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync payload exceeds 16 MiB")
        );
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
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_embedder_ingress_rejects_noncanonical_endowments() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                let raw_address = raw as usize;
                let off_owner = std::thread::spawn(move || {
                    let valid = [19_u32];
                    ex_hermes_set_exact_host_call_async(
                        raw_address as *mut HermesRuntimeOpaque,
                        1,
                        valid.as_ptr(),
                        valid.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    )
                })
                .join()
                .unwrap();
                assert_eq!(off_owner, -7);
                let unsorted = [11_u32, 7_u32];
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        unsorted.as_ptr(),
                        unsorted.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -4
                );
                let zero = [0_u32];
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        2,
                        zero.as_ptr(),
                        zero.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -4
                );
                let valid = [19_u32];
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        99,
                        valid.as_ptr(),
                        valid.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -3
                );
            })
            .unwrap();
        assert_eq!(
            engine
                .eval_immediate("typeof exact.invokeHostAsync")
                .await
                .unwrap()
                .as_deref(),
            Some("undefined")
        );
    }

    // LLP 0053 §I1 fail-closed matrix: a /2 snapshot refuses the v1 setter,
    // admits the v2 setter, and the tagged latch is one-shot across flavors.
    // §I3: the delivered attribution carries the projection-resolved root.
    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_exact_carrier_snapshot_binds_v2_ingress_with_attribution() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_exact_carrier_test_host(serde_json::json!({
            "home": exact_carrier_test_pin("app"),
            "settings": exact_carrier_test_pin("agentIsolate"),
        }));
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        EXACT_V2_PROBE_INVOCATIONS.lock().unwrap().clear();

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32, 11_u32];
        let manifest_digest =
            std::ffi::CString::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA").unwrap();
        let wrong_manifest_digest =
            std::ffi::CString::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -8,
                    "a carrier-armed artifact never runs behind the carrier-less v1 surface"
                );
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 1);
                assert_eq!(
                    ex_hermes_set_exact_host_call_async_v2(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        wrong_manifest_digest.as_ptr(),
                        abi_probe_exact_host_call_v2,
                        std::ptr::null_mut(),
                    ),
                    -8,
                    "the v2 setter still authenticates the manifest digest"
                );
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 1);
                assert_eq!(
                    ex_hermes_set_exact_host_call_async_v2(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call_v2,
                        std::ptr::null_mut(),
                    ),
                    0
                );
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 0);
                // One-shot on the tagged latch, both order combinations that
                // begin with an installed V2 flavor.
                assert_eq!(
                    ex_hermes_set_exact_host_call_async_v2(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call_v2,
                        std::ptr::null_mut(),
                    ),
                    -5,
                    "v2 after v2 must refuse the replacement"
                );
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -5,
                    "v1 after v2 must refuse the replacement"
                );
            })
            .unwrap();

        // Exactly 2 arguments => carrier ABSENT.
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "globalThis.__exactCarrierResult = 'pending'; \
                     exact.invokeHostAsync(7, new Uint8Array([1,2,3])).then(\
                       function(value) { globalThis.__exactCarrierResult = Array.from(value).join(','); },\
                       function(error) { globalThis.__exactCarrierResult = 'rejected:' + error.message; }); \
                     'kicked'",
                )
                .await,
            "kicked"
        );
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            evaluator
                .eval_string(&engine, "String(globalThis.__exactCarrierResult)")
                .await,
            "9,8"
        );
        // Exactly 3 arguments with a 32-byte carrier => PRESENT.
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "globalThis.__exactCarrierResult = 'pending'; \
                     exact.invokeHostAsync(11, new Uint8Array([4]), new Uint8Array(32).fill(7)).then(\
                       function(value) { globalThis.__exactCarrierResult = Array.from(value).join(','); },\
                       function(error) { globalThis.__exactCarrierResult = 'rejected:' + error.message; }); \
                     'kicked'",
                )
                .await,
            "kicked"
        );
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            evaluator
                .eval_string(&engine, "String(globalThis.__exactCarrierResult)")
                .await,
            "9,8"
        );
        // No other arity.
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "try { exact.invokeHostAsync(7, new Uint8Array([1]), new Uint8Array(1), 0); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await,
            "exact.invokeHostAsync requires an operation ID and bytes"
        );

        let invocations = EXACT_V2_PROBE_INVOCATIONS.lock().unwrap().clone();
        assert_eq!(invocations.len(), 2);
        let absent = &invocations[0];
        assert_eq!(absent.operation, 7);
        assert_eq!(absent.payload_len, 3);
        assert_eq!(absent.carrier, None);
        assert_eq!(absent.carrier_status, 2, "2 args deliver CARRIER_ABSENT");
        let present = &invocations[1];
        assert_eq!(present.operation, 11);
        assert_eq!(present.payload_len, 1);
        assert_eq!(present.carrier.as_deref(), Some(&[7_u8; 32][..]));
        assert_eq!(present.carrier_status, 1, "3 args deliver CARRIER_PRESENT");
        for invocation in &invocations {
            assert_eq!(invocation.abi_version, 1);
            assert_eq!(
                invocation.struct_size as usize,
                std::mem::size_of::<ExHermesExactIngressAttribution>()
            );
            assert_eq!(invocation.context_kind, 1);
            assert_ne!(invocation.runtime_nonce, 0);
            assert_eq!(
                invocation.principal_status, 1,
                "frame attribution authenticates the calling principal"
            );
            // §I3: exactly one app pin => ATTRIBUTED with that root id.
            assert_eq!(invocation.root_status, 1);
            assert_eq!(invocation.root_id.as_deref(), Some("home"));
        }
    }

    // LLP 0053 §I3: multiple pins for the installed context deliver AMBIGUOUS
    // in v1 — never a widened rule, never a defaulted root.
    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_exact_carrier_multi_pin_context_delivers_ambiguous_root() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_exact_carrier_test_host(serde_json::json!({
            "alpha": exact_carrier_test_pin("app"),
            "beta": exact_carrier_test_pin("app"),
            "settings": exact_carrier_test_pin("agentIsolate"),
        }));
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        EXACT_V2_PROBE_INVOCATIONS.lock().unwrap().clear();

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32, 11_u32];
        let manifest_digest =
            std::ffi::CString::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA").unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async_v2(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call_v2,
                        std::ptr::null_mut(),
                    ),
                    0
                );
            })
            .unwrap();
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "globalThis.__exactAmbiguous = 'pending'; \
                     exact.invokeHostAsync(7, new Uint8Array([1,2,3])).then(\
                       function(value) { globalThis.__exactAmbiguous = Array.from(value).join(','); },\
                       function(error) { globalThis.__exactAmbiguous = 'rejected:' + error.message; }); \
                     'kicked'",
                )
                .await,
            "kicked"
        );
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            evaluator
                .eval_string(&engine, "String(globalThis.__exactAmbiguous)")
                .await,
            "9,8"
        );
        let invocations = EXACT_V2_PROBE_INVOCATIONS.lock().unwrap().clone();
        assert_eq!(invocations.len(), 1);
        assert_eq!(
            invocations[0].root_status, 3,
            "multiple app pins => AMBIGUOUS"
        );
        assert_eq!(invocations[0].root_id, None);
    }

    // LLP 0053 §I1 fail-closed matrix: a /1 snapshot refuses the v2 setter
    // and keeps its shipped v1 behavior, including the exactly-2 arity.
    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_exact_v1_snapshot_refuses_carrier_capable_ingress() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_exact_test_host();
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32, 11_u32];
        let manifest_digest =
            std::ffi::CString::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA").unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async_v2(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call_v2,
                        std::ptr::null_mut(),
                    ),
                    -8,
                    "a carrier-bearing ingress may not install against a snapshot that does not pin what issuance is bound to"
                );
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 1);
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
                assert_eq!(
                    ex_hermes_set_exact_host_call_async_v2(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call_v2,
                        std::ptr::null_mut(),
                    ),
                    -5,
                    "v2 after v1 must refuse the replacement"
                );
            })
            .unwrap();
        // Under v1 install the shipped exactly-2 behavior is unchanged: a
        // third argument is an arity error, never a silently dropped carrier.
        assert_eq!(
            evaluator
                .eval_string(
                    &engine,
                    "try { exact.invokeHostAsync(7, new Uint8Array([1]), new Uint8Array(32)); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await,
            "exact.invokeHostAsync requires an operation ID and bytes"
        );
    }

    // LLP 0053 §I1 fail-closed matrix: a generically armed runtime (no Exact
    // binding at all) refuses both setter flavors.
    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn generic_armed_runtime_refuses_both_exact_ingress_flavors() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32];
        let manifest_digest =
            std::ffi::CString::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA").unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -8
                );
                assert_eq!(
                    ex_hermes_set_exact_host_call_async_v2(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call_v2,
                        std::ptr::null_mut(),
                    ),
                    -8
                );
                assert_root_global_paths_absent(raw, &["exact.invokeHostAsync"], 1);
            })
            .unwrap();
    }

    // Unarmed diagnostic runtimes accept the v2 flavor; attribution is still
    // delivered with root UNAVAILABLE, the latch stays one-shot, the carrier
    // grammar is enforced, and the sealed property survives finalization.
    #[tokio::test(flavor = "current_thread")]
    async fn diagnostic_exact_v2_ingress_delivers_attribution_and_validates_carrier() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        EXACT_V2_PROBE_INVOCATIONS.lock().unwrap().clear();

        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32, 11_u32];
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async_v2(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call_v2,
                        std::ptr::null_mut(),
                    ),
                    0
                );
                // v1 after v2: the one-shot tagged latch refuses (-5).
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -5
                );
            })
            .unwrap();

        // The sealed property is immutable after legacy auto-finalization.
        assert_eq!(
            engine
                .eval_immediate(
                    "(function () { \
                       var d = Object.getOwnPropertyDescriptor(exact, 'invokeHostAsync'); \
                       return typeof exact.invokeHostAsync + '/' + d.writable + '/' + d.configurable; \
                     })()",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("function/false/false")
        );

        // 2 args => ABSENT; 3 args (32 bytes) => PRESENT.
        engine
            .eval_immediate(
                "globalThis.__exactV2 = 'pending'; \
                 exact.invokeHostAsync(7, new Uint8Array([1,2,3])).then(\
                   function(value) { globalThis.__exactV2 = Array.from(value).join(','); });",
            )
            .await
            .unwrap();
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("globalThis.__exactV2")
                .await
                .unwrap()
                .as_deref(),
            Some("9,8")
        );
        engine
            .eval_immediate(
                "globalThis.__exactV2 = 'pending'; \
                 exact.invokeHostAsync(11, new Uint8Array([4,5]), new Uint8Array(32).fill(3)).then(\
                   function(value) { globalThis.__exactV2 = Array.from(value).join(','); });",
            )
            .await
            .unwrap();
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("globalThis.__exactV2")
                .await
                .unwrap()
                .as_deref(),
            Some("9,8")
        );

        // Carrier grammar: 0 bytes, 65 bytes, and non-buffer values refuse.
        assert_eq!(
            engine
                .eval_immediate(
                    "try { exact.invokeHostAsync(7, new Uint8Array([1]), new Uint8Array(0)); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync carrier must be 1..=64 bytes")
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "try { exact.invokeHostAsync(7, new Uint8Array([1]), new Uint8Array(65)); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync carrier must be 1..=64 bytes")
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "try { exact.invokeHostAsync(7, new Uint8Array([1]), {}); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync carrier must be an ArrayBuffer or view")
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "try { exact.invokeHostAsync(7, new Uint8Array([1]), 42); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync carrier must be an ArrayBuffer or view")
        );

        let invocations = EXACT_V2_PROBE_INVOCATIONS.lock().unwrap().clone();
        assert_eq!(
            invocations.len(),
            2,
            "refused carriers never reach the host"
        );
        assert_eq!(invocations[0].carrier_status, 2);
        assert_eq!(invocations[0].carrier, None);
        assert_eq!(invocations[1].carrier_status, 1);
        assert_eq!(invocations[1].carrier.as_deref(), Some(&[3_u8; 32][..]));
        for invocation in &invocations {
            assert_eq!(invocation.abi_version, 1);
            assert_eq!(invocation.context_kind, 1);
            assert_ne!(invocation.runtime_nonce, 0);
            assert_eq!(
                invocation.root_status, 2,
                "unarmed diagnostic delivers root UNAVAILABLE"
            );
            assert_eq!(invocation.root_id, None);
        }
    }

    // Rollback on the tagged latch: a failed v2 package finalization removes
    // the provisional capability, resets the latch to None, and a later v1
    // installation succeeds cleanly.
    #[tokio::test(flavor = "current_thread")]
    async fn exact_v2_ingress_rolls_back_tagged_latch_when_finalization_fails() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let _compartments = TestEnvVar::set("IBEX_COMPARTMENTS", "1");

        let engine = HermesEngine::new().unwrap();
        assert!(engine.runtime_bundle_installed().await.unwrap());
        engine
            .eval_immediate("delete globalThis.__ibexRefreshCompartmentBaseline")
            .await
            .unwrap();

        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32];
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async_v2(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call_v2,
                        std::ptr::null_mut(),
                    ),
                    -6
                );
            })
            .unwrap();
        assert_eq!(
            engine
                .eval_immediate(
                    "typeof exact.invokeHostAsync + '/' + \
                     __ibexCompartmentBaselineFinalized",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("undefined/false")
        );

        // The rollback reset the tagged latch: restoring the baseline hook
        // lets the OTHER flavor install afterwards.
        engine
            .eval_immediate(
                "globalThis.__ibexRefreshCompartmentBaseline = function () { \
                   globalThis.__ibexCompartmentBaselineFinalized = true; \
                   delete globalThis.__ibexRefreshCompartmentBaseline; \
                 };",
            )
            .await
            .unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    0,
                    "a rolled-back latch must be installable again"
                );
            })
            .unwrap();
        assert_eq!(
            engine
                .eval_immediate("typeof exact.invokeHostAsync")
                .await
                .unwrap()
                .as_deref(),
            Some("function")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn diagnostic_host_call_abi_allows_replacement_and_async_resolution() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        ABI_PROBE_SYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        ABI_PROBE_ASYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                ex_hermes_set_host_call(raw, abi_probe_sync_host_call);
                ex_hermes_set_host_call_async(raw, abi_probe_async_host_call);
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate("JSON.stringify(__hostCall('abi.sync', {value: 1}))")
                .await
                .unwrap()
                .as_deref(),
            Some(r#"{"bridge":"sync"}"#)
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "globalThis.__abiAsync = 'pending'; \
                     __hostCallAsync('abi.async', {}).then(\
                       function(value) { globalThis.__abiAsync = value.bridge; },\
                       function() { globalThis.__abiAsync = 'rejected'; }); \
                     'kicked'",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("kicked")
        );
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("globalThis.__abiAsync")
                .await
                .unwrap()
                .as_deref(),
            Some("async")
        );
        assert_eq!(
            ABI_PROBE_SYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            ABI_PROBE_ASYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn capsec_conformance_adapter_is_direct_and_not_a_public_bridge_route() {
        let _lock = hermes_engine_test_lock().lock().await;
        let floor = serde_json::json!({
            "cap": "sys:read",
            "resource": {"kind": "system-info", "name": "platform"}
        });
        let (_reset, _digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let decision = serde_json::json!({
            "decisionSetSchema": "ibex/capsec-decision-set/1",
            "operationId": "conformance-sys-read",
            "atomicityGroup": "surface.native.op.exactarch.0djy1vp.decision",
            "combination": "conjunction",
            "context": {
                "stage": "delivery",
                "actor": {"kind": "root", "identity": "project-root"},
                "constrainedPrincipals": [
                    {"kind": "root", "identity": "project-root"}
                ],
                "presentedHandleIds": []
            },
            "effects": [{
                "cap": "sys:read",
                "effectOwner": {"kind": "root", "identity": "project-root"},
                "resource": {
                    "kind": "system-info-occurrence",
                    "requested": {"kind": "system-info", "name": "platform"}
                }
            }]
        });
        let gates = serde_json::json!([{
            "coverageEdgeId": "surface.native.op.exactarch.0djy1vp",
            "targetCell": "complete",
            "definitionAndEdgePredicatesSatisfied": true
        }]);
        let request = serde_json::json!({
            "terminalBranchId": "enforcement.test.exactarch",
            "decisionSetJson": serde_json::to_string(&decision).unwrap(),
            "gatesJson": serde_json::to_string(&gates).unwrap()
        });
        let result: serde_json::Value = serde_json::from_str(
            &evaluate_capsec_conformance_adapter(&serde_json::to_string(&request).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(result["adapter"]["decision"]["outcome"], "allow");
        assert_eq!(result["typedObservations"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["typedObservations"][0]["terminalBranchId"],
            "enforcement.test.exactarch"
        );
        assert_eq!(
            result["typedObservations"][0]["decisionSet"]["effects"][0]["cap"],
            "sys:read"
        );
        assert_eq!(result["legacyObservations"], serde_json::json!([]));

        let operation = CString::new("capsec.conformance.evaluate").unwrap();
        let request = CString::new(serde_json::to_string(&request).unwrap()).unwrap();
        let generic_result = unsafe {
            CString::from_raw(exact_agent_host_call(operation.as_ptr(), request.as_ptr()))
        };
        assert!(
            generic_result
                .to_string_lossy()
                .contains("Unknown host call"),
            "the diagnostic adapter must not be reachable through the generic bridge"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn public_os_reads_reach_their_exact_typed_native_gates() {
        let _lock = hermes_engine_test_lock().lock().await;
        let floors = [
            "architecture",
            "cpus",
            "hostname",
            "load-average",
            "memory",
            "network-interfaces",
            "os-release",
            "platform",
            "storage-paths",
            "uptime",
            "user",
            "cwd",
        ]
        .into_iter()
        .map(|name| {
            if name == "cwd" {
                serde_json::json!({
                    "cap": "path:cwd-observe",
                    "resource": {"kind": "session-state", "name": "cwd"}
                })
            } else {
                serde_json::json!({
                    "cap": "sys:read",
                    "resource": {"kind": "system-info", "name": name}
                })
            }
        })
        .collect();
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, floors, None, |snapshot| {
                snapshot["principals"][0]["imports"]["builtins"] =
                    serde_json::json!(["node:os", "node:process"]);
            });
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
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
                b"var os = require('node:os'); var publicProcess = require('node:process'); JSON.stringify([\
                   os.platform(), os.arch(), os.type(), os.release(),\
                   os.homedir(), os.tmpdir(), os.hostname(), os.cpus().length,\
                   os.totalmem(), os.freemem(), os.uptime(), os.endianness(),\
                   Object.keys(os.networkInterfaces()).length, os.loadavg().length,\
                   os.version(), os.machine(), os.availableParallelism(),\
                   typeof os.userInfo().username, publicProcess.memoryUsage().rss,
                   publicProcess.cwd(), process.cwd()])"
                    .to_vec(),
            )
            .into_request()
            .unwrap();
        assert!(
            ibex_runtime::host::abi::begin_installed_conformance_observation(
                "public.node-os.native-readers"
            )
        );
        let evaluation = engine
            .evaluate_authenticated(&session, request)
            .await
            .unwrap();
        let AuthenticatedEvaluation::Value { receipt, .. } = evaluation else {
            panic!("public os calls must return normally: {evaluation:?}")
        };
        engine
            .release_undisplayed_value(receipt.expect("public os result must retain a receipt"))
            .await
            .unwrap();
        let (legacy, observed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "rev2 paths must not consult the legacy plane"
        );
        assert_eq!(
            observed.len(),
            42,
            "twenty-one reads must authorize two stages each"
        );

        let expected = [
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "platform",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "architecture",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "platform",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "os-release",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "storage-paths",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "storage-paths",
            ),
            ("surface.native.op.exactgethostname.01gi6am", "hostname"),
            ("surface.native.op.exactgetcpucount.1k05aty", "cpus"),
            ("surface.native.op.exactgettotalmem.0ziuv9c", "memory"),
            ("surface.native.op.exactgetfreemem.0dytp7m", "memory"),
            ("surface.native.op.exactgetuptime.0ydqt27", "uptime"),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "architecture",
            ),
            (
                "surface.native.op.exactgetnetworkinterfaces.15q8n2j",
                "network-interfaces",
            ),
            ("surface.native.op.exactgetloadavg.10t3k2t", "load-average"),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "os-release",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "architecture",
            ),
            ("surface.native.op.exactgetcpucount.1k05aty", "cpus"),
            ("surface.native.op.exactgetuserinfo.027b1gs", "user"),
            ("surface.native.op.exactgetprocessrss.0o50wgs", "memory"),
            ("surface.native.op.exactgetcwd.1bhagb7", "cwd"),
            ("surface.native.op.exactgetcwd.1bhagb7", "cwd"),
        ];
        for (index, (edge, name)) in expected.into_iter().enumerate() {
            let requested = &observed[index * 2];
            let committed = &observed[index * 2 + 1];
            assert_eq!(
                requested.terminal_branch_id,
                "public.node-os.native-readers"
            );
            assert_eq!(
                requested.decision_set.context.stage,
                capsec_semantics::model::Stage::Requested
            );
            assert_eq!(
                committed.decision_set.context.stage,
                capsec_semantics::model::Stage::Commit
            );
            for decision in [requested, committed] {
                assert_eq!(decision.gates.len(), 1);
                assert_eq!(decision.gates[0].coverage_edge_id.as_str(), edge);
                let resource =
                    serde_json::to_value(&decision.decision_set.effects[0].resource).unwrap();
                if name == "cwd" {
                    assert_eq!(
                        decision.decision_set.effects[0].action.as_str(),
                        "path:cwd-observe"
                    );
                    assert_eq!(resource["kind"], "session-state-occurrence");
                    assert_eq!(resource["requested"]["kind"], "session-state");
                    assert_eq!(resource["requested"]["name"], "cwd");
                } else {
                    assert_eq!(decision.decision_set.effects[0].action.as_str(), "sys:read");
                    assert_eq!(resource["requested"]["name"], name);
                }
                assert_eq!(
                    decision.evidence.outcome,
                    capsec_semantics::decision::DecisionOutcome::Allow
                );
            }
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn public_os_read_denial_stops_before_commit_and_data_access() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, vec![], None, |snapshot| {
                snapshot["principals"][0]["imports"]["builtins"] =
                    serde_json::json!(["node:os", "node:process"]);
                snapshot["principals"][0]["denials"] = serde_json::json!([
                    {
                        "cap": "sys:read",
                        "resource": {"kind": "system-info", "name": "cpus"}
                    },
                    {
                        "cap": "sys:read",
                        "resource": {"kind": "system-info", "name": "memory"}
                    },
                    {
                        "cap": "path:cwd-observe",
                        "resource": {"kind": "session-state", "name": "cwd"}
                    }
                ]);
            });
        let root = host
            .typed_principal_for_module("0")
            .expect("armed root principal");
        let direct_cwd_denial = host
            .authorize_typed_cwd_observe_stage(
                "0",
                vec![root],
                capsec_semantics::model::Stage::Requested,
            )
            .expect("evaluate direct cwd denial");
        assert_eq!(
            direct_cwd_denial.outcome,
            capsec_semantics::decision::DecisionOutcome::Deny,
            "the authored cwd denial must precede ambient root: {direct_cwd_denial:?}"
        );
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        assert!(
            ibex_runtime::host::abi::begin_installed_conformance_observation(
                "public.node-os.cpus.denied"
            )
        );
        let value = evaluator
            .eval_string(
                &engine,
                r#"(function() {
                    var os = require('node:os');
                    var publicProcess = require('node:process');
                    var calls = [
                      function() { return os.cpus(); },
                      function() { return publicProcess.memoryUsage().rss; },
                      function() { return publicProcess.cwd(); },
                      function() { return process.cwd(); }
                    ];
                    var errors = [];
                    for (var i = 0; i < calls.length; i++) {
                      try { calls[i](); errors.push(null); }
                      catch (error) {
                        errors.push(String(error && error.message || error));
                      }
                    }
                    return JSON.stringify(errors);
                })()"#,
            )
            .await;
        let errors: Vec<Option<String>> = serde_json::from_str(&value).unwrap();
        assert_eq!(errors.len(), 4);
        assert!(errors[0]
            .as_deref()
            .is_some_and(|message| message.contains("Permission denied")));
        assert!(errors[1]
            .as_deref()
            .is_some_and(|message| message.contains("Permission denied")));
        assert!(
            errors[2]
                .as_deref()
                .is_some_and(|message| message.contains("EACCES: cwd: filesystem policy denied")),
            "unexpected public cwd denial result: {errors:?}"
        );
        assert!(
            errors[3]
                .as_deref()
                .is_some_and(|message| message.contains("EACCES: cwd: filesystem policy denied")),
            "unexpected global cwd denial result: {errors:?}"
        );
        let (legacy, observed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert_eq!(
            observed.len(),
            4,
            "each denial must stop before Commit and read"
        );
        assert!(observed.iter().all(|decision| {
            decision.decision_set.context.stage == capsec_semantics::model::Stage::Requested
                && decision.evidence.outcome == capsec_semantics::decision::DecisionOutcome::Deny
        }));
        assert_eq!(
            observed
                .iter()
                .map(|decision| decision.decision_set.effects[0].action.as_str())
                .collect::<Vec<_>>(),
            vec![
                "sys:read",
                "sys:read",
                "path:cwd-observe",
                "path:cwd-observe"
            ]
        );
        assert_eq!(
            observed
                .iter()
                .map(|decision| decision.gates[0].coverage_edge_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "surface.native.op.exactgetcpucount.1k05aty",
                "surface.native.op.exactgetprocessrss.0o50wgs",
                "surface.native.op.exactgetcwd.1bhagb7",
                "surface.native.op.exactgetcwd.1bhagb7",
            ]
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn concurrent_equal_digest_runtimes_claim_their_exact_installed_host() {
        let _lock = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let first_path = root.join("first-context.txt");
        let second_path = root.join("second-context.txt");
        fs::write(&first_path, b"first").unwrap();
        fs::write(&second_path, b"second").unwrap();
        let (first, first_digest) =
            build_armed_test_host_at(Some(&root), false, false, false, vec![]);
        let (second, second_digest) =
            build_armed_test_host_at(Some(&root), false, false, false, vec![]);
        assert_eq!(first_digest, second_digest, "snapshots intentionally match");
        let first_observer = first.clone();
        let second_observer = second.clone();

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let spawn = |host: crate::host::Host,
                     digest: String,
                     virtual_path: &'static str,
                     barrier: Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                assert_ne!(crate::host::abi::install_host(host), 0);
                // Both equal-digest Hosts are published before either runtime
                // claims one. Digest-based newest-match selection can now swap
                // them; the pending token must bind this thread's exact Host.
                barrier.wait();
                let runtime = SharedRuntime::new(Some(&digest)).expect("armed runtime");
                let source = format!(
                    "if (typeof __exactEnsureFs === 'function') __exactEnsureFs(); \
                     try {{ __exactReadFile({path:?}); 'ALLOWED' }} \
                     catch (_) {{ 'denied' }}",
                    path = virtual_path,
                );
                let value = runtime
                    .with_runtime(|raw| unsafe {
                        let source_url = CString::new("host-context-binding-test.js").unwrap();
                        let mut output = std::ptr::null_mut();
                        let status = ex_hermes_eval(
                            raw,
                            source.as_ptr(),
                            source.len(),
                            source_url.as_ptr(),
                            0,
                            &mut output,
                        );
                        let value = if output.is_null() {
                            String::new()
                        } else {
                            let value = CStr::from_ptr(output).to_string_lossy().into_owned();
                            ex_hermes_free_string(output);
                            value
                        };
                        (status, value)
                    })
                    .unwrap();
                assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
                value
            })
        };

        let first_thread = spawn(
            first,
            first_digest.clone(),
            "/project/first-context.txt",
            Arc::clone(&barrier),
        );
        let second_thread = spawn(
            second,
            second_digest,
            "/project/second-context.txt",
            barrier,
        );
        assert_eq!(first_thread.join().unwrap(), (0, "denied".into()));
        assert_eq!(second_thread.join().unwrap(), (0, "denied".into()));

        let first_evidence = serde_json::to_string(&first_observer.typed_evidence()).unwrap();
        let second_evidence = serde_json::to_string(&second_observer.typed_evidence()).unwrap();
        assert!(
            first_evidence.contains("first-context.txt")
                && !first_evidence.contains("second-context.txt"),
            "first runtime decisions must stay on its exact Host: {first_evidence}"
        );
        assert!(
            second_evidence.contains("second-context.txt")
                && !second_evidence.contains("first-context.txt"),
            "second runtime decisions must stay on its exact Host: {second_evidence}"
        );
        crate::host::abi::install_host(crate::host::Host::strict());
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_reauthenticates_exact_package_source_after_creation() {
        use std::os::unix::fs::MetadataExt;

        let _lock = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let package_root = root.join("node_modules/pkg");
        fs::create_dir_all(&package_root).unwrap();
        fs::write(
            package_root.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0","main":"index.js"}"#,
        )
        .unwrap();
        let source = package_root.join("index.js");
        fs::write(&source, "module.exports = 'authenticated';\n").unwrap();
        let integrity = crate::module_loader::package_tree_integrity(&package_root).unwrap();
        let metadata = fs::metadata(&package_root).unwrap();
        let package_components = package_root
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(value) => Some(serde_json::json!({
                    "encoding": "utf8",
                    "value": value.to_str().unwrap(),
                })),
                _ => None,
            })
            .collect::<Vec<_>>();
        let principal = serde_json::json!({
            "kind": "package",
            "name": "pkg",
            "integrity": integrity,
            "locator": "pkg@1.0.0",
        });
        let principal_for_snapshot = principal.clone();
        let (host, digest) = build_armed_test_host_custom(
            Some(&root),
            false,
            false,
            false,
            vec![],
            None,
            move |value| {
                value["principals"][0]["imports"]["packages"] = serde_json::json!(["pkg@1.0.0"]);
                value["principals"][1]["principal"] = principal_for_snapshot.clone();
                value["packageGraph"]["nodes"][0]["principal"] = principal_for_snapshot.clone();
                value["packageGraph"]["importEdges"][0]["imported"] =
                    principal_for_snapshot.clone();
                value["rootBindings"][0] = serde_json::json!({
                    "logicalRoot": "package",
                    "owner": principal_for_snapshot,
                    "hostPath": {
                        "root": "absolute",
                        "components": package_components,
                        "hostBound": true,
                    },
                    "object": {
                        "platform": if cfg!(any(target_os = "macos", target_os = "ios", target_os = "tvos")) {
                            "apple"
                        } else {
                            "unix"
                        },
                        "volume": format!("dev:{}", metadata.dev()),
                        "file": format!("ino:{}", metadata.ino()),
                    },
                });
            },
        );
        assert_ne!(crate::host::abi::install_host(host), 0);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        // The Host and Hermes runtime are already armed. Replacing source now
        // must invalidate the package principal before any replacement bytes
        // reach compilation/evaluation.
        fs::write(
            &source,
            "globalThis.__packageMutationExecuted = true; module.exports = 'mutated';\n",
        )
        .unwrap();
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  try { require('pkg'); return 'ALLOWED'; }
                  catch (_) { return String(globalThis.__packageMutationExecuted === true); }
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("false"));
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_process_environment_and_signal_surfaces_stay_closed() {
        let _lock = hermes_engine_test_lock().lock().await;
        let original_cwd = std::env::current_dir().unwrap();
        let target = std::env::temp_dir();
        let marker = target.join(format!("ibex-armed-spawn-marker-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let script = format!(
            r#"(function() {{
                var denied = 0;
                if (Object.keys(__exactGetAllEnv()).length === 0) denied++;
                try {{ __exactSetCwd({target:?}); }} catch (_) {{ denied++; }}
                try {{ process.kill(process.pid, 0); }} catch (_) {{ denied++; }}
                try {{ __exactExecSync('touch ' + {marker:?}, '{{}}'); }} catch (_) {{ denied++; }}
                try {{ __exactSpawnSync('/usr/bin/touch', JSON.stringify([{marker:?}]), '{{}}'); }} catch (_) {{ denied++; }}
                try {{ __exactSpawn('/usr/bin/touch', JSON.stringify([{marker:?}]), '{{}}'); }} catch (_) {{ denied++; }}
                return String(denied);
            }})()"#,
            target = target.to_str().unwrap(),
            marker = marker.to_str().unwrap(),
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("6"));
        assert_eq!(std::env::current_dir().unwrap(), original_cwd);
        assert!(!marker.exists());
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_environment_enumeration_closes_without_any_authorization_oracle() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

        let typed_before = crate::host::abi::installed_typed_decision_count();
        let legacy_before = crate::host::abi::installed_legacy_authorization_check_count();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.test.environment-enumeration-closed"
        ));
        let outcome = evaluator
            .eval_string(&engine, "String(Object.keys(process.env).length)")
            .await;
        assert_eq!(outcome, "0");
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert!(typed.is_empty());
        assert_eq!(
            crate::host::abi::installed_typed_decision_count() - typed_before,
            0
        );
        assert_eq!(
            crate::host::abi::installed_legacy_authorization_check_count() - legacy_before,
            0
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_authority_bridge_rejects_forged_principals_and_unknown_ids() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) = build_armed_test_host_at(None, false, false, false, vec![]);
        let root = host
            .typed_principal_for_module("0")
            .expect("armed fixture must authenticate its root principal");
        let forged = serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": "image-lib@2.4.1"
        });
        let handle_request = serde_json::json!({
            "actor": forged,
            "holder": forged,
            "authority": {
                "cap": "fs:read",
                "resource": {
                    "kind": "path-tree",
                    "path": {
                        "root": "project",
                        "components": [{"encoding": "utf8", "value": "images"}]
                    }
                }
            }
        });
        assert!(host
            .mint_typed_handle_json_for_actor(
                root.clone(),
                vec![root.clone()],
                &serde_json::to_vec(&handle_request).unwrap(),
            )
            .is_err());
        let unknown_handle = serde_json::to_vec("h-forged-not-issued").unwrap();
        let unknown_handle_error = host
            .revoke_typed_handle_json_for_actor(&root, &unknown_handle)
            .unwrap_err();
        assert!(
            unknown_handle_error
                .to_string()
                .contains("only the authenticated handle owner or holder may revoke it"),
            "unexpected unknown-handle rejection: {unknown_handle_error}"
        );

        let grant_request = serde_json::json!({
            "grantId": "forged-package-grant",
            "principal": forged,
            "authority": {
                "cap": "device:location",
                "resource": {
                    "kind": "device-location",
                    "usage": "foreground",
                    "precision": "coarse"
                }
            }
        });
        assert!(host
            .grant_typed_dynamic_json_for_principal(
                root.clone(),
                &serde_json::to_vec(&grant_request).unwrap(),
            )
            .is_err());
        let unknown_grant = serde_json::to_vec("forged-grant-not-issued").unwrap();
        let unknown_grant_error = host
            .revoke_typed_dynamic_json_for_principal(&root, &unknown_grant)
            .unwrap_err();
        assert!(
            unknown_grant_error
                .to_string()
                .contains("only the grant principal may revoke a dynamic grant"),
            "unexpected unknown-grant rejection: {unknown_grant_error}"
        );

        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
        let outcome = evaluator
            .eval_string(
                &engine,
                "String(typeof Ibex.authority + '/' + typeof Ibex.permissions)",
            )
            .await;
        assert_eq!(outcome, "undefined/undefined");
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_tcp_connect_commits_and_rechecks_the_actual_peer() {
        use std::io::Read;
        use std::net::TcpListener;

        let _lock = hermes_engine_test_lock().lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut chunk = [0u8; 3];
                stream.read_exact(&mut chunk).unwrap();
                bytes.extend(chunk);
            }
            bytes
        });
        let floor = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "tcp",
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let (_reset, digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let before = crate::host::abi::installed_typed_decision_count();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                var socket = __exactTcpConnect('127.0.0.1', {port});
                if (__exactTcpWrite(socket, 'x') !== 1) throw new Error('write');
                if (__exactTcpWrite(socket, 'x') !== 1) throw new Error('write');
                if (__exactTcpWrite(socket, 'x') !== 1) throw new Error('write');
                __exactTcpClose(socket);
                var pending = __exactTcpConnectStart('127.0.0.1', {port});
                var pendingDenied = false;
                try {{ __exactTcpWrite(pending, 'z'); }} catch (_) {{ pendingDenied = true; }}
                if (!pendingDenied) throw new Error('pending socket gained write authority');
                var connected = false;
                for (var attempt = 0; attempt < 10000; attempt++) {{
                  if (__exactTcpConnectPoll(pending) === 1) {{ connected = true; break; }}
                }}
                if (!connected) throw new Error('pending connect did not complete');
                if (__exactTcpWrite(pending, 'y') !== 1) throw new Error('pending write');
                if (__exactTcpWrite(pending, 'y') !== 1) throw new Error('pending write');
                if (__exactTcpWrite(pending, 'y') !== 1) throw new Error('pending write');
                __exactTcpClose(pending);
                var metadataDenied = false;
                try {{ __exactTcpConnect('169.254.169.254', 80); }} catch (_) {{ metadataDenied = true; }}
                if (!metadataDenied) throw new Error('metadata peer was reachable');
                var mappedDenied = false;
                try {{ __exactTcpConnect('::ffff:127.0.0.1', {port}); }}
                catch (error) {{
                  mappedDenied = String(error && error.message || error).indexOf('not canonical') !== -1;
                }}
                if (!mappedDenied) throw new Error('mapped TCP literal was not rejected canonically');
                return 'ok';
            }})()"#
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("ok"));
        assert_eq!(server.join().unwrap(), b"xxxyyy");
        let decisions = crate::host::abi::installed_typed_decision_count() - before;
        assert!(
            (8..=10).contains(&decisions),
            "unexpected full network decision count: {decisions}"
        );
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_tcp_connect_commits_and_rechecks_the_actual_peer() {
        use capsec_semantics::model::Stage;
        use std::io::Read;
        use std::net::TcpListener;

        let _lock = hermes_engine_test_lock().lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0u8; 3];
            stream.read_exact(&mut bytes).unwrap();
            bytes
        });
        let floor = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "tcp",
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let (_reset, digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(
            crate::host::abi::begin_installed_conformance_observation(
                "surface.native.op.exacttcpconnect.1cs9rhu"
            ),
            "armed Windows TCP must have an installed Host observer"
        );
        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                var socket = __exactTcpConnect('127.0.0.1', {port});
                if (__exactTcpWrite(socket, 'x') !== 1) throw new Error('write');
                if (__exactTcpWrite(socket, 'x') !== 1) throw new Error('write');
                if (__exactTcpWrite(socket, 'x') !== 1) throw new Error('write');
                __exactTcpClose(socket);
                return 'ok';
            }})()"#
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("ok"));
        assert_eq!(server.join().unwrap(), *b"xxx");

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed Windows TCP crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![
                Stage::Requested,
                Stage::Candidate,
                Stage::Commit,
                Stage::Repeat,
                Stage::Repeat,
                Stage::Repeat,
            ]
        );
        assert!(typed.iter().all(|row| {
            row.decision_set.effects[0].action.as_str() == "network:connect"
                && row.gates.iter().all(|gate| {
                    gate.coverage_edge_id.as_str() == "surface.native.op.exacttcpconnect.1cs9rhu"
                })
        }));
        let committed = serde_json::to_value(&typed[2].decision_set.effects[0].resource).unwrap();
        assert_eq!(committed["selectedCandidate"], "127.0.0.1");
        assert_eq!(committed["verifiedPeer"]["address"], "127.0.0.1");
        assert_eq!(committed["verifiedPeer"]["port"], port);
        assert!(committed["connectionId"]
            .as_str()
            .is_some_and(|id| id.starts_with("tcp:")));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn dual_stack_listener_reports_ipv4_peer_in_canonical_form() {
        use std::net::TcpStream;

        let _lock = hermes_engine_test_lock().lock().await;
        // networkEndpointCapability("network:listen", "::", 0)
        let _reset = install_test_host_with_allow(&["network:listen::::0"]);
        let engine = HermesEngine::new().unwrap();
        let setup = engine
            .eval_immediate(
                r#"(function() {
                    if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                    try {
                      var listener = __exactTcpListen('::', 0, 1, 0, 0);
                      var local = JSON.parse(__exactTcpLocalAddr(listener));
                      globalThis.__dualStackListener = listener;
                      return JSON.stringify({port: local.port, family: local.family});
                    } catch (error) {
                      return JSON.stringify({error: String(error && error.message || error)});
                    }
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        let setup: serde_json::Value = serde_json::from_str(&setup).unwrap();
        if let Some(error) = setup.get("error").and_then(serde_json::Value::as_str) {
            let unsupported = [
                "Address family not supported",
                "Protocol not available",
                "Cannot assign requested address",
                "ai_family not supported",
            ]
            .iter()
            .any(|marker| error.contains(marker));
            assert!(
                unsupported,
                "dual-stack listener failed for a reason other than platform support: {error}"
            );
            return;
        }
        assert_eq!(setup["family"], "IPv6");
        let port = setup["port"].as_u64().unwrap() as u16;
        let client = TcpStream::connect(("127.0.0.1", port))
            .expect("IPv4 must connect to the explicitly dual-stack IPv6 listener");
        let remote = engine
            .eval_immediate(
                r#"(function() {
                    var accepted = -1;
                    for (var attempt = 0; attempt < 10000 && accepted < 0; attempt++) {
                      accepted = __exactTcpAccept(globalThis.__dualStackListener);
                    }
                    if (accepted < 0) throw new Error('dual-stack connection was not accepted');
                    var remote = JSON.parse(__exactTcpRemoteAddr(accepted));
                    __exactTcpClose(accepted);
                    __exactTcpClose(globalThis.__dualStackListener);
                    delete globalThis.__dualStackListener;
                    return JSON.stringify(remote);
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        drop(client);
        let remote: serde_json::Value = serde_json::from_str(&remote).unwrap();
        assert_eq!(remote["address"], "127.0.0.1");
        assert_eq!(remote["family"], "IPv4");
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_udp_send_authorizes_each_literal_datagram_peer() {
        use std::net::UdpSocket;

        let _lock = hermes_engine_test_lock().lock().await;
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let floor = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "udp",
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let (_reset, digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                var socket = __exactUdpSocket('udp4');
                var bindDenied = false;
                try {{ __exactUdpBind(socket, '127.0.0.1', 0); }} catch (_) {{ bindDenied = true; }}
                if (!bindDenied) throw new Error('send authority yielded UDP listen authority');
                var mappedDenied = false;
                try {{ __exactUdpSend(socket, 'm', {port}, '::ffff:127.0.0.1'); }}
                catch (error) {{
                  mappedDenied = String(error && error.message || error).indexOf('not canonical') !== -1;
                }}
                if (!mappedDenied) throw new Error('mapped UDP literal was not rejected canonically');
                if (__exactUdpSend(socket, 'u', {port}, '127.0.0.1') !== 1) throw new Error('send');
                __exactUdpClose(socket);
                var metadataDenied = false;
                var deniedSocket = __exactUdpSocket('udp4');
                try {{ __exactUdpSend(deniedSocket, 'x', 80, '169.254.169.254'); }} catch (_) {{ metadataDenied = true; }}
                __exactUdpClose(deniedSocket);
                if (!metadataDenied) throw new Error('metadata datagram was allowed');
                return 'ok';
            }})()"#
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("ok"));
        let mut byte = [0u8; 1];
        let (amount, _) = receiver.recv_from(&mut byte).unwrap();
        assert_eq!((amount, byte[0]), (1, b'u'));
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_udp_repeat_lease_is_bounded_and_generation_checked() {
        use std::net::UdpSocket;

        let _lock = hermes_engine_test_lock().lock().await;
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let udp_floor = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "udp",
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let unrelated_dynamic = serde_json::json!({
            "cap": "device:location",
            "resource": {
                "kind": "device-location",
                "usage": "foreground",
                "precision": "coarse"
            }
        });
        let (host, digest) = build_armed_test_host_control(
            None,
            false,
            false,
            false,
            vec![udp_floor],
            vec![unrelated_dynamic.clone()],
            true,
            0,
            None,
            |_| {},
        );
        let control = host.clone();
        let root = control.typed_principal_for_module("0").unwrap();
        let grant_id =
            capsec_semantics::model::NonEmptyString::new("udp-lease-generation").unwrap();
        let selector: capsec_semantics::model::AuthoritySelector =
            serde_json::from_value(unrelated_dynamic).unwrap();
        assert!(control
            .grant_typed_dynamic(grant_id.clone(), root, selector)
            .unwrap());
        assert_ne!(crate::host::abi::install_host(host), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let before = control.typed_decision_count();

        let first = engine
            .eval_immediate(&format!(
                r#"(function() {{
                    if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                    var socket = __exactUdpSocket('udp4');
                    for (var i = 0; i < 16; i++) {{
                      if (__exactUdpSend(socket, 'a', {port}, '127.0.0.1') !== 1) {{
                        throw new Error('first send batch');
                      }}
                    }}
                    globalThis.__udpLeaseSocket = socket;
                    return 'first';
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(first.as_deref(), Some("first"));
        assert_eq!(
            control.typed_decision_count() - before,
            3,
            "sixteen identical datagrams must share one three-stage decision lease"
        );

        assert!(control.revoke_typed_dynamic(&grant_id).unwrap());
        let second = engine
            .eval_immediate(&format!(
                r#"(function() {{
                    for (var i = 0; i < 16; i++) {{
                      if (__exactUdpSend(globalThis.__udpLeaseSocket, 'b', {port}, '127.0.0.1') !== 1) {{
                        throw new Error('second send batch');
                      }}
                    }}
                    __exactUdpClose(globalThis.__udpLeaseSocket);
                    delete globalThis.__udpLeaseSocket;
                    return 'second';
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(second.as_deref(), Some("second"));
        assert_eq!(
            control.typed_decision_count() - before,
            6,
            "revocation generation change must force exactly one lease renewal"
        );

        let mut received = [0u8; 32];
        for expected in received.iter_mut().take(16) {
            let mut byte = [0u8; 1];
            let (amount, _) = receiver.recv_from(&mut byte).unwrap();
            assert_eq!(amount, 1);
            *expected = byte[0];
        }
        for expected in received.iter_mut().skip(16) {
            let mut byte = [0u8; 1];
            let (amount, _) = receiver.recv_from(&mut byte).unwrap();
            assert_eq!(amount, 1);
            *expected = byte[0];
        }
        assert_eq!(&received[..16], &[b'a'; 16]);
        assert_eq!(&received[16..], &[b'b'; 16]);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_unported_network_surfaces_refuse_synchronously_and_unix_listen_leaves_no_path() {
        let _lock = hermes_engine_test_lock().lock().await;
        let fetch_listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind no-I/O fetch observer");
        let fetch_port = fetch_listener.local_addr().unwrap().port();
        let fetch_floor = serde_json::json!({
            "cap": "network:fetch",
            "resource": {
                "kind": "fetch-endpoint",
                "schemes": ["http"],
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": fetch_port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let (host, digest) = build_armed_test_host_custom(
            None,
            false,
            false,
            false,
            vec![fetch_floor],
            None,
            |snapshot| {
                snapshot["principals"][0]["denials"] = serde_json::json!([{
                    "cap": "network:listen",
                    "resource": {
                        "kind": "listen-inet",
                        "transport": "tcp",
                        "bind": {"kind": "loopback"},
                        "port": {"kind": "ephemeral"},
                        "dualStack": false,
                        "peerClasses": ["loopback"]
                    }
                }]);
            },
        );
        assert_ne!(crate::host::abi::install_host(host), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        // These private native entry points are probed before the one-shot
        // seal; authenticated project code reaches only their public wrappers.
        // This regression proves synchronous refusal for every listed bridge
        // and the directly observable no-bind postcondition for Unix listen.
        // It deliberately does not claim that constructing and closing the UDP
        // handle below is itself a zero-allocation operation.
        let socket_path = std::env::temp_dir().join(format!(
            "ibex-capsec-closed-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                var denied = {{}};
                function refuses(name, call) {{
                  try {{ call(); denied[name] = false; }} catch (_) {{ denied[name] = true; }}
                }}
                try {{
                  __nativeFetch('http://127.0.0.1:{fetch_port}/', {{}});
                  denied.fetch = false;
                }} catch (error) {{
                  denied.fetch = String(error && error.message || error).indexOf(
                    'typed network:fetch transport is unavailable'
                  ) !== -1;
                }}
                refuses('dns', function() {{ __exactDnsLookup('localhost', 4); }});
                refuses('websocket', function() {{ __exactWsConnect('ws://127.0.0.1:9/', '', {{}}); }});
                var nulUrlRejected = false;
                try {{ __exactWsConnect('ws://127.0.0.1:9/\u0000suffix', '', {{}}); }}
                catch (error) {{
                  nulUrlRejected = String(error && error.message || error).indexOf('ASCII control') !== -1;
                }}
                if (!nulUrlRejected) throw new Error('NUL-bearing WebSocket URL was not rejected');
                refuses('tcpListen', function() {{ __exactTcpListen('127.0.0.1', 0, 1, 0, 0); }});
                refuses('httpServe', function() {{ __exactHttpServe(0, '127.0.0.1'); }});
                refuses('unixConnect', function() {{ __exactUnixConnect({socket_path:?}); }});
                refuses('unixListen', function() {{ __exactUnixListen({socket_path:?}, 1); }});
                var udp = __exactUdpSocket('udp4');
                refuses('udpBind', function() {{ __exactUdpBind(udp, '127.0.0.1', 0); }});
                __exactUdpClose(udp);
                return JSON.stringify(denied);
            }})()"#,
            socket_path = socket_path.to_str().unwrap(),
            fetch_port = fetch_port,
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        let outcome: serde_json::Value = serde_json::from_str(outcome.as_deref().unwrap()).unwrap();
        assert_eq!(
            outcome,
            serde_json::json!({
                "fetch": true,
                "dns": true,
                "websocket": true,
                "tcpListen": true,
                "httpServe": true,
                "unixConnect": true,
                "unixListen": true,
                "udpBind": true,
            })
        );
        assert!(!socket_path.exists());
        fetch_listener.set_nonblocking(true).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(25));
        match fetch_listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("closed typed fetch reached the loopback listener"),
            Err(error) => panic!("failed to observe closed typed fetch: {error}"),
        }
        engine.load_runtime().await.unwrap();
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_fs_open_authorizes_create_truncate_and_repeated_write() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-open-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let existing = root.join("existing.txt");
        let created = root.join("created.txt");
        let async_created = root.join("async-created.txt");
        let async_whole = root.join("async-whole.txt");
        let whole_created = root.join("whole-created.txt");
        let directory_created = root.join("created-directory");
        let async_directory_created = root.join("async-created-directory");
        std::fs::write(&existing, b"old contents").unwrap();
        let link = root.join("existing-link");
        std::os::unix::fs::symlink(&existing, &link).unwrap();
        let virtual_root = "/project";
        let virtual_existing = "/project/existing.txt";
        let virtual_created = "/project/created.txt";
        let virtual_async_created = "/project/async-created.txt";
        let virtual_async_whole = "/project/async-whole.txt";
        let virtual_whole_created = "/project/whole-created.txt";
        let virtual_directory_created = "/project/created-directory";
        let virtual_async_directory_created = "/project/async-created-directory";
        let virtual_link = "/project/existing-link";
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                var existing = __exactFsOpen({existing:?}, 'w');
                __exactFsWrite(existing, 'new', -1);
                __exactFsClose(existing);
                var created = __exactFsOpen({created:?}, 'w+');
                __exactFsWrite(created, 'made', -1);
                JSON.parse(__exactFsFstatSync(created));
                __exactFsFtruncateSync(created, 2);
                __exactFsFsyncSync(created);
                __exactFsClose(created);
                var reread = __exactReadFile({existing:?});
                if (String.fromCharCode.apply(null, reread) !== 'new') throw new Error('readFile');
                if (!JSON.parse(__exactStat({existing:?})).is_file) throw new Error('stat');
                if (!JSON.parse(__exactLstat({link:?})).is_symlink) throw new Error('lstat');
                if (__exactRealpath({link:?}) !== {existing:?}) throw new Error('realpath-logical');
                if (JSON.parse(__exactReaddir({root:?})).indexOf('existing.txt') < 0) throw new Error('readdir');
                __exactWriteFile({existing:?}, 'whole');
                __exactAppendFile({existing:?}, '+tail');
                __exactWriteFile({whole_created:?}, 'fresh');
                __exactMkdir({directory_created:?}, false);
                return 'ok';
            }})()"#,
            existing = virtual_existing,
            created = virtual_created,
            root = virtual_root,
            link = virtual_link,
            whole_created = virtual_whole_created,
            directory_created = virtual_directory_created,
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();

        assert_eq!(outcome.as_deref(), Some("ok"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"whole+tail");
        assert_eq!(std::fs::read(&created).unwrap(), b"ma");
        assert_eq!(std::fs::read(&whole_created).unwrap(), b"fresh");
        assert!(directory_created.is_dir());

        let async_mkdir_script = format!(
            r#"globalThis.__armedAsyncMkdir = 'pending';
               __exactFsPathAsync('mkdir', {path:?}, '', 0, 0, 0).then(function() {{
                 globalThis.__armedAsyncMkdir = 'ok';
               }}, function(error) {{
                 globalThis.__armedAsyncMkdir = 'error:' + error.message;
               }});"#,
            path = virtual_async_directory_created,
        );
        engine.eval_immediate(&async_mkdir_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_mkdir = engine
            .eval_immediate("globalThis.__armedAsyncMkdir")
            .await
            .unwrap();
        assert_eq!(async_mkdir.as_deref(), Some("ok"));
        assert!(async_directory_created.is_dir());

        let async_realpath_script = format!(
            r#"globalThis.__armedAsyncRealpath = 'pending';
               __exactFsPathAsync('realpath', {link:?}, '', 0, 0, 0).then(function(path) {{
                 globalThis.__armedAsyncRealpath = path;
               }}, function(error) {{
                 globalThis.__armedAsyncRealpath = 'error:' + error.message;
               }});"#,
            link = virtual_link,
        );
        engine.eval_immediate(&async_realpath_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_realpath = engine
            .eval_immediate("globalThis.__armedAsyncRealpath")
            .await
            .unwrap();
        assert_eq!(async_realpath.as_deref(), Some(virtual_existing));

        let async_script = format!(
            r#"globalThis.__armedAsyncOpen = 'pending';
               __exactFsOpenAsync({path:?}, 'w+').then(function(fd) {{
                 __exactFsWrite(fd, 'async', -1);
                 return __exactFsFdAsync('fsync', fd, 0, 0).then(function() {{
                   return __exactFsStatAsync(fd, 'fstat');
                 }}).then(function() {{
                   __exactFsClose(fd);
                   globalThis.__armedAsyncOpen = 'ok';
                 }});
               }}, function(error) {{
                 globalThis.__armedAsyncOpen = 'error:' + error.message;
               }});"#,
            path = virtual_async_created,
        );
        engine.eval_immediate(&async_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_outcome = engine
            .eval_immediate("globalThis.__armedAsyncOpen")
            .await
            .unwrap();
        assert_eq!(async_outcome.as_deref(), Some("ok"));
        assert_eq!(std::fs::read(&async_created).unwrap(), b"async");
        let async_read_script = format!(
            r#"globalThis.__armedAsyncRead = 'pending';
               __exactFsReadFileAsync({path:?}, 'r', 0).then(function(bytes) {{
                 globalThis.__armedAsyncRead = String.fromCharCode.apply(null, bytes);
               }}, function(error) {{
                 globalThis.__armedAsyncRead = 'error:' + error.message;
               }});"#,
            path = virtual_existing,
        );
        engine.eval_immediate(&async_read_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_read = engine
            .eval_immediate("globalThis.__armedAsyncRead")
            .await
            .unwrap();
        assert_eq!(async_read.as_deref(), Some("whole+tail"));
        let async_stat_script = format!(
            r#"globalThis.__armedAsyncStat = 'pending';
               __exactFsStatAsync({path:?}, 'stat').then(function(json) {{
                 globalThis.__armedAsyncStat = String(JSON.parse(json).is_file);
               }}, function(error) {{
                 globalThis.__armedAsyncStat = 'error:' + error.message;
               }});"#,
            path = virtual_existing,
        );
        engine.eval_immediate(&async_stat_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_stat = engine
            .eval_immediate("globalThis.__armedAsyncStat")
            .await
            .unwrap();
        assert_eq!(async_stat.as_deref(), Some("true"));
        let async_lstat_script = format!(
            r#"globalThis.__armedAsyncLstat = 'pending';
               __exactFsStatAsync({path:?}, 'lstat').then(function(json) {{
                 globalThis.__armedAsyncLstat = String(JSON.parse(json).is_symlink);
               }}, function(error) {{
                 globalThis.__armedAsyncLstat = 'error:' + error.message;
               }});"#,
            path = virtual_link,
        );
        engine.eval_immediate(&async_lstat_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_lstat = engine
            .eval_immediate("globalThis.__armedAsyncLstat")
            .await
            .unwrap();
        assert_eq!(async_lstat.as_deref(), Some("true"));
        let async_write_script = format!(
            r#"globalThis.__armedAsyncWrite = 'pending';
               __exactFsWriteFileAsync({path:?}, 'worker', 'w', 438, true).then(function() {{
                 globalThis.__armedAsyncWrite = 'ok';
               }}, function(error) {{
                 globalThis.__armedAsyncWrite = 'error:' + error.message;
               }});"#,
            path = virtual_async_whole,
        );
        engine.eval_immediate(&async_write_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_write = engine
            .eval_immediate("globalThis.__armedAsyncWrite")
            .await
            .unwrap();
        assert_eq!(async_write.as_deref(), Some("ok"));
        assert_eq!(std::fs::read(&async_whole).unwrap(), b"worker");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_large_reads_use_generation_checked_descriptor_leases() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-large-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let large = root.join("large.bin");
        std::fs::write(&large, vec![0x5a; 4 * 1024 * 1024]).unwrap();
        let virtual_large = "/project/large.bin";
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let before = crate::host::abi::installed_typed_decision_count();
        for expected in ["first", "second"] {
            let script = format!(
                r#"(function() {{
                    if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                    var bytes = __exactReadFile({path:?});
                    if (bytes.length !== 4194304 || bytes[0] !== 90 || bytes[4194303] !== 90) {{
                      throw new Error('large read mismatch');
                    }}
                    return {expected:?};
                }})()"#,
                path = virtual_large,
            );
            let outcome = engine.eval_immediate(&script).await.unwrap();
            assert_eq!(outcome.as_deref(), Some(expected));
        }
        let decisions = crate::host::abi::installed_typed_decision_count() - before;
        // Each descriptor performs six full decisions: requested-path and
        // authenticated-root binding, retained child traversal, content
        // commit, and the first repeat. The remaining chunks recheck only the
        // three authority generations, and the lease does not survive into
        // the second descriptor operation.
        assert_eq!(
            decisions, 12,
            "two 4 MiB reads performed an unexpected number of full decisions"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_read_uses_typed_retained_object_stages() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::write(root.join("payload.txt"), b"retained-windows-bytes").unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(
            crate::host::abi::begin_installed_conformance_observation(
                "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactreadfile.1phia4e"
            ),
            "armed Windows read must have an installed Host observer"
        );
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  var bytes = __exactReadFile('/project/payload.txt', null);
                  return String.fromCharCode.apply(null, bytes);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("retained-windows-bytes"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed Windows read crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![
                Stage::Requested,
                Stage::Discovery,
                Stage::Commit,
                Stage::Repeat
            ]
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.effects[0].action.as_str())
                .collect::<Vec<_>>(),
            vec!["fs:list", "fs:list", "fs:read", "fs:read"]
        );
        assert!(typed.iter().all(|row| {
            row.gates.iter().all(|gate| {
                gate.coverage_edge_id.as_str() == "surface.native.op.exactreadfile.1cmzco7"
            })
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_read_denies_before_lookup_without_legacy_fallback() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-read-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let target = root.join("payload.txt");
        std::fs::write(&target, b"must-remain-unread").unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, false, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactreadfile.1phia4e"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  try { __exactReadFile('/project/payload.txt', null); }
                  catch (error) { return String(error.code); }
                  return 'unexpected-success';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("EACCES"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "denied armed Windows read consulted the legacy capability oracle"
        );
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(typed[0].decision_set.effects[0].action.as_str(), "fs:list");
        assert_eq!(std::fs::read(&target).unwrap(), b"must-remain-unread");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_async_readfile_path_uses_worker_typed_stages() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-async-read-path-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("payload.txt"), b"worker-retained-bytes").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactreadfile.async"
        ));
        engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__windowsAsyncTypedRead = 'pending';
                  __exactFsReadFileAsync('/project/payload.txt', 'r', 0, null).then(
                    function(bytes) {
                      globalThis.__windowsAsyncTypedRead =
                        String.fromCharCode.apply(null, bytes);
                    },
                    function(error) {
                      globalThis.__windowsAsyncTypedRead = 'error:' + String(error.code);
                    });
                  return 'queued';
                })()"#,
            )
            .await
            .unwrap();
        engine.drive_event_loop().await.unwrap();
        let outcome = engine
            .eval_immediate("globalThis.__windowsAsyncTypedRead")
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("worker-retained-bytes"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed Windows async readFile crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![
                Stage::Requested,
                Stage::Discovery,
                Stage::Commit,
                Stage::Repeat
            ]
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.effects[0].action.as_str())
                .collect::<Vec<_>>(),
            vec!["fs:list", "fs:list", "fs:read", "fs:read"]
        );
        assert!(typed.iter().all(|row| row.gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsreadfileasync.0fw3fo0"
        })));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_async_readfile_descriptor_repeats_each_chunk() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-async-read-fd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut payload = vec![0x41; 70 * 1024];
        payload[70 * 1024 - 1] = 0x5a;
        std::fs::write(root.join("payload.bin"), &payload).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__windowsAsyncReadFd =
                    __exactFsOpen('/project/payload.bin', 'r', 438, null);
                  return 'opened';
                })()"#,
            )
            .await
            .unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactreadfile.async.fd"
        ));
        engine
            .eval_immediate(
                r#"(function() {
                  globalThis.__windowsAsyncTypedFdRead = 'pending';
                  __exactFsReadFileAsync(
                    globalThis.__windowsAsyncReadFd, 'r', 0, null).then(
                    function(bytes) {
                      globalThis.__windowsAsyncTypedFdRead =
                        String(bytes.length) + ':' + String(bytes[0]) + ':' +
                        String(bytes[bytes.length - 1]);
                      __exactFsClose(globalThis.__windowsAsyncReadFd);
                    },
                    function(error) {
                      globalThis.__windowsAsyncTypedFdRead =
                        'error:' + String(error.code);
                    });
                  return 'queued';
                })()"#,
            )
            .await
            .unwrap();
        engine.drive_event_loop().await.unwrap();
        let outcome = engine
            .eval_immediate("globalThis.__windowsAsyncTypedFdRead")
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("71680:65:90"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed Windows descriptor readFile crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![Stage::Repeat, Stage::Repeat, Stage::Repeat]
        );
        assert!(typed
            .iter()
            .all(|row| row.decision_set.effects[0].action.as_str() == "fs:read"));
        assert!(typed.iter().all(|row| row.gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsreadfileasync.0fw3fo0"
        })));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_async_readfile_denies_on_worker_before_lookup() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-async-read-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("payload.txt");
        std::fs::write(&target, b"must-remain-unread").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, false, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactreadfile.async.denied"
        ));
        engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__windowsAsyncDeniedRead = 'pending';
                  __exactFsReadFileAsync('/project/payload.txt', 'r', 0, null).then(
                    function() {
                      globalThis.__windowsAsyncDeniedRead = 'unexpected-success';
                    },
                    function(error) {
                      globalThis.__windowsAsyncDeniedRead = String(error.code);
                    });
                  return 'queued';
                })()"#,
            )
            .await
            .unwrap();
        engine.drive_event_loop().await.unwrap();
        let outcome = engine
            .eval_immediate("globalThis.__windowsAsyncDeniedRead")
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("EACCES"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "denied armed Windows async readFile consulted the legacy capability oracle"
        );
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(typed[0].decision_set.effects[0].action.as_str(), "fs:list");
        assert_eq!(std::fs::read(&target).unwrap(), b"must-remain-unread");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_stat_uses_retained_metadata_for_file_and_root() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-stat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::write(root.join("payload.txt"), b"retained-stat-bytes").unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactstat.1o9sgdx"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  var stat = JSON.parse(__exactStat('/project/payload.txt', null));
                  return String(stat.size) + ':' + String(stat.is_file);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("19:true"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed Windows stat crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![Stage::Requested, Stage::Discovery, Stage::Repeat]
        );
        assert!(typed
            .iter()
            .all(|row| row.decision_set.effects[0].action.as_str() == "fs:list"));
        assert!(typed.iter().all(|row| {
            row.gates
                .iter()
                .all(|gate| gate.coverage_edge_id.as_str() == "surface.native.op.exactstat.1432ztv")
        }));

        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactstat.root"
        ));
        let root_outcome = engine
            .eval_immediate(
                r#"(function() {
                  var stat = JSON.parse(__exactStat('/project', null));
                  return String(stat.is_dir) + ':' + String(stat.is_file);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(root_outcome.as_deref(), Some("true:false"));
        let (root_legacy, root_typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(root_legacy.is_empty());
        assert_eq!(
            root_typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![Stage::Requested, Stage::Discovery, Stage::Repeat]
        );
        assert!(root_typed[1..].iter().all(|row| matches!(
            &row.decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                parent_object: None,
                final_object: Some(_),
                ..
            }
        )));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_stat_denies_before_lookup_without_legacy_fallback() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-stat-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let target = root.join("payload.txt");
        std::fs::write(&target, b"metadata-must-remain-hidden").unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, false, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactstat.1o9sgdx"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  try { __exactStat('/project/payload.txt', null); }
                  catch (error) { return String(error.code); }
                  return 'unexpected-success';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("EACCES"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "denied armed Windows stat consulted the legacy capability oracle"
        );
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(typed[0].decision_set.effects[0].action.as_str(), "fs:list");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"metadata-must-remain-hidden"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_lstat_retains_the_final_reparse_object() {
        use capsec_semantics::model::{FollowMode, Stage};
        use std::os::windows::fs::symlink_file;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-lstat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::write(root.join("target.txt"), b"retained-lstat-target").unwrap();
        symlink_file("target.txt", root.join("alias.txt")).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactlstat.retained"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  var stat = JSON.parse(__exactLstat('/project/alias.txt', null));
                  return String(stat.is_symlink) + ':' + String(stat.is_file);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("true:false"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed Windows lstat crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![Stage::Requested, Stage::Discovery, Stage::Repeat]
        );
        assert!(typed.iter().all(|row| matches!(
            &row.decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                follow_mode: FollowMode::NoFollowFinal,
                ..
            }
        )));
        assert!(typed.iter().all(|row| {
            row.gates.iter().all(|gate| {
                gate.coverage_edge_id.as_str() == "surface.native.op.exactlstat.1c98s6l"
            })
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_lstat_denies_before_lookup_without_legacy_fallback() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-lstat-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let target = root.join("target.txt");
        std::fs::write(&target, b"lstat-metadata-must-remain-hidden").unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, false, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactlstat.denied"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  try { __exactLstat('/project/target.txt', null); }
                  catch (error) { return String(error.code); }
                  return 'unexpected-success';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("EACCES"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "denied armed Windows lstat consulted the legacy capability oracle"
        );
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(typed[0].decision_set.effects[0].action.as_str(), "fs:list");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"lstat-metadata-must-remain-hidden"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_readdir_repeats_the_retained_directory_per_member() {
        use capsec_semantics::model::{FollowMode, Stage};

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-readdir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let listing = root.join("listing");
        std::fs::create_dir_all(&listing).unwrap();
        std::fs::write(listing.join("z-last.txt"), b"z").unwrap();
        std::fs::write(listing.join("a-first.txt"), b"a").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactreaddir.retained"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  return JSON.parse(__exactReaddir('/project/listing', null)).join(',');
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("a-first.txt,z-last.txt"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed Windows readdir crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![
                Stage::Requested,
                Stage::Discovery,
                Stage::Repeat,
                Stage::Repeat,
            ]
        );
        assert!(typed
            .iter()
            .all(|row| row.decision_set.effects[0].action.as_str() == "fs:list"));
        assert!(typed.iter().all(|row| matches!(
            &row.decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                follow_mode: FollowMode::FollowFinal,
                ..
            }
        )));
        assert!(typed.iter().all(|row| {
            row.gates.iter().all(|gate| {
                gate.coverage_edge_id.as_str() == "surface.native.op.exactreaddir.0tg30vk"
            })
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_readdir_denies_before_lookup_without_legacy_fallback() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-readdir-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let listing = root.join("listing");
        std::fs::create_dir_all(&listing).unwrap();
        let target = listing.join("secret.txt");
        std::fs::write(&target, b"directory-member-must-remain-hidden").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, false, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.cc.exactreaddir.denied"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  try { __exactReaddir('/project/listing', null); }
                  catch (error) { return String(error.code); }
                  return 'unexpected-success';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("EACCES"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "denied armed Windows readdir consulted the legacy capability oracle"
        );
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(typed[0].decision_set.effects[0].action.as_str(), "fs:list");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"directory-member-must-remain-hidden"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_descriptor_reads_and_fstat_share_the_retained_object() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-open-fstat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("descriptor.txt"), b"retained-descriptor").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.exactfsopen.read.fstat.retained"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  var fd = __exactFsOpen('/project/descriptor.txt', 'r', 438, null);
                  try {
                    var positioned = String.fromCharCode.apply(
                      null, __exactFsRead(fd, 10, 9));
                    var vector = [new Uint8Array(3), new Uint8Array(5)];
                    var vectorRead = __exactFsReadv(fd, vector, 0);
                    var vectorBytes = String.fromCharCode.apply(null, vector[0]) +
                      String.fromCharCode.apply(null, vector[1]);
                    var sequential = String.fromCharCode.apply(
                      null, __exactFsRead(fd, 8, -1));
                    var stat = JSON.parse(__exactFsFstatSync(fd));
                    return positioned + ':' + String(vectorRead) + ':' +
                      vectorBytes + ':' + sequential + ':' + String(stat.size) +
                      ':' + String(stat.is_file);
                  } finally {
                    __exactFsClose(fd);
                  }
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(
            outcome.as_deref(),
            Some("descriptor:8:retained:retained:19:true")
        );

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed Windows descriptor open/fstat crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![
                Stage::Requested,
                Stage::Discovery,
                Stage::Commit,
                Stage::Repeat,
                Stage::Repeat,
                Stage::Repeat,
                Stage::Repeat,
            ]
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.effects[0].action.as_str())
                .collect::<Vec<_>>(),
            vec!["fs:list", "fs:list", "fs:read", "fs:read", "fs:read", "fs:read", "fs:list",]
        );
        assert!(typed[..3].iter().all(|row| row.gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsopen.05ao6wa"
        })));
        assert!(typed[3].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsread.1ixlwve"
        }));
        assert!(typed[4].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsreadv.11moytw"
        }));
        assert!(typed[5].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsread.1ixlwve"
        }));
        assert!(typed[6].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsfstatsync.1md7g19"
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_async_descriptor_reads_authorize_on_worker_and_publish_owned_bytes() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-typed-async-descriptor-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("descriptor.txt"), b"retained-descriptor").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__asyncDescriptorReadFd =
                    __exactFsOpen('/project/descriptor.txt', 'r', 438, null);
                  return 'opened';
                })()"#,
            )
            .await
            .unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.async.descriptor.worker"
        ));
        engine
            .eval_immediate(
                r#"(function() {
                  globalThis.__asyncDescriptorReadResult = 'pending';
                  var fd = globalThis.__asyncDescriptorReadFd;
                  __exactFsReadAsync(fd, 10, 9).then(function(positioned) {
                    return __exactFsReadvAsync(
                      fd, [new Uint8Array(3), new Uint8Array(5)], 0
                    ).then(function(vector) {
                      return __exactFsReadAsync(fd, 8, -1).then(
                        function(sequential) {
                          globalThis.__asyncDescriptorReadResult =
                            String.fromCharCode.apply(null, positioned) + ':' +
                            String.fromCharCode.apply(null, vector) + ':' +
                            String.fromCharCode.apply(null, sequential);
                          __exactFsClose(fd);
                        });
                    });
                  }, function(error) {
                    globalThis.__asyncDescriptorReadResult =
                      'error:' + String(error.code);
                  });
                  return 'queued';
                })()"#,
            )
            .await
            .unwrap();
        engine.drive_event_loop().await.unwrap();
        let outcome = engine
            .eval_immediate("globalThis.__asyncDescriptorReadResult")
            .await
            .unwrap();
        assert_eq!(
            outcome.as_deref(),
            Some("descriptor:retained:retained"),
            "positioned reads must not advance the retained descriptor cursor"
        );

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed async descriptor reads crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![Stage::Repeat, Stage::Repeat, Stage::Repeat]
        );
        assert!(typed
            .iter()
            .all(|row| row.decision_set.effects[0].action.as_str() == "fs:read"));
        assert!(typed[0].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsreadasync.0l952a6"
        }));
        assert!(typed[1].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsreadvasync.0bn4x60"
        }));
        assert!(typed[2].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsreadasync.0l952a6"
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_existing_append_uses_retained_write_repeat() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-append-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("append.txt");
        std::fs::write(&target, b"prefix").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.exactfswrite.append.retained"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  var fd = __exactFsOpen('/project/append.txt', 'a', 438, null);
                  try {
                    return String(__exactFsWrite(fd, '-suffix', 0));
                  } finally {
                    __exactFsClose(fd);
                  }
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("7"));
        assert_eq!(std::fs::read(&target).unwrap(), b"prefix-suffix");

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "armed Windows append crossed the legacy capability oracle"
        );
        assert_eq!(
            typed
                .iter()
                .map(|row| (
                    row.decision_set.context.stage,
                    row.decision_set.effects[0].action.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                (Stage::Requested, "fs:write"),
                (Stage::Requested, "fs:list"),
                (Stage::Discovery, "fs:list"),
                (Stage::Commit, "fs:write"),
                (Stage::Repeat, "fs:write"),
            ]
        );
        assert!(typed[..4].iter().all(|row| row.gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsopen.05ao6wa"
        })));
        assert!(typed[4].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfswrite.1locgj1"
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_append_denial_precedes_lookup_and_preserves_bytes() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-append-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("append.txt");
        std::fs::write(&target, b"must-remain-unchanged").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.exactfsopen.append.denied"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  try { __exactFsOpen('/project/append.txt', 'a', 438, null); }
                  catch (error) { return String(error.code); }
                  return 'unexpected-success';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("EACCES"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(typed[0].decision_set.effects[0].action.as_str(), "fs:write");
        assert_eq!(std::fs::read(&target).unwrap(), b"must-remain-unchanged");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_read_open_denies_before_lookup() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-typed-open-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("secret.txt");
        std::fs::write(&target, b"descriptor-secret").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, false, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.exactfsopen.denied"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  try { __exactFsOpen('/project/secret.txt', 'r', 438, null); }
                  catch (error) { return String(error.code); }
                  return 'unexpected-success';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("EACCES"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(typed[0].decision_set.effects[0].action.as_str(), "fs:list");
        assert_eq!(std::fs::read(&target).unwrap(), b"descriptor-secret");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_public_unpromoted_flags_and_append_create_fail_closed() {
        use capsec_semantics::model::Stage;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-write-open-closed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.exactfsopen.write.closed"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  var results = [];
                  try { __exactFsOpen('/project/must-not-exist.txt', 'w', 438, null); }
                  catch (error) { results.push(String(error.code)); }
                  try { __exactFsOpen('/project/unknown-numeric.txt', 2048, 438, null); }
                  catch (error) { results.push(String(error.code)); }
                  try { __exactFsOpen('/project/append-must-not-exist.txt', 'a', 438, null); }
                  catch (error) { results.push(String(error.code)); }
                  return results.join(':');
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("EPERM:EPERM:ENOENT"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert_eq!(
            typed
                .iter()
                .map(|row| (
                    row.decision_set.context.stage,
                    row.decision_set.effects[0].action.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                (Stage::Requested, "fs:write"),
                (Stage::Requested, "fs:list"),
            ]
        );
        assert!(!root.join("must-not-exist.txt").exists());
        assert!(!root.join("unknown-numeric.txt").exists());
        assert!(!root.join("append-must-not-exist.txt").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(windows, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_windows_residual_fs_routes_fail_closed_before_legacy_effects() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-windows-residual-fs-closed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let existing = root.join("existing.txt");
        let absent = root.join("absent.txt");
        let directory = root.join("directory");
        let created_directory = root.join("created-directory");
        std::fs::write(&existing, b"must-remain-unchanged").unwrap();
        std::fs::create_dir(&directory).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.src.engine.hermes.runtime.fs.windows.residual.closed"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  var denied = 0;
                  function expectClosed(fn) {
                    try { fn(); } catch (error) {
                      if (String(error.code) !== 'EPERM') throw error;
                      denied++;
                      return;
                    }
                    throw new Error('residual Windows filesystem route allowed');
                  }
                  expectClosed(function() { __exactWriteFile('/project/existing.txt', 'lost'); });
                  expectClosed(function() { __exactWriteFile('/project/absent.txt', 'created'); });
                  expectClosed(function() { __exactMkdir('/project/created-directory', false, 438); });
                  expectClosed(function() { __exactRealpath('/project/existing.txt'); });
                  expectClosed(function() { __exactReadlink('/project/existing.txt'); });
                  expectClosed(function() { __exactAccess('/project/existing.txt', 0); });
                  expectClosed(function() { __exactTruncate('/project/existing.txt', 0); });
                  expectClosed(function() { __exactStatfs('/project'); });
                  expectClosed(function() {
                    __exactFsWriteFileAsync('/project/absent.txt', 'created', 'w', 438, true);
                  });
                  expectClosed(function() {
                    __exactFsWriteFileAsync(2147483647, 'created', 'w', 438, true);
                  });
                  expectClosed(function() {
                    __exactFsPathAsync('readdir', '/project/directory', '', 0, 0, 0);
                  });
                  expectClosed(function() {
                    __exactFsPathAsync('truncate', '/project/existing.txt', '', 0, 0, 0);
                  });
                  expectClosed(function() {
                    __exactFsReadFileAsync('/project/existing.txt', 'r', 0, null);
                  });
                  expectClosed(function() {
                    __exactFsStatAsync('/project/existing.txt', 'lstat');
                  });
                  expectClosed(function() { __exactFsStatAsync(2147483647, 'fstat'); });
                  return String(denied);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("15"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "closed Windows filesystem routes crossed the legacy observer: {legacy:?}"
        );
        assert!(
            typed.is_empty(),
            "closed Windows filesystem routes emitted typed decisions: {typed:?}"
        );
        assert_eq!(std::fs::read(&existing).unwrap(), b"must-remain-unchanged");
        assert!(!absent.exists());
        assert!(!created_directory.exists());
        assert!(directory.is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_read_stops_after_dynamic_authority_is_revoked_mid_stream() {
        use std::os::unix::fs::MetadataExt;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-revoked-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let large = root.join("large.bin");
        let file = std::fs::File::create(&large).unwrap();
        file.set_len(128 * 1024 * 1024).unwrap();
        drop(file);
        let package = root.join("node_modules/image-lib");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(
            package.join("index.js"),
            r#"module.exports = function(path) {
                try { require('node:fs').readFileSync(path); return 'completed'; }
                catch (error) { return String(error && error.message || error); }
            };"#,
        )
        .unwrap();
        let entry = root.join("app.js");
        std::fs::write(
            &entry,
            format!(
                "try {{ module.exports = require('image-lib')({:?}); }} \n\
                 catch (error) {{ module.exports = String(error && error.message || error); }}\n",
                "/project/large.bin"
            ),
        )
        .unwrap();
        struct RestoreCwd(std::path::PathBuf);
        impl Drop for RestoreCwd {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.0);
            }
        }
        let cwd = RestoreCwd(std::env::current_dir().unwrap());
        std::env::set_current_dir(&root).unwrap();

        let read_authority = serde_json::json!({
            "cap":"fs:read",
            "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
        });
        let integrity = crate::module_loader::package_tree_integrity(&package).unwrap();
        let principal: capsec_semantics::model::Principal =
            serde_json::from_value(serde_json::json!({
                "kind":"package",
                "name":"image-lib",
                "integrity": integrity,
                "locator":"image-lib@2.4.1"
            }))
            .unwrap();
        let package_components = package
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(value) => Some(serde_json::json!({
                    "encoding": "utf8",
                    "value": value.to_str().unwrap(),
                })),
                _ => None,
            })
            .collect::<Vec<_>>();
        let package_metadata = std::fs::metadata(&package).unwrap();
        let principal_for_snapshot = serde_json::to_value(&principal).unwrap();
        let (host, digest) = build_armed_test_host_control(
            Some(&root),
            false,
            false,
            true,
            Vec::new(),
            vec![read_authority.clone()],
            false,
            1,
            None,
            move |value| {
                value["entry"] = serde_json::json!({
                    "kind": "file",
                    "identity": "file:///project/app.js",
                    "mode": "program",
                });
                value["principals"][1]["principal"] = principal_for_snapshot.clone();
                value["packageGraph"]["nodes"][0]["principal"] = principal_for_snapshot.clone();
                value["packageGraph"]["importEdges"][0]["imported"] =
                    principal_for_snapshot.clone();
                value["rootBindings"][0] = serde_json::json!({
                    "logicalRoot": "package",
                    "owner": principal_for_snapshot,
                    "hostPath": {
                        "root": "absolute",
                        "components": package_components,
                        "hostBound": true,
                    },
                    "object": {
                        "platform": if cfg!(any(target_os = "macos", target_os = "ios", target_os = "tvos")) {
                            "apple"
                        } else {
                            "unix"
                        },
                        "volume": format!("dev:{}", package_metadata.dev()),
                        "file": format!("ino:{}", package_metadata.ino()),
                    },
                });
            },
        );
        assert_ne!(
            crate::host::abi::install_host(host.clone()),
            0,
            "test Host context token allocation"
        );
        let _reset = HostResetGuard;
        let selector: capsec_semantics::model::AuthoritySelector =
            serde_json::from_value(read_authority).unwrap();
        let grant_id = capsec_semantics::model::NonEmptyString::new("stream-read-grant").unwrap();
        assert!(host
            .grant_typed_dynamic(grant_id.clone(), principal.clone(), selector)
            .unwrap());
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let before = host.typed_decision_count();
        let control = host.clone();
        let revoked_id = grant_id.clone();
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let revoker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            // Wait through request/discovery/commit and the first repeat. The
            // read lease then covers chunks only while authority generations
            // remain unchanged, so revocation must stop a later chunk.
            while control.typed_decision_count() < before + 5 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "read never reached its first repeat decision"
                );
                std::thread::yield_now();
            }
            let revoked = control.revoke_typed_dynamic(&revoked_id).unwrap();
            sent.send(revoked).unwrap();
        });
        let vfs = host.virtual_file_system().unwrap();
        let entry = vfs
            .resolve_root_file_url("file:///project/app.js", None)
            .unwrap();
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence =
            ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone()).unwrap();
        let submission = sequence
            .mint_file(entry.logical_referrer().unwrap(), &[])
            .unwrap();
        let request = host
            .authenticated_vfs_file_read(&vfs, entry, submission)
            .unwrap()
            .into_capsule()
            .into_request()
            .unwrap();
        let evaluation = engine
            .evaluate_authenticated(&session, request)
            .await
            .unwrap();
        let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
            panic!("revoked read program did not return normally: {evaluation:?}")
        };
        let outcome: String = serde_json::from_str(&display.text).unwrap();
        engine
            .release_undisplayed_value(receipt.expect("program value must retain a receipt"))
            .await
            .unwrap();
        assert!(
            host.typed_decision_count() >= before + 5,
            "read never reached its first repeat decision; outcome: {outcome}"
        );
        assert!(
            received
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            "dynamic read grant was not revoked"
        );
        revoker.join().unwrap();
        assert!(
            outcome.to_ascii_lowercase().contains("permission denied"),
            "read continued after authority revocation: {outcome}"
        );
        assert!(host.typed_decision_count() >= before + 6);
        vfs.close();
        drop(cwd);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_fs_open_denial_cannot_truncate_or_create() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-open-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let existing = root.join("existing.txt");
        let absent = root.join("absent.txt");
        let absent_directory = root.join("absent-directory");
        let async_absent_directory = root.join("async-absent-directory");
        let retained_directory = root.join("retained-directory");
        let renamed = root.join("renamed.txt");
        let copied = root.join("copied.txt");
        let symlinked = root.join("symlinked.txt");
        let hard_linked = root.join("hard-linked.txt");
        std::fs::write(&existing, b"must survive").unwrap();
        std::fs::create_dir(&retained_directory).unwrap();
        let virtual_existing = "/project/existing.txt";
        let virtual_absent = "/project/absent.txt";
        let virtual_absent_directory = "/project/absent-directory";
        let virtual_async_absent_directory = "/project/async-absent-directory";
        let virtual_retained_directory = "/project/retained-directory";
        let virtual_renamed = "/project/renamed.txt";
        let virtual_copied = "/project/copied.txt";
        let virtual_symlinked = "/project/symlinked.txt";
        let virtual_hard_linked = "/project/hard-linked.txt";
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                var denied = 0;
                try {{ __exactFsOpen({existing:?}, 'w'); }} catch (_) {{ denied++; }}
                try {{ __exactFsOpen({absent:?}, 'w'); }} catch (_) {{ denied++; }}
                try {{ __exactReadFile({existing:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsReadFileAsync({existing:?}, 'r', 0); }} catch (_) {{ denied++; }}
                try {{ __exactWriteFile({existing:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactWriteFile({absent:?}, 'created'); }} catch (_) {{ denied++; }}
                try {{ __exactAppendFile({existing:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactAppendFile({absent:?}, 'created'); }} catch (_) {{ denied++; }}
                try {{ __exactMkdir({absent_directory:?}, false); }} catch (_) {{ denied++; }}
                try {{ __exactUnlink({existing:?}); }} catch (_) {{ denied++; }}
                try {{ __exactRmdir({retained_directory:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('unlink', {existing:?}, '', 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('rmdir', {retained_directory:?}, '', 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactRename({existing:?}, {renamed:?}); }} catch (_) {{ denied++; }}
                try {{ __exactCopyFile({existing:?}, {copied:?}); }} catch (_) {{ denied++; }}
                try {{ __exactSymlink({existing:?}, {symlinked:?}); }} catch (_) {{ denied++; }}
                try {{ __exactLink({existing:?}, {hard_linked:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('rename', {existing:?}, {renamed:?}, 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('copyfile', {existing:?}, {copied:?}, 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('symlink', {existing:?}, {symlinked:?}, 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('link', {existing:?}, {hard_linked:?}, 0, 0, 0); }} catch (_) {{ denied++; }}
                return String(denied);
            }})()"#,
            existing = virtual_existing,
            absent = virtual_absent,
            absent_directory = virtual_absent_directory,
            retained_directory = virtual_retained_directory,
            renamed = virtual_renamed,
            copied = virtual_copied,
            symlinked = virtual_symlinked,
            hard_linked = virtual_hard_linked,
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();

        assert_eq!(outcome.as_deref(), Some("21"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"must survive");
        assert!(!absent.exists());
        assert!(!absent_directory.exists());
        assert!(retained_directory.is_dir());
        assert!(!renamed.exists());
        assert!(!copied.exists());
        assert!(!symlinked.exists());
        assert!(!hard_linked.exists());

        let async_open_script = format!(
            r#"globalThis.__armedDeniedAsyncOpen = 'pending';
               var denied = 0;
               function expectDeniedOpen(path, label) {{
                 try {{
                   return __exactFsOpenAsync(path, 'w').then(function() {{
                     throw new Error(label + ' async open unexpectedly allowed');
                   }}, function() {{ denied++; }});
                 }} catch (_) {{
                   denied++;
                   return Promise.resolve();
                 }}
               }}
               function expectDeniedWrite(path, label) {{
                 try {{
                   return __exactFsWriteFileAsync(path, 'created', 'w', 438, true).then(function() {{
                     throw new Error(label + ' async write unexpectedly allowed');
                   }}, function() {{ denied++; }});
                 }} catch (_) {{
                   denied++;
                   return Promise.resolve();
                 }}
               }}
               Promise.all([
                 expectDeniedOpen({existing:?}, 'existing'),
                 expectDeniedOpen({absent:?}, 'absent'),
                 expectDeniedWrite({absent:?}, 'absent')
               ]).then(function() {{
                 globalThis.__armedDeniedAsyncOpen = String(denied);
               }}, function(error) {{
                 globalThis.__armedDeniedAsyncOpen = 'error:' + error.message;
               }});"#,
            existing = virtual_existing,
            absent = virtual_absent,
        );
        engine.eval_immediate(&async_open_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_open_outcome = engine
            .eval_immediate("globalThis.__armedDeniedAsyncOpen")
            .await
            .unwrap();
        assert_eq!(async_open_outcome.as_deref(), Some("3"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"must survive");
        assert!(!absent.exists());

        let async_script = format!(
            r#"globalThis.__armedDeniedAsyncMkdir = 'pending';
               try {{
                 __exactFsPathAsync('mkdir', {path:?}, '', 0, 0, 0).then(function() {{
                   globalThis.__armedDeniedAsyncMkdir = 'unexpected-allow';
                 }}, function() {{
                   globalThis.__armedDeniedAsyncMkdir = 'denied';
                 }});
               }} catch (_) {{
                 globalThis.__armedDeniedAsyncMkdir = 'denied';
               }}"#,
            path = virtual_async_absent_directory,
        );
        engine.eval_immediate(&async_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_outcome = engine
            .eval_immediate("globalThis.__armedDeniedAsyncMkdir")
            .await
            .unwrap();
        assert_eq!(async_outcome.as_deref(), Some("denied"));
        assert!(!async_absent_directory.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_create_rollback_never_unlinks_a_racing_creator() {
        struct TestEnvironment;
        impl Drop for TestEnvironment {
            fn drop(&mut self) {
                std::env::remove_var("IBEX_TEST_ARMED_CREATE_PAUSE_MS");
                std::env::remove_var("IBEX_TEST_ARMED_DENY_OPEN_COMMIT");
            }
        }

        let _lock = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let target = root.join("raced-create.txt");
        let virtual_target = "/project/raced-create.txt";
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        // Pause after the bridge observes absence, let an independent creator
        // publish the name, then force the post-open commit to deny. A racy
        // precheck implementation marks the competitor's object as "created"
        // and unlinks it during rollback; O_EXCL ownership must not.
        std::env::set_var("IBEX_TEST_ARMED_CREATE_PAUSE_MS", "250");
        std::env::set_var("IBEX_TEST_ARMED_DENY_OPEN_COMMIT", "1");
        let _environment = TestEnvironment;
        let competitor_target = target.clone();
        let competitor = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            fs::write(competitor_target, b"competitor-owned").unwrap();
        });

        let outcome = engine
            .eval_immediate(&format!(
                "if (typeof __exactEnsureFs === 'function') __exactEnsureFs(); \
                 try {{ __exactFsOpen({path:?}, 'w'); 'ALLOWED' }} \
                 catch (_) {{ 'denied' }}",
                path = virtual_target,
            ))
            .await
            .unwrap();
        competitor.join().unwrap();

        assert_eq!(outcome.as_deref(), Some("denied"));
        assert_eq!(fs::read(&target).unwrap(), b"competitor-owned");
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn all_protected_roles_deny_write_unlink_rename_and_replace_before_mutation() {
        use std::os::unix::fs::MetadataExt;

        let _lock = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let roles = ["armed-policy", "engine-binary", "package-graph", "registry"];
        let mut paths = Vec::new();
        let mut protected = Vec::new();
        for role in roles {
            let path = root.join(format!("{role}.artifact"));
            fs::write(&path, format!("original:{role}")).unwrap();
            fs::write(
                root.join(format!("{role}.artifact.replacement")),
                format!("replacement:{role}"),
            )
            .unwrap();
            let metadata = fs::metadata(&path).unwrap();
            protected.push(serde_json::json!({
                "role": role,
                "object": {
                    "platform": if cfg!(any(target_os = "macos", target_os = "ios", target_os = "tvos")) {
                        "apple"
                    } else {
                        "unix"
                    },
                    "volume": format!("dev:{}", metadata.dev()),
                    "file": format!("ino:{}", metadata.ino()),
                },
                "deniedActions": ["fs:write"],
            }));
            paths.push(path);
        }
        let (host, digest) = build_armed_test_host_at_with_protected(
            Some(&root),
            true,
            true,
            true,
            vec![],
            Some(protected),
        );
        assert_ne!(crate::host::abi::install_host(host), 0);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let js_paths = serde_json::to_string(
            &roles
                .iter()
                .map(|role| format!("/project/{role}.artifact"))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let outcome = engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  var paths = {js_paths};
                  var denied = 0;
                  for (var i = 0; i < paths.length; i++) {{
                    var path = paths[i];
                    try {{ __exactWriteFile(path, 'mutated'); }} catch (_) {{ denied++; }}
                    try {{ __exactUnlink(path); }} catch (_) {{ denied++; }}
                    try {{ __exactRename(path, path + '.moved'); }} catch (_) {{ denied++; }}
                    try {{ __exactRename(path + '.replacement', path); }} catch (_) {{ denied++; }}
                  }}
                  return String(denied);
                }})()"#,
            ))
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("16"));
        for (role, path) in roles.into_iter().zip(paths) {
            assert_eq!(
                fs::read(&path).unwrap(),
                format!("original:{role}").as_bytes()
            );
            assert!(!path.with_extension("artifact.moved").exists());
            assert_eq!(
                fs::read(format!("{}.replacement", path.display())).unwrap(),
                format!("replacement:{role}").as_bytes()
            );
        }
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_fs_list_denial_prevents_metadata_and_directory_disclosure() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-list-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let directory = root.join("directory");
        std::fs::create_dir_all(&directory).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let directory = root.join("directory");
        let file = directory.join("secret.txt");
        std::fs::write(&file, b"secret").unwrap();
        let virtual_directory = "/project/directory";
        let virtual_file = "/project/directory/secret.txt";
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, false, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                var denied = 0;
                try {{ __exactStat({file:?}); }} catch (_) {{ denied++; }}
                try {{ __exactReaddir({directory:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsStatAsync({file:?}, 'stat'); }} catch (_) {{ denied++; }}
                try {{ __exactRealpath({file:?}); }} catch (_) {{ denied++; }}
                try {{ __exactLstat({file:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsStatAsync({file:?}, 'lstat'); }} catch (_) {{ denied++; }}
                return String(denied);
            }})()"#,
            file = virtual_file,
            directory = virtual_directory,
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();

        assert_eq!(outcome.as_deref(), Some("6"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_fs_open_rejects_parent_and_final_symlink_escape() {
        use std::os::unix::fs::symlink;

        let _lock = hermes_engine_test_lock().lock().await;
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("ibex-capsec-symlink-root-{nonce}"));
        let outside = std::env::temp_dir().join(format!("ibex-capsec-symlink-outside-{nonce}"));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let outside = std::fs::canonicalize(outside).unwrap();
        let outside_file = outside.join("protected.txt");
        std::fs::write(&outside_file, b"outside").unwrap();
        symlink(&outside, root.join("parent-link")).unwrap();
        symlink(&outside_file, root.join("final-link")).unwrap();
        let parent_escape = "/project/parent-link/protected.txt";
        let final_escape = "/project/final-link";
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                var denied = 0;
                try {{ __exactFsOpen({parent_escape:?}, 'w'); }} catch (_) {{ denied++; }}
                try {{ __exactFsOpen({final_escape:?}, 'w'); }} catch (_) {{ denied++; }}
                try {{ __exactReadFile({parent_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactReadFile({final_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsReadFileAsync({parent_escape:?}, 'r', 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsReadFileAsync({final_escape:?}, 'r', 0); }} catch (_) {{ denied++; }}
                try {{ __exactStat({final_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactReaddir({parent_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactWriteFile({parent_escape:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactWriteFile({final_escape:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactAppendFile({parent_escape:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactAppendFile({final_escape:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactFsStatAsync({parent_escape:?}, 'stat'); }} catch (_) {{ denied++; }}
                try {{ __exactFsStatAsync({final_escape:?}, 'stat'); }} catch (_) {{ denied++; }}
                try {{ __exactRealpath({parent_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactRealpath({final_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactLstat({parent_escape:?}); }} catch (_) {{ denied++; }}
                if (!JSON.parse(__exactLstat({final_escape:?})).is_symlink) throw new Error('lstat-link');
                return String(denied);
            }})()"#,
            parent_escape = parent_escape,
            final_escape = final_escape,
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();

        assert_eq!(outcome.as_deref(), Some("17"));

        let async_write_script = format!(
            r#"globalThis.__armedDeniedSymlinkWrites = 'pending';
               var denied = 0;
               function expectDeniedWrite(path, label) {{
                 try {{
                   return __exactFsWriteFileAsync(path, 'lost', 'w', 438, true).then(function() {{
                     throw new Error(label + ' async write unexpectedly allowed');
                   }}, function() {{ denied++; }});
                 }} catch (_) {{
                   denied++;
                   return Promise.resolve();
                 }}
               }}
               Promise.all([
                 expectDeniedWrite({parent_escape:?}, 'parent escape'),
                 expectDeniedWrite({final_escape:?}, 'final escape')
               ]).then(function() {{
                 globalThis.__armedDeniedSymlinkWrites = String(denied);
               }}, function(error) {{
                 globalThis.__armedDeniedSymlinkWrites = 'error:' + error.message;
               }});"#,
            parent_escape = parent_escape,
            final_escape = final_escape,
        );
        engine.eval_immediate(&async_write_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_write_outcome = engine
            .eval_immediate("globalThis.__armedDeniedSymlinkWrites")
            .await
            .unwrap();
        assert_eq!(async_write_outcome.as_deref(), Some("2"));
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside");
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_installs_typed_dynamic_permission_bridge() {
        let _lock = hermes_engine_test_lock().lock().await;
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let result = engine
            .eval_immediate(
                "JSON.stringify([typeof Ibex.permissions.requestTyped, typeof Ibex.permissions.revokeTyped, typeof Ibex.authority.mintHandle, typeof Ibex.authority.revokeHandle])",
            )
            .await
            .unwrap();
        assert_eq!(
            result.as_deref(),
            Some("[\"function\",\"function\",\"function\",\"function\"]")
        );

        let malformed = engine
            .eval_immediate(
                "try { Ibex.permissions.requestTyped('fs:read:/tmp'); 'missed' } catch (e) { e.name }",
            )
            .await
            .unwrap();
        assert_eq!(malformed.as_deref(), Some("TypeError"));

        let malformed_handle = engine
            .eval_immediate(
                "try { Ibex.authority.mintHandle('fs:read:/tmp'); 'missed' } catch (e) { e.name }",
            )
            .await
            .unwrap();
        assert_eq!(malformed_handle.as_deref(), Some("TypeError"));
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn retained_sqlite_statements_reuse_generation_checked_authorization() {
        let _lock = hermes_engine_test_lock().lock().await;
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("retained.sqlite");
        let database = database.to_str().unwrap();
        let fs_read = format!("fs:read:{database}");
        let fs_write = format!("fs:write:{database}");
        let _reset = install_test_host_with_allow(&["sqlite:write", &fs_read, &fs_write]);
        let engine = HermesEngine::new().unwrap();
        let before = crate::host::abi::installed_legacy_authorization_check_count();
        let script = format!(
            r#"(function() {{
                    if (typeof __exactEnsureSqlite === 'function') __exactEnsureSqlite();
                    var db = __exactSqliteOpen({database:?}, null);
                    __exactSqliteExec(db, 'CREATE TABLE t (n INTEGER)', null);
                    var prepared = __exactSqlitePrepare(db, 'INSERT INTO t VALUES (?)');
                    for (var i = 0; i < 256; i++) {{
                      __exactSqliteRun(prepared.handle, [i]);
                    }}
                    __exactSqliteFinalize(prepared.handle);
                    var query = __exactSqlitePrepare(db, 'SELECT count(*) AS n FROM t');
                    var result = __exactSqliteGet(query.handle, null);
                    __exactSqliteFinalize(query.handle);
                    __exactSqliteClose(db);
                    return String(result.row.n);
                }})()"#
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("256"));
        let checks = crate::host::abi::installed_legacy_authorization_check_count() - before;
        assert!(
            (1..=3).contains(&checks),
            "259 retained SQLite operations performed {checks} full capability decisions"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn load_runtime_finalizes_preinstalled_compartment_baseline() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _lockdown_disabled = TestEnvVar::remove("IBEX_LOCKDOWN");
        let _compartments_disabled = TestEnvVar::remove("IBEX_COMPARTMENTS");
        let compartments_enabled = TestEnvVar::set("IBEX_COMPARTMENTS", "1");
        let engine = HermesEngine::new().unwrap();

        // HermesEngine::new is lazy; keep the flag set through the first native
        // runtime touch so C++ installs the compartment handshake.
        assert!(engine.runtime_bundle_installed().await.unwrap());
        // Mode selection belongs to native runtime creation. Removing the env
        // flag afterwards must not make Rust skip the already-installed hook.
        let pending = engine
            .eval_immediate(
                r#"JSON.stringify([
                  globalThis.__ibexCompartmentRegistryReady === true,
                  typeof globalThis.__ibexRefreshCompartmentBaseline,
                  typeof globalThis.__compartments,
                  globalThis.__ibexCompartmentBaselineFinalized
                ])"#,
            )
            .await
            .unwrap();
        assert_eq!(
            pending.as_deref(),
            Some(r#"[true,"function","object",false]"#)
        );
        drop(compartments_enabled);

        engine.load_runtime().await.unwrap();
        // Exercise the actual finalizer again, as Runtime::load_runtime does on
        // every Windows call instead of taking HermesEngine's loaded fast path.
        finalize_compartment_baseline(&engine).await.unwrap();
        // A second call takes the runtime_loaded fast path and must not require
        // the deliberately deleted one-shot hook again.
        engine.load_runtime().await.unwrap();

        let state = engine
            .eval_immediate(
                r#"JSON.stringify([
                  globalThis.__ibexCompartmentRegistryReady === true,
                  typeof globalThis.__ibexRefreshCompartmentBaseline,
                  typeof globalThis.__compartments,
                  globalThis.__ibexCompartmentBaselineFinalized
                ])"#,
            )
            .await
            .unwrap();
        assert_eq!(
            state.as_deref(),
            Some(r#"[true,"undefined","object",true]"#)
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_endowment_json_cannot_inject_or_overwrite_locator_buckets() {
        let _guard = hermes_engine_test_lock().lock().await;
        let attacker_locator = "attacker@zz:fetch,Buffer;victim";
        let overwritten_locator = "attacker@zz";
        let victim_locator = "victim@1.0.0";
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
                let integrity = snapshot["principals"][1]["principal"]["integrity"].clone();
                let attacker = serde_json::json!({
                    "kind": "package",
                    "name": "attacker",
                    "integrity": integrity,
                    "locator": attacker_locator,
                });
                let overwritten = serde_json::json!({
                    "kind": "package",
                    "name": "overwritten",
                    "integrity": integrity,
                    "locator": overwritten_locator,
                });
                let victim = serde_json::json!({
                    "kind": "package",
                    "name": "victim",
                    "integrity": integrity,
                    "locator": victim_locator,
                });

                snapshot["principals"][0]["imports"]["packages"] =
                    serde_json::json!([overwritten_locator, attacker_locator, victim_locator]);
                snapshot["principals"][1]["principal"] = attacker.clone();
                snapshot["principals"][1]["endowments"] = serde_json::json!(["process"]);
                let mut overwritten_row = snapshot["principals"][1].clone();
                overwritten_row["principal"] = overwritten.clone();
                overwritten_row["endowments"] = serde_json::json!(["Bun"]);
                let mut victim_row = snapshot["principals"][1].clone();
                victim_row["principal"] = victim.clone();
                victim_row["endowments"] = serde_json::json!([]);
                snapshot["principals"]
                    .as_array_mut()
                    .unwrap()
                    .extend([overwritten_row, victim_row]);

                snapshot["packageGraph"]["nodes"] = serde_json::json!([
                    {"principal": attacker},
                    {"principal": overwritten},
                    {"principal": victim},
                ]);
                let root = snapshot["rootIdentity"].clone();
                snapshot["packageGraph"]["importEdges"] = serde_json::json!([
                    {"importer": root, "imported": attacker},
                    {"importer": root, "imported": overwritten},
                    {"importer": root, "imported": victim},
                ]);

                snapshot["rootBindings"][0]["owner"] = attacker;
                let mut overwritten_binding = snapshot["rootBindings"][0].clone();
                overwritten_binding["owner"] = overwritten;
                overwritten_binding["hostPath"]["components"]
                    .as_array_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap()["value"] = serde_json::json!("overwritten");
                overwritten_binding["object"]["file"] = serde_json::json!("file-201");
                let mut victim_binding = snapshot["rootBindings"][0].clone();
                victim_binding["owner"] = victim;
                victim_binding["hostPath"]["components"]
                    .as_array_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap()["value"] = serde_json::json!("victim");
                victim_binding["object"]["file"] = serde_json::json!("file-202");
                snapshot["rootBindings"]
                    .as_array_mut()
                    .unwrap()
                    .extend([overwritten_binding, victim_binding]);
            });
        assert_ne!(crate::host::abi::install_host(host), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        assert!(engine.runtime_bundle_installed().await.unwrap());

        let script = format!(
            r#"(function () {{
              var registry = globalThis.__compartments;
              var attacker = registry[{}];
              var overwritten = registry[{}];
              var victim = registry[{}];
              var injectedBare = registry['victim'];
              return JSON.stringify({{
                attackerOwnsOnlyProcess:
                  attacker.process === globalThis.process &&
                  attacker.fetch === undefined && attacker.Buffer === undefined &&
                  attacker.Bun === undefined,
                otherExactBucketNotOverwritten:
                  overwritten.Bun === globalThis.Bun &&
                  overwritten.fetch === undefined && overwritten.Buffer === undefined &&
                  overwritten.process === undefined,
                emptyExactBucketBlocksBareInjection:
                  victim.fetch === undefined && victim.Buffer === undefined &&
                  victim.process === undefined && victim.Bun === undefined,
                noInjectedBareBucket:
                  injectedBare.fetch === undefined && injectedBare.Buffer === undefined &&
                  injectedBare.process === undefined && injectedBare.Bun === undefined,
                wireDeleted: typeof globalThis.__ibexEndowRaw === 'undefined'
              }});
            }})()"#,
            serde_json::to_string(attacker_locator).unwrap(),
            serde_json::to_string(overwritten_locator).unwrap(),
            serde_json::to_string(victim_locator).unwrap(),
        );
        let encoded = engine.eval_immediate(&script).await.unwrap().unwrap();
        let result: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            result,
            serde_json::json!({
                "attackerOwnsOnlyProcess": true,
                "otherExactBucketNotOverwritten": true,
                "emptyExactBucketBlocksBareInjection": true,
                "noInjectedBareBucket": true,
                "wireDeleted": true,
            })
        );
        // Finalization removes the bootstrap inspection path before any
        // authenticated project submission is admitted.
        engine.load_runtime().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn compartment_baseline_finalizer_accepts_disabled_and_rejects_partial_state() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _lockdown_disabled = TestEnvVar::remove("IBEX_LOCKDOWN");
        let _compartments_disabled = TestEnvVar::remove("IBEX_COMPARTMENTS");
        let engine = HermesEngine::new().unwrap();

        finalize_compartment_baseline(&engine)
            .await
            .expect("an entirely absent native handshake means compartments are disabled");
        engine
            .eval_immediate(
                r#"Object.defineProperty(
                  globalThis,
                  '__ibexCompartmentRegistryReady',
                  { value: true, configurable: true }
                )"#,
            )
            .await
            .unwrap();

        let error = finalize_compartment_baseline(&engine)
            .await
            .expect_err("a partial native handshake must fail closed");
        assert!(error.to_string().contains("malformed"), "{error:#}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn locked_baseline_rejects_prototype_and_contains_late_global_mutation() {
        let _guard = hermes_engine_test_lock().lock().await;
        // Structural lockdown is a constructor invariant. An ambient opt-out
        // must not restore the historical compartments-only mode where shared
        // prototypes and evaluator constructors remained mutable.
        // @ref LLP 0013#mechanism-1 — shared intrinsics are frozen and dynamic
        // evaluator constructors are tamed before application code executes.
        let _lockdown_cannot_disable = TestEnvVar::set("IBEX_LOCKDOWN", "0");
        let _compartments_enabled = TestEnvVar::set("IBEX_COMPARTMENTS", "1");
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();

        let raw = engine
            .eval_immediate(
                r#"(function () {
                  var root = globalThis;
                  var O = Object;
                  var R = Reflect;
                  var J = JSON;
                  var originalProxy = root.Proxy;
                  var proxyDescriptor = O.getOwnPropertyDescriptor(root, 'Proxy');
                  var registry = root.__compartments;
                  var sessionSymbol = Symbol('ibex.session.prototype');
                  var getterRan = false;
                  var prototypeStringRejected = !R.defineProperty(
                    O.prototype,
                    'sessionPrototypeString',
                    { value: 'STRING-SECRET', configurable: true }
                  );
                  var prototypeSymbolRejected = !R.defineProperty(
                    O.prototype,
                    sessionSymbol,
                    { value: 'SYMBOL-SECRET', configurable: true }
                  );
                  var prototypeGetterRejected = !R.defineProperty(
                    O.prototype,
                    'sessionPrototypeGetter',
                    {
                      configurable: true,
                      get: function () {
                        getterRan = true;
                        return 'GETTER-SECRET';
                      }
                    }
                  );

                  O.freeze(registry);
                  // Lockdown freezes shared intrinsics, not the session's realm
                  // global. Late root bindings may exist for REPL/application
                  // use, but the finalized package baseline must not acquire
                  // them or a replacement constructor binding.
                  var sessionGlobalAdded = R.defineProperty(
                    root,
                    'sessionGlobalSecret',
                    { value: 'GLOBAL-SECRET', configurable: true }
                  );
                  var replacementProxy = function PoisonedProxy() {
                    throw new Error('live global Proxy must not create compartments');
                  };
                  var proxyReplaced =
                    R.set(root, 'Proxy', replacementProxy, root) &&
                    root.Proxy === replacementProxy;

                  // This key has not been requested before: creation must use
                  // the captured Proxy constructor and immutable baseline.
                  var compartment = registry['late-session-pkg@1.0.0'];
                  var cachesDescriptorBefore = O.getOwnPropertyDescriptor(root, 'caches');
                  var indexedDBDescriptorBefore = O.getOwnPropertyDescriptor(root, 'indexedDB');

                  // Root-first and package-first access must converge on each
                  // lazy global's single shared memo without replacing a value
                  // that the other side has already observed.
                  var rootCaches = root.caches;
                  var packageCaches = compartment.caches;
                  var packageIndexedDB = compartment.indexedDB;
                  var rootIndexedDB = root.indexedDB;
                  var result = {
                    freshProxy: compartment !== root,
                    aliasesSelf: compartment.globalThis === compartment &&
                      compartment.global === compartment &&
                      compartment.self === compartment &&
                      compartment.window === compartment,
                    prototypeStringRejected: prototypeStringRejected,
                    prototypeSymbolRejected: prototypeSymbolRejected,
                    prototypeGetterRejected: prototypeGetterRejected,
                    sessionGlobalAdded: sessionGlobalAdded,
                    sessionGlobalType: typeof compartment.sessionGlobalSecret,
                    sessionGlobalHas: R.has(compartment, 'sessionGlobalSecret'),
                    proxyReplaced: proxyReplaced,
                    stringType: typeof compartment.sessionPrototypeString,
                    stringHas: R.has(compartment, 'sessionPrototypeString'),
                    symbolType: typeof compartment[sessionSymbol],
                    symbolHas: R.has(compartment, sessionSymbol),
                    getterType: typeof compartment.sessionPrototypeGetter,
                    getterHas: R.has(compartment, 'sessionPrototypeGetter'),
                    getterRan: getterRan,
                    toStringType: typeof compartment.toString,
                    registryFrozen: O.isFrozen(registry),
                    capturedProxy: compartment.Proxy === originalProxy,
                    lazyGlobalsPending:
                      !!cachesDescriptorBefore &&
                      typeof cachesDescriptorBefore.get === 'function' &&
                      !!indexedDBDescriptorBefore &&
                      typeof indexedDBDescriptorBefore.get === 'function',
                    cachesIdentity: rootCaches === packageCaches,
                    cachesRootStable: root.caches === rootCaches,
                    cachesInstalled:
                      O.getOwnPropertyDescriptor(root, 'caches').value === rootCaches,
                    indexedDBIdentity: packageIndexedDB === rootIndexedDB,
                    indexedDBRootStable: root.indexedDB === rootIndexedDB,
                    indexedDBPackageStable:
                      compartment.indexedDB === packageIndexedDB,
                    indexedDBInstalled:
                      O.getOwnPropertyDescriptor(root, 'indexedDB').value === rootIndexedDB,
                    lockedDown: root.__ibexLockedDown === true
                  };

                  R.deleteProperty(root, 'sessionGlobalSecret');
                  R.defineProperty(root, 'Proxy', proxyDescriptor);

                  return J.stringify(result);
                })()"#,
            )
            .await
            .unwrap()
            .expect("baseline regression probe should return JSON");
        let state: serde_json::Value = serde_json::from_str(&raw).unwrap();

        for field in [
            "freshProxy",
            "aliasesSelf",
            "prototypeStringRejected",
            "prototypeSymbolRejected",
            "prototypeGetterRejected",
            "sessionGlobalAdded",
            "proxyReplaced",
            "registryFrozen",
            "capturedProxy",
            "lazyGlobalsPending",
            "cachesIdentity",
            "cachesRootStable",
            "cachesInstalled",
            "indexedDBIdentity",
            "indexedDBRootStable",
            "indexedDBPackageStable",
            "indexedDBInstalled",
            "lockedDown",
        ] {
            assert_eq!(state[field], true, "{field} failed: {state}");
        }
        for field in [
            "sessionGlobalHas",
            "stringHas",
            "symbolHas",
            "getterHas",
            "getterRan",
        ] {
            assert_eq!(state[field], false, "{field} leaked: {state}");
        }
        for field in [
            "sessionGlobalType",
            "stringType",
            "symbolType",
            "getterType",
        ] {
            assert_eq!(state[field], "undefined", "{field} leaked: {state}");
        }
        assert_eq!(state["toStringType"], "function", "{state}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lockdown_enables_error_prototype_overrides() {
        let _guard = hermes_engine_test_lock().lock().await;
        // @ref LLP 0013#mechanism-1 — property override enablement: freezing
        // Error.prototype must not reject the npm error idioms
        // `SubError.prototype.name = ...` / `err.name = ...` (the override
        // mistake); the prototypes themselves stay unwritable.
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();

        let raw = engine
            .eval_immediate(
                r#"(function () {
                  'use strict';
                  var O = Object;
                  function threw(fn) {
                    try { fn(); return false; } catch (e) { return e instanceof TypeError; }
                  }

                  class SubError extends Error {}
                  SubError.prototype.name = 'SubError';

                  var renamed = new Error('boom');
                  renamed.name = 'Renamed';

                  class SubType extends TypeError {}
                  SubType.prototype.message = 'sub default';

                  // util.inherits-style legacy subclassing assigns constructor
                  // and name through the chain as well.
                  function Legacy() {}
                  Legacy.prototype = O.create(Error.prototype);
                  Legacy.prototype.constructor = Legacy;
                  Legacy.prototype.name = 'Legacy';

                  var nameDesc = O.getOwnPropertyDescriptor(Error.prototype, 'name');
                  var result = {
                    subclassName: new SubError('x').name,
                    subclassShadowOwn: SubError.prototype.hasOwnProperty('name'),
                    instanceName: renamed.name,
                    instanceMessage: renamed.message,
                    subTypeMessage: new SubType().message,
                    legacyName: new Legacy().name,
                    legacyCtor: Legacy.prototype.constructor === Legacy,
                    errorProtoNameIntact: Error.prototype.name,
                    typeErrorProtoNameIntact: TypeError.prototype.name,
                    protoAssignStillThrows: threw(function () {
                      Error.prototype.name = 'Poisoned';
                    }),
                    protoDefineStillRejected: !Reflect.defineProperty(
                      Error.prototype, 'name', { value: 'Poisoned' }),
                    accessorInstalled: typeof nameDesc.get === 'function' &&
                      typeof nameDesc.set === 'function',
                    accessorsFrozen: O.isFrozen(nameDesc.get) && O.isFrozen(nameDesc.set),
                    displacedToStringFrozen: O.isFrozen(Error.prototype.toString),
                    toStringWorks: String(new SubError('msg')) === 'SubError: msg'
                  };
                  return JSON.stringify(result);
                })()"#,
            )
            .await
            .unwrap()
            .expect("override enablement probe should return JSON");
        let state: serde_json::Value = serde_json::from_str(&raw).unwrap();

        assert_eq!(state["subclassName"], "SubError", "{state}");
        assert_eq!(state["instanceName"], "Renamed", "{state}");
        assert_eq!(state["instanceMessage"], "boom", "{state}");
        assert_eq!(state["subTypeMessage"], "sub default", "{state}");
        assert_eq!(state["legacyName"], "Legacy", "{state}");
        assert_eq!(state["errorProtoNameIntact"], "Error", "{state}");
        assert_eq!(state["typeErrorProtoNameIntact"], "TypeError", "{state}");
        for field in [
            "subclassShadowOwn",
            "legacyCtor",
            "protoAssignStillThrows",
            "protoDefineStillRejected",
            "accessorInstalled",
            "accessorsFrozen",
            "displacedToStringFrozen",
            "toStringWorks",
        ] {
            assert_eq!(state[field], true, "{field} failed: {state}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_runtime_preinstalls_shared_runtime_bundle() {
        // The C Hermes host callbacks are process-global in the test binary.
        // Keep engine-owning tests serial so the Rust test harness cannot
        // overlap bridge teardown with another runtime's event-loop pump.
        let _guard = hermes_engine_test_lock().lock().await;
        let engine = HermesEngine::new().unwrap();
        assert!(engine.runtime_bundle_installed().await.unwrap());

        let installed = engine
            .eval_immediate(
                r#"(function() {
                    return (
                      globalThis.__exactRuntimeLoaded === true &&
                      typeof globalThis.ExactBundle === 'object' &&
                      globalThis.ExactBundle !== null &&
                      typeof globalThis.__exactRuntime === 'object'
                    ) ? 'true' : 'false';
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        assert_eq!(installed.trim(), "true");

        let bootstrap_surface = engine
            .eval_immediate(
                r#"(function() {
                    var text = globalThis.Exact.unsafe.arrayBufferToString(new Uint8Array([104, 105]));
                    return JSON.stringify({
                      hasBunUnsafe: !!globalThis.Exact.unsafe,
                      hasPeekStatus: typeof globalThis.Exact.peek.status === 'function',
                      noAmbientBun: typeof globalThis.Bun === 'undefined',
                      text: text,
                      hasGetRandomValues: typeof globalThis.crypto.getRandomValues === 'function',
                      hasRandomUUID: typeof globalThis.crypto.randomUUID === 'function'
                    });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(bootstrap_surface.contains(r#""hasBunUnsafe":true"#));
        assert!(bootstrap_surface.contains(r#""noAmbientBun":true"#));
        assert!(bootstrap_surface.contains(r#""hasPeekStatus":true"#));
        assert!(bootstrap_surface.contains(r#""text":"hi""#));
        assert!(bootstrap_surface.contains(r#""hasGetRandomValues":true"#));
        assert!(bootstrap_surface.contains(r#""hasRandomUUID":true"#));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_byte_and_fetch_boundaries_reject_forged_inputs() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:fetch:127.0.0.1"]);
        let engine = HermesEngine::new().unwrap();

        let outcome = engine
            .eval_immediate(
                r#"(function() {
                    var out = [];
                    var forged = { buffer: new ArrayBuffer(4), byteOffset: 3, byteLength: 4 };
                    try {
                      __nativeFetch('http://127.0.0.1:9/', {
                        headers: [['x-test', 'ok\r\nInjected: yes']]
                      });
                      out.push('headers:ALLOWED');
                    } catch (e) {
                      out.push(String(e && e.message || e).indexOf('invalid header') !== -1
                        ? 'headers:DENIED' : 'headers:ERR');
                    }
                    try {
                      __exactBytesToUtf8String(forged);
                      out.push('utf8:ALLOWED');
                    } catch (e) {
                      out.push(String(e && e.message || e).indexOf('out of bounds') !== -1
                        ? 'utf8:DENIED' : 'utf8:ERR');
                    }
                    try {
                      __nativeFetch('http://127.0.0.1:9/', { method: 'POST', headers: [] }, forged);
                      out.push('fetch-body:ALLOWED');
                    } catch (e) {
                      out.push(String(e && e.message || e).indexOf('out of bounds') !== -1
                        ? 'fetch-body:DENIED' : 'fetch-body:ERR');
                    }
                    return out.join(' ');
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();

        assert_eq!(
            outcome.trim(),
            "headers:DENIED utf8:DENIED fetch-body:DENIED"
        );
    }

    #[cfg(feature = "host-http-server")]
    #[tokio::test(flavor = "current_thread")]
    async fn native_http_response_body_rejects_forged_view_bounds() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:listen:127.0.0.1:0"]);
        let engine = HermesEngine::new().unwrap();

        let outcome = engine
            .eval_immediate(
                r#"(function() {
                    if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
                    var server = JSON.parse(__exactHttpServe(0, '127.0.0.1'));
                    if (server.error) return 'setup:' + server.error;
                    __exactHttpSetRef(server.id, 0);
                    var forged = { buffer: new ArrayBuffer(4), byteOffset: 3, byteLength: 4 };
                    try {
                      __exactHttpRespond(server.id, 1, 200, '[]', forged);
                      return 'http-body:ALLOWED';
                    } catch (e) {
                      return String(e && e.message || e).indexOf('out of bounds') !== -1
                        ? 'http-body:DENIED' : 'http-body:ERR';
                    } finally {
                      __exactHttpClose(server.id, 1);
                    }
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();

        assert_eq!(outcome.trim(), "http-body:DENIED");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_call_async_resolves_and_rejects_through_the_promise_channel() {
        let _guard = hermes_engine_test_lock().lock().await;
        let engine = HermesEngine::new().unwrap();

        let kicked = engine
            .eval_immediate(
                r#"(function() {
                    globalThis.__hcAsync = {
                      resolve: 'pending', reject: 'pending', numOp: 'pending'
                    };
                    __hostCallAsync('agent.captureScreenshot', '{}').then(
                      function(r) {
                        globalThis.__hcAsync.resolve =
                          'ok:' + (r && typeof r.error === 'string');
                      },
                      function() { globalThis.__hcAsync.resolve = 'rejected'; });
                    __hostCallAsync('selftest.unknown-op', '{}').then(
                      function() { globalThis.__hcAsync.reject = 'resolved'; },
                      function(e) {
                        globalThis.__hcAsync.reject =
                          (e && typeof e.message === 'string' &&
                           e.message.indexOf('Unknown host call') !== -1)
                            ? 'rejected-with-message' : 'rejected-odd';
                      });
                    // ENG-22982: a non-string op must not sync-throw before the
                    // promise exists. It is coerced (12345 -> "12345"), reaches
                    // the host, and settles as a rejection like any unknown op —
                    // the kick itself must NOT throw.
                    try {
                      __hostCallAsync(12345, '{}').then(
                        function() { globalThis.__hcAsync.numOp = 'resolved'; },
                        function(e) {
                          globalThis.__hcAsync.numOp =
                            (e && typeof e.message === 'string' &&
                             e.message.indexOf('Unknown host call') !== -1)
                              ? 'rejected-with-message' : 'rejected-odd';
                        });
                    } catch (e) {
                      globalThis.__hcAsync.numOp = 'threw:' + (e && e.message);
                    }
                    return 'kicked';
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        assert_eq!(kicked.trim(), "kicked");

        engine.drive_event_loop().await.unwrap();

        let outcome = engine
            .eval_immediate("JSON.stringify(globalThis.__hcAsync)")
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(outcome.contains(r#""resolve":"ok:true""#), "{outcome}");
        assert!(
            outcome.contains(r#""reject":"rejected-with-message""#),
            "{outcome}"
        );
        assert!(
            outcome.contains(r#""numOp":"rejected-with-message""#),
            "{outcome}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fs_positional_read_does_not_move_the_file_offset() {
        // ENG-22982: __exactFsRead with a numeric position is a *positional*
        // read (pread) that leaves the fd's current offset unchanged, matching
        // Node's readSync. The old lseek+read moved the cursor, so a fixed
        // header read followed by a sequential read returned the wrong bytes.
        let _guard = hermes_engine_test_lock().lock().await;

        let path = std::env::temp_dir().join(format!(
            "ibex-eng-22982-positional-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, b"abcdefghij").unwrap();
        let path_str = path.to_str().unwrap().to_string();
        let cap = format!("fs:read:{path_str}");
        let _host_guard = install_test_host_with_allow(&[cap.as_str()]);

        let engine = HermesEngine::new().unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                function b2s(a) {{ return String.fromCharCode.apply(null, a); }}
                // The POSIX fs bridge is installed lazily on first use.
                var fd = __exactFsOpen({path_str:?}, 'r');
                // Positional read at offset 5 -> "fg". This must NOT advance the
                // fd cursor, so the following sequential read starts from 0.
                var positional = b2s(__exactFsRead(fd, 2, 5));
                var sequential = b2s(__exactFsRead(fd, 2, -1));
                __exactFsClose(fd);
                return JSON.stringify({{
                    positional: positional, sequential: sequential
                }});
            }})()"#
        );

        let outcome = engine
            .eval_immediate(&script)
            .await
            .unwrap()
            .unwrap_or_default();

        let _ = fs::remove_file(&path);

        let parsed: serde_json::Value = serde_json::from_str(&outcome)
            .unwrap_or_else(|_| panic!("fs positional read eval returned non-JSON: {outcome}"));
        assert_eq!(parsed["positional"], "fg", "{outcome}");
        // Pre-fix (lseek+read) this returned "hi" because the positional read
        // moved the cursor to offset 7; pread leaves it at 0 -> "ab".
        assert_eq!(parsed["sequential"], "ab", "{outcome}");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn terminal_session_descriptor_policy_precedes_every_native_fd_route() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["process:spawn"]);
        let _descriptor_guard =
            crate::host::abi::arm_terminal_session_descriptor_policy(true, [73, 74, 75]).unwrap();
        let engine = HermesEngine::new().unwrap();

        let sync_outcome = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  function denied(operation) {
                    try {
                      operation();
                      return 'ALLOWED';
                    } catch (error) {
                      return String(error && error.message || error);
                    }
                  }
                  var readvBuffers = [new Uint8Array(2), new Uint8Array(3)];
                  return JSON.stringify({
                    stdinRead: __exactStdinRead(16),
                    read: __exactFsRead(0, 8, -1).length,
                    readv: __exactFsReadv(0, readvBuffers, -1),
                    closeStdin: denied(function() { __exactFsClose(0); }),
                    closeStdout: denied(function() { __exactFsClose(1); }),
                    protectedRead: denied(function() { __exactFsRead(73, 1, -1); }),
                    protectedWrite: denied(function() {
                      __exactFsWrite(74, new Uint8Array([1]), -1);
                    }),
                    protectedStat: denied(function() { __exactFsFstatSync(75); }),
                    protectedClose: denied(function() { __exactFsClose(73); }),
                    protectedCloseAsync: denied(function() { __exactFsCloseAsync(74); }),
                    protectedSpawnSyncAlias: denied(function() {
                      __exactSpawnSync('/bin/true', '[]',
                        '{"stdio":["fd:73","ignore","ignore"]}');
                    }),
                    protectedSpawnAlias: denied(function() {
                      __exactSpawn('/bin/true', '[]',
                        '{"stdio":["fd:74","ignore","ignore"]}');
                    }),
                    outputAlias: denied(function() {
                      __exactSpawnSync('/bin/true', '[]',
                        '{"stdio":["fd:1","ignore","ignore"]}');
                    })
                  });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        let sync: serde_json::Value = serde_json::from_str(&sync_outcome).unwrap();
        assert_eq!(sync["stdinRead"], "");
        assert_eq!(sync["read"], 0);
        assert_eq!(sync["readv"], 0);
        assert_eq!(sync["closeStdin"], "ALLOWED");
        assert_eq!(sync["closeStdout"], "ALLOWED");
        for name in [
            "protectedRead",
            "protectedWrite",
            "protectedStat",
            "protectedClose",
            "protectedCloseAsync",
            "protectedSpawnSyncAlias",
            "protectedSpawnAlias",
            "outputAlias",
        ] {
            assert!(
                sync[name].as_str().unwrap_or_default().contains("EACCES"),
                "{name} did not fail with a typed descriptor refusal: {sync_outcome}"
            );
        }

        engine
            .eval_immediate(
                r#"(function() {
                  globalThis.__sessionDescriptorAsync = { status: 'pending' };
                  Promise.all([
                    __exactFsReadAsync(0, 8, -1).then(function(bytes) {
                      return bytes.length;
                    }),
                    __exactFsReadvAsync(0, [new Uint8Array(2)], -1).then(function(bytes) {
                      return bytes.length;
                    }),
                    __exactFsReadFileAsync(0, 0, 0).then(function(bytes) {
                      return bytes.length;
                    }),
                    __exactFsWriteAsync(1, new Uint8Array(0), -1),
                    __exactFsCloseAsync(0).then(function() { return 0; }),
                    __exactFsCloseAsync(1).then(function() { return 0; })
                  ]).then(function(values) {
                    globalThis.__sessionDescriptorAsync = {
                      status: 'settled', values: values
                    };
                  }, function(error) {
                    globalThis.__sessionDescriptorAsync = {
                      status: 'rejected', message: String(error && error.message || error)
                    };
                  });
                  return 'started';
                })()"#,
            )
            .await
            .unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_outcome = engine
            .eval_immediate("JSON.stringify(globalThis.__sessionDescriptorAsync)")
            .await
            .unwrap()
            .unwrap_or_default();
        let asynchronous: serde_json::Value = serde_json::from_str(&async_outcome).unwrap();
        assert_eq!(asynchronous["status"], "settled", "{async_outcome}");
        assert_eq!(
            asynchronous["values"],
            serde_json::json!([0, 0, 0, 0, 0, 0])
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn stale_fd_number_reuse_never_authorizes_the_replacement_object() {
        use std::os::fd::AsRawFd;

        const CHILD_ENV: &str = "IBEX_TEST_STALE_FD_REUSE_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::stale_fd_number_reuse_never_authorizes_the_replacement_object";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let first = tempdir.path().join("first.txt");
        let replacement = tempdir.path().join("replacement.txt");
        fs::write(&first, b"AAAA").unwrap();
        fs::write(&replacement, b"BBBB").unwrap();
        let first_path = first.to_str().unwrap();
        let read_cap = format!("fs:read:{first_path}");
        let _host_guard = install_test_host_with_allow(&[&read_cap]);
        let engine = HermesEngine::new().unwrap();

        let opened = engine
            .eval_immediate(&format!(
                "if (typeof __exactEnsureFs === 'function') __exactEnsureFs(); \
                 String(__exactFsOpen({first_path:?}, 'r'))"
            ))
            .await
            .unwrap()
            .unwrap();
        let fd: i32 = opened.trim().parse().expect("numeric native fd");

        assert_eq!(unsafe { libc::close(fd) }, 0);
        let replacement_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&replacement)
            .unwrap();
        let replacement_source_fd = replacement_file.as_raw_fd();
        if replacement_source_fd != fd {
            assert_eq!(unsafe { libc::dup2(replacement_source_fd, fd) }, fd);
        }

        let outcome = engine
            .eval_immediate(&format!(
                r#"(function(fd) {{
                  function denied(operation) {{
                    try {{
                      operation();
                      return 'ALLOWED';
                    }} catch (error) {{
                      return String(error && error.message || error);
                    }}
                  }}
                  return JSON.stringify([
                    denied(function() {{ __exactFsRead(fd, 1, -1); }}),
                    denied(function() {{ __exactFsFstatSync(fd); }}),
                    denied(function() {{ __exactFsWrite(fd, new Uint8Array([88]), 0); }}),
                    denied(function() {{ __exactFsReadAsync(fd, 1, -1); }}),
                    denied(function() {{ __exactFsWriteAsync(fd, new Uint8Array([88]), 0); }}),
                    denied(function() {{ __exactFsClose(fd); }}),
                    denied(function() {{ __exactFsCloseAsync(fd); }})
                  ]);
                }})({fd})"#
            ))
            .await
            .unwrap()
            .unwrap();
        let denials: Vec<String> = serde_json::from_str(&outcome).unwrap();
        assert_eq!(denials.len(), 7);
        assert!(
            denials
                .iter()
                .all(|message| message.contains("bad file descriptor")),
            "every stale sync/async operation must fail as EBADF: {denials:?}"
        );

        let mut bytes = [0u8; 4];
        assert_eq!(
            unsafe { libc::pread(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) },
            4,
            "denied close must leave the replacement descriptor open"
        );
        assert_eq!(&bytes, b"BBBB", "denied writes must not mutate replacement");

        drop(engine);
        if replacement_source_fd != fd {
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
        drop(replacement_file);
        assert_eq!(fs::read(&replacement).unwrap(), b"BBBB");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn process_ipc_disconnect_closes_once_without_reused_fd_damage() {
        use std::io::Read as _;
        use std::os::fd::{AsRawFd as _, IntoRawFd as _};
        use std::os::unix::net::UnixStream;

        const CHILD_ENV: &str = "IBEX_TEST_PROCESS_IPC_DISCONNECT_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::process_ipc_disconnect_closes_once_without_reused_fd_damage";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let (mut peer, adopted) = UnixStream::pair().expect("create process IPC socketpair");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let adopted_fd = adopted.into_raw_fd();
        let _ipc_fd = TestEnvVar::set("EXACT_IPC_FD", &adopted_fd.to_string());
        let _ipc_serialization = TestEnvVar::set("EXACT_IPC_SERIALIZATION", "advanced");
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        drop(_ipc_serialization);
        drop(_ipc_fd);

        let engine = HermesEngine::new().unwrap();
        assert_eq!(
            engine
                .eval_immediate(
                    "if (!process.connected || typeof process.disconnect !== 'function') throw new Error('IPC unavailable'); process.disconnect(); 'disconnected'",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("disconnected")
        );
        assert_eq!(
            engine
                .eval_immediate("'runtime-still-alive'")
                .await
                .unwrap()
                .as_deref(),
            Some("runtime-still-alive"),
            "disconnect must close the channel, not the runtime"
        );

        let mut saw_eof = false;
        let mut received = Vec::new();
        while !saw_eof {
            let mut chunk = [0u8; 1024];
            match peer.read(&mut chunk) {
                Ok(0) => saw_eof = true,
                Ok(count) => received.extend_from_slice(&chunk[..count]),
                Err(error) => panic!(
                    "process IPC peer did not reach EOF after disconnect: {error}; received={}",
                    String::from_utf8_lossy(&received)
                ),
            }
        }
        assert!(
            String::from_utf8_lossy(&received).contains("\"type\":\"disconnect\""),
            "disconnect packet was not flushed before close: {}",
            String::from_utf8_lossy(&received)
        );

        // Reuse the just-closed integer before runtime teardown. The JS close
        // must have unregistered the IPC row, so teardown cannot close this
        // unrelated replacement as a second attempt at channel cleanup.
        let replacement_path = std::env::temp_dir().join(format!(
            "ibex-process-ipc-replacement-{}",
            std::process::id()
        ));
        std::fs::write(&replacement_path, b"replacement").unwrap();
        let replacement = std::fs::File::open(&replacement_path).unwrap();
        let replacement_source_fd = replacement.as_raw_fd();
        if replacement_source_fd != adopted_fd {
            assert_eq!(
                unsafe { libc::dup2(replacement_source_fd, adopted_fd) },
                adopted_fd
            );
        }

        drop(engine);
        let mut bytes = [0u8; 11];
        assert_eq!(
            unsafe { libc::pread(adopted_fd, bytes.as_mut_ptr().cast(), bytes.len(), 0,) },
            bytes.len() as isize,
            "runtime teardown double-closed the reused IPC descriptor number"
        );
        assert_eq!(&bytes, b"replacement");
        if replacement_source_fd != adopted_fd {
            assert_eq!(unsafe { libc::close(adopted_fd) }, 0);
        }
        drop(replacement);
        let _ = std::fs::remove_file(replacement_path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn connected_process_ipc_closes_on_native_runtime_teardown() {
        use std::io::Read as _;
        use std::os::fd::IntoRawFd as _;
        use std::os::unix::net::UnixStream;

        const CHILD_ENV: &str = "IBEX_TEST_PROCESS_IPC_TEARDOWN_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::connected_process_ipc_closes_on_native_runtime_teardown";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let (mut peer, adopted) = UnixStream::pair().expect("create process IPC socketpair");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let adopted_fd = adopted.into_raw_fd();
        let _ipc_fd = TestEnvVar::set("EXACT_IPC_FD", &adopted_fd.to_string());
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        drop(_ipc_fd);

        let runtime = SharedRuntime::new(None).expect("create diagnostic runtime with IPC");
        assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);

        let mut byte = [0u8; 1];
        assert_eq!(
            peer.read(&mut byte).expect("read teardown EOF"),
            0,
            "native runtime teardown left the adopted IPC socket open"
        );
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn partial_diagnostic_startup_closes_registered_process_ipc() {
        use std::io::Read as _;
        use std::os::fd::IntoRawFd as _;
        use std::os::unix::net::UnixStream;

        struct ResetInjectedFailure;
        impl Drop for ResetInjectedFailure {
            fn drop(&mut self) {
                unsafe { ibex_test_set_diagnostic_startup_failure_stage(std::ptr::null()) };
            }
        }

        const CHILD_ENV: &str = "IBEX_TEST_PROCESS_IPC_PARTIAL_STARTUP_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::partial_diagnostic_startup_closes_registered_process_ipc";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let _reset_failure = ResetInjectedFailure;
        let (mut peer, adopted) = UnixStream::pair().expect("create process IPC socketpair");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let adopted_fd = adopted.into_raw_fd();
        let _ipc_fd = TestEnvVar::set("EXACT_IPC_FD", &adopted_fd.to_string());
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        drop(_ipc_fd);
        let stage = CString::new("process-ipc-registered").unwrap();
        unsafe { ibex_test_set_diagnostic_startup_failure_stage(stage.as_ptr()) };

        assert!(
            SharedRuntime::new(None).is_err(),
            "diagnostic runtime survived injected post-registration failure"
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            peer.read(&mut byte).expect("read partial-startup EOF"),
            0,
            "partial runtime cleanup left the registered IPC socket open"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn runtime_cleanup_never_closes_a_reused_descriptor_number() {
        use std::os::fd::AsRawFd;

        const CHILD_ENV: &str = "IBEX_TEST_RUNTIME_CLEANUP_REUSED_FD_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::runtime_cleanup_never_closes_a_reused_descriptor_number";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let owned_path = tempdir.path().join("owned.txt");
        let replacement_path = tempdir.path().join("replacement.txt");
        fs::write(&owned_path, b"owned").unwrap();
        fs::write(&replacement_path, b"replacement").unwrap();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let engine = HermesEngine::new().unwrap();
        let fd = engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  return String(__exactFsOpen({:?}, 'r'));
                }})()"#,
                owned_path.to_str().unwrap()
            ))
            .await
            .unwrap()
            .unwrap()
            .parse::<i32>()
            .unwrap();

        assert_eq!(unsafe { libc::close(fd) }, 0);
        let replacement = std::fs::File::open(&replacement_path).unwrap();
        let replacement_source_fd = replacement.as_raw_fd();
        if replacement_source_fd != fd {
            assert_eq!(unsafe { libc::dup2(replacement_source_fd, fd) }, fd);
        }

        drop(engine);
        let mut bytes = [0u8; 11];
        assert_eq!(
            unsafe { libc::pread(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) },
            bytes.len() as isize
        );
        assert_eq!(&bytes, b"replacement");
        if replacement_source_fd != fd {
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
    }

    #[cfg(unix)]
    async fn run_bounded_owner_thread_teardown_probe(
        child_env: &str,
        exact_test_name: &str,
    ) -> bool {
        if std::env::var(child_env).as_deref() == Ok("1") {
            return false;
        }

        let mut command = Command::new(std::env::current_exe().expect("current test binary"));
        command
            .arg(exact_test_name)
            .arg("--exact")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(child_env, "1")
            .env_remove("IBEX_TEST_FS_WORKER_THROW_ENQUEUE");
        let label = format!("owner-thread teardown probe {exact_test_name}");
        // The bound includes spawning and scheduling a second full test
        // process. Ten seconds is enough in isolation but flakes when all ten
        // owner-thread probes contend with the workspace's parallel test
        // suite; thirty remains a strict deadlock bound while admitting that
        // startup load.
        let output = output_with_timeout(&mut command, std::time::Duration::from_secs(30), &label)
            .await
            .unwrap_or_else(|error| panic!("{error:#}"));
        assert!(
            output.status.success(),
            "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_destroy_waits_for_an_inflight_structured_control_lease() {
        const CHILD_ENV: &str = "IBEX_TEST_INFLIGHT_STRUCTURED_CONTROL_TEARDOWN_CHILD";
        const TEST_NAME: &str = "engine::hermes::tests::concurrent_destroy_waits_for_an_inflight_structured_control_lease";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let _reset = HostResetGuard;
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let runtime = SharedRuntime::new(None).expect("diagnostic runtime");
        let raw = runtime.raw.load(Ordering::SeqCst);
        let raw_address = raw as usize;
        let runtime_nonce = runtime.runtime_nonce.get();
        assert_eq!(unsafe { ibex_test_arm_structured_control_lease_pause() }, 1);
        let _pause_release = StructuredControlLeasePauseReleaseGuard;

        let controller = std::thread::spawn(move || unsafe {
            ex_hermes_structured_active_work_target(
                raw_address as *mut HermesRuntimeOpaque,
                runtime_nonce,
            )
        });
        let pause_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while unsafe { ibex_test_structured_control_lease_paused() } != 1 {
            assert!(
                std::time::Instant::now() < pause_deadline,
                "structured control did not pause after acquiring its native lease"
            );
            std::thread::yield_now();
        }

        let shutdown_returned = Arc::new(AtomicBool::new(false));
        let shutdown_returned_for_releaser = Arc::clone(&shutdown_returned);
        let releaser = std::thread::spawn(move || {
            let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while unsafe { ibex_test_structured_control_teardown_wait_observed() } != 1 {
                if std::time::Instant::now() >= wait_deadline {
                    unsafe {
                        ibex_test_release_structured_control_lease_pause();
                    }
                    panic!("teardown did not observe the admitted structured-control lease");
                }
                std::thread::yield_now();
            }
            let returned_before_release = shutdown_returned_for_releaser.load(Ordering::Acquire);
            unsafe {
                ibex_test_release_structured_control_lease_pause();
            }
            assert!(
                !returned_before_release,
                "owner-thread destroy returned while an admitted structured-control lease was in flight"
            );
        });

        assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
        shutdown_returned.store(true, Ordering::Release);
        let releaser_result = releaser.join();
        // Ensure a failing releaser assertion cannot strand the controller.
        unsafe {
            ibex_test_release_structured_control_lease_pause();
        }
        assert_eq!(controller.join().unwrap(), 0);
        releaser_result.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_destroy_waits_for_an_inflight_fs_worker_pin() {
        const CHILD_ENV: &str = "IBEX_TEST_INFLIGHT_FS_PIN_TEARDOWN_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::concurrent_destroy_waits_for_an_inflight_fs_worker_pin";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let fifo = tempdir.path().join("blocked-read.fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let engine = HermesEngine::new().unwrap();
        let started = engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__blockedRead = __exactFsReadFileAsync({:?}, 'r', 0);
                  return 'started';
                }})()"#,
                fifo.to_str().unwrap()
            ))
            .await
            .unwrap();
        assert_eq!(started.as_deref(), Some("started"));

        // A nonblocking FIFO writer succeeds only after the worker has opened
        // the read end. Retain that writer through teardown so the committed
        // read stays blocked until the release thread writes to it.
        let release_fd = {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                let fd = unsafe { libc::open(fifo_c.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
                if fd >= 0 {
                    break fd;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "filesystem worker did not commit its FIFO read"
                );
                std::thread::yield_now();
            }
        };

        let shared = engine.runtime.lock().await.as_ref().unwrap().shared();
        let shutdown_returned = Arc::new(AtomicBool::new(false));
        let shutdown_returned_for_writer = Arc::clone(&shutdown_returned);
        let raw_for_writer = shared.raw.load(Ordering::SeqCst) as usize;
        let runtime_nonce =
            unsafe { ex_hermes_runtime_nonce(raw_for_writer as *mut HermesRuntimeOpaque) };
        assert_ne!(runtime_nonce, 0);
        let writer = std::thread::spawn(move || {
            // The nonce API returns zero once the native registry leaves
            // Running, so this cannot be satisfied merely by Rust swapping its
            // pointer before entering the C++ destructor.
            while unsafe { ex_hermes_runtime_nonce(raw_for_writer as *mut HermesRuntimeOpaque) }
                == runtime_nonce
            {
                std::thread::yield_now();
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            let returned_before_release = shutdown_returned_for_writer.load(Ordering::Acquire);
            assert_eq!(
                unsafe { libc::write(release_fd, b"release".as_ptr().cast(), 7) },
                7
            );
            assert_eq!(unsafe { libc::close(release_fd) }, 0);
            assert!(
                !returned_before_release,
                "owner-thread destroy returned while the worker still held a runtime lifetime pin"
            );
        });

        // JSI/Hermes destruction is owner-thread-only. Release the blocked
        // worker from another thread while shutdown waits on this thread.
        let started_waiting = std::time::Instant::now();
        assert_eq!(shared.shutdown(), RuntimeShutdown::Destroyed);
        shutdown_returned.store(true, Ordering::Release);
        writer.join().unwrap();
        assert!(
            started_waiting.elapsed() >= std::time::Duration::from_millis(100),
            "destroy must wait while the worker owns a runtime lifetime pin"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn destroy_cancels_queued_fs_lease_but_drains_committed_workers() {
        const CHILD_ENV: &str = "IBEX_TEST_QUEUED_FS_LEASE_TEARDOWN_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::destroy_cancels_queued_fs_lease_but_drains_committed_workers";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let mut fifos = Vec::new();
        for index in 0..8 {
            let fifo = tempdir.path().join(format!("blocked-read-{index}.fifo"));
            let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
            fifos.push(fifo);
        }
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let engine = HermesEngine::new().unwrap();
        let paths = fifos
            .iter()
            .map(|path| format!("{:?}", path.to_str().unwrap()))
            .collect::<Vec<_>>()
            .join(",");
        engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__blockedReads = [{paths}].map(function(path) {{
                    return __exactFsReadFileAsync(path, 'r', 0);
                  }});
                  return 'started';
                }})()"#
            ))
            .await
            .unwrap();

        // A nonblocking FIFO writer succeeds only after the matching worker
        // has opened the read end. Keeping all eight writers open leaves every
        // pool worker irreversibly committed and blocked in read(2), so the
        // next operation is deterministically still cancelable in the queue.
        let mut release_fds = Vec::new();
        for fifo in &fifos {
            let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                let fd = unsafe { libc::open(fifo_c.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
                if fd >= 0 {
                    release_fds.push(fd);
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "filesystem worker did not commit its FIFO read"
                );
                std::thread::yield_now();
            }
        }

        let queued_effect = tempdir.path().join("must-remain-absent.txt");
        engine
            .eval_immediate(&format!(
                r#"(function() {{
                  globalThis.__queuedWrite = __exactFsWriteFileAsync(
                    {:?}, 'should-not-land', 'w', 438, true);
                  return 'queued';
                }})()"#,
                queued_effect.to_str().unwrap()
            ))
            .await
            .unwrap();

        let shared = engine.runtime.lock().await.as_ref().unwrap().shared();
        let raw = shared.raw.load(Ordering::SeqCst) as usize;
        let nonce = unsafe { ex_hermes_runtime_nonce(raw as *mut HermesRuntimeOpaque) };
        assert_ne!(nonce, 0);
        let releaser = std::thread::spawn(move || {
            while unsafe { ex_hermes_runtime_nonce(raw as *mut HermesRuntimeOpaque) } == nonce {
                std::thread::yield_now();
            }
            for fd in release_fds {
                assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, 1);
                assert_eq!(unsafe { libc::close(fd) }, 0);
            }
        });

        assert_eq!(shared.shutdown(), RuntimeShutdown::Destroyed);
        releaser.join().unwrap();
        assert!(
            !queued_effect.exists(),
            "teardown executed a filesystem effect that was still queued"
        );
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn canceling_a_queued_async_close_rolls_back_its_descriptor_reservation() {
        const CHILD_ENV: &str = "IBEX_TEST_QUEUED_FS_CLOSE_LEASE_CHILD";
        const TEST_NAME: &str = "engine::hermes::tests::canceling_a_queued_async_close_rolls_back_its_descriptor_reservation";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let mut fifos = Vec::new();
        for index in 0..8 {
            let fifo = tempdir
                .path()
                .join(format!("blocked-close-read-{index}.fifo"));
            let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
            fifos.push(fifo);
        }
        let output = tempdir.path().join("close-reservation.txt");
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let engine = HermesEngine::new().unwrap();
        let paths = fifos
            .iter()
            .map(|path| format!("{:?}", path.to_str().unwrap()))
            .collect::<Vec<_>>()
            .join(",");
        engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__closeLeaseFd = __exactFsOpen({output:?}, 'w');
                  globalThis.__closeLeaseBlockers = [{paths}].map(function(path) {{
                    return __exactFsReadFileAsync(path, 'r', 0);
                  }});
                  return 'started';
                }})()"#,
                output = output.to_str().unwrap(),
            ))
            .await
            .unwrap();

        let mut release_fds = Vec::new();
        for fifo in &fifos {
            let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                let fd = unsafe { libc::open(fifo_c.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
                if fd >= 0 {
                    release_fds.push(fd);
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "filesystem worker did not commit its FIFO read"
                );
                std::thread::yield_now();
            }
        }

        engine
            .eval_immediate(
                "globalThis.__queuedClose = __exactFsCloseAsync(globalThis.__closeLeaseFd); 'queued';",
            )
            .await
            .unwrap();
        let shared = engine.runtime.lock().await.as_ref().unwrap().shared();
        let raw = shared.raw.load(Ordering::SeqCst);
        assert_eq!(
            unsafe { ibex_private_test_cancel_queued_fs_operations(raw) },
            1,
            "the close must still be Queued while all workers are committed"
        );

        let written = engine
            .eval_immediate("String(__exactFsWrite(globalThis.__closeLeaseFd, 'survived', 0))")
            .await
            .unwrap();
        assert_eq!(written.as_deref(), Some("8"));
        engine
            .eval_immediate("__exactFsClose(globalThis.__closeLeaseFd); 'closed';")
            .await
            .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"survived");

        for fd in release_fds {
            assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, 1);
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_prepared_mutations_are_committed_leases_and_drain_on_teardown() {
        const CHILD_ENV: &str = "IBEX_TEST_ARMED_COMMITTED_FS_LEASE_CHILD";
        const TEST_NAME: &str = "engine::hermes::tests::armed_prepared_mutations_are_committed_leases_and_drain_on_teardown";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let blockers_dir = tempfile::tempdir().unwrap();
        let mut fifos = Vec::new();
        for index in 0..8 {
            let fifo = blockers_dir
                .path()
                .join(format!("armed-commit-blocker-{index}.fifo"));
            let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
            fifos.push(fifo);
        }

        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let blocker_engine = HermesEngine::new().unwrap();
        let paths = fifos
            .iter()
            .map(|path| format!("{:?}", path.to_str().unwrap()))
            .collect::<Vec<_>>()
            .join(",");
        blocker_engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__armedCommitBlockers = [{paths}].map(function(path) {{
                    return __exactFsReadFileAsync(path, 'r', 0);
                  }});
                  return 'started';
                }})()"#,
            ))
            .await
            .unwrap();

        let mut release_fds = Vec::new();
        for fifo in &fifos {
            let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                let fd = unsafe { libc::open(fifo_c.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
                if fd >= 0 {
                    release_fds.push(fd);
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "filesystem worker did not commit its FIFO read"
                );
                std::thread::yield_now();
            }
        }

        let project = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        let existing = root.join("existing.txt");
        std::fs::write(&existing, b"original").unwrap();
        let created = root.join("created.txt");
        let created_dir = root.join("created-dir");
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, true, vec![]);
        let armed = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        armed
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__armedCommittedOps = [
                    __exactFsWriteFileAsync(
                      '/project/existing.txt', 'replacement', 'w', 438, false),
                    __exactFsOpenAsync('/project/created.txt', 'wx', 438),
                    __exactFsPathAsync(
                      'mkdir', '/project/created-dir', null, 0, 493, 0),
                    __exactFsReadFileAsync(
                      '/project/existing.txt', 'r', 0),
                    __exactFsPathAsync(
                      'readdir', '/project', null, 0, 0, 0)
                  ];
                  return 'queued';
                })()"#,
            )
            .await
            .unwrap();

        // Preparation has already performed authorized target lookup and the
        // create/truncate/mkdir effects. These records must therefore be
        // Committed, never reported or rolled back as cancelable queue work.
        assert!(created.exists());
        assert!(created_dir.is_dir());
        assert_eq!(std::fs::read(&existing).unwrap(), b"");
        let shared = armed.runtime.lock().await.as_ref().unwrap().shared();
        let raw = shared.raw.load(Ordering::SeqCst);
        assert_eq!(
            unsafe { ibex_private_test_cancel_queued_fs_operations(raw) },
            2,
            "queued armed read/list work is cancelable; prepared mutations are not"
        );
        let nonce = unsafe { ex_hermes_runtime_nonce(raw) };
        assert_ne!(nonce, 0);
        let raw_address = raw as usize;
        let releaser = std::thread::spawn(move || {
            while unsafe { ex_hermes_runtime_nonce(raw_address as *mut HermesRuntimeOpaque) }
                == nonce
            {
                std::thread::yield_now();
            }
            for fd in release_fds {
                assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, 1);
                assert_eq!(unsafe { libc::close(fd) }, 0);
            }
        });

        assert_eq!(shared.shutdown(), RuntimeShutdown::Destroyed);
        releaser.join().unwrap();
        assert_eq!(std::fs::read(&existing).unwrap(), b"replacement");
        assert!(created.exists());
        assert!(created_dir.is_dir());
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_committed_preparation_never_runs_before_queue_admission() {
        let _guard = hermes_engine_test_lock().lock().await;
        for (control, value, other) in [
            (
                "IBEX_TEST_FS_WORKER_THROW_ENQUEUE",
                "1",
                "IBEX_TEST_FS_WORKER_MAX_QUEUE",
            ),
            (
                "IBEX_TEST_FS_WORKER_MAX_QUEUE",
                "0",
                "IBEX_TEST_FS_WORKER_THROW_ENQUEUE",
            ),
        ] {
            let _other = TestEnvVar::remove(other);
            let _control = TestEnvVar::set(control, value);
            let project = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(project.path()).unwrap();
            let existing = root.join("existing.txt");
            std::fs::write(&existing, b"original").unwrap();
            let created = root.join("created.txt");
            let created_dir = root.join("created-dir");
            let (_reset, digest) =
                install_armed_test_host_at(Some(&root), true, true, true, vec![]);
            let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
            engine
                .eval_immediate(
                    r#"(function() {
                      if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                      __exactFsWriteFileAsync(
                        '/project/existing.txt', 'replacement', 'w', 438, false)
                        .catch(function() {});
                      __exactFsOpenAsync('/project/created.txt', 'wx', 438)
                        .catch(function() {});
                      __exactFsPathAsync(
                        'mkdir', '/project/created-dir', null, 0, 493, 0)
                        .catch(function() {});
                      return 'rejected';
                    })()"#,
                )
                .await
                .unwrap();

            assert_eq!(
                std::fs::read(&existing).unwrap(),
                b"original",
                "{control} allowed pre-admission truncation"
            );
            assert!(
                !created.exists(),
                "{control} allowed pre-admission creation"
            );
            assert!(
                !created_dir.exists(),
                "{control} allowed pre-admission mkdir"
            );
        }
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_committed_preparation_preserves_typed_failure_codes() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _throw_enqueue = TestEnvVar::remove("IBEX_TEST_FS_WORKER_THROW_ENQUEUE");
        let _max_queue = TestEnvVar::remove("IBEX_TEST_FS_WORKER_MAX_QUEUE");
        let project = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        let existing = root.join("existing.txt");
        std::fs::write(&existing, b"original").unwrap();
        let missing = root.join("missing.txt");
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        unsafe {
            ibex_private_test_reset_fs_conformance_observer();
            ibex_private_test_set_requested_fs_authorization_result(
                crate::host::abi::EX_HOST_VFS_RESULT_POLICY_DENIED as i32,
            );
        }
        engine
            .eval(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__committedPolicyFailureCode = 'pending';
                  __exactFsWriteFileAsync(
                    '/project/existing.txt', 'replacement', 'w', 438, false)
                    .catch(function(error) {
                      globalThis.__committedPolicyFailureCode = error.code;
                    });
                  return 'scheduled';
                })()"#,
            )
            .await
            .unwrap();
        unsafe { ibex_private_test_reset_fs_conformance_observer() };
        assert_eq!(
            engine
                .eval_immediate("String(globalThis.__committedPolicyFailureCode)")
                .await
                .unwrap()
                .as_deref(),
            Some("EACCES")
        );
        assert_eq!(std::fs::read(&existing).unwrap(), b"original");

        engine
            .eval(
                r#"(function() {
                  globalThis.__committedMissingFailureCode = 'pending';
                  __exactFsWriteFileAsync(
                    '/project/missing.txt', 'replacement', 'r+', 438, false)
                    .catch(function(error) {
                      globalThis.__committedMissingFailureCode = error.code;
                    });
                  return 'scheduled';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(
            engine
                .eval_immediate("String(globalThis.__committedMissingFailureCode)")
                .await
                .unwrap()
                .as_deref(),
            Some("ENOENT")
        );
        assert!(!missing.exists());
    }

    /// Regression for the Exact-reported real-input carrier defect (Exact
    /// `issues/20260805-input-dispatch-no-user-carrier-...`): a host input
    /// event delivered through `ex_hermes_dispatch_event` must run under the
    /// standard runtime entry boundary, so a granted first-party capability
    /// op succeeds identically (a) directly in the activation's promise
    /// reaction, (b) nested through the resulting native async completion,
    /// and (c) detached across `setTimeout(0)` — with no capability denial
    /// recorded. Before the drive guard, this harness produced
    /// `ERR_IBEX_STALE_SESSION` (no Host session was ever entered).
    ///
    /// The complementary no-shed direction (a constrained carrier must stay
    /// constrained across the same hop) is pinned by `__deputyTimerResult`
    /// in `src/engine/runtime_extension_conformance_tests.rs`.
    /// @ref LLP 0051#acceptance-evidence — positive input A/B witness
    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn input_dispatch_entry_grants_first_party_capabilities_across_hops() {
        let _guard = hermes_engine_test_lock().lock().await;
        let project = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        std::fs::write(root.join("existing.txt"), b"payload").unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        engine
            .eval(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__abResults = {
                    direct: 'pending',
                    hop: 'pending',
                    nested: 'pending',
                    handler: 'pending'
                  };
                  var probe = function(slot, next) {
                    try {
                      __exactFsReadFileAsync('/project/existing.txt', 'r', 0, null).then(
                        function() {
                          globalThis.__abResults[slot] = 'granted';
                          if (next) next();
                        },
                        function(error) {
                          globalThis.__abResults[slot] =
                            'denied:' + String(error && (error.code || error.message));
                          if (next) next();
                        });
                    } catch (error) {
                      globalThis.__abResults[slot] =
                        'threw:' + String(error && error.message);
                      if (next) next();
                    }
                  };
                  globalThis.__exactDispatchEvent = function(id, payload) {
                    globalThis.__abResults.handler = 'ran';
                    Promise.resolve().then(function() {
                      probe('direct', function() { probe('nested', null); });
                    });
                    setTimeout(function() { probe('hop', null); }, 0);
                  };
                  return 'installed';
                })()"#,
            )
            .await
            .unwrap();

        let runtime = engine.ensure_runtime().await.unwrap();
        let _ = crate::host::abi::take_installed_conformance_observations();
        runtime
            .with_runtime(|raw| {
                let dispatched = unsafe { ex_hermes_dispatch_event(raw, 1, std::ptr::null()) };
                assert_eq!(dispatched, 0, "dispatch_event failed");
            })
            .unwrap();
        let mut outcome = String::new();
        for _ in 0..100 {
            runtime
                .with_runtime(|raw| {
                    let _ = unsafe { ex_hermes_poll(raw, current_time_ms() + 50) };
                })
                .unwrap();
            outcome = engine
                .eval_immediate("JSON.stringify(globalThis.__abResults)")
                .await
                .unwrap()
                .unwrap();
            if !outcome.contains("pending") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let parsed: serde_json::Value = serde_json::from_str(&outcome).unwrap();
        assert_eq!(parsed["handler"], "ran", "the dispatch handler never ran");
        assert_eq!(parsed["direct"], "granted", "direct-chain op outcome");
        assert_eq!(parsed["nested"], "granted", "nested-chain op outcome");
        assert_eq!(parsed["hop"], "granted", "setTimeout-hop op outcome");

        // No legacy capability denial may be recorded for the activation
        // (the armed typed plane's positive gate-liveness control is the
        // withheld-authority sibling test below).
        let (legacy, _typed) = crate::host::abi::take_installed_conformance_observations();
        let denials: Vec<_> = legacy
            .iter()
            .filter(|decision| !decision.allowed)
            .map(|decision| decision.capability.clone())
            .collect();
        assert!(
            denials.is_empty(),
            "input-seeded chain recorded capability denials: {denials:?}"
        );
    }

    /// Gate-liveness control for the positive A/B above: the identical
    /// dispatch-seeded probe with read authority withheld must be DENIED on
    /// every leg, proving the grants in the positive test are real decisions
    /// by a live gate rather than an absence of checks.
    /// @ref LLP 0051#acceptance-evidence — positive input A/B witness
    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn input_dispatch_probe_is_gated_when_read_authority_is_withheld() {
        let _guard = hermes_engine_test_lock().lock().await;
        let project = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        std::fs::write(root.join("existing.txt"), b"payload").unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        engine
            .eval(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__abResults = {
                    direct: 'pending',
                    hop: 'pending',
                    handler: 'pending'
                  };
                  var probe = function(slot) {
                    try {
                      __exactFsReadFileAsync('/project/existing.txt', 'r', 0, null).then(
                        function() { globalThis.__abResults[slot] = 'granted'; },
                        function(error) {
                          globalThis.__abResults[slot] =
                            'denied:' + String(error && (error.code || error.message));
                        });
                    } catch (error) {
                      globalThis.__abResults[slot] =
                        'denied-sync:' + String(error && error.message);
                    }
                  };
                  globalThis.__exactDispatchEvent = function(id, payload) {
                    globalThis.__abResults.handler = 'ran';
                    Promise.resolve().then(function() { probe('direct'); });
                    setTimeout(function() { probe('hop'); }, 0);
                  };
                  return 'installed';
                })()"#,
            )
            .await
            .unwrap();

        let runtime = engine.ensure_runtime().await.unwrap();
        runtime
            .with_runtime(|raw| {
                let dispatched = unsafe { ex_hermes_dispatch_event(raw, 1, std::ptr::null()) };
                assert_eq!(dispatched, 0, "dispatch_event failed");
            })
            .unwrap();
        let mut outcome = String::new();
        for _ in 0..100 {
            runtime
                .with_runtime(|raw| {
                    let _ = unsafe { ex_hermes_poll(raw, current_time_ms() + 50) };
                })
                .unwrap();
            outcome = engine
                .eval_immediate("JSON.stringify(globalThis.__abResults)")
                .await
                .unwrap()
                .unwrap();
            if !outcome.contains("pending") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let parsed: serde_json::Value = serde_json::from_str(&outcome).unwrap();
        assert_eq!(parsed["handler"], "ran", "the dispatch handler never ran");
        for slot in ["direct", "hop"] {
            let value = parsed[slot].as_str().unwrap_or("missing");
            assert!(
                value.starts_with("denied"),
                "withheld-authority {slot} probe was not denied: {value}"
            );
        }
    }

    /// Runtime admission at the input ingress: `ex_hermes_dispatch_event` must
    /// refuse a stale generation rather than dereferencing it. (Owner-thread
    /// refusal is enforced by the same guard; `with_runtime` already asserts
    /// owner-thread affinity in this harness, so the reachable admission
    /// witness here is the post-shutdown generation.)
    /// @ref LLP 0051#acceptance-evidence — admission tests
    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn input_dispatch_refuses_a_stale_runtime_generation() {
        let _guard = hermes_engine_test_lock().lock().await;
        let project = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine
            .eval("globalThis.__exactDispatchEvent = function() {}; 'installed'")
            .await
            .unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let stale_address = runtime
            .with_runtime(|raw| raw as usize)
            .expect("runtime pointer");
        assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
        let refused = unsafe {
            ex_hermes_dispatch_event(
                stale_address as *mut HermesRuntimeOpaque,
                1,
                std::ptr::null(),
            )
        };
        assert_eq!(
            refused, -1,
            "input dispatch admitted a destroyed runtime generation"
        );
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn lane_c_a2_facades_close_over_separate_loaded_target_edges() {
        use std::collections::BTreeSet;
        use std::os::unix::fs::PermissionsExt;

        let _guard = hermes_engine_test_lock().lock().await;
        let project = tempfile::tempdir().unwrap();
        let bin = project.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let tool = bin.join("lane-c-a2-tool");
        std::fs::write(&tool, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&tool).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&tool, permissions).unwrap();
        std::fs::write(project.path().join("handle-input.txt"), b"lane-c-a2").unwrap();
        std::fs::write(
            project.path().join("lane-c-a2-module.cjs"),
            b"module.exports = 'lane-c-a2';\n",
        )
        .unwrap();
        let referrer = project.path().join("lane-c-a2-entry.cjs");
        std::fs::write(
            &referrer,
            b"module.exports = require('./lane-c-a2-module.cjs');\n",
        )
        .unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        let referrer = std::fs::canonicalize(referrer).unwrap();
        let (host, digest) = build_armed_test_host_custom(
            Some(&root),
            true,
            true,
            true,
            Vec::new(),
            None,
            |snapshot| {
                snapshot["bootstrapCompatibilityModes"] = serde_json::json!(["bun"]);
            },
        );
        let resolver_host = host.clone();
        assert_ne!(crate::host::abi::install_host(host), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let topology = engine
            .eval_immediate(
                r#"JSON.stringify((function () {
                  var privateNames = [
                    '__exactModuleResolve',
                    '__exactModuleResolveMeta',
                    '__exactNativeModuleResolve',
                    '__exactNativeModuleResolveMeta'
                  ];
                  return {
                    privateResolversAbsent: privateNames.every(function (name) {
                      return Object.getOwnPropertyDescriptor(globalThis, name) === undefined;
                    }),
                    bunIsExact: Bun === Exact,
                    whichAliasIdentity: Bun.which === Exact.which,
                    writeAliasIdentity: Bun.write === Exact.write,
                    importAliasIdentity: globalThis['import'] === globalThis.importModule,
                    publicTypes: [
                      typeof Exact.which,
                      typeof Exact.write,
                      typeof Ibex.fs.readHandle,
                      typeof globalThis['import'],
                      typeof globalThis.importModule,
                      typeof globalThis.require,
                      typeof globalThis.require.resolve
                    ]
                  };
                })())"#,
            )
            .await
            .unwrap()
            .unwrap();
        let topology: serde_json::Value = serde_json::from_str(&topology).unwrap();
        assert_eq!(topology["privateResolversAbsent"], true);
        assert_eq!(topology["bunIsExact"], true);
        assert_eq!(topology["whichAliasIdentity"], true);
        assert_eq!(topology["writeAliasIdentity"], true);
        assert_eq!(topology["importAliasIdentity"], true);
        assert_eq!(
            topology["publicTypes"],
            serde_json::json!([
                "function", "function", "function", "function", "function", "function", "function"
            ])
        );

        let mut observations = Vec::new();

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "lane-c-a2:Exact.which"
        ));
        let which_result = engine
            .eval_immediate("Exact.which('/project/bin/lane-c-a2-tool')")
            .await
            .unwrap();
        assert_eq!(which_result.as_deref(), Some("/project/bin/lane-c-a2-tool"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        let which_edges = typed
            .iter()
            .flat_map(|row| row.gates.iter())
            .map(|gate| gate.coverage_edge_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            which_edges,
            BTreeSet::from(["surface.native.op.exactwhich.0it66ce".to_owned()])
        );
        observations.push(serde_json::json!({
            "path": "Exact.which / Bun.which (same loaded function)",
            "typedDecisionCount": typed.len(),
            "coverageEdgeIds": which_edges,
        }));

        let _ = crate::host::abi::take_installed_conformance_observations();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "lane-c-a2:Exact.write"
        ));
        let write_result = engine
            .eval_immediate("Exact.write('/project/lane-c-a2-write.txt', 'written'); 'started'")
            .await
            .unwrap();
        assert_eq!(write_result.as_deref(), Some("started"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        let write_edges = typed
            .iter()
            .flat_map(|row| row.gates.iter())
            .map(|gate| gate.coverage_edge_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            write_edges,
            BTreeSet::from(["surface.native.op.exactwritefile.1h0gy8u".to_owned()])
        );
        observations.push(serde_json::json!({
            "path": "Exact.write / Bun.write (same loaded function)",
            "typedDecisionCount": typed.len(),
            "coverageEdgeIds": write_edges,
        }));

        for (label, method) in [
            ("readFileSync", "readFileSync"),
            ("readTextSync", "readTextSync"),
        ] {
            let _ = crate::host::abi::take_installed_conformance_observations();
            assert!(crate::host::abi::begin_installed_conformance_observation(
                &format!("lane-c-a2:Ibex.fs.readHandle.{label}")
            ));
            let result = engine
                .eval_immediate(&format!(
                    r#"(function () {{
                      try {{
                        var handle = Ibex.fs.readHandle('/project');
                        handle.{method}('/project/handle-input.txt');
                        return 'unexpected-success';
                      }} catch (error) {{
                        return String(error && error.message || error);
                      }}
                    }})()"#
                ))
                .await
                .unwrap()
                .unwrap();
            assert!(result.contains("Permission denied"), "{label}: {result}");
            let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
            assert!(legacy.is_empty());
            assert!(typed.is_empty());
            observations.push(serde_json::json!({
                "path": format!("Ibex.fs.readHandle.[[return]].{label}"),
                "result": result,
                "typedDecisionCount": 0,
                "coverageEdgeIds": [],
            }));
        }

        resolver_host.begin_conformance_observation("lane-c-a2:captured-resolver-host");
        let resolved = resolver_host
            .resolve_module_meta_for_principal("./lane-c-a2-module.cjs", Some(&referrer), Some("0"))
            .unwrap();
        assert_eq!(
            resolved.path.as_deref(),
            Some(root.join("lane-c-a2-module.cjs").as_path())
        );
        let typed = resolver_host.take_typed_conformance_observations();
        let resolver_edges = typed
            .iter()
            .flat_map(|row| row.gates.iter())
            .map(|gate| gate.coverage_edge_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        assert!(!resolver_edges.is_empty());
        assert!(resolver_edges.iter().all(|edge| {
            edge == "surface.loader.require.resolve.12c9l9i"
                || edge == "surface.native.op.exactreadfile.1cmzco7"
        }));
        observations.push(serde_json::json!({
            "path": "loaded require.resolve closure -> captured metadata resolver host",
            "typedDecisionCount": typed.len(),
            "coverageEdgeIds": resolver_edges,
        }));

        eprintln!(
            "LANE_C_A2_LOADED_TARGET_EVIDENCE={}",
            serde_json::to_string(&serde_json::json!({
                "topology": topology,
                "observations": observations,
            }))
            .unwrap()
        );
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_which_uses_overlay_then_vfs_and_preserves_logical_spelling() {
        use capsec_semantics::model::Stage;
        use std::os::unix::fs::PermissionsExt;

        let _guard = hermes_engine_test_lock().lock().await;
        let project = tempfile::tempdir().unwrap();
        let bin = project.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let tool = bin.join("ibex-which-fixture");
        std::fs::write(&tool, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&tool).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&tool, permissions).unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        let environment_floors = vec![
            serde_json::json!({
                "cap": "env:read",
                "resource": {
                    "kind": "environment-name",
                    "target": "principal-overlay",
                    "name": "PATH"
                }
            }),
            serde_json::json!({
                "cap": "env:write",
                "resource": {
                    "kind": "environment-name",
                    "target": "principal-overlay",
                    "name": "PATH"
                }
            }),
        ];
        let (_reset, digest) =
            install_armed_test_host_at(Some(&root), false, false, true, environment_floors);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        assert_eq!(
            engine
                .eval_immediate(
                    "__exactSetEnv('PATH', '/project/bin'); \
                     if (typeof __exactWhich !== 'function' && \
                         typeof __exactEnsureChildProcess === 'function') { \
                       __exactEnsureChildProcess(); \
                     } \
                     if (typeof __exactWhich !== 'function') throw new Error('which missing'); \
                     'ready'",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("ready")
        );

        let _ = crate::host::abi::take_installed_conformance_observations();
        unsafe { ibex_private_test_reset_fs_conformance_observer() };
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.exactwhich.0it66ce"
        ));
        let bare = engine
            .eval_immediate("__exactWhich('ibex-which-fixture')")
            .await
            .unwrap();
        assert_eq!(bare.as_deref(), Some("/project/bin/ibex-which-fixture"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "typed which must not consult the legacy oracle"
        );
        assert!(
            typed.len() >= 4,
            "PATH plus retained VFS stages must be observed"
        );
        assert_eq!(
            typed[..2]
                .iter()
                .map(|row| (
                    row.decision_set.context.stage,
                    row.decision_set.effects[0].action.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![(Stage::Requested, "env:read"), (Stage::Commit, "env:read")],
            "PATH must authorize before candidate discovery"
        );
        assert_eq!(typed[2].decision_set.context.stage, Stage::Requested);
        assert!(typed[2..]
            .iter()
            .all(|row| row.decision_set.effects[0].action.as_str() == "fs:list"));
        assert!(typed[2..]
            .iter()
            .any(|row| row.decision_set.context.stage == Stage::Discovery));
        assert!(typed.iter().all(|row| row.gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactwhich.0it66ce"
        })));
        assert!(unsafe { ibex_private_test_armed_path_lookup_count() } > 0);
        assert_eq!(
            unsafe { ibex_private_test_armed_path_lookup_after_refusal_count() },
            0
        );

        let _ = crate::host::abi::take_installed_conformance_observations();
        unsafe { ibex_private_test_reset_fs_conformance_observer() };
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.exactwhich.0it66ce"
        ));
        let direct = engine
            .eval_immediate("__exactWhich('/project/bin/ibex-which-fixture')")
            .await
            .unwrap();
        assert_eq!(direct.as_deref(), Some("/project/bin/ibex-which-fixture"));
        let (legacy, direct_typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert!(!direct_typed.is_empty());
        assert!(direct_typed
            .iter()
            .all(|row| row.decision_set.effects[0].action.as_str() == "fs:list"));
        assert!(direct_typed.iter().all(|row| row.gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactwhich.0it66ce"
        })));
        unsafe { ibex_private_test_reset_fs_conformance_observer() };
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_which_refuses_each_branch_before_discovery_without_grants() {
        use capsec_semantics::model::Stage;

        let _guard = hermes_engine_test_lock().lock().await;
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("bin")).unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        let write_path = serde_json::json!({
            "cap": "env:write",
            "resource": {
                "kind": "environment-name",
                "target": "principal-overlay",
                "name": "PATH"
            }
        });
        let (host, digest) = build_armed_test_host_custom(
            Some(&root),
            false,
            false,
            false,
            vec![write_path],
            None,
            |snapshot| {
                snapshot["principals"][0]["denials"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({
                        "cap": "env:read",
                        "resource": {
                            "kind": "environment-name",
                            "target": "principal-overlay",
                            "name": "PATH"
                        }
                    }));
            },
        );
        assert_ne!(crate::host::abi::install_host(host), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine
            .eval_immediate(
                "__exactSetEnv('PATH', '/project/bin'); \
                 if (typeof __exactWhich !== 'function' && \
                     typeof __exactEnsureChildProcess === 'function') { \
                   __exactEnsureChildProcess(); \
                 } \
                 if (typeof __exactWhich !== 'function') throw new Error('which missing'); \
                 'ready'",
            )
            .await
            .unwrap();

        let _ = crate::host::abi::take_installed_conformance_observations();
        unsafe { ibex_private_test_reset_fs_conformance_observer() };
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.exactwhich.0it66ce"
        ));
        let bare = engine
            .eval_immediate(
                "try { __exactWhich('missing-tool'); 'allowed' } \
                 catch (_) { 'denied' }",
            )
            .await
            .unwrap();
        assert_eq!(bare.as_deref(), Some("denied"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(typed[0].decision_set.effects[0].action.as_str(), "env:read");
        assert_eq!(unsafe { ibex_private_test_armed_path_lookup_count() }, 0);
        assert_eq!(
            unsafe { ibex_private_test_armed_path_lookup_after_refusal_count() },
            0
        );

        unsafe { ibex_private_test_reset_fs_conformance_observer() };
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.exactwhich.0it66ce"
        ));
        let direct = engine
            .eval_immediate(
                "try { __exactWhich('/project/bin/missing-tool'); 'allowed' } \
                 catch (_) { 'denied' }",
            )
            .await
            .unwrap();
        assert_eq!(direct.as_deref(), Some("denied"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(typed[0].decision_set.effects[0].action.as_str(), "fs:list");
        assert_eq!(unsafe { ibex_private_test_armed_path_lookup_count() }, 0);
        assert_eq!(
            unsafe { ibex_private_test_armed_path_lookup_after_refusal_count() },
            0
        );
        unsafe { ibex_private_test_reset_fs_conformance_observer() };
    }

    #[cfg(all(unix, feature = "insecure"))]
    #[tokio::test(flavor = "current_thread")]
    async fn insecure_which_keeps_ambient_host_path_lookup() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = hermes_engine_test_lock().lock().await;
        let directory = tempfile::tempdir().unwrap();
        let tool = directory.path().join("ibex-insecure-which-fixture");
        std::fs::write(&tool, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&tool).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&tool, permissions).unwrap();
        let _path = TestEnvVar::set("PATH", directory.path().to_str().unwrap());
        crate::host::abi::install_host(crate::host::Host::default_legacy());
        let engine = HermesEngine::new().unwrap();
        let actual = engine
            .eval_immediate(
                "if (typeof __exactWhich !== 'function' && \
                     typeof __exactEnsureChildProcess === 'function') { \
                   __exactEnsureChildProcess(); \
                 } \
                 __exactWhich('ibex-insecure-which-fixture')",
            )
            .await
            .unwrap();
        assert_eq!(
            actual.as_deref(),
            Some(std::fs::canonicalize(tool).unwrap().to_str().unwrap())
        );
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_requested_denial_and_outside_path_cross_no_lookup_syscall() {
        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        unsafe { ibex_private_test_reset_fs_conformance_observer() };
        let closed = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  try { __exactUnlink('/project/../outside-missing'); }
                  catch (error) { return JSON.stringify({ code: error.code }); }
                  return JSON.stringify({ code: 'unexpected-success' });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&closed).unwrap()["code"],
            "EPERM",
            "closed operation must precede outside-mount and absence"
        );
        assert_eq!(unsafe { ibex_private_test_armed_path_lookup_count() }, 0);
        assert_eq!(
            unsafe { ibex_private_test_armed_path_lookup_after_refusal_count() },
            0
        );

        // Positive control: with requested authorization allowed, a missing
        // path crosses an instrumented lookup boundary before producing
        // ENOENT.
        unsafe { ibex_private_test_reset_fs_conformance_observer() };
        let absent = engine
            .eval_immediate(
                r#"(function() {
                  try { __exactReadFile('/project/definitely-missing'); }
                  catch (error) { return JSON.stringify({ code: error.code }); }
                  return JSON.stringify({ code: 'unexpected-success' });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&absent).unwrap()["code"],
            "ENOENT"
        );
        assert!(unsafe { ibex_private_test_armed_path_lookup_count() } > 0);

        unsafe {
            ibex_private_test_reset_fs_conformance_observer();
            ibex_private_test_set_requested_fs_authorization_result(
                crate::host::abi::EX_HOST_VFS_RESULT_POLICY_DENIED as i32,
            );
        }
        let denied = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  try { __exactReadFile('/project/definitely-missing'); }
                  catch (error) { return JSON.stringify({ code: error.code }); }
                  return JSON.stringify({ code: 'unexpected-success' });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&denied).unwrap()["code"],
            "EACCES"
        );
        assert_eq!(unsafe { ibex_private_test_armed_path_lookup_count() }, 0);

        unsafe { ibex_private_test_reset_fs_conformance_observer() };
        let outside = engine
            .eval_immediate(
                r#"(function() {
                  try { __exactReadFile('/project/../outside-missing'); }
                  catch (error) { return JSON.stringify({ code: error.code }); }
                  return JSON.stringify({ code: 'unexpected-success' });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&outside).unwrap()["code"],
            "ERR_IBEX_OUTSIDE_MOUNT"
        );
        assert_eq!(unsafe { ibex_private_test_armed_path_lookup_count() }, 0);
        unsafe { ibex_private_test_reset_fs_conformance_observer() };
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn armed_discovered_denied_absent_target_is_not_probed() {
        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        std::os::unix::fs::symlink("denied-missing", root.join("link")).unwrap();
        let denied_target =
            std::ffi::CString::new(root.join("denied-missing").as_os_str().as_encoded_bytes())
                .unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        unsafe {
            ibex_private_test_reset_fs_conformance_observer();
            ibex_private_test_set_requested_fs_authorization_result_for_path(
                crate::host::abi::EX_HOST_VFS_RESULT_POLICY_DENIED as i32,
                denied_target.as_ptr(),
            );
        }
        let result = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  try { __exactReadFile('/project/link'); }
                  catch (error) { return JSON.stringify({ code: error.code }); }
                  return JSON.stringify({ code: 'unexpected-success' });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&result).unwrap()["code"],
            "EACCES"
        );
        assert!(
            unsafe { ibex_private_test_armed_path_lookup_count() } > 0,
            "the allowed link stage must reach its authenticated lookup"
        );
        assert_eq!(
            unsafe { ibex_private_test_armed_path_lookup_after_refusal_count() },
            0,
            "the absent discovered target must not be looked up after denial"
        );
        unsafe { ibex_private_test_reset_fs_conformance_observer() };
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn fs_enqueue_exception_releases_runtime_pin_before_destroy() {
        const CHILD_ENV: &str = "IBEX_TEST_FS_ENQUEUE_SHUTDOWN_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::fs_enqueue_exception_releases_runtime_pin_before_destroy";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        struct EnvReset;
        impl Drop for EnvReset {
            fn drop(&mut self) {
                std::env::remove_var("IBEX_TEST_FS_WORKER_THROW_ENQUEUE");
            }
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let file = tempdir.path().join("read.txt");
        fs::write(&file, b"data").unwrap();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let engine = HermesEngine::new().unwrap();
        // The closed-startup check has already run. This control exists only
        // for deterministic post-construction native failure injection.
        std::env::set_var("IBEX_TEST_FS_WORKER_THROW_ENQUEUE", "1");
        let _reset = EnvReset;
        engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__enqueueFailure = 'pending';
                  __exactFsReadFileAsync({:?}, 'r', 0).then(
                    function() {{ globalThis.__enqueueFailure = 'unexpected-success'; }},
                    function() {{ globalThis.__enqueueFailure = 'rejected'; }}
                  );
                  return 'started';
                }})()"#,
                file.to_str().unwrap()
            ))
            .await
            .unwrap();
        std::env::remove_var("IBEX_TEST_FS_WORKER_THROW_ENQUEUE");
        let shared = engine.runtime.lock().await.as_ref().unwrap().shared();
        // Shutdown executes on the runtime owner thread. The parent test
        // process supplies the deadline so a leaked pin cannot hang this suite.
        assert_eq!(shared.shutdown(), RuntimeShutdown::Destroyed);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    #[cfg(not(feature = "insecure"))]
    async fn diagnostic_allow_all_cannot_use_or_close_an_armed_runtime_fd_or_socket() {
        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let file = root.join("armed-owned.txt");
        fs::write(&file, b"armed").unwrap();
        let virtual_file = "/project/armed-owned.txt";
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let armed = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let handles = armed
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                  return JSON.stringify({{
                    fd: __exactFsOpen({path:?}, 'r'),
                    socket: __exactUdpSocket('udp4')
                  }});
                }})()"#,
                path = virtual_file,
            ))
            .await
            .unwrap()
            .unwrap();
        let handles: serde_json::Value = serde_json::from_str(&handles).unwrap();
        let fd = handles["fd"].as_i64().unwrap();
        let socket = handles["socket"].as_i64().unwrap();

        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let diagnostic = HermesEngine::new().unwrap();
        let denied = diagnostic
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                  var denied = 0;
                  try {{ __exactFsRead({fd}, 1, -1); }} catch (_) {{ denied++; }}
                  try {{ __exactFsClose({fd}); }} catch (_) {{ denied++; }}
                  try {{ __exactUdpClose({socket}); }} catch (_) {{ denied++; }}
                  return String(denied);
                }})()"#,
            ))
            .await
            .unwrap();
        assert_eq!(denied.as_deref(), Some("3"));

        let owner_result = armed
            .eval_immediate(&format!(
                r#"(function() {{
                  var text = String.fromCharCode.apply(null, __exactFsRead({fd}, 5, -1));
                  __exactFsClose({fd});
                  __exactUdpClose({socket});
                  return text;
                }})()"#,
            ))
            .await
            .unwrap();
        assert_eq!(owner_result.as_deref(), Some("armed"));
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_cannot_use_or_close_diagnostic_sqlite_handles() {
        let _guard = hermes_engine_test_lock().lock().await;
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let owner = HermesEngine::new().unwrap();
        let handles = owner
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureSqlite === 'function') __exactEnsureSqlite();
                  var db = __exactSqliteOpen(':memory:', null);
                  var statement = __exactSqlitePrepare(db, 'SELECT 1 AS value');
                  globalThis.__ownedSqliteDb = db;
                  globalThis.__ownedSqliteStatement = statement.handle;
                  return JSON.stringify({ db: db, statement: statement.handle });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap();
        let handles: serde_json::Value = serde_json::from_str(&handles).unwrap();
        let db = handles["db"].as_u64().unwrap();
        let statement = handles["statement"].as_u64().unwrap();

        let (_reset, digest) = install_armed_test_host();
        let intruder = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let denied = intruder
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureSqlite === 'function') __exactEnsureSqlite();
                  var denied = 0;
                  try {{ __exactSqliteInTransaction({db}); }} catch (_) {{ denied++; }}
                  try {{ __exactSqliteExpandedSql({statement}); }} catch (_) {{ denied++; }}
                  try {{ __exactSqliteFinalize({statement}); }} catch (_) {{ denied++; }}
                  try {{ __exactSqliteClose({db}); }} catch (_) {{ denied++; }}
                  return String(denied);
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(denied.as_deref(), Some("4"));

        let owner_result = owner
            .eval_immediate(
                r#"(function() {
                  var sql = __exactSqliteExpandedSql(globalThis.__ownedSqliteStatement);
                  __exactSqliteFinalize(globalThis.__ownedSqliteStatement);
                  __exactSqliteClose(globalThis.__ownedSqliteDb);
                  return sql;
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(owner_result.as_deref(), Some("SELECT 1 AS value"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_one_runtime_fetch_never_cancels_another_runtime_request() {
        let _guard = hermes_engine_test_lock().lock().await;

        struct HeldServer {
            url: String,
            accepted: std::sync::mpsc::Receiver<()>,
            release: std::sync::mpsc::Sender<()>,
            join: std::thread::JoinHandle<()>,
        }
        fn held_server(body: &'static str) -> HeldServer {
            use std::io::{Read as _, Write as _};
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (accepted_tx, accepted) = std::sync::mpsc::channel();
            let (release, release_rx) = std::sync::mpsc::channel();
            let join = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                accepted_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
            });
            HeldServer {
                url: format!("http://127.0.0.1:{port}/"),
                accepted,
                release,
                join,
            }
        }

        let first_server = held_server("first");
        let second_server = held_server("second");
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let first = HermesEngine::new().unwrap();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let second = HermesEngine::new().unwrap();

        for (engine, url, name) in [
            (&first, first_server.url.as_str(), "first"),
            (&second, second_server.url.as_str(), "second"),
        ] {
            let started = engine
                .eval_immediate(&format!(
                    r#"globalThis.__fetchState = 'pending';
                       globalThis.__fetchPromise = __nativeFetch({url:?}, {{}});
                       globalThis.__fetchPromise.then(
                         function(response) {{ globalThis.__fetchState = 'ok:' + response.status; }},
                         function(error) {{ globalThis.__fetchState = 'error:' + String(error); }}
                       );
                       {name:?};"#
                ))
                .await
                .unwrap();
            assert_eq!(started.as_deref(), Some(name));
        }
        first_server
            .accepted
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        second_server
            .accepted
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();

        first
            .eval_immediate("globalThis.__fetchPromise.__exactCancel(); 'cancelled';")
            .await
            .unwrap();
        second_server.release.send(()).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let second_state = loop {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                second.drive_event_loop(),
            )
            .await;
            let state = second
                .eval_immediate("globalThis.__fetchState")
                .await
                .unwrap()
                .unwrap_or_default();
            if state != "pending" || std::time::Instant::now() >= deadline {
                break state;
            }
        };
        assert_eq!(second_state, "ok:200");

        first_server.release.send(()).unwrap();
        first_server.join.join().unwrap();
        second_server.join.join().unwrap();
    }

    #[cfg(all(feature = "host-http-server", feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_http_serve_authorizes_requested_and_committed_listener() {
        let _guard = hermes_engine_test_lock().lock().await;
        let floor = serde_json::json!({
            "cap": "network:listen",
            "resource": {
                "kind": "listen-inet",
                "transport": "tcp",
                "bind": {"kind": "loopback"},
                "port": {"kind": "ephemeral"},
                "dualStack": false,
                "peerClasses": ["loopback"]
            }
        });
        let (_reset, digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "native.http.typed-listen"
        ));
        let served = engine
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
                  return __exactHttpServe(0, '127.0.0.1');
                })()"#,
            )
            .await
            .unwrap()
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&served).unwrap();
        assert!(
            payload.get("error").is_none(),
            "server setup failed: {payload}"
        );
        let server_id = payload["id"].as_u64().unwrap();
        let bound_port = payload["port"].as_u64().unwrap();

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert_eq!(typed.len(), 2, "serve must authorize Requested then Commit");
        assert_eq!(
            typed[0].decision_set.context.stage,
            capsec_semantics::model::Stage::Requested
        );
        assert_eq!(
            typed[1].decision_set.context.stage,
            capsec_semantics::model::Stage::Commit
        );
        assert!(typed.iter().all(|decision| {
            decision.evidence.outcome == capsec_semantics::decision::DecisionOutcome::Allow
                && decision.gates[0].coverage_edge_id.as_str()
                    == "surface.native.op.exacthttpserve.1eq8wio"
        }));
        let committed = serde_json::to_value(&typed[1].decision_set.effects[0].resource).unwrap();
        assert_eq!(committed["boundEndpoints"][0]["address"], "127.0.0.1");
        assert_eq!(committed["boundEndpoints"][0]["port"], bound_port);
        let listener_id = committed["listenerId"].as_str().unwrap();
        assert!(listener_id.starts_with("http-listener:"));
        assert!(listener_id.ends_with(&format!(":{server_id}")));

        engine
            .eval_immediate(&format!("__exactHttpClose({server_id}, 1); 'closed'"))
            .await
            .unwrap();
    }

    #[cfg(all(feature = "host-http-server", feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_cannot_use_or_close_diagnostic_http_server() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:listen:127.0.0.1:0"]);
        let owner = HermesEngine::new().unwrap();
        let server = eval_json(
            &owner,
            r#"(function() {
              if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
              var result = JSON.parse(__exactHttpServe(0, '127.0.0.1'));
              globalThis.__ownedHttpServer = result.id;
              return JSON.stringify(result);
            })()"#,
        )
        .await;
        let server_id = server["id"].as_u64().unwrap();

        let (_reset, digest) = install_armed_test_host();
        let intruder = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let denied = intruder
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
                  var denied = 0;
                  try {{ __exactHttpAddress({server_id}); }} catch (_) {{ denied++; }}
                  try {{ __exactHttpSetRef({server_id}, 0); }} catch (_) {{ denied++; }}
                  try {{ __exactHttpClose({server_id}, 1); }} catch (_) {{ denied++; }}
                  return String(denied);
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(denied.as_deref(), Some("3"));

        let owner_result = owner
            .eval_immediate(
                r#"(function() {
                  var address = __exactHttpAddress(globalThis.__ownedHttpServer);
                  __exactHttpClose(globalThis.__ownedHttpServer, 1);
                  return address === null ? 'missing' : 'closed';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(owner_result.as_deref(), Some("closed"));
    }

    #[cfg(feature = "host-http-server")]
    #[tokio::test(flavor = "current_thread")]
    async fn http_wait_timeout_is_not_starved_by_existing_waiters() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:listen:127.0.0.1:0"]);
        let _idle_delay = TestEnvVar::set("IBEX_TEST_HTTP_WAIT_IDLE_DELAY_MS", "250");
        let engine = HermesEngine::new().unwrap();

        let setup = eval_json(
            &engine,
            r#"(function() {
                if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
                var result = JSON.parse(__exactHttpServe(0, '127.0.0.1'));
                if (result.error) {
                  return JSON.stringify({ error: result.error });
                }
                __exactHttpSetRef(result.id, 0);
                globalThis.__exactWaitServerId = result.id;
                globalThis.__exactWaitStatus = 'pending';
                __exactHttpWait(result.id, 10).then(function(value) {
                  globalThis.__exactWaitStatus = value === null ? 'warm' : 'request';
                }).catch(function(err) {
                  globalThis.__exactWaitStatus =
                    'error:' + String(err && err.message ? err.message : err);
                });
                return JSON.stringify({ ok: true });
            })()"#,
        )
        .await;

        assert!(setup.get("error").is_none(), "server setup failed: {setup}");
        let warmed = wait_for_exact_wait_status(&engine).await;
        assert_eq!(
            warmed.get("status").and_then(serde_json::Value::as_str),
            Some("warm"),
            "warm-up wait should create an idle native worker: {warmed}",
        );

        // Let the completed worker return to the pool's idle wait before the
        // synchronous burst below. This is the state that used to strand the
        // finite wait behind the first unbounded wait: every enqueue observed
        // one idle worker even though that worker was already owed to an older
        // queued task.
        sleep(Duration::from_millis(25)).await;
        let burst = eval_json(
            &engine,
            r#"(function() {
                globalThis.__exactWaitStatus = 'pending';
                globalThis.__exactWaitKeepAlive = [
                  __exactHttpWait(globalThis.__exactWaitServerId, 0),
                  __exactHttpWait(globalThis.__exactWaitServerId, 0),
                  __exactHttpWait(globalThis.__exactWaitServerId, 0),
                  __exactHttpWait(globalThis.__exactWaitServerId, 0)
                ];
                __exactHttpWait(globalThis.__exactWaitServerId, 50).then(function(value) {
                  globalThis.__exactWaitStatus = value === null ? 'timeout' : 'request';
                }).catch(function(err) {
                  globalThis.__exactWaitStatus =
                    'error:' + String(err && err.message ? err.message : err);
                });
                return JSON.stringify({ ok: true });
            })()"#,
        )
        .await;

        assert_eq!(
            burst.get("ok").and_then(serde_json::Value::as_bool),
            Some(true)
        );

        // CI runners can start the native wait task after the fixed pre-sleep,
        // so observe the JS-visible terminal state instead of assuming a
        // single pump has already crossed the native timeout.
        let status = wait_for_exact_wait_status(&engine).await;
        close_server(&engine, "__exactWaitServerId").await;

        assert_eq!(
            status.get("status").and_then(serde_json::Value::as_str),
            Some("timeout"),
            "timed wait should resolve even while other waits are parked: {status}",
        );
    }

    #[cfg(feature = "host-http-server")]
    #[tokio::test(flavor = "current_thread")]
    async fn native_http_bridge_round_trips_wait_request_and_response() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:listen:127.0.0.1:0"]);
        let engine = HermesEngine::new().unwrap();

        let setup = eval_json(
            &engine,
            r#"(function() {
                if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
                var result = JSON.parse(__exactHttpServe(0, '127.0.0.1'));
                if (result.error) {
                  return JSON.stringify({ error: result.error });
                }
                __exactHttpSetRef(result.id, 0);
                globalThis.__bridgeServerId = result.id;
                globalThis.__bridgeServerPort = result.port;
                globalThis.__bridgeLastRequest = null;
                globalThis.__bridgePumpOnce = function() {
                  return __exactHttpWait(result.id, 1000).then(function(json) {
                    if (!json) {
                      return 'timeout';
                    }
                    var request = JSON.parse(json);
                    globalThis.__bridgeLastRequest = request.url;
                    __exactHttpRespondString(
                      result.id,
                      request.id,
                      200,
                      JSON.stringify({ 'content-type': 'text/plain; charset=utf-8' }),
                      'bridge-ok'
                    );
                    return 'responded';
                  });
                };
                return JSON.stringify({ id: result.id, port: result.port });
            })()"#,
        )
        .await;

        assert!(setup.get("error").is_none(), "server setup failed: {setup}");
        let server_id = setup
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .expect("server setup should return a server id");
        let port = setup
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .expect("server setup should return a port");

        let wait_deadline = Instant::now() + StdDuration::from_secs(1);
        while Instant::now() < wait_deadline {
            if crate::host::http_server::is_server_listening(server_id) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(
            crate::host::http_server::is_server_listening(server_id),
            "server should reach LISTENING before the bridge round-trip test starts",
        );

        engine
            .eval_immediate("globalThis.__bridgePumpOnce()")
            .await
            .expect("wait pump should start");

        let (response_tx, response_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = response_tx.send(blocking_http_get_with_retry(port, "/agent/onboarding", 10));
        });

        let deadline = Instant::now() + StdDuration::from_secs(2);
        let response = loop {
            if let Ok(result) = response_rx.try_recv() {
                break result;
            }

            if let Ok(result) = timeout(Duration::from_millis(250), engine.drive_event_loop()).await
            {
                result.expect("event loop pump should succeed");
            }

            if Instant::now() >= deadline {
                panic!("timed out waiting for Hermes HTTP bridge response");
            }
        };

        let state = eval_json(
            &engine,
            r#"(function() {
                return JSON.stringify({ lastRequest: globalThis.__bridgeLastRequest });
            })()"#,
        )
        .await;

        let response = response.unwrap_or_else(|err| {
            panic!("HTTP request should succeed: {err}; bridge state: {state}")
        });

        assert!(
            response.contains("HTTP/1.1 200 OK"),
            "expected a 200 response, got: {response}",
        );
        assert!(
            response.contains("bridge-ok"),
            "expected response body to contain bridge-ok, got: {response}",
        );

        assert_eq!(
            state.get("lastRequest").and_then(serde_json::Value::as_str),
            Some("/agent/onboarding"),
            "wait handler should receive the queued request path: {state}",
        );

        close_server(&engine, "__bridgeServerId").await;
    }
}
