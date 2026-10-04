//! Browser-free WPT Blob and FormData fixtures, run unmodified.
//!
//! The exact upstream bytes and the DOM/Streams/engine exclusions are pinned
//! in `third_party/wpt/MANIFEST.json`. This runner supplies only the small
//! testharness surface and the worker-style `self` alias expected by WPT.

#![cfg(feature = "hermes")]

use ibex2::bindings::{Context, Groups};
use ibex2::engine::hermes::{DynamicCode, Hermes};
use ibex2::grant::GrantSet;
use std::time::Duration;

const BLOB_FILES: &[&str] = &[
    "Blob-array-buffer.any.js",
    "Blob-bytes.any.js",
    "Blob-constructor.any.js",
    "Blob-newobject.any.js",
    "Blob-slice-overflow.any.js",
    "Blob-slice.any.js",
    "Blob-text.any.js",
];

const FORM_DATA_FILES: &[&str] = &[
    "append.any.js",
    "constructor.any.js",
    "delete.any.js",
    "foreach.any.js",
    "get.any.js",
    "has.any.js",
    "iteration.any.js",
    "set-blob.any.js",
    "set.any.js",
];

#[derive(Debug)]
struct Outcome {
    name: String,
    ok: bool,
    message: String,
    float16_available: bool,
}

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../third_party/wpt")
}

fn run_file(directory: &str, name: &str, blob_support: bool) -> Vec<Outcome> {
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    runtime
        .install_runtime(Groups::PURE | Groups::BLOB, &Context::new(GrantSet::none()))
        .expect("bindings");
    runtime.install_test_harness().expect("test harness");
    runtime
        .eval("globalThis.self = globalThis; __ibex2_reset_results()")
        .expect("WPT global aliases");
    if blob_support {
        let support = std::fs::read_to_string(root().join("FileAPI/support/Blob.js"))
            .expect("Blob WPT support");
        runtime.eval(&support).expect("Blob WPT support evaluates");
    }
    let source = std::fs::read_to_string(root().join(directory).join(name))
        .unwrap_or_else(|error| panic!("vendored {directory}/{name}: {error}"));
    runtime
        .eval(&source)
        .unwrap_or_else(|error| panic!("{directory}/{name} failed to evaluate: {error}"));
    runtime.run_to_quiescence(Duration::from_secs(5));
    let outstanding = runtime
        .eval("String(__ibex2_test_outstanding())")
        .expect("outstanding promise tests");
    assert_eq!(
        outstanding, "0",
        "{directory}/{name} still had promise_test work after quiescence"
    );
    let float16_available = runtime
        .eval("typeof Float16Array === 'function'")
        .expect("Float16Array availability")
        == "true";
    let raw = runtime.eval("__ibex2_test_results()").expect("results");
    serde_json::from_str::<Vec<serde_json::Value>>(&raw)
        .expect("results JSON")
        .into_iter()
        .map(|result| Outcome {
            name: result["name"].as_str().unwrap_or("").to_string(),
            ok: result["ok"].as_bool().unwrap_or(false),
            message: result["message"].as_str().unwrap_or("").to_string(),
            float16_available,
        })
        .collect()
}

fn engine_unavailable(outcome: &Outcome) -> bool {
    !outcome.float16_available
        && outcome.name
            == "Passing a Float16Array as element of the blobParts array should work."
        && outcome.message.contains("Float16Array' doesn't exist")
}

fn named_exclusion(outcome: &Outcome) -> bool {
    (outcome.name
        == "Passing a FrozenArray as the blobParts array should work (FrozenArray<MessagePort>)."
        && outcome.message.contains("MessageChannel"))
        || (outcome.name == "Blob.stream() returns [NewObject]"
            && outcome.message.contains("undefined is not a function"))
}

fn all_results() -> Vec<(String, Outcome)> {
    BLOB_FILES
        .iter()
        .map(|name| ("FileAPI/blob", *name, true))
        .chain(
            FORM_DATA_FILES
                .iter()
                .map(|name| ("xhr/formdata", *name, false)),
        )
        .flat_map(|(directory, file, support)| {
            run_file(directory, file, support)
                .into_iter()
                .map(move |outcome| (format!("{directory}/{file}"), outcome))
        })
        .collect()
}

#[test]
#[ignore]
fn wpt_blob_form_data_report() {
    let results = all_results();
    let passed = results.iter().filter(|(_, outcome)| outcome.ok).count();
    let unavailable = results
        .iter()
        .filter(|(_, outcome)| !outcome.ok && engine_unavailable(outcome))
        .count();
    let excluded = results
        .iter()
        .filter(|(_, outcome)| !outcome.ok && named_exclusion(outcome))
        .count();
    for (file, outcome) in &results {
        if !outcome.ok {
            println!("{file}: {}: {}", outcome.name, outcome.message);
        }
    }
    println!(
        "{passed}/{} passed; {excluded} named exclusions; {unavailable} unavailable; {} failed",
        results.len(),
        results.len() - passed - excluded - unavailable
    );
}

#[test]
fn wpt_blob_form_data_gate() {
    let results = all_results();
    let mut failures = Vec::new();
    let mut unavailable = 0;
    let mut excluded = 0;
    for (file, outcome) in &results {
        if outcome.ok {
            continue;
        }
        if named_exclusion(outcome) {
            excluded += 1;
        } else if engine_unavailable(outcome) {
            unavailable += 1;
        } else {
            failures.push(format!("{file}: {}: {}", outcome.name, outcome.message));
        }
    }
    println!(
        "{} passed; {excluded} named exclusions; {unavailable} unavailable (Hermes Float16Array); {} failed",
        results.len() - excluded - unavailable - failures.len(),
        failures.len()
    );
    assert_eq!(
        results.len(),
        289,
        "the pinned Blob/FormData WPT set changed; re-baseline deliberately"
    );
    assert!(
        failures.is_empty(),
        "WPT Blob/FormData regressions:\n  {}",
        failures.join("\n  ")
    );
}
