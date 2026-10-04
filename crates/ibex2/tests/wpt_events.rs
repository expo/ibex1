//! The DOM-tree-free WPT `dom/events` and `dom/abort` subset, unmodified.

#![cfg(feature = "hermes")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use ibex2::engine::hermes::{DynamicCode, Hermes};

const FILES: &[&str] = &[
    "dom/events/Event-constructors.any.js",
    "dom/events/Event-isTrusted.any.js",
    "dom/events/EventTarget-add-remove-listener.any.js",
    "dom/events/EventTarget-addEventListener.any.js",
    "dom/events/EventTarget-constructible.any.js",
    "dom/events/EventTarget-removeEventListener.any.js",
    "dom/events/AddEventListenerOptions-once.any.js",
    "dom/events/AddEventListenerOptions-passive.any.js",
    "dom/events/AddEventListenerOptions-signal.any.js",
    "dom/abort/AbortSignal.any.js",
    "dom/abort/abort-signal-any.any.js",
    "dom/abort/event.any.js",
    "dom/abort/timeout.any.js",
];

fn wpt_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/wpt")
}

fn eval_file(rt: &mut Hermes, root: &Path, name: &str) {
    let path = root.join(name);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("vendored {}: {e}", path.display()));
    rt.eval(&source)
        .unwrap_or_else(|e| panic!("{name} failed to evaluate: {e}"));
}

fn run_file(name: &str) -> Vec<(String, bool, String)> {
    let root = wpt_root();
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = ibex2::bindings::Context::new(ibex2::grant::GrantSet::none());
    rt.install_runtime(ibex2::bindings::Groups::DEFAULT, &context)
        .expect("bindings");
    rt.install_test_harness().expect("test harness");
    rt.eval("__ibex2_reset_results()").expect("reset");

    if name == "dom/abort/abort-signal-any.any.js" {
        eval_file(
            &mut rt,
            &root,
            "dom/abort/resources/abort-signal-any-tests.js",
        );
    }
    eval_file(&mut rt, &root, name);
    rt.run_to_quiescence(Duration::from_secs(5));

    let pending = rt
        .eval("String(__ibex2_pending_tests())")
        .expect("pending test count");
    assert_eq!(pending, "0", "{name} left asynchronous tests pending");
    let raw = rt.eval("__ibex2_test_results()").expect("results");
    serde_json::from_str::<Vec<serde_json::Value>>(&raw)
        .expect("results json")
        .into_iter()
        .map(|v| {
            (
                v["name"].as_str().unwrap_or("").to_string(),
                v["ok"].as_bool().unwrap_or(false),
                v["message"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

#[test]
#[ignore]
fn wpt_events_report() {
    let (mut total, mut passed) = (0usize, 0usize);
    println!("\n=== WPT dom/events + dom/abort ===");
    for file in FILES {
        let results = run_file(file);
        let ok = results.iter().filter(|(_, ok, _)| *ok).count();
        total += results.len();
        passed += ok;
        println!("  {file:58} {ok}/{}", results.len());
        for (name, is_ok, message) in &results {
            if !is_ok {
                println!("      FAIL {name}: {message}");
            }
        }
    }
    println!("\n  {passed}/{total} pass");
}

#[test]
fn wpt_events_all_pass() {
    let mut failures = Vec::new();
    let mut total = 0usize;
    for file in FILES {
        for (name, ok, message) in run_file(file) {
            total += 1;
            if !ok {
                failures.push(format!("{file}: {name}: {message}"));
            }
        }
    }
    assert_eq!(
        total, 76,
        "the vendored suite changed size; re-baseline deliberately"
    );
    assert!(
        failures.is_empty(),
        "WPT event regressions:\n  {}",
        failures.join("\n  ")
    );
}
