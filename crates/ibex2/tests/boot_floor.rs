//! The boot floor: what the runtime costs before a single module is loaded.
//!
//! LLP 0057 §7 is explicit that nothing in Ibex 2 had been measured against
//! the 30 ms budget in `rules/RULES.md`, "because nothing here is built".
//! Enough is built to measure the floor — everything a program pays before its
//! own code runs — even though the module loader that would complete the
//! picture does not exist yet.
//!
//! Run with:
//!     cargo test -p ibex2 --features hermes --release --test boot_floor -- --ignored --nocapture

#![cfg(feature = "hermes")]

use std::time::{Duration, Instant};

use ibex2::engine::hermes::{DynamicCode, Hermes};

struct Phases {
    create: Duration,
    stdlib: Duration,
    bindings: Duration,
    freeze: Duration,
    first_eval: Duration,
}

impl Phases {
    fn total(&self) -> Duration {
        self.create + self.stdlib + self.bindings + self.freeze + self.first_eval
    }
}

fn boot() -> Phases {
    let t = Instant::now();
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    let create = t.elapsed();

    let stdlib = Duration::ZERO;

    let t = Instant::now();
    let context = ibex2::bindings::Context::new(ibex2::grant::GrantSet::none());
    rt.install_runtime(ibex2::bindings::Groups::DEFAULT, &context)
        .expect("bindings");
    let bindings = t.elapsed();

    let t = Instant::now();
    rt.harden().expect("harden");
    let freeze = t.elapsed();

    // The first thing application code would do. Included because a runtime
    // that has never evaluated anything has not paid for its first evaluation.
    let t = Instant::now();
    rt.eval("1 + 1").expect("first eval");
    let first_eval = t.elapsed();

    Phases {
        create,
        stdlib,
        bindings,
        freeze,
        first_eval,
    }
}

fn groups_without_events() -> ibex2::bindings::Groups {
    use ibex2::bindings::Groups;
    let groups = Groups::PURE
        | Groups::CONSOLE
        | Groups::TIMERS
        | Groups::ABORT
        | Groups::CRYPTO
        | Groups::FETCH
        | Groups::STORAGE
        | Groups::ENV
        | Groups::SECRETS
        | Groups::KV;
    #[cfg(target_os = "linux")]
    let groups = groups | Groups::INTL;
    groups
}

fn post_create_floor(groups: ibex2::bindings::Groups) -> Duration {
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    let t = Instant::now();
    let context = ibex2::bindings::Context::new(ibex2::grant::GrantSet::none());
    rt.install_runtime(groups, &context).expect("bindings");
    rt.harden().expect("harden");
    rt.eval("1 + 1").expect("first eval");
    t.elapsed()
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("finite measurement"));
    values[values.len() / 2]
}

#[test]
#[ignore]
fn boot_floor() {
    // The cold boot is what a real binary pays: it includes any one-time
    // process initialization the engine does on first construction.
    let cold = boot();

    let runs = 30;
    let mut warm = Phases {
        create: Duration::ZERO,
        stdlib: Duration::ZERO,
        bindings: Duration::ZERO,
        freeze: Duration::ZERO,
        first_eval: Duration::ZERO,
    };
    for _ in 0..runs {
        let p = boot();
        warm.create += p.create;
        warm.stdlib += p.stdlib;
        warm.bindings += p.bindings;
        warm.freeze += p.freeze;
        warm.first_eval += p.first_eval;
    }
    let mean = Phases {
        create: warm.create / runs,
        stdlib: warm.stdlib / runs,
        bindings: warm.bindings / runs,
        freeze: warm.freeze / runs,
        first_eval: warm.first_eval / runs,
    };

    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    println!("\n=== Ibex 2 boot floor (release) ===");
    println!("  {:<22} {:>10} {:>10}", "phase", "cold", "warm mean");
    println!(
        "  {:<22} {:>9.3}ms {:>9.3}ms",
        "runtime construction",
        ms(cold.create),
        ms(mean.create)
    );
    println!(
        "  {:<22} {:>9.3}ms {:>9.3}ms",
        "stdlib host functions",
        ms(cold.stdlib),
        ms(mean.stdlib)
    );
    println!(
        "  {:<22} {:>9.3}ms {:>9.3}ms",
        "JS bindings (bytecode)",
        ms(cold.bindings),
        ms(mean.bindings)
    );
    println!(
        "  {:<22} {:>9.3}ms {:>9.3}ms",
        "intrinsic freeze",
        ms(cold.freeze),
        ms(mean.freeze)
    );
    println!(
        "  {:<22} {:>9.3}ms {:>9.3}ms",
        "first evaluation",
        ms(cold.first_eval),
        ms(mean.first_eval)
    );
    println!(
        "  {:<22} {:>9.3}ms {:>9.3}ms",
        "TOTAL",
        ms(cold.total()),
        ms(mean.total())
    );
    println!();
    println!("  budget (rules/RULES.md): 30ms to app entry");
    println!(
        "  floor consumes: {:.1}% cold, {:.1}% warm",
        100.0 * ms(cold.total()) / 30.0,
        100.0 * ms(mean.total()) / 30.0
    );
    println!(
        "  headroom for modules: {:.2}ms cold",
        30.0 - ms(cold.total())
    );
    println!();
    println!("  NOTE: the cold column is a SINGLE sample and is heavily affected by");
    println!("  machine contention and OS page cache — observed 1.7ms to 59ms for the");
    println!("  same phase on the same machine. Take the MINIMUM over several fresh");
    println!("  processes as the estimate, and run it on a quiet machine. The first");
    println!("  run after a link is always an outlier: the binary's pages are cold.");
}

/// The D5 family delta, paired inside one process to remove runtime creation
/// and most machine-load noise. Diagnostic only, like the other cost tests.
#[test]
#[ignore]
fn event_group_floor_delta() {
    let with = ibex2::bindings::Groups::DEFAULT;
    let without = groups_without_events();
    assert_eq!(
        with.bits() & !ibex2::bindings::Groups::EVENTS.bits(),
        without.bits()
    );

    let _ = post_create_floor(without);
    let _ = post_create_floor(with);
    let mut with_samples = Vec::new();
    let mut without_samples = Vec::new();
    let mut paired_deltas = Vec::new();
    for index in 0..101 {
        let (without_elapsed, with_elapsed) = if index % 2 == 0 {
            (post_create_floor(without), post_create_floor(with))
        } else {
            let with_elapsed = post_create_floor(with);
            (post_create_floor(without), with_elapsed)
        };
        let without_us = without_elapsed.as_secs_f64() * 1_000_000.0;
        let with_us = with_elapsed.as_secs_f64() * 1_000_000.0;
        without_samples.push(without_us);
        with_samples.push(with_us);
        paired_deltas.push(with_us - without_us);
    }

    println!("\n=== EVENTS incremental boot floor (release) ===");
    println!("  without EVENTS: {:.1} us", median(without_samples));
    println!("  with EVENTS:    {:.1} us", median(with_samples));
    println!("  paired delta:   {:+.1} us", median(paired_deltas));
}

/// WEBSOCKET is explicit rather than part of DEFAULT, so measure its bytecode
/// install, hardening, and first-evaluation delta directly.
#[cfg(feature = "websocket")]
#[test]
#[ignore]
fn websocket_group_floor_delta() {
    let without = ibex2::bindings::Groups::DEFAULT;
    let with = without | ibex2::bindings::Groups::WEBSOCKET;

    let _ = post_create_floor(without);
    let _ = post_create_floor(with);
    let mut with_samples = Vec::new();
    let mut without_samples = Vec::new();
    let mut paired_deltas = Vec::new();
    for index in 0..101 {
        let (without_elapsed, with_elapsed) = if index % 2 == 0 {
            (post_create_floor(without), post_create_floor(with))
        } else {
            let with_elapsed = post_create_floor(with);
            (post_create_floor(without), with_elapsed)
        };
        let without_us = without_elapsed.as_secs_f64() * 1_000_000.0;
        let with_us = with_elapsed.as_secs_f64() * 1_000_000.0;
        without_samples.push(without_us);
        with_samples.push(with_us);
        paired_deltas.push(with_us - without_us);
    }

    println!("\n=== WEBSOCKET incremental boot floor (release) ===");
    println!("  without WEBSOCKET: {:.1} us", median(without_samples));
    println!("  with WEBSOCKET:    {:.1} us", median(with_samples));
    println!("  paired delta:      {:+.1} us", median(paired_deltas));
}
