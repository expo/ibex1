//! Ibex shared runtime
//!
//! This crate contains the shared runtime components used by both the `ibex`
//! binary and embedding apps. It provides:
//!
//! - **Module Loader**: Node.js-compatible `require()` with 30+ builtin modules
//! - **Host ABI**: C-level functions for filesystem, SQLite, crypto, etc.
//! - **Hermes C++ adapter**: The `hermes_runtime.cc` compiled into this library
//!   provides authenticated `ex_hermes_create_armed()` construction plus eval,
//!   poll, and destroy. The historical `ex_hermes_create()` symbol is retained
//!   but non-executable; diagnostics must opt into
//!   `ex_hermes_create_diagnostic()` by name.
//!
//! The `ibex` binary wraps these in async Rust (via tokio). The iOS app calls the C API
//! directly from Swift via the bridging header.

// @ref LLP 0039#simulator-only-performance-observer — the measurement carrier
// is release-only and iOS-Simulator-only; it must not become a product mode.
#[cfg(all(feature = "capsec-simulator-performance-observer", debug_assertions))]
compile_error!("capsec-simulator-performance-observer is unavailable in debug builds");
#[cfg(all(
    feature = "capsec-simulator-performance-observer",
    not(all(target_os = "ios", any(target_arch = "x86_64", target_abi = "sim")))
))]
compile_error!("capsec-simulator-performance-observer is available only for iOS Simulator targets");

// Keep libz-sys in the Windows link graph; the C++ zlib host functions call
// zlib symbols directly.
#[cfg(windows)]
use libz_sys as _;

#[cfg(feature = "host-http-server")]
pub mod cdp;
// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
// committed binding exposes generated registry identities without duplicating
// decision logic in handwritten Rust.
pub mod cache_topology;
pub mod capsec_registry_generated;
pub mod capsec_runtime_projection_generated;
pub mod compiled_contract;
pub mod compiled_environment_profile_generated;
pub mod engine;
pub mod host;
pub mod identity_generated;
pub mod module_loader;
pub mod repl_surface;
pub mod restricted_worker;
pub mod session_constants;
pub mod session_lifecycle;
#[cfg(feature = "host-http-server")]
mod sync;
pub mod vfs;

use anyhow::Result;
use std::path::PathBuf;

/// Determine runtime cache directory.
/// - macOS: ~/Library/Caches/Exact
/// - iOS/tvOS: app's Caches directory
/// - Linux/Android: platform cache directory, falling back to ~/.cache/exact
pub fn runtime_cache_dir() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join("Library").join("Caches").join("Exact"));
        }
    }

    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    {
        // On iOS and tvOS, use the app's Caches directory
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("Exact"));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        #[cfg(target_os = "android")]
        if let Ok(dir) = std::env::var("EXACT_ANDROID_CACHE_DIR") {
            if !dir.is_empty() {
                return Ok(PathBuf::from(dir).join("exact"));
            }
        }
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("exact"));
        }
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(".cache").join("exact"));
        }
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "linux",
        target_os = "android"
    )))]
    {
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("exact"));
        }
    }

    anyhow::bail!("Failed to determine cache directory")
}
