//! C ABI surface for the Exact host.
//!
//! These functions are intended to be called from engine adapters (C/C++).
//! The CLI stores a singleton Host instance that backs these calls.
//!
//! # Safety
//! FFI functions receive raw pointers from foreign code. The safety contract
//! is between the caller (C/C++ code) and this module. Functions validate
//! null pointers where possible but assume pointers are valid when non-null.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use super::Host;
use base64::Engine as _;
use getrandom::getrandom;
use rusqlite::{
    hooks::{AuthAction, AuthContext, Authorization},
    params_from_iter,
    types::ValueRef,
    Connection, OpenFlags, ToSql,
};
use serde_json::json;
use std::cell::Cell;
use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::ffi::c_int;
use std::ffi::{c_char, CStr, CString};
use std::io::{self, Write};
use std::num::NonZeroU64;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
#[cfg(unix)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    /// Normalized POSIX-style error code for the most recent host filesystem
    /// failure on this thread. Windows `raw_os_error()` values are Win32
    /// status codes, not errno values, so the C++ bridge must not interpret
    /// them directly. The worker-pool caller consumes this immediately after
    /// a failed ABI call on the same thread.
    static LAST_FS_ERROR: Cell<i32> = const { Cell::new(0) };
}

// @ref LLP 0025#1-modes-descriptors-and-topology — JavaScript may write the
// broker-owned standard outputs but cannot close or replace them.
static TERMINAL_SESSION_OUTPUT_CLOSE_GUARD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// An armed CLI output capture replaces the embedding host's lossy async
// console queue with a synchronous, counted relay. The sealed state closes the
// final descriptor-handoff race: once selected, new console records are
// refused until the capture guard is dropped instead of escaping to restored
// native descriptors or a late async writer.
const TERMINAL_CONSOLE_RELAY_INACTIVE: u8 = 0;
const TERMINAL_CONSOLE_RELAY_ACTIVE: u8 = 1;
const TERMINAL_CONSOLE_RELAY_SEALED: u8 = 2;
static TERMINAL_CONSOLE_RELAY_STATE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(TERMINAL_CONSOLE_RELAY_INACTIVE);

#[derive(Default)]
struct TerminalConsoleRelayEpoch {
    in_flight: std::sync::atomic::AtomicUsize,
    write_failed: std::sync::atomic::AtomicBool,
}

fn terminal_console_relay_epoch() -> &'static Mutex<Option<Arc<TerminalConsoleRelayEpoch>>> {
    static EPOCH: OnceLock<Mutex<Option<Arc<TerminalConsoleRelayEpoch>>>> = OnceLock::new();
    EPOCH.get_or_init(|| Mutex::new(None))
}

fn terminal_console_relay_gate() -> &'static Mutex<()> {
    static GATE: OnceLock<Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| Mutex::new(()))
}

/// Worker-local live terminal facts used by the typed `stdio:query` surface.
///
/// The authenticated worker deliberately has pipes on fd 1/fd 2 and no
/// controlling terminal, so asking its kernel descriptors would report the
/// transport topology instead of the operator's presentation topology.  The
/// supervisor supplies live dimensions over the authenticated control lane;
/// getters may read this state without taking the Runtime lock.
/// @ref LLP 0025#2-startup-configuration-is-captured-before-arming
/// @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker
struct TerminalSessionStdioQueryState {
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    stderr_is_tty: bool,
    dimensions: std::sync::atomic::AtomicU32,
}

impl TerminalSessionStdioQueryState {
    const fn pack_dimensions(columns: u16, rows: u16) -> u32 {
        columns as u32 | ((rows as u32) << 16)
    }

    fn update_dimensions(&self, columns: u16, rows: u16) {
        self.dimensions.store(
            Self::pack_dimensions(columns, rows),
            std::sync::atomic::Ordering::Release,
        );
    }

    fn query(&self, fd: i32) -> Option<(bool, u16, u16)> {
        let is_tty = match fd {
            0 => self.stdin_is_tty,
            1 => self.stdout_is_tty,
            2 => self.stderr_is_tty,
            _ => return None,
        };
        let dimensions = self.dimensions.load(std::sync::atomic::Ordering::Acquire);
        Some((is_tty, dimensions as u16, (dimensions >> 16) as u16))
    }
}

static TERMINAL_SESSION_STDIO_QUERY_STATE: Mutex<Option<Arc<TerminalSessionStdioQueryState>>> =
    Mutex::new(None);

/// Exclusive worker-side lifetime for the supervisor-authenticated terminal
/// facts.  This is installed before Runtime construction and retained by the
/// verified worker endpoint.
pub struct TerminalSessionStdioQueryGuard {
    state: Arc<TerminalSessionStdioQueryState>,
}

pub fn arm_terminal_session_stdio_query(
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    stderr_is_tty: bool,
) -> io::Result<TerminalSessionStdioQueryGuard> {
    let state = Arc::new(TerminalSessionStdioQueryState {
        stdin_is_tty,
        stdout_is_tty,
        stderr_is_tty,
        dimensions: std::sync::atomic::AtomicU32::new(0),
    });
    let mut installed = TERMINAL_SESSION_STDIO_QUERY_STATE
        .lock()
        .map_err(|_| io::Error::other("terminal stdio query state lock is poisoned"))?;
    if installed.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "terminal stdio query state is already active",
        ));
    }
    *installed = Some(Arc::clone(&state));
    Ok(TerminalSessionStdioQueryGuard { state })
}

impl TerminalSessionStdioQueryGuard {
    pub fn update_dimensions(&self, columns: u16, rows: u16) {
        self.state.update_dimensions(columns, rows);
    }
}

impl Drop for TerminalSessionStdioQueryGuard {
    fn drop(&mut self) {
        match TERMINAL_SESSION_STDIO_QUERY_STATE.lock() {
            Ok(mut installed) => {
                if installed
                    .as_ref()
                    .is_some_and(|state| Arc::ptr_eq(state, &self.state))
                {
                    *installed = None;
                }
            }
            Err(poisoned) => *poisoned.into_inner() = None,
        }
    }
}

/// Read the worker's supervisor-authenticated typed stdio state.
///
/// Returns 1 when a session state supplied all outputs, 0 when no worker state
/// is installed (the native adapter must query its own descriptor), and -1 for
/// an invalid descriptor or pointer. Unknown dimensions are returned as zero.
///
/// # Safety
///
/// Each output pointer must address one properly aligned, writable scalar for
/// the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_terminal_session_stdio_query(
    fd: i32,
    out_is_tty: *mut i32,
    out_columns: *mut u16,
    out_rows: *mut u16,
) -> i32 {
    if !matches!(fd, 0..=2) || out_is_tty.is_null() || out_columns.is_null() || out_rows.is_null() {
        return -1;
    }
    let query = match TERMINAL_SESSION_STDIO_QUERY_STATE.lock() {
        Ok(installed) => match installed.as_ref() {
            Some(state) => state.query(fd),
            None => return 0,
        },
        Err(_) => return -1,
    };
    let Some((is_tty, columns, rows)) = query else {
        return -1;
    };
    // SAFETY: non-null output pointers are part of this C ABI's caller
    // contract and each points to one writable scalar.
    unsafe {
        *out_is_tty = i32::from(is_tty);
        *out_columns = columns;
        *out_rows = rows;
    }
    1
}

#[doc(hidden)]
pub struct AuthenticatedWorkerConsoleRelayGuard {
    epoch: Arc<TerminalConsoleRelayEpoch>,
}

#[doc(hidden)]
pub fn arm_authenticated_worker_console_relay() -> io::Result<AuthenticatedWorkerConsoleRelayGuard>
{
    let _gate = terminal_console_relay_gate()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let epoch = Arc::new(TerminalConsoleRelayEpoch::default());
    TERMINAL_CONSOLE_RELAY_STATE
        .compare_exchange(
            TERMINAL_CONSOLE_RELAY_INACTIVE,
            TERMINAL_CONSOLE_RELAY_ACTIVE,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "an authenticated worker console relay is already active",
            )
        })?;
    *terminal_console_relay_epoch()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&epoch));
    Ok(AuthenticatedWorkerConsoleRelayGuard { epoch })
}

impl AuthenticatedWorkerConsoleRelayGuard {
    fn epoch_status(&self) -> io::Result<()> {
        let in_flight = self
            .epoch
            .in_flight
            .load(std::sync::atomic::Ordering::Acquire);
        let write_failed = self
            .epoch
            .write_failed
            .load(std::sync::atomic::Ordering::Acquire);
        match (in_flight, write_failed) {
            (0, false) => Ok(()),
            (0, true) => Err(io::Error::other(
                "an authenticated host-console record failed before final handoff",
            )),
            (count, false) => Err(io::Error::other(format!(
                "{count} authenticated host-console record(s) remain in flight during final handoff"
            ))),
            (count, true) => Err(io::Error::other(format!(
                "{count} authenticated host-console record(s) remain in flight and an earlier record failed during final handoff"
            ))),
        }
    }

    /// Serialize descriptor replacement against synchronous host-console
    /// records. Callers keep this closure small and perform no broker waits.
    pub fn with_output_quiesced<T>(&self, action: impl FnOnce() -> T) -> T {
        let _gate = terminal_console_relay_gate()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        action()
    }

    /// Refuse new host-console records before the standard descriptors move
    /// through their bounded final handoff. A writer accepted before this call
    /// owns a duplicate of the captured descriptor, so it cannot jump to a
    /// subsequently restored fd 1/fd 2. Such a writer is reported as in-flight
    /// instead of making restoration wait for a stalled output destination.
    pub fn seal(&self) -> io::Result<()> {
        let _gate = terminal_console_relay_gate()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transition = match TERMINAL_CONSOLE_RELAY_STATE.compare_exchange(
            TERMINAL_CONSOLE_RELAY_ACTIVE,
            TERMINAL_CONSOLE_RELAY_SEALED,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) | Err(TERMINAL_CONSOLE_RELAY_SEALED) => Ok(()),
            Err(_) => Err(io::Error::other(
                "terminal console relay is not active during final handoff",
            )),
        };
        transition?;
        self.epoch_status()
    }

    fn with_final_sealed_status_action<T>(&self, action: impl FnOnce(io::Result<()>) -> T) -> T {
        let _gate = terminal_console_relay_gate()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let status = if TERMINAL_CONSOLE_RELAY_STATE.load(std::sync::atomic::Ordering::Acquire)
            == TERMINAL_CONSOLE_RELAY_SEALED
        {
            self.epoch_status()
        } else {
            Err(io::Error::other(
                "terminal console relay was not sealed at final process exit",
            ))
        };
        action(status)
    }

    /// Select the final status and terminate while the sealed-epoch gate is
    /// still held. No console producer can enter between the loss observation
    /// and `_exit`, and the non-returning contract is enforced by this method's
    /// implementation rather than a caller-supplied closure type.
    #[cfg(unix)]
    pub fn exit_with_final_sealed_status(
        &self,
        status_without_new_loss: i32,
        status_with_new_loss: i32,
    ) -> ! {
        self.with_final_sealed_status_action(|status| {
            let status = if status.is_ok() {
                status_without_new_loss
            } else {
                status_with_new_loss
            };
            // SAFETY: the console gate remains held until the process exits.
            unsafe { libc::_exit(status) }
        })
    }
}

impl Drop for AuthenticatedWorkerConsoleRelayGuard {
    fn drop(&mut self) {
        let _gate = terminal_console_relay_gate()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TERMINAL_CONSOLE_RELAY_STATE.store(
            TERMINAL_CONSOLE_RELAY_INACTIVE,
            std::sync::atomic::Ordering::Release,
        );
        let mut active_epoch = terminal_console_relay_epoch()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active_epoch
            .as_ref()
            .is_some_and(|epoch| Arc::ptr_eq(epoch, &self.epoch))
        {
            active_epoch.take();
        }
    }
}

/// Closed route values shared with the native engine adapters. Unknown values
/// are deliberately absent: native callers treat anything other than an
/// explicitly permitted route as refusal.
pub const SESSION_DESCRIPTOR_ROUTE_REFUSED: i32 = -1;
pub const SESSION_DESCRIPTOR_ROUTE_NATIVE: i32 = 0;
pub const SESSION_DESCRIPTOR_ROUTE_VIRTUAL: i32 = 1;

#[derive(Debug)]
struct TerminalSessionDescriptorPolicy {
    seals_javascript_stdin: bool,
    protected_descriptors: Box<[i32]>,
}

impl TerminalSessionDescriptorPolicy {
    fn new(
        seals_javascript_stdin: bool,
        protected_descriptors: impl IntoIterator<Item = i32>,
    ) -> io::Result<Self> {
        let mut protected_descriptors = protected_descriptors.into_iter().collect::<Vec<_>>();
        if protected_descriptors
            .iter()
            .any(|descriptor| *descriptor <= 2)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a terminal-session protected descriptor must be greater than fd 2",
            ));
        }
        protected_descriptors.sort_unstable();
        let original_len = protected_descriptors.len();
        protected_descriptors.dedup();
        if protected_descriptors.len() != original_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a terminal-session protected descriptor was registered twice",
            ));
        }
        Ok(Self {
            seals_javascript_stdin,
            protected_descriptors: protected_descriptors.into_boxed_slice(),
        })
    }

    fn is_protected(&self, descriptor: i32) -> bool {
        self.protected_descriptors
            .binary_search(&descriptor)
            .is_ok()
    }

    fn read_route(&self, descriptor: i32) -> i32 {
        if self.is_protected(descriptor) {
            SESSION_DESCRIPTOR_ROUTE_REFUSED
        } else if descriptor == 0 && self.seals_javascript_stdin {
            SESSION_DESCRIPTOR_ROUTE_VIRTUAL
        } else {
            SESSION_DESCRIPTOR_ROUTE_NATIVE
        }
    }

    fn write_route(&self, descriptor: i32) -> i32 {
        if self.is_protected(descriptor) {
            SESSION_DESCRIPTOR_ROUTE_REFUSED
        } else {
            SESSION_DESCRIPTOR_ROUTE_NATIVE
        }
    }

    fn close_route(&self, descriptor: i32) -> i32 {
        if self.is_protected(descriptor) {
            SESSION_DESCRIPTOR_ROUTE_REFUSED
        } else if matches!(descriptor, 1 | 2) || (descriptor == 0 && self.seals_javascript_stdin) {
            SESSION_DESCRIPTOR_ROUTE_VIRTUAL
        } else {
            SESSION_DESCRIPTOR_ROUTE_NATIVE
        }
    }

    fn alias_source_route(&self, descriptor: i32) -> i32 {
        if self.is_protected(descriptor) || matches!(descriptor, 1 | 2) {
            SESSION_DESCRIPTOR_ROUTE_REFUSED
        } else if descriptor == 0 && self.seals_javascript_stdin {
            SESSION_DESCRIPTOR_ROUTE_VIRTUAL
        } else {
            SESSION_DESCRIPTOR_ROUTE_NATIVE
        }
    }

    fn alias_target_route(&self, descriptor: i32) -> i32 {
        if self.is_protected(descriptor) || matches!(descriptor, 0..=2) {
            SESSION_DESCRIPTOR_ROUTE_REFUSED
        } else {
            SESSION_DESCRIPTOR_ROUTE_NATIVE
        }
    }
}

// @ref LLP 0025#1-modes-descriptors-and-topology — the authenticated worker
// installs one process-wide descriptor policy before Runtime construction.
// A mutex makes installation exclusive and keeps every native query coherent
// with the RAII lifetime transition.
static TERMINAL_SESSION_DESCRIPTOR_POLICY: Mutex<Option<TerminalSessionDescriptorPolicy>> =
    Mutex::new(None);

/// Exclusive native descriptor-policy lifetime. This value is intentionally
/// neither cloneable nor constructible outside this module; dropping it is the
/// only normal route that uninstalls the process-wide policy.
pub struct TerminalSessionDescriptorPolicyGuard {
    _private: (),
}

pub fn arm_terminal_session_descriptor_policy(
    seals_javascript_stdin: bool,
    protected_descriptors: impl IntoIterator<Item = i32>,
) -> io::Result<TerminalSessionDescriptorPolicyGuard> {
    let policy =
        TerminalSessionDescriptorPolicy::new(seals_javascript_stdin, protected_descriptors)?;
    let mut installed = TERMINAL_SESSION_DESCRIPTOR_POLICY
        .lock()
        .map_err(|_| io::Error::other("terminal-session descriptor policy lock is poisoned"))?;
    if installed.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a terminal-session descriptor policy is already active",
        ));
    }
    *installed = Some(policy);
    Ok(TerminalSessionDescriptorPolicyGuard { _private: () })
}

impl Drop for TerminalSessionDescriptorPolicyGuard {
    fn drop(&mut self) {
        match TERMINAL_SESSION_DESCRIPTOR_POLICY.lock() {
            Ok(mut installed) => *installed = None,
            Err(poisoned) => *poisoned.into_inner() = None,
        }
    }
}

fn terminal_session_descriptor_route(
    descriptor: i32,
    classify: impl FnOnce(&TerminalSessionDescriptorPolicy, i32) -> i32,
) -> i32 {
    match TERMINAL_SESSION_DESCRIPTOR_POLICY.lock() {
        Ok(installed) => installed
            .as_ref()
            .map_or(SESSION_DESCRIPTOR_ROUTE_NATIVE, |policy| {
                classify(policy, descriptor)
            }),
        // If native code cannot observe a coherent policy, it cannot prove a
        // descriptor operation safe. Refuse instead of falling through.
        Err(_) => SESSION_DESCRIPTOR_ROUTE_REFUSED,
    }
}

#[no_mangle]
pub extern "C" fn ex_host_session_descriptor_is_protected(descriptor: i32) -> i32 {
    match TERMINAL_SESSION_DESCRIPTOR_POLICY.lock() {
        Ok(installed) => i32::from(
            installed
                .as_ref()
                .is_some_and(|policy| policy.is_protected(descriptor)),
        ),
        // Lock poisoning is an indeterminate policy state, so every descriptor
        // is treated as protected until process teardown.
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn ex_host_session_descriptor_read_route(descriptor: i32) -> i32 {
    terminal_session_descriptor_route(descriptor, TerminalSessionDescriptorPolicy::read_route)
}

#[no_mangle]
pub extern "C" fn ex_host_session_descriptor_write_route(descriptor: i32) -> i32 {
    terminal_session_descriptor_route(descriptor, TerminalSessionDescriptorPolicy::write_route)
}

#[no_mangle]
pub extern "C" fn ex_host_session_descriptor_close_route(descriptor: i32) -> i32 {
    let route =
        terminal_session_descriptor_route(descriptor, TerminalSessionDescriptorPolicy::close_route);
    if route == SESSION_DESCRIPTOR_ROUTE_NATIVE
        && matches!(descriptor, 1 | 2)
        && TERMINAL_SESSION_OUTPUT_CLOSE_GUARD.load(std::sync::atomic::Ordering::Acquire)
    {
        SESSION_DESCRIPTOR_ROUTE_VIRTUAL
    } else {
        route
    }
}

#[no_mangle]
pub extern "C" fn ex_host_session_descriptor_alias_source_route(descriptor: i32) -> i32 {
    terminal_session_descriptor_route(
        descriptor,
        TerminalSessionDescriptorPolicy::alias_source_route,
    )
}

#[no_mangle]
pub extern "C" fn ex_host_session_descriptor_alias_target_route(descriptor: i32) -> i32 {
    terminal_session_descriptor_route(
        descriptor,
        TerminalSessionDescriptorPolicy::alias_target_route,
    )
}

/// Closed acknowledgement returned by the authenticated worker's native
/// supervisor channel. `Acknowledged` means the supervisor durably accepted
/// the exact record before the callback returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerLifecycleAcknowledgement {
    Acknowledged,
    Unacknowledged,
}

/// Authorized, normalized `process.exitCode` mutation handed to a worker's
/// native supervisor channel. The private field prevents callers from
/// manufacturing an authorization result; only the Host ABI constructs it
/// after both typed lifecycle stages allow the live principal stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedWorkerExitCodeMirror {
    status: i32,
}

impl AuthorizedWorkerExitCodeMirror {
    pub fn status(self) -> i32 {
        self.status
    }
}

/// Authorized cooperative lifecycle record handed to a worker's native
/// supervisor channel. The binary-side callback adds its current write-time
/// relay counters plus the authenticated channel envelope before sending it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedWorkerLifecycleCommit {
    request_id: u64,
    status: i32,
}

impl AuthorizedWorkerLifecycleCommit {
    pub fn request_id(self) -> u64 {
        self.request_id
    }

    pub fn status(self) -> i32 {
        self.status
    }
}

type WorkerExitCodeMirrorCallback = dyn Fn(AuthorizedWorkerExitCodeMirror) -> WorkerLifecycleAcknowledgement
    + Send
    + Sync
    + 'static;
type WorkerLifecycleCommitCallback = dyn Fn(AuthorizedWorkerLifecycleCommit) -> WorkerLifecycleAcknowledgement
    + Send
    + Sync
    + 'static;

/// Native-only authenticated worker lifecycle callbacks.
///
/// The binary installs this port only after authenticating its supervisor
/// channel and before constructing `Runtime`. Callbacks execute synchronously
/// on the engine thread and therefore must not re-enter `Runtime`, the Host
/// ABI, or the session lifecycle port. They may perform only the bounded
/// control-channel send/ack exchange. JavaScript has no installation or direct
/// invocation surface.
pub struct AuthenticatedWorkerLifecyclePort {
    mirror_exit_code: Box<WorkerExitCodeMirrorCallback>,
    commit_lifecycle: Box<WorkerLifecycleCommitCallback>,
}

impl AuthenticatedWorkerLifecyclePort {
    pub fn new<Mirror, Commit>(mirror_exit_code: Mirror, commit_lifecycle: Commit) -> Self
    where
        Mirror: Fn(AuthorizedWorkerExitCodeMirror) -> WorkerLifecycleAcknowledgement
            + Send
            + Sync
            + 'static,
        Commit: Fn(AuthorizedWorkerLifecycleCommit) -> WorkerLifecycleAcknowledgement
            + Send
            + Sync
            + 'static,
    {
        Self {
            mirror_exit_code: Box::new(mirror_exit_code),
            commit_lifecycle: Box::new(commit_lifecycle),
        }
    }

    fn mirror_exit_code(
        &self,
        mutation: AuthorizedWorkerExitCodeMirror,
    ) -> WorkerLifecycleAcknowledgement {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (self.mirror_exit_code)(mutation)
        }))
        .unwrap_or(WorkerLifecycleAcknowledgement::Unacknowledged)
    }

    fn commit_lifecycle(
        &self,
        commit: AuthorizedWorkerLifecycleCommit,
    ) -> WorkerLifecycleAcknowledgement {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (self.commit_lifecycle)(commit)
        }))
        .unwrap_or(WorkerLifecycleAcknowledgement::Unacknowledged)
    }
}

// @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker — a
// worker installs exactly one authenticated native control port for the
// Runtime lifetime; JavaScript receives no callback handle or channel token.
static AUTHENTICATED_WORKER_LIFECYCLE_PORT: Mutex<Option<Arc<AuthenticatedWorkerLifecyclePort>>> =
    Mutex::new(None);

/// Exclusive RAII lifetime for the authenticated worker lifecycle port.
#[must_use = "dropping this guard removes the worker lifecycle bridge"]
pub struct AuthenticatedWorkerLifecyclePortGuard {
    _private: (),
}

/// Install an authenticated worker lifecycle port around one `Runtime`
/// lifetime. Installation is process-exclusive and refuses a poisoned or
/// already-active port instead of replacing it.
pub fn install_authenticated_worker_lifecycle_port(
    port: AuthenticatedWorkerLifecyclePort,
) -> io::Result<AuthenticatedWorkerLifecyclePortGuard> {
    let mut installed = AUTHENTICATED_WORKER_LIFECYCLE_PORT
        .lock()
        .map_err(|_| io::Error::other("authenticated worker lifecycle port lock is poisoned"))?;
    if installed.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an authenticated worker lifecycle port is already active",
        ));
    }
    *installed = Some(Arc::new(port));
    Ok(AuthenticatedWorkerLifecyclePortGuard { _private: () })
}

impl Drop for AuthenticatedWorkerLifecyclePortGuard {
    fn drop(&mut self) {
        match AUTHENTICATED_WORKER_LIFECYCLE_PORT.lock() {
            Ok(mut installed) => *installed = None,
            Err(poisoned) => *poisoned.into_inner() = None,
        }
    }
}

fn authenticated_worker_lifecycle_port() -> io::Result<Option<Arc<AuthenticatedWorkerLifecyclePort>>>
{
    AUTHENTICATED_WORKER_LIFECYCLE_PORT
        .lock()
        .map(|installed| installed.clone())
        .map_err(|_| io::Error::other("authenticated worker lifecycle port lock is poisoned"))
}

/// Native-only lifetime guard used by the CLI terminal adapter. JavaScript
/// can query neither this type nor its activation path; the engine bridge can
/// only ask whether closing fd 1/fd 2 is currently a no-op.
pub struct TerminalSessionOutputCloseGuard {
    _private: (),
}

pub fn arm_terminal_session_output_close_guard() -> io::Result<TerminalSessionOutputCloseGuard> {
    TERMINAL_SESSION_OUTPUT_CLOSE_GUARD
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a terminal-session output adapter is already active",
            )
        })?;
    Ok(TerminalSessionOutputCloseGuard { _private: () })
}

impl Drop for TerminalSessionOutputCloseGuard {
    fn drop(&mut self) {
        TERMINAL_SESSION_OUTPUT_CLOSE_GUARD.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[no_mangle]
pub extern "C" fn ex_host_terminal_session_close_is_noop(fd: i32) -> i32 {
    i32::from(ex_host_session_descriptor_close_route(fd) == SESSION_DESCRIPTOR_ROUTE_VIRTUAL)
}

fn normalized_io_error_code(err: &std::io::Error) -> i32 {
    use std::io::ErrorKind;
    #[cfg(windows)]
    if let Some(code) = err.raw_os_error() {
        // Preserve Win32 conditions that Node callers branch on. Mapping all
        // unrecognized Windows errors to EIO made rename fallbacks and rimraf
        // retries unreachable even though the C++ bridge understands these
        // POSIX spellings.
        match code {
            4 => return libc::EMFILE,        // ERROR_TOO_MANY_OPEN_FILES
            17 => return libc::EXDEV,        // ERROR_NOT_SAME_DEVICE
            39 | 112 => return libc::ENOSPC, // ERROR_HANDLE_DISK_FULL / ERROR_DISK_FULL
            145 => return libc::ENOTEMPTY,   // ERROR_DIR_NOT_EMPTY
            267 => return libc::ENOTDIR,     // ERROR_DIRECTORY
            _ => {}
        }
    }
    match err.kind() {
        ErrorKind::NotFound => libc::ENOENT,
        ErrorKind::PermissionDenied => libc::EACCES,
        ErrorKind::AlreadyExists => libc::EEXIST,
        ErrorKind::NotADirectory => libc::ENOTDIR,
        ErrorKind::IsADirectory => libc::EISDIR,
        ErrorKind::DirectoryNotEmpty => libc::ENOTEMPTY,
        ErrorKind::StorageFull | ErrorKind::QuotaExceeded => libc::ENOSPC,
        ErrorKind::CrossesDevices => libc::EXDEV,
        ErrorKind::InvalidInput | ErrorKind::InvalidData => libc::EINVAL,
        ErrorKind::UnexpectedEof => libc::EIO,
        ErrorKind::WriteZero => libc::ENOSPC,
        ErrorKind::WouldBlock => libc::EAGAIN,
        ErrorKind::TimedOut => libc::ETIMEDOUT,
        ErrorKind::Interrupted => libc::EINTR,
        _ => {
            #[cfg(unix)]
            {
                err.raw_os_error().unwrap_or(libc::EIO)
            }
            #[cfg(not(unix))]
            {
                libc::EIO
            }
        }
    }
}

fn record_fs_error(code: i32) {
    LAST_FS_ERROR.with(|slot| slot.set(code));
}

#[inline]
fn set_fs_error_code(code: i32) {
    record_fs_error(code);
    #[cfg(all(
        unix,
        not(target_os = "android"),
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "tvos"),
        not(target_os = "watchos")
    ))]
    unsafe {
        *libc::__errno_location() = code;
    }
    #[cfg(target_os = "android")]
    unsafe {
        *libc::__errno() = code;
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos"
    ))]
    unsafe {
        *libc::__error() = code;
    }
}

#[no_mangle]
pub extern "C" fn ex_host_fs_last_error() -> i32 {
    LAST_FS_ERROR.with(Cell::get)
}

#[cfg(all(
    unix,
    not(target_os = "android"),
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "tvos"),
    not(target_os = "watchos")
))]
#[inline]
fn set_errno_from_io_error(err: &std::io::Error) {
    let code = normalized_io_error_code(err);
    record_fs_error(code);
    unsafe {
        *libc::__errno_location() = code;
    }
}

#[cfg(target_os = "android")]
#[inline]
fn set_errno_from_io_error(err: &std::io::Error) {
    let code = normalized_io_error_code(err);
    record_fs_error(code);
    unsafe {
        *libc::__errno() = code;
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
#[inline]
fn set_errno_from_io_error(err: &std::io::Error) {
    let code = normalized_io_error_code(err);
    record_fs_error(code);
    unsafe {
        *libc::__error() = code;
    }
}

#[cfg(not(unix))]
#[inline]
fn set_errno_from_io_error(err: &std::io::Error) {
    record_fs_error(normalized_io_error_code(err));
}
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub const EXACT_HOST_ABI_VERSION: u32 = 1;

/// Version-1 typed result discriminants for the private runtime VFS bridge.
/// Zero is success; every non-zero value is a stable refusal/error class.
pub const EX_HOST_VFS_RESULT_OK: u32 = 0;
pub const EX_HOST_VFS_RESULT_CLOSED_OPERATION: u32 = 1;
pub const EX_HOST_VFS_RESULT_STALE_SESSION: u32 = 2;
pub const EX_HOST_VFS_RESULT_MALFORMED_INPUT: u32 = 3;
pub const EX_HOST_VFS_RESULT_ENCODED_SEPARATOR: u32 = 4;
pub const EX_HOST_VFS_RESULT_OUTSIDE_MOUNT: u32 = 5;
pub const EX_HOST_VFS_RESULT_SYNTHETIC_NODE: u32 = 6;
pub const EX_HOST_VFS_RESULT_POLICY_DENIED: u32 = 7;
pub const EX_HOST_VFS_RESULT_ABSENT: u32 = 8;
pub const EX_HOST_VFS_RESULT_SYMLINK_DEPTH: u32 = 9;
pub const EX_HOST_VFS_RESULT_UNMAPPABLE_LINK: u32 = 10;
pub const EX_HOST_VFS_RESULT_STALE_IDENTITY: u32 = 11;
pub const EX_HOST_VFS_RESULT_INPUT_TOO_LARGE: u32 = 12;
pub const EX_HOST_VFS_RESULT_HOST_ERROR: u32 = 13;

fn vfs_reason_discriminant(reason: crate::vfs::VfsReason) -> u32 {
    match reason {
        crate::vfs::VfsReason::ClosedOperation => EX_HOST_VFS_RESULT_CLOSED_OPERATION,
        crate::vfs::VfsReason::StaleSession => EX_HOST_VFS_RESULT_STALE_SESSION,
        crate::vfs::VfsReason::MalformedInput => EX_HOST_VFS_RESULT_MALFORMED_INPUT,
        crate::vfs::VfsReason::EncodedSeparator => EX_HOST_VFS_RESULT_ENCODED_SEPARATOR,
        crate::vfs::VfsReason::OutsideMount => EX_HOST_VFS_RESULT_OUTSIDE_MOUNT,
        crate::vfs::VfsReason::SyntheticNode => EX_HOST_VFS_RESULT_SYNTHETIC_NODE,
        crate::vfs::VfsReason::PolicyDenied => EX_HOST_VFS_RESULT_POLICY_DENIED,
        crate::vfs::VfsReason::Absent => EX_HOST_VFS_RESULT_ABSENT,
        crate::vfs::VfsReason::SymlinkDepthExceeded => EX_HOST_VFS_RESULT_SYMLINK_DEPTH,
        crate::vfs::VfsReason::UnmappableLink => EX_HOST_VFS_RESULT_UNMAPPABLE_LINK,
        crate::vfs::VfsReason::StaleIdentity => EX_HOST_VFS_RESULT_STALE_IDENTITY,
        crate::vfs::VfsReason::InputTooLarge => EX_HOST_VFS_RESULT_INPUT_TOO_LARGE,
        crate::vfs::VfsReason::HostError => EX_HOST_VFS_RESULT_HOST_ERROR,
    }
}

fn vfs_result_discriminant(error: &crate::vfs::VfsError) -> u32 {
    vfs_reason_discriminant(error.reason())
}

static HOST: OnceLock<RwLock<Host>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessIpcBootstrap {
    fd: i32,
    serialization: u32,
}

#[derive(Default)]
struct ProcessIpcBootstrapLease {
    initialized: bool,
    available: Option<ProcessIpcBootstrap>,
}

impl ProcessIpcBootstrapLease {
    fn initialize_with(&mut self, capture: impl FnOnce() -> Option<ProcessIpcBootstrap>) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        self.available = capture();
    }

    fn take(&mut self) -> Option<ProcessIpcBootstrap> {
        self.available.take()
    }
}

/// Capture the inherited child-process channel exactly once, at the
/// Host-to-engine construction handoff. The value is retained in a process-wide
/// one-shot lease and released only to the first eligible claimed, unarmed Host
/// context; neither armed `process.env` nor a later host-environment read
/// participates in JavaScript bootstrap.
/// @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
/// @ref LLP 0022#7-capabilities-principals-and-affordance-parity
/// @ref LLP 0025#2-startup-configuration-is-captured-before-arming
#[cfg(not(windows))]
fn capture_process_ipc_bootstrap() -> Option<ProcessIpcBootstrap> {
    let raw_fd = std::env::var("EXACT_IPC_FD").ok()?;
    let fd = parse_process_ipc_fd(&raw_fd)?;
    let serialization =
        u32::from(std::env::var("EXACT_IPC_SERIALIZATION").as_deref() == Ok("advanced"));
    Some(ProcessIpcBootstrap { fd, serialization })
}

#[cfg(any(not(windows), test))]
fn parse_process_ipc_fd(raw_fd: &str) -> Option<i32> {
    let digits = raw_fd.strip_prefix('+').unwrap_or(raw_fd);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    i32::try_from(digits.parse::<u32>().ok()?).ok()
}

// Native child-process IPC is a POSIX socket protocol. Windows spawn rejects
// `ipc` stdio and must not interpret environment text as a transferable HANDLE
// or descriptor authority.
#[cfg(windows)]
fn capture_process_ipc_bootstrap() -> Option<ProcessIpcBootstrap> {
    None
}

struct HostContextRecord {
    host: Arc<Host>,
    claimed: bool,
    runtime_nonce: Option<u64>,
    runtime_extension_leases: HashMap<u64, super::RuntimeExtensionLeaseGrant>,
}

impl HostContextRecord {
    fn runtime_extension_lease_is_current(&self, lease: u64) -> bool {
        fn visit(
            record: &HostContextRecord,
            lease: u64,
            visiting: &mut std::collections::BTreeSet<u64>,
        ) -> bool {
            if lease == 0 || !visiting.insert(lease) || visiting.len() > 256 {
                return false;
            }
            let current = record
                .runtime_extension_leases
                .get(&lease)
                .is_some_and(|grant| {
                    record.host.runtime_extension_lease_is_current(grant)
                        && grant
                            .presented_lease_ids
                            .iter()
                            .all(|presented| visit(record, *presented, visiting))
                });
            visiting.remove(&lease);
            current
        }

        visit(self, lease, &mut std::collections::BTreeSet::new())
    }

    fn try_runtime_extension_lease_is_current(
        &self,
        lease: u64,
    ) -> super::RuntimeExtensionLeaseStatus {
        fn visit(
            record: &HostContextRecord,
            lease: u64,
            visiting: &mut [u64; 256],
            depth: usize,
        ) -> super::RuntimeExtensionLeaseStatus {
            if lease == 0 || depth >= visiting.len() || visiting[..depth].contains(&lease) {
                return super::RuntimeExtensionLeaseStatus::Stale;
            }
            let Some(grant) = record.runtime_extension_leases.get(&lease) else {
                return super::RuntimeExtensionLeaseStatus::Stale;
            };
            visiting[depth] = lease;
            match record.host.try_runtime_extension_lease_is_current(grant) {
                super::RuntimeExtensionLeaseStatus::Current => {}
                status => return status,
            }
            for presented in &grant.presented_lease_ids {
                match visit(record, *presented, visiting, depth + 1) {
                    super::RuntimeExtensionLeaseStatus::Current => {}
                    status => return status,
                }
            }
            super::RuntimeExtensionLeaseStatus::Current
        }

        visit(self, lease, &mut [0; 256], 0)
    }
}

static HOST_CONTEXTS: OnceLock<RwLock<HashMap<u64, HostContextRecord>>> = OnceLock::new();
static PROCESS_IPC_BOOTSTRAP_LEASE: OnceLock<Mutex<ProcessIpcBootstrapLease>> = OnceLock::new();

#[cfg(all(test, feature = "runtime-extension-conformance"))]
pub(crate) fn with_runtime_extension_host_contexts_write_lock_for_test<R>(
    body: impl FnOnce() -> R,
) -> R {
    let contexts = HOST_CONTEXTS.get_or_init(|| RwLock::new(HashMap::new()));
    let _guard = contexts
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    body()
}

fn process_ipc_bootstrap_lease() -> &'static Mutex<ProcessIpcBootstrapLease> {
    PROCESS_IPC_BOOTSTRAP_LEASE.get_or_init(|| Mutex::new(ProcessIpcBootstrapLease::default()))
}

fn initialize_process_ipc_bootstrap_lease(host: &Host) {
    let mut lease = match process_ipc_bootstrap_lease().lock() {
        Ok(lease) => lease,
        Err(poisoned) => poisoned.into_inner(),
    };
    lease.initialize_with(|| {
        // The production armed entrypoint rejects these closed startup names.
        // Keep direct embedding paths equally closed: only an explicitly
        // unarmed compatibility Host may adopt the native IPC socket.
        if host.armed_snapshot().is_some() {
            None
        } else {
            capture_process_ipc_bootstrap()
        }
    });
}

fn take_process_ipc_bootstrap_for_context(
    contexts: &RwLock<HashMap<u64, HostContextRecord>>,
    lease: &Mutex<ProcessIpcBootstrapLease>,
    context_id: u64,
) -> Option<ProcessIpcBootstrap> {
    let contexts = match contexts.read() {
        Ok(contexts) => contexts,
        Err(poisoned) => poisoned.into_inner(),
    };
    let context = contexts.get(&context_id)?;
    if !context.claimed || context.host.armed_snapshot().is_some() {
        return None;
    }
    let mut lease = match lease.lock() {
        Ok(lease) => lease,
        Err(poisoned) => poisoned.into_inner(),
    };
    lease.take()
}

struct RuntimeVfsBinding {
    context_id: u64,
    session: Arc<crate::vfs::RuntimeVfsSession>,
}

static RUNTIME_VFS_SESSIONS: OnceLock<RwLock<HashMap<u64, RuntimeVfsBinding>>> = OnceLock::new();

struct PendingHostContext(Cell<u64>);

impl Drop for PendingHostContext {
    fn drop(&mut self) {
        let context_id = self.0.replace(0);
        if context_id != 0 {
            release_unclaimed_host_context(context_id);
        }
    }
}

thread_local! {
    static ACTIVE_HOST_CONTEXT: Cell<u64> = const { Cell::new(0) };
    /// Exact install-to-create handoff. A runtime can claim only the Host that
    /// its own creating thread most recently installed; equal snapshot digests
    /// in concurrent creators are therefore not interchangeable credentials.
    static PENDING_HOST_CONTEXT: PendingHostContext = const { PendingHostContext(Cell::new(0)) };
}
static SECURITY_LOG_ENABLED: OnceLock<bool> = OnceLock::new();
static CONSOLE_MIRROR_ENABLED: OnceLock<bool> = OnceLock::new();

#[cfg(test)]
pub(crate) fn host_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A SQLite connection is wrapped in its own `Mutex` and shared via `Arc` so
/// each connection can be locked independently. The process-global registry
/// lock is only held long enough to look up and clone this handle, not across
/// query execution — so a slow query on one connection no longer stalls every
/// other SQLite call process-wide.
type SqliteConnection = Arc<Mutex<Connection>>;

#[derive(Clone)]
struct SqliteStatementRecord {
    db_id: u64,
    sql: String,
    read_only: bool,
}

struct SqliteState {
    next_db_handle: u64,
    next_statement_handle: u64,
    dbs: HashMap<u64, SqliteConnection>,
    statements: HashMap<u64, SqliteStatementRecord>,
}

impl SqliteState {
    fn new() -> Self {
        Self {
            next_db_handle: 1,
            next_statement_handle: 1,
            dbs: HashMap::new(),
            statements: HashMap::new(),
        }
    }

    fn allocate_db_handle(&mut self) -> Option<u64> {
        let handle = self.next_db_handle;
        if handle == 0 || self.dbs.contains_key(&handle) {
            return None;
        }
        self.next_db_handle = handle.checked_add(1)?;
        Some(handle)
    }

    fn allocate_statement_handle(&mut self) -> Option<u64> {
        let handle = self.next_statement_handle;
        if handle == 0 || self.statements.contains_key(&handle) {
            return None;
        }
        self.next_statement_handle = handle.checked_add(1)?;
        Some(handle)
    }
}

static SQLITE_STATE: OnceLock<Mutex<SqliteState>> = OnceLock::new();

fn with_sqlite_state<T>(f: impl FnOnce(&mut SqliteState) -> T) -> T {
    let mutex = SQLITE_STATE.get_or_init(|| Mutex::new(SqliteState::new()));
    let mut state = match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut state)
}

/// Clone the shared handle for a connection. The registry lock is held only for
/// the lookup + `Arc` clone; callers then lock the per-connection mutex on their
/// own so independent connections execute concurrently.
fn sqlite_connection(db_id: u64) -> Option<SqliteConnection> {
    with_sqlite_state(|state| state.dbs.get(&db_id).map(Arc::clone))
}

/// Resolve a prepared-statement handle to its record plus the shared handle for
/// the connection it belongs to, in a single registry-lock critical section.
fn sqlite_statement_connection(
    statement_handle: u64,
) -> Option<(SqliteStatementRecord, SqliteConnection)> {
    with_sqlite_state(|state| {
        let statement = state.statements.get(&statement_handle)?.clone();
        let connection = state.dbs.get(&statement.db_id).map(Arc::clone)?;
        Some((statement, connection))
    })
}

/// Lock a connection for the duration of an operation, recovering the guard if a
/// previous holder panicked (a poisoned SQLite connection is still usable).
fn lock_connection(connection: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    match connection.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn allocate_host_context(host: Arc<Host>, claimed: bool) -> u64 {
    // Random context tokens are capabilities, not enumerable IDs. Zero is the
    // absent token and `u64::MAX` is the `ex_host_enter_context` failure
    // sentinel, so neither value may ever name a live context.
    // Entropy failure or repeated collisions fail closed instead of falling
    // back to a wrapping process-global counter.
    for _ in 0..32 {
        let mut bytes = [0u8; std::mem::size_of::<u64>()];
        if getrandom(&mut bytes).is_err() {
            return 0;
        }
        let context_id = u64::from_ne_bytes(bytes);
        if context_id == 0 || context_id == u64::MAX {
            continue;
        }
        let contexts = HOST_CONTEXTS.get_or_init(|| RwLock::new(HashMap::new()));
        let mut contexts = match contexts.write() {
            Ok(contexts) => contexts,
            Err(poisoned) => poisoned.into_inner(),
        };
        if contexts.contains_key(&context_id) {
            continue;
        }
        contexts.insert(
            context_id,
            HostContextRecord {
                host: Arc::clone(&host),
                claimed,
                runtime_nonce: None,
                runtime_extension_leases: HashMap::new(),
            },
        );
        return context_id;
    }
    0
}

fn insert_host_context(host: Arc<Host>, claimed: bool) -> u64 {
    // Capture at most once for the process, before engine JavaScript exists.
    // Unclaimed Host replacement does not clone or discard the lease; only the
    // first eligible claimed context can consume it.
    initialize_process_ipc_bootstrap_lease(&host);
    allocate_host_context(host, claimed)
}

/// Give a restricted auxiliary runtime its own closed Host selection without
/// consuming or replacing the thread's install-to-constructor handoff. This is
/// an implementation bridge rather than a public embedder surface.
/// @ref LLP 0002#runtime-driving-thread-contract
#[export_name = "ibex_private_claim_restricted_host_context"]
pub(crate) extern "C" fn private_claim_restricted_host_context() -> u64 {
    allocate_host_context(Arc::new(Host::closed_unarmed()), true)
}

fn release_unclaimed_host_context(context_id: u64) {
    let Some(contexts) = HOST_CONTEXTS.get() else {
        return;
    };
    let mut contexts = match contexts.write() {
        Ok(contexts) => contexts,
        Err(poisoned) => poisoned.into_inner(),
    };
    if contexts
        .get(&context_id)
        .is_some_and(|context| !context.claimed)
    {
        contexts.remove(&context_id);
    }
}

/// Publish a Host and retain an exact, thread-bound creation token for the
/// next Hermes constructor on this thread. Replacing an unclaimed install
/// retires it immediately; thread teardown retires any remaining token.
pub fn install_host(host: Host) -> u64 {
    let previous = PENDING_HOST_CONTEXT.with(|pending| pending.0.replace(0));
    if previous != 0 {
        release_unclaimed_host_context(previous);
    }

    let context_id = insert_host_context(Arc::new(host.clone()), false);
    if context_id != 0 {
        PENDING_HOST_CONTEXT.with(|pending| pending.0.set(context_id));
    }
    if let Some(slot) = HOST.get() {
        match slot.write() {
            Ok(mut current) => {
                *current = host;
            }
            Err(poisoned) => {
                *poisoned.into_inner() = host;
            }
        }
        return context_id;
    }

    let _ = HOST.set(RwLock::new(host));
    context_id
}

/// Move the construction-time child-process IPC signal out of its exact Host
/// context.  This is deliberately an `ibex_private_*` implementation bridge,
/// not a public embedder ABI, and it is one-shot: a second runtime cannot replay
/// a descriptor signal captured for the first.
///
/// `serialization` is 0 for JSON and 1 for the advanced codec.
/// @ref LLP 0022#7-capabilities-principals-and-affordance-parity
/// @ref LLP 0025#2-startup-configuration-is-captured-before-arming
#[export_name = "ibex_private_take_process_ipc_bootstrap"]
pub(crate) unsafe extern "C" fn private_take_process_ipc_bootstrap(
    context_id: u64,
    out_fd: *mut i32,
    out_serialization: *mut u32,
) -> i32 {
    if out_fd.is_null() || out_serialization.is_null() {
        return 0;
    }
    unsafe {
        *out_fd = -1;
        *out_serialization = 0;
    }
    let Some(contexts) = HOST_CONTEXTS.get() else {
        return 0;
    };
    let Some(bootstrap) =
        take_process_ipc_bootstrap_for_context(contexts, process_ipc_bootstrap_lease(), context_id)
    else {
        return 0;
    };
    unsafe {
        *out_fd = bootstrap.fd;
        *out_serialization = bootstrap.serialization;
    }
    1
}

/// Install an immutable armed host from caller-owned bytes. The bytes are
/// copied and authenticated before publication; later caller mutation cannot
/// affect the installed decision context.
/// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
pub fn install_armed_host(snapshot: &[u8], expected_json: &[u8]) -> Result<(), String> {
    use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
    let mut phase = super::HostStartupPhaseTrace::begin();
    super::reject_closed_startup_environment().map_err(|error| error.to_string())?;
    phase.mark("install_environment");
    let expected_text = std::str::from_utf8(expected_json)
        .map_err(|error| format!("expected arming identity is not UTF-8: {error}"))?;
    let expected_value = capsec_semantics::strict_json::parse_strict(expected_text)
        .map_err(|error| error.to_string())?;
    let expected: ExpectedArmingIdentity = serde_json::from_value(expected_value)
        .map_err(|error| format!("invalid expected arming identity: {error}"))?;
    phase.mark("install_expected_identity");
    let armed = ArmedSnapshot::load(snapshot, &expected).map_err(|error| error.to_string())?;
    phase.mark("install_snapshot_load");
    validate_dev_served_project_root_pairing(&armed)?;
    phase.mark("install_dev_root_pairing");
    #[cfg(not(feature = "capsec-simulator-performance-observer"))]
    let host = Host::new_armed(
        super::HostConfig {
            mode: super::SecurityMode::Enforce,
            ..Default::default()
        },
        Arc::new(armed),
    )
    .map_err(|error| error.to_string())?;
    #[cfg(feature = "capsec-simulator-performance-observer")]
    let host = Host::new_armed_for_capsec_simulator_performance_observer(
        super::HostConfig {
            mode: super::SecurityMode::Enforce,
            ..Default::default()
        },
        Arc::new(armed),
    )
    .map_err(|error| error.to_string())?;
    phase.mark("install_host_construct");
    if install_host(host) == 0 {
        return Err("failed to allocate an armed Host context token".into());
    }
    phase.mark("install_publish");
    Ok(())
}

pub(super) fn validate_dev_served_project_root_pairing(
    armed: &capsec_semantics::arming::ArmedSnapshot,
) -> Result<(), String> {
    use capsec_semantics::model::{LogicalPath, LogicalRoot};

    let admits_dev_served = armed
        .bootstrap_compatibility_modes()
        .iter()
        .any(|mode| mode == "dev-served");
    let claimed_root = armed.document().get("devServedProjectRoot");
    if !admits_dev_served {
        return if claimed_root.is_none() {
            Ok(())
        } else {
            Err("dev-served project root requires the dev-served compatibility mode".into())
        };
    }
    let claimed_root: LogicalPath =
        serde_json::from_value(claimed_root.cloned().ok_or_else(|| {
            "dev-served compatibility mode requires an explicit dev project root binding".to_owned()
        })?)
        .map_err(|error| format!("invalid dev-served project root binding: {error}"))?;
    let project_binding = armed
        .root_bindings()
        .map_err(|error| error.to_string())?
        .iter()
        .find(|binding| binding.logical_root == LogicalRoot::Project)
        .ok_or_else(|| {
            "dev-served compatibility mode requires the project root binding".to_owned()
        })?;
    if claimed_root != project_binding.host_path
        || claimed_root != armed.project_root_discovery().selected_root
    {
        return Err(
            "dev-served project root must equal the authenticated project root binding".into(),
        );
    }
    Ok(())
}

/// Prepare one construction-fresh authenticated artifact pair for a native
/// embedder. The returned strict JSON envelope is owned by Rust and must be
/// released with `ex_host_free_string`.
///
/// Success: `{ "ok": true, "artifacts": { ... } }`.
/// Refusal: `{ "ok": false, "error": "..." }`.
///
/// # Safety
///
/// Each non-null input pointer must reference its declared byte length for the
/// duration of this call. The input buffers are read-only and are not retained.
/// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
#[no_mangle]
pub unsafe extern "C" fn ex_host_prepare_armed_embedder_artifacts(
    snapshot_template: *const u8,
    snapshot_template_len: usize,
    expected_identity: *const u8,
    expected_identity_len: usize,
) -> *mut c_char {
    let result = if snapshot_template.is_null()
        || snapshot_template_len == 0
        || expected_identity.is_null()
        || expected_identity_len == 0
    {
        Err(anyhow::anyhow!(
            "snapshot template and expected identity are required"
        ))
    } else {
        let snapshot =
            unsafe { std::slice::from_raw_parts(snapshot_template, snapshot_template_len) };
        let expected =
            unsafe { std::slice::from_raw_parts(expected_identity, expected_identity_len) };
        super::embedder_artifacts::prepare_embedder_artifacts(snapshot, expected)
    };
    let envelope = match result {
        Ok(artifacts) => serde_json::json!({"ok": true, "artifacts": artifacts}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
    };
    CString::new(envelope.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Bind one strict Exact operation manifest to an authenticated generic Ibex
/// artifact pair, materialize it as the fifth protected artifact, and return a
/// construction-fresh pair. The returned string is released with
/// `ex_host_free_string`.
///
/// # Safety
///
/// Each non-null pointer must reference its declared byte length for this call.
/// Inputs are copied or consumed synchronously and are not retained.
/// @ref LLP 0002#the-exact-embedder-ingress — operation endowments come only
/// from the digest-bound manifest, never from a caller-selected allowlist.
#[no_mangle]
pub unsafe extern "C" fn ex_host_prepare_exact_armed_embedder_artifacts(
    snapshot_template: *const u8,
    snapshot_template_len: usize,
    expected_identity: *const u8,
    expected_identity_len: usize,
    operation_manifest: *const u8,
    operation_manifest_len: usize,
) -> *mut c_char {
    let result = if snapshot_template.is_null()
        || snapshot_template_len == 0
        || expected_identity.is_null()
        || expected_identity_len == 0
        || operation_manifest.is_null()
        || operation_manifest_len == 0
    {
        Err(anyhow::anyhow!(
            "snapshot template, expected identity, and Exact operation manifest are required"
        ))
    } else {
        let snapshot =
            unsafe { std::slice::from_raw_parts(snapshot_template, snapshot_template_len) };
        let expected =
            unsafe { std::slice::from_raw_parts(expected_identity, expected_identity_len) };
        let manifest =
            unsafe { std::slice::from_raw_parts(operation_manifest, operation_manifest_len) };
        super::embedder_artifacts::prepare_exact_embedder_artifacts(snapshot, expected, manifest)
    };
    let envelope = match result {
        Ok(artifacts) => serde_json::json!({"ok": true, "artifacts": artifacts}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
    };
    CString::new(envelope.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Carrier-bearing sibling of `ex_host_prepare_exact_armed_embedder_artifacts`
/// (LLP 0053 §I2): the additional strict `exact/carrier-binding/1` JSON input
/// is validated through the armed-snapshot carrier machinery and embedded as
/// the required `carrierBinding` of an `exact/host-operation-endowments/2`
/// binding before nonce freshening and digest recomputation.
///
/// # Safety
///
/// Each non-null pointer must reference its declared byte length for this call.
/// Inputs are copied or consumed synchronously and are not retained.
#[no_mangle]
pub unsafe extern "C" fn ex_host_prepare_exact_armed_embedder_artifacts_v2(
    snapshot_template: *const u8,
    snapshot_template_len: usize,
    expected_identity: *const u8,
    expected_identity_len: usize,
    operation_manifest: *const u8,
    operation_manifest_len: usize,
    carrier_binding_json: *const u8,
    carrier_binding_json_len: usize,
) -> *mut c_char {
    let result = if snapshot_template.is_null()
        || snapshot_template_len == 0
        || expected_identity.is_null()
        || expected_identity_len == 0
        || operation_manifest.is_null()
        || operation_manifest_len == 0
        || carrier_binding_json.is_null()
        || carrier_binding_json_len == 0
    {
        Err(anyhow::anyhow!(
            "snapshot template, expected identity, Exact operation manifest, and carrier binding are required"
        ))
    } else {
        let snapshot =
            unsafe { std::slice::from_raw_parts(snapshot_template, snapshot_template_len) };
        let expected =
            unsafe { std::slice::from_raw_parts(expected_identity, expected_identity_len) };
        let manifest =
            unsafe { std::slice::from_raw_parts(operation_manifest, operation_manifest_len) };
        let carrier =
            unsafe { std::slice::from_raw_parts(carrier_binding_json, carrier_binding_json_len) };
        super::embedder_artifacts::prepare_exact_embedder_artifacts_v2(
            snapshot, expected, manifest, carrier,
        )
    };
    let envelope = match result {
        Ok(artifacts) => serde_json::json!({"ok": true, "artifacts": artifacts}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
    };
    CString::new(envelope.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Build a complete target-local Exact artifact pair from the installed
/// project root and the checked operation manifest. The project-root bytes are
/// UTF-8 and need not be NUL terminated. The returned string is released with
/// `ex_host_free_string`.
///
/// # Safety
///
/// Each non-null pointer must reference its declared byte length for this call.
/// Inputs are copied or consumed synchronously and are not retained.
/// @ref LLP 0002#the-exact-embedder-ingress — the native embedder supplies its
/// installed root and checked manifest, never an operation allowlist.
#[no_mangle]
pub unsafe extern "C" fn ex_host_build_exact_armed_embedder_artifacts(
    project_root_utf8: *const u8,
    project_root_utf8_len: usize,
    dev_project_root_utf8: *const u8,
    dev_project_root_utf8_len: usize,
    operation_manifest: *const u8,
    operation_manifest_len: usize,
) -> *mut c_char {
    let result = if project_root_utf8.is_null()
        || project_root_utf8_len == 0
        || operation_manifest.is_null()
        || operation_manifest_len == 0
    {
        Err(anyhow::anyhow!(
            "Exact project root and operation manifest are required"
        ))
    } else {
        let root_bytes =
            unsafe { std::slice::from_raw_parts(project_root_utf8, project_root_utf8_len) };
        let root = std::str::from_utf8(root_bytes)
            .map(std::path::Path::new)
            .map_err(|error| anyhow::anyhow!("Exact project root is not UTF-8: {error}"));
        let manifest =
            unsafe { std::slice::from_raw_parts(operation_manifest, operation_manifest_len) };
        let dev_root = unsafe {
            optional_utf8_path(
                dev_project_root_utf8,
                dev_project_root_utf8_len,
                "Exact dev project root",
            )
        };
        root.and_then(|root| {
            dev_root.and_then(|dev_root| {
                super::embedder_artifacts::build_exact_embedder_artifacts(root, dev_root, manifest)
            })
        })
    };
    let envelope = match result {
        Ok(artifacts) => serde_json::json!({"ok": true, "artifacts": artifacts}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
    };
    CString::new(envelope.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Carrier-bearing sibling of `ex_host_build_exact_armed_embedder_artifacts`
/// (LLP 0053 §I2): the additional strict `exact/carrier-binding/1` JSON input
/// is validated and embedded as the required `carrierBinding` of a /2 binding
/// before nonce freshening and digest recomputation.
///
/// # Safety
///
/// Each non-null pointer must reference its declared byte length for this call.
/// Inputs are copied or consumed synchronously and are not retained.
#[no_mangle]
pub unsafe extern "C" fn ex_host_build_exact_armed_embedder_artifacts_v2(
    project_root_utf8: *const u8,
    project_root_utf8_len: usize,
    dev_project_root_utf8: *const u8,
    dev_project_root_utf8_len: usize,
    operation_manifest: *const u8,
    operation_manifest_len: usize,
    carrier_binding_json: *const u8,
    carrier_binding_json_len: usize,
) -> *mut c_char {
    let result = if project_root_utf8.is_null()
        || project_root_utf8_len == 0
        || operation_manifest.is_null()
        || operation_manifest_len == 0
        || carrier_binding_json.is_null()
        || carrier_binding_json_len == 0
    {
        Err(anyhow::anyhow!(
            "Exact project root, operation manifest, and carrier binding are required"
        ))
    } else {
        let root_bytes =
            unsafe { std::slice::from_raw_parts(project_root_utf8, project_root_utf8_len) };
        let root = std::str::from_utf8(root_bytes)
            .map(std::path::Path::new)
            .map_err(|error| anyhow::anyhow!("Exact project root is not UTF-8: {error}"));
        let manifest =
            unsafe { std::slice::from_raw_parts(operation_manifest, operation_manifest_len) };
        let carrier =
            unsafe { std::slice::from_raw_parts(carrier_binding_json, carrier_binding_json_len) };
        let dev_root = unsafe {
            optional_utf8_path(
                dev_project_root_utf8,
                dev_project_root_utf8_len,
                "Exact dev project root",
            )
        };
        root.and_then(|root| {
            dev_root.and_then(|dev_root| {
                super::embedder_artifacts::build_exact_embedder_artifacts_v2(
                    root, dev_root, manifest, carrier,
                )
            })
        })
    };
    let envelope = match result {
        Ok(artifacts) => serde_json::json!({"ok": true, "artifacts": artifacts}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
    };
    CString::new(envelope.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Build a complete target-local Exact artifact pair with one authenticated,
/// statically linked runtime-extension set. The authority capsule and
/// launcher-observed loaded-executable file identity are separate strict JSON
/// inputs (the latter retains a historical mapped-executable schema name);
/// descriptor labels cannot authenticate their own executable.
///
/// # Safety
///
/// Each non-null pointer must reference its declared byte length for this
/// call. Inputs are copied or consumed synchronously and are not retained.
/// The optional dev-project-root pair is valid only as `(NULL, 0)` or a
/// non-empty UTF-8 byte string.
/// @ref LLP 0040#authenticated-construction-projection
#[no_mangle]
pub unsafe extern "C" fn ex_host_build_exact_runtime_extension_armed_embedder_artifacts(
    project_root_utf8: *const u8,
    project_root_utf8_len: usize,
    dev_project_root_utf8: *const u8,
    dev_project_root_utf8_len: usize,
    operation_manifest: *const u8,
    operation_manifest_len: usize,
    authority_capsule: *const u8,
    authority_capsule_len: usize,
    launcher_mapped_executable: *const u8,
    launcher_mapped_executable_len: usize,
) -> *mut c_char {
    let result = if project_root_utf8.is_null()
        || project_root_utf8_len == 0
        || operation_manifest.is_null()
        || operation_manifest_len == 0
        || authority_capsule.is_null()
        || authority_capsule_len == 0
        || launcher_mapped_executable.is_null()
        || launcher_mapped_executable_len == 0
    {
        Err(anyhow::anyhow!(
            "Exact project root, operation manifest, runtime-extension authority capsule, and launcher loaded-executable file identity are required"
        ))
    } else {
        let root_bytes =
            unsafe { std::slice::from_raw_parts(project_root_utf8, project_root_utf8_len) };
        let root = std::str::from_utf8(root_bytes)
            .map(std::path::Path::new)
            .map_err(|error| anyhow::anyhow!("Exact project root is not UTF-8: {error}"));
        let manifest =
            unsafe { std::slice::from_raw_parts(operation_manifest, operation_manifest_len) };
        let capsule =
            unsafe { std::slice::from_raw_parts(authority_capsule, authority_capsule_len) };
        let mapped_executable = unsafe {
            std::slice::from_raw_parts(launcher_mapped_executable, launcher_mapped_executable_len)
        };
        let dev_root = unsafe {
            optional_utf8_path(
                dev_project_root_utf8,
                dev_project_root_utf8_len,
                "Exact dev project root",
            )
        };
        root.and_then(|root| {
            dev_root.and_then(|dev_root| {
                super::embedder_artifacts::build_exact_runtime_extension_embedder_artifacts(
                    root,
                    dev_root,
                    manifest,
                    capsule,
                    mapped_executable,
                )
            })
        })
    };
    let envelope = match result {
        Ok(artifacts) => serde_json::json!({"ok": true, "artifacts": artifacts}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
    };
    CString::new(envelope.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Carrier-bearing sibling of
/// `ex_host_build_exact_runtime_extension_armed_embedder_artifacts`
/// (LLP 0053 §I2): the additional strict `exact/carrier-binding/1` JSON input
/// is validated and embedded as the required `carrierBinding` of a /2 binding
/// before nonce freshening and digest recomputation.
///
/// # Safety
///
/// Each non-null pointer must reference its declared byte length for this
/// call. Inputs are copied or consumed synchronously and are not retained.
/// The optional dev-project-root pair is valid only as `(NULL, 0)` or a
/// non-empty UTF-8 byte string.
#[no_mangle]
pub unsafe extern "C" fn ex_host_build_exact_runtime_extension_armed_embedder_artifacts_v2(
    project_root_utf8: *const u8,
    project_root_utf8_len: usize,
    dev_project_root_utf8: *const u8,
    dev_project_root_utf8_len: usize,
    operation_manifest: *const u8,
    operation_manifest_len: usize,
    authority_capsule: *const u8,
    authority_capsule_len: usize,
    launcher_mapped_executable: *const u8,
    launcher_mapped_executable_len: usize,
    carrier_binding_json: *const u8,
    carrier_binding_json_len: usize,
) -> *mut c_char {
    let result = if project_root_utf8.is_null()
        || project_root_utf8_len == 0
        || operation_manifest.is_null()
        || operation_manifest_len == 0
        || authority_capsule.is_null()
        || authority_capsule_len == 0
        || launcher_mapped_executable.is_null()
        || launcher_mapped_executable_len == 0
        || carrier_binding_json.is_null()
        || carrier_binding_json_len == 0
    {
        Err(anyhow::anyhow!(
            "Exact project root, operation manifest, runtime-extension authority capsule, launcher loaded-executable file identity, and carrier binding are required"
        ))
    } else {
        let root_bytes =
            unsafe { std::slice::from_raw_parts(project_root_utf8, project_root_utf8_len) };
        let root = std::str::from_utf8(root_bytes)
            .map(std::path::Path::new)
            .map_err(|error| anyhow::anyhow!("Exact project root is not UTF-8: {error}"));
        let manifest =
            unsafe { std::slice::from_raw_parts(operation_manifest, operation_manifest_len) };
        let capsule =
            unsafe { std::slice::from_raw_parts(authority_capsule, authority_capsule_len) };
        let mapped_executable = unsafe {
            std::slice::from_raw_parts(launcher_mapped_executable, launcher_mapped_executable_len)
        };
        let carrier =
            unsafe { std::slice::from_raw_parts(carrier_binding_json, carrier_binding_json_len) };
        let dev_root = unsafe {
            optional_utf8_path(
                dev_project_root_utf8,
                dev_project_root_utf8_len,
                "Exact dev project root",
            )
        };
        root.and_then(|root| {
            dev_root.and_then(|dev_root| {
                super::embedder_artifacts::build_exact_runtime_extension_embedder_artifacts_v2(
                    root,
                    dev_root,
                    manifest,
                    capsule,
                    mapped_executable,
                    carrier,
                )
            })
        })
    };
    let envelope = match result {
        Ok(artifacts) => serde_json::json!({"ok": true, "artifacts": artifacts}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
    };
    CString::new(envelope.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Finalize a generated runtime-extension authority template against a
/// launcher-observed loaded executable before Hermes construction.
///
/// # Safety
///
/// Both byte pointers must reference their declared lengths. All four output
/// pointers must be non-null and are initialized to null before any fallible
/// work. Successful outputs are independent C strings released through
/// `ex_host_free_string`.
/// @abi-output ex_host_finalize_runtime_extension_authority_v1 out_authority_capsule role=output kind=pointer ownership=caller-frees:ex_host_free_string
/// @abi-output ex_host_finalize_runtime_extension_authority_v1 out_authority_capsule_digest role=output kind=pointer ownership=caller-frees:ex_host_free_string
/// @abi-output ex_host_finalize_runtime_extension_authority_v1 out_executable_selection_identity role=output kind=pointer ownership=caller-frees:ex_host_free_string
/// @abi-output ex_host_finalize_runtime_extension_authority_v1 out_mapped_executable role=output kind=pointer ownership=caller-frees:ex_host_free_string
#[no_mangle]
pub unsafe extern "C" fn ex_host_finalize_runtime_extension_authority_v1(
    authority_template: *const u8,
    authority_template_len: usize,
    loaded_image_observation: *const u8,
    loaded_image_observation_len: usize,
    out_authority_capsule: *mut *mut c_char,
    out_authority_capsule_digest: *mut *mut c_char,
    out_executable_selection_identity: *mut *mut c_char,
    out_mapped_executable: *mut *mut c_char,
) -> i32 {
    const INVALID_ARGUMENT: i32 = 1;
    const AUTHENTICATION_FAILED: i32 = 5;
    if out_authority_capsule.is_null()
        || out_authority_capsule_digest.is_null()
        || out_executable_selection_identity.is_null()
        || out_mapped_executable.is_null()
    {
        return INVALID_ARGUMENT;
    }
    unsafe {
        *out_authority_capsule = std::ptr::null_mut();
        *out_authority_capsule_digest = std::ptr::null_mut();
        *out_executable_selection_identity = std::ptr::null_mut();
        *out_mapped_executable = std::ptr::null_mut();
    }
    if authority_template.is_null()
        || authority_template_len == 0
        || loaded_image_observation.is_null()
        || loaded_image_observation_len == 0
    {
        return INVALID_ARGUMENT;
    }
    let template =
        unsafe { std::slice::from_raw_parts(authority_template, authority_template_len) };
    let observation = unsafe {
        std::slice::from_raw_parts(loaded_image_observation, loaded_image_observation_len)
    };
    let finalized = match super::embedder_artifacts::finalize_runtime_extension_authority(
        template,
        observation,
    ) {
        Ok(finalized) => finalized,
        Err(error) => {
            eprintln!("Ibex runtime-extension authority finalization refused: {error:#}");
            return AUTHENTICATION_FAILED;
        }
    };
    let capsule = match CString::new(finalized.authority_capsule_bytes) {
        Ok(value) => value,
        Err(_) => return AUTHENTICATION_FAILED,
    };
    let authority_digest = match CString::new(finalized.authority_capsule_digest) {
        Ok(value) => value,
        Err(_) => return AUTHENTICATION_FAILED,
    };
    let selection_identity = match CString::new(finalized.executable_selection_identity) {
        Ok(value) => value,
        Err(_) => return AUTHENTICATION_FAILED,
    };
    let mapped_executable = match CString::new(finalized.mapped_executable_bytes) {
        Ok(value) => value,
        Err(_) => return AUTHENTICATION_FAILED,
    };
    unsafe {
        *out_authority_capsule = capsule.into_raw();
        *out_authority_capsule_digest = authority_digest.into_raw();
        *out_executable_selection_identity = selection_identity.into_raw();
        *out_mapped_executable = mapped_executable.into_raw();
    }
    0
}

unsafe fn optional_utf8_path<'a>(
    bytes: *const u8,
    len: usize,
    label: &str,
) -> anyhow::Result<Option<&'a std::path::Path>> {
    if bytes.is_null() && len == 0 {
        return Ok(None);
    }
    anyhow::ensure!(
        !bytes.is_null() && len > 0,
        "{label} pointer and length must be supplied together"
    );
    let bytes = unsafe { std::slice::from_raw_parts(bytes, len) };
    let text = std::str::from_utf8(bytes)
        .map_err(|error| anyhow::anyhow!("{label} is not UTF-8: {error}"))?;
    Ok(Some(std::path::Path::new(text)))
}

/// REAL installed-host arming state for the dev-unarmed committed embedder's
/// construction-time exclusion (runner_pipeline::dev_committed_embedder).
/// Unlike `ex_host_is_armed`, this never takes the `insecure` presentation
/// branch: an armed Host must exclude the dev admission even in builds that
/// present themselves as unarmed.
/// @ref LLP 0042#visible-non-production — armed contexts never reach dev admission
#[cfg(feature = "dev-committed-embedder")]
pub(crate) fn installed_host_is_armed_for_dev_exclusion() -> bool {
    with_host(|host| host.armed_snapshot().is_some(), false)
}

fn with_host<T>(f: impl FnOnce(&Host) -> T, default: T) -> T {
    let active = ACTIVE_HOST_CONTEXT.with(Cell::get);
    if active != 0 {
        let selected = HOST_CONTEXTS.get().and_then(|contexts| {
            contexts
                .read()
                .ok()?
                .get(&active)
                .map(|row| row.host.clone())
        });
        if let Some(host) = selected {
            return f(&host);
        }
        return default;
    }
    let Some(host) = HOST.get() else {
        return default;
    };

    match host.read() {
        Ok(current) => f(&current),
        Err(poisoned) => f(&poisoned.into_inner()),
    }
}

/// Resolve one native schedule-time principal against the exact Host context
/// and runtime generation that captured it. This is an internal authenticated
/// event bridge, not ambient-host fallback: a stale/mismatched context returns
/// `None` and callers must surface attribution as unavailable.
/// @ref LLP 0024#9-asynchronous-failures
#[doc(hidden)]
pub fn authenticated_principal_for_host_context(
    context_id: u64,
    runtime_nonce: u64,
    principal_id: u64,
) -> Option<capsec_semantics::model::Principal> {
    const RUNTIME_PRINCIPAL_ID: u64 = 0xFFFF_FFFF;
    const NO_USER_PRINCIPAL_ID: u64 = 0xFFFF_FFFE;

    if context_id == 0 || runtime_nonce == 0 || principal_id == NO_USER_PRINCIPAL_ID {
        return None;
    }
    let host = HOST_CONTEXTS.get().and_then(|contexts| {
        let contexts = contexts.read().ok()?;
        let record = contexts.get(&context_id)?;
        (record.claimed && record.runtime_nonce == Some(runtime_nonce))
            .then(|| Arc::clone(&record.host))
    })?;
    if principal_id == RUNTIME_PRINCIPAL_ID {
        return Some(capsec_semantics::model::Principal::Runtime {
            identity: capsec_semantics::model::NonEmptyString::new("ibex-runtime-internal")
                .expect("static runtime principal identity is non-empty"),
        });
    }
    host.typed_principal_for_module(&principal_id.to_string())
}

#[cfg(any(test, feature = "module-runner"))]
pub(crate) fn current_module_runner_snapshot(
) -> anyhow::Result<std::sync::Arc<capsec_semantics::arming::ArmedSnapshot>> {
    with_host(
        |host| {
            host.armed_snapshot()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("module runner requires an armed snapshot"))
        },
        Err(anyhow::anyhow!("module runner host is not installed")),
    )
}

#[cfg(any(test, feature = "module-runner"))]
pub(crate) fn resolve_module_meta_for_runner(
    specifier: &str,
    referrer: Option<&std::path::Path>,
    requester_module_id: Option<&str>,
    kind: crate::module_loader::identity::ResolutionKind,
    attributes: &crate::module_loader::identity::ImportAttributes,
) -> anyhow::Result<crate::module_loader::ResolvedModule> {
    with_host(
        |host| {
            let mut meta = host.resolve_module_meta_for_principal_typed_with_attributes(
                specifier,
                referrer,
                requester_module_id,
                kind,
                attributes,
            )?;
            if meta
                .path
                .as_deref()
                .and_then(std::path::Path::extension)
                .and_then(|value| value.to_str())
                .is_some_and(|extension| {
                    matches!(
                        extension.to_ascii_lowercase().as_str(),
                        "mjs" | "mts" | "ts" | "tsx" | "jsx"
                    )
                })
            {
                meta.kind = crate::module_loader::ModuleKind::Esm;
            }
            Ok(meta)
        },
        Err(anyhow::anyhow!("module runner host is not installed")),
    )
}

#[cfg(any(test, feature = "module-runner"))]
pub(crate) fn load_module_source_for_runner(
    meta: crate::module_loader::ResolvedModule,
) -> anyhow::Result<crate::module_loader::ResolvedModule> {
    with_host(
        |host| host.load_authenticated_module_source_for_runner(meta),
        Err(anyhow::anyhow!("module runner host is not installed")),
    )
}

#[cfg(any(test, feature = "module-runner"))]
pub(crate) fn resolve_manifest_builtin_internal_for_runner(
    specifier: &str,
) -> anyhow::Result<crate::module_loader::ResolvedModule> {
    with_host(
        |host| host.resolve_manifest_builtin_internal(specifier),
        Err(anyhow::anyhow!("module runner host is not installed")),
    )
}

#[cfg(any(
    test,
    feature = "module-runner",
    feature = "capsec-conformance-observer"
))]
pub(crate) fn module_runner_principal_id(
    principal: &capsec_semantics::model::Principal,
) -> anyhow::Result<u32> {
    with_host(
        |host| host.module_runner_principal_id(principal),
        Err(anyhow::anyhow!("module runner host is not installed")),
    )
}

#[cfg(any(test, feature = "module-runner"))]
pub(crate) fn authenticate_prepared_module_record(
    path: &std::path::Path,
    source_id: &crate::module_loader::identity::SourceId,
    source_integrity: &capsec_semantics::model::Digest,
) -> anyhow::Result<()> {
    with_host(
        |host| host.authenticate_prepared_module_record(path, source_id, source_integrity),
        Err(anyhow::anyhow!("module runner host is not installed")),
    )
}

#[derive(Clone, Copy)]
enum RuntimeExtensionAuthorityClaim<'a> {
    Ignore,
    RequireEmpty,
    RequireExact(&'a str),
}

fn claim_pending_host_context(
    require_armed_digest: Option<&str>,
    extension_claim: RuntimeExtensionAuthorityClaim<'_>,
) -> u64 {
    let context_id = PENDING_HOST_CONTEXT.with(|pending| pending.0.get());
    if context_id == 0 {
        // Diagnostic construction is explicit and may be used without an
        // embedder-installed Host. Its fallback is a fresh audit context;
        // armed construction never has a fallback.
        return if require_armed_digest.is_none()
            && matches!(extension_claim, RuntimeExtensionAuthorityClaim::Ignore)
        {
            insert_host_context(
                Arc::new(Host::new(super::HostConfig {
                    mode: super::SecurityMode::Audit,
                    ..Default::default()
                })),
                true,
            )
        } else {
            0
        };
    }
    let Some(contexts) = HOST_CONTEXTS.get() else {
        return 0;
    };
    let mut contexts = match contexts.write() {
        Ok(contexts) => contexts,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(context) = contexts.get_mut(&context_id) else {
        return 0;
    };
    if context.claimed {
        return 0;
    }
    let kind_matches = match require_armed_digest {
        Some(digest) => context
            .host
            .armed_snapshot()
            .is_some_and(|snapshot| snapshot.digest().as_str() == digest),
        None => context.host.armed_snapshot().is_none(),
    };
    if !kind_matches {
        return 0;
    }
    let extension_matches = match extension_claim {
        RuntimeExtensionAuthorityClaim::Ignore => true,
        RuntimeExtensionAuthorityClaim::RequireEmpty => context
            .host
            .armed_snapshot()
            .is_some_and(|snapshot| snapshot.runtime_extension_authority().is_none()),
        RuntimeExtensionAuthorityClaim::RequireExact(authority_digest) => context
            .host
            .matches_runtime_extension_authority_digest(authority_digest),
    };
    if !extension_matches {
        return 0;
    }
    context.claimed = true;
    PENDING_HOST_CONTEXT.with(|pending| pending.0.set(0));
    context_id
}

fn bind_runtime_vfs_session(
    context_id: u64,
    runtime_nonce: u64,
) -> Result<(), crate::vfs::VfsError> {
    let runtime_nonce = NonZeroU64::new(runtime_nonce)
        .ok_or_else(|| crate::vfs::VfsError::stale_session("bind", None))?;
    let host = HOST_CONTEXTS
        .get()
        .and_then(|contexts| {
            contexts.read().ok()?.get(&context_id).and_then(|record| {
                (record.claimed && record.runtime_nonce.is_none()).then(|| record.host.clone())
            })
        })
        .ok_or_else(|| crate::vfs::VfsError::stale_session("bind", None))?;
    let session = Arc::new(host.runtime_vfs_session(runtime_nonce)?);

    // Every path that needs both registries takes them in this order. The
    // context is revalidated after session construction so release racing bind
    // cannot publish an orphaned runtime generation.
    let sessions = RUNTIME_VFS_SESSIONS.get_or_init(|| RwLock::new(HashMap::new()));
    let mut sessions = match sessions.write() {
        Ok(sessions) => sessions,
        Err(poisoned) => poisoned.into_inner(),
    };
    let contexts = HOST_CONTEXTS
        .get()
        .ok_or_else(|| crate::vfs::VfsError::stale_session("bind", None))?;
    let mut contexts = match contexts.write() {
        Ok(contexts) => contexts,
        Err(poisoned) => poisoned.into_inner(),
    };
    let record = contexts
        .get_mut(&context_id)
        .filter(|record| {
            record.claimed && record.runtime_nonce.is_none() && Arc::ptr_eq(&record.host, &host)
        })
        .ok_or_else(|| crate::vfs::VfsError::stale_session("bind", None))?;
    if sessions.contains_key(&runtime_nonce.get()) {
        return Err(crate::vfs::VfsError::stale_session("bind", None));
    }
    record.runtime_nonce = Some(runtime_nonce.get());
    sessions.insert(
        runtime_nonce.get(),
        RuntimeVfsBinding {
            context_id,
            session,
        },
    );
    Ok(())
}

fn runtime_vfs_session(
    runtime_nonce: u64,
    operation: &str,
) -> Result<Arc<crate::vfs::RuntimeVfsSession>, crate::vfs::VfsError> {
    let runtime_nonce = NonZeroU64::new(runtime_nonce)
        .ok_or_else(|| crate::vfs::VfsError::stale_session(operation, None))?;
    let binding = RUNTIME_VFS_SESSIONS
        .get()
        .and_then(|sessions| {
            sessions
                .read()
                .ok()?
                .get(&runtime_nonce.get())
                .map(|binding| (binding.context_id, Arc::clone(&binding.session)))
        })
        .ok_or_else(|| crate::vfs::VfsError::stale_session(operation, None))?;
    let active_context = ACTIVE_HOST_CONTEXT.with(Cell::get);
    if active_context != 0 && active_context != binding.0 {
        return Err(crate::vfs::VfsError::stale_session(operation, None));
    }
    if binding.1.runtime_nonce() != runtime_nonce {
        return Err(crate::vfs::VfsError::stale_session(operation, None));
    }
    Ok(binding.1)
}

/// Match an engine-owned runtime generation to the exact Host identity which
/// native construction claimed, then return an opaque Rust-side lease over
/// that generation's VFS state. This is the session-ingress counterpart to the
/// private native VFS calls: it accepts no JavaScript principal, path spelling,
/// or ambient cwd as identity.
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
pub(crate) fn authenticated_runtime_vfs_for_host(
    host: &Host,
    runtime_nonce: NonZeroU64,
) -> Result<crate::vfs::AuthenticatedRuntimeVfs, crate::vfs::VfsError> {
    let session = runtime_vfs_session(runtime_nonce.get(), "session-ingress")?;
    let context_id = RUNTIME_VFS_SESSIONS
        .get()
        .and_then(|sessions| {
            let sessions = sessions.read().ok()?;
            let binding = sessions.get(&runtime_nonce.get())?;
            Arc::ptr_eq(&binding.session, &session).then_some(binding.context_id)
        })
        .ok_or_else(|| crate::vfs::VfsError::stale_session("session-ingress", None))?;
    let host_matches = HOST_CONTEXTS
        .get()
        .and_then(|contexts| {
            let contexts = contexts.read().ok()?;
            let record = contexts.get(&context_id)?;
            (record.claimed
                && record.runtime_nonce == Some(runtime_nonce.get())
                && record.host.same_runtime_security_identity(host))
            .then_some(())
        })
        .is_some();
    if !host_matches {
        return Err(crate::vfs::VfsError::stale_session("session-ingress", None));
    }
    Ok(crate::vfs::AuthenticatedRuntimeVfs::new(session))
}

fn unbind_runtime_vfs_session(runtime_nonce: u64) -> bool {
    if runtime_nonce == 0 {
        return false;
    }
    let Some(sessions) = RUNTIME_VFS_SESSIONS.get() else {
        return false;
    };
    let mut sessions = match sessions.write() {
        Ok(sessions) => sessions,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(binding) = sessions.remove(&runtime_nonce) else {
        return false;
    };
    if let Some(contexts) = HOST_CONTEXTS.get() {
        let mut contexts = match contexts.write() {
            Ok(contexts) => contexts,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(context) = contexts.get_mut(&binding.context_id) {
            if context.runtime_nonce == Some(runtime_nonce) {
                context.runtime_nonce = None;
            }
        }
    }
    binding.session.close();
    true
}

/// Claim the pending armed Host context identified by `digest`.
///
/// # Safety
///
/// A non-null `digest` must point to a readable NUL-terminated C string for the
/// duration of this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_claim_armed_context(digest: *const c_char) -> u64 {
    if digest.is_null() {
        return 0;
    }
    let Ok(digest) = unsafe { CStr::from_ptr(digest) }.to_str() else {
        return 0;
    };
    claim_pending_host_context(Some(digest), RuntimeExtensionAuthorityClaim::RequireEmpty)
}

/// Claim an armed Host while binding the engine construction to the exact
/// runtime-extension authority capsule. A null `authority_digest` means the
/// canonical empty projection; it never matches a non-empty capsule.
///
/// # Safety
///
/// Non-null pointers must address readable NUL-terminated UTF-8 strings for
/// the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_claim_armed_context_with_runtime_extensions(
    snapshot_digest: *const c_char,
    authority_digest: *const c_char,
) -> u64 {
    if snapshot_digest.is_null() {
        return 0;
    }
    let Ok(snapshot_digest) = unsafe { CStr::from_ptr(snapshot_digest) }.to_str() else {
        return 0;
    };
    let extension_claim = if authority_digest.is_null() {
        RuntimeExtensionAuthorityClaim::RequireEmpty
    } else {
        let Ok(authority_digest) = unsafe { CStr::from_ptr(authority_digest) }.to_str() else {
            return 0;
        };
        RuntimeExtensionAuthorityClaim::RequireExact(authority_digest)
    };
    claim_pending_host_context(Some(snapshot_digest), extension_claim)
}

#[no_mangle]
pub extern "C" fn ex_host_claim_diagnostic_context() -> u64 {
    claim_pending_host_context(None, RuntimeExtensionAuthorityClaim::Ignore)
}

/// Claim the deliberate enforcement-off context installed only by a compiled
/// standalone application's authenticated ambient boot path.
/// @ref LLP 0047#ambient-path
#[no_mangle]
#[cfg(feature = "sfe-compiled-runtime")]
pub extern "C" fn ibex_private_host_claim_compiled_ambient_context_v1() -> u64 {
    claim_pending_host_context(None, RuntimeExtensionAuthorityClaim::Ignore)
}

#[no_mangle]
pub extern "C" fn ex_host_enter_context(context_id: u64) -> u64 {
    let exists = HOST_CONTEXTS
        .get()
        .and_then(|contexts| {
            contexts
                .read()
                .ok()
                .map(|rows| rows.get(&context_id).is_some_and(|row| row.claimed))
        })
        .unwrap_or(false);
    if !exists {
        return u64::MAX;
    }
    ACTIVE_HOST_CONTEXT.with(|active| active.replace(context_id))
}

#[no_mangle]
pub extern "C" fn ex_host_restore_context(previous: u64) {
    ACTIVE_HOST_CONTEXT.with(|active| active.set(previous));
}

#[no_mangle]
pub extern "C" fn ex_host_release_context(context_id: u64) {
    let mut removed_sessions = Vec::new();
    if let Some(sessions) = RUNTIME_VFS_SESSIONS.get() {
        let mut sessions = match sessions.write() {
            Ok(sessions) => sessions,
            Err(poisoned) => poisoned.into_inner(),
        };
        let runtime_nonces = sessions
            .iter()
            .filter_map(|(nonce, binding)| (binding.context_id == context_id).then_some(*nonce))
            .collect::<Vec<_>>();
        for runtime_nonce in runtime_nonces {
            if let Some(binding) = sessions.remove(&runtime_nonce) {
                removed_sessions.push(binding.session);
            }
        }
    }
    if let Some(contexts) = HOST_CONTEXTS.get() {
        let mut contexts = match contexts.write() {
            Ok(contexts) => contexts,
            Err(poisoned) => poisoned.into_inner(),
        };
        contexts.remove(&context_id);
    }
    for session in removed_sessions {
        session.close();
    }
}

fn vfs_error_result(error: &crate::vfs::VfsError, out_errno: *mut i32) -> u32 {
    let errno = error.host_errno().unwrap_or(0);
    if !out_errno.is_null() {
        // SAFETY: callers pass an optional writable scalar; non-null is the
        // complete output-pointer contract for this field.
        unsafe { *out_errno = errno };
    }
    if errno != 0 {
        record_fs_error(errno);
    }
    vfs_result_discriminant(error)
}

unsafe fn initialize_vfs_output(
    out_data: *mut *mut u8,
    out_len: *mut u64,
) -> Result<(), crate::vfs::VfsError> {
    if out_data.is_null() || out_len.is_null() {
        return Err(crate::vfs::VfsError::malformed("vfs-output"));
    }
    // SAFETY: both pointers were checked above and the ABI requires one
    // writable pointer-sized value plus one writable u64.
    unsafe {
        *out_data = ptr::null_mut();
        *out_len = 0;
    }
    Ok(())
}

unsafe fn write_vfs_output(bytes: Vec<u8>, out_data: *mut *mut u8, out_len: *mut u64) {
    if bytes.is_empty() {
        return;
    }
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len() as u64;
    let data = Box::into_raw(boxed) as *mut u8;
    // SAFETY: initialize_vfs_output validated both pointers for this call.
    unsafe {
        *out_data = data;
        *out_len = len;
    }
}

unsafe fn vfs_input_bytes(
    input: *const u8,
    input_len: u64,
    operation: &str,
) -> Result<Vec<u8>, crate::vfs::VfsError> {
    let input_len =
        usize::try_from(input_len).map_err(|_| crate::vfs::VfsError::malformed(operation))?;
    if input_len == 0 {
        return Ok(Vec::new());
    }
    if input.is_null() {
        return Err(crate::vfs::VfsError::malformed(operation));
    }
    // SAFETY: the native caller promises `input_len` readable bytes for the
    // duration of this synchronous call. No reference escapes the call.
    Ok(unsafe { std::slice::from_raw_parts(input, input_len) }.to_vec())
}

fn typed_principals_for_ids(
    host: &Host,
    module_ids: &[u64],
) -> Option<Vec<capsec_semantics::model::Principal>> {
    let principals = module_ids
        .iter()
        .map(|id| host.typed_principal_for_module(&id.to_string()))
        .collect::<Option<Vec<_>>>()?;
    capsec_semantics::model::canonicalize_principal_set(principals).ok()
}

/// Bind an authenticated Host context and its `/project` mount to one exact
/// engine runtime generation. This must run during armed runtime construction,
/// after the nonce is minted and before any bootstrap or user evaluation.
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
#[no_mangle]
pub extern "C" fn ex_host_vfs_bind_runtime(context_id: u64, runtime_nonce: u64) -> u32 {
    match bind_runtime_vfs_session(context_id, runtime_nonce) {
        Ok(()) => EX_HOST_VFS_RESULT_OK,
        Err(error) => vfs_error_result(&error, ptr::null_mut()),
    }
}

/// Close and remove the exact runtime generation's VFS state. A second call is
/// a stale-session failure rather than a success against a recycled nonce.
#[no_mangle]
pub extern "C" fn ex_host_vfs_unbind_runtime(runtime_nonce: u64) -> u32 {
    if unbind_runtime_vfs_session(runtime_nonce) {
        EX_HOST_VFS_RESULT_OK
    } else {
        EX_HOST_VFS_RESULT_STALE_SESSION
    }
}

/// Return a malloc-independent, explicit-length copy of the runtime's virtual
/// cwd. The caller frees a non-empty output with `ex_host_free_buffer`.
///
/// # Safety
///
/// `module_ids` must address `module_ids_len` readable, properly aligned `u64`
/// values. `out_virtual` and `out_virtual_len` must each address one writable
/// value, and a non-null `out_errno` must address one writable `i32`, for the
/// duration of this call.
/// @abi-output ex_host_vfs_get_cwd out_virtual role=output kind=buffer length=out_virtual_len ownership=caller-frees:ex_host_free_buffer
#[no_mangle]
pub unsafe extern "C" fn ex_host_vfs_get_cwd(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    out_virtual: *mut *mut u8,
    out_virtual_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_virtual, out_virtual_len) } {
        return vfs_error_result(&error, out_errno);
    }
    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return EX_HOST_VFS_RESULT_POLICY_DENIED;
    }
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let result = runtime_vfs_session(runtime_nonce, "cwd").and_then(|session| {
        with_host(
            |host| {
                use capsec_semantics::decision::DecisionOutcome;
                use capsec_semantics::model::Stage;
                let principals = typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        "cwd",
                        Arc::from("/project"),
                        "path:cwd-observe",
                    )
                })?;
                for stage in [Stage::Requested, Stage::Commit] {
                    let decision = host.authorize_typed_cwd_observe_stage(
                        &module_id.to_string(),
                        principals.clone(),
                        stage,
                    );
                    if !matches!(decision, Ok(decision) if decision.outcome == DecisionOutcome::Allow)
                    {
                        return Err(crate::vfs::VfsError::policy_denied(
                            "cwd",
                            Arc::from("/project"),
                            "path:cwd-observe",
                        ));
                    }
                }
                session.current_cwd()
            },
            Err(crate::vfs::VfsError::stale_session("cwd", None)),
        )
    });
    match result {
        Ok(virtual_path) => {
            unsafe { write_vfs_output(virtual_path, out_virtual, out_virtual_len) };
            EX_HOST_VFS_RESULT_OK
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Change only this runtime generation's virtual cwd. The target bytes are
/// borrowed and explicit-length; successful output is the canonical virtual
/// spelling, never a host path. Native code must perform the typed cwd and
/// directory-metadata decisions before calling this private commit operation.
///
/// # Safety
///
/// For nonzero lengths, `module_ids` and `input` must address their declared
/// readable elements or bytes. `module_ids` must be properly aligned.
/// `out_virtual` and `out_virtual_len` must each address one writable value,
/// and a non-null `out_errno` must address one writable `i32`, for the duration
/// of this call.
/// @abi-output ex_host_vfs_chdir out_virtual role=output kind=buffer length=out_virtual_len ownership=caller-frees:ex_host_free_buffer
#[no_mangle]
pub unsafe extern "C" fn ex_host_vfs_chdir(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    out_virtual: *mut *mut u8,
    out_virtual_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_virtual, out_virtual_len) } {
        return vfs_error_result(&error, out_errno);
    }
    let input = match unsafe { vfs_input_bytes(input, input_len, "chdir") } {
        Ok(input) => input,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return EX_HOST_VFS_RESULT_POLICY_DENIED;
    }
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let result = runtime_vfs_session(runtime_nonce, "chdir").and_then(|session| {
        with_host(
            |host| {
                use capsec_semantics::decision::DecisionOutcome;
                use capsec_semantics::model::{NonEmptyString, Stage};
                let principals = typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        "chdir",
                        Arc::from("/project"),
                        "path:cwd-mutate",
                    )
                })?;
                session.chdir_authorized(
                    &input,
                    |stage, path, namespace, final_object| {
                        let retained_handle = if stage == Stage::Commit {
                            NonEmptyString::new(format!("vfs-cwd:{runtime_nonce}"))
                                .map(Some)
                                .map_err(|_| {
                                    crate::vfs::VfsError::stale_session(
                                        "chdir",
                                        Some(Arc::from(namespace.virtual_path())),
                                    )
                                })?
                        } else {
                            None
                        };
                        let decision = host.authorize_typed_cwd_mutate_stage(
                            &module_id.to_string(),
                            principals.clone(),
                            path,
                            stage,
                            final_object.cloned(),
                            retained_handle,
                        );
                        if matches!(decision, Ok(decision) if decision.outcome == DecisionOutcome::Allow)
                        {
                            Ok(())
                        } else {
                            Err(crate::vfs::VfsError::policy_denied(
                                "chdir",
                                Arc::from(namespace.virtual_path()),
                                "path:cwd-mutate+fs:list",
                            ))
                        }
                    },
                )
            },
            Err(crate::vfs::VfsError::stale_session("chdir", None)),
        )
    });
    match result {
        Ok(virtual_path) => {
            unsafe { write_vfs_output(virtual_path, out_virtual, out_virtual_len) };
            EX_HOST_VFS_RESULT_OK
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Resolve lexical virtual syntax against the runtime's sealed cwd. The
/// backing bytes are for private native adapter use only; `out_virtual` is the
/// separate safe spelling for JavaScript-visible fields and diagnostics.
///
/// # Safety
///
/// For a nonzero `input_len`, `input` must address that many readable bytes.
/// Each output-data and output-length pointer must address one writable value,
/// and a non-null `out_errno` must address one writable `i32`, for the duration
/// of this call.
/// @abi-output ex_host_vfs_resolve_path out_backing role=output kind=buffer length=out_backing_len ownership=caller-frees:ex_host_free_buffer
/// @abi-output ex_host_vfs_resolve_path out_virtual role=output kind=buffer length=out_virtual_len ownership=caller-frees:ex_host_free_buffer
#[no_mangle]
pub unsafe extern "C" fn ex_host_vfs_resolve_path(
    runtime_nonce: u64,
    input: *const u8,
    input_len: u64,
    out_backing: *mut *mut u8,
    out_backing_len: *mut u64,
    out_virtual: *mut *mut u8,
    out_virtual_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_backing, out_backing_len) } {
        return vfs_error_result(&error, out_errno);
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_virtual, out_virtual_len) } {
        return vfs_error_result(&error, out_errno);
    }
    let input = match unsafe { vfs_input_bytes(input, input_len, "resolve") } {
        Ok(input) => input,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let result = runtime_vfs_session(runtime_nonce, "resolve")
        .and_then(|session| session.resolve_private_path(&input));
    match result {
        Ok(resolved) => {
            let (backing_path, virtual_path) = resolved.into_parts();
            unsafe {
                write_vfs_output(backing_path, out_backing, out_backing_len);
                write_vfs_output(virtual_path, out_virtual, out_virtual_len);
            }
            EX_HOST_VFS_RESULT_OK
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Open one virtual regular file for descriptor-backed reads through the
/// retained-object VFS. The returned opaque handle carries the exact occurrence
/// and bearer facts required by later descriptor Repeat operations.
///
/// This private native-adapter bridge supports read-only opens. Armed callers
/// must fail closed before calling it for write/create/truncate/append flags.
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
///
/// # Safety
///
/// Nonempty input buffers and `module_ids` must be readable for this
/// synchronous call. `out_file` must address one writable pointer.
#[export_name = "ibex_private_vfs_open_read_typed"]
pub(crate) unsafe extern "C" fn private_vfs_open_read_typed(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    presented_handle_id: *const u8,
    presented_handle_id_len: u64,
    out_file: *mut *mut ExactFileHandle,
    out_virtual: *mut *mut u8,
    out_virtual_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::NonEmptyString;

    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if out_file.is_null() {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    unsafe { *out_file = ptr::null_mut() };
    if let Err(error) = unsafe { initialize_vfs_output(out_virtual, out_virtual_len) } {
        return vfs_error_result(&error, out_errno);
    }
    let session = match runtime_vfs_session(runtime_nonce, "open") {
        Ok(session) => session,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let input = match unsafe { vfs_input_bytes(input, input_len, "open") } {
        Ok(input) => input,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let presented = match unsafe {
        vfs_input_bytes(presented_handle_id, presented_handle_id_len, "open-handle")
    } {
        Ok(bytes) if bytes.is_empty() => Vec::new(),
        Ok(bytes) => {
            let value = match String::from_utf8(bytes)
                .ok()
                .and_then(|value| NonEmptyString::new(value).ok())
            {
                Some(value) => value,
                None => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
            };
            vec![value]
        }
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let namespace = match session.resolve_namespace(&input) {
        Ok(namespace) => namespace,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let vfs = match session.virtual_file_system() {
        Ok(vfs) => vfs,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let result = with_host(
        |host| {
            let constrained_principals =
                typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        "open",
                        Arc::from(namespace.virtual_path()),
                        "typed-open-principal-refused",
                    )
                })?;
            vfs.open_read_descriptor_authenticated(namespace, |authorization| {
                let path = Arc::<str>::from(match &authorization {
                    crate::vfs::ReadAuthorization::Requested(path) => path.virtual_path(),
                    crate::vfs::ReadAuthorization::Discovery(path) => {
                        path.namespace().virtual_path()
                    }
                    crate::vfs::ReadAuthorization::Commit(path) => path.namespace().virtual_path(),
                    crate::vfs::ReadAuthorization::Repeat(path) => path.namespace().virtual_path(),
                });
                let result = host
                    .authorize_vfs_read_stage(
                        vfs,
                        &module_id.to_string(),
                        constrained_principals.clone(),
                        "fs-open",
                        "surface.native.op.exactfsopen.05ao6wa",
                        authorization,
                        presented.clone(),
                    )
                    .map_err(|_| {
                        crate::vfs::VfsError::policy_denied(
                            "open",
                            path.clone(),
                            "typed-open-evaluation-refused",
                        )
                    })?;
                let receipt =
                    crate::vfs::AuthorizationReceipt::from_structured_decision(&result.evidence)?;
                match result.decision.outcome {
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => {
                        Ok(receipt)
                    }
                    DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                        Err(crate::vfs::VfsError::policy_denied(
                            "open",
                            path,
                            Arc::<str>::from(receipt.evidence_digest().as_str()),
                        ))
                    }
                }
            })
        },
        Err(crate::vfs::VfsError::stale_session("open", None)),
    );
    match result {
        Ok(descriptor) => {
            let (file, retained_identity) = descriptor.into_parts();
            let virtual_path = retained_identity.virtual_path().as_bytes().to_vec();
            let file = Box::new(ExactFileHandle {
                file,
                retained_identity: Some(retained_identity),
                presented_handles: presented,
            });
            unsafe {
                *out_file = Box::into_raw(file);
                write_vfs_output(virtual_path, out_virtual, out_virtual_len);
            }
            EX_HOST_VFS_RESULT_OK
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Open one existing virtual regular file through an append-only retained
/// descriptor. `fs:write` Requested precedes lookup, `fs:list` authorizes
/// discovery, and `fs:write` Commit binds the exact existing object. This
/// bridge never creates an absent file.
///
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#41-the-v1-mutation-surface-small-object-bound-and-completely-specified
/// @ref LLP 0023#42-authenticated-package-source-is-immutable
///
/// # Safety
///
/// The pointer and lifetime requirements are identical to
/// [`private_vfs_open_read_typed`].
#[export_name = "ibex_private_vfs_open_append_typed"]
pub(crate) unsafe extern "C" fn private_vfs_open_append_typed(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    presented_handle_id: *const u8,
    presented_handle_id_len: u64,
    out_file: *mut *mut ExactFileHandle,
    out_virtual: *mut *mut u8,
    out_virtual_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{FollowMode, NonEmptyString};

    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if out_file.is_null() {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    unsafe { *out_file = ptr::null_mut() };
    if let Err(error) = unsafe { initialize_vfs_output(out_virtual, out_virtual_len) } {
        return vfs_error_result(&error, out_errno);
    }
    let session = match runtime_vfs_session(runtime_nonce, "open") {
        Ok(session) => session,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let input = match unsafe { vfs_input_bytes(input, input_len, "open") } {
        Ok(input) => input,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let presented = match unsafe {
        vfs_input_bytes(presented_handle_id, presented_handle_id_len, "open-handle")
    } {
        Ok(bytes) if bytes.is_empty() => Vec::new(),
        Ok(bytes) => {
            let value = match String::from_utf8(bytes)
                .ok()
                .and_then(|value| NonEmptyString::new(value).ok())
            {
                Some(value) => value,
                None => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
            };
            vec![value]
        }
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let namespace = match session.resolve_namespace(&input) {
        Ok(namespace) => namespace,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let vfs = match session.virtual_file_system() {
        Ok(vfs) => vfs,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let result = with_host(
        |host| {
            let constrained_principals =
                typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        "open",
                        Arc::from(namespace.virtual_path()),
                        "typed-open-principal-refused",
                    )
                })?;
            let authorize = |authorization: crate::vfs::RetainedPathAuthorization<'_>,
                             action: &'static str| {
                let path = Arc::<str>::from(authorization.namespace().virtual_path());
                let result = host
                    .authorize_vfs_retained_path_stage(
                        vfs,
                        &module_id.to_string(),
                        constrained_principals.clone(),
                        "fs-open",
                        "surface.native.op.exactfsopen.05ao6wa",
                        authorization,
                        FollowMode::FollowFinal,
                        action,
                        presented.clone(),
                    )
                    .map_err(|_| {
                        crate::vfs::VfsError::policy_denied(
                            "open",
                            path.clone(),
                            "typed-open-evaluation-refused",
                        )
                    })?;
                let receipt =
                    crate::vfs::AuthorizationReceipt::from_structured_decision(&result.evidence)?;
                match result.decision.outcome {
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => {
                        Ok(receipt)
                    }
                    DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                        Err(crate::vfs::VfsError::policy_denied(
                            "open",
                            path,
                            Arc::<str>::from(receipt.evidence_digest().as_str()),
                        ))
                    }
                }
            };
            vfs.open_append_descriptor_authenticated(
                namespace,
                |authorization| {
                    authorize(
                        crate::vfs::RetainedPathAuthorization::from_read(&authorization),
                        "fs:list",
                    )
                },
                |authorization| authorize(authorization, "fs:write"),
            )
        },
        Err(crate::vfs::VfsError::stale_session("open", None)),
    );
    match result {
        Ok(descriptor) => {
            let (file, retained_identity) = descriptor.into_parts();
            let virtual_path = retained_identity.virtual_path().as_bytes().to_vec();
            let file = Box::new(ExactFileHandle {
                file,
                retained_identity: Some(retained_identity),
                presented_handles: presented,
            });
            unsafe {
                *out_file = Box::into_raw(file);
                write_vfs_output(virtual_path, out_virtual, out_virtual_len);
            }
            EX_HOST_VFS_RESULT_OK
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Read one virtual file through the runtime VFS's cross-platform retained
/// object state machine. The path and optional bearer are explicit-length
/// input; JavaScript cannot supply runtime or principal identity.
///
/// This is a private native-adapter bridge, not an embedder ABI. It exists
/// separately from `ex_host_fs_read_file` so armed Windows execution cannot
/// accidentally fall through to the legacy pathname implementation.
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#21-staged-authorization-identity
///
/// # Safety
///
/// Nonempty input buffers and `module_ids` must be readable for this
/// synchronous call. Output pointers must each address one writable value.
unsafe fn private_vfs_read_file_typed_for_surface(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    presented_handle_id: *const u8,
    presented_handle_id_len: u64,
    out_data: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
    adapter_operation: &'static str,
    coverage_edge_id: &'static str,
) -> u32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::NonEmptyString;

    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_data, out_len) } {
        return vfs_error_result(&error, out_errno);
    }
    let session = match runtime_vfs_session(runtime_nonce, "read") {
        Ok(session) => session,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let input = match unsafe { vfs_input_bytes(input, input_len, "read") } {
        Ok(input) => input,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let presented = match unsafe {
        vfs_input_bytes(presented_handle_id, presented_handle_id_len, "read-handle")
    } {
        Ok(bytes) if bytes.is_empty() => Vec::new(),
        Ok(bytes) => {
            let value = match String::from_utf8(bytes)
                .ok()
                .and_then(|value| NonEmptyString::new(value).ok())
            {
                Some(value) => value,
                None => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
            };
            vec![value]
        }
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let namespace = match session.resolve_namespace(&input) {
        Ok(namespace) => namespace,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let vfs = match session.virtual_file_system() {
        Ok(vfs) => vfs,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let result = with_host(
        |host| {
            let constrained_principals =
                typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        "read",
                        Arc::from(namespace.virtual_path()),
                        "typed-read-principal-refused",
                    )
                })?;
            vfs.read_authenticated(namespace, crate::vfs::SourceUse::Script, |authorization| {
                let path = Arc::<str>::from(match &authorization {
                    crate::vfs::ReadAuthorization::Requested(path) => path.virtual_path(),
                    crate::vfs::ReadAuthorization::Discovery(path) => {
                        path.namespace().virtual_path()
                    }
                    crate::vfs::ReadAuthorization::Commit(path) => path.namespace().virtual_path(),
                    crate::vfs::ReadAuthorization::Repeat(path) => path.namespace().virtual_path(),
                });
                let result = host
                    .authorize_vfs_read_stage(
                        vfs,
                        &module_id.to_string(),
                        constrained_principals.clone(),
                        adapter_operation,
                        coverage_edge_id,
                        authorization,
                        presented.clone(),
                    )
                    .map_err(|_| {
                        crate::vfs::VfsError::policy_denied(
                            "read",
                            path.clone(),
                            "typed-read-evaluation-refused",
                        )
                    })?;
                let receipt =
                    crate::vfs::AuthorizationReceipt::from_structured_decision(&result.evidence)?;
                match result.decision.outcome {
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => {
                        Ok(receipt)
                    }
                    DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                        Err(crate::vfs::VfsError::policy_denied(
                            "read",
                            path,
                            Arc::<str>::from(receipt.evidence_digest().as_str()),
                        ))
                    }
                }
            })
        },
        Err(crate::vfs::VfsError::stale_session("read", None)),
    );
    match result {
        Ok(read) => {
            unsafe { write_vfs_output(read.into_bytes().to_vec(), out_data, out_len) };
            EX_HOST_VFS_RESULT_OK
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Synchronous whole-file read adapter.
///
/// # Safety
///
/// The safety contract is identical to
/// [`private_vfs_read_file_typed_for_surface`].
#[export_name = "ibex_private_vfs_read_file_typed"]
pub(crate) unsafe extern "C" fn private_vfs_read_file_typed(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    presented_handle_id: *const u8,
    presented_handle_id_len: u64,
    out_data: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_read_file_typed_for_surface(
            runtime_nonce,
            module_id,
            module_ids,
            module_ids_len,
            input,
            input_len,
            presented_handle_id,
            presented_handle_id_len,
            out_data,
            out_len,
            out_errno,
            "fs-read-file",
            "surface.native.op.exactreadfile.1cmzco7",
        )
    }
}

/// Worker-backed whole-file read adapter. The retained VFS protocol is shared
/// with the synchronous form, but evidence is attributed to the async native
/// surface that scheduled and owns the operation.
///
/// # Safety
///
/// The safety contract is identical to [`private_vfs_read_file_typed`].
#[export_name = "ibex_private_vfs_read_file_async_typed"]
pub(crate) unsafe extern "C" fn private_vfs_read_file_async_typed(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    presented_handle_id: *const u8,
    presented_handle_id_len: u64,
    out_data: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_read_file_typed_for_surface(
            runtime_nonce,
            module_id,
            module_ids,
            module_ids_len,
            input,
            input_len,
            presented_handle_id,
            presented_handle_id_len,
            out_data,
            out_len,
            out_errno,
            "fs-read-file-async",
            "surface.native.op.exactfsreadfileasync.0fw3fo0",
        )
    }
}

/// Return Node-shaped metadata JSON for one virtual path through the runtime
/// VFS's retained metadata-only state machine.
///
/// This is private to the native adapter. Runtime and principal identity are
/// engine-derived, and armed errors never fall through to pathname stat.
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#21-staged-authorization-identity
///
/// # Safety
///
/// Nonempty input buffers and `module_ids` must be readable for this
/// synchronous call. Output pointers must each address one writable value.
#[export_name = "ibex_private_vfs_stat_typed"]
pub(crate) unsafe extern "C" fn private_vfs_stat_typed(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    presented_handle_id: *const u8,
    presented_handle_id_len: u64,
    out_json: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_metadata_typed(
            TypedVfsMetadataKind::Stat,
            runtime_nonce,
            module_id,
            module_ids,
            module_ids_len,
            input,
            input_len,
            presented_handle_id,
            presented_handle_id_len,
            out_json,
            out_len,
            out_errno,
        )
    }
}

/// Private retained-object lstat counterpart to
/// [`private_vfs_stat_typed`]. The final link object is never followed.
///
/// # Safety
///
/// The pointer requirements are identical to [`private_vfs_stat_typed`].
#[export_name = "ibex_private_vfs_lstat_typed"]
pub(crate) unsafe extern "C" fn private_vfs_lstat_typed(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    presented_handle_id: *const u8,
    presented_handle_id_len: u64,
    out_json: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_metadata_typed(
            TypedVfsMetadataKind::Lstat,
            runtime_nonce,
            module_id,
            module_ids,
            module_ids_len,
            input,
            input_len,
            presented_handle_id,
            presented_handle_id_len,
            out_json,
            out_len,
            out_errno,
        )
    }
}

/// Return metadata for one authenticated retained file descriptor. The
/// descriptor's original occurrence and bearer are reused for one fresh
/// `fs:list` Repeat; no pathname is resolved or reopened.
///
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
///
/// # Safety
///
/// `file` must be a live handle returned by this Host ABI. Nonempty
/// `module_ids` must be readable, and output pointers must be writable.
#[export_name = "ibex_private_vfs_fstat_typed"]
pub(crate) unsafe extern "C" fn private_vfs_fstat_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    out_json: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::FollowMode;

    const OPERATION: &str = "fstat";
    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_json, out_len) } {
        return vfs_error_result(&error, out_errno);
    }
    if file.is_null() || module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let session = match runtime_vfs_session(runtime_nonce, OPERATION) {
        Ok(session) => session,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let handle = unsafe { &*file };
    let Some(retained_identity) = handle.retained_identity.as_ref() else {
        return EX_HOST_VFS_RESULT_STALE_IDENTITY;
    };
    let vfs = match session.virtual_file_system() {
        Ok(vfs) => vfs,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let presented = handle.presented_handles.clone();
    let result = with_host(
        |host| {
            let constrained_principals =
                typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        OPERATION,
                        Arc::from(retained_identity.virtual_path()),
                        "typed-fstat-principal-refused",
                    )
                })?;
            vfs.fstat_descriptor_authenticated(&handle.file, retained_identity, |authorization| {
                let path = Arc::<str>::from(authorization.namespace().virtual_path());
                let result = host
                    .authorize_vfs_retained_path_stage(
                        vfs,
                        &descriptor_owner.to_string(),
                        constrained_principals.clone(),
                        "fs-fstat",
                        "surface.native.op.exactfsfstatsync.1md7g19",
                        authorization,
                        FollowMode::FollowFinal,
                        "fs:list",
                        presented.clone(),
                    )
                    .map_err(|_| {
                        crate::vfs::VfsError::policy_denied(
                            OPERATION,
                            path.clone(),
                            "typed-fstat-evaluation-refused",
                        )
                    })?;
                let receipt =
                    crate::vfs::AuthorizationReceipt::from_structured_decision(&result.evidence)?;
                match result.decision.outcome {
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => {
                        Ok(receipt)
                    }
                    DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                        Err(crate::vfs::VfsError::policy_denied(
                            OPERATION,
                            path,
                            Arc::<str>::from(receipt.evidence_digest().as_str()),
                        ))
                    }
                }
            })
        },
        Err(crate::vfs::VfsError::stale_session(OPERATION, None)),
    );
    match result {
        Ok(stat) => {
            match serde_json::to_vec(&make_stat_payload_from_metadata(stat.into_metadata())) {
                Ok(json) => {
                    unsafe { write_vfs_output(json, out_json, out_len) };
                    EX_HOST_VFS_RESULT_OK
                }
                Err(_) => {
                    vfs_error_result(&crate::vfs::VfsError::malformed("fstat-json"), out_errno)
                }
            }
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

unsafe fn private_vfs_read_typed_for_surface(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    length: u32,
    positioned: u8,
    position: u64,
    out_data: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
    operation: &'static str,
    adapter_operation: &'static str,
    coverage_edge_id: &'static str,
) -> u32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::FollowMode;

    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_data, out_len) } {
        return vfs_error_result(&error, out_errno);
    }
    if file.is_null()
        || module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || positioned > 1
    {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let session = match runtime_vfs_session(runtime_nonce, operation) {
        Ok(session) => session,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let handle = unsafe { &mut *file };
    let Some(retained_identity) = handle.retained_identity.as_ref() else {
        return EX_HOST_VFS_RESULT_STALE_IDENTITY;
    };
    let vfs = match session.virtual_file_system() {
        Ok(vfs) => vfs,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let presented = handle.presented_handles.clone();
    let result = with_host(
        |host| {
            let constrained_principals =
                typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        operation,
                        Arc::from(retained_identity.virtual_path()),
                        "typed-descriptor-read-principal-refused",
                    )
                })?;
            vfs.read_descriptor_authenticated(
                &mut handle.file,
                retained_identity,
                length,
                (positioned == 1).then_some(position),
                |authorization| {
                    let path = Arc::<str>::from(authorization.namespace().virtual_path());
                    let result = host
                        .authorize_vfs_retained_path_stage(
                            vfs,
                            &descriptor_owner.to_string(),
                            constrained_principals.clone(),
                            adapter_operation,
                            coverage_edge_id,
                            authorization,
                            FollowMode::FollowFinal,
                            "fs:read",
                            presented.clone(),
                        )
                        .map_err(|_| {
                            crate::vfs::VfsError::policy_denied(
                                operation,
                                path.clone(),
                                "typed-descriptor-read-evaluation-refused",
                            )
                        })?;
                    let receipt = crate::vfs::AuthorizationReceipt::from_structured_decision(
                        &result.evidence,
                    )?;
                    match result.decision.outcome {
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => {
                            Ok(receipt)
                        }
                        DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                            Err(crate::vfs::VfsError::policy_denied(
                                operation,
                                path,
                                Arc::<str>::from(receipt.evidence_digest().as_str()),
                            ))
                        }
                    }
                },
            )
        },
        Err(crate::vfs::VfsError::stale_session(operation, None)),
    );
    match result {
        Ok(bytes) => {
            unsafe { write_vfs_output(bytes, out_data, out_len) };
            EX_HOST_VFS_RESULT_OK
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Read from one authenticated retained file descriptor. The descriptor's
/// original occurrence and bearer are reused for one fresh `fs:read` Repeat;
/// no pathname is resolved or reopened.
///
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
///
/// # Safety
///
/// `file` must be a live handle returned by this Host ABI. Nonempty
/// `module_ids` must be readable, and output pointers must be writable.
#[export_name = "ibex_private_vfs_read_typed"]
pub(crate) unsafe extern "C" fn private_vfs_read_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    length: u32,
    positioned: u8,
    position: u64,
    out_data: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_read_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            length,
            positioned,
            position,
            out_data,
            out_len,
            out_errno,
            "read",
            "fs-read",
            "surface.native.op.exactfsread.1ixlwve",
        )
    }
}

/// Worker-backed scalar read from one authenticated retained descriptor.
/// Authorization and acquisition execute together on the filesystem worker.
///
/// # Safety
///
/// The safety contract is identical to [`private_vfs_read_typed`].
#[export_name = "ibex_private_vfs_read_async_typed"]
pub(crate) unsafe extern "C" fn private_vfs_read_async_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    length: u32,
    positioned: u8,
    position: u64,
    out_data: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_read_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            length,
            positioned,
            position,
            out_data,
            out_len,
            out_errno,
            "read",
            "fs-read-async",
            "surface.native.op.exactfsreadasync.0l952a6",
        )
    }
}

/// Read the next chunk of one authenticated retained descriptor for a
/// whole-file read. The descriptor cursor advances only after a fresh
/// `fs:read` Repeat over its original object identity and bearer.
///
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
///
/// # Safety
///
/// The safety contract is identical to [`private_vfs_read_typed`].
#[export_name = "ibex_private_vfs_read_file_descriptor_typed"]
pub(crate) unsafe extern "C" fn private_vfs_read_file_descriptor_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    length: u32,
    out_data: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_read_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            length,
            0,
            0,
            out_data,
            out_len,
            out_errno,
            "read-file",
            "fs-read-file",
            "surface.native.op.exactfsreadfileasync.0fw3fo0",
        )
    }
}

/// Read and scatter bytes for one synchronous authenticated descriptor-vector
/// call. The aggregate acquisition is still one exact-object `fs:read`
/// Repeat; the Windows adapter scatters the owned result only after success.
///
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
///
/// # Safety
///
/// The safety contract is identical to [`private_vfs_read_typed`].
#[export_name = "ibex_private_vfs_readv_typed"]
pub(crate) unsafe extern "C" fn private_vfs_readv_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    length: u32,
    positioned: u8,
    position: u64,
    out_data: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_read_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            length,
            positioned,
            position,
            out_data,
            out_len,
            out_errno,
            "readv",
            "fs-readv",
            "surface.native.op.exactfsreadv.11moytw",
        )
    }
}

/// Worker-backed vector read from one authenticated retained descriptor. The
/// returned aggregate remains private until the runtime thread publishes it
/// into the caller's validated destinations.
///
/// # Safety
///
/// The safety contract is identical to [`private_vfs_read_typed`].
#[export_name = "ibex_private_vfs_readv_async_typed"]
pub(crate) unsafe extern "C" fn private_vfs_readv_async_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    length: u32,
    positioned: u8,
    position: u64,
    out_data: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_read_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            length,
            positioned,
            position,
            out_data,
            out_len,
            out_errno,
            "readv",
            "fs-readv-async",
            "surface.native.op.exactfsreadvasync.0bn4x60",
        )
    }
}

unsafe fn private_vfs_write_typed_for_surface(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    data: *const u8,
    data_len: u32,
    out_written: *mut u32,
    out_errno: *mut i32,
    operation: &'static str,
    operation_key: &'static str,
    coverage_edge_id: &'static str,
) -> u32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::FollowMode;

    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if out_written.is_null() {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    unsafe { *out_written = 0 };
    if file.is_null()
        || module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || (data.is_null() && data_len != 0)
    {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let session = match runtime_vfs_session(runtime_nonce, operation) {
        Ok(session) => session,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let bytes = if data_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len as usize) }
    };
    if bytes.is_empty() {
        return EX_HOST_VFS_RESULT_OK;
    }
    let handle = unsafe { &mut *file };
    let Some(retained_identity) = handle.retained_identity.as_ref() else {
        return EX_HOST_VFS_RESULT_STALE_IDENTITY;
    };
    let vfs = match session.virtual_file_system() {
        Ok(vfs) => vfs,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let presented = handle.presented_handles.clone();
    let result = with_host(
        |host| {
            let constrained_principals =
                typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        operation,
                        Arc::from(retained_identity.virtual_path()),
                        "typed-descriptor-write-principal-refused",
                    )
                })?;
            vfs.write_append_descriptor_authenticated(
                &mut handle.file,
                retained_identity,
                bytes,
                |authorization| {
                    let path = Arc::<str>::from(authorization.namespace().virtual_path());
                    let result = host
                        .authorize_vfs_retained_path_stage(
                            vfs,
                            &descriptor_owner.to_string(),
                            constrained_principals.clone(),
                            operation_key,
                            coverage_edge_id,
                            authorization,
                            FollowMode::FollowFinal,
                            "fs:write",
                            presented.clone(),
                        )
                        .map_err(|_| {
                            crate::vfs::VfsError::policy_denied(
                                operation,
                                path.clone(),
                                "typed-descriptor-write-evaluation-refused",
                            )
                        })?;
                    let receipt = crate::vfs::AuthorizationReceipt::from_structured_decision(
                        &result.evidence,
                    )?;
                    match result.decision.outcome {
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => {
                            Ok(receipt)
                        }
                        DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                            Err(crate::vfs::VfsError::policy_denied(
                                operation,
                                path,
                                Arc::<str>::from(receipt.evidence_digest().as_str()),
                            ))
                        }
                    }
                },
            )
        },
        Err(crate::vfs::VfsError::stale_session(operation, None)),
    );
    match result {
        Ok(written) => match u32::try_from(written) {
            Ok(written) => {
                unsafe { *out_written = written };
                EX_HOST_VFS_RESULT_OK
            }
            Err(_) => vfs_error_result(&crate::vfs::VfsError::malformed(operation), out_errno),
        },
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Append bytes to one authenticated retained file descriptor. The
/// descriptor's original occurrence and bearer are reused for one fresh
/// `fs:write` Repeat; no pathname is resolved or reopened.
///
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#41-the-v1-mutation-surface-small-object-bound-and-completely-specified
///
/// # Safety
///
/// `file` must be a live handle returned by the append-open bridge. Nonempty
/// `module_ids` and `data` must be readable, and `out_written` must be writable.
#[export_name = "ibex_private_vfs_write_append_typed"]
pub(crate) unsafe extern "C" fn private_vfs_write_append_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    data: *const u8,
    data_len: u32,
    out_written: *mut u32,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_write_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            data,
            data_len,
            out_written,
            out_errno,
            "write",
            "fs-write",
            "surface.native.op.exactfswrite.1locgj1",
        )
    }
}

/// Worker-backed scalar append using the async descriptor-write edge.
///
/// # Safety
///
/// The safety contract is identical to [`private_vfs_write_append_typed`].
#[export_name = "ibex_private_vfs_write_async_typed"]
pub(crate) unsafe extern "C" fn private_vfs_write_async_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    data: *const u8,
    data_len: u32,
    out_written: *mut u32,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_write_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            data,
            data_len,
            out_written,
            out_errno,
            "write",
            "fs-write-async",
            "surface.native.op.exactfswriteasync.0f1ap1j",
        )
    }
}

/// Worker-backed aggregate append using the async descriptor-writev edge.
///
/// # Safety
///
/// The safety contract is identical to [`private_vfs_write_append_typed`].
#[export_name = "ibex_private_vfs_writev_async_typed"]
pub(crate) unsafe extern "C" fn private_vfs_writev_async_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    data: *const u8,
    data_len: u32,
    out_written: *mut u32,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_write_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            data,
            data_len,
            out_written,
            out_errno,
            "writev",
            "fs-writev-async",
            "surface.native.op.exactfswritevasync.0l050fv",
        )
    }
}

unsafe fn private_vfs_sync_typed_for_surface(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    data_only: bool,
    out_errno: *mut i32,
    operation: &'static str,
    operation_key: &'static str,
    coverage_edge_id: &'static str,
) -> u32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::FollowMode;

    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if file.is_null() || module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let session = match runtime_vfs_session(runtime_nonce, operation) {
        Ok(session) => session,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let handle = unsafe { &mut *file };
    let Some(retained_identity) = handle.retained_identity.as_ref() else {
        return EX_HOST_VFS_RESULT_STALE_IDENTITY;
    };
    let vfs = match session.virtual_file_system() {
        Ok(vfs) => vfs,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let presented = handle.presented_handles.clone();
    let result = with_host(
        |host| {
            let constrained_principals =
                typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        operation,
                        Arc::from(retained_identity.virtual_path()),
                        "typed-descriptor-sync-principal-refused",
                    )
                })?;
            vfs.sync_descriptor_authenticated(
                &mut handle.file,
                retained_identity,
                data_only,
                |authorization| {
                    let path = Arc::<str>::from(authorization.namespace().virtual_path());
                    let result = host
                        .authorize_vfs_retained_path_stage(
                            vfs,
                            &descriptor_owner.to_string(),
                            constrained_principals.clone(),
                            operation_key,
                            coverage_edge_id,
                            authorization,
                            FollowMode::FollowFinal,
                            "fs:write",
                            presented.clone(),
                        )
                        .map_err(|_| {
                            crate::vfs::VfsError::policy_denied(
                                operation,
                                path.clone(),
                                "typed-descriptor-sync-evaluation-refused",
                            )
                        })?;
                    let receipt = crate::vfs::AuthorizationReceipt::from_structured_decision(
                        &result.evidence,
                    )?;
                    match result.decision.outcome {
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => {
                            Ok(receipt)
                        }
                        DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                            Err(crate::vfs::VfsError::policy_denied(
                                operation,
                                path,
                                Arc::<str>::from(receipt.evidence_digest().as_str()),
                            ))
                        }
                    }
                },
            )
        },
        Err(crate::vfs::VfsError::stale_session(operation, None)),
    );
    match result {
        Ok(()) => EX_HOST_VFS_RESULT_OK,
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Flush all retained descriptor state under the synchronous fsync edge.
///
/// # Safety
///
/// `file` must be a live append-open handle and `module_ids` readable.
#[export_name = "ibex_private_vfs_fsync_typed"]
pub(crate) unsafe extern "C" fn private_vfs_fsync_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_sync_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            false,
            out_errno,
            "fsync",
            "fs-fsync-sync",
            "surface.native.op.exactfsfsyncsync.02nw7ns",
        )
    }
}

/// Flush retained descriptor data under the synchronous fdatasync edge.
///
/// # Safety
///
/// `file` must be a live append-open handle and `module_ids` readable.
#[export_name = "ibex_private_vfs_fdatasync_typed"]
pub(crate) unsafe extern "C" fn private_vfs_fdatasync_typed(
    runtime_nonce: u64,
    descriptor_owner: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    file: *mut ExactFileHandle,
    out_errno: *mut i32,
) -> u32 {
    unsafe {
        private_vfs_sync_typed_for_surface(
            runtime_nonce,
            descriptor_owner,
            module_ids,
            module_ids_len,
            file,
            true,
            out_errno,
            "fdatasync",
            "fs-fdatasync-sync",
            "surface.native.op.exactfsfdatasyncsync.1p6q71s",
        )
    }
}

/// Enumerate one virtual directory through its exact retained object. The VFS
/// performs one `fs:list` Repeat for every member before that member enters the
/// returned JSON array.
///
/// This private native-adapter bridge cannot fall through to
/// [`ex_host_fs_readdir`] while armed.
/// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
/// @ref LLP 0023#21-staged-authorization-identity
///
/// # Safety
///
/// The pointer requirements are identical to [`private_vfs_stat_typed`].
#[export_name = "ibex_private_vfs_readdir_typed"]
pub(crate) unsafe extern "C" fn private_vfs_readdir_typed(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    presented_handle_id: *const u8,
    presented_handle_id_len: u64,
    out_json: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    use base64::Engine as _;
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{FollowMode, NonEmptyString};

    const OPERATION: &str = "readdir";
    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_json, out_len) } {
        return vfs_error_result(&error, out_errno);
    }
    let session = match runtime_vfs_session(runtime_nonce, OPERATION) {
        Ok(session) => session,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let input = match unsafe { vfs_input_bytes(input, input_len, OPERATION) } {
        Ok(input) => input,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let presented = match unsafe {
        vfs_input_bytes(
            presented_handle_id,
            presented_handle_id_len,
            "readdir-handle",
        )
    } {
        Ok(bytes) if bytes.is_empty() => Vec::new(),
        Ok(bytes) => {
            let value = match String::from_utf8(bytes)
                .ok()
                .and_then(|value| NonEmptyString::new(value).ok())
            {
                Some(value) => value,
                None => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
            };
            vec![value]
        }
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let namespace = match session.resolve_namespace(&input) {
        Ok(namespace) => namespace,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let vfs = match session.virtual_file_system() {
        Ok(vfs) => vfs,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let result = with_host(
        |host| {
            let constrained_principals =
                typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        OPERATION,
                        Arc::from(namespace.virtual_path()),
                        "typed-readdir-principal-refused",
                    )
                })?;
            vfs.readdir_authenticated(namespace, |authorization| {
                let path = Arc::<str>::from(authorization.namespace().virtual_path());
                let result = host
                    .authorize_vfs_retained_path_stage(
                        vfs,
                        &module_id.to_string(),
                        constrained_principals.clone(),
                        "fs-readdir",
                        "surface.native.op.exactreaddir.0tg30vk",
                        authorization,
                        FollowMode::FollowFinal,
                        "fs:list",
                        presented.clone(),
                    )
                    .map_err(|_| {
                        crate::vfs::VfsError::policy_denied(
                            OPERATION,
                            path.clone(),
                            "typed-readdir-evaluation-refused",
                        )
                    })?;
                let receipt =
                    crate::vfs::AuthorizationReceipt::from_structured_decision(&result.evidence)?;
                match result.decision.outcome {
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => {
                        Ok(receipt)
                    }
                    DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                        Err(crate::vfs::VfsError::policy_denied(
                            OPERATION,
                            path,
                            Arc::<str>::from(receipt.evidence_digest().as_str()),
                        ))
                    }
                }
            })
        },
        Err(crate::vfs::VfsError::stale_session(OPERATION, None)),
    );
    match result {
        Ok(listing) => {
            let entries = listing
                .into_entries()
                .into_iter()
                .map(|entry| match entry {
                    crate::vfs::AuthenticatedDirectoryEntry::Utf8(name) => {
                        serde_json::Value::String(name)
                    }
                    crate::vfs::AuthenticatedDirectoryEntry::MalformedBytes(bytes) => {
                        serde_json::json!({
                            "__ibexMalformedPathEntry": true,
                            "encoding": "base64url",
                            "value": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
                        })
                    }
                })
                .collect::<Vec<_>>();
            match serde_json::to_vec(&entries) {
                Ok(json) => {
                    unsafe { write_vfs_output(json, out_json, out_len) };
                    EX_HOST_VFS_RESULT_OK
                }
                Err(_) => {
                    vfs_error_result(&crate::vfs::VfsError::malformed("readdir-json"), out_errno)
                }
            }
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

#[derive(Clone, Copy)]
enum TypedVfsMetadataKind {
    Lstat,
    Stat,
}

unsafe fn private_vfs_metadata_typed(
    kind: TypedVfsMetadataKind,
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    input: *const u8,
    input_len: u64,
    presented_handle_id: *const u8,
    presented_handle_id_len: u64,
    out_json: *mut *mut u8,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{FollowMode, NonEmptyString};

    let (operation, operation_key, coverage_edge, follow_mode) = match kind {
        TypedVfsMetadataKind::Lstat => (
            "lstat",
            "fs-lstat",
            "surface.native.op.exactlstat.1c98s6l",
            FollowMode::NoFollowFinal,
        ),
        TypedVfsMetadataKind::Stat => (
            "stat",
            "fs-stat",
            "surface.native.op.exactstat.1432ztv",
            FollowMode::FollowFinal,
        ),
    };
    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_json, out_len) } {
        return vfs_error_result(&error, out_errno);
    }
    let session = match runtime_vfs_session(runtime_nonce, operation) {
        Ok(session) => session,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let input = match unsafe { vfs_input_bytes(input, input_len, operation) } {
        Ok(input) => input,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let presented = match unsafe {
        vfs_input_bytes(
            presented_handle_id,
            presented_handle_id_len,
            match kind {
                TypedVfsMetadataKind::Lstat => "lstat-handle",
                TypedVfsMetadataKind::Stat => "stat-handle",
            },
        )
    } {
        Ok(bytes) if bytes.is_empty() => Vec::new(),
        Ok(bytes) => {
            let value = match String::from_utf8(bytes)
                .ok()
                .and_then(|value| NonEmptyString::new(value).ok())
            {
                Some(value) => value,
                None => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
            };
            vec![value]
        }
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let namespace = match session.resolve_namespace(&input) {
        Ok(namespace) => namespace,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let vfs = match session.virtual_file_system() {
        Ok(vfs) => vfs,
        Err(error) => return vfs_error_result(&error, out_errno),
    };
    let result = with_host(
        |host| {
            let constrained_principals =
                typed_principals_for_ids(host, module_ids).ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        operation,
                        Arc::from(namespace.virtual_path()),
                        "typed-metadata-principal-refused",
                    )
                })?;
            let authorize = |authorization: crate::vfs::RetainedPathAuthorization<'_>| {
                let path = Arc::<str>::from(authorization.namespace().virtual_path());
                let result = host
                    .authorize_vfs_retained_path_stage(
                        vfs,
                        &module_id.to_string(),
                        constrained_principals.clone(),
                        operation_key,
                        coverage_edge,
                        authorization,
                        follow_mode,
                        "fs:list",
                        presented.clone(),
                    )
                    .map_err(|_| {
                        crate::vfs::VfsError::policy_denied(
                            operation,
                            path.clone(),
                            "typed-metadata-evaluation-refused",
                        )
                    })?;
                let receipt =
                    crate::vfs::AuthorizationReceipt::from_structured_decision(&result.evidence)?;
                match result.decision.outcome {
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => {
                        Ok(receipt)
                    }
                    DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                        Err(crate::vfs::VfsError::policy_denied(
                            operation,
                            path,
                            Arc::<str>::from(receipt.evidence_digest().as_str()),
                        ))
                    }
                }
            };
            match kind {
                TypedVfsMetadataKind::Lstat => vfs.lstat_authenticated(namespace, authorize),
                TypedVfsMetadataKind::Stat => vfs.stat_authenticated(namespace, authorize),
            }
        },
        Err(crate::vfs::VfsError::stale_session(operation, None)),
    );
    match result {
        Ok(stat) => {
            match serde_json::to_vec(&make_stat_payload_from_metadata(stat.into_metadata())) {
                Ok(json) => {
                    unsafe { write_vfs_output(json, out_json, out_len) };
                    EX_HOST_VFS_RESULT_OK
                }
                Err(_) => vfs_error_result(
                    &crate::vfs::VfsError::malformed(match kind {
                        TypedVfsMetadataKind::Lstat => "lstat-json",
                        TypedVfsMetadataKind::Stat => "stat-json",
                    }),
                    out_errno,
                ),
            }
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Private native realpath projector. The caller supplies the canonical
/// backing identity of an already-retained target plus its requested virtual
/// spelling; the only output is the runtime/session-bound logical spelling.
/// A non-empty output is owned by the caller and must be released with
/// `ex_host_free_buffer` using the exact returned length.
///
/// This symbol is intentionally outside the public `ex_host_*` ABI inventory:
/// it is an implementation bridge between the native filesystem adapter and
/// the Rust VFS session, not an embedder surface.
/// @ref LLP 0023#6-path-bearing-observables
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
#[export_name = "ibex_private_vfs_project_realpath"]
pub(crate) unsafe extern "C" fn private_vfs_project_realpath(
    runtime_nonce: u64,
    requested_virtual: *const u8,
    requested_virtual_len: u64,
    canonical_backing: *const u8,
    canonical_backing_len: u64,
    out_virtual: *mut *mut u8,
    out_virtual_len: *mut u64,
    out_errno: *mut i32,
) -> u32 {
    if !out_errno.is_null() {
        unsafe { *out_errno = 0 };
    }
    if let Err(error) = unsafe { initialize_vfs_output(out_virtual, out_virtual_len) } {
        return vfs_error_result(&error, out_errno);
    }
    let requested_virtual =
        match unsafe { vfs_input_bytes(requested_virtual, requested_virtual_len, "realpath") } {
            Ok(input) => input,
            Err(error) => return vfs_error_result(&error, out_errno),
        };
    let canonical_backing =
        match unsafe { vfs_input_bytes(canonical_backing, canonical_backing_len, "realpath") } {
            Ok(input) => input,
            Err(error) => return vfs_error_result(&error, out_errno),
        };
    let result = runtime_vfs_session(runtime_nonce, "realpath").and_then(|session| {
        session.project_realpath_identity(&requested_virtual, &canonical_backing)
    });
    match result {
        Ok(virtual_path) => {
            unsafe { write_vfs_output(virtual_path, out_virtual, out_virtual_len) };
            EX_HOST_VFS_RESULT_OK
        }
        Err(error) => vfs_error_result(&error, out_errno),
    }
}

/// Check an Exact operation endowment against the runtime-scoped armed host
/// context. This is called before Hermes mutates JSI or finalizes package
/// baselines, so every mismatch is a fail-before-publication refusal.
///
/// # Safety
///
/// `operation_ids` must address `operation_count` readable `u32` values, and a
/// non-null `operation_manifest_digest` must point to a valid NUL-terminated
/// UTF-8 string for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_exact_endowment(
    context_id: u64,
    context_kind: u32,
    operation_manifest_digest: *const c_char,
    operation_ids: *const u32,
    operation_count: usize,
) -> i32 {
    if context_id == 0 || operation_ids.is_null() || operation_count == 0 || operation_count > 4096
    {
        return 0;
    }
    let manifest_digest = if operation_manifest_digest.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(operation_manifest_digest) }
            .to_str()
            .ok()
    };
    if !operation_manifest_digest.is_null() && manifest_digest.is_none() {
        return 0;
    }
    let operations = unsafe { std::slice::from_raw_parts(operation_ids, operation_count) };
    let host = HOST_CONTEXTS.get().and_then(|contexts| {
        contexts.read().ok().and_then(|contexts| {
            contexts
                .get(&context_id)
                .filter(|record| record.claimed)
                .map(|record| Arc::clone(&record.host))
        })
    });
    // This v1 hook is the carrier-less path: it refuses when the armed
    // binding is /2 (LLP 0053 §I1 fail-closed matrix, schema-aware on both
    // paths).
    host.is_some_and(|host| {
        host.authorizes_exact_endowment(context_kind, manifest_digest, operations, false)
    }) as i32
}

/// Carrier-capable sibling of `ex_host_authorize_exact_endowment` for the v2
/// ingress setter. `carrier_capable` names the installing surface's schema;
/// authorization refuses any schema mismatch against the armed binding. On
/// success, when `carrier_capable` is nonzero, the hook also resolves the
/// installed context against the authenticated /2 carrier-binding root pins
/// and returns the installation-time copied immutable projection through the
/// out parameters (the engine copies and never re-queries at call time).
///
/// `out_root_status` receives an `ExHermesExactRootAttributionStatus` value
/// (1 attributed / 2 unavailable / 3 ambiguous) and `out_root_id` a
/// heap-owned NUL-terminated UTF-8 root id only when attributed (release with
/// `ex_host_free_string`); both are initialized on every branch.
///
/// # Safety
///
/// `operation_ids` must address `operation_count` readable `u32` values, a
/// non-null `operation_manifest_digest` must point to a valid NUL-terminated
/// UTF-8 string for the duration of this call, and non-null out pointers must
/// be writable.
// @ref LLP 0053#r2-i3--derived-root-attribution-on-ingress — the projection
// travels under the same authorization that admits the setter
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_exact_endowment_v2(
    context_id: u64,
    context_kind: u32,
    operation_manifest_digest: *const c_char,
    operation_ids: *const u32,
    operation_count: usize,
    carrier_capable: u32,
    out_root_status: *mut u32,
    out_root_id: *mut *mut c_char,
) -> i32 {
    const ROOT_UNAVAILABLE: u32 = 2;
    if !out_root_status.is_null() {
        unsafe { *out_root_status = ROOT_UNAVAILABLE };
    }
    if !out_root_id.is_null() {
        unsafe { *out_root_id = std::ptr::null_mut() };
    }
    if context_id == 0
        || operation_ids.is_null()
        || operation_count == 0
        || operation_count > 4096
        || out_root_status.is_null()
        || out_root_id.is_null()
    {
        return 0;
    }
    let manifest_digest = if operation_manifest_digest.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(operation_manifest_digest) }
            .to_str()
            .ok()
    };
    if !operation_manifest_digest.is_null() && manifest_digest.is_none() {
        return 0;
    }
    let operations = unsafe { std::slice::from_raw_parts(operation_ids, operation_count) };
    let host = HOST_CONTEXTS.get().and_then(|contexts| {
        contexts.read().ok().and_then(|contexts| {
            contexts
                .get(&context_id)
                .filter(|record| record.claimed)
                .map(|record| Arc::clone(&record.host))
        })
    });
    let Some(host) = host else {
        return 0;
    };
    if !host.authorizes_exact_endowment(
        context_kind,
        manifest_digest,
        operations,
        carrier_capable != 0,
    ) {
        return 0;
    }
    if carrier_capable != 0 {
        let (status, root_id) = host.exact_carrier_root_attribution(context_kind);
        unsafe { *out_root_status = status };
        if let Some(root_id) = root_id {
            if let Ok(root_id) = CString::new(root_id) {
                unsafe { *out_root_id = root_id.into_raw() };
            } else {
                // The frozen root-id grammar forbids embedded NUL; a value
                // that cannot cross the C boundary fails closed to
                // UNAVAILABLE rather than truncating.
                unsafe { *out_root_status = ROOT_UNAVAILABLE };
            }
        }
    }
    1
}

/// Verify that an explicit construction transaction installed exactly the
/// capability roles named by its runtime-scoped armed snapshot.
#[no_mangle]
pub extern "C" fn ex_host_authorize_embedder_capability_set(
    context_id: u64,
    installed_flags: u32,
) -> i32 {
    if context_id == 0 {
        return 0;
    }
    let host = HOST_CONTEXTS.get().and_then(|contexts| {
        contexts.read().ok().and_then(|contexts| {
            contexts
                .get(&context_id)
                .filter(|record| record.claimed)
                .map(|record| Arc::clone(&record.host))
        })
    });
    host.is_some_and(|host| host.authorizes_embedder_capability_set(installed_flags)) as i32
}

#[doc(hidden)]
pub fn installed_typed_decision_count() -> usize {
    with_host(Host::typed_decision_count, 0)
}

#[doc(hidden)]
pub fn installed_legacy_authorization_check_count() -> usize {
    with_host(Host::legacy_authorization_check_count, 0)
}

#[cfg(feature = "capsec-conformance-observer")]
pub fn begin_installed_conformance_observation(terminal_branch_id: &str) -> bool {
    with_host(
        |host| {
            host.begin_conformance_observation(terminal_branch_id);
            true
        },
        false,
    )
}

#[cfg(feature = "capsec-conformance-observer")]
pub fn take_installed_conformance_observations() -> (
    Vec<super::capability::ObservedCapabilityDecision>,
    Vec<super::ObservedTypedDecision>,
) {
    with_host(
        |host| {
            (
                host.take_conformance_observations(),
                host.take_typed_conformance_observations(),
            )
        },
        (Vec::new(), Vec::new()),
    )
}

/// Render the would-deny audit report for the installed host, but only when it
/// is running in `Audit` mode and something was flagged.
///
/// @ref LLP 0013#phase-1 — printed at process shutdown so `ibex run --capsec
/// audit` surfaces the grants an app must declare before moving to `enforce`.
pub fn current_audit_report() -> Option<String> {
    with_host(
        |host| {
            if host.security_mode() == super::SecurityMode::Audit {
                let report = host.audit_report();
                if report.is_empty() {
                    None
                } else {
                    Some(report)
                }
            } else {
                None
            }
        },
        None,
    )
}

fn security_log_enabled() -> bool {
    *SECURITY_LOG_ENABLED.get_or_init(|| {
        std::env::var("EXACT_SECURITY_LOG")
            .map(|v| !matches!(v.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
            .unwrap_or(false)
    })
}

fn console_mirror_enabled() -> bool {
    // Memoized like `security_log_enabled` above: `ex_host_console_log` calls this
    // on every log line on the JS thread, and an env lookup per line (allocating
    // on a hit) is needless per-line work for a value fixed for the process
    // lifetime (ENG-22955).
    *CONSOLE_MIRROR_ENABLED.get_or_init(|| {
        std::env::var("IBEX_SUPPRESS_CONSOLE_MIRROR")
            .map(|v| matches!(v.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
            .unwrap_or(true)
    })
}

/// Eagerly initialize process-lifetime observability controls while the Host
/// is being constructed. Later log/console calls consume only these immutable
/// values and never consult a mutated post-arm host environment.
/// @ref LLP 0025#2-startup-configuration-is-captured-before-arming
pub(crate) fn capture_immutable_environment_configuration() {
    let _ = security_log_enabled();
    let _ = console_mirror_enabled();
}

fn write_stdio_line(writer: &mut impl Write, msg: &str) -> io::Result<()> {
    writer.write_all(msg.as_bytes())?;
    writer.write_all(b"\n")
}

fn write_stdout_line(msg: &str) {
    let mut stdout = io::stdout().lock();
    let _ = write_stdio_line(&mut stdout, msg);
}

fn write_stderr_line(msg: &str) {
    let mut stderr = io::stderr().lock();
    let _ = write_stdio_line(&mut stderr, msg);
}

#[cfg(unix)]
fn duplicate_counted_worker_console_writer(level: i32) -> io::Result<std::fs::File> {
    use std::os::fd::FromRawFd as _;

    let source = if level == 1 {
        libc::STDERR_FILENO
    } else {
        libc::STDOUT_FILENO
    };
    loop {
        // SAFETY: source is a live standard descriptor while the console relay
        // gate serializes this duplicate against descriptor replacement. The
        // returned descriptor is uniquely transferred into File below.
        let descriptor = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 3) };
        if descriptor >= 0 {
            // SAFETY: fcntl returned a fresh, uniquely owned descriptor.
            return Ok(unsafe { std::fs::File::from_raw_fd(descriptor) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(not(unix))]
fn duplicate_counted_worker_console_writer(_level: i32) -> io::Result<std::fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "authenticated counted console relay requires Unix descriptors",
    ))
}

fn write_counted_worker_console_record(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    writer.write_all(payload)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

// @ref LLP 0006#degrade-diagnostics-never-the-caller — console output is mirrored to stdio from the JS
// thread, which is the app host's main thread. stdout there is a PTY or pipe
// drained by a console UI (Xcode) or a script wrapper; when the consumer
// stalls, a direct write blocks the main thread ("Application Not
// Responding"), and a vanished consumer used to abort the process through the
// `println!` panic path. Stdio mirroring is best-effort diagnostics, so it
// goes through a bounded queue to a writer thread and drops lines under
// backpressure instead of ever blocking or failing the caller.
const CONSOLE_QUEUE_CAPACITY: usize = 2048;

enum ConsoleLine {
    Out(String),
    Err(String),
}

struct ConsoleQueue {
    tx: std::sync::mpsc::SyncSender<ConsoleLine>,
    dropped: std::sync::atomic::AtomicU64,
}

// Lines accepted into the queue but not yet written by the writer thread.
// `ex_host_console_flush` waits (bounded) on this reaching zero so
// process.exit does not discard output enqueued in the same tick — the
// writer thread otherwise races process teardown, and on Windows
// (legacyUnarmedExit -> ExitProcess) it loses deterministically. (ENG-23639)
static CONSOLE_PENDING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[doc(hidden)]
pub fn terminal_console_pending_records() -> u64 {
    CONSOLE_PENDING.load(std::sync::atomic::Ordering::Acquire)
}

impl ConsoleQueue {
    fn enqueue(&self, line: ConsoleLine) {
        use std::sync::atomic::Ordering;

        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let notice = ConsoleLine::Err(format!(
                "[ibex-console] dropped {dropped} line(s) under stdio backpressure"
            ));
            // Count BEFORE sending so the writer's decrement can never land
            // first and transiently wrap the counter below zero.
            CONSOLE_PENDING.fetch_add(1, Ordering::Release);
            if self.tx.try_send(notice).is_err() {
                CONSOLE_PENDING.fetch_sub(1, Ordering::Release);
                self.dropped.fetch_add(dropped, Ordering::Relaxed);
            }
        }
        CONSOLE_PENDING.fetch_add(1, Ordering::Release);
        if self.tx.try_send(line).is_err() {
            CONSOLE_PENDING.fetch_sub(1, Ordering::Release);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn console_queue() -> &'static ConsoleQueue {
    static QUEUE: OnceLock<ConsoleQueue> = OnceLock::new();
    QUEUE.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<ConsoleLine>(CONSOLE_QUEUE_CAPACITY);
        // If the spawn fails the receiver is dropped and enqueue() degrades to
        // counting drops; console mirroring is lost but the app keeps running.
        let _ = std::thread::Builder::new()
            .name("ibex-console".to_string())
            .spawn(move || {
                while let Ok(line) = rx.recv() {
                    match line {
                        ConsoleLine::Out(msg) => write_stdout_line(&msg),
                        ConsoleLine::Err(msg) => write_stderr_line(&msg),
                    }
                    CONSOLE_PENDING.fetch_sub(1, std::sync::atomic::Ordering::Release);
                }
            });
        ConsoleQueue {
            tx,
            dropped: std::sync::atomic::AtomicU64::new(0),
        }
    })
}

/// Wait (bounded by `timeout_ms`) for the console writer thread to drain
/// every line already accepted into the queue. Called by `legacyUnarmedExit`
/// before terminating so `console.log(...); process.exit(0)` cannot lose
/// the log line; a stalled stdio consumer only delays exit by the timeout,
/// never wedges it. (ENG-23639)
#[no_mangle]
pub extern "C" fn ex_host_console_flush(timeout_ms: u32) {
    use std::sync::atomic::Ordering;

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(u64::from(timeout_ms));
    while CONSOLE_PENDING.load(Ordering::Acquire) > 0 {
        if std::time::Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn enqueue_stdout_line(msg: String) {
    console_queue().enqueue(ConsoleLine::Out(msg));
}

fn enqueue_stderr_line(msg: String) {
    console_queue().enqueue(ConsoleLine::Err(msg));
}

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
}

#[cfg(target_os = "android")]
fn write_android_logcat(level: i32, msg: &str) {
    const ANDROID_LOG_INFO: c_int = 4;
    const ANDROID_LOG_ERROR: c_int = 6;
    static TAG: &[u8] = b"Ibex\0";
    static FORMAT: &[u8] = b"%s\0";

    let sanitized;
    let c_msg = match CString::new(msg) {
        Ok(value) => value,
        Err(_) => {
            sanitized = msg.replace('\0', "\\0");
            match CString::new(sanitized.as_str()) {
                Ok(value) => value,
                Err(_) => return,
            }
        }
    };
    let priority = if level == 1 {
        ANDROID_LOG_ERROR
    } else {
        ANDROID_LOG_INFO
    };
    unsafe {
        // @ref LLP 0008#android-backend-matrix — Android console output is
        // mirrored to logcat while retaining the host/stdout queue.
        __android_log_print(
            priority,
            TAG.as_ptr() as *const c_char,
            FORMAT.as_ptr() as *const c_char,
            c_msg.as_ptr(),
        );
    }
}

const SQLITE_OPEN_READONLY: u64 = 0x00000001;
const SQLITE_OPEN_READWRITE: u64 = 0x00000002;
const SQLITE_OPEN_CREATE: u64 = 0x00000004;

#[derive(Default)]
#[allow(dead_code)]
struct SqliteOpenOptions {
    readonly: bool,
    create: bool,
    readwrite: bool,
    flags: Option<u64>,
}

fn parse_sqlite_open_options(raw: *const c_char) -> SqliteOpenOptions {
    if raw.is_null() {
        return SqliteOpenOptions {
            readonly: false,
            create: true,
            readwrite: true,
            flags: None,
        };
    }

    let raw = unsafe { CStr::from_ptr(raw) }.to_string_lossy();
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(serde_json::Value::Object(values)) => {
            let flags = values
                .get("flags")
                .and_then(serde_json::Value::as_u64)
                .or(None);
            SqliteOpenOptions {
                readonly: values
                    .get("readonly")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                create: values
                    .get("create")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
                readwrite: values
                    .get("readwrite")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
                flags,
            }
        }
        Ok(serde_json::Value::Number(flags)) => SqliteOpenOptions {
            readonly: false,
            create: true,
            readwrite: true,
            flags: flags.as_u64(),
        },
        _ => SqliteOpenOptions {
            readonly: false,
            create: true,
            readwrite: true,
            flags: None,
        },
    }
}

fn sqlite_open_flags(options: &SqliteOpenOptions) -> OpenFlags {
    if let Some(raw_flags) = options.flags {
        let mut open_flags = OpenFlags::empty();
        if raw_flags & SQLITE_OPEN_READONLY != 0 {
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        }
        if raw_flags & SQLITE_OPEN_READWRITE != 0 {
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        }
        if raw_flags & SQLITE_OPEN_CREATE != 0 {
            open_flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
        }
        return open_flags;
    }

    // A read-only connection must not also carry READ_WRITE or CREATE: SQLite
    // rejects `READ_ONLY|CREATE` with SQLITE_MISUSE, which is why `{readonly:
    // true}` opens silently failed (returning handle 0 with no error) even for a
    // file that exists and is readable. When not read-only, honor the previously
    // ignored `readwrite` field, and treat `create` as implying write access
    // (CREATE requires READ_WRITE, or SQLite likewise returns SQLITE_MISUSE).
    let mut open_flags = OpenFlags::empty();
    if options.readonly {
        open_flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
    } else {
        if options.readwrite || options.create {
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        }
        if options.create {
            open_flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
        }
        if open_flags.is_empty() {
            // `{readonly:false, readwrite:false, create:false}` requested no access
            // mode at all; fall back to read-only rather than hand SQLite empty
            // flags (also SQLITE_MISUSE).
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        }
    }
    open_flags
}

fn sqlite_authorizer(ctx: AuthContext<'_>) -> Authorization {
    match ctx.action {
        AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,
        AuthAction::Function { function_name }
            if function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Deny
        }
        _ => Authorization::Allow,
    }
}

fn install_sqlite_authorizer(db: &Connection) -> rusqlite::Result<()> {
    db.authorizer(Some(sqlite_authorizer))
}

fn sqlite_isolated_io_authorizer(ctx: AuthContext<'_>) -> Authorization {
    match ctx.action {
        AuthAction::Pragma {
            pragma_name,
            pragma_value: Some(_),
        } if pragma_name.eq_ignore_ascii_case("journal_mode")
            || pragma_name.eq_ignore_ascii_case("temp_store") =>
        {
            Authorization::Deny
        }
        AuthAction::Pragma { pragma_name, .. }
            if pragma_name.eq_ignore_ascii_case("temp_store_directory")
                || pragma_name.eq_ignore_ascii_case("data_store_directory") =>
        {
            Authorization::Deny
        }
        _ => sqlite_authorizer(ctx),
    }
}

/// Pin every SQLite-owned auxiliary byte to memory before user SQL can run.
/// File-backed armed connections enter through an already authorized retained
/// descriptor; permitting rollback journals, WAL/SHM, or temp databases to
/// derive sibling pathnames would escape that checked object.
// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
fn configure_sqlite_isolated_io(db: &Connection) -> rusqlite::Result<()> {
    let journal_mode: String =
        db.pragma_update_and_check(None, "journal_mode", "MEMORY", |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("memory") {
        return Err(rusqlite::Error::InvalidQuery);
    }
    db.pragma_update(None, "temp_store", "MEMORY")?;
    let temp_store: i64 = db.pragma_query_value(None, "temp_store", |row| row.get(0))?;
    if temp_store != 2 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    db.authorizer(Some(sqlite_isolated_io_authorizer))?;
    Ok(())
}

fn stable_legacy_json_text(value: &serde_json::Value, output: &mut String) {
    match value {
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                stable_legacy_json_text(value, output);
            }
            output.push(']');
        }
        serde_json::Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            output.push('{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output
                    .push_str(&serde_json::to_string(key).expect("JSON object key must serialize"));
                output.push(':');
                stable_legacy_json_text(value, output);
            }
            output.push('}');
        }
        _ => output.push_str(&value.to_string()),
    }
}

/// Convert an ordinary user binding using the legacy SQLite semantics. This
/// function deliberately does not recognize the private transport envelope:
/// envelope decoding happens exactly once at the binding boundary, otherwise
/// a user value nested inside `{kind:"value"}` can smuggle a second envelope.
fn plain_sql_value(value: &serde_json::Value) -> rusqlite::types::Value {
    match value {
        serde_json::Value::Null => rusqlite::types::Value::Null,
        serde_json::Value::Bool(value) => {
            rusqlite::types::Value::Integer(if *value { 1 } else { 0 })
        }
        serde_json::Value::Number(value) => {
            if let Some(num) = value.as_i64() {
                rusqlite::types::Value::Integer(num)
            } else if let Some(num) = value.as_u64() {
                if num <= i64::MAX as u64 {
                    rusqlite::types::Value::Integer(num as i64)
                } else {
                    rusqlite::types::Value::Real(num as f64)
                }
            } else {
                rusqlite::types::Value::Real(value.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(value) => rusqlite::types::Value::Text(value.clone()),
        serde_json::Value::Array(values) => rusqlite::types::Value::Blob(
            values
                .iter()
                .map(|value| value.as_u64().unwrap_or_default() as u8)
                .collect(),
        ),
        serde_json::Value::Object(value) => {
            // serde_json's map representation is feature-unified across the
            // workspace. Do not let an unrelated dependency enabling
            // `preserve_order` silently change the legacy SQLite text value.
            let mut entries = value.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            rusqlite::types::Value::Text(entries.into_iter().fold(
                String::new(),
                |mut out, (key, value)| {
                    if !out.is_empty() {
                        out.push(',');
                    }
                    out.push_str(key);
                    out.push('=');
                    stable_legacy_json_text(value, &mut out);
                    out
                },
            ))
        }
    }
}

fn to_sql_value(value: &serde_json::Value) -> rusqlite::types::Value {
    if let serde_json::Value::Object(object) = value {
        if object.len() == 1 {
            if let Some(envelope) = object
                .get("$ibexSqliteBindingV1")
                .and_then(serde_json::Value::as_object)
            {
                match envelope.get("kind").and_then(serde_json::Value::as_str) {
                    Some("blob") if envelope.len() == 2 => {
                        if let Some(encoded) =
                            envelope.get("base64").and_then(serde_json::Value::as_str)
                        {
                            if let Ok(bytes) =
                                base64::engine::general_purpose::STANDARD.decode(encoded)
                            {
                                return rusqlite::types::Value::Blob(bytes);
                            }
                        }
                    }
                    Some("value") if envelope.len() == 2 => {
                        if let Some(inner) = envelope.get("value") {
                            return plain_sql_value(inner);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    plain_sql_value(value)
}

enum SqlBindings {
    Positional(Vec<rusqlite::types::Value>),
    Named(Vec<(String, rusqlite::types::Value)>),
}

fn parse_bindings(raw: *const c_char) -> SqlBindings {
    if raw.is_null() {
        return SqlBindings::Positional(vec![]);
    }

    let raw = unsafe { CStr::from_ptr(raw) }.to_string_lossy();
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(serde_json::Value::Array(values)) => {
            SqlBindings::Positional(values.iter().map(to_sql_value).collect())
        }
        Ok(serde_json::Value::Object(values)) => SqlBindings::Named(
            values
                .into_iter()
                .map(|(key, value)| (key, to_sql_value(&value)))
                .collect(),
        ),
        Ok(serde_json::Value::Null) => SqlBindings::Positional(vec![]),
        Ok(other) => SqlBindings::Positional(vec![to_sql_value(&other)]),
        Err(_) => SqlBindings::Positional(vec![]),
    }
}

fn query_with_bindings<'stmt>(
    stmt: &'stmt mut rusqlite::Statement<'_>,
    bindings: &SqlBindings,
) -> rusqlite::Result<rusqlite::Rows<'stmt>> {
    match bindings {
        SqlBindings::Positional(values) => stmt.query(params_from_iter(values.iter())),
        SqlBindings::Named(values) => {
            let named: Vec<(&str, &dyn ToSql)> = values
                .iter()
                .map(|(name, value)| (name.as_str(), value as &dyn ToSql))
                .collect();
            stmt.query(named.as_slice())
        }
    }
}

fn execute_with_bindings(
    stmt: &mut rusqlite::Statement<'_>,
    bindings: &SqlBindings,
) -> rusqlite::Result<usize> {
    match bindings {
        SqlBindings::Positional(values) => stmt.execute(params_from_iter(values.iter())),
        SqlBindings::Named(values) => {
            let named: Vec<(&str, &dyn ToSql)> = values
                .iter()
                .map(|(name, value)| (name.as_str(), value as &dyn ToSql))
                .collect();
            stmt.execute(named.as_slice())
        }
    }
}

fn sqlite_value_to_json(value: ValueRef<'_>) -> serde_json::Value {
    match value {
        ValueRef::Null => serde_json::Value::Null,
        ValueRef::Integer(value) => serde_json::json!(value),
        ValueRef::Real(value) => serde_json::json!(value),
        ValueRef::Text(value) => std::str::from_utf8(value)
            .map(std::string::ToString::to_string)
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
        ValueRef::Blob(value) => {
            serde_json::json!({
                "$ibexSqliteBlobResultBase64":
                    base64::engine::general_purpose::STANDARD.encode(value)
            })
        }
    }
}

fn sqlite_value_type_name(value: &ValueRef<'_>) -> &'static str {
    match value {
        ValueRef::Null => "NULL",
        ValueRef::Integer(_) => "INTEGER",
        ValueRef::Real(_) => "FLOAT",
        ValueRef::Text(_) => "TEXT",
        ValueRef::Blob(_) => "BLOB",
    }
}

fn as_json_cstring(value: &serde_json::Value) -> *mut c_char {
    match serde_json::to_string(value) {
        Ok(payload) => match CString::new(payload) {
            Ok(value) => value.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

fn unix_time_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos() / 1_000_000)
        .unwrap_or(0) as u64
}

fn unix_time_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0) as u64
}

fn make_stat_payload(path: &str, follow_links: bool) -> Option<serde_json::Value> {
    let meta = if follow_links {
        std::fs::metadata(path).ok()?
    } else {
        std::fs::symlink_metadata(path).ok()?
    };

    Some(make_stat_payload_from_metadata(meta))
}

fn make_stat_payload_from_metadata(meta: std::fs::Metadata) -> serde_json::Value {
    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode()
        }
        #[cfg(not(unix))]
        {
            0u32
        }
    };

    let (dev, ino, nlink, uid, gid, rdev, blksize, blocks) = {
        #[cfg(unix)]
        {
            (
                meta.dev(),
                meta.ino(),
                meta.nlink(),
                meta.uid(),
                meta.gid(),
                meta.rdev(),
                meta.blksize(),
                meta.blocks(),
            )
        }
        #[cfg(not(unix))]
        {
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
        }
    };

    let atime = meta.accessed().ok().unwrap_or(UNIX_EPOCH);
    let mtime = meta.modified().ok().unwrap_or(UNIX_EPOCH);
    let (ctime, birthtime) = {
        #[cfg(unix)]
        {
            let ctime_sec = meta.ctime();
            let ctime_nsec = meta.ctime_nsec() as u32;
            let ctime = if ctime_sec >= 0 {
                UNIX_EPOCH + Duration::new(ctime_sec as u64, ctime_nsec)
            } else {
                UNIX_EPOCH
            };
            (ctime, meta.created().ok().unwrap_or(ctime))
        }
        #[cfg(not(unix))]
        {
            let ctime = meta.modified().unwrap_or(UNIX_EPOCH);
            let birthtime = meta.created().unwrap_or(ctime);
            (ctime, birthtime)
        }
    };

    let atime_ms = unix_time_millis(atime);
    let mtime_ms = unix_time_millis(mtime);
    let ctime_ms = unix_time_millis(ctime);
    let birthtime_ms = unix_time_millis(birthtime);

    let atime_ns = unix_time_nanos(atime);
    let mtime_ns = unix_time_nanos(mtime);
    let ctime_ns = unix_time_nanos(ctime);
    let birthtime_ns = unix_time_nanos(birthtime);
    let file_type = meta.file_type();
    let (is_char_device, is_block_device, is_fifo, is_socket) = {
        #[cfg(unix)]
        {
            (
                file_type.is_char_device(),
                file_type.is_block_device(),
                file_type.is_fifo(),
                file_type.is_socket(),
            )
        }
        #[cfg(not(unix))]
        {
            (false, false, false, false)
        }
    };

    json!({
        "size": meta.len(),
        "mode": mode,
        "dev": dev,
        "ino": ino,
        "nlink": nlink,
        "uid": uid,
        "gid": gid,
        "rdev": rdev,
        "blksize": blksize,
        "blocks": blocks,
        "is_dir": file_type.is_dir(),
        "is_file": file_type.is_file(),
        "is_symlink": file_type.is_symlink(),
        "is_char_device": is_char_device,
        "is_block_device": is_block_device,
        "is_fifo": is_fifo,
        "is_socket": is_socket,
        "atime_ms": atime_ms,
        "mtime_ms": mtime_ms,
        "ctime_ms": ctime_ms,
        "birthtime_ms": birthtime_ms,
        "atime_ns": atime_ns,
        "mtime_ns": mtime_ns,
        "ctime_ns": ctime_ns,
        "birthtime_ns": birthtime_ns
    })
}

#[no_mangle]
pub extern "C" fn ex_host_version() -> u32 {
    EXACT_HOST_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn ex_host_init() {}

/// Install a closed, unarmed host singleton for ABI compatibility.
/// Called from iOS/Swift before creating a runtime.
/// Production embedders must replace it through `ex_host_install_armed`
/// before calling the armed Hermes constructor.
#[no_mangle]
pub extern "C" fn ex_host_install() {
    install_host(Host::closed_unarmed());
}

/// Explicit fail-closed embedder arming entry point. Returns 0 only after the
/// immutable snapshot is authenticated and installed.
///
/// # Safety
///
/// Each pointer must reference its declared byte length for the duration of
/// this call. The buffers are copied before return.
#[no_mangle]
pub unsafe extern "C" fn ex_host_install_armed(
    snapshot: *const u8,
    snapshot_len: usize,
    expected_identity: *const u8,
    expected_identity_len: usize,
) -> i32 {
    if snapshot.is_null() || expected_identity.is_null() {
        return -1;
    }
    let snapshot = unsafe { std::slice::from_raw_parts(snapshot, snapshot_len) };
    let expected = unsafe { std::slice::from_raw_parts(expected_identity, expected_identity_len) };
    match install_armed_host(snapshot, expected) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: refusing host arming: {error}");
            -1
        }
    }
}

/// Engine/host handshake: exact digest equality proves the runtime being
/// created is attached to the decision context the caller authenticated.
///
/// # Safety
///
/// `digest` must be null or point to a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ex_host_matches_armed_snapshot_digest(digest: *const c_char) -> i32 {
    if digest.is_null() {
        return 0;
    }
    let Ok(digest) = unsafe { CStr::from_ptr(digest) }.to_str() else {
        return 0;
    };
    with_host(
        |host| {
            i32::from(
                host.armed_snapshot()
                    .is_some_and(|snapshot| snapshot.digest().as_str() == digest),
            )
        },
        0,
    )
}

/// Return 1 only when `context_id` names the claimed Host whose authenticated
/// runtime-extension capsule has exactly `digest`.
///
/// # Safety
///
/// `digest` must address a readable NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn ex_host_matches_runtime_extension_authority_digest(
    context_id: u64,
    digest: *const c_char,
) -> i32 {
    if context_id == 0 || digest.is_null() {
        return 0;
    }
    let Ok(digest) = unsafe { CStr::from_ptr(digest) }.to_str() else {
        return 0;
    };
    HOST_CONTEXTS
        .get()
        .and_then(|contexts| contexts.read().ok())
        .and_then(|contexts| {
            contexts
                .get(&context_id)
                .filter(|record| record.claimed)
                .map(|record| {
                    i32::from(
                        record
                            .host
                            .matches_runtime_extension_authority_digest(digest),
                    )
                })
        })
        .unwrap_or(0)
}

/// Hash one copied runtime-extension bootstrap payload and return 1 only when
/// its bytes exactly match the canonical textual SHA-256 digest. This is a
/// context-free structural integrity check; authority still comes from a
/// claimed armed Host and an exactly matching registry projection.
///
/// # Safety
///
/// `bytes` must address `len` readable bytes and `digest` must address a
/// readable NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn ex_host_runtime_extension_bootstrap_digest_matches_v1(
    bytes: *const u8,
    len: usize,
    digest: *const c_char,
) -> i32 {
    const MAX_RUNTIME_EXTENSION_BOOTSTRAP_BYTES: usize = 64 * 1024 * 1024;
    if bytes.is_null()
        || digest.is_null()
        || len == 0
        || len > MAX_RUNTIME_EXTENSION_BOOTSTRAP_BYTES
    {
        return 0;
    }
    let Ok(expected) = unsafe { CStr::from_ptr(digest) }.to_str() else {
        return 0;
    };
    let Ok(expected) = capsec_semantics::model::Digest::new(expected) else {
        return 0;
    };
    let payload = unsafe { std::slice::from_raw_parts(bytes, len) };
    use sha2::{Digest as _, Sha256};
    let observed = format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(payload))
    );
    i32::from(observed == expected.as_str())
}

/// Return 1 only when a strict data-only projection of the structurally
/// validated native registry exactly matches the authenticated capsule.
///
/// # Safety
///
/// `projection_json` must address a readable NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn ex_host_matches_runtime_extension_registry_projection_v1(
    context_id: u64,
    projection_json: *const c_char,
) -> i32 {
    const MAX_REGISTRY_PROJECTION_BYTES: usize = 4 * 1024 * 1024;
    if context_id == 0 || projection_json.is_null() {
        return 0;
    }
    let Ok(projection_json) = unsafe { CStr::from_ptr(projection_json) }.to_str() else {
        return 0;
    };
    if projection_json.is_empty() || projection_json.len() > MAX_REGISTRY_PROJECTION_BYTES {
        return 0;
    }
    HOST_CONTEXTS
        .get()
        .and_then(|contexts| contexts.read().ok())
        .and_then(|contexts| {
            contexts
                .get(&context_id)
                .filter(|record| record.claimed)
                .map(|record| {
                    i32::from(
                        record
                            .host
                            .matches_runtime_extension_registry_projection(projection_json),
                    )
                })
        })
        .unwrap_or(0)
}

/// Authorize one authenticated native extension operation and mint an opaque
/// context-local lease. The lease binds the capsule, exact namespace/class,
/// canonical resource digest, and full constrained principal set.
///
/// # Safety
///
/// String pointers must address readable NUL-terminated UTF-8 strings;
/// `constrained_principals` must address `count` readable `u64` values; and
/// `presented_leases` must be null for a zero count or address the declared
/// sorted, duplicate-free opaque lease IDs; `out_lease` must address one
/// writable `u64`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ex_host_authorize_runtime_extension_operation_v1(
    host_context_id: u64,
    runtime_nonce: u64,
    extension_generation: u64,
    extension_id: *const c_char,
    operation_id: *const c_char,
    authority_class: *const c_char,
    semantics: *const c_char,
    stage: *const c_char,
    atomicity_group: *const c_char,
    resource_kinds: *const *const c_char,
    resource_kind_count: usize,
    resource_json: *const c_char,
    constrained_principals: *const u64,
    count: usize,
    presented_leases: *const u64,
    presented_lease_count: usize,
    out_lease: *mut u64,
) -> i32 {
    const MAX_CONSTRAINED_PRINCIPALS: usize = 256;
    const MAX_PRESENTED_LEASES: usize = 256;
    const MAX_RESOURCE_KINDS: usize = 256;
    if out_lease.is_null() {
        return 0;
    }
    unsafe { *out_lease = 0 };
    if host_context_id == 0
        || runtime_nonce == 0
        || extension_generation == 0
        || extension_id.is_null()
        || operation_id.is_null()
        || authority_class.is_null()
        || semantics.is_null()
        || stage.is_null()
        || atomicity_group.is_null()
        || resource_kinds.is_null()
        || resource_kind_count == 0
        || resource_kind_count > MAX_RESOURCE_KINDS
        || resource_json.is_null()
        || constrained_principals.is_null()
        || count == 0
        || count > MAX_CONSTRAINED_PRINCIPALS
        || presented_lease_count > MAX_PRESENTED_LEASES
        || (presented_lease_count == 0) != presented_leases.is_null()
    {
        return 0;
    }
    let Ok(extension_id) = unsafe { CStr::from_ptr(extension_id) }.to_str() else {
        return 0;
    };
    let Ok(operation_id) = unsafe { CStr::from_ptr(operation_id) }.to_str() else {
        return 0;
    };
    let Ok(authority_class) = unsafe { CStr::from_ptr(authority_class) }.to_str() else {
        return 0;
    };
    let Ok(semantics) = unsafe { CStr::from_ptr(semantics) }.to_str() else {
        return 0;
    };
    let Ok(stage) = unsafe { CStr::from_ptr(stage) }.to_str() else {
        return 0;
    };
    let Ok(atomicity_group) = unsafe { CStr::from_ptr(atomicity_group) }.to_str() else {
        return 0;
    };
    let resource_kind_pointers =
        unsafe { std::slice::from_raw_parts(resource_kinds, resource_kind_count) };
    let Some(resource_kinds) = resource_kind_pointers
        .iter()
        .map(|pointer| {
            if pointer.is_null() {
                return None;
            }
            unsafe { CStr::from_ptr(*pointer) }.to_str().ok()
        })
        .collect::<Option<Vec<_>>>()
    else {
        return 0;
    };
    if resource_kinds.windows(2).any(|pair| pair[0] >= pair[1]) {
        return 0;
    }
    let Ok(resource_json) = unsafe { CStr::from_ptr(resource_json) }.to_str() else {
        return 0;
    };
    let module_ids = unsafe { std::slice::from_raw_parts(constrained_principals, count) };
    let presented_lease_ids = if presented_lease_count == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(presented_leases, presented_lease_count) }
    };
    if presented_lease_ids.iter().any(|lease| *lease == 0)
        || presented_lease_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return 0;
    }
    let Some((host, presented_grants)) = HOST_CONTEXTS.get().and_then(|contexts| {
        contexts.read().ok().and_then(|contexts| {
            let record = contexts
                .get(&host_context_id)
                .filter(|record| record.claimed)?;
            let grants = presented_lease_ids
                .iter()
                .map(|lease| {
                    record
                        .runtime_extension_lease_is_current(*lease)
                        .then(|| record.runtime_extension_leases.get(lease).cloned())
                        .flatten()
                })
                .collect::<Option<Vec<_>>>()?;
            Some((Arc::clone(&record.host), grants))
        })
    }) else {
        return 0;
    };
    let Some(actor) = module_ids
        .first()
        .and_then(|id| host.typed_principal_for_module(&id.to_string()))
    else {
        return 0;
    };
    let Some(mut principals) = typed_principals_for_ids(&host, module_ids) else {
        return 0;
    };
    for grant in &presented_grants {
        if grant.runtime_nonce != runtime_nonce
            || grant.extension_generation != extension_generation
            || grant.extension_id.as_str() != extension_id
        {
            return 0;
        }
        principals.extend(grant.constrained_principals.iter().cloned());
    }
    if capsec_semantics::model::sort_and_dedup_principals(&mut principals).is_err()
        || principals.len() > MAX_CONSTRAINED_PRINCIPALS
    {
        return 0;
    }
    let Ok(grant) = host.authorize_runtime_extension_operation(
        runtime_nonce,
        extension_generation,
        extension_id,
        operation_id,
        authority_class,
        semantics,
        stage,
        atomicity_group,
        &resource_kinds,
        resource_json,
        actor,
        principals,
        presented_lease_ids.to_vec(),
    ) else {
        return 0;
    };

    let Some(contexts) = HOST_CONTEXTS.get() else {
        return 0;
    };
    let mut contexts = match contexts.write() {
        Ok(contexts) => contexts,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(record) = contexts.get_mut(&host_context_id).filter(|record| {
        record.claimed
            && Arc::ptr_eq(&record.host, &host)
            && record
                .host
                .matches_runtime_extension_authority_digest(grant.authority_capsule_digest.as_str())
            && presented_lease_ids
                .iter()
                .all(|lease| record.runtime_extension_lease_is_current(*lease))
    }) else {
        return 0;
    };
    let mut fresh_lease = None;
    for _ in 0..32 {
        let mut bytes = [0u8; std::mem::size_of::<u64>()];
        if getrandom(&mut bytes).is_err() {
            return 0;
        }
        let lease = u64::from_ne_bytes(bytes);
        if lease == 0 || record.runtime_extension_leases.contains_key(&lease) {
            continue;
        }
        fresh_lease = Some(lease);
        break;
    }
    let Some(lease) = fresh_lease else {
        return 0;
    };
    record.runtime_extension_leases.insert(lease, grant);
    unsafe { *out_lease = lease };
    1
}

/// Try to check that an opaque runtime-extension operation lease remains live
/// and is bound to this exact runtime nonce, extension generation, namespace,
/// and operation. Returns 1 for current, 0 for stale/malformed, and -1 when a
/// concurrent Host-context or typed-generation writer owns the relevant lock.
/// This is the producer-thread admission path and never waits.
///
/// # Safety
///
/// String pointers must address readable NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn ex_host_check_runtime_extension_lease_binding_v1(
    host_context_id: u64,
    lease: u64,
    runtime_nonce: u64,
    extension_generation: u64,
    extension_id: *const c_char,
    operation_id: *const c_char,
) -> i32 {
    if host_context_id == 0
        || lease == 0
        || runtime_nonce == 0
        || extension_generation == 0
        || extension_id.is_null()
        || operation_id.is_null()
    {
        return 0;
    }
    let Ok(extension_id) = unsafe { CStr::from_ptr(extension_id) }.to_str() else {
        return 0;
    };
    let Ok(operation_id) = unsafe { CStr::from_ptr(operation_id) }.to_str() else {
        return 0;
    };
    let Some(contexts) = HOST_CONTEXTS.get() else {
        return 0;
    };
    let contexts = match contexts.try_read() {
        Ok(contexts) => contexts,
        Err(std::sync::TryLockError::WouldBlock) => return -1,
        Err(std::sync::TryLockError::Poisoned(_)) => return 0,
    };
    let Some(record) = contexts
        .get(&host_context_id)
        .filter(|record| record.claimed)
    else {
        return 0;
    };
    let Some(grant) = record.runtime_extension_leases.get(&lease) else {
        return 0;
    };
    if grant.runtime_nonce != runtime_nonce
        || grant.extension_generation != extension_generation
        || grant.extension_id.as_str() != extension_id
        || grant.operation_id.as_str() != operation_id
    {
        return 0;
    }
    match record.try_runtime_extension_lease_is_current(lease) {
        super::RuntimeExtensionLeaseStatus::Current => 1,
        super::RuntimeExtensionLeaseStatus::Stale => 0,
        super::RuntimeExtensionLeaseStatus::Busy => -1,
    }
}

/// Recheck an admitted runtime-extension completion on the runtime owner.
///
/// Producer admission uses the try-lock ABI above and must return immediately
/// on contention. Once a completion is in the owner queue, transient Host lock
/// contention is not revocation and must not silently discard an accepted
/// callback, so this delivery-side check waits for the exact context and typed
/// generation snapshots before deciding current versus stale.
///
/// Lock invariant: the caller is the runtime owner; while the Host-context
/// read guard is held this function performs only context-local lease lookup
/// and immutable Host policy/generation comparison. It invokes no extension
/// provider, external callback, worker, runtime drive, or effectful Host API.
/// No producer or other cross-thread SDK path calls this entry point.
///
/// # Safety
///
/// String pointers must address readable NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn ex_host_check_runtime_extension_lease_binding_owner_v1(
    host_context_id: u64,
    lease: u64,
    runtime_nonce: u64,
    extension_generation: u64,
    extension_id: *const c_char,
    operation_id: *const c_char,
) -> i32 {
    if host_context_id == 0
        || lease == 0
        || runtime_nonce == 0
        || extension_generation == 0
        || extension_id.is_null()
        || operation_id.is_null()
    {
        return 0;
    }
    let Ok(extension_id) = unsafe { CStr::from_ptr(extension_id) }.to_str() else {
        return 0;
    };
    let Ok(operation_id) = unsafe { CStr::from_ptr(operation_id) }.to_str() else {
        return 0;
    };
    let Some(contexts) = HOST_CONTEXTS.get() else {
        return 0;
    };
    let Ok(contexts) = contexts.read() else {
        return 0;
    };
    let Some(record) = contexts
        .get(&host_context_id)
        .filter(|record| record.claimed)
    else {
        return 0;
    };
    let Some(grant) = record.runtime_extension_leases.get(&lease) else {
        return 0;
    };
    if grant.runtime_nonce != runtime_nonce
        || grant.extension_generation != extension_generation
        || grant.extension_id.as_str() != extension_id
        || grant.operation_id.as_str() != operation_id
    {
        return 0;
    }
    i32::from(record.runtime_extension_lease_is_current(lease))
}

/// Revoke a context-local runtime-extension operation lease. A stale, forged,
/// or cross-context token returns 0.
#[no_mangle]
pub extern "C" fn ex_host_revoke_runtime_extension_lease_v1(
    host_context_id: u64,
    lease: u64,
) -> i32 {
    if host_context_id == 0 || lease == 0 {
        return 0;
    }
    HOST_CONTEXTS
        .get()
        .and_then(|contexts| contexts.write().ok())
        .and_then(|mut contexts| {
            contexts
                .get_mut(&host_context_id)
                .filter(|record| record.claimed)?
                .runtime_extension_leases
                .remove(&lease)
                .map(|_| 1)
        })
        .unwrap_or(0)
}

/// Irreversibly consume the active armed Host's evaluator-owned bootstrap
/// authority token. Returns 1 only for the single live-to-sealed transition;
/// absent, unarmed, poisoned, and already-sealed contexts return 0.
/// @ref LLP 0029#4-compiled-mode-authority — seal before application evaluation
#[no_mangle]
pub extern "C" fn ex_host_seal_bootstrap_phase() -> i32 {
    with_host(
        |host| i32::from(host.seal_bootstrap_phase() == Some(true)),
        0,
    )
}

/// Evaluate a complete typed decision set against the installed immutable
/// context. Returns a heap-owned JSON decision/evidence envelope; malformed
/// input, missing arming, and semantic errors return an `error` envelope and
/// must be treated as denial by the caller.
/// @ref LLP 0021#decision-staging-and-principal-semantics
///
/// The public JSON ingress discards and recomputes every scoped target-cell
/// value before evaluation; this C ABI never authorizes the serialized
/// disposition supplied by its caller.
/// @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — F1c/F3a ABI
/// ingress authority.
///
/// # Safety
///
/// Non-null pointers must reference their declared byte lengths for the
/// duration of this call. The returned string is owned by the caller and must
/// be released with `ex_host_free_string`.
#[no_mangle]
pub unsafe extern "C" fn ex_host_evaluate_typed_decision(
    decision_set: *const u8,
    decision_set_len: usize,
    gates: *const u8,
    gates_len: usize,
) -> *mut c_char {
    if decision_set.is_null() || gates.is_null() {
        return as_json_cstring(&json!({"error": "null typed decision input"}));
    }
    let decision_set = unsafe { std::slice::from_raw_parts(decision_set, decision_set_len) };
    let gates = unsafe { std::slice::from_raw_parts(gates, gates_len) };
    let result = with_host(
        |host| match host.evaluate_typed_decision_json_with_evidence(decision_set, gates) {
            Ok(result) => as_json_cstring(&json!({
                "decision": result.decision,
                "evidence": result.evidence,
            })),
            Err(error) => as_json_cstring(&json!({"error": error.to_string()})),
        },
        std::ptr::null_mut(),
    );
    if result.is_null() {
        as_json_cstring(&json!({"error": "host is not installed"}))
    } else {
        result
    }
}

fn authorize_typed_lifecycle(
    host: &Host,
    actor: u64,
    module_ids: &[u64],
    disposition: capsec_semantics::model::LifecycleDisposition,
    operation_key: &str,
    coverage_edge_id: &str,
) -> bool {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::Stage;

    let Some(principals) = module_ids
        .iter()
        .map(|id| host.typed_principal_for_module(&id.to_string()))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let Ok(principals) = capsec_semantics::model::canonicalize_principal_set(principals) else {
        return false;
    };
    for stage in [Stage::Requested, Stage::Commit] {
        let decision = host.authorize_typed_lifecycle_stage(
            &actor.to_string(),
            operation_key,
            coverage_edge_id,
            principals.clone(),
            disposition,
            stage,
        );
        if !matches!(decision, Ok(decision) if decision.outcome == DecisionOutcome::Allow) {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleExitSurface {
    ProcessExit,
    ExactExit,
}

impl LifecycleExitSurface {
    fn from_abi(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::ProcessExit),
            2 => Some(Self::ExactExit),
            _ => None,
        }
    }

    fn operation_key(self) -> &'static str {
        match self {
            Self::ProcessExit => "lifecycle-process-exit-request",
            Self::ExactExit => "lifecycle-exact-exit-request",
        }
    }

    fn coverage_edge_id(self) -> Option<&'static str> {
        match self {
            Self::ProcessExit => {
                super::generated_coverage_edge_id("native-op", "global:process.exit")
            }
            Self::ExactExit => super::generated_coverage_edge_id("native-op", "__exactExit"),
        }
    }
}

#[cold]
fn park_after_acknowledged_worker_lifecycle_commit() -> ! {
    // The supervisor owns teardown. An unpark or spurious wake cannot return
    // control to the engine frame that requested exit.
    loop {
        std::thread::park();
    }
}

#[cold]
fn terminate_unacknowledged_worker_lifecycle_commit() -> ! {
    let status = crate::session_constants::EXIT_STATUS_WORKER_COMMIT_UNACKNOWLEDGED;
    #[cfg(unix)]
    unsafe {
        libc::_exit(status)
    }
    #[cfg(not(unix))]
    std::process::exit(status)
}

/// Hand an authorized, idempotent record to the authenticated supervisor
/// channel. The callback returns only after the acknowledgement exchange; an
/// acknowledgement parks this engine thread forever, while every other result
/// takes LLP 0025's reserved worker-fatal disposition.
// @ref LLP 0025#8-exit-and-lifecycle — the authenticated worker commits and is
// acknowledged before parking; it never takes the in-process teardown path.
fn commit_worker_lifecycle_and_park(
    port: Arc<AuthenticatedWorkerLifecyclePort>,
    commit: AuthorizedWorkerLifecycleCommit,
) -> ! {
    match port.commit_lifecycle(commit) {
        WorkerLifecycleAcknowledgement::Acknowledged => {
            park_after_acknowledged_worker_lifecycle_commit()
        }
        WorkerLifecycleAcknowledgement::Unacknowledged => {
            terminate_unacknowledged_worker_lifecycle_commit()
        }
    }
}

/// Authorize a cooperative exit request against the authenticated live frame
/// set. The code is deliberately not a selector dimension: all normalized
/// i32 exit statuses exercise the same exact exit-request disposition.
/// Returns 1 only for a fully staged typed allow; every other state denies.
// @ref LLP 0025#8-exit-and-lifecycle — package, missing, ambiguous, and mixed
// attribution all deny before the native runtime records an exit request.
///
/// # Safety
/// `module_ids` must reference `module_ids_len` u64 values for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_lifecycle_exit_stack(
    actor: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    surface: u32,
    requested_code: i32,
    has_requested_code: u32,
    out_code: *mut i32,
) -> i32 {
    if module_ids.is_null()
        || out_code.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || has_requested_code > 1
    {
        return 0;
    }
    let Some(surface) = LifecycleExitSurface::from_abi(surface) else {
        return 0;
    };
    let Some(coverage_edge_id) = surface.coverage_edge_id() else {
        return 0;
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let effective_code = if has_requested_code == 1 {
                requested_code
            } else {
                host.lifecycle_exit_code()
            };
            if !authorize_typed_lifecycle(
                host,
                actor,
                module_ids,
                capsec_semantics::model::LifecycleDisposition::ExitRequest,
                surface.operation_key(),
                coverage_edge_id,
            ) {
                return 0;
            }
            let worker_port = match authenticated_worker_lifecycle_port() {
                Ok(port) => port,
                // An indeterminate scoped port cannot safely fall through to
                // the in-process lifecycle realization.
                Err(_) => return 0,
            };
            let lifecycle = host.session_lifecycle();
            let request = match lifecycle.request_exit(
                crate::session_lifecycle::LifecyclePrincipal::Root,
                effective_code,
            ) {
                crate::session_lifecycle::LifecycleRequestDisposition::Accepted { request } => {
                    request
                }
                crate::session_lifecycle::LifecycleRequestDisposition::AlreadyInProgress => {
                    let Some(request) = lifecycle.latched_request() else {
                        return 0;
                    };
                    request
                }
                crate::session_lifecycle::LifecycleRequestDisposition::Denied => return 0,
            };
            if let Some(worker_port) = worker_port {
                commit_worker_lifecycle_and_park(
                    worker_port,
                    AuthorizedWorkerLifecycleCommit {
                        request_id: request.request_id,
                        status: request.status,
                    },
                );
            }
            unsafe { out_code.write(request.status) };
            1
        },
        0,
    )
}

/// Authorize and return the supervisor-authoritative orderly-exit code.
/// `out_code` is untouched on denial.
///
/// # Safety
/// Pointer arguments must remain valid for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_lifecycle_exit_code_get_stack(
    actor: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    out_code: *mut i32,
) -> i32 {
    if module_ids.is_null() || out_code.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return 0;
    }
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let Some(edge) =
                super::generated_coverage_edge_id("native-op", "global:process.exitCode")
            else {
                return 0;
            };
            if !authorize_typed_lifecycle(
                host,
                actor,
                module_ids,
                capsec_semantics::model::LifecycleDisposition::ExitCodeGet,
                "lifecycle-exit-code-get",
                edge,
            ) {
                return 0;
            }
            let crate::session_lifecycle::LifecycleGetDisposition::Value(code) = host
                .session_lifecycle()
                .get_exit_code(crate::session_lifecycle::LifecyclePrincipal::Root)
            else {
                return 0;
            };
            unsafe { out_code.write(code) };
            1
        },
        0,
    )
}

/// Authorize and synchronously mirror the orderly-exit code before returning
/// to JavaScript. Returns 1 only after the atomic store has completed.
///
/// # Safety
/// `module_ids` must reference `module_ids_len` u64 values for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_lifecycle_exit_code_set_stack(
    actor: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    code: i32,
) -> i32 {
    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return 0;
    }
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let Some(edge) =
                super::generated_coverage_edge_id("native-op", "global:process.exitCode")
            else {
                return 0;
            };
            if !authorize_typed_lifecycle(
                host,
                actor,
                module_ids,
                capsec_semantics::model::LifecycleDisposition::ExitCodeSet,
                "lifecycle-exit-code-set",
                edge,
            ) {
                return 0;
            }
            let worker_port = match authenticated_worker_lifecycle_port() {
                Ok(port) => port,
                // Never reinterpret an indeterminate worker bridge as an
                // in-process Host mutation.
                Err(_) => return 0,
            };
            let lifecycle = host.session_lifecycle();
            let disposition = if let Some(worker_port) = worker_port {
                lifecycle.set_exit_code_with_synchronous_mirror(
                    crate::session_lifecycle::LifecyclePrincipal::Root,
                    code,
                    |status| {
                        worker_port.mirror_exit_code(AuthorizedWorkerExitCodeMirror { status })
                            == WorkerLifecycleAcknowledgement::Acknowledged
                    },
                )
            } else {
                lifecycle.set_exit_code(crate::session_lifecycle::LifecyclePrincipal::Root, code)
            };
            i32::from(matches!(
                disposition,
                crate::session_lifecycle::LifecycleSetDisposition::Accepted { .. }
            ))
        },
        0,
    )
}

/// Authorize one stage of the native `fs.open` branch against authenticated
/// logical roots, a retained parent directory, and the actual descriptor.
/// Returns one stable `EX_HOST_VFS_RESULT_*` discriminant. The runtime nonce is
/// validated before shape so a stale/foreign generation is always tier zero.
///
/// # Safety
/// `module_ids` must reference `module_ids_len` values. `path` and an optional
/// `presented_handle_id` must be valid C strings for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_fs_stack(
    runtime_nonce: u64,
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    path: *const c_char,
    stage: u32,
    surface: u32,
    parent_fd: i32,
    fd: i32,
    needs_read: i32,
    needs_write: i32,
    presented_handle_id: *const c_char,
) -> u32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{NonEmptyString, Stage};

    let _session_lease = match runtime_vfs_session(runtime_nonce, "authorize") {
        Ok(session) => session,
        Err(_) => return EX_HOST_VFS_RESULT_STALE_SESSION,
    };
    if path.is_null()
        || module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || !matches!(stage, 0..=5)
    {
        return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
    }
    let (operation_key, coverage_edge_id) = match surface {
        0 => ("fs-open", "surface.native.op.exactfsopen.05ao6wa"),
        1 => ("fs-read-file", "surface.native.op.exactreadfile.1cmzco7"),
        2 => (
            "fs-read-file-async",
            "surface.native.op.exactfsreadfileasync.0fw3fo0",
        ),
        3 => ("fs-stat", "surface.native.op.exactstat.1432ztv"),
        4 => ("fs-readdir", "surface.native.op.exactreaddir.0tg30vk"),
        5 => ("fs-write-file", "surface.native.op.exactwritefile.1h0gy8u"),
        6 => (
            "fs-append-file",
            "surface.native.op.exactappendfile.1b1b7nn",
        ),
        7 => (
            "fs-write-file-async",
            "surface.native.op.exactfswritefileasync.0fv6zp9",
        ),
        8 => (
            "fs-stat-async",
            "surface.native.op.exactfsstatasync.0b0hr8s",
        ),
        9 => ("fs-realpath", "surface.native.op.exactrealpath.06qb6s2"),
        10 => ("fs-lstat", "surface.native.op.exactlstat.1c98s6l"),
        11 => (
            "fs-lstat-async",
            "surface.native.op.exactfsstatasync.0b0hr8s",
        ),
        12 => ("fs-mkdir", "surface.native.op.exactmkdir.021eaz0"),
        13 => ("fs-access", "surface.native.op.exactaccess.1a12cmn"),
        14 => ("fs-opendir", "surface.native.op.exactopendir.0eh7ha4"),
        15 => ("fs-readlink", "surface.native.op.exactreadlink.1p5ozx1"),
        16 => ("fs-truncate", "surface.native.op.exacttruncate.13gh223"),
        17 => ("fs-statfs", "surface.native.op.exactstatfs.151kkzo"),
        18 => ("sqlite-open", "surface.native.op.exactsqliteopen.0a20llh"),
        19 => (
            "sqlite-prepare",
            "surface.native.op.exactsqliteprepare.10ue6lk",
        ),
        20 => ("sqlite-all", "surface.native.op.exactsqliteall.0gw7b3k"),
        21 => ("sqlite-get", "surface.native.op.exactsqliteget.1ihlki3"),
        22 => ("sqlite-run", "surface.native.op.exactsqliterun.0nde0wm"),
        23 => (
            "sqlite-values",
            "surface.native.op.exactsqlitevalues.03uveqn",
        ),
        24 => ("sqlite-exec", "surface.native.op.exactsqliteexec.0oogg80"),
        // `fs-path-async` arrived independently after the closed CapSec ABI
        // had assigned 13..=24. Keep the established codes stable and give
        // the generic retained-path operation the next free discriminant.
        25 => (
            "fs-path-async",
            "surface.native.op.exactfspathasync.10cb78b",
        ),
        26 => (
            "fs-read-async",
            "surface.native.op.exactfsreadasync.0l952a6",
        ),
        27 => (
            "fs-readv-async",
            "surface.native.op.exactfsreadvasync.0bn4x60",
        ),
        28 => (
            "fs-write-async",
            "surface.native.op.exactfswriteasync.0f1ap1j",
        ),
        29 => (
            "fs-writev-async",
            "surface.native.op.exactfswritevasync.0l050fv",
        ),
        30 => (
            "fs-fsync-sync",
            "surface.native.op.exactfsfsyncsync.02nw7ns",
        ),
        31 => (
            "fs-fdatasync-sync",
            "surface.native.op.exactfsfdatasyncsync.1p6q71s",
        ),
        32 => ("fs-which", "surface.native.op.exactwhich.0it66ce"),
        _ => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
    };
    let follow_mode = if matches!(surface, 10 | 11 | 15) {
        capsec_semantics::model::FollowMode::NoFollowFinal
    } else {
        capsec_semantics::model::FollowMode::FollowFinal
    };
    let path_bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    let path = match std::str::from_utf8(path_bytes) {
        Ok(path) => std::path::PathBuf::from(path),
        Err(_) => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
    };
    let presented = if presented_handle_id.is_null() {
        Vec::new()
    } else {
        let value = match unsafe { CStr::from_ptr(presented_handle_id) }.to_str() {
            Ok(value) => value.to_owned(),
            Err(_) => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
        };
        match NonEmptyString::new(value) {
            Ok(value) => vec![value],
            Err(_) => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
        }
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let (
        stage,
        object_state,
        disclosure_only,
        parent_object,
        final_object,
        final_object_generation,
        retained_handle,
    ) = if stage == 0 {
        (
            Stage::Requested,
            // No lookup has occurred yet, so existence is not an
            // authenticated fact at the requested stage.
            // @ref LLP 0023#21-staged-authorization-identity
            capsec_semantics::model::ObjectState::Unknown,
            true,
            None,
            None,
            None,
            None,
        )
    } else if matches!(stage, 3 | 4) {
        #[cfg(unix)]
        {
            if parent_fd < 0 {
                return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
            }
            let Some(parent_object) = object_identity_for_fd(parent_fd) else {
                return EX_HOST_VFS_RESULT_STALE_IDENTITY;
            };
            let (object_state, final_object, final_object_generation) = match object_identity_at(
                parent_fd,
                &path,
                follow_mode == capsec_semantics::model::FollowMode::FollowFinal,
            ) {
                Ok(Some((identity, generation))) => (
                    capsec_semantics::model::ObjectState::Existing,
                    Some(identity),
                    Some(generation),
                ),
                Ok(None) => (
                    capsec_semantics::model::ObjectState::AbsentCreate,
                    None,
                    None,
                ),
                Err(()) => return EX_HOST_VFS_RESULT_HOST_ERROR,
            };
            (
                Stage::Discovery,
                object_state,
                stage == 3,
                Some(parent_object),
                final_object,
                final_object_generation,
                None,
            )
        }
        #[cfg(not(unix))]
        {
            return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
        }
    } else {
        if parent_fd < 0 || fd < 0 {
            return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
        }
        #[cfg(unix)]
        {
            let Some(final_object) = object_identity_for_fd(fd) else {
                return EX_HOST_VFS_RESULT_STALE_IDENTITY;
            };
            let Some(final_object_generation) = object_verification_generation_for_fd(fd) else {
                return EX_HOST_VFS_RESULT_STALE_IDENTITY;
            };
            let Some(parent_object) = object_identity_for_fd(parent_fd) else {
                return EX_HOST_VFS_RESULT_STALE_IDENTITY;
            };
            let retained = match NonEmptyString::new(format!("fd:{fd}")) {
                Ok(value) => value,
                Err(_) => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
            };
            (
                if stage == 1 {
                    Stage::Commit
                } else {
                    Stage::Repeat
                },
                capsec_semantics::model::ObjectState::Existing,
                stage == 5,
                Some(parent_object),
                Some(final_object),
                Some(final_object_generation),
                Some(retained),
            )
        }
        #[cfg(not(unix))]
        {
            return EX_HOST_VFS_RESULT_MALFORMED_INPUT;
        }
    };
    let resolved_parent_path = if stage == Stage::Requested {
        None
    } else {
        match resolved_path_for_fd(parent_fd) {
            Some(path) => Some(path),
            None => return EX_HOST_VFS_RESULT_STALE_IDENTITY,
        }
    };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return EX_HOST_VFS_RESULT_POLICY_DENIED,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return EX_HOST_VFS_RESULT_MALFORMED_INPUT,
                };
            #[cfg(unix)]
            if matches!(stage, Stage::Discovery | Stage::Commit) {
                let Some(principal) = host.typed_principal_for_module(&module_id.to_string())
                else {
                    return EX_HOST_VFS_RESULT_POLICY_DENIED;
                };
                let requested = match host.typed_logical_path(&principal, &path) {
                    Ok(requested) => requested,
                    Err(error) => {
                        eprintln!("error: typed filesystem path refused: {error}");
                        return EX_HOST_VFS_RESULT_STALE_IDENTITY;
                    }
                };
                // Opening a logical root necessarily retains its parent, which
                // is outside that root. The decision below binds the discovered
                // final object to the authenticated root object; descendants
                // still require the retained parent itself to descend from it.
                // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
                if !requested.components.is_empty() {
                    match host.validate_typed_parent_fd_ancestry(&principal, &path, parent_fd) {
                        Ok(true) => {}
                        Ok(false) => return EX_HOST_VFS_RESULT_OUTSIDE_MOUNT,
                        Err(error) => {
                            eprintln!(
                                "error: retained filesystem parent ancestry refused: {error}"
                            );
                            return EX_HOST_VFS_RESULT_STALE_IDENTITY;
                        }
                    }
                }
            }
            match host.authorize_typed_fs_open_stage(
                &module_id.to_string(),
                operation_key,
                coverage_edge_id,
                constrained_principals,
                &path,
                stage,
                object_state,
                follow_mode,
                disclosure_only,
                resolved_parent_path.as_deref(),
                needs_read != 0
                    && !(stage == Stage::Discovery
                        && object_state == capsec_semantics::model::ObjectState::AbsentCreate
                        && !disclosure_only),
                needs_write != 0,
                parent_object,
                final_object,
                final_object_generation,
                retained_handle,
                presented,
            ) {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    EX_HOST_VFS_RESULT_OK
                }
                Ok(_) => EX_HOST_VFS_RESULT_POLICY_DENIED,
                Err(error) => {
                    eprintln!("error: typed filesystem authorization refused: {error}");
                    EX_HOST_VFS_RESULT_HOST_ERROR
                }
            }
        },
        EX_HOST_VFS_RESULT_STALE_SESSION,
    )
}

/// Authorize one declared stage of a reviewed native system-information read.
/// Returns 1 for allow, 0 for deny, and -1 for malformed or unsupported input.
///
/// `surface` selects a closed native adapter/coverage-edge mapping.  The
/// `info_name` tag is consulted only by the generic cached-value gate; native
/// readers have an immutable resource kind in the table below.  This keeps
/// JavaScript from supplying action ids or coverage-edge ids as strings.
///
/// # Safety
/// `module_ids` must reference `module_ids_len` values for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_system_info_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    surface: u32,
    info_name: u32,
    stage: u32,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{Stage, SystemInfoName};

    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 || stage > 1 {
        return -1;
    }
    let decode_name = |tag| match tag {
        0 => Some(SystemInfoName::Architecture),
        1 => Some(SystemInfoName::CameraMetadata),
        2 => Some(SystemInfoName::Cpus),
        3 => Some(SystemInfoName::Cwd),
        4 => Some(SystemInfoName::Hostname),
        5 => Some(SystemInfoName::Language),
        6 => Some(SystemInfoName::LoadAverage),
        7 => Some(SystemInfoName::Locale),
        8 => Some(SystemInfoName::Memory),
        9 => Some(SystemInfoName::NetworkInterfaces),
        10 => Some(SystemInfoName::OsRelease),
        11 => Some(SystemInfoName::Platform),
        12 => Some(SystemInfoName::Screen),
        13 => Some(SystemInfoName::StoragePaths),
        14 => Some(SystemInfoName::Uptime),
        15 => Some(SystemInfoName::User),
        _ => None,
    };
    let (operation_key, coverage_edge_id, name) = match surface {
        0 => (
            "get-cpu-count",
            "surface.native.op.exactgetcpucount.1k05aty",
            SystemInfoName::Cpus,
        ),
        1 => (
            "get-free-memory",
            "surface.native.op.exactgetfreemem.0dytp7m",
            SystemInfoName::Memory,
        ),
        2 => (
            "get-hostname",
            "surface.native.op.exactgethostname.01gi6am",
            SystemInfoName::Hostname,
        ),
        3 => (
            "get-load-average",
            "surface.native.op.exactgetloadavg.10t3k2t",
            SystemInfoName::LoadAverage,
        ),
        4 => (
            "get-network-interfaces",
            "surface.native.op.exactgetnetworkinterfaces.15q8n2j",
            SystemInfoName::NetworkInterfaces,
        ),
        5 => (
            "get-total-memory",
            "surface.native.op.exactgettotalmem.0ziuv9c",
            SystemInfoName::Memory,
        ),
        6 => (
            "get-uptime",
            "surface.native.op.exactgetuptime.0ydqt27",
            SystemInfoName::Uptime,
        ),
        7 => (
            "get-user-info",
            "surface.native.op.exactgetuserinfo.027b1gs",
            SystemInfoName::User,
        ),
        8 => (
            "authorize-cached-system-info",
            "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
            match decode_name(info_name) {
                Some(name) => name,
                None => return -1,
            },
        ),
        9 => (
            "system-info-process-rss",
            "surface.native.op.exactgetprocessrss.0o50wgs",
            SystemInfoName::Memory,
        ),
        10 => (
            "system-info-cwd",
            "surface.native.op.exactgetcwd.1bhagb7",
            SystemInfoName::Cwd,
        ),
        _ => return -1,
    };
    let stage = if stage == 0 {
        Stage::Requested
    } else {
        Stage::Commit
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            match host.authorize_typed_system_info_stage(
                &module_id.to_string(),
                operation_key,
                coverage_edge_id,
                constrained_principals,
                name,
                stage,
            ) {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed system-information authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one requested/commit stage for an exact principal-overlay
/// environment read. Returns 1 allow, 0 deny, and -1 for malformed adapter
/// input.
///
/// # Safety
/// `module_ids` and `name` must reference their declared lengths for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_environment_read_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    stage: u32,
    read_surface: u32,
    name: *const u8,
    name_len: usize,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{EnvironmentName, Stage};

    if module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || name.is_null()
        || name_len == 0
        || name_len > 32_768
        || stage > 1
        || read_surface > 2
    {
        return -1;
    }
    let stage = if stage == 0 {
        Stage::Requested
    } else {
        Stage::Commit
    };
    let name = unsafe { std::slice::from_raw_parts(name, name_len) };
    let name = match std::str::from_utf8(name)
        .ok()
        .and_then(|name| EnvironmentName::new(name).ok())
    {
        Some(name) => name,
        None => return -1,
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            let decision = match read_surface {
                0 => host.authorize_typed_environment_read_stage(
                    &module_id.to_string(),
                    constrained_principals,
                    name,
                    stage,
                ),
                1 => host.authorize_typed_environment_enumeration_stage(
                    &module_id.to_string(),
                    constrained_principals,
                    name,
                    stage,
                ),
                2 => host.authorize_typed_environment_which_stage(
                    &module_id.to_string(),
                    constrained_principals,
                    name,
                    stage,
                ),
                _ => unreachable!("read_surface was validated above"),
            };
            match decision {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed environment authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one requested/commit stage for an exact principal-overlay
/// environment mutation. Returns 1 allow, 0 deny, and -1 for malformed adapter
/// input.
///
/// # Safety
/// `module_ids` and `name` must reference their declared lengths for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_environment_write_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    stage: u32,
    name: *const u8,
    name_len: usize,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{EnvironmentName, Stage};

    if module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || name.is_null()
        || name_len == 0
        || name_len > 32_768
        || stage > 1
    {
        return -1;
    }
    let stage = if stage == 0 {
        Stage::Requested
    } else {
        Stage::Commit
    };
    let name = unsafe { std::slice::from_raw_parts(name, name_len) };
    let name = match std::str::from_utf8(name)
        .ok()
        .and_then(|name| EnvironmentName::new(name).ok())
    {
        Some(name) => name,
        None => return -1,
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            match host.authorize_typed_environment_write_stage(
                &module_id.to_string(),
                constrained_principals,
                name,
                stage,
            ) {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed environment authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one stage of the direct global `print()` stdout broker write.
/// Returns 1 allow, 0 deny, and -1 for malformed adapter input.
///
/// # Safety
/// `module_ids` must reference `module_ids_len` values for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_print_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    stage: u32,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::Stage;

    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return -1;
    }
    let stage = match stage {
        0 => Stage::Requested,
        2 => Stage::Commit,
        4 => Stage::Repeat,
        _ => return -1,
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            match host.authorize_typed_print_stage(
                &module_id.to_string(),
                constrained_principals,
                stage,
            ) {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed print authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one staged fetch or raw-connect occurrence from an engine adapter.
/// Returns 1 allow, 0 deny, and -1 for malformed or unsupported input.
///
/// `network_kind` is 0/1 for HTTP/HTTPS fetch and 2..=7 for
/// TCP/TLS/UDP/WS/WSS connect. `stage` is requested, candidate,
/// commit, delivery, repeat, or cleanup as 0..=5. Candidates are a canonical
/// JSON array of IP address strings; optional strings use null pointers.
///
/// # Safety
/// All pointer/length pairs and C strings must remain valid for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_network_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    network_kind: u32,
    host: *const c_char,
    port: u16,
    stage: u32,
    candidates_json: *const c_char,
    selected_candidate: *const c_char,
    verified_peer: *const c_char,
    connection_id: *const c_char,
    redirect_index: u64,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{
        ConcreteHost, ConnectTransport, DnsName, FetchScheme, IpAddress, NonEmptyString, Port,
        SafeUint, Stage, VerifiedPeer,
    };

    if module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || host.is_null()
        || candidates_json.is_null()
        || port == 0
        || stage > 5
        || network_kind > 6
    {
        return -1;
    }
    let stage = match stage {
        0 => Stage::Requested,
        1 => Stage::Candidate,
        2 => Stage::Commit,
        3 => Stage::Delivery,
        4 => Stage::Repeat,
        5 => Stage::Cleanup,
        _ => return -1,
    };
    let host_text = unsafe { CStr::from_ptr(host) }.to_string_lossy();
    let concrete_host = match host_text.parse::<std::net::IpAddr>() {
        Ok(address) if IpAddress::new(address).to_string() == host_text => ConcreteHost::Ip {
            address: IpAddress::new(address),
        },
        Ok(_) => return -1,
        Err(_) => match DnsName::new(host_text.as_ref()) {
            Ok(name) => ConcreteHost::DnsName { name },
            Err(_) => return -1,
        },
    };
    let Some(port) = Port::new(port) else {
        return -1;
    };
    let candidates_text = unsafe { CStr::from_ptr(candidates_json) }.to_bytes();
    let candidates: Vec<IpAddress> = match std::str::from_utf8(candidates_text)
        .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))
        .and_then(capsec_semantics::strict_json::parse_strict)
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))
        }) {
        Ok(candidates) => candidates,
        Err(_) => return -1,
    };
    let parse_optional_ip = |value: *const c_char| -> Option<Option<IpAddress>> {
        if value.is_null() {
            return Some(None);
        }
        let text = unsafe { CStr::from_ptr(value) }.to_string_lossy();
        let address = text.parse::<std::net::IpAddr>().ok()?;
        (IpAddress::new(address).to_string() == text).then_some(Some(IpAddress::new(address)))
    };
    let Some(selected_candidate) = parse_optional_ip(selected_candidate) else {
        return -1;
    };
    let Some(verified_address) = parse_optional_ip(verified_peer) else {
        return -1;
    };
    let verified_peer = verified_address.map(|address| VerifiedPeer { address, port });
    let connection_id = if connection_id.is_null() {
        None
    } else {
        match NonEmptyString::new(
            unsafe { CStr::from_ptr(connection_id) }
                .to_string_lossy()
                .into_owned(),
        ) {
            Ok(value) => Some(value),
            Err(_) => return -1,
        }
    };
    let redirect_index = if redirect_index == u64::MAX {
        None
    } else {
        match SafeUint::new(redirect_index) {
            Ok(value) => Some(value),
            Err(_) => return -1,
        }
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            let result = match network_kind {
                0 | 1 => host.authorize_typed_fetch_stage(
                    &module_id.to_string(),
                    constrained_principals,
                    if network_kind == 0 {
                        FetchScheme::Http
                    } else {
                        FetchScheme::Https
                    },
                    concrete_host,
                    port,
                    stage,
                    candidates,
                    selected_candidate,
                    verified_peer,
                    connection_id,
                    redirect_index,
                ),
                2..=6 => host.authorize_typed_connect_stage(
                    &module_id.to_string(),
                    match network_kind {
                        2 | 3 => "tcp-connect",
                        4 => "udp-send",
                        5 | 6 => "websocket-connect",
                        _ => unreachable!(),
                    },
                    match network_kind {
                        2 | 3 => "surface.native.op.exacttcpconnect.1cs9rhu",
                        4 => "surface.native.op.exactudpsend.0k2gg86",
                        5 | 6 => "surface.native.op.exactwsconnect.026jz87",
                        _ => unreachable!(),
                    },
                    constrained_principals,
                    match network_kind {
                        2 => ConnectTransport::Tcp,
                        3 => ConnectTransport::Tls,
                        4 => ConnectTransport::Udp,
                        5 => ConnectTransport::Ws,
                        6 => ConnectTransport::Wss,
                        _ => unreachable!(),
                    },
                    concrete_host,
                    port,
                    stage,
                    candidates,
                    selected_candidate,
                    verified_peer,
                    connection_id,
                ),
                _ => return -1,
            };
            match result {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed network authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one staged TCP-listen occurrence from an engine adapter.
///
/// `operation_kind` is 0 for `__exactTcpListen` and 1 for
/// `__exactHttpServe`. `port == 0` denotes an ephemeral requested port.
/// Requested-stage calls omit every late fact. Commit calls provide the exact
/// bound address/port and listener id. Delivery/repeat calls additionally
/// provide the accepted peer address/port.
///
/// Returns 1 allow, 0 deny, and -1 for malformed or unsupported input.
///
/// # Safety
/// All pointer/length pairs and C strings must remain valid for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_listen_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    operation_kind: u32,
    host: *const c_char,
    port: u16,
    dual_stack: i32,
    stage: u32,
    bound_address: *const c_char,
    bound_port: u16,
    listener_id: *const c_char,
    accepted_address: *const c_char,
    accepted_port: u16,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{
        BoundEndpoint, IpAddress, ListenBind, ListenPort, ListenTransport, NonEmptyString,
        PeerClass, Port, Stage, VerifiedPeer,
    };

    if module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || host.is_null()
        || operation_kind > 1
        || !matches!(dual_stack, 0 | 1)
        || !matches!(stage, 0 | 2 | 3 | 4)
    {
        return -1;
    }
    let stage = match stage {
        0 => Stage::Requested,
        2 => Stage::Commit,
        3 => Stage::Delivery,
        4 => Stage::Repeat,
        _ => return -1,
    };
    let host_text = unsafe { CStr::from_ptr(host) }.to_string_lossy();
    let host_address = match host_text.parse::<std::net::IpAddr>() {
        Ok(address) if IpAddress::new(address).to_string() == host_text => IpAddress::new(address),
        _ => return -1,
    };
    let bind = if host_address.get().is_unspecified() {
        ListenBind::AllInterfaces
    } else {
        ListenBind::Address {
            address: host_address,
        }
    };
    let peer_classes = if host_address.get().is_loopback() {
        vec![PeerClass::Loopback]
    } else {
        // Canonical JSON string order, not enum declaration order.
        vec![
            PeerClass::CarrierGradeNat,
            PeerClass::LinkLocal,
            PeerClass::Loopback,
            PeerClass::Metadata,
            PeerClass::Multicast,
            PeerClass::Private,
            PeerClass::Public,
            PeerClass::Reserved,
            PeerClass::UniqueLocal,
            PeerClass::Unspecified,
        ]
    };
    let requested_port = if port == 0 {
        ListenPort::Ephemeral
    } else {
        let Some(value) = Port::new(port) else {
            return -1;
        };
        ListenPort::Exact { value }
    };
    let parse_ip = |value: *const c_char| -> Option<Option<IpAddress>> {
        if value.is_null() {
            return Some(None);
        }
        let text = unsafe { CStr::from_ptr(value) }.to_string_lossy();
        let address = text.parse::<std::net::IpAddr>().ok()?;
        (IpAddress::new(address).to_string() == text).then_some(Some(IpAddress::new(address)))
    };
    let Some(bound_address) = parse_ip(bound_address) else {
        return -1;
    };
    let Some(accepted_address) = parse_ip(accepted_address) else {
        return -1;
    };
    let listener_id = if listener_id.is_null() {
        None
    } else {
        match NonEmptyString::new(
            unsafe { CStr::from_ptr(listener_id) }
                .to_string_lossy()
                .into_owned(),
        ) {
            Ok(value) => Some(value),
            Err(_) => return -1,
        }
    };
    let bound_endpoints = match (bound_address, Port::new(bound_port)) {
        (Some(address), Some(port)) => Some(vec![BoundEndpoint {
            address,
            port,
            interface: None,
        }]),
        (None, None) if bound_port == 0 => None,
        _ => return -1,
    };
    let accepted_peer = match (accepted_address, Port::new(accepted_port)) {
        (Some(address), Some(port)) => Some(VerifiedPeer { address, port }),
        (None, None) if accepted_port == 0 => None,
        _ => return -1,
    };
    let late_facts_valid = match stage {
        Stage::Requested => {
            bound_endpoints.is_none() && listener_id.is_none() && accepted_peer.is_none()
        }
        Stage::Commit => {
            bound_endpoints.is_some() && listener_id.is_some() && accepted_peer.is_none()
        }
        Stage::Delivery | Stage::Repeat => {
            bound_endpoints.is_some() && listener_id.is_some() && accepted_peer.is_some()
        }
        _ => false,
    };
    if !late_facts_valid {
        return -1;
    }

    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => {
                    eprintln!(
                        "error: typed listen authorization refused: principal stack {module_ids:?} is not registered in the authenticated snapshot"
                    );
                    return -1;
                }
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            let (operation_key, coverage_edge_id) = match operation_kind {
                0 => ("tcp-listen", "surface.native.op.exacttcplisten.0mfz04n"),
                1 => ("http-serve", "surface.native.op.exacthttpserve.1eq8wio"),
                _ => return -1,
            };
            match host.authorize_typed_listen_stage(
                &module_id.to_string(),
                operation_key,
                coverage_edge_id,
                constrained_principals,
                ListenTransport::Tcp,
                bind,
                requested_port,
                dual_stack == 1,
                peer_classes,
                stage,
                bound_endpoints,
                listener_id,
                accepted_peer,
            ) {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(decision) => {
                    eprintln!(
                        "error: typed listen authorization denied: outcome={:?} evidence={:?}",
                        decision.outcome, decision.evidence
                    );
                    0
                }
                Err(error) => {
                    eprintln!("error: typed listen authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one literal-destination UDP datagram across requested, candidate,
/// and commit stages while parsing and attributing its inputs only once.
///
/// # Safety
/// Pointer arguments must remain valid for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_udp_datagram_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    host: *const c_char,
    port: u16,
    connection_id: *const c_char,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{
        ConcreteHost, ConnectTransport, IpAddress, NonEmptyString, Port, Stage, VerifiedPeer,
    };

    if module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || host.is_null()
        || connection_id.is_null()
        || port == 0
    {
        return -1;
    }
    let host_text = unsafe { CStr::from_ptr(host) }.to_string_lossy();
    let address = match host_text.parse::<std::net::IpAddr>() {
        Ok(address) if IpAddress::new(address).to_string() == host_text => IpAddress::new(address),
        _ => return -1,
    };
    let Some(port) = Port::new(port) else {
        return -1;
    };
    let connection_id = match NonEmptyString::new(
        unsafe { CStr::from_ptr(connection_id) }
            .to_string_lossy()
            .into_owned(),
    ) {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let mut constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            constrained_principals
                .sort_by_key(|principal| principal.canonical_sort_key().unwrap_or_default());
            constrained_principals.dedup();
            let requested = ConcreteHost::Ip { address };
            for stage in [Stage::Requested, Stage::Candidate, Stage::Commit] {
                let selected = (stage != Stage::Requested).then_some(address);
                let verified = (stage == Stage::Commit).then_some(VerifiedPeer { address, port });
                let committed_id = (stage == Stage::Commit).then_some(connection_id.clone());
                let result = host.authorize_typed_connect_stage(
                    &module_id.to_string(),
                    "udp-send",
                    "surface.native.op.exactudpsend.0k2gg86",
                    constrained_principals.clone(),
                    ConnectTransport::Udp,
                    requested.clone(),
                    port,
                    stage,
                    vec![address],
                    selected,
                    verified,
                    committed_id,
                );
                match result {
                    Ok(decision)
                        if matches!(
                            decision.outcome,
                            DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                        ) => {}
                    Ok(_) => return 0,
                    Err(error) => {
                        eprintln!("error: typed UDP authorization refused: {error}");
                        return -1;
                    }
                }
            }
            1
        },
        -1,
    )
}

#[cfg(unix)]
fn object_identity_for_fd(fd: i32) -> Option<capsec_semantics::model::ObjectIdentity> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    object_identity_from_stat(&unsafe { stat.assume_init() })
}

#[cfg(unix)]
// @ref LLP 0023#42-authenticated-package-source-is-immutable — commit-stage
// object evidence carries the same generation primitive used by arming.
fn object_verification_generation_for_fd(
    fd: i32,
) -> Option<capsec_semantics::model::NonEmptyString> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    object_verification_generation_from_stat(&unsafe { stat.assume_init() })
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
fn resolved_path_for_fd(fd: i32) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    if unsafe { libc::fcntl(fd, libc::F_GETPATH, buffer.as_mut_ptr()) } != 0 {
        return None;
    }
    let length = buffer.iter().position(|byte| *byte == 0)?;
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        &buffer[..length],
    )))
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "tvos"))
))]
fn resolved_path_for_fd(fd: i32) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

#[cfg(not(unix))]
fn resolved_path_for_fd(_fd: i32) -> Option<std::path::PathBuf> {
    None
}

#[cfg(unix)]
fn object_identity_at(
    parent_fd: i32,
    path: &std::path::Path,
    follow_final: bool,
) -> Result<
    Option<(
        capsec_semantics::model::ObjectIdentity,
        capsec_semantics::model::NonEmptyString,
    )>,
    (),
> {
    use std::os::unix::ffi::OsStrExt;
    let name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("."));
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| ())?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let flags = if follow_final {
        0
    } else {
        libc::AT_SYMLINK_NOFOLLOW
    };
    if unsafe { libc::fstatat(parent_fd, name.as_ptr(), stat.as_mut_ptr(), flags) } == 0 {
        let stat = unsafe { stat.assume_init() };
        let identity = object_identity_from_stat(&stat).ok_or(())?;
        let generation = object_verification_generation_from_stat(&stat).ok_or(())?;
        return Ok(Some((identity, generation)));
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOENT) => Ok(None),
        _ => Err(()),
    }
}

#[cfg(unix)]
fn object_verification_generation_from_stat(
    stat: &libc::stat,
) -> Option<capsec_semantics::model::NonEmptyString> {
    use capsec_semantics::model::NonEmptyString;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    {
        // Apple documents st_gen as super-user-only. Zero is therefore not a
        // usable generation for ordinary armed execution; the inventory keeps
        // the original object alive with a Host-lifetime descriptor instead.
        // @ref LLP 0023#42-authenticated-package-source-is-immutable
        if stat.st_gen != 0 {
            return NonEmptyString::new(format!("apple-st-gen:{}", stat.st_gen)).ok();
        }
        NonEmptyString::new("retained-descriptor-v1").ok()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    {
        let _ = stat;
        NonEmptyString::new("retained-descriptor-v1").ok()
    }
}

#[cfg(unix)]
fn object_identity_from_stat(stat: &libc::stat) -> Option<capsec_semantics::model::ObjectIdentity> {
    object_identity(stat.st_dev as u64, stat.st_ino)
}

#[cfg(unix)]
fn object_identity(dev: u64, ino: u64) -> Option<capsec_semantics::model::ObjectIdentity> {
    use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
    Some(ObjectIdentity {
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
        volume: NonEmptyString::new(format!("dev:{dev}")).ok()?,
        file: NonEmptyString::new(format!("ino:{ino}")).ok()?,
    })
}

/// Publish a ceiling-bounded typed dynamic grant. Returns 1 when applied, 0
/// for an idempotent duplicate, and -1 on malformed/forbidden input.
///
/// # Safety
///
/// `request` must reference `request_len` readable bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_dynamic_grant(
    module_id: u64,
    request: *const u8,
    request_len: usize,
) -> i32 {
    if request.is_null() {
        return -1;
    }
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    let result = with_host(
        |host| match host.typed_principal_for_module(&module_id.to_string()) {
            Some(principal) => {
                match host.grant_typed_dynamic_json_for_principal(principal, request) {
                    Ok(applied) => i32::from(applied),
                    Err(error) => {
                        eprintln!("error: typed dynamic grant refused: {error}");
                        -1
                    }
                }
            }
            None => {
                eprintln!("error: typed dynamic grant refused: unknown executing principal");
                -1
            }
        },
        -1,
    );
    if result == 1 {
        notify_runtime_authority_change();
    }
    result
}

/// Revoke a typed dynamic grant by its JSON string ID. Returns 1 when removed,
/// 0 when absent, and -1 on malformed input.
///
/// # Safety
///
/// `request` must reference `request_len` readable bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_dynamic_revoke(
    module_id: u64,
    request: *const u8,
    request_len: usize,
) -> i32 {
    if request.is_null() {
        return -1;
    }
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    let result = with_host(
        |host| match host.typed_principal_for_module(&module_id.to_string()) {
            Some(principal) => {
                match host.revoke_typed_dynamic_json_for_principal(&principal, request) {
                    Ok(removed) => i32::from(removed),
                    Err(error) => {
                        eprintln!("error: typed dynamic revocation refused: {error}");
                        -1
                    }
                }
            }
            None => {
                eprintln!("error: typed dynamic revocation refused: unknown executing principal");
                -1
            }
        },
        -1,
    );
    if result == 1 {
        notify_runtime_authority_change();
    }
    result
}

/// Mint or re-attenuate an unguessable typed bearer handle. Returns a
/// heap-owned JSON `handleId` or `error` envelope.
///
/// # Safety
///
/// `request` must reference `request_len` readable bytes for this call. Free
/// the returned string with `ex_host_free_string`.
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_handle_mint(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    request: *const u8,
    request_len: usize,
) -> *mut c_char {
    if request.is_null() || module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return as_json_cstring(&json!({"error": "null typed handle request"}));
    }
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let result = with_host(
        |host| {
            let Some(actor) = host.typed_principal_for_module(&module_id.to_string()) else {
                return as_json_cstring(&json!({"error": "authenticated handle actor is unknown"}));
            };
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => {
                    return as_json_cstring(
                        &json!({"error": "constrained handle principal is unknown"}),
                    )
                }
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(error) => {
                        return as_json_cstring(&json!({"error": error.to_string()}));
                    }
                };
            match host.mint_typed_handle_json_for_actor(actor, constrained_principals, request) {
                Ok(handle_id) => {
                    notify_runtime_authority_change();
                    as_json_cstring(&json!({"handleId": handle_id.as_str()}))
                }
                Err(error) => as_json_cstring(&json!({"error": error.to_string()})),
            }
        },
        std::ptr::null_mut(),
    );
    if result.is_null() {
        as_json_cstring(&json!({"error": "host is not installed"}))
    } else {
        result
    }
}

/// Revoke a typed bearer handle and all descendants by JSON string ID.
/// Returns 1 when removed, 0 when absent, and -1 on malformed input.
///
/// # Safety
///
/// `request` must reference `request_len` readable bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_handle_revoke(
    module_id: u64,
    request: *const u8,
    request_len: usize,
) -> i32 {
    if request.is_null() {
        return -1;
    }
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    let result = with_host(
        |host| {
            let Some(actor) = host.typed_principal_for_module(&module_id.to_string()) else {
                return -1;
            };
            match host.revoke_typed_handle_json_for_actor(&actor, request) {
                Ok(removed) => i32::from(removed),
                Err(error) => {
                    eprintln!("error: typed handle revocation refused: {error}");
                    -1
                }
            }
        },
        -1,
    );
    if result == 1 {
        notify_runtime_authority_change();
    }
    result
}

/// Copy the current authenticated authority generations into caller-owned
/// outputs. Returns 1 for an armed host and 0 otherwise.
///
/// # Safety
/// All output pointers must be non-null and writable.
/// @abi-output ex_host_typed_generations negative role=output kind=scalar ownership=caller-storage
/// @abi-output ex_host_typed_generations dynamic role=output kind=scalar ownership=caller-storage
/// @abi-output ex_host_typed_generations handle role=output kind=scalar ownership=caller-storage
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_generations(
    negative: *mut u64,
    dynamic: *mut u64,
    handle: *mut u64,
) -> i32 {
    if negative.is_null() || dynamic.is_null() || handle.is_null() {
        return 0;
    }
    let Some(generations) = with_host(|host| host.typed_generations(), None) else {
        return 0;
    };
    unsafe {
        *negative = generations.negative.get();
        *dynamic = generations.dynamic.get();
        *handle = generations.handle.get();
    }
    1
}

fn notify_runtime_authority_change() {
    unsafe extern "C" {
        fn ex_hermes_notify_callback();
    }
    unsafe { ex_hermes_notify_callback() };
}

/// Returns 1 if the host is in Legacy (allow-all) mode, 0 otherwise.
/// Used by the C++ bridge to skip expensive capability checks.
#[no_mangle]
pub extern "C" fn ex_host_is_allow_all() -> i32 {
    with_host(|host| if host.is_allow_all() { 1 } else { 0 }, 0)
}

#[no_mangle]
pub extern "C" fn ex_host_is_armed() -> i32 {
    // `insecure` reports unarmed so the ~46 native `ex_host_is_armed()` gates
    // (fetch, net, http, sqlite, process, fs) take their diagnostic branch
    // instead of refusing. Those branches fall back to the legacy capability
    // check, which the same feature makes permissive — so this is the single
    // point that opens the natively-gated families.
    // @ref LLP 0038#fully-open-mode-insecure
    if cfg!(feature = "insecure") {
        return 0;
    }
    with_host(|host| i32::from(host.armed_snapshot().is_some()), 0)
}

/// Return the immutable, digest-bound compatibility controls for the active
/// armed Host. Bits: 0 = Bun facade, 1 = compat fixture mode, 2 = Bun fixture
/// section, 3 = dev-served module table. These controls affect trusted
/// compatibility shape only; they are never projected into `process.env` and
/// grant no external authority.
#[no_mangle]
pub extern "C" fn ex_host_armed_bootstrap_compatibility_flags() -> u32 {
    with_host(
        |host| {
            let Some(snapshot) = host.armed_snapshot() else {
                return 0;
            };
            snapshot
                .bootstrap_compatibility_modes()
                .iter()
                .fold(0_u32, |flags, mode| {
                    flags
                        | match mode.as_str() {
                            "bun" => 1,
                            "fixture" => 2,
                            "fixture:bun" => 4,
                            "dev-served" => 8,
                            _ => 0,
                        }
                })
        },
        0,
    )
}

/// Return the authenticated snapshot endowments for the active Host context as
/// a strict JSON array of `{locator,endowments}` rows. Bootstrap consumes and
/// frees this copy; no process-global environment channel or delimiter parser
/// participates in production authority.
/// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
#[no_mangle]
pub extern "C" fn ex_host_armed_endowments() -> *mut c_char {
    let projection = with_host(
        |host| {
            host.armed_snapshot().map_or(Ok(None), |snapshot| {
                snapshot.compartment_endowments_json().map(Some)
            })
        },
        Ok(None),
    );
    let Ok(Some(projection)) = projection else {
        return ptr::null_mut();
    };
    CString::new(projection)
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

/// Return the current legacy capability-decision generation. Zero means no
/// host is installed and therefore cannot validate a retained-resource lease.
#[no_mangle]
pub extern "C" fn ex_host_legacy_authorization_generation() -> u64 {
    with_host(Host::legacy_authorization_generation, 0)
}

/// Only enforce-mode allows may be memoized. Audit would-denies deliberately
/// proceed but must still append evidence on every occurrence.
#[no_mangle]
pub extern "C" fn ex_host_legacy_authorization_cacheable() -> i32 {
    with_host(|host| i32::from(host.legacy_authorization_cacheable()), 0)
}

/// Read an entire file into a heap-allocated buffer in a single call.
/// Returns null on error. Caller must free with `ex_host_free_buffer`.
#[no_mangle]
pub extern "C" fn ex_host_fs_read_file(
    path: *const c_char,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> *mut u8 {
    if path.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            let errno_code = normalized_io_error_code(&err);
            record_fs_error(errno_code);
            unsafe {
                *out_len = 0;
                if !out_errno.is_null() {
                    *out_errno = errno_code;
                }
            }
            return ptr::null_mut();
        }
    };

    let mut data = Vec::new();
    match std::io::Read::read_to_end(&mut file, &mut data) {
        Ok(_) => {
            let boxed = data.into_boxed_slice();
            // Report the true allocation length. `usize as u64` is lossless on all
            // supported targets; the C++ caller passes this exact value back to
            // `ex_host_free_buffer`, so the reconstructed slice layout matches the
            // allocation. Truncating to u32 here corrupted the free layout and
            // silently short-read files >= 4 GiB.
            let len = boxed.len();
            unsafe { *out_len = len as u64 };
            Box::into_raw(boxed) as *mut u8
        }
        Err(err) => {
            let errno_code = normalized_io_error_code(&err);
            record_fs_error(errno_code);
            unsafe {
                *out_len = 0;
                if !out_errno.is_null() {
                    *out_errno = errno_code;
                }
            }
            ptr::null_mut()
        }
    }
}

/// Free a buffer returned by `ex_host_fs_read_file`.
#[no_mangle]
pub extern "C" fn ex_host_free_buffer(buf: *mut u8, len: u64) {
    if !buf.is_null() && len > 0 {
        unsafe {
            let raw = ptr::slice_from_raw_parts_mut(buf, len as usize);
            drop(Box::from_raw(raw));
        }
    }
}

/// A u64 principal id rendered to its decimal-string form in a fixed inline
/// buffer. The capability manager keys principals by decimal string; the check
/// FFI entry points run on the enforce/audit hot path (every gated syscall), so
/// they must not heap-allocate a `String` per call just to perform a lookup —
/// the string form is only materialized on the heap where audit rendering
/// actually records it (a would-deny). (ENG-22644)
#[derive(Clone, Copy)]
struct PrincipalIdBuf {
    buf: [u8; 20],
    start: usize,
}

impl PrincipalIdBuf {
    const EMPTY: PrincipalIdBuf = PrincipalIdBuf {
        buf: [b'0'; 20],
        start: 20,
    };

    fn new(mut value: u64) -> Self {
        let mut buf = [b'0'; 20];
        let mut start = 20;
        loop {
            start -= 1;
            buf[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        PrincipalIdBuf { buf, start }
    }

    fn as_str(&self) -> &str {
        // The buffer holds only ASCII digits.
        std::str::from_utf8(&self.buf[self.start..]).unwrap_or("0")
    }
}

/// Render a principal-id stack to the decimal-string forms the capability
/// manager keys on, without per-call heap allocation for the common case.
/// Stacks carry DISTINCT principals (one per package on the call chain), so
/// almost every real stack fits the inline capacity; deeper stacks fall back
/// to a heap rendering. (ENG-22644)
fn with_rendered_principal_stack<R>(ids: &[u64], f: impl FnOnce(&[&str]) -> R) -> R {
    const INLINE_STACK_PRINCIPALS: usize = 16;
    if ids.len() <= INLINE_STACK_PRINCIPALS {
        let mut bufs = [PrincipalIdBuf::EMPTY; INLINE_STACK_PRINCIPALS];
        for (slot, id) in bufs.iter_mut().zip(ids.iter()) {
            *slot = PrincipalIdBuf::new(*id);
        }
        let mut refs: [&str; INLINE_STACK_PRINCIPALS] = [""; INLINE_STACK_PRINCIPALS];
        for (slot, buf) in refs.iter_mut().zip(bufs.iter()).take(ids.len()) {
            *slot = buf.as_str();
        }
        f(&refs[..ids.len()])
    } else {
        let strings: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        f(&refs)
    }
}

#[no_mangle]
pub extern "C" fn ex_host_check_capability(module_id: u64, capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }

    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();

    #[cfg(feature = "capsec-simulator-performance-observer")]
    if simulator_performance_observer_allows_legacy_fetch(&[module_id], &cap) {
        return 1;
    }

    let module = PrincipalIdBuf::new(module_id);
    let allowed = with_host(|host| host.check_capability(module.as_str(), &cap), false);
    if allowed {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn ex_host_check_capability_no_follow_final(
    module_id: u64,
    capability: *const c_char,
) -> i32 {
    if capability.is_null() {
        return 0;
    }

    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();

    let module = PrincipalIdBuf::new(module_id);
    let allowed = with_host(
        |host| host.check_capability_no_follow_final(module.as_str(), &cap),
        false,
    );
    if allowed {
        1
    } else {
        0
    }
}

/// Handle minting is stricter than ordinary root operations: the caller must
/// have an explicit grant for the exact capability carried by the handle, so an
/// ambient trusted root operation cannot mint a passable subtree token.
#[no_mangle]
pub extern "C" fn ex_host_check_handle_mint(module_id: u64, capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }

    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();

    let module = PrincipalIdBuf::new(module_id);
    let allowed = with_host(|host| host.check_handle_mint(module.as_str(), &cap), false);
    if allowed {
        1
    } else {
        0
    }
}

/// Stack-intersection capability check for deputy-sensitive classes (Phase 5).
/// `module_ids` is the distinct principal stack, innermost-first, from
/// frame-derived attribution; the effective grant is the AND over the stack for
/// configured deputy classes, and the normal top-principal check otherwise.
/// @ref LLP 0013#phase-5
#[no_mangle]
pub extern "C" fn ex_host_check_capability_stack(
    module_ids: *const u64,
    len: usize,
    capability: *const c_char,
) -> i32 {
    if capability.is_null() || module_ids.is_null() || len == 0 {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();
    let ids = unsafe { std::slice::from_raw_parts(module_ids, len) };
    #[cfg(feature = "capsec-simulator-performance-observer")]
    if simulator_performance_observer_allows_legacy_fetch(ids, &cap) {
        return 1;
    }
    // Render each numeric principal to the decimal-string form the manager keys
    // on (matching ex_host_check_capability's single-principal conversion),
    // using inline stack buffers instead of a per-call Vec<String>. (ENG-22644)
    let allowed = with_rendered_principal_stack(ids, |stack_refs| {
        with_host(|host| host.check_capability_stack(stack_refs, &cap), false)
    });
    if allowed {
        1
    } else {
        0
    }
}

#[cfg(feature = "capsec-simulator-performance-observer")]
fn simulator_performance_observer_allows_legacy_fetch(
    principal_ids: &[u64],
    capability: &str,
) -> bool {
    simulator_performance_observer_matches_root_loopback_fetch(principal_ids, capability)
        && with_host(|host| host.armed_snapshot().is_some(), false)
}

#[cfg(feature = "capsec-simulator-performance-observer")]
fn simulator_performance_observer_matches_root_loopback_fetch(
    principal_ids: &[u64],
    capability: &str,
) -> bool {
    principal_ids == [0] && capability == "network:fetch:127.0.0.1"
}

#[no_mangle]
pub extern "C" fn ex_host_check_capability_stack_no_follow_final(
    module_ids: *const u64,
    len: usize,
    capability: *const c_char,
) -> i32 {
    if capability.is_null() || module_ids.is_null() || len == 0 {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();
    let ids = unsafe { std::slice::from_raw_parts(module_ids, len) };
    let allowed = with_rendered_principal_stack(ids, |stack_refs| {
        with_host(
            |host| host.check_capability_stack_no_follow_final(stack_refs, &cap),
            false,
        )
    });
    if allowed {
        1
    } else {
        0
    }
}

/// Complete intersection for an authenticated async-continuation carrier.
/// This is intentionally distinct from `ex_host_check_capability_stack`:
/// ordinary synchronous stacks retain LLP 0013's opt-in deputy-class
/// semantics, while every Promise/native-completion carrier member is a
/// mandatory authority constraint.
#[no_mangle]
pub extern "C" fn ex_host_check_capability_constrained_stack(
    module_ids: *const u64,
    len: usize,
    capability: *const c_char,
) -> i32 {
    if capability.is_null() || module_ids.is_null() || len == 0 {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();
    let ids = unsafe { std::slice::from_raw_parts(module_ids, len) };
    let allowed = with_rendered_principal_stack(ids, |stack_refs| {
        with_host(
            |host| host.check_capability_constrained_stack(stack_refs, &cap),
            false,
        )
    });
    i32::from(allowed)
}

#[no_mangle]
pub extern "C" fn ex_host_check_capability_constrained_stack_no_follow_final(
    module_ids: *const u64,
    len: usize,
    capability: *const c_char,
) -> i32 {
    if capability.is_null() || module_ids.is_null() || len == 0 {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();
    let ids = unsafe { std::slice::from_raw_parts(module_ids, len) };
    let allowed = with_rendered_principal_stack(ids, |stack_refs| {
        with_host(
            |host| host.check_capability_constrained_stack_no_follow_final(stack_refs, &cap),
            false,
        )
    });
    i32::from(allowed)
}

/// Whether any deputy capability classes are configured. The engine only
/// collects the full principal stack when this returns non-zero. @ref LLP 0013#phase-5
#[no_mangle]
pub extern "C" fn ex_host_has_deputy_classes() -> i32 {
    if with_host(|host| host.has_deputy_classes(), false) {
        1
    } else {
        0
    }
}

// --- Authority-bearing capability handles (attenuators). @ref LLP 0013#delegation-and-authority-flow

/// Mint a handle carrying `capability` and return its (unforgeable, random) id.
/// The engine only calls this after verifying the *calling frame* holds
/// `capability` — so a package cannot mint a handle for authority it lacks.
#[no_mangle]
pub extern "C" fn ex_host_handle_create(capability: *const c_char) -> u64 {
    if capability.is_null() {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    with_host(|host| host.handles().create(&cap), 0)
}

/// Re-attenuate handle `parent` to a narrower grant (a full capability that must
/// be within the parent, or a bare sub-path appended to the parent's resource).
/// Returns 0 if the parent is missing/dead, the request would widen it, or the
/// secure Host has crossed the typed-arm boundary.
#[no_mangle]
pub extern "C" fn ex_host_handle_scoped(parent: u64, narrower: *const c_char) -> u64 {
    if narrower.is_null() {
        return 0;
    }
    let n = unsafe { CStr::from_ptr(narrower) }
        .to_string_lossy()
        .to_string();
    with_host(|host| host.scope_legacy_handle(parent, &n), 0)
}

/// Possession check: in an unarmed or explicitly insecure Host, is the handle
/// live (no revoked ancestor) and does its grant cover `capability`? Secure
/// armed Hosts reject this legacy numeric bearer family at use time; typed
/// opaque handles carry armed authority.
#[no_mangle]
pub extern "C" fn ex_host_handle_check(id: u64, capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    if with_host(|host| host.check_legacy_handle_possession(id, &cap), false) {
        1
    } else {
        0
    }
}

/// Revoke a handle; every handle derived from it fail-closes on its next check.
#[no_mangle]
pub extern "C" fn ex_host_handle_revoke(id: u64) {
    with_host(|host| host.handles().revoke(id), ());
}

// --- Dynamic root-principal permissions. @ref LLP 0013 — §dynamic permissions

/// Runtime-grant `capability` to the root principal, bounded by the policy
/// ceiling. Returns 1 if applied, 0 if outside the ceiling (denied).
#[no_mangle]
pub extern "C" fn ex_host_permission_request(capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    if with_host(|host| host.runtime_grant_root(&cap), false) {
        1
    } else {
        0
    }
}

/// Runtime-revoke a previously runtime-granted root capability.
#[no_mangle]
pub extern "C" fn ex_host_permission_revoke(capability: *const c_char) {
    if capability.is_null() {
        return;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    with_host(|host| host.runtime_revoke_root(&cap), ());
}

/// Tri-state grant status: 1 = granted, 2 = prompt (acquirable), 0 = denied.
#[no_mangle]
pub extern "C" fn ex_host_permission_status(capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    with_host(|host| host.grant_status(&cap) as i32, 0)
}

#[no_mangle]
pub extern "C" fn ex_host_grant_capability(module_id: u64, capability: *const c_char) {
    if capability.is_null() {
        return;
    }

    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();

    let module = module_id.to_string();
    // @ref LLP 0013 — §self-grant — this ABI is the JS-reachable package self-grant
    // (Exact.setModuleCapabilities / require({needs})); route it through
    // runtime_self_grant so it is refused under enforce and audited without
    // changing behavior under audit. Policy-driven grants use grant() directly
    // and are unaffected. (ENG-22695/ENG-22770)
    with_host(
        |host| host.capabilities().runtime_self_grant(&module, &cap),
        (),
    );
}

/// Register the resolved package principal for a numeric module id, so
/// per-package policy resolves at the host boundary.
///
/// @ref LLP 0013#mechanism-3 — Phase 1 attribution is loader-provided and thus
/// forgeable; Phase 2 replaces it with frame-derived provenance.
#[no_mangle]
pub extern "C" fn ex_host_register_module_package(
    module_id: u64,
    package: *const c_char,
    locator: *const c_char,
    integrity: *const c_char,
) {
    if package.is_null() {
        return;
    }
    let package = unsafe { CStr::from_ptr(package) }
        .to_string_lossy()
        .to_string();
    let locator = if locator.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(locator) }
                .to_string_lossy()
                .to_string(),
        )
    };
    let integrity = if integrity.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(integrity) }
                .to_string_lossy()
                .to_string(),
        )
    };
    let module = module_id.to_string();
    with_host(
        |host| {
            host.register_module_package(
                &module,
                &package,
                locator.as_deref(),
                integrity.as_deref(),
            )
        },
        (),
    );
}

/// Import-graph gate: may `module_id` load `specifier`? On an authenticated
/// route-cache hit, `target_source_id` names the already-resolved file identity
/// and `resolution_kind` completes the exact edge tuple that must be
/// re-authorized without another filesystem lookup. Returns 1 if the load may
/// proceed, else 0.
///
/// @ref LLP 0013#policy — builtins are reachable by `require`, so import policy
/// is the primary containment gate for them.
/// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
#[no_mangle]
pub extern "C" fn ex_host_check_import(
    module_id: u64,
    specifier: *const c_char,
    target_source_id: *const c_char,
    resolution_kind: u32,
) -> i32 {
    let module = PrincipalIdBuf::new(module_id);
    let allowed = if target_source_id.is_null() {
        if specifier.is_null() {
            true
        } else {
            let specifier = unsafe { CStr::from_ptr(specifier) }.to_string_lossy();
            with_host(|host| host.check_import(module.as_str(), &specifier), true)
        }
    } else {
        if specifier.is_null() {
            return 0;
        }
        let Ok(target_source_id) = unsafe { CStr::from_ptr(target_source_id) }.to_str() else {
            return 0;
        };
        let Ok(specifier) = unsafe { CStr::from_ptr(specifier) }.to_str() else {
            return 0;
        };
        let Ok(resolution_kind) =
            crate::module_loader::identity::ResolutionKind::from_abi_code(resolution_kind)
        else {
            return 0;
        };
        with_host(
            |host| {
                host.check_cached_module_import(
                    module.as_str(),
                    specifier,
                    target_source_id,
                    resolution_kind,
                )
            },
            false,
        )
    };
    if allowed {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn ex_host_log_event(
    event_type: *const c_char,
    module_id: u64,
    capability: *const c_char,
    result: i32,
) {
    if event_type.is_null() || capability.is_null() {
        return;
    }
    if !security_log_enabled() {
        return;
    }
    let event_type = unsafe { CStr::from_ptr(event_type) }
        .to_string_lossy()
        .to_string();
    let capability = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    let module = module_id.to_string();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let payload = json!({
        "ts": ts,
        "event": event_type,
        "module": module,
        "capability": capability,
        "result": result,
        "allowed": result != 0
    });
    enqueue_stderr_line(payload.to_string());
}

/// Decode the `(specifier, referrer)` C-string pair the module-resolve bridges
/// receive. Returns `None` when the specifier is null (caller returns null).
fn module_resolve_args(
    specifier: *const c_char,
    referrer: *const c_char,
) -> Option<(String, Option<String>)> {
    if specifier.is_null() {
        return None;
    }
    let spec = unsafe { CStr::from_ptr(specifier) }
        .to_string_lossy()
        .to_string();
    let referrer = if referrer.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(referrer) }
                .to_string_lossy()
                .to_string(),
        )
    };
    Some((spec, referrer))
}

/// The resolution-metadata fields shared by the full-resolve and metadata-only
/// bridges: everything except the module `source`. `require.resolve` needs only
/// these; the full `require`/`import` load path additionally attaches `source`.
fn module_meta_json(module: &crate::module_loader::ResolvedModule) -> serde_json::Value {
    let typed_path = module.resolver_path.as_ref();
    let public_id = typed_path
        .map(crate::vfs::ResolverLogicalPath::virtual_path)
        .or_else(|| {
            module
                .private_resolver_path
                .as_ref()
                .map(crate::module_loader::PrivateResolverPath::virtual_path)
        })
        .unwrap_or_else(|| {
            if module.kind == crate::module_loader::ModuleKind::Builtin {
                module.id.as_str()
            } else {
                "ibex:invalid-module-record"
            }
        });
    let serialized_path = typed_path
        .map(|path| json!(path))
        .or_else(|| {
            module
                .private_resolver_path
                .as_ref()
                .map(|path| json!(path))
        })
        .unwrap_or(serde_json::Value::Null);
    let serialized_package_root = module
        .resolver_package_root
        .as_ref()
        .map(|path| json!(path))
        .or_else(|| {
            module
                .private_resolver_package_root
                .as_ref()
                .map(|path| json!(path))
        })
        .unwrap_or(serde_json::Value::Null);
    let artifact_source_id = module
        .artifact_source_id
        .as_ref()
        .map(crate::module_loader::identity::SourceId::encode)
        .transpose();
    let artifact_source_id = match artifact_source_id {
        Ok(value) => value,
        Err(_) => {
            return module_resolution_error_json(&anyhow::anyhow!(
                "invalid authenticated artifact SourceId"
            ));
        }
    };
    json!({
        "schema": "ibex/module-resolution/1",
        "id": public_id,
        "kind": match module.kind {
            crate::module_loader::ModuleKind::Builtin => "builtin",
            crate::module_loader::ModuleKind::CommonJs => "cjs",
            crate::module_loader::ModuleKind::Json => "json",
            crate::module_loader::ModuleKind::Esm => "esm",
        },
        // Armed records carry versioned logical identities. The physical
        // resolver path remains in `ResolvedModule` as private native state and
        // is never serialized into the loader realm.
        // @ref LLP 0023#6-path-bearing-observables
        "path": serialized_path,
        // Resolver-owned package metadata. The JS loader must not decide
        // root-vs-package trust solely from the path shape because symlinked
        // and realpathed dependencies can live outside `node_modules`.
        "pkgName": module.package_name,
        "pkgRoot": serialized_package_root,
        // The resolved package's own version (node_modules packages only),
        // so the loader can form the `name@version` runtime identity for
        // version-distinguished principals/compartments. (ENG-22621)
        "pkgVersion": module.package_version,
        "pkgIntegrity": module.package_integrity,
        // Armed file records key the private loader cache by authenticated
        // VFS SourceId. `path` remains resolver-local native state; project
        // code observes only the paired virtual path/label.
        // @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
        "sourceId": module.source_id.as_ref().map(crate::vfs::SourceId::cache_key),
        // The native artifact runner uses a portable SourceId which omits the
        // compatibility cache identity's VFS-only logical-root tag. Both IDs
        // are stamped from the same authenticated binding; keeping distinct
        // fields prevents either consumer from reinterpreting the other wire
        // format.
        "artifactSourceId": artifact_source_id,
        "sourceLabel": module.source_label.as_ref().map(crate::vfs::SourceLabel::as_str),
        "virtualPath": module.virtual_path.as_deref(),
    })
}

/// Keep resolver failures useful without returning the resolver's native error
/// chain. That chain may name a probed backing path; it is host-private for the
/// same reason as `ResolvedModule::path`. The few semantic errors consumed by
/// the structured loader retain stable public codes and messages, while all
/// other resolver/library diagnostics collapse to one non-path-bearing class.
/// @ref LLP 0023#72-the-structured-result-and-its-error-classes
fn module_resolution_error_json(error: &anyhow::Error) -> serde_json::Value {
    let detail = format!("{error:#}");
    let (code, message) = if detail.contains("IBEX_DEPENDENCY_TOP_LEVEL_AWAIT") {
        (
            "IBEX_DEPENDENCY_TOP_LEVEL_AWAIT",
            "IBEX_DEPENDENCY_TOP_LEVEL_AWAIT: static dependency top-level await is unavailable",
        )
    } else if detail.contains("Import denied by authenticated package graph") {
        (
            "ERR_IBEX_IMPORT_DENIED",
            "Import denied by authenticated package graph",
        )
    } else {
        ("ERR_IBEX_MODULE_RESOLUTION", "Module resolution failed")
    };
    json!({
        "schema": "ibex/module-resolution/1",
        "error": message,
        "errorCode": code,
    })
}

fn module_resolve_cstring(payload: &serde_json::Value) -> *mut c_char {
    match std::ffi::CString::new(payload.to_string()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn ex_host_module_resolve(
    requester_module_id: u64,
    resolution_kind: u32,
    specifier: *const c_char,
    referrer: *const c_char,
) -> *mut c_char {
    let Some((spec, referrer)) = module_resolve_args(specifier, referrer) else {
        return ptr::null_mut();
    };

    let resolution_kind =
        crate::module_loader::identity::ResolutionKind::from_abi_code(resolution_kind);
    let resolved = with_host(
        |host| {
            let resolution_kind = resolution_kind?;
            let path = referrer
                .as_deref()
                .map(|encoded| host.module_referrer_path(encoded))
                .transpose()?;
            host.resolve_module_for_principal_typed(
                &spec,
                path.as_deref(),
                Some(&requester_module_id.to_string()),
                resolution_kind,
            )
        },
        Err(anyhow::anyhow!("Host not initialized")),
    );

    let payload = match resolved {
        Ok(module) => {
            let mut record = module_meta_json(&module);
            record["source"] = json!(module.source.unwrap_or_default());
            record
        }
        Err(err) => module_resolution_error_json(&err),
    };

    module_resolve_cstring(&payload)
}

// Observer-only call counts let end-to-end structured-session tests prove a
// cache hit did not quietly reacquire source through either resolver surface.
#[cfg(any(test, feature = "capsec-conformance-observer"))]
static SESSION_ROOT_FULL_RESOLVE_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(any(test, feature = "capsec-conformance-observer"))]
static SESSION_ROOT_META_RESOLVE_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(any(test, feature = "capsec-conformance-observer"))]
pub fn reset_session_root_resolve_counts_for_test() {
    SESSION_ROOT_FULL_RESOLVE_COUNT.store(0, std::sync::atomic::Ordering::Release);
    SESSION_ROOT_META_RESOLVE_COUNT.store(0, std::sync::atomic::Ordering::Release);
}

#[cfg(any(test, feature = "capsec-conformance-observer"))]
pub fn session_root_resolve_counts_for_test() -> (u64, u64) {
    (
        SESSION_ROOT_FULL_RESOLVE_COUNT.load(std::sync::atomic::Ordering::Acquire),
        SESSION_ROOT_META_RESOLVE_COUNT.load(std::sync::atomic::Ordering::Acquire),
    )
}

/// C-only structured-session root resolver. The referrer is a canonical
/// `LogicalPath` copied from the already-authenticated source request; unlike
/// the public loader bridge, no caller-controlled host pathname enters this
/// seam. Native phase 4 uses it for static imports, and lowering protocol v2
/// uses the same typed route at a live dynamic-import call. The returned full
/// record reaches only the captured loader closure, never a realm-global
/// require/import function.
/// @ref LLP 0024#73-evaluation-phases-collisions-and-the-cross-kind-matrix
/// @ref LLP 0026#6-top-level-await-and-dynamic-import
#[no_mangle]
pub extern "C" fn ex_host_session_static_import_resolve(
    logical_referrer: *const u8,
    logical_referrer_length: usize,
    specifier: *const u8,
    specifier_length: usize,
    resolution_kind: u32,
) -> *mut c_char {
    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    SESSION_ROOT_FULL_RESOLVE_COUNT.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let payload = (|| -> anyhow::Result<serde_json::Value> {
        if logical_referrer.is_null()
            || logical_referrer_length == 0
            || specifier.is_null()
            || specifier_length == 0
        {
            anyhow::bail!("invalid structured static-import resolver input");
        }
        let referrer_bytes =
            unsafe { std::slice::from_raw_parts(logical_referrer, logical_referrer_length) };
        let referrer_text = std::str::from_utf8(referrer_bytes)
            .map_err(|_| anyhow::anyhow!("static-import logical referrer is not UTF-8"))?;
        let referrer_value = capsec_semantics::strict_json::parse_strict(referrer_text)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let referrer: capsec_semantics::model::LogicalPath = serde_json::from_value(referrer_value)
            .map_err(|error| anyhow::anyhow!("invalid static-import referrer: {error}"))?;
        if !referrer.is_canonical() {
            anyhow::bail!("static-import logical referrer is not canonical");
        }
        let specifier =
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(specifier, specifier_length) })
                .map_err(|_| anyhow::anyhow!("static-import specifier is not UTF-8"))?;
        if specifier.as_bytes().contains(&0) {
            anyhow::bail!("static-import specifier contains NUL");
        }
        let resolution_kind =
            crate::module_loader::identity::ResolutionKind::from_abi_code(resolution_kind)?;
        let module = with_host(
            |host| host.resolve_session_static_import(specifier, &referrer, resolution_kind),
            Err(anyhow::anyhow!("Host not initialized")),
        )?;
        let mut record = module_meta_json(&module);
        record["source"] = json!(module.source.unwrap_or_default());
        Ok(record)
    })();

    let payload = match payload {
        Ok(payload) => payload,
        Err(error) => module_resolution_error_json(&error),
    };
    module_resolve_cstring(&payload)
}

/// C-only metadata route for authenticated direct-CommonJS
/// `require.resolve()`. It accepts the same canonical logical-referrer
/// credential as the full session static-import resolver, but deliberately
/// omits source loading and serialization.
/// @ref LLP 0023#72-the-structured-result-and-its-error-classes
#[no_mangle]
pub extern "C" fn ex_host_session_static_import_resolve_meta(
    logical_referrer: *const u8,
    logical_referrer_length: usize,
    specifier: *const u8,
    specifier_length: usize,
    resolution_kind: u32,
) -> *mut c_char {
    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    SESSION_ROOT_META_RESOLVE_COUNT.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let payload = (|| -> anyhow::Result<serde_json::Value> {
        if logical_referrer.is_null()
            || logical_referrer_length == 0
            || specifier.is_null()
            || specifier_length == 0
        {
            anyhow::bail!("invalid session-root metadata resolver input");
        }
        let referrer_bytes =
            unsafe { std::slice::from_raw_parts(logical_referrer, logical_referrer_length) };
        let referrer_text = std::str::from_utf8(referrer_bytes)
            .map_err(|_| anyhow::anyhow!("session-root logical referrer is not UTF-8"))?;
        let referrer_value = capsec_semantics::strict_json::parse_strict(referrer_text)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let referrer: capsec_semantics::model::LogicalPath = serde_json::from_value(referrer_value)
            .map_err(|error| anyhow::anyhow!("invalid session-root referrer: {error}"))?;
        if !referrer.is_canonical() {
            anyhow::bail!("session-root logical referrer is not canonical");
        }
        let specifier =
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(specifier, specifier_length) })
                .map_err(|_| anyhow::anyhow!("session-root specifier is not UTF-8"))?;
        if specifier.as_bytes().contains(&0) {
            anyhow::bail!("session-root specifier contains NUL");
        }
        let resolution_kind =
            crate::module_loader::identity::ResolutionKind::from_abi_code(resolution_kind)?;
        let module = with_host(
            |host| host.resolve_session_static_import_meta(specifier, &referrer, resolution_kind),
            Err(anyhow::anyhow!("Host not initialized")),
        )?;
        Ok(module_meta_json(&module))
    })();

    let payload = match payload {
        Ok(payload) => payload,
        Err(error) => module_resolution_error_json(&error),
    };
    module_resolve_cstring(&payload)
}

/// Loader-private resolver for trusted builtin implementation fan-out. The
/// host method accepts only exact generated-manifest specifiers and can never
/// enter package/path resolution. The corresponding JSI global is captured and
/// deleted by the bootstrap loader before package code can execute.
/// @ref LLP 0013#policy
#[no_mangle]
pub extern "C" fn ex_host_resolve_manifest_builtin_internal(
    specifier: *const c_char,
) -> *mut c_char {
    if specifier.is_null() {
        return ptr::null_mut();
    }
    let spec = unsafe { CStr::from_ptr(specifier) }
        .to_string_lossy()
        .to_string();
    let resolved = with_host(
        |host| host.resolve_manifest_builtin_internal(&spec),
        Err(anyhow::anyhow!("Host not initialized")),
    );
    let payload = match resolved {
        Ok(module) => {
            let mut record = module_meta_json(&module);
            record["source"] = json!(module.source.unwrap_or_default());
            record
        }
        Err(err) => module_resolution_error_json(&err),
    };
    module_resolve_cstring(&payload)
}

/// Metadata-only resolve: returns just the resolution record (id/kind/path/pkg
/// fields, no `source`) so `require.resolve` can get the resolved path without
/// the full-resolve bridge reading + transpiling + JSON-escaping the entire
/// module body only for the loader to discard it. (ENG-23007)
///
/// Caller must free the returned string with `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_module_resolve_meta(
    requester_module_id: u64,
    resolution_kind: u32,
    specifier: *const c_char,
    referrer: *const c_char,
) -> *mut c_char {
    let Some((spec, referrer)) = module_resolve_args(specifier, referrer) else {
        return ptr::null_mut();
    };

    let resolution_kind =
        crate::module_loader::identity::ResolutionKind::from_abi_code(resolution_kind);
    let resolved = with_host(
        |host| {
            let resolution_kind = resolution_kind?;
            let path = referrer
                .as_deref()
                .map(|encoded| host.module_referrer_path(encoded))
                .transpose()?;
            host.resolve_module_meta_for_principal_typed(
                &spec,
                path.as_deref(),
                Some(&requester_module_id.to_string()),
                resolution_kind,
            )
        },
        Err(anyhow::anyhow!("Host not initialized")),
    );

    let payload = match resolved {
        Ok(module) => module_meta_json(&module),
        Err(err) => module_resolution_error_json(&err),
    };

    module_resolve_cstring(&payload)
}

#[no_mangle]
pub extern "C" fn ex_host_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = std::ffi::CString::from_raw(ptr);
    }
}

#[repr(C)]
pub struct ExactFileHandle {
    file: std::fs::File,
    retained_identity: Option<crate::vfs::AuthenticatedFileDescriptorIdentity>,
    presented_handles: Vec<capsec_semantics::model::NonEmptyString>,
}

const FS_READ: u32 = 1;
const FS_WRITE: u32 = 2;
const FS_CREATE: u32 = 4;
const FS_TRUNCATE: u32 = 8;
const FS_APPEND: u32 = 16;

#[no_mangle]
pub extern "C" fn ex_host_fs_open(path: *const c_char, flags: u32) -> *mut ExactFileHandle {
    if path.is_null() {
        return ptr::null_mut();
    }

    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let mut opts = std::fs::OpenOptions::new();
    opts.read(flags & FS_READ != 0);
    opts.write(flags & FS_WRITE != 0);
    opts.create(flags & FS_CREATE != 0);
    opts.truncate(flags & FS_TRUNCATE != 0);
    opts.append(flags & FS_APPEND != 0);

    match opts.open(path) {
        Ok(file) => Box::into_raw(Box::new(ExactFileHandle {
            file,
            retained_identity: None,
            presented_handles: Vec::new(),
        })),
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

/// @abi-output ex_host_fs_read buf role=output kind=buffer length=len ownership=caller-storage
#[no_mangle]
pub extern "C" fn ex_host_fs_read(file: *mut ExactFileHandle, buf: *mut u8, len: u32) -> i32 {
    if file.is_null() || buf.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    match std::io::Read::read(&mut handle.file, slice) {
        Ok(bytes) => bytes as i32,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_fs_write(file: *mut ExactFileHandle, buf: *const u8, len: u32) -> i32 {
    if file.is_null() || buf.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    match std::io::Write::write(&mut handle.file, slice) {
        Ok(bytes) => bytes as i32,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_fs_seek(file: *mut ExactFileHandle, position: u64) -> i32 {
    if file.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    match std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(position)) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Positional read: read up to `len` bytes at absolute `offset` WITHOUT leaving
/// the handle's file cursor moved. Node's `readSync` leaves the fd offset
/// unchanged when `position` is a number, so the Windows JSI bridge needs a
/// `pread`-equivalent; the previous `ex_host_fs_seek` + `ex_host_fs_read`
/// permanently moved the cursor and corrupted a "header at a fixed offset then
/// stream sequentially" read pattern (ENG-22993, mirroring the POSIX `pread`
/// fix in ENG-22982). Implemented as save-cursor / seek / read / restore-cursor
/// rather than a platform positional API because Windows overlapped reads still
/// advance the pointer; this keeps behavior identical on every platform.
/// Returns the number of bytes read, or -1 on error.
/// @abi-output ex_host_fs_pread buf role=output kind=buffer length=len ownership=caller-storage
#[no_mangle]
pub extern "C" fn ex_host_fs_pread(
    file: *mut ExactFileHandle,
    buf: *mut u8,
    len: u32,
    offset: u64,
) -> i32 {
    if file.is_null() || buf.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    let saved = match std::io::Seek::stream_position(&mut handle.file) {
        Ok(pos) => pos,
        Err(err) => {
            set_errno_from_io_error(&err);
            return -1;
        }
    };
    if let Err(err) = std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(offset)) {
        set_errno_from_io_error(&err);
        return -1;
    }
    let read_result = std::io::Read::read(&mut handle.file, slice);
    // Restore the cursor regardless of the read outcome so a positional read
    // never disturbs a subsequent sequential read.
    let restore_result = std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(saved));
    match (read_result, restore_result) {
        (Ok(bytes), Ok(_)) => bytes as i32,
        (Err(err), _) | (Ok(_), Err(err)) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Positional write: write up to `len` bytes at absolute `offset` WITHOUT
/// leaving the handle's file cursor moved (see `ex_host_fs_pread`; ENG-22993,
/// mirroring the POSIX `pwrite` fix in ENG-22982). Returns the number of bytes
/// written, which — like a single `std::io::Write::write` — may be fewer than
/// `len`; the JS caller is responsible for looping on a short write. Returns -1
/// on error.
#[no_mangle]
pub extern "C" fn ex_host_fs_pwrite(
    file: *mut ExactFileHandle,
    buf: *const u8,
    len: u32,
    offset: u64,
) -> i32 {
    if file.is_null() || buf.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    let saved = match std::io::Seek::stream_position(&mut handle.file) {
        Ok(pos) => pos,
        Err(err) => {
            set_errno_from_io_error(&err);
            return -1;
        }
    };
    if let Err(err) = std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(offset)) {
        set_errno_from_io_error(&err);
        return -1;
    }
    let write_result = std::io::Write::write(&mut handle.file, slice);
    // Restore the cursor regardless of the write outcome so a positional write
    // never disturbs a subsequent sequential write.
    let restore_result = std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(saved));
    match (write_result, restore_result) {
        (Ok(bytes), Ok(_)) => bytes as i32,
        // The write is irreversible. Reporting failure here invites callers
        // to retry and duplicate the write; retain the restore diagnostic for
        // observability but report the committed byte count.
        (Ok(bytes), Err(err)) => {
            set_errno_from_io_error(&err);
            bytes as i32
        }
        (Err(err), _) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_fs_close(file: *mut ExactFileHandle) {
    if file.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(file));
    }
}

/// Flush file contents and metadata (`data_only == 0`) or file contents only
/// (`data_only != 0`) to stable storage.
#[no_mangle]
pub extern "C" fn ex_host_fs_sync(file: *mut ExactFileHandle, data_only: i32) -> i32 {
    if file.is_null() {
        record_fs_error(libc::EBADF);
        return -1;
    }
    let handle = unsafe { &mut *file };
    let result = if data_only != 0 {
        handle.file.sync_data()
    } else {
        handle.file.sync_all()
    };
    match result {
        Ok(()) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Return metadata for the open file identity, independent of later path
/// rename/unlink operations. Caller frees the JSON string with
/// `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_fstat(file: *mut ExactFileHandle) -> *mut c_char {
    if file.is_null() {
        record_fs_error(libc::EBADF);
        return ptr::null_mut();
    }
    let handle = unsafe { &mut *file };
    match handle.file.metadata() {
        Ok(metadata) => as_json_cstring(&make_stat_payload_from_metadata(metadata)),
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

/// Return a JSON string with file metadata matching Node-style Stats payload fields.
/// Caller must free the returned string with `ex_host_free_string`.
/// Returns null on error.
#[no_mangle]
pub extern "C" fn ex_host_fs_stat(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match make_stat_payload(&path, true) {
        Some(payload) => as_json_cstring(&payload),
        None => match std::fs::metadata(&path) {
            Ok(_) => {
                set_errno_from_io_error(&std::io::Error::other("stat payload failed"));
                ptr::null_mut()
            }
            Err(err) => {
                set_errno_from_io_error(&err);
                ptr::null_mut()
            }
        },
    }
}

/// Like stat but does not follow symlinks.
#[no_mangle]
pub extern "C" fn ex_host_fs_lstat(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match make_stat_payload(&path, false) {
        Some(payload) => as_json_cstring(&payload),
        None => match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                set_errno_from_io_error(&std::io::Error::other("lstat payload failed"));
                ptr::null_mut()
            }
            Err(err) => {
                set_errno_from_io_error(&err);
                ptr::null_mut()
            }
        },
    }
}

/// Return a JSON array of entry names in the directory.
/// Caller must free the returned string with `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_readdir(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match std::fs::read_dir(&path) {
        Ok(entries) => {
            let names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            let payload = serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_string());
            match CString::new(payload) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    set_errno_from_io_error(&std::io::Error::other("invalid JSON payload"));
                    ptr::null_mut()
                }
            }
        }
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

/// Create a directory. If `recursive` is non-zero, creates parent directories too.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn ex_host_fs_mkdir(path: *const c_char, recursive: i32) -> i32 {
    if recursive != 0 && refuse_armed_legacy_path_output() {
        return -1;
    }
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let result = if recursive != 0 {
        std::fs::create_dir_all(&path)
    } else {
        std::fs::create_dir(&path)
    };
    match result {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

fn refuse_armed_legacy_path_output() -> bool {
    if ex_host_is_armed() != 1 {
        return false;
    }
    set_fs_error_code(libc::EPERM);
    true
}

/// Recursively create a directory and return the highest missing path that
/// this call created (Node's recursive-mkdir result), or an empty string when
/// the full path already existed. This is a diagnostic/unarmed compatibility
/// bridge; an armed Host refuses before inspecting or creating any path.
/// Caller frees the result with `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_mkdir_recursive_result(path: *const c_char) -> *mut c_char {
    if refuse_armed_legacy_path_output() {
        return ptr::null_mut();
    }
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = std::path::PathBuf::from(
        unsafe { CStr::from_ptr(path) }
            .to_string_lossy()
            .into_owned(),
    );
    let mut cursor = path.clone();
    let mut first_created = None;
    while !cursor.exists() {
        first_created = Some(cursor.clone());
        if !cursor.pop() {
            break;
        }
    }
    if let Err(err) = std::fs::create_dir_all(&path) {
        set_errno_from_io_error(&err);
        return ptr::null_mut();
    }
    let value = first_created
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    CString::new(value)
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

/// Remove an empty directory.
#[no_mangle]
pub extern "C" fn ex_host_fs_rmdir(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match std::fs::remove_dir(&path) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Remove a file.
#[no_mangle]
pub extern "C" fn ex_host_fs_unlink(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match std::fs::remove_file(&path) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Rename / move a file or directory.
#[no_mangle]
pub extern "C" fn ex_host_fs_rename(from: *const c_char, to: *const c_char) -> i32 {
    if from.is_null() || to.is_null() {
        return -1;
    }
    let from = unsafe { CStr::from_ptr(from) }
        .to_string_lossy()
        .to_string();
    let to = unsafe { CStr::from_ptr(to) }.to_string_lossy().to_string();
    match std::fs::rename(&from, &to) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Copy a file.
#[no_mangle]
pub extern "C" fn ex_host_fs_copy(from: *const c_char, to: *const c_char) -> i32 {
    if from.is_null() || to.is_null() {
        return -1;
    }
    let from = unsafe { CStr::from_ptr(from) }
        .to_string_lossy()
        .to_string();
    let to = unsafe { CStr::from_ptr(to) }.to_string_lossy().to_string();
    match std::fs::copy(&from, &to) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Copy a file while atomically refusing an existing destination.
#[no_mangle]
pub extern "C" fn ex_host_fs_copy_exclusive(from: *const c_char, to: *const c_char) -> i32 {
    if from.is_null() || to.is_null() {
        return -1;
    }
    let from = unsafe { CStr::from_ptr(from) }
        .to_string_lossy()
        .into_owned();
    let to = unsafe { CStr::from_ptr(to) }.to_string_lossy().into_owned();
    let result = (|| -> std::io::Result<()> {
        let mut source = std::fs::File::open(&from)?;
        let mut destination = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&to)?;
        std::io::copy(&mut source, &mut destination)?;
        if let Ok(metadata) = source.metadata() {
            destination.set_permissions(metadata.permissions())?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Resize a file by path.
#[no_mangle]
pub extern "C" fn ex_host_fs_truncate(path: *const c_char, len: u64) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    match std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_len(len))
    {
        Ok(()) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

fn system_time_from_unix_seconds(value: f64) -> Option<SystemTime> {
    if !value.is_finite() {
        return None;
    }
    let duration = std::time::Duration::try_from_secs_f64(value.abs()).ok()?;
    if value.is_sign_negative() {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
}

/// Set path access and modification timestamps from Unix seconds.
#[no_mangle]
pub extern "C" fn ex_host_fs_utimes(path: *const c_char, atime: f64, mtime: f64) -> i32 {
    if path.is_null() {
        return -1;
    }
    let Some(atime) = system_time_from_unix_seconds(atime) else {
        record_fs_error(libc::EINVAL);
        return -1;
    };
    let Some(mtime) = system_time_from_unix_seconds(mtime) else {
        record_fs_error(libc::EINVAL);
        return -1;
    };
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    let times = std::fs::FileTimes::new()
        .set_accessed(atime)
        .set_modified(mtime);
    match std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_times(times))
    {
        Ok(()) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Return Node-shaped filesystem capacity metadata as JSON.
#[no_mangle]
pub extern "C" fn ex_host_fs_statfs(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let payload = {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "Kernel32")]
        extern "system" {
            fn GetDiskFreeSpaceW(
                root: *const u16,
                sectors_per_cluster: *mut u32,
                bytes_per_sector: *mut u32,
                free_clusters: *mut u32,
                total_clusters: *mut u32,
            ) -> i32;
        }
        let canonical = match std::fs::canonicalize(&path) {
            Ok(path) => path,
            Err(err) => {
                set_errno_from_io_error(&err);
                return ptr::null_mut();
            }
        };
        let mut root = std::path::PathBuf::new();
        for component in canonical.components() {
            root.push(component.as_os_str());
            if matches!(component, std::path::Component::RootDir) {
                break;
            }
        }
        let mut wide = root.as_os_str().encode_wide().collect::<Vec<_>>();
        wide.push(0);
        let mut sectors = 0u32;
        let mut bytes_per_sector = 0u32;
        let mut free_clusters = 0u32;
        let mut total_clusters = 0u32;
        if unsafe {
            GetDiskFreeSpaceW(
                wide.as_ptr(),
                &mut sectors,
                &mut bytes_per_sector,
                &mut free_clusters,
                &mut total_clusters,
            )
        } == 0
        {
            let err = std::io::Error::last_os_error();
            set_errno_from_io_error(&err);
            return ptr::null_mut();
        }
        let block_size = u64::from(sectors) * u64::from(bytes_per_sector);
        json!({
            "type": 0,
            "bsize": block_size,
            "blocks": total_clusters,
            "bfree": free_clusters,
            "bavail": free_clusters,
            "files": 0,
            "ffree": 0,
        })
    };
    #[cfg(unix)]
    let payload = {
        use std::os::unix::ffi::OsStrExt;
        let Ok(path) = CString::new(std::ffi::OsStr::new(&path).as_bytes()) else {
            record_fs_error(libc::EINVAL);
            return ptr::null_mut();
        };
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
            record_fs_error(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            );
            return ptr::null_mut();
        }
        json!({
            "type": 0,
            "bsize": stat.f_bsize,
            "blocks": stat.f_blocks,
            "bfree": stat.f_bfree,
            "bavail": stat.f_bavail,
            "files": stat.f_files,
            "ffree": stat.f_ffree,
        })
    };
    #[cfg(not(any(unix, windows)))]
    let payload = {
        record_fs_error(libc::ENOSYS);
        return ptr::null_mut();
    };
    as_json_cstring(&payload)
}

/// Return the canonical host path for diagnostic/unarmed compatibility.
/// Armed runtimes use the session-bound private VFS projector and this legacy
/// bridge refuses before filesystem lookup. Caller must free with
/// `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_realpath(path: *const c_char) -> *mut c_char {
    if refuse_armed_legacy_path_output() {
        return ptr::null_mut();
    }
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match std::fs::canonicalize(&path) {
        Ok(canonical) => match CString::new(canonical.to_string_lossy().to_string()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => {
                set_errno_from_io_error(&std::io::Error::other("invalid canonical path"));
                ptr::null_mut()
            }
        },
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

/// Check access to a path. `mode` is a bitmask that matches Node.js `fs.access`
/// constants: 0=existence, 1=execute, 2=write, 4=read.
/// Returns 0 if accessible, -1 if not.
#[no_mangle]
pub extern "C" fn ex_host_fs_access(path: *const c_char, mode: i32) -> i32 {
    if path.is_null() {
        return -1;
    }
    #[cfg(unix)]
    {
        let c_path = unsafe { CStr::from_ptr(path) };
        let flags = if mode == 0 {
            libc::F_OK
        } else {
            let mut requested = 0;
            if mode & 1 != 0 {
                requested |= libc::X_OK;
            }
            if mode & 2 != 0 {
                requested |= libc::W_OK;
            }
            if mode & 4 != 0 {
                requested |= libc::R_OK;
            }
            requested
        };

        let result = unsafe { libc::access(c_path.as_ptr(), flags) };
        if result == 0 {
            0
        } else {
            set_errno_from_io_error(&std::io::Error::last_os_error());
            -1
        }
    }
    #[cfg(not(unix))]
    {
        let path = unsafe { CStr::from_ptr(path) }
            .to_string_lossy()
            .to_string();
        if mode == 0 {
            return match std::fs::metadata(&path) {
                Ok(_) => 0,
                Err(err) => {
                    set_errno_from_io_error(&err);
                    -1
                }
            };
        }

        if mode & 4 != 0 {
            if let Err(err) = std::fs::File::open(&path) {
                set_errno_from_io_error(&err);
                return -1;
            }
        }
        if mode & 2 != 0 {
            if let Err(err) = std::fs::OpenOptions::new().write(true).open(&path) {
                set_errno_from_io_error(&err);
                return -1;
            }
        }
        if mode & 1 != 0 {
            if let Err(err) = std::fs::metadata(&path) {
                set_errno_from_io_error(&err);
                return -1;
            }
        }
        0
    }
}

/// Change file permissions (unix mode).
#[no_mangle]
pub extern "C" fn ex_host_fs_chmod(path: *const c_char, mode: u32) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        match std::fs::set_permissions(&path, perms) {
            Ok(_) => 0,
            Err(err) => {
                set_errno_from_io_error(&err);
                -1
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = mode;
        -1
    }
}

/// Create a temporary directory with the given prefix.
/// This is a diagnostic/unarmed compatibility bridge. An armed Host refuses
/// before reading the prefix, generating randomness, or creating a directory.
/// Caller must free the returned path with `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_mkdtemp(prefix: *const c_char, module_id: u64) -> *mut c_char {
    if refuse_armed_legacy_path_output() {
        return ptr::null_mut();
    }
    let prefix_str = if prefix.is_null() {
        "tmp".to_string()
    } else {
        unsafe { CStr::from_ptr(prefix) }
            .to_string_lossy()
            .to_string()
    };

    // Generate random suffix
    let mut rng_bytes = [0u8; 6];
    if getrandom(&mut rng_bytes).is_err() {
        return ptr::null_mut();
    }
    let suffix: String = rng_bytes
        .iter()
        .map(|b| {
            let idx = (*b as usize) % 36;
            if idx < 10 {
                (b'0' + idx as u8) as char
            } else {
                (b'a' + (idx - 10) as u8) as char
            }
        })
        .collect();

    let dir_path = std::env::temp_dir().join(format!("{}{}", prefix_str, suffix));
    let cap = format!("fs:write:{}", dir_path.to_string_lossy());
    let module = module_id.to_string();
    let allowed = with_host(|host| host.check_capability(&module, &cap), false);
    if !allowed {
        set_errno_from_io_error(&std::io::Error::from_raw_os_error(libc::EACCES));
        return ptr::null_mut();
    }
    match std::fs::create_dir(&dir_path) {
        Ok(_) => match CString::new(dir_path.to_string_lossy().to_string()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => {
                set_errno_from_io_error(&std::io::Error::other("invalid temp path"));
                ptr::null_mut()
            }
        },
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

fn write_all_return_count(writer: &mut impl Write, data: &[u8]) -> io::Result<i32> {
    writer.write_all(data)?;
    i32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "write length exceeds i32"))
}

/// Append data to a file. Returns bytes written or -1 on error.
#[no_mangle]
pub extern "C" fn ex_host_fs_append(path: *const c_char, data: *const u8, len: u32) -> i32 {
    if path.is_null() || data.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let slice = unsafe { std::slice::from_raw_parts(data, len as usize) };

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).append(true);
    match opts.open(&path) {
        Ok(mut file) => match write_all_return_count(&mut file, slice) {
            Ok(n) => n,
            Err(err) => {
                set_errno_from_io_error(&err);
                -1
            }
        },
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_open(path: *const c_char, options: *const c_char) -> u64 {
    if path.is_null() {
        return 0;
    }

    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let options = parse_sqlite_open_options(options);
    let flags = sqlite_open_flags(&options);

    let db = match Connection::open_with_flags(path.as_str(), flags) {
        Ok(db) => db,
        Err(_) => return 0,
    };
    if install_sqlite_authorizer(&db).is_err() {
        return 0;
    }

    register_sqlite_connection(db)
}

fn register_sqlite_connection(db: Connection) -> u64 {
    with_sqlite_state(|state| {
        let Some(handle) = state.allocate_db_handle() else {
            return 0;
        };
        state.dbs.insert(handle, Arc::new(Mutex::new(db)));
        handle
    })
}

/// Open the exact retained descriptor selected by the native checked-path
/// adapter. The special descriptor spelling duplicates that object; it never
/// re-resolves the caller's original pathname.
#[no_mangle]
pub extern "C" fn ex_host_sqlite_open_checked_fd(fd: i32, options: *const c_char) -> u64 {
    #[cfg(unix)]
    {
        if fd < 0 {
            return 0;
        }
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        let descriptor_path = format!("/dev/fd/{fd}");
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        let descriptor_path = format!("/proc/self/fd/{fd}");
        let parsed = parse_sqlite_open_options(options);
        let flags = sqlite_open_flags(&parsed);
        let db = match Connection::open_with_flags(descriptor_path, flags) {
            Ok(db) => db,
            Err(_) => return 0,
        };
        if configure_sqlite_isolated_io(&db).is_err() {
            return 0;
        }
        register_sqlite_connection(db)
    }
    #[cfg(not(unix))]
    {
        let _ = (fd, options);
        0
    }
}

/// In-memory SQLite is a zero-effect computation branch only while SQLite is
/// unable to spill temp state or attach a file later.
#[no_mangle]
pub extern "C" fn ex_host_sqlite_open_isolated_memory(options: *const c_char) -> u64 {
    let parsed = parse_sqlite_open_options(options);
    let flags = sqlite_open_flags(&parsed);
    let db = match Connection::open_with_flags(":memory:", flags) {
        Ok(db) => db,
        Err(_) => return 0,
    };
    if configure_sqlite_isolated_io(&db).is_err() {
        return 0;
    }
    register_sqlite_connection(db)
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_close(handle: u64) -> i32 {
    with_sqlite_state(|state| {
        if state.dbs.remove(&handle).is_some() {
            state
                .statements
                .retain(|_, statement| statement.db_id != handle);
            0
        } else {
            -1
        }
    })
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_prepare(db_handle: u64, sql: *const c_char) -> *mut c_char {
    if db_handle == 0 || sql.is_null() {
        return ptr::null_mut();
    }

    let sql = unsafe { CStr::from_ptr(sql) }.to_string_lossy().to_string();

    let connection = match sqlite_connection(db_handle) {
        Some(connection) => connection,
        None => return ptr::null_mut(),
    };

    // Compile via `prepare_cached` and read the statement's metadata under the
    // per-connection lock only. Caching the compiled plan here means the later
    // exec/query calls for the same SQL reuse it instead of re-tokenizing,
    // re-parsing and re-planning on every invocation.
    let (column_names, declared_types, read_only, params_count) = {
        let guard = lock_connection(&connection);
        let statement = match guard.prepare_cached(&sql) {
            Ok(statement) => statement,
            Err(err) => {
                return as_json_cstring(&json!({ "error": err.to_string() }));
            }
        };

        let column_count = statement.column_count();
        let column_names: Vec<String> = (0..column_count)
            .filter_map(|index| {
                statement
                    .column_name(index)
                    .ok()
                    .map(|name| name.to_string())
            })
            .collect();

        let declared_types: Vec<Option<String>> = statement
            .columns()
            .into_iter()
            .map(|column| column.decl_type().map(std::string::ToString::to_string))
            .collect();
        let read_only = statement.readonly();
        let params_count = statement.parameter_count() as usize;

        (column_names, declared_types, read_only, params_count)
    };

    let statement_handle = with_sqlite_state(|state| {
        let statement_handle = state.allocate_statement_handle()?;
        state.statements.insert(
            statement_handle,
            SqliteStatementRecord {
                db_id: db_handle,
                sql,
                read_only,
            },
        );
        Some(statement_handle)
    });
    let Some(statement_handle) = statement_handle else {
        return as_json_cstring(&json!({"error": "sqlite statement handle space exhausted"}));
    };

    as_json_cstring(&json!({
        "handle": statement_handle,
        "columnNames": column_names,
        "declaredTypes": declared_types,
        "paramsCount": params_count,
        "readOnly": read_only,
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_finalize(statement_handle: u64) -> i32 {
    with_sqlite_state(|state| {
        if state.statements.remove(&statement_handle).is_some() {
            0
        } else {
            -1
        }
    })
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_expanded_sql(statement_handle: u64) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    with_sqlite_state(|state| {
        let statement = match state.statements.get(&statement_handle) {
            Some(statement) => statement,
            None => return ptr::null_mut(),
        };
        match CString::new(statement.sql.clone()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_in_transaction(handle: u64) -> i32 {
    let connection = match sqlite_connection(handle) {
        Some(connection) => connection,
        None => return 0,
    };
    let guard = lock_connection(&connection);
    if guard.is_autocommit() {
        0
    } else {
        1
    }
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_all(
    statement_handle: u64,
    bindings_json: *const c_char,
) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    let bindings = parse_bindings(bindings_json);

    let (statement, connection) = match sqlite_statement_connection(statement_handle) {
        Some(pair) => pair,
        None => return ptr::null_mut(),
    };
    let read_only = statement.read_only;
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&statement.sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .filter_map(|index| stmt.column_name(index).ok().map(|name| name.to_string()))
        .collect();
    let mut rows = match query_with_bindings(&mut stmt, &bindings) {
        Ok(result) => result,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let mut payload_rows = Vec::new();
    let mut column_types: Option<Vec<String>> = None;
    loop {
        // A step error after N rows (SQLITE_BUSY, an I/O error, a RAISE in a
        // trigger, arithmetic overflow) must surface as an error — not exit the
        // loop and return the partial rows as a silently truncated success. The
        // old `while let Ok(Some(row))` form dropped the error on the floor.
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };
        let mut object = serde_json::Map::new();
        let mut row_column_types = if read_only {
            Some(Vec::with_capacity(column_count))
        } else {
            None
        };
        for index in 0..column_count {
            let name = match column_names.get(index) {
                Some(name) => name.clone(),
                None => continue,
            };

            if let Ok(value) = row.get_ref(index) {
                if let Some(ref mut types) = row_column_types {
                    types.push(sqlite_value_type_name(&value).to_string());
                }
                object.insert(name, sqlite_value_to_json(value));
            } else if let Some(ref mut types) = row_column_types {
                types.push(String::new());
            }
        }
        if column_types.is_none() {
            column_types = row_column_types;
        }
        payload_rows.push(serde_json::Value::Object(object));
    }

    as_json_cstring(&json!({
        "rows": payload_rows,
        "columnNames": column_names,
        "columnTypes": column_types.unwrap_or_default(),
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_get(
    statement_handle: u64,
    bindings_json: *const c_char,
) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    let bindings = parse_bindings(bindings_json);

    let (statement, connection) = match sqlite_statement_connection(statement_handle) {
        Some(pair) => pair,
        None => return ptr::null_mut(),
    };
    let read_only = statement.read_only;
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&statement.sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .filter_map(|index| stmt.column_name(index).ok().map(|name| name.to_string()))
        .collect();
    let mut rows = match query_with_bindings(&mut stmt, &bindings) {
        Ok(result) => result,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let mut column_types = Vec::new();
    let row = match rows.next() {
        Ok(Some(row)) => {
            let mut object = serde_json::Map::new();
            for index in 0..column_count {
                let name = match column_names.get(index) {
                    Some(name) => name.clone(),
                    None => continue,
                };
                if let Ok(value) = row.get_ref(index) {
                    if read_only {
                        column_types.push(sqlite_value_type_name(&value).to_string());
                    }
                    object.insert(name, sqlite_value_to_json(value));
                } else if read_only {
                    column_types.push(String::new());
                }
            }
            serde_json::Value::Object(object)
        }
        Ok(None) => serde_json::Value::Null,
        Err(err) => serde_json::json!({"error": err.to_string()}),
    };

    as_json_cstring(&json!({
        "row": row,
        "columnNames": column_names,
        "columnTypes": column_types,
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_values(
    statement_handle: u64,
    bindings_json: *const c_char,
) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    let bindings = parse_bindings(bindings_json);

    let (statement, connection) = match sqlite_statement_connection(statement_handle) {
        Some(pair) => pair,
        None => return ptr::null_mut(),
    };
    let read_only = statement.read_only;
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&statement.sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let column_count = stmt.column_count();
    let mut rows = match query_with_bindings(&mut stmt, &bindings) {
        Ok(result) => result,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let mut payload_rows = Vec::new();
    let mut column_types: Option<Vec<String>> = None;
    loop {
        // As in `ex_host_sqlite_all`: surface a mid-iteration step error instead
        // of returning the rows gathered so far as a silently truncated success.
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };
        let mut values = Vec::new();
        let mut row_column_types = if read_only {
            Some(Vec::with_capacity(column_count))
        } else {
            None
        };
        for index in 0..column_count {
            if let Ok(value) = row.get_ref(index) {
                if let Some(ref mut types) = row_column_types {
                    types.push(sqlite_value_type_name(&value).to_string());
                }
                values.push(sqlite_value_to_json(value));
            } else if let Some(ref mut types) = row_column_types {
                types.push(String::new());
            }
        }
        if column_types.is_none() {
            column_types = row_column_types;
        }
        payload_rows.push(serde_json::Value::Array(values));
    }

    as_json_cstring(&json!({
        "rows": payload_rows,
        "columnTypes": column_types.unwrap_or_default(),
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_run(
    statement_handle: u64,
    bindings_json: *const c_char,
) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    let bindings = parse_bindings(bindings_json);

    let (statement, connection) = match sqlite_statement_connection(statement_handle) {
        Some(pair) => pair,
        None => return ptr::null_mut(),
    };
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&statement.sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    if let Err(err) = execute_with_bindings(&mut stmt, &bindings) {
        return as_json_cstring(&json!({"error": err.to_string()}));
    }
    // Return the cached statement to the connection's cache before reading the
    // connection-level counters.
    drop(stmt);

    as_json_cstring(&json!({
        "changes": guard.changes(),
        "lastInsertRowid": guard.last_insert_rowid(),
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_exec(
    db_handle: u64,
    sql: *const c_char,
    bindings_json: *const c_char,
) -> *mut c_char {
    if db_handle == 0 || sql.is_null() {
        return ptr::null_mut();
    }

    let sql = unsafe { CStr::from_ptr(sql) }.to_string_lossy().to_string();
    let bindings = parse_bindings(bindings_json);

    let connection = match sqlite_connection(db_handle) {
        Some(connection) => connection,
        None => return ptr::null_mut(),
    };
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    if let Err(err) = execute_with_bindings(&mut stmt, &bindings) {
        return as_json_cstring(&json!({"error": err.to_string()}));
    }
    drop(stmt);

    as_json_cstring(&json!({
        "changes": guard.changes(),
        "lastInsertRowid": guard.last_insert_rowid(),
    }))
}

/// Read an environment variable into `out_buf`.
///
/// Returns the value's *full* byte length (which may exceed `len`), or `-1` when
/// the variable is unset. This lets a caller (a) distinguish "unset" from
/// "present but empty" — the previous `unwrap_or_default()` folded both to an
/// empty string — and (b) detect truncation: if the return value is `>= len`,
/// the buffer held only a `len - 1` byte prefix and the caller should re-query
/// with a buffer of at least `return + 1` bytes. `out_buf`/`len` may be
/// null/`0` to query the length without copying. Previously values longer than
/// the buffer (notably the C++ side's fixed 4096-byte buffer) were clipped with
/// no signal (ENG-22955).
#[no_mangle]
pub extern "C" fn ex_host_env_get(key: *const c_char, out_buf: *mut c_char, len: u32) -> i64 {
    if key.is_null() {
        return -1;
    }
    let key = unsafe { CStr::from_ptr(key) }.to_string_lossy().to_string();
    if let Some(value) = super::process::compiled_environment_value(&key) {
        return copy_environment_bytes(value.as_deref(), out_buf, len);
    }
    // `var_os` returns None only when the variable is absent, so unset stays
    // distinguishable from empty; a non-UTF-8 value is rendered lossily (like the
    // key) rather than reported as absent.
    let value = match std::env::var_os(&key) {
        Some(v) => v,
        None => return -1,
    };
    let value = value.to_string_lossy();
    copy_environment_bytes(Some(value.as_bytes()), out_buf, len)
}

fn copy_environment_bytes(value: Option<&[u8]>, out_buf: *mut c_char, len: u32) -> i64 {
    let Some(bytes) = value else {
        return -1;
    };
    let full_len = bytes.len();

    if !out_buf.is_null() && len > 0 {
        let write_len = full_len.min((len as usize).saturating_sub(1));
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf as *mut u8, write_len);
            *out_buf.add(write_len) = 0;
        }
    }

    full_len as i64
}

/// Return the number of canonical keys in the compiled broker base, or `-1`
/// when this is an ordinary source runtime. Values remain available only via
/// `ex_host_env_get`, whose native caller performs the exact-name authority
/// decision before disclosure.
#[no_mangle]
pub extern "C" fn ex_host_env_compiled_key_count() -> i64 {
    super::process::compiled_environment_key_count()
        .and_then(|count| i64::try_from(count).ok())
        .unwrap_or(-1)
}

/// Copy one canonical compiled broker-base key using the same full-length
/// protocol as `ex_host_env_get`.
#[no_mangle]
pub extern "C" fn ex_host_env_compiled_key_at(index: usize, out_buf: *mut c_char, len: u32) -> i64 {
    copy_environment_bytes(
        super::process::compiled_environment_key(index).map(str::as_bytes),
        out_buf,
        len,
    )
}

/// 1 when the insecure ambient `process.env` projection is installed, else 0.
/// Always 0 in secure builds: the installer only exists behind the
/// compile-time `insecure` feature, and even there it must be called
/// explicitly by the launcher (or an embedder), so armed secure runtimes and
/// embedded runtimes never observe an ambient host environment by default.
/// The symbol itself exists in every build so the native env bridges can
/// consult it unconditionally, mirroring `ex_host_is_armed`.
/// @ref LLP 0038#fully-open-mode-insecure
#[no_mangle]
pub extern "C" fn ex_host_env_ambient_active() -> i32 {
    i32::from(super::process::insecure_ambient_environment_active())
}

/// Read one name from the insecure ambient environment using the same
/// full-length protocol as `ex_host_env_get`. `-1` when the projection is
/// inactive or the name is unset.
#[no_mangle]
pub extern "C" fn ex_host_env_ambient_get(
    key: *const c_char,
    out_buf: *mut c_char,
    len: u32,
) -> i64 {
    if key.is_null() {
        return -1;
    }
    let key = unsafe { CStr::from_ptr(key) }.to_string_lossy().to_string();
    match super::process::insecure_ambient_env_get(&key) {
        Some(value) => copy_environment_bytes(Some(value.as_bytes()), out_buf, len),
        None => -1,
    }
}

/// Write (`value` non-null) or delete (`value` null) one insecure ambient
/// environment name. Returns 0 on success, -1 when the projection is inactive
/// or `key` is null.
#[no_mangle]
pub extern "C" fn ex_host_env_ambient_set(key: *const c_char, value: *const c_char) -> i32 {
    if key.is_null() || !super::process::insecure_ambient_environment_active() {
        return -1;
    }
    let key = unsafe { CStr::from_ptr(key) }.to_string_lossy().to_string();
    if value.is_null() {
        super::process::insecure_ambient_env_set(&key, None);
    } else {
        let value = unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .to_string();
        super::process::insecure_ambient_env_set(&key, Some(&value));
    }
    0
}

/// Number of names in the insecure ambient environment, or `-1` while the
/// projection is inactive.
#[no_mangle]
pub extern "C" fn ex_host_env_ambient_key_count() -> i64 {
    super::process::insecure_ambient_env_key_count()
        .and_then(|count| i64::try_from(count).ok())
        .unwrap_or(-1)
}

/// Copy one insecure ambient environment name (display spelling) using the
/// same full-length protocol as `ex_host_env_get`.
#[no_mangle]
pub extern "C" fn ex_host_env_ambient_key_at(index: usize, out_buf: *mut c_char, len: u32) -> i64 {
    match super::process::insecure_ambient_env_key_at(index) {
        Some(name) => copy_environment_bytes(Some(name.as_bytes()), out_buf, len),
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn ex_host_time_now_ms() -> u64 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// @abi-output ex_host_random_fill buf role=output kind=buffer length=len ownership=caller-storage
#[no_mangle]
pub extern "C" fn ex_host_random_fill(buf: *mut u8, len: u32) -> i32 {
    if buf.is_null() || len == 0 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    match getrandom(slice) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn ex_host_console_log(level: i32, message: *const c_char) {
    if message.is_null() {
        return;
    }
    let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
    // SAFETY: CStr proved this pointer readable for exactly `bytes.len()`
    // bytes; the length-bearing entry point does not retain it.
    unsafe { ex_host_console_log_bytes(level, bytes.as_ptr(), bytes.len()) };
}

/// Length-bearing console ingress. Authenticated CLI workers synchronously
/// enter their counted fd relay here, before returning to JavaScript; embedded
/// hosts retain the bounded asynchronous diagnostics queue. This split makes
/// queue backpressure a host policy without letting it silently drop or reorder
/// CLI program output, and preserves embedded NUL bytes end to end.
///
/// # Safety
///
/// For a nonzero `length`, `message` must address `length` readable bytes for
/// the duration of this synchronous call.
/// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker
#[no_mangle]
pub unsafe extern "C" fn ex_host_console_log_bytes(level: i32, message: *const u8, length: usize) {
    if message.is_null() && length != 0 {
        return;
    }
    let bytes = if length == 0 {
        &[][..]
    } else {
        // SAFETY: the caller promises a readable length-bearing payload for
        // this synchronous call; no reference escapes.
        unsafe { std::slice::from_raw_parts(message, length) }
    };
    #[cfg(target_os = "android")]
    write_android_logcat(level, &String::from_utf8_lossy(bytes));
    // The gate makes arming, synchronous writes, sealing, and the inactive
    // queue decision one ordered transition. In particular, a writer cannot
    // observe INACTIVE, pause, and enqueue after an armed caller has drained
    // the preexisting asynchronous queue.
    let counted_writer = {
        let _gate = terminal_console_relay_gate()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match TERMINAL_CONSOLE_RELAY_STATE.load(std::sync::atomic::Ordering::Acquire) {
            TERMINAL_CONSOLE_RELAY_ACTIVE => {
                let epoch = terminal_console_relay_epoch()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                    .cloned();
                match (epoch, duplicate_counted_worker_console_writer(level)) {
                    (Some(epoch), Ok(writer)) => {
                        epoch
                            .in_flight
                            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        Some((epoch, writer))
                    }
                    (Some(epoch), Err(_)) => {
                        epoch
                            .write_failed
                            .store(true, std::sync::atomic::Ordering::Release);
                        None
                    }
                    (None, _) => None,
                }
            }
            TERMINAL_CONSOLE_RELAY_SEALED => {
                if let Some(epoch) = terminal_console_relay_epoch()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                {
                    epoch
                        .write_failed
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                None
            }
            _ if !console_mirror_enabled() => None,
            _ => {
                let msg = String::from_utf8_lossy(bytes).into_owned();
                match level {
                    1 => enqueue_stderr_line(msg),
                    _ => enqueue_stdout_line(msg),
                }
                None
            }
        }
    };
    if let Some((epoch, mut writer)) = counted_writer {
        if write_counted_worker_console_record(&mut writer, bytes).is_err() {
            epoch
                .write_failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        epoch
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Host, HostConfig, SecurityMode};
    use std::io::{self, Write};

    #[cfg(unix)]
    #[test]
    fn final_sealed_console_observation_excludes_a_new_producer() {
        const MARKER: &[u8] = b"post-seal-producer";

        let guard = arm_authenticated_worker_console_relay().unwrap();
        guard.seal().unwrap();
        let (start_tx, start_rx) = std::sync::mpsc::sync_channel(1);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let producer = std::thread::spawn(move || {
            start_rx.recv().unwrap();
            // SAFETY: MARKER is live for this synchronous call.
            unsafe {
                ex_host_console_log_bytes(0, MARKER.as_ptr(), MARKER.len());
            }
            done_tx.send(()).unwrap();
        });
        guard.with_final_sealed_status_action(|status| {
            assert!(status.is_ok());
            start_tx.send(()).unwrap();
            assert_eq!(
                done_rx.recv_timeout(std::time::Duration::from_millis(50)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout),
                "a producer entered after the final sealed-epoch observation"
            );
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        producer.join().unwrap();
        assert!(
            guard.seal().is_err(),
            "the post-seal attempt was not recorded after the final gate opened"
        );
    }

    #[test]
    fn process_ipc_bootstrap_lease_initializes_only_once() {
        let mut lease = ProcessIpcBootstrapLease::default();
        let captures = Cell::new(0_u32);
        lease.initialize_with(|| {
            captures.set(captures.get() + 1);
            Some(ProcessIpcBootstrap {
                fd: 17,
                serialization: 1,
            })
        });
        lease.initialize_with(|| {
            captures.set(captures.get() + 1);
            Some(ProcessIpcBootstrap {
                fd: 18,
                serialization: 0,
            })
        });

        assert_eq!(captures.get(), 1);
        assert_eq!(
            lease.take(),
            Some(ProcessIpcBootstrap {
                fd: 17,
                serialization: 1,
            })
        );
        assert_eq!(lease.take(), None);
    }

    #[test]
    fn process_ipc_bootstrap_fd_parser_rejects_malformed_and_out_of_range_text() {
        assert_eq!(parse_process_ipc_fd("0"), Some(0));
        assert_eq!(parse_process_ipc_fd("+23"), Some(23));
        for malformed in [
            "",
            "+",
            "-1",
            " 3",
            "3 ",
            "3.0",
            "0x3",
            "2147483648",
            "4294967296",
        ] {
            assert_eq!(
                parse_process_ipc_fd(malformed),
                None,
                "accepted malformed IPC descriptor text {malformed:?}"
            );
        }
    }

    #[test]
    fn process_ipc_bootstrap_requires_claimed_unarmed_context_and_is_one_shot() {
        let audit = Arc::new(Host::new(HostConfig {
            mode: SecurityMode::Audit,
            ..Default::default()
        }));
        let armed = Arc::new(crate::host::tests::example_vfs_armed_host());
        let contexts = RwLock::new(HashMap::from([
            (
                11,
                HostContextRecord {
                    host: Arc::clone(&audit),
                    claimed: false,
                    runtime_nonce: None,
                    runtime_extension_leases: HashMap::new(),
                },
            ),
            (
                12,
                HostContextRecord {
                    host: Arc::clone(&audit),
                    claimed: true,
                    runtime_nonce: None,
                    runtime_extension_leases: HashMap::new(),
                },
            ),
            (
                13,
                HostContextRecord {
                    host: Arc::clone(&audit),
                    claimed: true,
                    runtime_nonce: None,
                    runtime_extension_leases: HashMap::new(),
                },
            ),
            (
                14,
                HostContextRecord {
                    host: armed,
                    claimed: true,
                    runtime_nonce: None,
                    runtime_extension_leases: HashMap::new(),
                },
            ),
        ]));
        let marker = ProcessIpcBootstrap {
            fd: 23,
            serialization: 1,
        };
        let lease = Mutex::new(ProcessIpcBootstrapLease {
            initialized: true,
            available: Some(marker),
        });

        assert_eq!(
            take_process_ipc_bootstrap_for_context(&contexts, &lease, 99),
            None,
            "a forged context id must not consume the process lease"
        );
        assert_eq!(
            take_process_ipc_bootstrap_for_context(&contexts, &lease, 11),
            None,
            "an unclaimed context must not consume the process lease"
        );
        {
            let mut records = contexts.write().unwrap();
            records.remove(&11);
            records.insert(
                15,
                HostContextRecord {
                    host: Arc::clone(&audit),
                    claimed: false,
                    runtime_nonce: None,
                    runtime_extension_leases: HashMap::new(),
                },
            );
        }
        assert_eq!(
            take_process_ipc_bootstrap_for_context(&contexts, &lease, 15),
            None,
            "replacement must remain ineligible until it is claimed"
        );
        assert_eq!(
            take_process_ipc_bootstrap_for_context(&contexts, &lease, 14),
            None,
            "an armed context must never adopt environment-carried IPC authority"
        );
        contexts.write().unwrap().get_mut(&15).unwrap().claimed = true;
        assert_eq!(
            take_process_ipc_bootstrap_for_context(&contexts, &lease, 15),
            Some(marker),
            "replacing an unclaimed context must not lose the process lease"
        );
        assert_eq!(
            take_process_ipc_bootstrap_for_context(&contexts, &lease, 15),
            None,
            "the same context must not replay the lease"
        );
        assert_eq!(
            take_process_ipc_bootstrap_for_context(&contexts, &lease, 12),
            None,
            "a later claimed context must not rebind the descriptor"
        );
    }

    unsafe fn take_vfs_output(data: *mut u8, len: u64) -> Vec<u8> {
        let bytes = if len == 0 {
            Vec::new()
        } else {
            assert!(!data.is_null());
            unsafe { std::slice::from_raw_parts(data, len as usize) }.to_vec()
        };
        ex_host_free_buffer(data, len);
        bytes
    }

    #[test]
    fn authenticated_runtime_vfs_lease_requires_exact_host_and_live_generation() {
        use crate::vfs::VfsReason;

        let _guard = host_test_lock();
        let host = crate::host::tests::example_vfs_armed_host();
        let foreign = crate::host::tests::example_vfs_armed_host();
        let context = insert_host_context(Arc::new(host.clone()), true);
        assert_ne!(context, 0);
        let nonce = NonZeroU64::new(0x4357_445f_4c45_4153).unwrap();

        assert_eq!(
            host.authenticated_runtime_vfs(nonce).unwrap_err().reason(),
            VfsReason::StaleSession,
            "a Host cannot obtain a lease before native runtime binding"
        );
        assert_eq!(
            ex_host_vfs_bind_runtime(context, nonce.get()),
            EX_HOST_VFS_RESULT_OK
        );
        let lease = host.authenticated_runtime_vfs(nonce).unwrap();
        assert_eq!(lease.capture_cwd().unwrap().virtual_path(), "/project");
        assert_eq!(
            foreign
                .authenticated_runtime_vfs(nonce)
                .unwrap_err()
                .reason(),
            VfsReason::StaleSession,
            "an equal snapshot on a foreign Host must not adopt the generation"
        );
        assert_eq!(
            host.authenticated_runtime_vfs(NonZeroU64::new(nonce.get() + 1).unwrap())
                .unwrap_err()
                .reason(),
            VfsReason::StaleSession
        );

        assert_eq!(
            ex_host_vfs_unbind_runtime(nonce.get()),
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(
            lease.capture_cwd().unwrap_err().reason(),
            VfsReason::StaleSession,
            "a retained ingress lease must not extend native generation lifetime"
        );
        assert_eq!(
            host.authenticated_runtime_vfs(nonce).unwrap_err().reason(),
            VfsReason::StaleSession
        );
        ex_host_release_context(context);
    }

    #[test]
    fn runtime_vfs_abi_isolates_two_runtime_generations_and_contexts() {
        let _guard = host_test_lock();
        let process_cwd = std::env::current_dir().unwrap();
        let root = crate::host::tests::test_project_root();
        let one_dir = root.join("runtime-vfs-one");
        let two_dir = root.join("runtime-vfs-two");
        let _ = std::fs::remove_dir_all(&one_dir);
        let _ = std::fs::remove_dir_all(&two_dir);
        std::fs::create_dir(&one_dir).unwrap();
        std::fs::create_dir(&two_dir).unwrap();

        let context_one =
            insert_host_context(Arc::new(crate::host::tests::example_vfs_armed_host()), true);
        let context_two =
            insert_host_context(Arc::new(crate::host::tests::example_vfs_armed_host()), true);
        assert_ne!(context_one, 0);
        assert_ne!(context_two, 0);
        assert_ne!(context_one, context_two);
        let nonce_one = 0x1111_2222_3333_4444;
        let nonce_two = 0x5555_6666_7777_8888;
        assert_eq!(
            ex_host_vfs_bind_runtime(context_one, nonce_one),
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(
            ex_host_vfs_bind_runtime(context_two, nonce_two),
            EX_HOST_VFS_RESULT_OK
        );

        let previous = ex_host_enter_context(context_one);
        assert_ne!(previous, u64::MAX);
        let mut virtual_data = ptr::null_mut();
        let mut virtual_len = 0;
        let mut errno = -1;
        let root_principals = [0_u64];
        assert_eq!(
            unsafe {
                ex_host_vfs_chdir(
                    nonce_one,
                    0,
                    root_principals.as_ptr(),
                    root_principals.len(),
                    b"runtime-vfs-one".as_ptr(),
                    b"runtime-vfs-one".len() as u64,
                    &mut virtual_data,
                    &mut virtual_len,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(errno, 0);
        assert_eq!(
            unsafe { take_vfs_output(virtual_data, virtual_len) },
            b"/project/runtime-vfs-one"
        );
        ex_host_restore_context(previous);

        let previous = ex_host_enter_context(context_two);
        assert_ne!(previous, u64::MAX);
        virtual_data = ptr::null_mut();
        virtual_len = 0;
        assert_eq!(
            unsafe {
                ex_host_vfs_get_cwd(
                    nonce_two,
                    0,
                    root_principals.as_ptr(),
                    root_principals.len(),
                    &mut virtual_data,
                    &mut virtual_len,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(
            unsafe { take_vfs_output(virtual_data, virtual_len) },
            b"/project"
        );

        // An exact nonce cannot be used while another runtime context is
        // selected, even though both contexts carry the same snapshot digest.
        virtual_data = ptr::null_mut();
        virtual_len = 0;
        assert_eq!(
            unsafe {
                ex_host_vfs_get_cwd(
                    nonce_one,
                    0,
                    root_principals.as_ptr(),
                    root_principals.len(),
                    &mut virtual_data,
                    &mut virtual_len,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_STALE_SESSION
        );
        assert!(virtual_data.is_null());
        assert_eq!(virtual_len, 0);
        ex_host_restore_context(previous);

        let previous = ex_host_enter_context(context_one);
        let mut backing_data = ptr::null_mut();
        let mut backing_len = 0;
        virtual_data = ptr::null_mut();
        virtual_len = 0;
        assert_eq!(
            unsafe {
                ex_host_vfs_resolve_path(
                    nonce_one,
                    b"child.txt".as_ptr(),
                    b"child.txt".len() as u64,
                    &mut backing_data,
                    &mut backing_len,
                    &mut virtual_data,
                    &mut virtual_len,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        let backing = unsafe { take_vfs_output(backing_data, backing_len) };
        let virtual_path = unsafe { take_vfs_output(virtual_data, virtual_len) };
        assert_eq!(virtual_path, b"/project/runtime-vfs-one/child.txt");
        assert!(!String::from_utf8_lossy(&virtual_path).contains(root.to_string_lossy().as_ref()));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            assert_eq!(backing, one_dir.join("child.txt").as_os_str().as_bytes());
        }

        let canonical_one = std::fs::canonicalize(&one_dir).unwrap();
        #[cfg(unix)]
        let canonical_one_bytes = {
            use std::os::unix::ffi::OsStrExt as _;
            canonical_one.as_os_str().as_bytes().to_vec()
        };
        #[cfg(not(unix))]
        let canonical_one_bytes = canonical_one.to_str().unwrap().as_bytes().to_vec();
        virtual_data = ptr::null_mut();
        virtual_len = 0;
        assert_eq!(
            unsafe {
                private_vfs_project_realpath(
                    nonce_one,
                    b"/project/runtime-vfs-one".as_ptr(),
                    b"/project/runtime-vfs-one".len() as u64,
                    canonical_one_bytes.as_ptr(),
                    canonical_one_bytes.len() as u64,
                    &mut virtual_data,
                    &mut virtual_len,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(errno, 0);
        assert_eq!(
            unsafe { take_vfs_output(virtual_data, virtual_len) },
            b"/project/runtime-vfs-one"
        );

        // A stale generation and an outside canonical identity both clear a
        // caller's preexisting output without disclosing backing bytes.
        for (nonce, backing, expected) in [
            (
                u64::MAX - 1,
                canonical_one_bytes.clone(),
                EX_HOST_VFS_RESULT_STALE_SESSION,
            ),
            ({
                let outside = std::fs::canonicalize(root.parent().unwrap()).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStrExt as _;
                    (
                        nonce_one,
                        outside.as_os_str().as_bytes().to_vec(),
                        EX_HOST_VFS_RESULT_OUTSIDE_MOUNT,
                    )
                }
                #[cfg(not(unix))]
                {
                    (
                        nonce_one,
                        outside.to_str().unwrap().as_bytes().to_vec(),
                        EX_HOST_VFS_RESULT_OUTSIDE_MOUNT,
                    )
                }
            }),
        ] {
            virtual_data = std::ptr::NonNull::<u8>::dangling().as_ptr();
            virtual_len = 99;
            assert_eq!(
                unsafe {
                    private_vfs_project_realpath(
                        nonce,
                        b"/project/runtime-vfs-one".as_ptr(),
                        b"/project/runtime-vfs-one".len() as u64,
                        backing.as_ptr(),
                        backing.len() as u64,
                        &mut virtual_data,
                        &mut virtual_len,
                        &mut errno,
                    )
                },
                expected
            );
            assert!(virtual_data.is_null());
            assert_eq!(virtual_len, 0);
        }

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            let mut canonical_unencodable = root.as_os_str().as_bytes().to_vec();
            canonical_unencodable.extend_from_slice(b"/unicode-");
            canonical_unencodable.push(0xff);
            virtual_data = std::ptr::NonNull::<u8>::dangling().as_ptr();
            virtual_len = 99;
            assert_eq!(
                unsafe {
                    private_vfs_project_realpath(
                        nonce_one,
                        b"/project/unicode-invalid".as_ptr(),
                        b"/project/unicode-invalid".len() as u64,
                        canonical_unencodable.as_ptr(),
                        canonical_unencodable.len() as u64,
                        &mut virtual_data,
                        &mut virtual_len,
                        &mut errno,
                    )
                },
                EX_HOST_VFS_RESULT_MALFORMED_INPUT
            );
            assert!(virtual_data.is_null());
            assert_eq!(virtual_len, 0);
        }
        ex_host_restore_context(previous);

        assert_eq!(ex_host_vfs_unbind_runtime(nonce_one), EX_HOST_VFS_RESULT_OK);
        assert_eq!(
            ex_host_vfs_unbind_runtime(nonce_one),
            EX_HOST_VFS_RESULT_STALE_SESSION
        );
        assert_eq!(ex_host_vfs_unbind_runtime(nonce_two), EX_HOST_VFS_RESULT_OK);
        ex_host_release_context(context_one);
        ex_host_release_context(context_two);
        assert_eq!(std::env::current_dir().unwrap(), process_cwd);
    }

    #[test]
    fn typed_fs_authorization_uses_the_vfs_union_and_stale_session_precedence() {
        let _guard = host_test_lock();
        let context =
            insert_host_context(Arc::new(crate::host::tests::example_vfs_armed_host()), true);
        assert_ne!(context, 0);
        let nonce = 0x4552_5255_4e49_4f4e;
        assert_eq!(
            ex_host_vfs_bind_runtime(context, nonce),
            EX_HOST_VFS_RESULT_OK
        );
        let previous = ex_host_enter_context(context);
        assert_ne!(previous, u64::MAX);

        let root = [0_u64];
        assert_eq!(
            unsafe {
                ex_host_authorize_typed_fs_stack(
                    nonce.wrapping_add(1),
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    u32::MAX,
                    u32::MAX,
                    -1,
                    -1,
                    0,
                    0,
                    ptr::null(),
                )
            },
            EX_HOST_VFS_RESULT_STALE_SESSION,
            "tier-zero session identity must win over malformed shape"
        );
        assert_eq!(
            unsafe {
                ex_host_authorize_typed_fs_stack(
                    nonce,
                    0,
                    root.as_ptr(),
                    root.len(),
                    ptr::null(),
                    0,
                    0,
                    -1,
                    -1,
                    0,
                    0,
                    ptr::null(),
                )
            },
            EX_HOST_VFS_RESULT_MALFORMED_INPUT
        );

        let missing = std::ffi::CString::new(
            crate::host::tests::test_project_root()
                .join("authorization-must-not-probe-missing")
                .to_string_lossy()
                .as_bytes(),
        )
        .unwrap();
        let forged = [u64::MAX - 1];
        assert_eq!(
            unsafe {
                ex_host_authorize_typed_fs_stack(
                    nonce,
                    forged[0],
                    forged.as_ptr(),
                    forged.len(),
                    missing.as_ptr(),
                    0,
                    1,
                    -1,
                    -1,
                    1,
                    0,
                    ptr::null(),
                )
            },
            EX_HOST_VFS_RESULT_POLICY_DENIED,
            "an unauthenticated principal must not be collapsed into malformed or absence"
        );

        ex_host_restore_context(previous);
        assert_eq!(ex_host_vfs_unbind_runtime(nonce), EX_HOST_VFS_RESULT_OK);
        ex_host_release_context(context);
    }

    #[test]
    fn private_typed_vfs_read_binds_bytes_to_retained_stages_and_principal_stack() {
        use capsec_semantics::model::{ObjectState, Stage};

        let _guard = host_test_lock();
        let host = Arc::new(crate::host::tests::example_vfs_armed_host());
        host.begin_conformance_observation("enforcement.test.private-typed-vfs-read");
        let context = insert_host_context(Arc::clone(&host), true);
        assert_ne!(context, 0);
        let nonce = 0x5459_5045_4452_4541;
        assert_eq!(
            ex_host_vfs_bind_runtime(context, nonce),
            EX_HOST_VFS_RESULT_OK
        );
        let previous = ex_host_enter_context(context);
        assert_ne!(previous, u64::MAX);

        let principals = [0_u64];
        let input = b"images/photo.jpg";
        let mut data = ptr::null_mut();
        let mut data_len = 0;
        let mut errno = 0;
        assert_eq!(
            unsafe {
                private_vfs_read_file_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    input.as_ptr(),
                    input.len() as u64,
                    ptr::null(),
                    0,
                    &mut data,
                    &mut data_len,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(errno, 0);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(data, data_len as usize) },
            b"test image"
        );
        ex_host_free_buffer(data, data_len);

        let observed = host.take_typed_conformance_observations();
        assert_eq!(
            observed
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
            observed
                .iter()
                .map(|row| row.decision_set.effects[0].action.as_str())
                .collect::<Vec<_>>(),
            vec!["fs:list", "fs:list", "fs:read", "fs:read"]
        );
        assert!(matches!(
            observed[0].decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                object_state: ObjectState::Unknown,
                ..
            }
        ));
        assert!(observed[1..].iter().all(|row| matches!(
            row.decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                object_state: ObjectState::Existing,
                ..
            }
        )));
        assert!(observed.iter().all(|row| {
            row.decision_set.context.actor == row.decision_set.context.constrained_principals[0]
                && row.gates.iter().all(|gate| {
                    gate.coverage_edge_id.as_str() == "surface.native.op.exactreadfile.1cmzco7"
                })
        }));

        ex_host_restore_context(previous);
        assert_eq!(ex_host_vfs_unbind_runtime(nonce), EX_HOST_VFS_RESULT_OK);
        ex_host_release_context(context);
    }

    #[test]
    fn private_typed_vfs_descriptor_reads_retain_identity_and_surface() {
        use capsec_semantics::model::Stage;

        let _guard = host_test_lock();
        let host = Arc::new(crate::host::tests::example_vfs_armed_host());
        host.begin_conformance_observation("enforcement.test.private-typed-vfs-open");
        let context = insert_host_context(Arc::clone(&host), true);
        assert_ne!(context, 0);
        let nonce = 0x5459_5045_444F_504E;
        assert_eq!(
            ex_host_vfs_bind_runtime(context, nonce),
            EX_HOST_VFS_RESULT_OK
        );
        let previous = ex_host_enter_context(context);
        assert_ne!(previous, u64::MAX);
        let principals = [0_u64];
        let mut file = ptr::null_mut();
        let mut virtual_path = ptr::null_mut();
        let mut virtual_path_len = 0;
        let mut open_errno = 0;
        assert_eq!(
            unsafe {
                private_vfs_open_read_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    b"images/photo.jpg".as_ptr(),
                    b"images/photo.jpg".len() as u64,
                    ptr::null(),
                    0,
                    &mut file,
                    &mut virtual_path,
                    &mut virtual_path_len,
                    &mut open_errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(open_errno, 0);
        assert!(!file.is_null());
        assert_eq!(
            unsafe { std::slice::from_raw_parts(virtual_path, virtual_path_len as usize) },
            b"/project/images/photo.jpg"
        );
        ex_host_free_buffer(virtual_path, virtual_path_len);

        let open_observed = host.take_typed_conformance_observations();
        assert_eq!(
            open_observed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![Stage::Requested, Stage::Discovery, Stage::Commit]
        );
        assert_eq!(
            open_observed
                .iter()
                .map(|row| row.decision_set.effects[0].action.as_str())
                .collect::<Vec<_>>(),
            vec!["fs:list", "fs:list", "fs:read"]
        );
        assert!(open_observed.iter().all(|row| row
            .decision_set
            .context
            .presented_handle_ids
            .is_empty()));

        host.begin_conformance_observation("enforcement.test.private-typed-vfs-read");
        let mut data = ptr::null_mut();
        let mut data_len = 0;
        let mut read_errno = 0;
        assert_eq!(
            unsafe {
                private_vfs_read_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    file,
                    5,
                    1,
                    5,
                    &mut data,
                    &mut data_len,
                    &mut read_errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(read_errno, 0);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(data, data_len as usize) },
            b"image"
        );
        ex_host_free_buffer(data, data_len);
        let read_observed = host.take_typed_conformance_observations();
        assert_eq!(read_observed.len(), 1);
        assert_eq!(read_observed[0].decision_set.context.stage, Stage::Repeat);
        assert_eq!(
            read_observed[0].decision_set.effects[0].action.as_str(),
            "fs:read"
        );
        assert!(read_observed[0].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsread.1ixlwve"
        }));
        assert!(read_observed[0]
            .decision_set
            .context
            .presented_handle_ids
            .is_empty());

        host.begin_conformance_observation("enforcement.test.private-typed-vfs-readv");
        let mut vector_data = ptr::null_mut();
        let mut vector_data_len = 0;
        let mut readv_errno = 0;
        assert_eq!(
            unsafe {
                private_vfs_readv_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    file,
                    4,
                    1,
                    0,
                    &mut vector_data,
                    &mut vector_data_len,
                    &mut readv_errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(readv_errno, 0);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(vector_data, vector_data_len as usize) },
            b"test"
        );
        ex_host_free_buffer(vector_data, vector_data_len);
        let readv_observed = host.take_typed_conformance_observations();
        assert_eq!(readv_observed.len(), 1);
        assert_eq!(readv_observed[0].decision_set.context.stage, Stage::Repeat);
        assert_eq!(
            readv_observed[0].decision_set.effects[0].action.as_str(),
            "fs:read"
        );
        assert!(readv_observed[0].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsreadv.11moytw"
        }));

        host.begin_conformance_observation("enforcement.test.private-typed-vfs-fstat");
        let mut json = ptr::null_mut();
        let mut json_len = 0;
        let mut fstat_errno = 0;
        assert_eq!(
            unsafe {
                private_vfs_fstat_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    file,
                    &mut json,
                    &mut json_len,
                    &mut fstat_errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(fstat_errno, 0);
        let metadata: serde_json::Value =
            serde_json::from_slice(unsafe { std::slice::from_raw_parts(json, json_len as usize) })
                .unwrap();
        ex_host_free_buffer(json, json_len);
        assert_eq!(metadata["size"], 10);
        let fstat_observed = host.take_typed_conformance_observations();
        assert_eq!(fstat_observed.len(), 1);
        assert_eq!(fstat_observed[0].decision_set.context.stage, Stage::Repeat);
        assert_eq!(
            fstat_observed[0].decision_set.effects[0].action.as_str(),
            "fs:list"
        );
        assert!(fstat_observed[0]
            .decision_set
            .context
            .presented_handle_ids
            .is_empty());

        ex_host_fs_close(file);
        ex_host_restore_context(previous);
        assert_eq!(ex_host_vfs_unbind_runtime(nonce), EX_HOST_VFS_RESULT_OK);
        ex_host_release_context(context);
    }

    #[test]
    fn private_typed_vfs_existing_append_repeats_write_without_creating_absent_paths() {
        use capsec_semantics::model::Stage;

        let _guard = host_test_lock();
        let fixture = tempfile::Builder::new()
            .prefix("typed-vfs-append-")
            .tempdir_in(crate::host::tests::test_project_root())
            .unwrap();
        let relative_dir = fixture.path().file_name().unwrap().to_str().unwrap();
        let relative = format!("{relative_dir}/append.txt");
        let virtual_expected = format!("/project/{relative}");
        let live = fixture.path().join("append.txt");
        std::fs::write(&live, b"prefix").unwrap();

        let host = Arc::new(crate::host::tests::example_vfs_armed_host());
        host.begin_conformance_observation("enforcement.test.private-typed-vfs-append-open");
        let context = insert_host_context(Arc::clone(&host), true);
        assert_ne!(context, 0);
        let nonce = 0x5459_5045_4441_5050;
        assert_eq!(
            ex_host_vfs_bind_runtime(context, nonce),
            EX_HOST_VFS_RESULT_OK
        );
        let previous = ex_host_enter_context(context);
        assert_ne!(previous, u64::MAX);
        let principals = [0_u64];
        let mut file = ptr::null_mut();
        let mut virtual_path = ptr::null_mut();
        let mut virtual_path_len = 0;
        let mut errno = 0;
        assert_eq!(
            unsafe {
                private_vfs_open_append_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    relative.as_ptr(),
                    relative.len() as u64,
                    ptr::null(),
                    0,
                    &mut file,
                    &mut virtual_path,
                    &mut virtual_path_len,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(errno, 0);
        assert!(!file.is_null());
        assert_eq!(
            unsafe { std::slice::from_raw_parts(virtual_path, virtual_path_len as usize) },
            virtual_expected.as_bytes()
        );
        ex_host_free_buffer(virtual_path, virtual_path_len);
        let open_observed = host.take_typed_conformance_observations();
        assert_eq!(
            open_observed
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
            ]
        );
        assert!(open_observed.iter().all(|row| row.gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfsopen.05ao6wa"
        })));

        host.begin_conformance_observation("enforcement.test.private-typed-vfs-append-write");
        let suffix = b"-suffix";
        let mut written = 0;
        assert_eq!(
            unsafe {
                private_vfs_write_append_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    file,
                    suffix.as_ptr(),
                    suffix.len() as u32,
                    &mut written,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(errno, 0);
        assert_eq!(written, suffix.len() as u32);
        assert_eq!(std::fs::read(&live).unwrap(), b"prefix-suffix");
        let write_observed = host.take_typed_conformance_observations();
        assert_eq!(write_observed.len(), 1);
        assert_eq!(write_observed[0].decision_set.context.stage, Stage::Repeat);
        assert_eq!(
            write_observed[0].decision_set.effects[0].action.as_str(),
            "fs:write"
        );
        assert!(write_observed[0].gates.iter().all(|gate| {
            gate.coverage_edge_id.as_str() == "surface.native.op.exactfswrite.1locgj1"
        }));

        host.begin_conformance_observation("enforcement.test.private-typed-vfs-empty-write");
        written = u32::MAX;
        assert_eq!(
            unsafe {
                private_vfs_write_async_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    file,
                    ptr::null(),
                    0,
                    &mut written,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(written, 0);
        assert!(host.take_typed_conformance_observations().is_empty());

        for (label, bytes, bridge, expected_edge) in [
            (
                "enforcement.test.private-typed-vfs-async-write",
                b"-async".as_slice(),
                private_vfs_write_async_typed
                    as unsafe extern "C" fn(
                        u64,
                        u64,
                        *const u64,
                        usize,
                        *mut ExactFileHandle,
                        *const u8,
                        u32,
                        *mut u32,
                        *mut i32,
                    ) -> u32,
                "surface.native.op.exactfswriteasync.0f1ap1j",
            ),
            (
                "enforcement.test.private-typed-vfs-async-writev",
                b"-vector".as_slice(),
                private_vfs_writev_async_typed
                    as unsafe extern "C" fn(
                        u64,
                        u64,
                        *const u64,
                        usize,
                        *mut ExactFileHandle,
                        *const u8,
                        u32,
                        *mut u32,
                        *mut i32,
                    ) -> u32,
                "surface.native.op.exactfswritevasync.0l050fv",
            ),
        ] {
            host.begin_conformance_observation(label);
            written = 0;
            assert_eq!(
                unsafe {
                    bridge(
                        nonce,
                        0,
                        principals.as_ptr(),
                        principals.len(),
                        file,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                        &mut written,
                        &mut errno,
                    )
                },
                EX_HOST_VFS_RESULT_OK
            );
            assert_eq!(written, bytes.len() as u32);
            let observed = host.take_typed_conformance_observations();
            assert_eq!(observed.len(), 1);
            assert_eq!(observed[0].decision_set.context.stage, Stage::Repeat);
            assert_eq!(
                observed[0].decision_set.effects[0].action.as_str(),
                "fs:write"
            );
            assert!(observed[0]
                .gates
                .iter()
                .all(|gate| gate.coverage_edge_id.as_str() == expected_edge));
        }
        assert_eq!(std::fs::read(&live).unwrap(), b"prefix-suffix-async-vector");

        for (label, bridge, expected_edge) in [
            (
                "enforcement.test.private-typed-vfs-fsync",
                private_vfs_fsync_typed
                    as unsafe extern "C" fn(
                        u64,
                        u64,
                        *const u64,
                        usize,
                        *mut ExactFileHandle,
                        *mut i32,
                    ) -> u32,
                "surface.native.op.exactfsfsyncsync.02nw7ns",
            ),
            (
                "enforcement.test.private-typed-vfs-fdatasync",
                private_vfs_fdatasync_typed
                    as unsafe extern "C" fn(
                        u64,
                        u64,
                        *const u64,
                        usize,
                        *mut ExactFileHandle,
                        *mut i32,
                    ) -> u32,
                "surface.native.op.exactfsfdatasyncsync.1p6q71s",
            ),
        ] {
            host.begin_conformance_observation(label);
            assert_eq!(
                unsafe {
                    bridge(
                        nonce,
                        0,
                        principals.as_ptr(),
                        principals.len(),
                        file,
                        &mut errno,
                    )
                },
                EX_HOST_VFS_RESULT_OK
            );
            let observed = host.take_typed_conformance_observations();
            assert_eq!(observed.len(), 1);
            assert_eq!(observed[0].decision_set.context.stage, Stage::Repeat);
            assert_eq!(
                observed[0].decision_set.effects[0].action.as_str(),
                "fs:write"
            );
            assert!(observed[0]
                .gates
                .iter()
                .all(|gate| gate.coverage_edge_id.as_str() == expected_edge));
        }
        ex_host_fs_close(file);

        host.begin_conformance_observation("enforcement.test.private-typed-vfs-append-absent");
        let absent_relative = format!("{relative_dir}/absent.txt");
        file = ptr::null_mut();
        virtual_path = ptr::null_mut();
        virtual_path_len = 0;
        assert_eq!(
            unsafe {
                private_vfs_open_append_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    absent_relative.as_ptr(),
                    absent_relative.len() as u64,
                    ptr::null(),
                    0,
                    &mut file,
                    &mut virtual_path,
                    &mut virtual_path_len,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_ABSENT
        );
        assert!(file.is_null());
        assert!(virtual_path.is_null());
        assert_eq!(virtual_path_len, 0);
        assert!(!fixture.path().join("absent.txt").exists());
        let absent_observed = host.take_typed_conformance_observations();
        assert_eq!(
            absent_observed
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

        ex_host_restore_context(previous);
        assert_eq!(ex_host_vfs_unbind_runtime(nonce), EX_HOST_VFS_RESULT_OK);
        ex_host_release_context(context);
    }

    #[cfg(unix)]
    #[test]
    fn private_typed_vfs_append_refuses_authenticated_package_hardlink_at_commit() {
        use capsec_semantics::model::Stage;

        let _guard = host_test_lock();
        let fixture = tempfile::Builder::new()
            .prefix("typed-vfs-append-package-hardlink-")
            .tempdir_in(crate::host::tests::test_project_root())
            .unwrap();
        let relative_dir = fixture.path().file_name().unwrap().to_str().unwrap();
        let (_package_fixture, host, package_root, _) =
            crate::host::tests::example_unique_package_host(
                br#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
                &[("index.js", b"module.exports = true;\n")],
            );
        let host = Arc::new(host);
        let package_source = package_root.join("index.js");
        let package_bytes = std::fs::read(&package_source).unwrap();
        let hardlink = fixture.path().join("package-hardlink.js");
        std::fs::hard_link(&package_source, &hardlink).unwrap();
        let hardlink_relative = format!("{relative_dir}/package-hardlink.js");

        host.begin_conformance_observation(
            "enforcement.test.private-typed-vfs-append-package-hardlink",
        );
        let context = insert_host_context(Arc::clone(&host), true);
        assert_ne!(context, 0);
        let nonce = 0x5459_5045_4441_5048;
        assert_eq!(
            ex_host_vfs_bind_runtime(context, nonce),
            EX_HOST_VFS_RESULT_OK
        );
        let previous = ex_host_enter_context(context);
        assert_ne!(previous, u64::MAX);
        let principals = [0_u64];
        let mut file = ptr::null_mut();
        let mut virtual_path = ptr::null_mut();
        let mut virtual_path_len = 0;
        let mut errno = 0;
        assert_eq!(
            unsafe {
                private_vfs_open_append_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    hardlink_relative.as_ptr(),
                    hardlink_relative.len() as u64,
                    ptr::null(),
                    0,
                    &mut file,
                    &mut virtual_path,
                    &mut virtual_path_len,
                    &mut errno,
                )
            },
            EX_HOST_VFS_RESULT_POLICY_DENIED
        );
        assert!(file.is_null());
        assert!(virtual_path.is_null());
        assert_eq!(virtual_path_len, 0);
        assert_eq!(std::fs::read(&hardlink).unwrap(), package_bytes);
        assert_eq!(std::fs::read(&package_source).unwrap(), package_bytes);
        let observed = host.take_typed_conformance_observations();
        assert_eq!(
            observed
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
            ]
        );
        assert!(matches!(
            &observed[3].decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                final_object_generation: Some(_),
                ..
            }
        ));

        ex_host_restore_context(previous);
        assert_eq!(ex_host_vfs_unbind_runtime(nonce), EX_HOST_VFS_RESULT_OK);
        ex_host_release_context(context);
    }

    #[test]
    fn private_typed_vfs_stat_binds_file_and_mount_root_metadata_to_retained_stages() {
        use capsec_semantics::model::{FollowMode, ObjectState, Stage};

        let _guard = host_test_lock();
        let host = Arc::new(crate::host::tests::example_vfs_armed_host());
        host.begin_conformance_observation("enforcement.test.private-typed-vfs-stat-file");
        let context = insert_host_context(Arc::clone(&host), true);
        assert_ne!(context, 0);
        let nonce = 0x5459_5045_4453_5441;
        assert_eq!(
            ex_host_vfs_bind_runtime(context, nonce),
            EX_HOST_VFS_RESULT_OK
        );
        let previous = ex_host_enter_context(context);
        assert_ne!(previous, u64::MAX);
        let principals = [0_u64];

        let call_stat = |input: &[u8]| {
            let mut json = ptr::null_mut();
            let mut json_len = 0;
            let mut errno = 0;
            assert_eq!(
                unsafe {
                    private_vfs_stat_typed(
                        nonce,
                        0,
                        principals.as_ptr(),
                        principals.len(),
                        input.as_ptr(),
                        input.len() as u64,
                        ptr::null(),
                        0,
                        &mut json,
                        &mut json_len,
                        &mut errno,
                    )
                },
                EX_HOST_VFS_RESULT_OK
            );
            assert_eq!(errno, 0);
            let value: serde_json::Value = serde_json::from_slice(unsafe {
                std::slice::from_raw_parts(json, json_len as usize)
            })
            .unwrap();
            ex_host_free_buffer(json, json_len);
            value
        };

        let file = call_stat(b"images/photo.jpg");
        assert_eq!(file["size"], 10);
        assert_eq!(file["is_file"], true);
        assert_eq!(file["is_dir"], false);
        let observed = host.take_typed_conformance_observations();
        assert_eq!(
            observed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![Stage::Requested, Stage::Discovery, Stage::Repeat]
        );
        assert!(observed
            .iter()
            .all(|row| row.decision_set.effects[0].action.as_str() == "fs:list"));
        assert!(matches!(
            observed[0].decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                object_state: ObjectState::Unknown,
                ..
            }
        ));
        assert!(observed[1..].iter().all(|row| matches!(
            row.decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                object_state: ObjectState::Existing,
                ..
            }
        )));
        assert!(observed.iter().all(|row| {
            row.gates
                .iter()
                .all(|gate| gate.coverage_edge_id.as_str() == "surface.native.op.exactstat.1432ztv")
        }));

        host.begin_conformance_observation("enforcement.test.private-typed-vfs-stat-root");
        let root = call_stat(b"/project");
        assert_eq!(root["is_dir"], true);
        assert_eq!(root["is_file"], false);
        let root_observed = host.take_typed_conformance_observations();
        assert_eq!(
            root_observed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![Stage::Requested, Stage::Discovery, Stage::Repeat]
        );
        assert!(root_observed[1..].iter().all(|row| matches!(
            &row.decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                parent_object: None,
                final_object: Some(_),
                ..
            }
        )));

        host.begin_conformance_observation("enforcement.test.private-typed-vfs-lstat-file");
        let mut lstat_json = ptr::null_mut();
        let mut lstat_json_len = 0;
        let mut lstat_errno = 0;
        assert_eq!(
            unsafe {
                private_vfs_lstat_typed(
                    nonce,
                    0,
                    principals.as_ptr(),
                    principals.len(),
                    b"images/photo.jpg".as_ptr(),
                    b"images/photo.jpg".len() as u64,
                    ptr::null(),
                    0,
                    &mut lstat_json,
                    &mut lstat_json_len,
                    &mut lstat_errno,
                )
            },
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(lstat_errno, 0);
        let lstat: serde_json::Value = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(lstat_json, lstat_json_len as usize)
        })
        .unwrap();
        ex_host_free_buffer(lstat_json, lstat_json_len);
        assert_eq!(lstat["is_file"], true);
        let lstat_observed = host.take_typed_conformance_observations();
        assert_eq!(
            lstat_observed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![Stage::Requested, Stage::Discovery, Stage::Repeat]
        );
        assert!(lstat_observed.iter().all(|row| matches!(
            &row.decision_set.effects[0].resource,
            capsec_semantics::model::OccurrenceResource::PathOccurrence {
                follow_mode: FollowMode::NoFollowFinal,
                ..
            }
        )));
        assert!(lstat_observed.iter().all(|row| {
            row.gates.iter().all(|gate| {
                gate.coverage_edge_id.as_str() == "surface.native.op.exactlstat.1c98s6l"
            })
        }));

        ex_host_restore_context(previous);
        assert_eq!(ex_host_vfs_unbind_runtime(nonce), EX_HOST_VFS_RESULT_OK);
        ex_host_release_context(context);
    }

    #[test]
    fn generated_vfs_union_corpus_executes_every_projection_and_precedence_pair() {
        use crate::vfs::VfsReason;

        fn reason(id: &str) -> VfsReason {
            match id {
                "stale-session" => VfsReason::StaleSession,
                "closed-operation" => VfsReason::ClosedOperation,
                "malformed-input" => VfsReason::MalformedInput,
                "encoded-separator" => VfsReason::EncodedSeparator,
                "outside-mount" => VfsReason::OutsideMount,
                "synthetic-node" => VfsReason::SyntheticNode,
                "policy-denied" => VfsReason::PolicyDenied,
                "absent" => VfsReason::Absent,
                "symlink-depth" => VfsReason::SymlinkDepthExceeded,
                "unmappable-link" => VfsReason::UnmappableLink,
                "stale-identity" => VfsReason::StaleIdentity,
                "input-too-large" => VfsReason::InputTooLarge,
                "host-error" => VfsReason::HostError,
                other => panic!("unknown generated VFS reason {other}"),
            }
        }

        let union: serde_json::Value = serde_json::from_str(include_str!(
            "../../llp/fixtures/0023-vfs-error-union.v1.json"
        ))
        .unwrap();
        for entry in union["reasons"].as_array().unwrap() {
            let reason = reason(entry["id"].as_str().unwrap());
            assert_eq!(
                vfs_reason_discriminant(reason),
                entry["discriminant"].as_u64().unwrap() as u32
            );
            assert_eq!(reason.stable_code(), entry["code"].as_str().unwrap());
            assert_eq!(
                reason.precedence_rank(),
                entry["precedence"].as_u64().unwrap() as u8
            );
        }

        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../llp/fixtures/0023-vfs-error-precedence.generated.json"
        ))
        .unwrap();
        assert_eq!(corpus["reasonCount"], 13);
        assert_eq!(corpus["pairCount"], 78);
        for pair in corpus["pairs"].as_array().unwrap() {
            let contenders = pair["contenders"].as_array().unwrap();
            let left = reason(contenders[0].as_str().unwrap());
            let right = reason(contenders[1].as_str().unwrap());
            let winner = reason(pair["winner"].as_str().unwrap());
            assert_eq!(left.dominant(right), winner, "{}", pair["id"]);
            assert_eq!(right.dominant(left), winner, "{}", pair["id"]);
            assert_eq!(winner.stable_code(), pair["winnerCode"]);
            assert_eq!(
                vfs_reason_discriminant(winner),
                pair["winnerDiscriminant"].as_u64().unwrap() as u32
            );
        }
    }

    #[test]
    fn runtime_vfs_bind_rejects_stale_project_identity_without_publishing() {
        let _guard = host_test_lock();
        let fixture = tempfile::Builder::new()
            .prefix("runtime-vfs-stale-project-")
            .tempdir_in(crate::host::tests::test_project_root())
            .unwrap();
        let project_root = fixture.path().join("project");
        let package_root = project_root.join("node_modules/image-lib");
        std::fs::create_dir_all(&package_root).unwrap();
        let host = crate::host::tests::example_vfs_armed_host_with(|snapshot| {
            for binding in snapshot["rootBindings"].as_array_mut().unwrap() {
                let path = match binding["logicalRoot"].as_str().unwrap() {
                    "project" => &project_root,
                    "package" => &package_root,
                    _ => continue,
                };
                binding["hostPath"]["components"] =
                    serde_json::to_value(crate::host::host_path_components(path).unwrap()).unwrap();
                binding["object"] =
                    serde_json::to_value(crate::host::object_identity_for_host_path(path).unwrap())
                        .unwrap();
            }
        });
        let armed_project_object = host
            .armed_snapshot()
            .unwrap()
            .root_bindings()
            .unwrap()
            .iter()
            .find(|binding| {
                binding.logical_root == capsec_semantics::model::LogicalRoot::Project
                    && binding.owner.is_none()
            })
            .unwrap()
            .object
            .clone();
        let stale_project_root = fixture.path().join("stale-project");
        std::fs::rename(&project_root, &stale_project_root).unwrap();
        std::fs::create_dir_all(project_root.join("node_modules/image-lib")).unwrap();
        let replacement_project_object =
            crate::host::object_identity_for_host_path(&project_root).unwrap();
        assert_eq!(
            replacement_project_object.platform,
            armed_project_object.platform
        );
        assert_eq!(
            replacement_project_object.volume,
            armed_project_object.volume
        );
        assert_ne!(replacement_project_object.file, armed_project_object.file);

        let context_id = insert_host_context(Arc::new(host), true);
        assert_ne!(context_id, 0);
        let runtime_nonce = 0x8877_6655_4433_2211;

        assert_eq!(
            ex_host_vfs_bind_runtime(context_id, runtime_nonce),
            EX_HOST_VFS_RESULT_STALE_IDENTITY
        );
        assert_eq!(
            runtime_vfs_session(runtime_nonce, "regression")
                .unwrap_err()
                .reason(),
            crate::vfs::VfsReason::StaleSession
        );
        let runtime_nonce_recorded = HOST_CONTEXTS
            .get()
            .and_then(|contexts| contexts.read().ok())
            .and_then(|contexts| {
                contexts
                    .get(&context_id)
                    .map(|context| context.runtime_nonce)
            });
        assert_eq!(runtime_nonce_recorded, Some(None));

        ex_host_release_context(context_id);

        // A failed bind must not reserve the runtime generation in the session
        // registry. A fresh authenticated context can use that exact nonce and
        // then tear it down normally.
        let recovery_context =
            insert_host_context(Arc::new(crate::host::tests::example_vfs_armed_host()), true);
        assert_ne!(recovery_context, 0);
        assert_eq!(
            ex_host_vfs_bind_runtime(recovery_context, runtime_nonce),
            EX_HOST_VFS_RESULT_OK
        );
        assert_eq!(
            ex_host_vfs_unbind_runtime(runtime_nonce),
            EX_HOST_VFS_RESULT_OK
        );
        ex_host_release_context(recovery_context);
    }

    #[test]
    fn armed_module_metadata_serializes_only_typed_virtual_paths() {
        let typed_path: crate::vfs::ResolverLogicalPath =
            serde_json::from_value(serde_json::json!({
                "schema": "ibex/logical-path/1",
                "sessionHandle": "mrs0000000000000001",
                "virtualPath": "/project/node_modules/image-lib/index.js",
                "logicalPath": {
                    "root": "package",
                    "components": [{ "encoding": "utf8", "value": "index.js" }],
                    "hostBound": null,
                },
                "bindingOwner": {
                    "kind": "package",
                    "name": "image-lib",
                    "locator": "image-lib@2.4.1",
                    "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
                },
            }))
            .unwrap();
        let typed_root: crate::vfs::ResolverLogicalPath =
            serde_json::from_value(serde_json::json!({
                "schema": "ibex/logical-path/1",
                "sessionHandle": "mrs0000000000000001",
                "virtualPath": "/project/node_modules/image-lib",
                "logicalPath": {
                    "root": "package",
                    "components": [],
                    "hostBound": null,
                },
                "bindingOwner": {
                    "kind": "package",
                    "name": "image-lib",
                    "locator": "image-lib@2.4.1",
                    "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
                },
            }))
            .unwrap();
        let module = crate::module_loader::ResolvedModule {
            artifact_source_id: None,
            id: "/private/host/project/node_modules/image-lib/index.js".into(),
            kind: crate::module_loader::ModuleKind::CommonJs,
            path: Some("/private/host/project/node_modules/image-lib/index.js".into()),
            source: Some("module.exports = 1".into()),
            package_name: Some("image-lib".into()),
            package_root: Some("/private/host/project/node_modules/image-lib".into()),
            package_version: Some("2.4.1".into()),
            package_integrity: Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA".into()),
            source_id: None,
            source_label: None,
            virtual_path: Some("/project/node_modules/image-lib/index.js".into()),
            resolver_path: Some(typed_path),
            resolver_package_root: Some(typed_root),
            private_resolver_path: None,
            private_resolver_package_root: None,
        };

        let value = module_meta_json(&module);
        let encoded = value.to_string();
        assert_eq!(value["schema"], "ibex/module-resolution/1");
        assert_eq!(value["id"], "/project/node_modules/image-lib/index.js");
        assert_eq!(value["path"]["schema"], "ibex/logical-path/1");
        assert_eq!(value["path"]["sessionHandle"], "mrs0000000000000001");
        assert_eq!(
            value["pkgRoot"]["virtualPath"],
            "/project/node_modules/image-lib"
        );
        assert!(!encoded.contains("/private/host"));
    }

    #[test]
    fn unarmed_module_metadata_serializes_only_opaque_resolver_handles() {
        let private_path = crate::module_loader::PrivateResolverPath::new(
            "mrs0000000000000001".into(),
            "r0000000000000001".into(),
            "/project/.ibex-resolver/r0000000000000001".into(),
        )
        .unwrap();
        let private_root = crate::module_loader::PrivateResolverPath::new(
            "mrs0000000000000001".into(),
            "r0000000000000002".into(),
            "/project/.ibex-resolver/r0000000000000002".into(),
        )
        .unwrap();
        let module = crate::module_loader::ResolvedModule {
            artifact_source_id: None,
            id: "/private/host/project/node_modules/image-lib/index.js".into(),
            kind: crate::module_loader::ModuleKind::CommonJs,
            path: Some("/private/host/project/node_modules/image-lib/index.js".into()),
            source: Some("module.exports = 1".into()),
            package_name: Some("image-lib".into()),
            package_root: Some("/private/host/project/node_modules/image-lib".into()),
            package_version: Some("2.4.1".into()),
            package_integrity: None,
            source_id: None,
            source_label: None,
            virtual_path: None,
            resolver_path: None,
            resolver_package_root: None,
            private_resolver_path: Some(private_path),
            private_resolver_package_root: Some(private_root),
        };

        let value = module_meta_json(&module);
        let encoded = value.to_string();
        assert_eq!(value["schema"], "ibex/module-resolution/1");
        assert_eq!(value["path"]["schema"], "ibex/private-resolver-ref/1");
        assert_eq!(value["path"]["sessionHandle"], "mrs0000000000000001");
        assert_eq!(
            value["pkgRoot"]["virtualPath"],
            "/project/.ibex-resolver/r0000000000000002"
        );
        assert!(!encoded.contains("/private/host"));
        assert!(!encoded.contains("node_modules/image-lib"));
    }

    #[test]
    fn module_resolution_errors_never_serialize_native_diagnostic_paths() {
        let error =
            anyhow::anyhow!("failed to resolve /private/host/project/node_modules/secret/index.js");
        let value = module_resolution_error_json(&error);
        let encoded = value.to_string();
        assert_eq!(value["schema"], "ibex/module-resolution/1");
        assert_eq!(value["errorCode"], "ERR_IBEX_MODULE_RESOLUTION");
        assert_eq!(value["error"], "Module resolution failed");
        assert!(!encoded.contains("/private/host"));
        assert!(!encoded.contains("secret/index.js"));
    }

    #[test]
    fn terminal_stdio_query_is_scoped_and_updates_dimensions_atomically() {
        let _lock = host_test_lock();
        let mut is_tty = -1;
        let mut columns = u16::MAX;
        let mut rows = u16::MAX;

        assert_eq!(
            unsafe {
                ex_host_terminal_session_stdio_query(1, &mut is_tty, &mut columns, &mut rows)
            },
            0
        );

        let guard = arm_terminal_session_stdio_query(false, true, true).unwrap();
        assert!(arm_terminal_session_stdio_query(false, true, true).is_err());
        assert_eq!(
            unsafe {
                ex_host_terminal_session_stdio_query(0, &mut is_tty, &mut columns, &mut rows)
            },
            1
        );
        assert_eq!((is_tty, columns, rows), (0, 0, 0));

        guard.update_dimensions(173, 61);
        assert_eq!(
            unsafe {
                ex_host_terminal_session_stdio_query(2, &mut is_tty, &mut columns, &mut rows)
            },
            1
        );
        assert_eq!((is_tty, columns, rows), (1, 173, 61));
        assert_eq!(
            unsafe {
                ex_host_terminal_session_stdio_query(9, &mut is_tty, &mut columns, &mut rows)
            },
            -1
        );

        drop(guard);
        assert_eq!(
            unsafe {
                ex_host_terminal_session_stdio_query(1, &mut is_tty, &mut columns, &mut rows)
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_host_terminal_session_stdio_query(9, &mut is_tty, &mut columns, &mut rows)
            },
            -1
        );
    }

    #[test]
    fn terminal_session_output_close_guard_is_exclusive_and_fd_scoped() {
        assert_eq!(ex_host_terminal_session_close_is_noop(0), 0);
        assert_eq!(ex_host_terminal_session_close_is_noop(1), 0);
        let guard = arm_terminal_session_output_close_guard().unwrap();
        assert_eq!(ex_host_terminal_session_close_is_noop(0), 0);
        assert_eq!(ex_host_terminal_session_close_is_noop(1), 1);
        assert_eq!(ex_host_terminal_session_close_is_noop(2), 1);
        assert_eq!(ex_host_terminal_session_close_is_noop(3), 0);
        assert!(arm_terminal_session_output_close_guard().is_err());
        drop(guard);
        assert_eq!(ex_host_terminal_session_close_is_noop(1), 0);

        let policy = arm_terminal_session_descriptor_policy(true, [6, 3, 5]).unwrap();
        assert_eq!(ex_host_session_descriptor_read_route(0), 1);
        assert_eq!(ex_host_session_descriptor_read_route(1), 0);
        assert_eq!(ex_host_session_descriptor_read_route(3), -1);
        assert_eq!(ex_host_session_descriptor_write_route(1), 0);
        assert_eq!(ex_host_session_descriptor_write_route(5), -1);
        assert_eq!(ex_host_session_descriptor_close_route(0), 1);
        assert_eq!(ex_host_session_descriptor_close_route(1), 1);
        assert_eq!(ex_host_session_descriptor_close_route(6), -1);
        assert_eq!(ex_host_session_descriptor_alias_source_route(0), 1);
        assert_eq!(ex_host_session_descriptor_alias_source_route(1), -1);
        assert_eq!(ex_host_session_descriptor_alias_target_route(2), -1);
        assert_eq!(ex_host_session_descriptor_alias_target_route(7), 0);
        assert_eq!(ex_host_session_descriptor_is_protected(3), 1);
        assert_eq!(ex_host_session_descriptor_is_protected(4), 0);
        assert!(arm_terminal_session_descriptor_policy(true, [8]).is_err());
        drop(policy);
        assert_eq!(ex_host_session_descriptor_read_route(0), 0);
        assert_eq!(ex_host_session_descriptor_close_route(1), 0);
        assert_eq!(ex_host_session_descriptor_is_protected(3), 0);
        assert!(arm_terminal_session_descriptor_policy(false, [0]).is_err());
        assert!(arm_terminal_session_descriptor_policy(false, [7, 7]).is_err());
    }

    #[test]
    fn authenticated_worker_lifecycle_port_is_exclusive_scoped_and_panic_closed() {
        let _lock = host_test_lock();
        assert!(authenticated_worker_lifecycle_port().unwrap().is_none());

        let mirrored = Arc::new(Mutex::new(Vec::new()));
        let committed = Arc::new(Mutex::new(Vec::new()));
        let mirror_sink = Arc::clone(&mirrored);
        let commit_sink = Arc::clone(&committed);
        let guard =
            install_authenticated_worker_lifecycle_port(AuthenticatedWorkerLifecyclePort::new(
                move |mutation| {
                    mirror_sink.lock().unwrap().push(mutation);
                    WorkerLifecycleAcknowledgement::Acknowledged
                },
                move |commit| {
                    commit_sink.lock().unwrap().push(commit);
                    WorkerLifecycleAcknowledgement::Acknowledged
                },
            ))
            .unwrap();
        assert!(install_authenticated_worker_lifecycle_port(
            AuthenticatedWorkerLifecyclePort::new(
                |_| WorkerLifecycleAcknowledgement::Acknowledged,
                |_| WorkerLifecycleAcknowledgement::Acknowledged,
            ),
        )
        .is_err());

        let port = authenticated_worker_lifecycle_port().unwrap().unwrap();
        let mutation = AuthorizedWorkerExitCodeMirror { status: 73 };
        let commit = AuthorizedWorkerLifecycleCommit {
            request_id: 19,
            status: 7,
        };
        assert_eq!(
            port.mirror_exit_code(mutation),
            WorkerLifecycleAcknowledgement::Acknowledged
        );
        assert_eq!(
            port.commit_lifecycle(commit),
            WorkerLifecycleAcknowledgement::Acknowledged
        );
        assert_eq!(&*mirrored.lock().unwrap(), &[mutation]);
        assert_eq!(&*committed.lock().unwrap(), &[commit]);

        drop(guard);
        assert!(authenticated_worker_lifecycle_port().unwrap().is_none());

        let guard =
            install_authenticated_worker_lifecycle_port(AuthenticatedWorkerLifecyclePort::new(
                |_| panic!("mirror callback panic"),
                |_| panic!("commit callback panic"),
            ))
            .unwrap();
        let port = authenticated_worker_lifecycle_port().unwrap().unwrap();
        assert_eq!(
            port.mirror_exit_code(mutation),
            WorkerLifecycleAcknowledgement::Unacknowledged
        );
        assert_eq!(
            port.commit_lifecycle(commit),
            WorkerLifecycleAcknowledgement::Unacknowledged
        );
        drop(guard);
    }

    #[test]
    fn acknowledged_worker_lifecycle_commit_parks_without_returning() {
        let (commit_tx, commit_rx) = std::sync::mpsc::channel();
        let port = Arc::new(AuthenticatedWorkerLifecyclePort::new(
            |_| WorkerLifecycleAcknowledgement::Acknowledged,
            move |commit| {
                commit_tx.send(commit).unwrap();
                WorkerLifecycleAcknowledgement::Acknowledged
            },
        ));
        let commit = AuthorizedWorkerLifecycleCommit {
            request_id: 23,
            status: 9,
        };
        let worker = std::thread::spawn(move || commit_worker_lifecycle_and_park(port, commit));

        assert_eq!(
            commit_rx.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(commit)
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
        assert!(!worker.is_finished());
        drop(worker);
    }

    #[test]
    fn unacknowledged_worker_lifecycle_commit_uses_reserved_status() {
        const CHILD_SENTINEL: &str = "IBEX_TEST_UNACKNOWLEDGED_WORKER_LIFECYCLE_COMMIT";
        if std::env::var_os(CHILD_SENTINEL).is_some() {
            let port = Arc::new(AuthenticatedWorkerLifecyclePort::new(
                |_| WorkerLifecycleAcknowledgement::Unacknowledged,
                |_| WorkerLifecycleAcknowledgement::Unacknowledged,
            ));
            commit_worker_lifecycle_and_park(
                port,
                AuthorizedWorkerLifecycleCommit {
                    request_id: 29,
                    status: 11,
                },
            );
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("host::abi::tests::unacknowledged_worker_lifecycle_commit_uses_reserved_status")
            .env(CHILD_SENTINEL, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(crate::session_constants::EXIT_STATUS_WORKER_COMMIT_UNACKNOWLEDGED)
        );
    }

    // The inline decimal rendering must agree byte-for-byte with the
    // `u64::to_string` keying the capability manager has always used, across
    // the special principals (root 0, kNoUserPrincipal, kRuntimePackageId) and
    // the extremes. (ENG-22644)
    #[test]
    fn principal_id_buf_matches_to_string() {
        for id in [
            0u64,
            1,
            9,
            10,
            42,
            0xFFFF_FFFE, // kNoUserPrincipal (4294967294)
            0xFFFF_FFFF, // runtime principal
            u64::MAX,
        ] {
            assert_eq!(PrincipalIdBuf::new(id).as_str(), id.to_string());
        }
    }

    #[test]
    fn rendered_principal_stack_matches_to_string_inline_and_heap() {
        // Inline path (<= 16 principals) and the heap fallback (> 16) must
        // produce identical renderings.
        let short: Vec<u64> = vec![0, 7, 4294967294, u64::MAX];
        let long: Vec<u64> = (0..40).map(|i| i * 1_000_003 + 7).collect();
        for ids in [&short, &long] {
            let expected: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
            with_rendered_principal_stack(ids, |refs| {
                assert_eq!(refs.len(), expected.len());
                for (r, e) in refs.iter().zip(expected.iter()) {
                    assert_eq!(*r, e.as_str());
                }
            });
        }
    }

    #[test]
    fn typed_network_abi_rejects_noncanonical_inputs_before_host_lookup() {
        let ids = [0u64];
        let candidates = CString::new("[]").unwrap();
        let uppercase_host = CString::new("API.example.com").unwrap();
        let mapped_host = CString::new("::ffff:169.254.169.254").unwrap();
        let canonical_host = CString::new("api.example.com").unwrap();
        let malformed_candidates = CString::new(r#"{"a":1,"a":2}"#).unwrap();

        let uppercase = unsafe {
            ex_host_authorize_typed_network_stack(
                0,
                ids.as_ptr(),
                ids.len(),
                1,
                uppercase_host.as_ptr(),
                443,
                0,
                candidates.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                u64::MAX,
            )
        };
        assert_eq!(uppercase, -1);

        let mapped = unsafe {
            ex_host_authorize_typed_network_stack(
                0,
                ids.as_ptr(),
                ids.len(),
                4,
                mapped_host.as_ptr(),
                80,
                0,
                candidates.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                u64::MAX,
            )
        };
        assert_eq!(mapped, -1);

        let duplicate_key = unsafe {
            ex_host_authorize_typed_network_stack(
                0,
                ids.as_ptr(),
                ids.len(),
                1,
                canonical_host.as_ptr(),
                443,
                0,
                malformed_candidates.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                u64::MAX,
            )
        };
        assert_eq!(duplicate_key, -1);

        let unsafe_redirect = unsafe {
            ex_host_authorize_typed_network_stack(
                0,
                ids.as_ptr(),
                ids.len(),
                1,
                canonical_host.as_ptr(),
                443,
                0,
                candidates.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                9_007_199_254_740_992,
            )
        };
        assert_eq!(unsafe_redirect, -1);
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FragmentedInterruptingWriter {
        bytes: Vec<u8>,
        max_chunk: usize,
        interrupt_once: bool,
    }

    impl Write for FragmentedInterruptingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.interrupt_once {
                self.interrupt_once = false;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "signal"));
            }
            let n = self.max_chunk.min(buf.len());
            self.bytes.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stdio_line_writer_appends_newline() {
        let mut output = Vec::new();

        write_stdio_line(&mut output, "hello").unwrap();

        assert_eq!(output, b"hello\n");
    }

    #[test]
    fn stdio_line_writer_returns_broken_pipe_without_panicking() {
        let mut writer = FailingWriter;

        let result = write_stdio_line(&mut writer, "hello");

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn append_write_helper_retries_interrupted_and_short_writes() {
        let mut writer = FragmentedInterruptingWriter {
            bytes: Vec::new(),
            max_chunk: 3,
            interrupt_once: true,
        };
        let payload = b"abcdefghij";

        let written = write_all_return_count(&mut writer, payload).unwrap();

        assert_eq!(written, payload.len() as i32);
        assert_eq!(writer.bytes, payload);
    }

    #[test]
    fn console_queue_drops_under_backpressure_then_reports() {
        use std::sync::atomic::Ordering;

        let (tx, rx) = std::sync::mpsc::sync_channel::<ConsoleLine>(2);
        let queue = ConsoleQueue {
            tx,
            dropped: std::sync::atomic::AtomicU64::new(0),
        };

        queue.enqueue(ConsoleLine::Out("first".to_string()));
        queue.enqueue(ConsoleLine::Out("second".to_string()));
        queue.enqueue(ConsoleLine::Out("third".to_string()));
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 1);

        assert!(matches!(rx.recv().unwrap(), ConsoleLine::Out(ref m) if m == "first"));
        assert!(matches!(rx.recv().unwrap(), ConsoleLine::Out(ref m) if m == "second"));

        queue.enqueue(ConsoleLine::Out("fourth".to_string()));
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 0);
        match rx.recv().unwrap() {
            ConsoleLine::Err(m) => assert!(m.contains("dropped 1 line(s)")),
            ConsoleLine::Out(m) => panic!("expected drop notice before line, got {m}"),
        }
        assert!(matches!(rx.recv().unwrap(), ConsoleLine::Out(ref m) if m == "fourth"));
    }

    #[test]
    fn console_queue_survives_missing_receiver() {
        use std::sync::atomic::Ordering;

        let (tx, rx) = std::sync::mpsc::sync_channel::<ConsoleLine>(4);
        drop(rx);
        let queue = ConsoleQueue {
            tx,
            dropped: std::sync::atomic::AtomicU64::new(0),
        };

        queue.enqueue(ConsoleLine::Out("lost".to_string()));

        assert_eq!(queue.dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn named_sqlite_bindings_are_bound_by_name() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)", [])
            .unwrap();

        let insert_json = CString::new("{\":name\":\"alice\",\":id\":7}").unwrap();
        let insert_bindings = parse_bindings(insert_json.as_ptr());
        let mut insert = conn
            .prepare("INSERT INTO items (id, name) VALUES (:id, :name)")
            .unwrap();
        execute_with_bindings(&mut insert, &insert_bindings).unwrap();

        let query_json = CString::new("{\":id\":7}").unwrap();
        let query_bindings = parse_bindings(query_json.as_ptr());
        let mut query = conn
            .prepare("SELECT name FROM items WHERE id = :id")
            .unwrap();
        let mut rows = query_with_bindings(&mut query, &query_bindings).unwrap();
        let row = rows.next().unwrap().unwrap();
        let name: String = row.get(0).unwrap();

        assert_eq!(name, "alice");
    }

    #[test]
    fn sqlite_handle_allocators_refuse_before_wrap_or_reuse() {
        let mut state = SqliteState::new();
        state.next_db_handle = u64::MAX - 1;
        state.next_statement_handle = u64::MAX - 1;

        assert_eq!(state.allocate_db_handle(), Some(u64::MAX - 1));
        assert_eq!(state.allocate_db_handle(), None);
        assert_eq!(state.next_db_handle, u64::MAX);

        assert_eq!(state.allocate_statement_handle(), Some(u64::MAX - 1));
        assert_eq!(state.allocate_statement_handle(), None);
        assert_eq!(state.next_statement_handle, u64::MAX);
    }

    #[test]
    fn install_host_replaces_existing_host() {
        let _guard = host_test_lock();

        install_host(Host::default_legacy());
        assert!(with_host(|host| host.is_allow_all(), false));

        install_host(Host::new(HostConfig {
            mode: SecurityMode::Enforce,
            ..Default::default()
        }));
        assert!(!with_host(|host| host.is_allow_all(), true));
    }

    // A valid numeric bearer seeded before injection must not survive the
    // typed-arm boundary. This covers the use-time check and its only sibling
    // positive possession route; revocation intentionally remains available.
    // @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence
    #[cfg(not(feature = "insecure"))]
    #[test]
    fn armed_host_refuses_seeded_legacy_bearer_at_use_time() {
        let _guard = host_test_lock();
        struct ResetHost;
        impl Drop for ResetHost {
            fn drop(&mut self) {
                install_host(Host::default_legacy());
            }
        }
        let _reset = ResetHost;

        let host = crate::host::tests::example_armed_host();
        let capability = "fs:read:/project/seeded.txt";
        let bearer = host.handles().create(capability);
        assert_ne!(bearer, 0, "the legacy bearer fixture must be valid");
        assert!(
            host.handles().check(bearer, capability),
            "the raw registry must prove this is a valid injected bearer"
        );

        install_host(host);
        assert_eq!(ex_host_is_armed(), 1);
        let capability = CString::new(capability).unwrap();
        assert_eq!(
            ex_host_handle_check(bearer, capability.as_ptr()),
            0,
            "armed use-time possession must fail closed"
        );
        let narrower = CString::new("fs:read:/project/seeded.txt").unwrap();
        assert_eq!(
            ex_host_handle_scoped(bearer, narrower.as_ptr()),
            0,
            "armed re-attenuation must not use a legacy bearer"
        );
    }

    #[test]
    fn runtime_extension_claim_operation_and_lease_are_exact_context_local() {
        let _guard = host_test_lock();
        struct ResetHost;
        impl Drop for ResetHost {
            fn drop(&mut self) {
                install_host(Host::default_legacy());
            }
        }
        let _reset = ResetHost;

        let host = crate::host::tests::example_runtime_extension_armed_host();
        let snapshot_digest = host.armed_snapshot().unwrap().digest().as_str().to_owned();
        let authority_digest = host
            .armed_snapshot()
            .unwrap()
            .runtime_extension_authority()
            .unwrap()
            .authority_capsule_digest
            .as_str()
            .to_owned();
        let registry_projection = host
            .armed_snapshot()
            .unwrap()
            .runtime_extension_authority()
            .unwrap()
            .registry_projection();
        let projection_c =
            CString::new(serde_json::to_string(&registry_projection).unwrap()).unwrap();
        let mut mismatched_projection = serde_json::to_value(registry_projection).unwrap();
        mismatched_projection["descriptors"][0]["authorityFragment"]["operations"][0]["flags"] =
            serde_json::json!(1);
        let mismatched_projection_c =
            CString::new(serde_json::to_string(&mismatched_projection).unwrap()).unwrap();
        let pending = install_host(host);
        assert_ne!(pending, 0);
        let snapshot_c = CString::new(snapshot_digest).unwrap();
        let authority_c = CString::new(authority_digest).unwrap();
        let wrong_c = CString::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();

        assert_eq!(
            unsafe { ex_host_claim_armed_context(snapshot_c.as_ptr()) },
            0,
            "legacy armed claim must refuse a non-empty extension projection"
        );
        assert_eq!(
            unsafe {
                ex_host_claim_armed_context_with_runtime_extensions(
                    snapshot_c.as_ptr(),
                    ptr::null(),
                )
            },
            0,
            "null authority means canonical empty and must refuse non-empty"
        );
        assert_eq!(
            unsafe {
                ex_host_claim_armed_context_with_runtime_extensions(
                    snapshot_c.as_ptr(),
                    wrong_c.as_ptr(),
                )
            },
            0
        );
        let context_id = unsafe {
            ex_host_claim_armed_context_with_runtime_extensions(
                snapshot_c.as_ptr(),
                authority_c.as_ptr(),
            )
        };
        assert_eq!(context_id, pending);
        assert_eq!(
            unsafe {
                ex_host_matches_runtime_extension_authority_digest(context_id, authority_c.as_ptr())
            },
            1
        );
        assert_eq!(
            unsafe {
                ex_host_matches_runtime_extension_authority_digest(context_id, wrong_c.as_ptr())
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_host_matches_runtime_extension_registry_projection_v1(
                    context_id,
                    projection_c.as_ptr(),
                )
            },
            1
        );
        assert_eq!(
            unsafe {
                ex_host_matches_runtime_extension_registry_projection_v1(
                    context_id,
                    mismatched_projection_c.as_ptr(),
                )
            },
            0,
            "a matching capsule digest cannot authenticate a different native table"
        );

        let extension = CString::new("ibex.conformance").unwrap();
        let operation = CString::new("complete").unwrap();
        let authority_class = CString::new("fixture.complete").unwrap();
        let semantics = CString::new("runtime-extension.invoke.authenticated-v1").unwrap();
        let stage = CString::new("requested").unwrap();
        let atomicity_group = CString::new("fixture.operation.decision").unwrap();
        let resource_kind = CString::new("runtime-extension").unwrap();
        let resource_kinds = [resource_kind.as_ptr()];
        let resource = CString::new(r#"{"input":"hello"}"#).unwrap();
        let principals = [0_u64];
        let runtime_nonce = 11;
        let extension_generation = 17;
        let mut lease = 0;
        assert_eq!(
            unsafe {
                ex_host_authorize_runtime_extension_operation_v1(
                    context_id,
                    runtime_nonce,
                    extension_generation,
                    extension.as_ptr(),
                    operation.as_ptr(),
                    authority_class.as_ptr(),
                    semantics.as_ptr(),
                    stage.as_ptr(),
                    atomicity_group.as_ptr(),
                    resource_kinds.as_ptr(),
                    resource_kinds.len(),
                    resource.as_ptr(),
                    principals.as_ptr(),
                    principals.len(),
                    ptr::null(),
                    0,
                    &mut lease,
                )
            },
            1
        );
        assert_ne!(lease, 0);
        assert_eq!(
            unsafe {
                ex_host_check_runtime_extension_lease_binding_v1(
                    context_id,
                    lease,
                    runtime_nonce,
                    extension_generation,
                    extension.as_ptr(),
                    operation.as_ptr(),
                )
            },
            1
        );
        assert_eq!(
            unsafe {
                ex_host_check_runtime_extension_lease_binding_v1(
                    context_id ^ 1,
                    lease,
                    runtime_nonce,
                    extension_generation,
                    extension.as_ptr(),
                    operation.as_ptr(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_host_check_runtime_extension_lease_binding_v1(
                    context_id,
                    lease,
                    runtime_nonce ^ 1,
                    extension_generation,
                    extension.as_ptr(),
                    operation.as_ptr(),
                )
            },
            0,
            "a lease cannot cross runtime instances"
        );
        assert_eq!(
            unsafe {
                ex_host_check_runtime_extension_lease_binding_v1(
                    context_id,
                    lease,
                    runtime_nonce,
                    extension_generation + 1,
                    extension.as_ptr(),
                    operation.as_ptr(),
                )
            },
            0,
            "a lease cannot cross extension generations"
        );
        let wrong_extension = CString::new("ibex.other").unwrap();
        assert_eq!(
            unsafe {
                ex_host_check_runtime_extension_lease_binding_v1(
                    context_id,
                    lease,
                    runtime_nonce,
                    extension_generation,
                    wrong_extension.as_ptr(),
                    operation.as_ptr(),
                )
            },
            0,
            "a lease cannot cross extension namespaces"
        );
        let wrong_operation = CString::new("copyBuffer").unwrap();
        assert_eq!(
            unsafe {
                ex_host_check_runtime_extension_lease_binding_v1(
                    context_id,
                    lease,
                    runtime_nonce,
                    extension_generation,
                    extension.as_ptr(),
                    wrong_operation.as_ptr(),
                )
            },
            0,
            "a lease cannot cross operation scopes"
        );
        let presented = [lease];
        let mut derived_lease = 0;
        assert_eq!(
            unsafe {
                ex_host_authorize_runtime_extension_operation_v1(
                    context_id,
                    runtime_nonce,
                    extension_generation,
                    extension.as_ptr(),
                    operation.as_ptr(),
                    authority_class.as_ptr(),
                    semantics.as_ptr(),
                    stage.as_ptr(),
                    atomicity_group.as_ptr(),
                    resource_kinds.as_ptr(),
                    resource_kinds.len(),
                    resource.as_ptr(),
                    principals.as_ptr(),
                    principals.len(),
                    presented.as_ptr(),
                    presented.len(),
                    &mut derived_lease,
                )
            },
            1,
            "a current acquisition lease can constrain a later operation"
        );
        assert_ne!(derived_lease, 0);
        assert_eq!(
            unsafe {
                ex_host_check_runtime_extension_lease_binding_v1(
                    context_id,
                    derived_lease,
                    runtime_nonce,
                    extension_generation,
                    extension.as_ptr(),
                    operation.as_ptr(),
                )
            },
            1
        );
        let forged_presented = [lease ^ u64::MAX];
        let mut forged_derived = 0;
        assert_eq!(
            unsafe {
                ex_host_authorize_runtime_extension_operation_v1(
                    context_id,
                    runtime_nonce,
                    extension_generation,
                    extension.as_ptr(),
                    operation.as_ptr(),
                    authority_class.as_ptr(),
                    semantics.as_ptr(),
                    stage.as_ptr(),
                    atomicity_group.as_ptr(),
                    resource_kinds.as_ptr(),
                    resource_kinds.len(),
                    resource.as_ptr(),
                    principals.as_ptr(),
                    principals.len(),
                    forged_presented.as_ptr(),
                    forged_presented.len(),
                    &mut forged_derived,
                )
            },
            0
        );
        assert_eq!(forged_derived, 0);
        assert_eq!(
            ex_host_revoke_runtime_extension_lease_v1(context_id, lease),
            1
        );
        assert_eq!(
            unsafe {
                ex_host_check_runtime_extension_lease_binding_v1(
                    context_id,
                    lease,
                    runtime_nonce,
                    extension_generation,
                    extension.as_ptr(),
                    operation.as_ptr(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_host_check_runtime_extension_lease_binding_v1(
                    context_id,
                    derived_lease,
                    runtime_nonce,
                    extension_generation,
                    extension.as_ptr(),
                    operation.as_ptr(),
                )
            },
            0,
            "revoking an acquisition lease invalidates every derived lease"
        );
        assert_eq!(
            ex_host_revoke_runtime_extension_lease_v1(context_id, derived_lease),
            1
        );
        ex_host_release_context(context_id);
    }

    #[test]
    fn runtime_extension_bootstrap_digest_matcher_is_strict_and_bounded() {
        use sha2::{Digest as _, Sha256};

        let payload = b"authenticated runtime-extension bootstrap";
        let digest = CString::new(format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(payload))
        ))
        .unwrap();
        let wrong_digest =
            CString::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let malformed_digest = CString::new("sha256-not-a-canonical-digest").unwrap();
        let non_utf8_digest = [0xff_u8, 0];

        assert_eq!(
            unsafe {
                ex_host_runtime_extension_bootstrap_digest_matches_v1(
                    payload.as_ptr(),
                    payload.len(),
                    digest.as_ptr(),
                )
            },
            1
        );
        assert_eq!(
            unsafe {
                ex_host_runtime_extension_bootstrap_digest_matches_v1(
                    payload.as_ptr(),
                    payload.len(),
                    wrong_digest.as_ptr(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_host_runtime_extension_bootstrap_digest_matches_v1(
                    payload.as_ptr(),
                    payload.len(),
                    malformed_digest.as_ptr(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_host_runtime_extension_bootstrap_digest_matches_v1(
                    payload.as_ptr(),
                    payload.len(),
                    non_utf8_digest.as_ptr().cast(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_host_runtime_extension_bootstrap_digest_matches_v1(
                    ptr::null(),
                    payload.len(),
                    digest.as_ptr(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_host_runtime_extension_bootstrap_digest_matches_v1(
                    payload.as_ptr(),
                    0,
                    digest.as_ptr(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_host_runtime_extension_bootstrap_digest_matches_v1(
                    payload.as_ptr(),
                    (64 * 1024 * 1024) + 1,
                    digest.as_ptr(),
                )
            },
            0,
            "oversize must refuse before forming a slice from the caller pointer"
        );
        assert_eq!(
            unsafe {
                ex_host_runtime_extension_bootstrap_digest_matches_v1(
                    payload.as_ptr(),
                    payload.len(),
                    ptr::null(),
                )
            },
            0
        );
    }

    // Asserts armed-refusal semantics, which an `insecure` build
    // deliberately does not have. @ref LLP 0039#secure-mode-must-stay-exercised
    #[cfg(not(feature = "insecure"))]
    #[test]
    fn armed_legacy_path_outputs_refuse_before_lookup_randomness_or_creation() {
        let _guard = host_test_lock();
        struct ResetHost;
        impl Drop for ResetHost {
            fn drop(&mut self) {
                install_host(Host::default_legacy());
            }
        }
        let _reset = ResetHost;
        install_host(crate::host::tests::example_vfs_armed_host());
        assert_eq!(ex_host_is_armed(), 1);

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let target = std::env::temp_dir().join(format!(
            "ibex-armed-legacy-path-refusal-{}-{nonce}",
            std::process::id()
        ));
        let target_c = CString::new(target.to_string_lossy().as_bytes()).unwrap();
        assert!(!target.exists());

        assert!(ex_host_fs_realpath(target_c.as_ptr()).is_null());
        assert_eq!(ex_host_fs_last_error(), libc::EPERM);
        assert!(!target.exists(), "armed realpath performed filesystem work");

        assert!(ex_host_fs_mkdir_recursive_result(target_c.as_ptr()).is_null());
        assert_eq!(ex_host_fs_last_error(), libc::EPERM);
        assert!(
            !target.exists(),
            "armed recursive mkdir result bridge created a directory"
        );

        assert_eq!(ex_host_fs_mkdir(target_c.as_ptr(), 1), -1);
        assert_eq!(ex_host_fs_last_error(), libc::EPERM);
        assert!(
            !target.exists(),
            "armed recursive mkdir compatibility bridge created a directory"
        );

        let prefix = format!("ibex-armed-mkdtemp-refusal-{}-{nonce}-", std::process::id());
        let matching_temp_entries = || {
            std::fs::read_dir(std::env::temp_dir())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
                .count()
        };
        assert_eq!(matching_temp_entries(), 0);
        let prefix_c = CString::new(prefix.as_str()).unwrap();
        assert!(ex_host_fs_mkdtemp(prefix_c.as_ptr(), 0).is_null());
        assert_eq!(ex_host_fs_last_error(), libc::EPERM);
        assert_eq!(
            matching_temp_entries(),
            0,
            "armed mkdtemp consumed its prefix or created a directory"
        );
    }

    #[test]
    fn typed_decision_abi_returns_fail_closed_error_envelope() {
        let result =
            unsafe { ex_host_evaluate_typed_decision(std::ptr::null(), 0, std::ptr::null(), 0) };
        assert!(!result.is_null());
        let payload = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let value: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(value["error"], "null typed decision input");
        ex_host_free_string(result);
    }

    #[test]
    fn read_file_round_trips_full_length_and_frees_true_layout() {
        // The `ex_host_fs_read_file` / `ex_host_free_buffer` length must survive the
        // FFI round trip without truncation: the caller frees with the exact length
        // read_file reported, so the reconstructed Box layout must match the
        // allocation. A payload larger than a page ensures a non-trivial layout.
        // (A real >= 4 GiB reproduction of the former `as u32` truncation is
        // impractical in a unit test; the regression this guards is that the ABI
        // carries the full length through.)
        let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();

        let mut file = tempfile::NamedTempFile::new().unwrap();
        Write::write_all(&mut file, &payload).unwrap();
        Write::flush(&mut file).unwrap();
        let path = CString::new(file.path().to_str().unwrap()).unwrap();

        let mut out_len: u64 = 0;
        let mut out_errno: i32 = 0;
        let buf = ex_host_fs_read_file(path.as_ptr(), &mut out_len, &mut out_errno);
        assert!(!buf.is_null());
        assert_eq!(out_len, payload.len() as u64);

        let read_back = unsafe { std::slice::from_raw_parts(buf, out_len as usize) };
        assert_eq!(read_back, payload.as_slice());

        // Free with the exact reported length so the Box layout matches the
        // allocation (this is the path the C++ caller takes).
        ex_host_free_buffer(buf, out_len);
    }

    #[test]
    fn pread_pwrite_are_positional_and_leave_the_cursor_unchanged() {
        // ENG-22993 / ENG-22982: a numeric `position` in Node's readSync/writeSync
        // is a *positional* op that must not move the fd cursor. ex_host_fs_pread /
        // ex_host_fs_pwrite must read/write at the given offset and restore the
        // cursor so a subsequent sequential read/write continues where it left
        // off (the pre-fix seek+read/seek+write path moved the cursor and
        // corrupted header-then-stream access).
        let mut file = tempfile::NamedTempFile::new().unwrap();
        Write::write_all(&mut file, b"ABCDEFGHIJ").unwrap();
        Write::flush(&mut file).unwrap();
        let path = CString::new(file.path().to_str().unwrap()).unwrap();

        // Open read+write (no truncate): cursor starts at 0, contents preserved.
        let handle = ex_host_fs_open(path.as_ptr(), FS_READ | FS_WRITE);
        assert!(!handle.is_null());

        // Sequential read of the first 3 bytes advances the cursor to 3.
        let mut head = [0u8; 3];
        assert_eq!(ex_host_fs_read(handle, head.as_mut_ptr(), 3), 3);
        assert_eq!(&head, b"ABC");

        // Positional read at offset 7 must NOT disturb the cursor.
        let mut mid = [0u8; 2];
        assert_eq!(ex_host_fs_pread(handle, mid.as_mut_ptr(), 2, 7), 2);
        assert_eq!(&mid, b"HI");

        // The next sequential read continues from 3 (not from 9). With the
        // pre-fix seek+read bug this would have returned bytes at offset 9.
        let mut next = [0u8; 3];
        assert_eq!(ex_host_fs_read(handle, next.as_mut_ptr(), 3), 3);
        assert_eq!(&next, b"DEF");

        // Positional write at offset 0 must also leave the cursor at 6.
        assert_eq!(ex_host_fs_pwrite(handle, b"xy".as_ptr(), 2, 0), 2);

        // Sequential read continues from 6 -> "GHI".
        let mut after = [0u8; 3];
        assert_eq!(ex_host_fs_read(handle, after.as_mut_ptr(), 3), 3);
        assert_eq!(&after, b"GHI");

        ex_host_fs_close(handle);

        // The positional write landed at offset 0, leaving the rest intact.
        let contents = std::fs::read(file.path()).unwrap();
        assert_eq!(&contents, b"xyCDEFGHIJ");
    }

    #[test]
    fn portable_path_abi_preserves_node_creation_and_metadata_semantics() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("first/second");
        let nested_c = CString::new(nested.to_string_lossy().as_bytes()).unwrap();
        let created = ex_host_fs_mkdir_recursive_result(nested_c.as_ptr());
        assert!(!created.is_null());
        let created_path = unsafe { CStr::from_ptr(created) }
            .to_string_lossy()
            .into_owned();
        ex_host_free_string(created);
        assert_eq!(created_path, root.path().join("first").to_string_lossy());
        let created_again = ex_host_fs_mkdir_recursive_result(nested_c.as_ptr());
        assert_eq!(unsafe { CStr::from_ptr(created_again) }.to_bytes(), b"");
        ex_host_free_string(created_again);

        let source = root.path().join("source");
        let destination = root.path().join("destination");
        std::fs::write(&source, b"abcdef").unwrap();
        let source_c = CString::new(source.to_string_lossy().as_bytes()).unwrap();
        let destination_c = CString::new(destination.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(
            ex_host_fs_copy_exclusive(source_c.as_ptr(), destination_c.as_ptr()),
            0
        );
        std::fs::write(&source, b"replacement").unwrap();
        assert_eq!(
            ex_host_fs_copy_exclusive(source_c.as_ptr(), destination_c.as_ptr()),
            -1
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"abcdef");

        assert_eq!(ex_host_fs_truncate(destination_c.as_ptr(), 3), 0);
        assert_eq!(std::fs::read(&destination).unwrap(), b"abc");
        let timestamp = 1_700_000_000.0;
        assert_eq!(
            ex_host_fs_utimes(destination_c.as_ptr(), timestamp, timestamp),
            0
        );
        let modified = std::fs::metadata(&destination)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(modified, timestamp as u64);

        let root_c = CString::new(root.path().to_string_lossy().as_bytes()).unwrap();
        let statfs = ex_host_fs_statfs(root_c.as_ptr());
        assert!(!statfs.is_null());
        let payload: serde_json::Value =
            serde_json::from_slice(unsafe { CStr::from_ptr(statfs) }.to_bytes()).unwrap();
        ex_host_free_string(statfs);
        assert!(payload["bsize"].as_u64().is_some_and(|size| size > 0));
        assert!(payload["blocks"].as_u64().is_some_and(|blocks| blocks > 0));
    }

    /// Run `sql` through the exec ABI, asserting it did not fault, and free the
    /// returned status string.
    #[cfg(test)]
    fn exec_ok(db: u64, sql: &str, bindings: Option<&str>) {
        let c_sql = CString::new(sql).unwrap();
        let c_bindings = bindings.map(|b| CString::new(b).unwrap());
        let bindings_ptr = c_bindings.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let result = ex_host_sqlite_exec(db, c_sql.as_ptr(), bindings_ptr);
        assert!(!result.is_null(), "exec returned null for {sql}");
        let text = unsafe { CStr::from_ptr(result) }
            .to_string_lossy()
            .into_owned();
        ex_host_free_string(result);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            value.get("error").is_none(),
            "exec of {sql} unexpectedly errored: {text}"
        );
    }

    /// Read a `*mut c_char` JSON result out of the SQLite ABI and free it.
    #[cfg(test)]
    fn take_json(ptr: *mut c_char) -> serde_json::Value {
        assert!(!ptr.is_null(), "SQLite ABI returned null");
        let text = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        ex_host_free_string(ptr);
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn sqlite_tagged_blob_binding_is_stored_as_blob() {
        let _guard = host_test_lock();

        let mem = CString::new(":memory:").unwrap();
        let db = ex_host_sqlite_open(mem.as_ptr(), ptr::null());
        assert_ne!(db, 0);
        exec_ok(db, "CREATE TABLE bytes (value BLOB)", None);
        exec_ok(
            db,
            "INSERT INTO bytes (value) VALUES (?)",
            Some(r#"[{"$ibexSqliteBindingV1":{"kind":"blob","base64":"AAEC/v8="}}]"#),
        );

        let prep = CString::new(
            "SELECT typeof(value) AS kind, length(value) AS size, hex(value) AS hex FROM bytes",
        )
        .unwrap();
        let prepared = take_json(ex_host_sqlite_prepare(db, prep.as_ptr()));
        let handle = prepared["handle"].as_u64().unwrap();
        let result = take_json(ex_host_sqlite_get(handle, ptr::null()));
        assert_eq!(result["row"]["kind"], "blob");
        assert_eq!(result["row"]["size"], 5);
        assert_eq!(result["row"]["hex"], "000102FEFF");

        assert_eq!(ex_host_sqlite_close(db), 0);
    }

    #[test]
    fn sqlite_blob_tag_lookalike_plain_object_keeps_legacy_text_semantics() {
        let value = serde_json::json!({"$ibexSqliteBlobBase64": "AAEC/v8="});
        assert!(matches!(
            to_sql_value(&value),
            rusqlite::types::Value::Text(text)
                if text == "$ibexSqliteBlobBase64=\"AAEC/v8=\""
        ));
    }

    #[test]
    fn sqlite_value_envelope_does_not_recursively_decode_user_transport_lookalike() {
        let value = serde_json::json!({
            "$ibexSqliteBindingV1": {
                "kind": "value",
                "value": {
                    "$ibexSqliteBindingV1": {
                        "kind": "blob",
                        "base64": "AAEC/v8="
                    }
                }
            }
        });
        assert_eq!(
            to_sql_value(&value),
            rusqlite::types::Value::Text(
                "$ibexSqliteBindingV1={\"base64\":\"AAEC/v8=\",\"kind\":\"blob\"}".into(),
            ),
        );
    }

    #[test]
    fn sqlite_readonly_open_of_existing_file_succeeds() {
        let _guard = host_test_lock();

        // Create an on-disk database and write a row through a read-write open.
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let c_path = CString::new(path).unwrap();

        let rw = ex_host_sqlite_open(c_path.as_ptr(), ptr::null());
        assert_ne!(rw, 0, "default (read-write) open should succeed");
        exec_ok(rw, "CREATE TABLE t (v INTEGER)", None);
        exec_ok(rw, "INSERT INTO t (v) VALUES (42)", None);
        assert_eq!(ex_host_sqlite_close(rw), 0);

        // Reopen read-only. Before the fix this produced `READ_ONLY|CREATE`,
        // which rusqlite rejects with SQLITE_MISUSE, so open returned 0.
        let ro_opts = CString::new("{\"readonly\":true}").unwrap();
        let ro = ex_host_sqlite_open(c_path.as_ptr(), ro_opts.as_ptr());
        assert_ne!(
            ro, 0,
            "{{readonly:true}} open of an existing file must succeed"
        );

        // Reads work.
        let prep = CString::new("SELECT v FROM t").unwrap();
        let prepared = take_json(ex_host_sqlite_prepare(ro, prep.as_ptr()));
        let handle = prepared["handle"].as_u64().unwrap();
        let rows = take_json(ex_host_sqlite_all(handle, ptr::null()));
        assert_eq!(rows["rows"][0]["v"].as_i64(), Some(42));

        // Writes are rejected on a read-only connection.
        let write = CString::new("INSERT INTO t (v) VALUES (7)").unwrap();
        let write_result = take_json(ex_host_sqlite_exec(ro, write.as_ptr(), ptr::null()));
        assert!(
            write_result.get("error").is_some(),
            "write on a read-only connection must error, got {write_result}"
        );

        assert_eq!(ex_host_sqlite_close(ro), 0);
    }

    #[test]
    fn sqlite_authorizer_denies_attach_detach_and_load_extension() {
        let _guard = host_test_lock();

        let mem = CString::new(":memory:").unwrap();
        let db = ex_host_sqlite_open(mem.as_ptr(), ptr::null());
        assert_ne!(db, 0);

        let attach = CString::new("ATTACH DATABASE ':memory:' AS other").unwrap();
        let attach_result = take_json(ex_host_sqlite_exec(db, attach.as_ptr(), ptr::null()));
        assert!(
            attach_result
                .get("error")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|err| err.to_ascii_lowercase().contains("not authorized")),
            "ATTACH must be denied by the SQLite authorizer, got {attach_result}"
        );

        let detach = CString::new("DETACH DATABASE main").unwrap();
        let detach_result = take_json(ex_host_sqlite_exec(db, detach.as_ptr(), ptr::null()));
        assert!(
            detach_result
                .get("error")
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "DETACH must be denied by the SQLite authorizer, got {detach_result}"
        );

        let load_extension = CString::new("SELECT load_extension('x')").unwrap();
        let load_extension_result = take_json(ex_host_sqlite_prepare(db, load_extension.as_ptr()));
        assert!(
            load_extension_result.get("error").is_some(),
            "load_extension() must be denied or unavailable, got {load_extension_result}"
        );

        assert_eq!(ex_host_sqlite_close(db), 0);
    }

    #[test]
    fn sqlite_all_surfaces_mid_iteration_step_error() {
        let _guard = host_test_lock();

        let mem = CString::new(":memory:").unwrap();
        let db = ex_host_sqlite_open(mem.as_ptr(), ptr::null());
        assert_ne!(db, 0);

        // One well-behaved row, then i64::MIN (bound as an integer so it is stored
        // as INTEGER, not coerced to REAL). `abs(i64::MIN)` raises "integer
        // overflow" during step — a genuine mid-iteration error after a good row.
        exec_ok(db, "CREATE TABLE t (v INTEGER)", None);
        exec_ok(db, "INSERT INTO t (v) VALUES (1)", None);
        exec_ok(
            db,
            "INSERT INTO t (v) VALUES (?)",
            Some("[-9223372036854775808]"),
        );

        let prep = CString::new("SELECT abs(v) AS a FROM t").unwrap();
        let prepared = take_json(ex_host_sqlite_prepare(db, prep.as_ptr()));
        let handle = prepared["handle"].as_u64().unwrap();

        let result = take_json(ex_host_sqlite_all(handle, ptr::null()));
        assert!(
            result.get("error").is_some(),
            "a mid-iteration step error must surface as an error, got {result}"
        );
        assert!(
            result.get("rows").is_none(),
            "must not return partial rows as a successful result, got {result}"
        );

        // `values` takes the same code path and must behave the same way.
        let values = take_json(ex_host_sqlite_values(handle, ptr::null()));
        assert!(
            values.get("error").is_some(),
            "values must also surface the step error, got {values}"
        );

        assert_eq!(ex_host_sqlite_close(db), 0);
    }

    #[test]
    fn env_get_distinguishes_unset_empty_and_reports_full_length() {
        // ENG-22955: the ABI must (a) distinguish unset (-1) from present-but-empty
        // (0), which the old `unwrap_or_default()` folded together, and (b) report
        // the value's full byte length so a caller can detect truncation and
        // re-query instead of silently clipping long values (the C++ side's 4096
        // buffer used to lose the tail with no signal).
        use std::os::raw::c_char;

        const KEY: &str = "IBEX_ENG22955_ENV_TEST";
        let key = CString::new(KEY).unwrap();
        let call = |buf: &mut [c_char]| -> i64 {
            ex_host_env_get(key.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };

        std::env::remove_var(KEY);
        // Unset -> -1 (distinct from empty).
        let mut buf = [0x7f as c_char; 32];
        assert_eq!(call(&mut buf), -1);

        // Present but empty -> length 0, null-terminated at index 0.
        std::env::set_var(KEY, "");
        buf = [0x7f as c_char; 32];
        assert_eq!(call(&mut buf), 0);
        assert_eq!(buf[0], 0);

        // Normal value -> full length, exact bytes + null terminator.
        std::env::set_var(KEY, "hello");
        buf = [0x7f as c_char; 32];
        assert_eq!(call(&mut buf), 5);
        assert_eq!(
            &buf[..5].iter().map(|&b| b as u8).collect::<Vec<_>>(),
            b"hello"
        );
        assert_eq!(buf[5], 0);

        // Value longer than the buffer -> return is the FULL length (> buffer),
        // the buffer holds a len-1 byte prefix and stays null-terminated: the
        // caller can see it was truncated and re-query with a bigger buffer.
        let long = "x".repeat(10_000);
        std::env::set_var(KEY, &long);
        let mut small = [0x7f as c_char; 8];
        assert_eq!(call(&mut small), 10_000);
        assert_eq!(small[7], 0);
        assert!(small[..7].iter().all(|&b| b as u8 == b'x'));

        // A null/zero buffer is a pure length query: no write, just the length.
        assert_eq!(ex_host_env_get(key.as_ptr(), ptr::null_mut(), 0), 10_000);

        std::env::remove_var(KEY);
    }

    #[test]
    fn embedder_artifact_preparation_refuses_missing_inputs() {
        let envelope = take_json(unsafe {
            ex_host_prepare_armed_embedder_artifacts(ptr::null(), 0, ptr::null(), 0)
        });
        assert_eq!(envelope["ok"], false);
        assert!(envelope["error"]
            .as_str()
            .unwrap()
            .contains("snapshot template and expected identity are required"));

        let exact_envelope = take_json(unsafe {
            ex_host_prepare_exact_armed_embedder_artifacts(
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
            )
        });
        assert_eq!(exact_envelope["ok"], false);
        assert!(exact_envelope["error"]
            .as_str()
            .unwrap()
            .contains("Exact operation manifest are required"));

        let build_envelope = take_json(unsafe {
            ex_host_build_exact_armed_embedder_artifacts(
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
            )
        });
        assert_eq!(build_envelope["ok"], false);
        assert!(build_envelope["error"]
            .as_str()
            .unwrap()
            .contains("Exact project root and operation manifest are required"));
    }

    #[cfg(feature = "capsec-simulator-performance-observer")]
    #[test]
    fn simulator_performance_observer_matches_only_root_ipv4_loopback_fetch() {
        assert!(simulator_performance_observer_matches_root_loopback_fetch(
            &[0],
            "network:fetch:127.0.0.1"
        ));
        for (principals, capability) in [
            (Vec::new(), "network:fetch:127.0.0.1"),
            (vec![1], "network:fetch:127.0.0.1"),
            (vec![0, 1], "network:fetch:127.0.0.1"),
            (vec![0], "network:fetch:localhost"),
            (vec![0], "network:fetch:::1"),
            (vec![0], "network:fetch:example.com"),
            (vec![0], "network:connect:127.0.0.1"),
        ] {
            assert!(
                !simulator_performance_observer_matches_root_loopback_fetch(
                    &principals,
                    capability
                ),
                "unexpected admission for principals={principals:?} capability={capability}"
            );
        }
    }
}
