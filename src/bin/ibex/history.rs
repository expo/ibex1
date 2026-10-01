//! Supervisor-owned persistent history for the interactive REPL editor.
//!
//! This module deliberately has no JavaScript-facing handle. The terminal
//! supervisor gives it an already-authenticated project root before arming,
//! then uses the narrow load/append/search API while it owns the editor.
//! @ref LLP 0025#9-history — project-scoped, hardened, append-at-submission
//! history is terminal-supervisor state, never engine authority.

use crate::cli::HistoryMode;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fmt;
#[cfg(any(test, windows))]
use std::fs::OpenOptions;
use std::fs::{self, File, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthenticatedProjectHistoryRoot<'a> {
    pub(crate) path: &'a Path,
    pub(crate) object: &'a capsec_semantics::model::ObjectIdentity,
}

const STORE_DIRECTORY: &str = "repl-history-v1";
const KEY_FILE: &str = "user-key-v1";
const KEY_MAGIC: &[u8; 4] = b"IBHK";
const KEY_VERSION: u16 = 1;
const KEY_BYTES: usize = 32;
const KEY_CHECK_DOMAIN: &[u8] = b"ibex-history-user-key-check-v1";
const KEY_RECORD_BYTES: usize = 4 + 2 + 2 + KEY_BYTES + 32;
const SCOPE_DOMAIN: &[u8] = b"ibex-history-scope-v1\0";
const GLOBAL_SCOPE: &[u8] = b"global-v1";
const JOURNAL_MAGIC: &[u8; 4] = b"IBHJ";
const JOURNAL_VERSION: u16 = 1;
const JOURNAL_HEADER_BYTES: usize = 4 + 2 + 2 + 8 + 4;
const JOURNAL_CHECKSUM_BYTES: usize = 32;
const LOCK_POLL_MILLIS: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryScopeStrength {
    DurableObject,
    CanonicalPathFallback,
    Global,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HistoryDiagnostic {
    UnavailableWithoutEditor,
    AuthenticatedProjectRootRequired,
    DataDirectoryUnavailable,
    #[cfg(windows)]
    PlatformSecurityUnavailable,
    UnsafeStorageRefused,
    UserKeyUnavailableOrMalformed,
    JournalUnavailableOrMalformed,
    LockTimedOut,
    RecordTooLarge,
    LegacyHistoryIgnored,
}

impl fmt::Display for HistoryDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnavailableWithoutEditor => {
                "persistent history was requested, but this input mode has no interactive editor"
            }
            Self::AuthenticatedProjectRootRequired => {
                "persistent project history is disabled because no authenticated project root is available"
            }
            Self::DataDirectoryUnavailable => {
                "persistent history is disabled because the per-user data directory is unavailable"
            }
            #[cfg(windows)]
            Self::PlatformSecurityUnavailable => {
                "persistent history is disabled on this platform because Ibex cannot yet prove invoking-user ownership and a 0600-equivalent DACL"
            }
            Self::UnsafeStorageRefused => {
                "persistent history is disabled because its directory or file failed ownership, permission, type, or no-follow checks"
            }
            Self::UserKeyUnavailableOrMalformed => {
                "persistent history is disabled because the Ibex history key is unreadable or malformed; repair or remove it manually (Ibex will never rotate it)"
            }
            Self::JournalUnavailableOrMalformed => {
                "this history operation was not persisted because the hardened journal could not be used"
            }
            Self::LockTimedOut => {
                "this history entry was not persisted because the history lock was busy"
            }
            Self::RecordTooLarge => {
                "this history entry was not persisted because it exceeds the history record limit"
            }
            Self::LegacyHistoryIgnored => {
                "legacy global REPL history exists but is intentionally ignored; Ibex does not migrate it into project history"
            }
        };
        formatter.write_str(message)
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct HistoryStartup<'a> {
    pub(crate) mode: HistoryMode,
    pub(crate) editor_present: bool,
    pub(crate) mode_was_explicit: bool,
    pub(crate) authenticated_project_root: Option<&'a Path>,
}

/// Platform-dependent storage discovery captured before the Host is armed.
///
/// The disabled shape intentionally contains no path. In particular, an
/// editorless route and `--history=off` do not call the platform directory
/// resolver at all.
#[derive(Clone, Debug)]
pub(crate) struct HistoryPlatformCapture {
    mode: HistoryMode,
    editor_present: bool,
    mode_was_explicit: bool,
    data_root: Option<PathBuf>,
    diagnostic: Option<HistoryDiagnostic>,
}

/// Complete, supervisor-private history startup state. This value is bound to
/// the exact authenticated project root before the engine is constructed, and
/// is later consumed by the terminal adapter without consulting the
/// environment or re-deriving project identity.
#[derive(Clone, Debug)]
pub(crate) struct HistoryStartupCapture {
    mode: HistoryMode,
    editor_present: bool,
    mode_was_explicit: bool,
    data_root: Option<PathBuf>,
    scope: Option<Vec<u8>>,
    scope_strength: Option<HistoryScopeStrength>,
    diagnostic: Option<HistoryDiagnostic>,
}

impl HistoryPlatformCapture {
    pub(crate) fn capture(
        mode: HistoryMode,
        editor_present: bool,
        mode_was_explicit: bool,
    ) -> Self {
        if !editor_present || mode == HistoryMode::Off {
            return Self {
                mode,
                editor_present,
                mode_was_explicit,
                data_root: None,
                diagnostic: None,
            };
        }

        // Windows history stays fail-closed until descriptor-relative owner
        // SID and protected-DACL validation is implemented. Reparse-point and
        // inherited-ACL checks alone do not satisfy LLP 0025 AC11.
        #[cfg(windows)]
        return Self {
            mode,
            editor_present,
            mode_was_explicit,
            data_root: None,
            diagnostic: Some(HistoryDiagnostic::PlatformSecurityUnavailable),
        };

        #[cfg(not(windows))]
        let data_root = match mode {
            HistoryMode::Project => capture_project_history_platform_data_root(),
            HistoryMode::Global => capture_global_history_platform_data_root(),
            HistoryMode::Off => unreachable!("off returned before data-root discovery"),
        };
        #[cfg(not(windows))]
        match data_root {
            Some(data_root) => Self {
                mode,
                editor_present,
                mode_was_explicit,
                data_root: Some(data_root),
                diagnostic: None,
            },
            None => Self {
                mode,
                editor_present,
                mode_was_explicit,
                data_root: None,
                diagnostic: Some(HistoryDiagnostic::DataDirectoryUnavailable),
            },
        }
    }

    pub(crate) fn bind_authenticated_project_root(
        self,
        authenticated_project_root: Option<AuthenticatedProjectHistoryRoot<'_>>,
    ) -> HistoryStartupCapture {
        let (scope, scope_strength, diagnostic) =
            if self.diagnostic.is_some() || !self.editor_present || self.mode == HistoryMode::Off {
                (None, None, self.diagnostic)
            } else {
                match self.mode {
                    HistoryMode::Project => match authenticated_project_root.and_then(|root| {
                        derive_authenticated_project_history_scope(root.path, root.object).ok()
                    }) {
                        Some(scope) => (Some(scope.bytes), Some(scope.strength), None),
                        None => (
                            None,
                            None,
                            Some(HistoryDiagnostic::AuthenticatedProjectRootRequired),
                        ),
                    },
                    HistoryMode::Global => (
                        Some(GLOBAL_SCOPE.to_vec()),
                        Some(HistoryScopeStrength::Global),
                        None,
                    ),
                    HistoryMode::Off => unreachable!("off returned before scope derivation"),
                }
            };

        HistoryStartupCapture {
            mode: self.mode,
            editor_present: self.editor_present,
            mode_was_explicit: self.mode_was_explicit,
            data_root: self.data_root,
            scope,
            scope_strength,
            diagnostic,
        }
    }
}

/// The single environment-backed locator used by persistent history. Callers
/// must gate this before invocation; its result remains Rust-private and is
/// never written to diagnostics or projected into JavaScript.
fn capture_project_history_platform_data_root() -> Option<PathBuf> {
    dirs::data_local_dir()
}

/// The global mode is an explicit supervisor-internal route to the platform
/// data root. The locator spelling never crosses the terminal broker and is
/// never included in user-visible output.
fn capture_global_history_platform_data_root() -> Option<PathBuf> {
    dirs::data_local_dir()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HistoryAppendDisposition {
    Ignored,
    Persisted,
    InMemoryOnly,
    Skipped(HistoryDiagnostic),
}

/// The only history handle the terminal adapter needs. It contains neither a
/// serializable scope id nor any operation capable of crossing into JS.
pub(crate) struct HistorySession {
    entries: Vec<String>,
    startup_diagnostics: Vec<HistoryDiagnostic>,
    store: Option<HistoryStore>,
    scope_strength: Option<HistoryScopeStrength>,
}

impl HistorySession {
    pub(crate) fn open(startup: HistoryStartupCapture) -> Self {
        Self::open_captured(
            startup,
            Arc::new(SystemLockClock::new()),
            Limits::generated(),
        )
    }

    fn disabled(
        mode: HistoryMode,
        editor_present: bool,
        mode_was_explicit: bool,
        diagnostic: Option<HistoryDiagnostic>,
    ) -> Self {
        let mut startup_diagnostics = Vec::new();
        if let Some(diagnostic) = diagnostic {
            startup_diagnostics.push(diagnostic);
        } else if !editor_present && mode_was_explicit && mode != HistoryMode::Off {
            startup_diagnostics.push(HistoryDiagnostic::UnavailableWithoutEditor);
        }
        Self {
            entries: Vec::new(),
            startup_diagnostics,
            store: None,
            scope_strength: None,
        }
    }

    #[cfg(test)]
    fn open_at(
        startup: HistoryStartup<'_>,
        data_root: &Path,
        clock: Arc<dyn LockClock>,
        limits: Limits,
    ) -> Self {
        let platform = HistoryPlatformCapture {
            mode: startup.mode,
            editor_present: startup.editor_present,
            mode_was_explicit: startup.mode_was_explicit,
            data_root: if startup.editor_present && startup.mode != HistoryMode::Off {
                Some(data_root.to_owned())
            } else {
                None
            },
            diagnostic: None,
        };
        let expected_object = startup.authenticated_project_root.and_then(|root| {
            let handle = open_directory_no_follow(root).ok()?;
            project_object_identity_for_handle(&handle).ok()
        });
        let authenticated_root = startup
            .authenticated_project_root
            .zip(expected_object.as_ref())
            .map(|(path, object)| AuthenticatedProjectHistoryRoot { path, object });
        let capture = platform.bind_authenticated_project_root(authenticated_root);
        Self::open_captured(capture, clock, limits)
    }

    fn open_captured(
        startup: HistoryStartupCapture,
        clock: Arc<dyn LockClock>,
        limits: Limits,
    ) -> Self {
        // Modes without an editor were captured without a locator lookup and
        // must remain inert here as well.
        if !startup.editor_present || startup.mode == HistoryMode::Off {
            return Self::disabled(
                startup.mode,
                startup.editor_present,
                startup.mode_was_explicit,
                startup.diagnostic,
            );
        }
        if startup.diagnostic.is_some() {
            return Self::disabled(
                startup.mode,
                startup.editor_present,
                startup.mode_was_explicit,
                startup.diagnostic,
            );
        }
        let Some(data_root) = startup.data_root.as_deref() else {
            return Self::disabled(
                startup.mode,
                startup.editor_present,
                startup.mode_was_explicit,
                Some(HistoryDiagnostic::DataDirectoryUnavailable),
            );
        };
        let Some(scope) = startup.scope.as_deref() else {
            return Self::disabled(
                startup.mode,
                startup.editor_present,
                startup.mode_was_explicit,
                Some(HistoryDiagnostic::AuthenticatedProjectRootRequired),
            );
        };
        let scope_strength = startup.scope_strength;

        let mut diagnostics = Vec::new();
        if legacy_history_present(data_root) {
            diagnostics.push(HistoryDiagnostic::LegacyHistoryIgnored);
        }

        match HistoryStore::open_history_store(data_root, scope, clock, limits) {
            Ok(store) => match store.load() {
                Ok(entries) => Self {
                    entries,
                    startup_diagnostics: diagnostics,
                    store: Some(store),
                    scope_strength,
                },
                Err(error) => {
                    diagnostics.push(error.diagnostic());
                    Self {
                        entries: Vec::new(),
                        startup_diagnostics: diagnostics,
                        store: None,
                        scope_strength,
                    }
                }
            },
            Err(error) => {
                diagnostics.push(error.diagnostic());
                Self {
                    entries: Vec::new(),
                    startup_diagnostics: diagnostics,
                    store: None,
                    scope_strength,
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[String] {
        &self.entries
    }

    pub(crate) fn startup_diagnostics(&self) -> &[HistoryDiagnostic] {
        &self.startup_diagnostics
    }

    // Retain the strength projection alongside the captured scope so a
    // supervisor diagnostic can distinguish durable object identity from the
    // specified canonical-path fallback without re-deriving either identity.
    #[allow(dead_code)]
    pub(crate) fn scope_strength(&self) -> Option<HistoryScopeStrength> {
        self.scope_strength
    }

    pub(crate) fn append_submission(&mut self, input: &str) -> HistoryAppendDisposition {
        if input.trim().is_empty() || input.starts_with(' ') {
            return HistoryAppendDisposition::Ignored;
        }

        if input.len() > ibex_runtime::session_constants::HISTORY_RECORD_MAX_BYTES {
            self.push_memory(input.to_owned());
            return HistoryAppendDisposition::Skipped(HistoryDiagnostic::RecordTooLarge);
        }

        let Some(store) = self.store.as_ref() else {
            self.push_memory(input.to_owned());
            return HistoryAppendDisposition::InMemoryOnly;
        };

        match store.append_history_journal(input) {
            Ok(entries) => {
                self.entries = entries;
                HistoryAppendDisposition::Persisted
            }
            Err(error) => {
                self.push_memory(input.to_owned());
                HistoryAppendDisposition::Skipped(error.diagnostic())
            }
        }
    }

    /// Reverse-search without exposing the store, scope digest, or filesystem.
    pub(crate) fn reverse_search(
        &self,
        needle: &str,
        before: Option<usize>,
    ) -> Option<(usize, &str)> {
        let end = before.unwrap_or(self.entries.len()).min(self.entries.len());
        self.entries[..end]
            .iter()
            .enumerate()
            .rev()
            .find(|(_, entry)| entry.contains(needle))
            .map(|(index, entry)| (index, entry.as_str()))
    }

    fn push_memory(&mut self, input: String) {
        self.entries.push(input);
        while self.entries.len() > ibex_runtime::session_constants::HISTORY_MAX_ENTRIES
            || self.entries.iter().map(String::len).sum::<usize>()
                > ibex_runtime::session_constants::HISTORY_MAX_BYTES
        {
            self.entries.remove(0);
        }
    }
}

#[derive(Clone, Copy)]
struct Limits {
    entries: usize,
    bytes: usize,
    record_bytes: usize,
    lock_wait: Duration,
}

impl Limits {
    fn generated() -> Self {
        Self {
            entries: ibex_runtime::session_constants::HISTORY_MAX_ENTRIES,
            bytes: ibex_runtime::session_constants::HISTORY_MAX_BYTES,
            record_bytes: ibex_runtime::session_constants::HISTORY_RECORD_MAX_BYTES,
            lock_wait: Duration::from_millis(
                ibex_runtime::session_constants::HISTORY_LOCK_ACQUISITION_MILLIS,
            ),
        }
    }
}

trait LockClock: Send + Sync {
    fn now(&self) -> Duration;
    fn sleep(&self, duration: Duration);
}

struct SystemLockClock {
    epoch: Instant,
}

impl SystemLockClock {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl LockClock for SystemLockClock {
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Debug)]
enum StoreError {
    Io(io::Error),
    UnsafeStorage,
    KeyUnavailable,
    JournalUnavailable,
    LockTimeout,
    RecordTooLarge,
    IndexExhausted,
}

impl StoreError {
    fn diagnostic(&self) -> HistoryDiagnostic {
        match self {
            Self::UnsafeStorage => HistoryDiagnostic::UnsafeStorageRefused,
            Self::KeyUnavailable => HistoryDiagnostic::UserKeyUnavailableOrMalformed,
            Self::LockTimeout => HistoryDiagnostic::LockTimedOut,
            Self::RecordTooLarge => HistoryDiagnostic::RecordTooLarge,
            Self::Io(_) | Self::JournalUnavailable | Self::IndexExhausted => {
                HistoryDiagnostic::JournalUnavailableOrMalformed
            }
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct HistoryStore {
    directory: SecureDirectory,
    journal_name: String,
    lock_name: String,
    clock: Arc<dyn LockClock>,
    limits: Limits,
}

impl HistoryStore {
    fn open_history_store(
        data_root: &Path,
        scope: &[u8],
        clock: Arc<dyn LockClock>,
        limits: Limits,
    ) -> Result<Self, StoreError> {
        let directory = SecureDirectory::open(data_root)?;
        let key = load_or_create_history_user_key(&directory)?;
        let digest = hmac_bytes(&key, &[SCOPE_DOMAIN, scope]);
        let stem = format!("history-v1-{}", hex(&digest));
        Ok(Self {
            directory,
            journal_name: format!("{stem}.journal"),
            lock_name: format!("{stem}.lock"),
            clock,
            limits,
        })
    }

    fn load(&self) -> Result<Vec<String>, StoreError> {
        let _lock = self.acquire_history_sidecar_lock()?;
        self.recover_history_journal_locked()
            .map(|records| records.into_iter().map(|record| record.payload).collect())
    }

    fn append_history_journal(&self, input: &str) -> Result<Vec<String>, StoreError> {
        if input.len() > self.limits.record_bytes {
            return Err(StoreError::RecordTooLarge);
        }
        let _lock = self.acquire_history_sidecar_lock()?;
        let mut records = self.recover_history_journal_locked()?;
        let next_index = records
            .last()
            .map_or(Some(1), |record| record.index.checked_add(1))
            .ok_or(StoreError::IndexExhausted)?;
        let record = JournalRecord {
            index: next_index,
            payload: input.to_owned(),
        };

        // Reopen and re-verify the journal only after the stable sidecar lock
        // is held. Compaction replaces the journal inode, never the lock inode.
        let (mut journal, _) = self
            .directory
            .open_or_create_file(&self.journal_name)
            .map_err(classify_journal_io)?;
        journal.seek(SeekFrom::End(0))?;
        write_record(&mut journal, &record)?;
        journal.flush()?; // OS-accepted durability; intentionally no per-entry fsync.
        records.push(record);

        if prune_records(&mut records, self.limits) {
            self.compact_history_journal_locked(&records)?;
        }
        Ok(records.into_iter().map(|record| record.payload).collect())
    }

    fn acquire_history_sidecar_lock(&self) -> Result<HeldLock, StoreError> {
        let (file, _) = self
            .directory
            .open_or_create_file(&self.lock_name)
            .map_err(classify_journal_io)?;
        let start = self.clock.now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(HeldLock { file }),
                Err(TryLockError::WouldBlock) => {
                    let elapsed = self.clock.now().saturating_sub(start);
                    if elapsed >= self.limits.lock_wait {
                        return Err(StoreError::LockTimeout);
                    }
                    let remaining = self.limits.lock_wait.saturating_sub(elapsed);
                    self.clock
                        .sleep(remaining.min(Duration::from_millis(LOCK_POLL_MILLIS)));
                }
                Err(TryLockError::Error(error)) => return Err(StoreError::Io(error)),
            }
        }
    }

    fn recover_history_journal_locked(&self) -> Result<Vec<JournalRecord>, StoreError> {
        let (mut file, _) = self
            .directory
            .open_or_create_file(&self.journal_name)
            .map_err(classify_journal_io)?;
        file.seek(SeekFrom::Start(0))?;
        let mut records = VecDeque::new();
        let mut valid_end = 0u64;
        let mut previous_index: Option<u64> = None;
        let mut payload_bytes = 0usize;
        let mut needs_rewrite = false;

        loop {
            let record_start = valid_end;
            let mut header = [0u8; JOURNAL_HEADER_BYTES];
            let header_read = read_up_to(&mut file, &mut header)?;
            if header_read == 0 {
                break;
            }
            if header_read != header.len()
                || &header[..4] != JOURNAL_MAGIC
                || u16::from_le_bytes([header[4], header[5]]) != JOURNAL_VERSION
                || u16::from_le_bytes([header[6], header[7]]) != 0
            {
                file.set_len(record_start)?;
                needs_rewrite = true;
                break;
            }
            let index = u64::from_le_bytes(header[8..16].try_into().expect("fixed index"));
            let length =
                u32::from_le_bytes(header[16..20].try_into().expect("fixed length")) as usize;
            if index == 0
                || previous_index.is_some_and(|previous| previous.checked_add(1) != Some(index))
                || length > self.limits.record_bytes
            {
                file.set_len(record_start)?;
                needs_rewrite = true;
                break;
            }
            let mut payload = vec![0u8; length];
            let mut checksum = [0u8; JOURNAL_CHECKSUM_BYTES];
            if read_up_to(&mut file, &mut payload)? != payload.len()
                || read_up_to(&mut file, &mut checksum)? != checksum.len()
            {
                file.set_len(record_start)?;
                needs_rewrite = true;
                break;
            }
            let expected = record_checksum(&header, &payload);
            if expected != checksum {
                file.set_len(record_start)?;
                needs_rewrite = true;
                break;
            }
            let Ok(payload) = String::from_utf8(payload) else {
                file.set_len(record_start)?;
                needs_rewrite = true;
                break;
            };
            valid_end = record_start
                .checked_add((JOURNAL_HEADER_BYTES + length + JOURNAL_CHECKSUM_BYTES) as u64)
                .ok_or(StoreError::JournalUnavailable)?;
            previous_index = Some(index);
            payload_bytes = payload_bytes.saturating_add(payload.len());
            records.push_back(JournalRecord { index, payload });
            while records.len() > self.limits.entries || payload_bytes > self.limits.bytes {
                if let Some(removed) = records.pop_front() {
                    payload_bytes = payload_bytes.saturating_sub(removed.payload.len());
                    needs_rewrite = true;
                } else {
                    break;
                }
            }
        }

        let records: Vec<JournalRecord> = records.into_iter().collect();
        if needs_rewrite {
            self.compact_history_journal_locked(&records)?;
        }
        Ok(records)
    }

    fn compact_history_journal_locked(&self, records: &[JournalRecord]) -> Result<(), StoreError> {
        let (temp_name, mut temp) = self.directory.create_temp_file("journal")?;
        let result = (|| -> Result<(), StoreError> {
            for record in records {
                write_record(&mut temp, record)?;
            }
            temp.sync_all()?;
            drop(temp);
            self.directory
                .replace(&temp_name, &self.journal_name)
                .map_err(classify_journal_io)?;
            self.directory.sync()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = self.directory.remove(&temp_name);
        }
        result
    }
}

struct HeldLock {
    file: File,
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Clone)]
struct JournalRecord {
    index: u64,
    payload: String,
}

fn prune_records(records: &mut Vec<JournalRecord>, limits: Limits) -> bool {
    let mut changed = false;
    let mut bytes: usize = records.iter().map(|record| record.payload.len()).sum();
    while records.len() > limits.entries || bytes > limits.bytes {
        let removed = records.remove(0);
        bytes = bytes.saturating_sub(removed.payload.len());
        changed = true;
    }
    changed
}

fn write_record(file: &mut File, record: &JournalRecord) -> Result<(), StoreError> {
    let length = u32::try_from(record.payload.len()).map_err(|_| StoreError::RecordTooLarge)?;
    let mut header = Vec::with_capacity(JOURNAL_HEADER_BYTES);
    header.extend_from_slice(JOURNAL_MAGIC);
    header.extend_from_slice(&JOURNAL_VERSION.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&record.index.to_le_bytes());
    header.extend_from_slice(&length.to_le_bytes());
    let checksum = record_checksum(&header, record.payload.as_bytes());
    file.write_all(&header)?;
    file.write_all(record.payload.as_bytes())?;
    file.write_all(&checksum)?;
    Ok(())
}

fn record_checksum(header: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(header);
    digest.update(payload);
    digest.finalize().into()
}

fn read_up_to(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut read = 0;
    while read < buffer.len() {
        match file.read(&mut buffer[read..])? {
            0 => break,
            count => read += count,
        }
    }
    Ok(read)
}

fn classify_journal_io(error: StoreError) -> StoreError {
    match error {
        StoreError::UnsafeStorage => StoreError::UnsafeStorage,
        StoreError::Io(_) => StoreError::JournalUnavailable,
        other => other,
    }
}

fn load_or_create_history_user_key(
    directory: &SecureDirectory,
) -> Result<[u8; KEY_BYTES], StoreError> {
    match directory.open_existing_file(KEY_FILE) {
        Ok(file) => return read_key(file),
        Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
        Err(StoreError::UnsafeStorage) => return Err(StoreError::UnsafeStorage),
        Err(_) => return Err(StoreError::KeyUnavailable),
    }

    let mut key = [0u8; KEY_BYTES];
    getrandom::getrandom(&mut key).map_err(|_| StoreError::KeyUnavailable)?;
    let record = encode_key(&key);
    let (temp_name, mut temp) = directory.create_temp_file("key")?;
    let publish = (|| -> Result<bool, StoreError> {
        temp.write_all(&record)?;
        temp.sync_all()?;
        drop(temp);
        match directory.publish_no_clobber(&temp_name, KEY_FILE) {
            Ok(()) => {
                directory.remove(&temp_name)?;
                directory.sync()?;
                Ok(true)
            }
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                directory.remove(&temp_name)?;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    })();
    if publish.is_err() {
        let _ = directory.remove(&temp_name);
    }
    publish.map_err(|_| StoreError::KeyUnavailable)?;
    let file = directory
        .open_existing_file(KEY_FILE)
        .map_err(|_| StoreError::KeyUnavailable)?;
    read_key(file)
}

fn encode_key(key: &[u8; KEY_BYTES]) -> [u8; KEY_RECORD_BYTES] {
    let mut record = [0u8; KEY_RECORD_BYTES];
    record[..4].copy_from_slice(KEY_MAGIC);
    record[4..6].copy_from_slice(&KEY_VERSION.to_le_bytes());
    record[6..8].copy_from_slice(&(KEY_BYTES as u16).to_le_bytes());
    record[8..40].copy_from_slice(key);
    record[40..].copy_from_slice(&hmac_bytes(key, &[KEY_CHECK_DOMAIN]));
    record
}

fn read_key(mut file: File) -> Result<[u8; KEY_BYTES], StoreError> {
    if file
        .metadata()
        .map_err(|_| StoreError::KeyUnavailable)?
        .len()
        != KEY_RECORD_BYTES as u64
    {
        return Err(StoreError::KeyUnavailable);
    }
    let mut record = [0u8; KEY_RECORD_BYTES];
    file.read_exact(&mut record)
        .map_err(|_| StoreError::KeyUnavailable)?;
    if &record[..4] != KEY_MAGIC
        || u16::from_le_bytes([record[4], record[5]]) != KEY_VERSION
        || u16::from_le_bytes([record[6], record[7]]) as usize != KEY_BYTES
    {
        return Err(StoreError::KeyUnavailable);
    }
    let key: [u8; KEY_BYTES] = record[8..40]
        .try_into()
        .map_err(|_| StoreError::KeyUnavailable)?;
    let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| StoreError::KeyUnavailable)?;
    mac.update(KEY_CHECK_DOMAIN);
    mac.verify_slice(&record[40..])
        .map_err(|_| StoreError::KeyUnavailable)?;
    Ok(key)
}

fn hmac_bytes(key: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    for chunk in chunks {
        mac.update(chunk);
    }
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

fn legacy_history_present(data_root: &Path) -> bool {
    [
        data_root.join("ibex").join("repl_history"),
        data_root.join("exact").join("repl_history"),
    ]
    .iter()
    .any(|path| fs::symlink_metadata(path).is_ok())
}

struct ProjectHistoryScopeId {
    bytes: Vec<u8>,
    strength: HistoryScopeStrength,
}

impl ProjectHistoryScopeId {
    fn derive(
        authenticated_project_root: &Path,
        expected_object: &capsec_semantics::model::ObjectIdentity,
    ) -> io::Result<Self> {
        let canonical = fs::canonicalize(authenticated_project_root)?;
        let handle = open_directory_no_follow(&canonical)?;
        if !handle.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "authenticated project root is not a directory",
            ));
        }
        if project_object_identity_for_handle(&handle)? != *expected_object {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "history project root no longer names the armed snapshot object",
            ));
        }

        if let Some(bytes) = durable_object_witness(&handle) {
            return Ok(Self {
                bytes,
                strength: HistoryScopeStrength::DurableObject,
            });
        }

        let mut bytes = b"project-history-scope-v1\0path\0".to_vec();
        bytes.extend_from_slice(&path_identity_bytes(&canonical));
        Ok(Self {
            bytes,
            strength: HistoryScopeStrength::CanonicalPathFallback,
        })
    }
}

/// Derive the private history scope only from the canonical root already
/// authenticated for this launch. No cwd, manifest, or environment fallback
/// is permitted here.
fn derive_authenticated_project_history_scope(
    authenticated_project_root: &Path,
    expected_object: &capsec_semantics::model::ObjectIdentity,
) -> io::Result<ProjectHistoryScopeId> {
    ProjectHistoryScopeId::derive(authenticated_project_root, expected_object)
}

fn project_object_identity_for_handle(
    handle: &File,
) -> io::Result<capsec_semantics::model::ObjectIdentity> {
    ibex_runtime::host::object_identity_for_open_file(handle)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(unix)]
fn path_identity_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn path_identity_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(target_os = "macos")]
fn durable_object_witness(handle: &File) -> Option<Vec<u8>> {
    use std::os::fd::AsRawFd;
    use std::os::macos::fs::MetadataExt;

    let metadata = handle.metadata().ok()?;
    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_UUID,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut buffer = [0u8; 20];
    let result = unsafe {
        libc::fgetattrlist(
            handle.as_raw_fd(),
            (&mut attributes as *mut libc::attrlist).cast(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
        )
    };
    if result != 0 || u32::from_ne_bytes(buffer[..4].try_into().ok()?) < 20 {
        return None;
    }
    let mut bytes = b"project-history-scope-v1\0object\0darwin-volume-uuid\0".to_vec();
    bytes.extend_from_slice(&buffer[4..20]);
    bytes.extend_from_slice(&metadata.st_ino().to_le_bytes());
    bytes.extend_from_slice(&metadata.st_birthtime().to_le_bytes());
    bytes.extend_from_slice(&metadata.st_birthtime_nsec().to_le_bytes());
    Some(bytes)
}

#[cfg(target_os = "linux")]
fn durable_object_witness(handle: &File) -> Option<Vec<u8>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let metadata = handle.metadata().ok()?;
    let volume_uuid = linux_volume_uuid(metadata.dev())?;
    let mut statx: libc::statx = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::statx(
            handle.as_raw_fd(),
            b"\0".as_ptr().cast(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_INO | libc::STATX_BTIME,
            &mut statx,
        )
    };
    if result != 0 || statx.stx_mask & libc::STATX_BTIME == 0 {
        return None;
    }
    let mut bytes = b"project-history-scope-v1\0object\0linux-filesystem-uuid\0".to_vec();
    bytes.extend_from_slice(&volume_uuid);
    bytes.extend_from_slice(&statx.stx_ino.to_le_bytes());
    bytes.extend_from_slice(&statx.stx_btime.tv_sec.to_le_bytes());
    bytes.extend_from_slice(&statx.stx_btime.tv_nsec.to_le_bytes());
    Some(bytes)
}

#[cfg(target_os = "linux")]
fn linux_volume_uuid(device: u64) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    for directory in ["/dev/disk/by-uuid", "/dev/disk/by-partuuid"] {
        let mut candidates = fs::read_dir(directory)
            .ok()?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let metadata = fs::metadata(entry.path()).ok()?;
                (metadata.rdev() == device).then(|| entry.file_name())
            })
            .collect::<Vec<_>>();
        candidates.sort();
        if let Some(candidate) = candidates.first() {
            return Some(candidate.as_os_str().as_bytes().to_vec());
        }
    }
    None
}

#[cfg(windows)]
fn durable_object_witness(handle: &File) -> Option<Vec<u8>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let result =
        unsafe { GetFileInformationByHandle(handle.as_raw_handle().cast(), &mut information) };
    let creation = (u64::from(information.ftCreationTime.dwHighDateTime) << 32)
        | u64::from(information.ftCreationTime.dwLowDateTime);
    if result == 0 || creation == 0 {
        return None;
    }
    let file_id =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    let mut bytes = b"project-history-scope-v1\0object\0windows-volume-file-id\0".to_vec();
    bytes.extend_from_slice(&information.dwVolumeSerialNumber.to_le_bytes());
    bytes.extend_from_slice(&file_id.to_le_bytes());
    bytes.extend_from_slice(&creation.to_le_bytes());
    Some(bytes)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn durable_object_witness(_handle: &File) -> Option<Vec<u8>> {
    // Windows and filesystems without a trustworthy creation-generation plus
    // durable volume id use the explicitly weaker canonical-path form. This
    // must not be relabeled as an object proof.
    None
}

#[cfg(unix)]
fn open_directory_no_follow(path: &Path) -> io::Result<File> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(windows)]
fn open_directory_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

struct SecureDirectory {
    #[cfg(any(windows, test))]
    path: PathBuf,
    #[cfg(unix)]
    handle: File,
}

impl SecureDirectory {
    fn open(data_root: &Path) -> Result<Self, StoreError> {
        ensure_platform_data_root(data_root)?;
        let canonical = fs::canonicalize(data_root)?;
        let root = open_directory_no_follow(&canonical)?;
        validate_directory(&root)?;

        #[cfg(unix)]
        {
            let ibex = ensure_child_directory(&root, "ibex")?;
            let history = ensure_child_directory(&ibex, STORE_DIRECTORY)?;
            Ok(Self {
                #[cfg(test)]
                path: canonical.join("ibex").join(STORE_DIRECTORY),
                handle: history,
            })
        }
        #[cfg(windows)]
        {
            let ibex_path = canonical.join("ibex");
            ensure_windows_directory(&ibex_path)?;
            let history_path = ibex_path.join(STORE_DIRECTORY);
            ensure_windows_directory(&history_path)?;
            Ok(Self { path: history_path })
        }
    }

    fn open_existing_file(&self, name: &str) -> Result<File, StoreError> {
        self.open_file(name, false)
    }

    fn open_or_create_file(&self, name: &str) -> Result<(File, bool), StoreError> {
        match self.create_file(name) {
            Ok(file) => Ok((file, true)),
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.open_existing_file(name).map(|file| (file, false))
            }
            Err(error) => Err(error),
        }
    }

    fn create_temp_file(&self, kind: &str) -> Result<(String, File), StoreError> {
        for _ in 0..16 {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).map_err(|_| StoreError::KeyUnavailable)?;
            let name = format!(".{kind}-{}.tmp", hex(&random));
            match self.create_file(&name) {
                Ok(file) => return Ok((name, file)),
                Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary name collision",
        )))
    }

    #[cfg(unix)]
    fn open_file(&self, name: &str, create_new: bool) -> Result<File, StoreError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = c_name(name)?;
        let mut flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        if create_new {
            flags |= libc::O_CREAT | libc::O_EXCL;
        }
        let fd = unsafe { libc::openat(self.handle.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            return Err(StoreError::Io(io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        validate_file(&file)?;
        Ok(file)
    }

    #[cfg(windows)]
    fn open_file(&self, name: &str, create_new: bool) -> Result<File, StoreError> {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        if create_new {
            options.create_new(true);
        }
        let file = options.open(self.path.join(name)).map_err(StoreError::Io)?;
        validate_file(&file)?;
        Ok(file)
    }

    fn create_file(&self, name: &str) -> Result<File, StoreError> {
        self.open_file(name, true)
    }

    #[cfg(unix)]
    fn publish_no_clobber(&self, from: &str, to: &str) -> Result<(), StoreError> {
        use std::os::fd::AsRawFd;
        let from = c_name(from)?;
        let to = c_name(to)?;
        let result = unsafe {
            libc::linkat(
                self.handle.as_raw_fd(),
                from.as_ptr(),
                self.handle.as_raw_fd(),
                to.as_ptr(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(StoreError::Io(io::Error::last_os_error()))
        }
    }

    #[cfg(windows)]
    fn publish_no_clobber(&self, from: &str, to: &str) -> Result<(), StoreError> {
        fs::hard_link(self.path.join(from), self.path.join(to)).map_err(StoreError::Io)
    }

    #[cfg(unix)]
    fn replace(&self, from: &str, to: &str) -> Result<(), StoreError> {
        use std::os::fd::AsRawFd;
        let from = c_name(from)?;
        let to = c_name(to)?;
        let result = unsafe {
            libc::renameat(
                self.handle.as_raw_fd(),
                from.as_ptr(),
                self.handle.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(StoreError::Io(io::Error::last_os_error()))
        }
    }

    #[cfg(windows)]
    fn replace(&self, from: &str, to: &str) -> Result<(), StoreError> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        let wide = |path: &Path| {
            path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>()
        };
        let source = wide(&self.path.join(from));
        let destination = wide(&self.path.join(to));
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            Err(StoreError::Io(io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    #[cfg(unix)]
    fn remove(&self, name: &str) -> Result<(), StoreError> {
        use std::os::fd::AsRawFd;
        let name = c_name(name)?;
        let result = unsafe { libc::unlinkat(self.handle.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(StoreError::Io(io::Error::last_os_error()))
        }
    }

    #[cfg(windows)]
    fn remove(&self, name: &str) -> Result<(), StoreError> {
        fs::remove_file(self.path.join(name)).map_err(StoreError::Io)
    }

    #[cfg(unix)]
    fn sync(&self) -> Result<(), StoreError> {
        self.handle.sync_all().map_err(StoreError::Io)
    }

    #[cfg(windows)]
    fn sync(&self) -> Result<(), StoreError> {
        Ok(())
    }

    #[cfg(test)]
    fn file_path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

fn ensure_platform_data_root(path: &Path) -> Result<(), StoreError> {
    if !path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700).create(path)?;
        }
        #[cfg(windows)]
        fs::create_dir_all(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_child_directory(parent: &File, name: &str) -> Result<File, StoreError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if created != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(StoreError::Io(error));
        }
    }
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(StoreError::UnsafeStorage);
    }
    let directory = unsafe { File::from_raw_fd(fd) };
    validate_directory(&directory)?;
    Ok(directory)
}

#[cfg(windows)]
fn ensure_windows_directory(path: &Path) -> Result<(), StoreError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(StoreError::Io(error)),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(StoreError::UnsafeStorage);
    }
    Ok(())
}

#[cfg(unix)]
fn c_name(name: &str) -> Result<std::ffi::CString, StoreError> {
    if name.contains('/') {
        return Err(StoreError::UnsafeStorage);
    }
    std::ffi::CString::new(name).map_err(|_| StoreError::UnsafeStorage)
}

#[cfg(unix)]
fn validate_directory(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    let mode = metadata.mode();
    if mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR)
        || metadata.uid() != unsafe { libc::geteuid() }
        || mode & 0o022 != 0
    {
        return Err(StoreError::UnsafeStorage);
    }
    Ok(())
}

#[cfg(windows)]
fn validate_directory(file: &File) -> Result<(), StoreError> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let metadata = file.metadata()?;
    if metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(StoreError::UnsafeStorage)
    }
}

#[cfg(unix)]
fn validate_file(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    let mode = metadata.mode();
    if mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG)
        || metadata.uid() != unsafe { libc::geteuid() }
        || mode & 0o777 != 0o600
    {
        return Err(StoreError::UnsafeStorage);
    }
    Ok(())
}

#[cfg(windows)]
fn validate_file(file: &File) -> Result<(), StoreError> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let metadata = file.metadata()?;
    if metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(StoreError::UnsafeStorage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    struct FakeClock {
        millis: AtomicU64,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                millis: AtomicU64::new(0),
            }
        }
    }

    impl LockClock for FakeClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.millis.load(Ordering::SeqCst))
        }

        fn sleep(&self, duration: Duration) {
            self.millis
                .fetch_add(duration.as_millis() as u64, Ordering::SeqCst);
        }
    }

    fn startup<'a>(mode: HistoryMode, project: Option<&'a Path>) -> HistoryStartup<'a> {
        HistoryStartup {
            mode,
            editor_present: true,
            mode_was_explicit: false,
            authenticated_project_root: project,
        }
    }

    fn open_test(mode: HistoryMode, project: Option<&Path>, data: &Path) -> HistorySession {
        HistorySession::open_at(
            startup(mode, project),
            data,
            Arc::new(FakeClock::new()),
            Limits::generated(),
        )
    }

    #[test]
    fn off_and_editorless_modes_touch_no_history_files() {
        let parent = tempfile::tempdir().unwrap();
        let absent = parent.path().join("must-remain-absent");
        let off = HistorySession::open_at(
            startup(HistoryMode::Off, None),
            &absent,
            Arc::new(FakeClock::new()),
            Limits::generated(),
        );
        assert!(off.entries().is_empty());
        assert!(!absent.exists());

        let editorless = HistorySession::open_at(
            HistoryStartup {
                mode: HistoryMode::Project,
                editor_present: false,
                mode_was_explicit: false,
                authenticated_project_root: None,
            },
            &absent,
            Arc::new(FakeClock::new()),
            Limits::generated(),
        );
        assert!(editorless.startup_diagnostics().is_empty());
        assert!(
            !absent.exists(),
            "transcript/program modes perform no history I/O"
        );

        let explicit = HistorySession::open_at(
            HistoryStartup {
                mode: HistoryMode::Global,
                editor_present: false,
                mode_was_explicit: true,
                authenticated_project_root: None,
            },
            &absent,
            Arc::new(FakeClock::new()),
            Limits::generated(),
        );
        assert_eq!(
            explicit.startup_diagnostics(),
            &[HistoryDiagnostic::UnavailableWithoutEditor]
        );
        assert!(!absent.exists());
    }

    #[test]
    fn multiline_round_trips_and_blank_or_space_prefixed_input_is_ignored() {
        let data = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = open_test(HistoryMode::Project, Some(project.path()), data.path());
        let multiline = "const answer = {\n  value: 42\n};\nanswer";
        assert_eq!(
            session.append_submission(multiline),
            HistoryAppendDisposition::Persisted
        );
        assert_eq!(
            session.append_submission("   secret"),
            HistoryAppendDisposition::Ignored
        );
        assert_eq!(
            session.append_submission("\n\t"),
            HistoryAppendDisposition::Ignored
        );

        let reopened = open_test(HistoryMode::Project, Some(project.path()), data.path());
        assert_eq!(reopened.entries(), &[multiline]);
        assert_eq!(reopened.reverse_search("value", None), Some((0, multiline)));
    }

    #[test]
    fn torn_and_hostile_tails_recover_only_the_valid_prefix() {
        let data = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = open_test(HistoryMode::Project, Some(project.path()), data.path());
        session.append_submission("first");
        session.append_submission("second");
        let store = session.store.as_ref().unwrap();
        let journal = store.directory.file_path(&store.journal_name);
        let valid_len = fs::metadata(&journal).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap()
            .write_all(b"IBHJ\x01")
            .unwrap();

        let reopened = open_test(HistoryMode::Project, Some(project.path()), data.path());
        assert_eq!(reopened.entries(), &["first", "second"]);
        assert_eq!(fs::metadata(&journal).unwrap().len(), valid_len);

        // A complete-looking hostile record with a bad checksum is also tail
        // corruption, never a reason to discard the earlier prefix.
        let mut hostile = Vec::new();
        hostile.extend_from_slice(JOURNAL_MAGIC);
        hostile.extend_from_slice(&JOURNAL_VERSION.to_le_bytes());
        hostile.extend_from_slice(&0u16.to_le_bytes());
        hostile.extend_from_slice(&3u64.to_le_bytes());
        hostile.extend_from_slice(&4u32.to_le_bytes());
        hostile.extend_from_slice(b"evil");
        hostile.extend_from_slice(&[0u8; JOURNAL_CHECKSUM_BYTES]);
        OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap()
            .write_all(&hostile)
            .unwrap();
        let reopened = open_test(HistoryMode::Project, Some(project.path()), data.path());
        assert_eq!(reopened.entries(), &["first", "second"]);
        assert_eq!(fs::metadata(&journal).unwrap().len(), valid_len);
    }

    #[test]
    fn concurrent_first_run_publishes_one_key_without_clobbering_entries() {
        let data = Arc::new(tempfile::tempdir().unwrap());
        let project = Arc::new(tempfile::tempdir().unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for entry in ["from-a", "from-b"] {
            let data = Arc::clone(&data);
            let project = Arc::clone(&project);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let mut session = HistorySession::open_at(
                    startup(HistoryMode::Project, Some(project.path())),
                    data.path(),
                    Arc::new(SystemLockClock::new()),
                    Limits::generated(),
                );
                assert_eq!(
                    session.append_submission(entry),
                    HistoryAppendDisposition::Persisted,
                    "startup diagnostics: {:?}",
                    session.startup_diagnostics()
                );
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let reopened = open_test(HistoryMode::Project, Some(project.path()), data.path());
        assert_eq!(
            reopened.entries().iter().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from(["from-a".to_owned(), "from-b".to_owned()])
        );
        let key = data
            .path()
            .join("ibex")
            .join(STORE_DIRECTORY)
            .join(KEY_FILE);
        assert_eq!(fs::metadata(key).unwrap().len(), KEY_RECORD_BYTES as u64);
    }

    #[test]
    fn malformed_key_disables_persistence_and_is_never_rotated() {
        let data = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let session = open_test(HistoryMode::Project, Some(project.path()), data.path());
        let key_path = session
            .store
            .as_ref()
            .unwrap()
            .directory
            .file_path(KEY_FILE);
        fs::write(&key_path, b"malformed").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let before = fs::read(&key_path).unwrap();
        for _ in 0..2 {
            let disabled = open_test(HistoryMode::Project, Some(project.path()), data.path());
            assert!(disabled.store.is_none());
            assert!(disabled
                .startup_diagnostics()
                .contains(&HistoryDiagnostic::UserKeyUnavailableOrMalformed));
            assert_eq!(fs::read(&key_path).unwrap(), before);
        }
    }

    #[cfg(unix)]
    #[test]
    fn permissions_symlink_and_non_regular_files_are_refused() {
        use std::os::unix::fs::PermissionsExt;

        let data = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = open_test(HistoryMode::Project, Some(project.path()), data.path());
        session.append_submission("safe");
        let store = session.store.as_ref().unwrap();
        let journal = store.directory.file_path(&store.journal_name);
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
        let refused = open_test(HistoryMode::Project, Some(project.path()), data.path());
        assert!(refused.store.is_none());
        assert!(refused
            .startup_diagnostics()
            .contains(&HistoryDiagnostic::UnsafeStorageRefused));

        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&journal).unwrap();
        let victim = data.path().join("victim");
        fs::write(&victim, b"do not touch").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&victim, &journal).unwrap();
        let refused = open_test(HistoryMode::Project, Some(project.path()), data.path());
        assert!(refused.store.is_none());
        assert_eq!(fs::read(&victim).unwrap(), b"do not touch");

        fs::remove_file(&journal).unwrap();
        fs::create_dir(&journal).unwrap();
        let refused = open_test(HistoryMode::Project, Some(project.path()), data.path());
        assert!(refused.store.is_none());
    }

    #[test]
    fn projects_are_separate_while_global_mode_is_shared() {
        let data = tempfile::tempdir().unwrap();
        let project_a = tempfile::tempdir().unwrap();
        let project_b = tempfile::tempdir().unwrap();
        let mut a = open_test(HistoryMode::Project, Some(project_a.path()), data.path());
        let mut b = open_test(HistoryMode::Project, Some(project_b.path()), data.path());
        assert_ne!(
            a.store.as_ref().unwrap().journal_name,
            b.store.as_ref().unwrap().journal_name
        );
        a.append_submission("alpha");
        b.append_submission("beta");
        assert_eq!(
            open_test(HistoryMode::Project, Some(project_a.path()), data.path()).entries(),
            &["alpha"]
        );
        assert_eq!(
            open_test(HistoryMode::Project, Some(project_b.path()), data.path()).entries(),
            &["beta"]
        );

        let mut global_a = open_test(HistoryMode::Global, Some(project_a.path()), data.path());
        global_a.append_submission("shared");
        let global_b = open_test(HistoryMode::Global, Some(project_b.path()), data.path());
        assert_eq!(global_b.entries(), &["shared"]);
    }

    #[test]
    fn compaction_drops_oldest_by_generated_shape_without_losing_new_append() {
        let data = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let limits = Limits {
            entries: 3,
            bytes: 16,
            record_bytes: 16,
            lock_wait: Duration::from_millis(250),
        };
        let mut session = HistorySession::open_at(
            startup(HistoryMode::Project, Some(project.path())),
            data.path(),
            Arc::new(FakeClock::new()),
            limits,
        );
        for entry in ["one", "two", "three", "four", "five"] {
            assert_eq!(
                session.append_submission(entry),
                HistoryAppendDisposition::Persisted
            );
        }
        assert_eq!(session.entries(), &["three", "four", "five"]);
        let reopened = HistorySession::open_at(
            startup(HistoryMode::Project, Some(project.path())),
            data.path(),
            Arc::new(FakeClock::new()),
            limits,
        );
        assert_eq!(reopened.entries(), &["three", "four", "five"]);
    }

    #[test]
    fn concurrent_appends_survive_compaction_under_the_stable_sidecar_lock() {
        let data = Arc::new(tempfile::tempdir().unwrap());
        let project = Arc::new(tempfile::tempdir().unwrap());
        let limits = Limits {
            entries: 4,
            bytes: 128,
            record_bytes: 32,
            lock_wait: Duration::from_millis(250),
        };
        let mut initial = HistorySession::open_at(
            startup(HistoryMode::Project, Some(project.path())),
            data.path(),
            Arc::new(SystemLockClock::new()),
            limits,
        );
        for entry in ["base-a", "base-b", "base-c"] {
            assert_eq!(
                initial.append_submission(entry),
                HistoryAppendDisposition::Persisted
            );
        }
        drop(initial);

        let barrier = Arc::new(Barrier::new(2));
        let threads = ["concurrent-a", "concurrent-b"].map(|entry| {
            let data = Arc::clone(&data);
            let project = Arc::clone(&project);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut session = HistorySession::open_at(
                    startup(HistoryMode::Project, Some(project.path())),
                    data.path(),
                    Arc::new(SystemLockClock::new()),
                    limits,
                );
                barrier.wait();
                assert_eq!(
                    session.append_submission(entry),
                    HistoryAppendDisposition::Persisted
                );
            })
        });
        for thread in threads {
            thread.join().unwrap();
        }

        let reopened = HistorySession::open_at(
            startup(HistoryMode::Project, Some(project.path())),
            data.path(),
            Arc::new(SystemLockClock::new()),
            limits,
        );
        assert_eq!(reopened.entries().len(), 4);
        assert!(reopened
            .entries()
            .iter()
            .any(|entry| entry == "concurrent-a"));
        assert!(reopened
            .entries()
            .iter()
            .any(|entry| entry == "concurrent-b"));
    }

    #[test]
    fn lock_timeout_is_bounded_by_the_injected_clock_and_does_not_append() {
        let data = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let clock = Arc::new(FakeClock::new());
        let limits = Limits {
            lock_wait: Duration::from_millis(20),
            ..Limits::generated()
        };
        let mut session = HistorySession::open_at(
            startup(HistoryMode::Project, Some(project.path())),
            data.path(),
            clock.clone(),
            limits,
        );
        let held = session
            .store
            .as_ref()
            .unwrap()
            .acquire_history_sidecar_lock()
            .unwrap();
        assert_eq!(
            session.append_submission("not-on-disk"),
            HistoryAppendDisposition::Skipped(HistoryDiagnostic::LockTimedOut)
        );
        assert_eq!(clock.now(), Duration::from_millis(20));
        drop(held);
        let reopened = HistorySession::open_at(
            startup(HistoryMode::Project, Some(project.path())),
            data.path(),
            Arc::new(FakeClock::new()),
            limits,
        );
        assert!(reopened.entries().is_empty());
    }

    #[test]
    fn monotonic_index_rollback_or_reordering_is_truncated_as_tamper() {
        let data = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = open_test(HistoryMode::Project, Some(project.path()), data.path());
        session.append_submission("one");
        let store = session.store.as_ref().unwrap();
        let journal = store.directory.file_path(&store.journal_name);
        let valid_len = fs::metadata(&journal).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&journal).unwrap();
        write_record(
            &mut file,
            &JournalRecord {
                index: 1,
                payload: "rollback".to_owned(),
            },
        )
        .unwrap();
        drop(file);
        let reopened = open_test(HistoryMode::Project, Some(project.path()), data.path());
        assert_eq!(reopened.entries(), &["one"]);
        assert_eq!(fs::metadata(journal).unwrap().len(), valid_len);
    }

    #[test]
    fn swapped_project_root_is_refused_before_history_store_io() {
        let fixture = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let project = fixture.path().join("project");
        let moved = fixture.path().join("authenticated-project-moved");
        fs::create_dir(&project).unwrap();

        let authenticated_handle = open_directory_no_follow(&project).unwrap();
        let authenticated_object =
            project_object_identity_for_handle(&authenticated_handle).unwrap();
        drop(authenticated_handle);

        fs::rename(&project, &moved).unwrap();
        fs::create_dir(&project).unwrap();

        let capture = HistoryPlatformCapture {
            mode: HistoryMode::Project,
            editor_present: true,
            mode_was_explicit: false,
            data_root: Some(data.path().to_owned()),
            diagnostic: None,
        }
        .bind_authenticated_project_root(Some(AuthenticatedProjectHistoryRoot {
            path: &project,
            object: &authenticated_object,
        }));
        let session = HistorySession::open_captured(
            capture,
            Arc::new(SystemLockClock::new()),
            Limits::generated(),
        );

        assert_eq!(
            session.startup_diagnostics(),
            &[HistoryDiagnostic::AuthenticatedProjectRootRequired]
        );
        assert!(!data.path().join("ibex").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_history_is_explicitly_fail_closed_until_dacl_proof_exists() {
        let capture = HistoryPlatformCapture::capture(HistoryMode::Global, true, true)
            .bind_authenticated_project_root(None);
        let session = HistorySession::open(capture);
        assert_eq!(
            session.startup_diagnostics(),
            &[HistoryDiagnostic::PlatformSecurityUnavailable]
        );
    }
}
