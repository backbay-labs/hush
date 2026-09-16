//! Hash-linked receipt log (spec/hushspec-log.md, format 0.1).
//!
//! A log is a JSON Lines file of [`LogEntry`] records. Each entry carries a
//! sequence number, the hash of the previous entry, its own hash over its
//! canonical form, and optionally an Ed25519 signature over that hash. A
//! verifier can therefore detect a line that was edited, deleted, inserted,
//! or reordered, without any other source of truth.
//!
//! Entries wrap a [`DecisionReceipt`] or a [`PolicyEvent`] (which policy was
//! loaded or swapped in, with its provenance) so the log proves not only what
//! was decided but what was in force when.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::canonical::{self, CanonicalError};
use crate::receipt::{
    DecisionReceipt, EnforcementMode, PolicySummary, RECEIPT_VERSION, format_timestamp,
};
use crate::sink::{ReceiptSink, SinkError};
use crate::version::HUSHSPEC_VERSION;

#[cfg(feature = "signing")]
use crate::signing::{Envelope, Keyring, SigningKey, VerifyOptions, sign_content_hash};

/// The log-entry format this module writes and verifies.
pub const LOG_VERSION: &str = "0.1";

/// `prev_hash` of the first entry of a log that continues nothing.
pub const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Load-time conditions reported by [`verify_log`] besides the signing spec's
/// reason codes.
pub const REASON_UNSIGNED: &str = "entry_unsigned";

// --------------------------------------------------------------------------
// Wire types
// --------------------------------------------------------------------------

/// What an entry wraps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    Receipt,
    PolicyLoaded,
    PolicySwapped,
    LogStarted,
}

/// The SDK that wrote an entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkInfo {
    pub name: String,
    pub version: String,
}

impl SdkInfo {
    /// This crate.
    #[must_use]
    pub fn this_sdk() -> Self {
        Self {
            name: "hushspec-rs".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEventKind {
    Loaded,
    Swapped,
}

/// A policy-in-effect record (log spec 6): what was enforced from this
/// moment on, with the same identity a receipt carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvent {
    pub event: PolicyEventKind,
    /// RFC 3339 UTC, millisecond precision.
    pub timestamp: String,
    pub policy: PolicySummary,
    pub enforcement_mode: EnforcementMode,
    pub sdk: SdkInfo,
    /// The HushSpec version the engine implements.
    pub spec_version: String,
    /// For `swapped`: the content hash of the policy that was replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_content_hash: Option<String>,
}

impl PolicyEvent {
    /// A `loaded` event for `policy`, stamped now.
    #[must_use]
    pub fn loaded(policy: PolicySummary, enforcement_mode: EnforcementMode) -> Self {
        Self {
            event: PolicyEventKind::Loaded,
            timestamp: format_timestamp(chrono::Utc::now()),
            policy,
            enforcement_mode,
            sdk: SdkInfo::this_sdk(),
            spec_version: HUSHSPEC_VERSION.to_string(),
            previous_content_hash: None,
        }
    }

    /// A `swapped` event: `policy` replaces the policy with `previous` hash.
    #[must_use]
    pub fn swapped(
        policy: PolicySummary,
        enforcement_mode: EnforcementMode,
        previous_content_hash: String,
    ) -> Self {
        Self {
            event: PolicyEventKind::Swapped,
            previous_content_hash: Some(previous_content_hash),
            ..Self::loaded(policy, enforcement_mode)
        }
    }
}

/// The first entry of a rotated log file: where the chain came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogStarted {
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_file: Option<String>,
    /// The last `entry_hash` of the previous file; equals this entry's
    /// `prev_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_entry_hash: Option<String>,
}

/// An entry signature: the 0.2 signature envelope (signing spec 4) whose
/// `content_hash` is the entry's `entry_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSignature {
    pub format_version: String,
    pub algorithm: String,
    pub key_id: String,
    pub signed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    pub signature: String,
}

/// One line of a log.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub log_version: String,
    /// Starts at 1 in every file and increases by exactly 1.
    pub seq: u64,
    /// `entry_hash` of the previous entry, or [`GENESIS_HASH`].
    pub prev_hash: String,
    pub entry_type: EntryType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<DecisionReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_event: Option<PolicyEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_started: Option<LogStarted>,
    /// `sha256:` over the canonical form of this entry without `entry_hash`
    /// and `signature`.
    pub entry_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<LogSignature>,
}

impl LogEntry {
    /// Recompute the hash this entry should carry.
    ///
    /// # Errors
    ///
    /// [`CanonicalError`] when the entry cannot be serialized.
    pub fn compute_entry_hash(&self) -> Result<String, CanonicalError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| CanonicalError::Serialize(error.to_string()))?;
        if let Some(object) = value.as_object_mut() {
            object.remove("entry_hash");
            object.remove("signature");
        }
        Ok(canonical::digest(&canonical::serialize_jcs(&value)?))
    }

    /// Whether exactly the payload named by `entry_type` is present.
    #[must_use]
    pub fn payload_matches_type(&self) -> bool {
        let (receipt, event, started) = (
            self.receipt.is_some(),
            self.policy_event.is_some(),
            self.log_started.is_some(),
        );
        match self.entry_type {
            EntryType::Receipt => receipt && !event && !started,
            EntryType::PolicyLoaded => {
                !receipt
                    && !started
                    && self
                        .policy_event
                        .as_ref()
                        .is_some_and(|e| e.event == PolicyEventKind::Loaded)
            }
            EntryType::PolicySwapped => {
                !receipt
                    && !started
                    && self
                        .policy_event
                        .as_ref()
                        .is_some_and(|e| e.event == PolicyEventKind::Swapped)
            }
            EntryType::LogStarted => started && !receipt && !event,
        }
    }
}

/// What an entry wraps, when appending.
#[derive(Clone, Debug)]
pub enum Payload {
    Receipt(Box<DecisionReceipt>),
    PolicyEvent(Box<PolicyEvent>),
    LogStarted(LogStarted),
}

// --------------------------------------------------------------------------
// Chained sink
// --------------------------------------------------------------------------

struct ChainState {
    path: PathBuf,
    seq: u64,
    prev_hash: String,
}

/// Appends hash-linked entries to a JSON Lines file, fsyncing each one.
///
/// Opening an existing file continues its chain from the last entry.
/// Appends are serialized in-process by a mutex and across processes by a
/// best-effort `<path>.lock` file; a lock held longer than
/// [`ChainedFileSink::LOCK_TIMEOUT`] is reported as an error rather than
/// bypassed. Each entry's `seq` and `prev_hash` come from the file's current
/// last entry, read while that lock is held, so a second sink or process
/// writing the same log extends the chain instead of forking it. Rotation
/// ([`ChainedFileSink::rotate`]) carries the chain into the new file through a
/// `log_started` entry.
pub struct ChainedFileSink {
    state: Mutex<ChainState>,
    /// Fixed instant for `log_started` timestamps and signature `signed_at`
    /// (conformance vectors); production sinks use the wall clock.
    clock: Option<chrono::DateTime<chrono::Utc>>,
    #[cfg(feature = "signing")]
    signer: Option<SigningKey>,
}

impl ChainedFileSink {
    /// How long to wait for another process's lock before failing.
    pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

    /// Open (or create) the log at `path` and continue its chain.
    ///
    /// # Errors
    ///
    /// [`SinkError::Io`] for I/O failures, [`SinkError::Chain`] when the
    /// existing file's last line is not a log entry.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SinkError> {
        let path = path.as_ref().to_path_buf();
        let (seq, prev_hash) = match last_entry(&path)? {
            Some(entry) => (entry.seq, entry.entry_hash),
            None => (0, GENESIS_HASH.to_string()),
        };
        Ok(Self {
            state: Mutex::new(ChainState {
                path,
                seq,
                prev_hash,
            }),
            clock: None,
            #[cfg(feature = "signing")]
            signer: None,
        })
    }

    /// Use a fixed instant for `log_started` timestamps and signatures.
    #[must_use]
    pub fn with_clock(mut self, clock: chrono::DateTime<chrono::Utc>) -> Self {
        self.clock = Some(clock);
        self
    }

    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.clock.unwrap_or_else(chrono::Utc::now)
    }

    /// Sign every entry with `key` (signing spec 4, over `entry_hash`).
    #[cfg(feature = "signing")]
    #[must_use]
    pub fn with_signer(mut self, key: SigningKey) -> Self {
        self.signer = Some(key);
        self
    }

    /// The file currently being written.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.state().path.clone()
    }

    /// The last sequence number and entry hash written (or the genesis
    /// values for an empty log).
    #[must_use]
    pub fn head(&self) -> (u64, String) {
        let state = self.state();
        (state.seq, state.prev_hash.clone())
    }

    /// Observe the chain head, recovering from a poisoned lock.
    ///
    /// A sink must never break enforcement, so reading the head of a log whose
    /// previous writer panicked reports what is there rather than panicking in
    /// turn. Writers go through [`Self::state_mut`], which refuses instead.
    fn state(&self) -> std::sync::MutexGuard<'_, ChainState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Take the chain head for writing, refusing a poisoned lock.
    ///
    /// A panic between bumping `seq` and storing `entry_hash` would leave the
    /// head describing an entry that was never written, so appending onto it
    /// would produce a chain that cannot verify. Fail closed instead.
    fn state_mut(&self) -> Result<std::sync::MutexGuard<'_, ChainState>, SinkError> {
        self.state.lock().map_err(|_| {
            SinkError::Chain(
                "log state is poisoned: a previous append panicked, so the chain head \
                 cannot be trusted to continue the log"
                    .to_string(),
            )
        })
    }

    /// Append one entry.
    ///
    /// The chain head is re-read from the file under the write lock, so an
    /// entry continues what the file holds rather than what this sink last
    /// wrote. A tail that cannot be parsed fails the append: continuing past
    /// it would leave a second, unlinked chain in the file.
    ///
    /// # Errors
    ///
    /// [`SinkError::Io`], [`SinkError::Serialization`], or
    /// [`SinkError::Chain`].
    pub fn append(&self, payload: Payload) -> Result<LogEntry, SinkError> {
        let mut state = self.state_mut()?;
        let path = state.path.clone();
        let cached = (state.seq, state.prev_hash.clone());
        let entry = with_file_lock(&path, || {
            // A missing or empty file means a fresh log, or a rotation whose
            // `log_started` entry is about to seed the new file; both continue
            // from the head this sink carries.
            let (seq, prev_hash) = match last_entry(&path)? {
                Some(head) => (head.seq, head.entry_hash),
                None => cached,
            };
            let mut entry = LogEntry {
                log_version: LOG_VERSION.to_string(),
                seq: seq + 1,
                prev_hash,
                entry_type: match &payload {
                    Payload::Receipt(_) => EntryType::Receipt,
                    Payload::PolicyEvent(event) => match event.event {
                        PolicyEventKind::Loaded => EntryType::PolicyLoaded,
                        PolicyEventKind::Swapped => EntryType::PolicySwapped,
                    },
                    Payload::LogStarted(_) => EntryType::LogStarted,
                },
                receipt: None,
                policy_event: None,
                log_started: None,
                entry_hash: String::new(),
                signature: None,
            };
            match payload {
                Payload::Receipt(receipt) => entry.receipt = Some(*receipt),
                Payload::PolicyEvent(event) => entry.policy_event = Some(*event),
                Payload::LogStarted(started) => entry.log_started = Some(started),
            }
            entry.entry_hash = entry
                .compute_entry_hash()
                .map_err(|error| SinkError::Chain(error.to_string()))?;
            // Signing belongs under the lock too: the signature covers
            // `entry_hash`, which depends on the `prev_hash` just read.
            #[cfg(feature = "signing")]
            if let Some(key) = &self.signer {
                let options = crate::signing::SignOptions {
                    signed_at: Some(self.now()),
                    ..Default::default()
                };
                let envelope = sign_content_hash(&entry.entry_hash, key, &options)
                    .map_err(|error| SinkError::Chain(error.to_string()))?;
                entry.signature = Some(envelope_to_log_signature(&envelope));
            }

            let mut line = serde_json::to_string(&entry)?;
            line.push('\n');
            let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
            file.write_all(line.as_bytes())?;
            file.sync_all()?;
            Ok(entry)
        })?;

        state.seq = entry.seq;
        state.prev_hash.clone_from(&entry.entry_hash);
        Ok(entry)
    }

    /// Record a policy-in-effect event (log spec 6).
    ///
    /// # Errors
    ///
    /// As [`ChainedFileSink::append`].
    pub fn record_policy_event(&self, event: &PolicyEvent) -> Result<LogEntry, SinkError> {
        self.append(Payload::PolicyEvent(Box::new(event.clone())))
    }

    /// Start writing to `new_path`, whose first entry is a `log_started`
    /// record naming the file this chain continues from and its last hash.
    /// Sequence numbers restart at 1 in the new file; `prev_hash` carries over.
    ///
    /// # Errors
    ///
    /// As [`ChainedFileSink::append`]; the new file must not already exist.
    pub fn rotate(&self, new_path: impl AsRef<Path>) -> Result<LogEntry, SinkError> {
        let new_path = new_path.as_ref().to_path_buf();
        if new_path.exists() {
            return Err(SinkError::Chain(format!(
                "cannot rotate into existing file {}",
                new_path.display()
            )));
        }
        let (previous_file, previous_entry_hash) = {
            let mut state = self.state_mut()?;
            // Only the file name: logs are moved between hosts, and a path
            // would leak the writer's layout for no verification benefit.
            let previous = state
                .path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| state.path.display().to_string());
            let hash = state.prev_hash.clone();
            state.path = new_path;
            state.seq = 0;
            (previous, hash)
        };
        self.append(Payload::LogStarted(LogStarted {
            timestamp: format_timestamp(self.now()),
            previous_file: Some(previous_file),
            previous_entry_hash: (previous_entry_hash != GENESIS_HASH)
                .then_some(previous_entry_hash),
        }))
    }
}

impl ReceiptSink for ChainedFileSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        self.append(Payload::Receipt(Box::new(receipt.clone())))
            .map(|_| ())
    }

    fn record_policy_event(&self, event: &PolicyEvent) -> Result<(), SinkError> {
        ChainedFileSink::record_policy_event(self, event).map(|_| ())
    }
}

#[cfg(feature = "signing")]
fn envelope_to_log_signature(envelope: &Envelope) -> LogSignature {
    LogSignature {
        format_version: envelope.format_version.clone(),
        algorithm: envelope.algorithm.clone(),
        key_id: envelope.key_id.clone(),
        signed_at: envelope.signed_at.clone(),
        expires_at: envelope.expires_at.clone(),
        policy_version: envelope.policy_version,
        policy_name: envelope.policy_name.clone(),
        content_hash: envelope.content_hash.clone(),
        signer: envelope.signer.clone(),
        signature: envelope.signature.clone(),
    }
}

#[cfg(feature = "signing")]
fn log_signature_to_envelope(signature: &LogSignature) -> Envelope {
    Envelope {
        format_version: signature.format_version.clone(),
        algorithm: signature.algorithm.clone(),
        key_id: signature.key_id.clone(),
        signed_at: signature.signed_at.clone(),
        expires_at: signature.expires_at.clone(),
        policy_version: signature.policy_version,
        policy_name: signature.policy_name.clone(),
        content_hash: signature.content_hash.clone(),
        signer: signature.signer.clone(),
        signature: signature.signature.clone(),
    }
}

/// Read the last non-empty line of `path` as an entry, or `None` for a
/// missing or empty file.
fn last_entry(path: &Path) -> Result<Option<LogEntry>, SinkError> {
    let Some(line) = last_line(path)? else {
        return Ok(None);
    };
    serde_json::from_str::<LogEntry>(&line)
        .map(Some)
        .map_err(|error| {
            SinkError::Chain(format!(
                "last line of {} is not a log entry: {error}",
                path.display()
            ))
        })
}

/// How much of the tail to read at a time when looking for the last line.
const TAIL_CHUNK_BYTES: u64 = 8 * 1024;

/// The last non-empty line of `path`, read by seeking back from the end.
///
/// Every append reads the head this way, so the cost has to be the size of one
/// entry rather than the size of the log.
fn last_line(path: &Path) -> Result<Option<String>, SinkError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SinkError::Io(error)),
    };
    let mut end = file.seek(SeekFrom::End(0))?;
    let mut tail: Vec<u8> = Vec::new();
    while end > 0 {
        let start = end.saturating_sub(TAIL_CHUNK_BYTES);
        let mut chunk = vec![0u8; (end - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&tail);
        tail = chunk;
        end = start;
        if let Some(line) = last_line_of(&tail, end == 0) {
            return String::from_utf8(line.to_vec()).map(Some).map_err(|error| {
                SinkError::Chain(format!(
                    "last line of {} is not UTF-8: {error}",
                    path.display()
                ))
            });
        }
    }
    Ok(None)
}

/// The last non-empty line inside `buffer`, or `None` when it may still begin
/// earlier in the file. `at_start` says `buffer` reaches the file's first byte,
/// so a line with no newline before it is already complete.
fn last_line_of(buffer: &[u8], at_start: bool) -> Option<&[u8]> {
    let last = buffer
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())?;
    let trimmed = &buffer[..=last];
    match trimmed.iter().rposition(|byte| *byte == b'\n') {
        Some(index) => Some(&trimmed[index + 1..]),
        None if at_start => Some(trimmed),
        None => None,
    }
}

/// Run `f` while holding `<path>.lock`, created atomically. A stale lock
/// (a writer that died) times out rather than being bypassed.
fn with_file_lock<T>(
    path: &Path,
    f: impl FnOnce() -> Result<T, SinkError>,
) -> Result<T, SinkError> {
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let start = Instant::now();
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if start.elapsed() > ChainedFileSink::LOCK_TIMEOUT {
                    return Err(SinkError::Chain(format!(
                        "timed out waiting for {}",
                        lock_path.display()
                    )));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(SinkError::Io(error)),
        }
    }
    // Release through `Drop`: a panic inside `f` would otherwise leave the
    // lock file behind, and every later append would wait out `LOCK_TIMEOUT`
    // and then fail permanently.
    struct LockGuard(PathBuf);
    impl Drop for LockGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _guard = LockGuard(lock_path);
    f()
}

// --------------------------------------------------------------------------
// Verification
// --------------------------------------------------------------------------

/// What a verifier trusts and demands.
#[derive(Default)]
pub struct LogVerifyOptions {
    /// Every entry must carry a signature that verifies.
    pub require_signatures: bool,
    /// Keys to verify entry signatures against. When absent, signed entries
    /// are counted but not verified (an error under `require_signatures`).
    #[cfg(feature = "signing")]
    pub keyring: Option<Keyring>,
    #[cfg(feature = "signing")]
    pub verify: Option<VerifyOptions>,
}

/// Summary of a verified log.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogVerifyReport {
    pub files: usize,
    pub entries: usize,
    pub receipts: usize,
    pub policy_events: usize,
    pub signed: usize,
    pub verified_signatures: usize,
    pub last_seq: u64,
    pub last_entry_hash: String,
}

/// Why a log did not verify. `file` and `line` locate the first break.
#[derive(Debug, thiserror::Error)]
#[error("{file}:{line}: {message}")]
pub struct LogError {
    pub file: String,
    pub line: usize,
    pub message: String,
}

/// Verify one log file's text.
///
/// # Errors
///
/// [`LogError`] naming the first line that breaks the chain.
pub fn verify_log(
    name: &str,
    text: &str,
    options: &LogVerifyOptions,
) -> Result<LogVerifyReport, LogError> {
    verify_logs(&[(name, text)], options)
}

/// Verify a sequence of rotated log files in order: each file after the
/// first must start with a `log_started` entry whose `previous_entry_hash`
/// is the previous file's last hash.
///
/// # Errors
///
/// [`LogError`] naming the first line that breaks the chain.
pub fn verify_logs(
    files: &[(&str, &str)],
    options: &LogVerifyOptions,
) -> Result<LogVerifyReport, LogError> {
    let mut report = LogVerifyReport {
        last_entry_hash: GENESIS_HASH.to_string(),
        ..LogVerifyReport::default()
    };
    let mut carried_hash: Option<String> = None;

    for (index, (name, text)) in files.iter().enumerate() {
        report.files += 1;
        let mut expected_seq = 1u64;
        let mut prev_hash = carried_hash
            .clone()
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let mut any = false;

        for (line_index, line) in text.lines().enumerate() {
            let line_no = line_index + 1;
            if line.trim().is_empty() {
                continue;
            }
            let fail = |message: String| LogError {
                file: (*name).to_string(),
                line: line_no,
                message,
            };
            let entry: LogEntry =
                serde_json::from_str(line).map_err(|e| fail(entry_parse_message(line, &e)))?;
            if entry.log_version != LOG_VERSION {
                return Err(fail(format!(
                    "unsupported log_version {:?}, expected {LOG_VERSION:?}",
                    entry.log_version
                )));
            }
            if entry.seq != expected_seq {
                return Err(fail(format!(
                    "sequence gap: expected seq {expected_seq}, found {}",
                    entry.seq
                )));
            }
            if !entry.payload_matches_type() {
                return Err(fail(format!(
                    "payload does not match entry_type {:?}",
                    entry.entry_type
                )));
            }
            if expected_seq == 1 && index > 0 {
                let Some(started) = &entry.log_started else {
                    return Err(fail(
                        "a continued file must start with a log_started entry".into(),
                    ));
                };
                // An empty predecessor carries the genesis hash, which
                // `rotate` records as an absent `previous_entry_hash`; treat
                // the two spellings as the same link.
                let started_hash = started.previous_entry_hash.as_deref();
                let carried = carried_hash.as_deref();
                if started_hash.unwrap_or(GENESIS_HASH) != carried.unwrap_or(GENESIS_HASH) {
                    return Err(fail(
                        "log_started.previous_entry_hash does not match the previous file's last hash"
                            .into(),
                    ));
                }
            }
            if expected_seq == 1
                && let Some(started) = &entry.log_started
                && let Some(previous) = &started.previous_entry_hash
                && index == 0
            {
                // The first file of a set may itself continue an earlier
                // file the verifier was not given; its prev_hash must then
                // be that file's last hash.
                prev_hash.clone_from(previous);
            }
            if entry.prev_hash != prev_hash {
                return Err(fail(format!(
                    "prev_hash {} does not link to the previous entry {}",
                    entry.prev_hash, prev_hash
                )));
            }
            let recomputed = entry
                .compute_entry_hash()
                .map_err(|e| fail(format!("cannot canonicalize entry: {e}")))?;
            if recomputed != entry.entry_hash {
                return Err(fail(format!(
                    "entry_hash {} does not match the entry's canonical form ({recomputed})",
                    entry.entry_hash
                )));
            }
            if let Some(receipt) = &entry.receipt {
                if receipt.receipt_version != RECEIPT_VERSION {
                    return Err(fail(format!(
                        "receipt_version {:?} is not {RECEIPT_VERSION:?}",
                        receipt.receipt_version
                    )));
                }
                report.receipts += 1;
            }
            if entry.policy_event.is_some() {
                report.policy_events += 1;
            }
            match &entry.signature {
                None => {
                    if options.require_signatures {
                        return Err(fail(format!("{REASON_UNSIGNED}: signatures are required")));
                    }
                }
                Some(signature) => {
                    report.signed += 1;
                    if signature.content_hash != entry.entry_hash {
                        return Err(fail(
                            "signature.content_hash does not name this entry's entry_hash".into(),
                        ));
                    }
                    #[cfg(feature = "signing")]
                    {
                        match &options.keyring {
                            Some(keyring) => {
                                let envelope = log_signature_to_envelope(signature);
                                let verify = options.verify.clone().unwrap_or_default();
                                crate::signing::verify_content_hash(
                                    &envelope,
                                    Some(&entry.entry_hash),
                                    keyring,
                                    &verify,
                                )
                                .map_err(|e| fail(format!("signature: {e}")))?;
                                report.verified_signatures += 1;
                            }
                            None if options.require_signatures => {
                                return Err(fail(
                                    "no_keyring: cannot verify a required signature".into(),
                                ));
                            }
                            None => {}
                        }
                    }
                    #[cfg(not(feature = "signing"))]
                    if options.require_signatures {
                        return Err(fail(
                            "signing_unavailable: cannot verify a required signature".into(),
                        ));
                    }
                }
            }
            prev_hash.clone_from(&entry.entry_hash);
            expected_seq += 1;
            any = true;
            report.entries += 1;
            report.last_seq = entry.seq;
            report.last_entry_hash.clone_from(&entry.entry_hash);
        }
        if !any && index > 0 {
            return Err(LogError {
                file: (*name).to_string(),
                line: 0,
                message: "continued file is empty".to_string(),
            });
        }
        carried_hash = Some(prev_hash);
    }
    Ok(report)
}

/// Why a line is not a log entry.
///
/// A `receipt` member of the wrong shape is named as such (log spec 8, step 8)
/// rather than reported as an opaque parse failure, so every SDK reports the
/// same break for the same line.
fn entry_parse_message(line: &str, error: &serde_json::Error) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
        && let Some(receipt) = value.get("receipt")
        && let Err(receipt_error) = serde_json::from_value::<DecisionReceipt>(receipt.clone())
    {
        return format!(
            "receipt does not validate against the 0.2 receipt schema: {receipt_error}"
        );
    }
    format!("not a log entry: {error}")
}

/// Verify the log files at `paths`, in order.
///
/// # Errors
///
/// [`LogError`] with `line: 0` for a file that cannot be read, otherwise as
/// [`verify_logs`].
pub fn verify_log_files(
    paths: &[impl AsRef<Path>],
    options: &LogVerifyOptions,
) -> Result<LogVerifyReport, LogError> {
    let mut texts = Vec::with_capacity(paths.len());
    for path in paths {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|e| LogError {
            file: path.display().to_string(),
            line: 0,
            message: format!("cannot read: {e}"),
        })?;
        texts.push((path.display().to_string(), text));
    }
    let borrowed: Vec<(&str, &str)> = texts
        .iter()
        .map(|(name, text)| (name.as_str(), text.as_str()))
        .collect();
    verify_logs(&borrowed, options)
}
