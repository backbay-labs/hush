//! Where a policy comes from, and how it gets replaced without a restart.
//!
//! A [`PolicyProvider`] answers one question -- "what is the policy right
//! now?" -- and answers it with a fully resolved, verified [`Resolution`], not
//! a bare document. That matters: a leaf policy whose `extends` chain has not
//! been merged silently drops every rule its base declares, so a provider that
//! handed one over would quietly weaken the guard.
//!
//! On top of that, two drivers reload on an interval and hand each new
//! resolution to a callback -- typically [`HushGuard::swap_policy`]:
//!
//! - [`PolicyWatcher`] watches one file. Each tick stats the file and reloads
//!   only when its mtime or size moved, so an unchanged policy costs one
//!   `stat`.
//! - [`PolicyPoller`] reloads through any provider on an interval and delivers
//!   only when the resolved `content_hash` actually changed.
//!
//! ```no_run
//! use hushspec::{HushGuard, Policy, PolicyWatcher};
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! let guard = Arc::new(HushGuard::from_path("policy.yaml")?);
//! let _watch = PolicyWatcher::new("policy.yaml")
//!     .every(Duration::from_secs(2))
//!     .swapping_into(guard.clone())
//!     .start()?;
//! // The guard now follows the file. Dropping `_watch` stops the thread.
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Fail-closed reloading
//!
//! A reload that will not load, resolve, verify, validate or compile is an
//! error, not a policy. The previous resolution stays in force, the error goes
//! to `on_error`, and the driver keeps ticking -- an unverified file must never
//! become the policy in effect just because it arrived second. The same applies
//! to [`HushGuard::swap_policy`], which validates and compiles before it
//! swaps.
//!
//! # Panic sentinel
//!
//! [`PolicyWatcher::panic_sentinel`] and [`PolicyPoller::panic_sentinel`] check
//! a sentinel file on the same tick as the reload and arm the guard's
//! [`PanicState`] when it appears -- governance spec file-based activation,
//! without a second thread. Checking fails closed: an I/O error that cannot
//! prove the file absent arms the latch.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::guard::{GuardError, HushGuard};
use crate::panic::PanicState;
use crate::resolve::{Resolution, ResolveError, ResolveOptions, resolve_path_with_options};

/// Why a policy could not be obtained.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The source could not be read or resolved.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// The document resolved but could not become a policy in force.
    #[error(transparent)]
    Guard(#[from] GuardError),
    /// Something else went wrong; see the message.
    #[error("{0}")]
    Other(String),
}

/// A source of policy.
///
/// Implementations must return a *resolved* [`Resolution`] -- `extends` merged
/// away, every hop hashed, whatever verification the options require already
/// done -- because a guard never re-resolves what a provider hands it: by then
/// the source the signatures were checked against is gone.
pub trait PolicyProvider: Send + Sync {
    /// Load the policy as it stands now.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] when the policy cannot be obtained or resolved.
    fn load(&self) -> Result<Resolution, ProviderError>;

    /// Where this provider loads from, for logs and error messages.
    fn source(&self) -> &str;
}

impl<T: PolicyProvider + ?Sized> PolicyProvider for Arc<T> {
    fn load(&self) -> Result<Resolution, ProviderError> {
        (**self).load()
    }

    fn source(&self) -> &str {
        (**self).source()
    }
}

// --------------------------------------------------------------------------
// File
// --------------------------------------------------------------------------

/// Loads a policy from a file, resolving relative `extends` against the file's
/// own directory and looking for its detached signature next to it.
pub struct FileProvider {
    path: PathBuf,
    source: String,
    options: ResolveOptions,
}

impl std::fmt::Debug for FileProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileProvider")
            .field("path", &self.path)
            .field("options", &self.options)
            .finish()
    }
}

impl FileProvider {
    /// Load `path` with no verification.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_options(path, ResolveOptions::default())
    }

    /// Load `path`, applying `options` on this load and on every reload.
    #[must_use]
    pub fn with_options(path: impl Into<PathBuf>, options: ResolveOptions) -> Self {
        let path = path.into();
        let source = path.to_string_lossy().into_owned();
        Self {
            path,
            source,
            options,
        }
    }

    /// The file this provider loads.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl PolicyProvider for FileProvider {
    fn load(&self) -> Result<Resolution, ProviderError> {
        Ok(resolve_path_with_options(&self.path, &self.options)?)
    }

    fn source(&self) -> &str {
        &self.source
    }
}

// --------------------------------------------------------------------------
// HTTPS
// --------------------------------------------------------------------------

/// Loads a policy over HTTPS through the SDK's own loader: HTTPS only, SSRF
/// protection, a size cap, and -- with a cache directory -- ETag revalidation,
/// so an unchanged policy costs a `304` rather than a body.
///
/// A remote policy may only extend a `builtin:` base. A remote base would have
/// to be fetched from an origin nobody vouched for, so it fails closed here
/// with a message that says so, rather than being evaluated without its base.
#[cfg(feature = "http")]
pub struct HttpProvider {
    url: String,
    config: crate::resolve::http::HttpLoaderConfig,
    options: ResolveOptions,
    /// A locator the caller installed, held behind an `Arc` so every load can
    /// be given it without moving it out of [`HttpProvider::options`].
    locator: Option<Arc<crate::resolve::SignatureLocator>>,
}

#[cfg(feature = "http")]
impl std::fmt::Debug for HttpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProvider")
            .field("url", &self.url)
            .field("config", &self.config)
            .field("options", &self.options)
            .field("signature_locator", &self.locator.is_some())
            .finish()
    }
}

#[cfg(feature = "http")]
impl HttpProvider {
    /// Load from `url` with the default loader configuration.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            config: crate::resolve::http::HttpLoaderConfig::default(),
            options: ResolveOptions::default(),
            locator: None,
        }
    }

    /// Replace the loader configuration (timeout, size cap, auth header, TLS).
    #[must_use]
    pub fn with_config(mut self, config: crate::resolve::http::HttpLoaderConfig) -> Self {
        self.config = config;
        self
    }

    /// Verify on every load with these options.
    #[must_use]
    pub fn with_options(mut self, mut options: ResolveOptions) -> Self {
        self.locator = options.signature_locator.take().map(Arc::from);
        self.options = options;
        self
    }

    /// Keep the ETag and body in `dir`, so a poll that finds the policy
    /// unchanged is answered `304 Not Modified` and costs no body transfer.
    #[must_use]
    pub fn with_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.cache_dir = Some(dir.into());
        self
    }

    /// Send this header on every request (`Authorization: <value>`).
    #[must_use]
    pub fn with_auth_header(mut self, value: impl Into<String>) -> Self {
        self.config.auth_header = Some(value.into());
        self
    }

    /// The URL this provider loads.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The options a load resolves under: the caller's, with the sidecar
    /// locator filled in when the caller left it unset.
    ///
    /// A policy fetched over the network needs its `<url>.sig` fetched the
    /// same way and under the same rules: the TLS trust, the size cap and the
    /// authorization header the policy was fetched with. The resolver's own
    /// default locator knows no URL sources, so without this a signed remote
    /// policy could never satisfy `require_signature`.
    fn resolve_options(&self) -> ResolveOptions {
        let locator: Box<crate::resolve::SignatureLocator> = match &self.locator {
            Some(caller) => {
                let caller = Arc::clone(caller);
                Box::new(move |source: &str| caller(source))
            }
            None => crate::resolve::http::signature_locator(self.config.clone()),
        };
        ResolveOptions {
            require_signature: self.options.require_signature,
            #[cfg(feature = "signing")]
            keyring: self.options.keyring.clone(),
            #[cfg(feature = "signing")]
            verify: self.options.verify.clone(),
            signature_locator: Some(locator),
        }
    }
}

#[cfg(feature = "http")]
impl PolicyProvider for HttpProvider {
    fn load(&self) -> Result<Resolution, ProviderError> {
        let loaded = crate::resolve::http::load_from_https(&self.url, &self.config)?;
        let options = self.resolve_options();
        let extends = loaded.spec.extends.clone();
        // Builtin-only loader: `source` is the URL, so the default locator
        // looks for `<url>.sig`.
        let builtins = |reference: &str, _from: Option<&str>| {
            let yaml =
                crate::resolve::load_builtin(reference).ok_or_else(|| ResolveError::NotFound {
                    reference: reference.to_string(),
                    message: "a remote policy may only extend a builtin ruleset".to_string(),
                })?;
            let spec = crate::HushSpec::parse(yaml).map_err(|error| ResolveError::Parse {
                path: reference.to_string(),
                message: error.to_string(),
            })?;
            let source = if reference.starts_with("builtin:") {
                reference.to_string()
            } else {
                format!("builtin:{reference}")
            };
            Ok(crate::resolve::LoadedSpec { source, spec })
        };
        crate::resolve::resolve_with_options(
            &loaded.spec,
            Some(&loaded.source),
            &builtins,
            &options,
        )
        .map_err(|error| match extends {
            Some(reference) => ProviderError::Other(format!(
                "failed to resolve policy 'extends: {reference}' from {}: {error}",
                self.url
            )),
            None => ProviderError::Resolve(error),
        })
    }

    fn source(&self) -> &str {
        &self.url
    }
}

// --------------------------------------------------------------------------
// Reload drivers
// --------------------------------------------------------------------------

/// Called with each newly resolved policy.
pub type OnChange = dyn Fn(&Resolution) + Send + Sync;
/// Called when a reload failed; the previous policy stays in force.
pub type OnError = dyn Fn(&ProviderError) + Send + Sync;

/// Default reload interval for both drivers.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// What a running [`PolicyWatcher`] or [`PolicyPoller`] shares with its
/// thread.
#[derive(Debug, Default)]
struct HandleState {
    stop: AtomicBool,
    generation: AtomicU64,
    errors: AtomicU64,
    last_error: Mutex<Option<String>>,
}

/// A running reload thread. Dropping it stops the thread and joins it.
#[derive(Debug)]
pub struct PolicyHandle {
    state: Arc<HandleState>,
    current: Arc<Mutex<Arc<Resolution>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PolicyHandle {
    /// The resolution most recently put in force.
    #[must_use]
    pub fn current(&self) -> Arc<Resolution> {
        match self.current.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// How many times a *new* policy was delivered (the initial load is 1).
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.state.generation.load(Ordering::SeqCst)
    }

    /// How many reloads failed since the driver started.
    #[must_use]
    pub fn errors(&self) -> u64 {
        self.state.errors.load(Ordering::SeqCst)
    }

    /// The message from the most recent failed reload.
    #[must_use]
    pub fn last_error(&self) -> Option<String> {
        match self.state.last_error.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Stop the thread and wait for it. Also runs on drop.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for PolicyHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The reload settings both drivers share.
#[derive(Default)]
struct Reload {
    interval: Option<Duration>,
    guard: Option<Arc<HushGuard>>,
    on_change: Option<Box<OnChange>>,
    on_error: Option<Box<OnError>>,
    sentinel: Option<(PathBuf, PanicState)>,
}

impl Reload {
    fn interval(&self) -> Duration {
        self.interval.unwrap_or(DEFAULT_INTERVAL)
    }
}

/// Drives one loop iteration shared by both drivers.
struct Loop {
    state: Arc<HandleState>,
    current: Arc<Mutex<Arc<Resolution>>>,
    reload: Reload,
}

impl Loop {
    /// Put `resolution` in force, or report why it could not be.
    ///
    /// The guard swap happens *first*: a document that will not validate or
    /// compile is a failed reload, so `current()`, `generation()` and the
    /// `on_change` callback all keep describing the policy actually in effect
    /// rather than one the guard rejected.
    fn deliver(&self, resolution: Resolution) {
        if let Err(error) = self.apply(&resolution) {
            self.fail(&error);
            return;
        }
        self.store(Arc::new(resolution));
    }

    /// Swap `resolution` into the attached guard, if there is one and it is
    /// not already holding exactly this document.
    ///
    /// The hash check is what keeps a driver's first tick quiet: the usual
    /// setup builds the guard and the watcher from the same file, and a
    /// `policy_swapped` entry for a policy that did not change would be noise
    /// in the audit log.
    fn apply(&self, resolution: &Resolution) -> Result<(), ProviderError> {
        let Some(guard) = self.reload.guard.as_ref() else {
            return Ok(());
        };
        if guard.content_hash() == resolution.content_hash {
            return Ok(());
        }
        guard.swap_policy(resolution.clone()).map_err(|error| {
            let error = ProviderError::Guard(error);
            // The observer stream shows the gap too, not just the callback.
            guard.report_load_failure(&error.to_string(), None);
            error
        })
    }

    fn store(&self, resolution: Arc<Resolution>) {
        match self.current.lock() {
            Ok(mut slot) => *slot = resolution.clone(),
            Err(poisoned) => *poisoned.into_inner() = resolution.clone(),
        }
        self.state.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(on_change) = self.reload.on_change.as_ref() {
            on_change(&resolution);
        }
    }

    fn current(&self) -> Arc<Resolution> {
        match self.current.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn fail(&self, error: &ProviderError) {
        self.state.errors.fetch_add(1, Ordering::SeqCst);
        match self.state.last_error.lock() {
            Ok(mut slot) => *slot = Some(error.to_string()),
            Err(poisoned) => *poisoned.into_inner() = Some(error.to_string()),
        }
        if let Some(on_error) = self.reload.on_error.as_ref() {
            on_error(error);
        }
    }

    fn check_sentinel(&self) {
        if let Some((path, panic)) = self.reload.sentinel.as_ref() {
            panic.check_sentinel(path);
        }
    }

    /// Sleep until the next tick, waking early if the handle was stopped.
    /// Returns `false` when the driver should exit.
    fn wait(&self) -> bool {
        // Poll the stop flag on a short beat so `stop()` and `drop()` return
        // promptly even with a long reload interval.
        const BEAT: Duration = Duration::from_millis(50);
        let mut left = self.reload.interval();
        while !left.is_zero() {
            if self.state.stop.load(Ordering::SeqCst) {
                return false;
            }
            let step = left.min(BEAT);
            std::thread::sleep(step);
            left -= step;
        }
        !self.state.stop.load(Ordering::SeqCst)
    }
}

/// Follows one policy file and delivers each change.
///
/// Each tick stats the file; a reload only happens when its mtime or size
/// moved, so a policy that is not changing costs a `stat` per interval. See
/// the module documentation for the fail-closed reload rule.
pub struct PolicyWatcher {
    provider: Arc<FileProvider>,
    reload: Reload,
}

impl std::fmt::Debug for PolicyWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyWatcher")
            .field("provider", &self.provider)
            .field("interval", &self.reload.interval())
            .finish()
    }
}

impl PolicyWatcher {
    /// Watch `path`, loading with no verification.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_provider(Arc::new(FileProvider::new(path)))
    }

    /// Watch the file a [`FileProvider`] was configured for, keeping its
    /// verification options.
    #[must_use]
    pub fn with_provider(provider: Arc<FileProvider>) -> Self {
        Self {
            provider,
            reload: Reload::default(),
        }
    }

    /// How often to check the file. Default: [`DEFAULT_INTERVAL`].
    #[must_use]
    pub fn every(mut self, interval: Duration) -> Self {
        self.reload.interval = Some(interval);
        self
    }

    /// Call `handler` with each newly resolved policy.
    #[must_use]
    pub fn on_change(mut self, handler: impl Fn(&Resolution) + Send + Sync + 'static) -> Self {
        self.reload.on_change = Some(Box::new(handler));
        self
    }

    /// Call `handler` when a reload fails. The previous policy stays in force.
    #[must_use]
    pub fn on_error(mut self, handler: impl Fn(&ProviderError) + Send + Sync + 'static) -> Self {
        self.reload.on_error = Some(Box::new(handler));
        self
    }

    /// Swap each new policy into `guard` before anything else sees it. A swap
    /// the guard rejects is reported through
    /// [`PolicyWatcher::on_error`], not [`PolicyWatcher::on_change`].
    #[must_use]
    pub fn swapping_into(mut self, guard: Arc<HushGuard>) -> Self {
        self.reload.guard = Some(guard);
        self
    }

    /// Arm `panic` when the sentinel file at `path` appears, checked on every
    /// tick (see the module documentation).
    #[must_use]
    pub fn panic_sentinel(mut self, path: impl Into<PathBuf>, panic: PanicState) -> Self {
        self.reload.sentinel = Some((path.into(), panic));
        self
    }

    /// Load once, then follow the file on a background thread.
    ///
    /// The initial load is synchronous and its failure is returned: a driver
    /// that never had a policy has nothing to keep.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] from the initial load.
    pub fn start(self) -> Result<PolicyHandle, ProviderError> {
        let Self { provider, reload } = self;
        // Fingerprint before loading: taking it afterwards would bake a write
        // that landed during the load into the baseline, and that edit would
        // then never be delivered.
        let baseline = stat(provider.path());
        let initial = provider.load()?;
        let state = Arc::new(HandleState::default());
        let current = Arc::new(Mutex::new(Arc::new(initial)));
        let driver = Loop {
            state: state.clone(),
            current: current.clone(),
            reload,
        };
        driver.check_sentinel();
        let initial = driver.current();
        // A guard that will not accept the very first policy is a
        // misconfiguration, not a reload to keep retrying.
        driver.apply(&initial)?;
        driver.state.generation.store(1, Ordering::SeqCst);
        if let Some(on_change) = driver.reload.on_change.as_ref() {
            on_change(&initial);
        }

        let path = provider.path().to_path_buf();
        let thread = std::thread::Builder::new()
            .name("hushspec-policy-watcher".to_string())
            .spawn(move || {
                let mut fingerprint = baseline;
                while driver.wait() {
                    driver.check_sentinel();
                    let next = stat(&path);
                    // `None` means the file is gone or unreadable right now:
                    // keep the policy in force and try again next tick rather
                    // than treat a mid-write rename as a policy change.
                    if next.is_none() || next == fingerprint {
                        continue;
                    }
                    fingerprint = next;
                    match provider.load() {
                        Ok(resolution) => driver.deliver(resolution),
                        Err(error) => driver.fail(&error),
                    }
                }
            })
            .map_err(|error| ProviderError::Other(error.to_string()))?;

        Ok(PolicyHandle {
            state,
            current,
            thread: Some(thread),
        })
    }
}

/// `(mtime, len)` of `path`, or `None` when it cannot be stated.
fn stat(path: &Path) -> Option<(std::time::SystemTime, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

/// Reloads through any [`PolicyProvider`] on an interval.
///
/// Delivers only when the resolved `content_hash` changed, so a remote policy
/// that is re-served byte-identically does not churn the guard.
pub struct PolicyPoller {
    provider: Arc<dyn PolicyProvider>,
    reload: Reload,
}

impl std::fmt::Debug for PolicyPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyPoller")
            .field("source", &self.provider.source())
            .field("interval", &self.reload.interval())
            .finish()
    }
}

impl PolicyPoller {
    /// Poll `provider`.
    #[must_use]
    pub fn new(provider: Arc<dyn PolicyProvider>) -> Self {
        Self {
            provider,
            reload: Reload::default(),
        }
    }

    /// How often to reload. Default: [`DEFAULT_INTERVAL`].
    #[must_use]
    pub fn every(mut self, interval: Duration) -> Self {
        self.reload.interval = Some(interval);
        self
    }

    /// Call `handler` with each newly resolved policy.
    #[must_use]
    pub fn on_change(mut self, handler: impl Fn(&Resolution) + Send + Sync + 'static) -> Self {
        self.reload.on_change = Some(Box::new(handler));
        self
    }

    /// Call `handler` when a reload fails. The previous policy stays in force.
    #[must_use]
    pub fn on_error(mut self, handler: impl Fn(&ProviderError) + Send + Sync + 'static) -> Self {
        self.reload.on_error = Some(Box::new(handler));
        self
    }

    /// Swap each new policy into `guard` before anything else sees it. A swap
    /// the guard rejects is reported through [`PolicyPoller::on_error`], not
    /// [`PolicyPoller::on_change`].
    #[must_use]
    pub fn swapping_into(mut self, guard: Arc<HushGuard>) -> Self {
        self.reload.guard = Some(guard);
        self
    }

    /// Arm `panic` when the sentinel file at `path` appears, checked on every
    /// tick.
    #[must_use]
    pub fn panic_sentinel(mut self, path: impl Into<PathBuf>, panic: PanicState) -> Self {
        self.reload.sentinel = Some((path.into(), panic));
        self
    }

    /// Load once, then reload on a background thread.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] from the initial load.
    pub fn start(self) -> Result<PolicyHandle, ProviderError> {
        let Self { provider, reload } = self;
        let initial = provider.load()?;
        let mut last_hash = initial.content_hash.clone();
        let state = Arc::new(HandleState::default());
        let current = Arc::new(Mutex::new(Arc::new(initial)));
        let driver = Loop {
            state: state.clone(),
            current: current.clone(),
            reload,
        };
        driver.check_sentinel();
        let initial = driver.current();
        // A guard that will not accept the very first policy is a
        // misconfiguration, not a reload to keep retrying.
        driver.apply(&initial)?;
        driver.state.generation.store(1, Ordering::SeqCst);
        if let Some(on_change) = driver.reload.on_change.as_ref() {
            on_change(&initial);
        }

        let thread = std::thread::Builder::new()
            .name("hushspec-policy-poller".to_string())
            .spawn(move || {
                while driver.wait() {
                    driver.check_sentinel();
                    match provider.load() {
                        Ok(resolution) => {
                            if resolution.content_hash == last_hash {
                                continue;
                            }
                            last_hash = resolution.content_hash.clone();
                            driver.deliver(resolution);
                        }
                        Err(error) => driver.fail(&error),
                    }
                }
            })
            .map_err(|error| ProviderError::Other(error.to_string()))?;

        Ok(PolicyHandle {
            state,
            current,
            thread: Some(thread),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate::{Decision, EvaluationAction};
    use std::io::Write as _;

    const ALLOWING: &str = r#"hushspec: "0.1.0"
name: allowing
rules:
  egress:
    allow: ["*.example.com"]
    default: block
"#;

    const BLOCKING: &str = r#"hushspec: "0.1.0"
name: blocking
rules:
  egress:
    allow: []
    default: block
"#;

    /// Parses and resolves, but does not validate: an unsupported spec
    /// version. It gets past the provider and is stopped by `swap_policy`.
    const UNSUPPORTED: &str = "hushspec: \"99.0.0\"\nname: broken\n";
    /// Does not even parse: an unknown top-level key (`deny_unknown_fields`).
    /// The provider itself refuses it.
    const UNPARSEABLE: &str = "hushspec: \"0.1.0\"\nnot_a_field: true\n";

    fn write(path: &Path, content: &str) {
        let mut file = std::fs::File::create(path).expect("creates");
        file.write_all(content.as_bytes()).expect("writes");
        file.sync_all().expect("syncs");
    }

    fn action(target: &str) -> EvaluationAction {
        EvaluationAction {
            action_type: "egress".to_string(),
            target: Some(target.to_string()),
            ..Default::default()
        }
    }

    /// Wait for `predicate`, or fail after a generous timeout. Watchers run on
    /// a real clock, so tests must not assume a tick already happened.
    fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if predicate() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}");
    }

    #[test]
    fn a_file_provider_resolves_the_extends_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.yaml");
        write(&path, "hushspec: \"0.1.0\"\nextends: \"builtin:default\"\n");

        let resolution = FileProvider::new(&path).load().expect("loads");
        assert!(
            resolution.spec.extends.is_none(),
            "a provider never hands over an unresolved leaf"
        );
        assert_eq!(resolution.chain.len(), 2);
    }

    #[cfg(feature = "http")]
    #[test]
    fn an_http_provider_locates_a_sidecar_under_its_own_configuration() {
        let provider = HttpProvider::new("https://policies.example.test/policy.yaml");
        let options = provider.resolve_options();
        let locate = options
            .signature_locator
            .as_ref()
            .expect("a provider without a locator installs the HTTPS one");
        // The HTTPS locator answers only URL sources; a file source is not its
        // business, so it reports no envelope rather than reaching the network.
        assert!(matches!(locate("policy.yaml"), Ok(None)));

        let supplied = HttpProvider::new("https://policies.example.test/policy.yaml").with_options(
            ResolveOptions {
                signature_locator: Some(Box::new(|_: &str| Ok(Some(b"envelope".to_vec())))),
                ..ResolveOptions::default()
            },
        );
        let supplied_options = supplied.resolve_options();
        let locate = supplied_options
            .signature_locator
            .as_ref()
            .expect("a caller's locator is kept as given");
        assert_eq!(
            locate("policy.yaml").expect("the caller's locator answers"),
            Some(b"envelope".to_vec())
        );
    }

    #[test]
    fn a_file_provider_reports_a_missing_file() {
        let error = FileProvider::new("/nonexistent/policy.yaml")
            .load()
            .expect_err("a missing policy is an error, not an empty one");
        assert!(matches!(error, ProviderError::Resolve(_)), "{error}");
    }

    #[test]
    fn a_watcher_swaps_the_guard_when_the_file_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.yaml");
        write(&path, ALLOWING);

        let guard = Arc::new(
            HushGuard::builder()
                .build_from_resolution_with(
                    FileProvider::new(&path).load().expect("loads"),
                    PanicState::new(),
                )
                .expect("builds"),
        );
        assert!(guard.check(&action("api.example.com")).allowed());

        let handle = PolicyWatcher::new(&path)
            .every(Duration::from_millis(20))
            .swapping_into(guard.clone())
            .start()
            .expect("starts");

        // A fresh mtime: some filesystems have coarse timestamps, and a
        // same-second rewrite of the same length would otherwise look
        // unchanged.
        std::thread::sleep(Duration::from_millis(50));
        write(&path, BLOCKING);

        eventually("the guard to follow the file", || {
            !guard.check(&action("api.example.com")).allowed()
        });
        assert!(handle.generation() >= 2);
        assert_eq!(handle.errors(), 0);
        assert_eq!(handle.current().spec.name.as_deref(), Some("blocking"));
    }

    #[test]
    fn a_reload_that_will_not_parse_keeps_the_last_good_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.yaml");
        write(&path, ALLOWING);

        let errors = Arc::new(AtomicU64::new(0));
        let counter = errors.clone();
        let handle = PolicyWatcher::new(&path)
            .every(Duration::from_millis(20))
            .on_error(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            })
            .start()
            .expect("starts");
        assert_eq!(handle.current().spec.name.as_deref(), Some("allowing"));

        std::thread::sleep(Duration::from_millis(50));
        write(&path, UNPARSEABLE);

        eventually("the failed reload to be reported", || {
            errors.load(Ordering::SeqCst) > 0
        });
        assert_eq!(
            handle.current().spec.name.as_deref(),
            Some("allowing"),
            "an unusable document must never displace the policy in force"
        );
        assert!(handle.last_error().is_some());
    }

    #[test]
    fn a_broken_reload_never_reaches_the_guard() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.yaml");
        write(&path, ALLOWING);

        let guard = Arc::new(
            HushGuard::builder()
                .build_from_resolution_with(
                    FileProvider::new(&path).load().expect("loads"),
                    PanicState::new(),
                )
                .expect("builds"),
        );
        let hash = guard.content_hash();

        let errors = Arc::new(AtomicU64::new(0));
        let counter = errors.clone();
        let _handle = PolicyWatcher::new(&path)
            .every(Duration::from_millis(20))
            .swapping_into(guard.clone())
            .on_error(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            })
            .start()
            .expect("starts");

        std::thread::sleep(Duration::from_millis(50));
        write(&path, UNSUPPORTED);
        eventually("the reload to fail", || errors.load(Ordering::SeqCst) > 0);
        assert_eq!(guard.content_hash(), hash);
        assert_eq!(
            guard.check(&action("api.example.com")).result.decision,
            Decision::Allow
        );
    }

    #[test]
    fn an_initial_load_failure_is_returned_rather_than_swallowed() {
        let error = PolicyWatcher::new("/nonexistent/policy.yaml")
            .start()
            .expect_err("a driver with no policy has nothing to keep");
        assert!(matches!(error, ProviderError::Resolve(_)), "{error}");
    }

    #[test]
    fn a_poller_delivers_only_when_the_content_hash_moves() {
        /// Serves whatever the test most recently put in it.
        struct Mutable {
            yaml: Mutex<String>,
            loads: AtomicU64,
        }
        impl PolicyProvider for Mutable {
            fn load(&self) -> Result<Resolution, ProviderError> {
                self.loads.fetch_add(1, Ordering::SeqCst);
                let yaml = self.yaml.lock().expect("lock").clone();
                let spec = crate::HushSpec::parse(&yaml)
                    .map_err(|error| ProviderError::Other(error.to_string()))?;
                Ok(Resolution::from_resolved(&spec, Some("test"))?)
            }
            fn source(&self) -> &str {
                "test"
            }
        }

        let provider = Arc::new(Mutable {
            yaml: Mutex::new(ALLOWING.to_string()),
            loads: AtomicU64::new(0),
        });
        let changes = Arc::new(AtomicU64::new(0));
        let counter = changes.clone();
        let handle = PolicyPoller::new(provider.clone())
            .every(Duration::from_millis(20))
            .on_change(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            })
            .start()
            .expect("starts");

        eventually("several polls of an unchanged policy", || {
            provider.loads.load(Ordering::SeqCst) >= 4
        });
        assert_eq!(
            changes.load(Ordering::SeqCst),
            1,
            "only the initial load was a change"
        );

        *provider.yaml.lock().expect("lock") = BLOCKING.to_string();
        eventually("the change to be delivered", || {
            changes.load(Ordering::SeqCst) >= 2
        });
        assert_eq!(handle.current().spec.name.as_deref(), Some("blocking"));
        assert_eq!(handle.generation(), 2);
    }

    #[test]
    fn a_driver_stops_when_its_handle_is_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.yaml");
        write(&path, ALLOWING);

        let ticks = Arc::new(AtomicU64::new(0));
        let counter = ticks.clone();
        struct Counting(Arc<AtomicU64>, PathBuf);
        impl PolicyProvider for Counting {
            fn load(&self) -> Result<Resolution, ProviderError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                FileProvider::new(&self.1).load()
            }
            fn source(&self) -> &str {
                "counting"
            }
        }

        let handle = PolicyPoller::new(Arc::new(Counting(counter, path)))
            .every(Duration::from_millis(10))
            .start()
            .expect("starts");
        eventually("a few polls", || ticks.load(Ordering::SeqCst) >= 3);
        drop(handle);

        let after = ticks.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            after,
            "dropping the handle stops the thread"
        );
    }

    #[test]
    fn a_sentinel_appearing_arms_the_guards_kill_switch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.yaml");
        write(&path, ALLOWING);
        let sentinel = dir.path().join(".hushspec_panic");

        let latch = PanicState::new();
        let guard = Arc::new(
            HushGuard::builder()
                .build_from_resolution_with(
                    FileProvider::new(&path).load().expect("loads"),
                    latch.clone(),
                )
                .expect("builds"),
        );
        let _handle = PolicyWatcher::new(&path)
            .every(Duration::from_millis(20))
            .panic_sentinel(&sentinel, guard.panic_state().clone())
            .start()
            .expect("starts");

        assert!(guard.check(&action("api.example.com")).allowed());
        write(&sentinel, "");
        eventually("the kill switch to arm", || latch.is_active());
        assert!(
            !guard.check(&action("api.example.com")).allowed(),
            "panic denies everything"
        );
    }
}
