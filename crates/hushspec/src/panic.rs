//! Emergency override (panic mode) for HushSpec.
//!
//! When panic mode is active, **all** evaluation returns `Deny` immediately,
//! before any rule evaluation takes place. This provides an instant kill
//! switch for agent runtimes that detect an active compromise.
//!
//! Panic is carried by a [`PanicState`] *handle* rather than by a process
//! global, so an embedder hosting several tenants in one process can arm one
//! tenant's kill switch without denying every other tenant's actions, and so
//! tests are not racing each other over one static.
//!
//! [`PanicState::shared`] is the process-wide handle. It is what
//! [`activate_panic`], [`deactivate_panic`], [`is_panic_active`] and
//! [`check_panic_sentinel`] drive, and what a
//! [`CompiledPolicy`](crate::CompiledPolicy) holds by default, so existing
//! `panic::activate_panic()`-style callers -- and the `h2h panic` sentinel --
//! keep working unchanged.
//!
//! Activation mechanisms:
//!  - Programmatic: [`PanicState::activate`] / [`PanicState::deactivate`], or
//!    the free [`activate_panic`] / [`deactivate_panic`] on the shared handle
//!  - Sentinel file: [`PanicState::check_sentinel`] / [`check_panic_sentinel`]
//!
//! Thread safety is guaranteed via an [`AtomicBool`].

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};

/// The process-wide panic latch, shared by every [`PanicState::shared`] handle
/// and by the free functions in this module.
static SHARED: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));

/// A handle on one panic latch.
///
/// Cloning a handle shares its latch: arming a clone arms every handle cloned
/// from the same origin. [`PanicState::new`] mints an independent latch;
/// [`PanicState::shared`] returns a handle on the process-wide one.
#[derive(Clone, Debug)]
pub struct PanicState {
    flag: Arc<AtomicBool>,
}

impl PanicState {
    /// A fresh, inactive latch, independent of the process-wide one.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A handle on the process-wide latch the free functions in this module
    /// drive. This is what [`PanicState::default`] returns and what a policy
    /// compiled without an explicit handle consults.
    #[must_use]
    pub fn shared() -> Self {
        Self {
            flag: SHARED.clone(),
        }
    }

    /// Arm this latch: every evaluation consulting it now denies.
    pub fn activate(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Disarm this latch, restoring normal evaluation.
    pub fn deactivate(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }

    /// Whether this latch is armed.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Whether two handles drive the same latch.
    #[must_use]
    pub fn same_latch(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.flag, &other.flag)
    }

    /// Check a sentinel file for panic activation.
    ///
    /// If the file at `path` exists, this latch is armed and `true` is
    /// returned. If the file does not exist, `false` is returned (the latch is
    /// **not** automatically disarmed -- use [`PanicState::deactivate`] for
    /// that).
    ///
    /// This is a kill switch, so it **fails closed**: if the file's existence
    /// cannot be determined (a permission or I/O error from `try_exists`), the
    /// sentinel is treated as present and the latch is armed.
    pub fn check_sentinel(&self, path: impl AsRef<Path>) -> bool {
        // An `Err` from `try_exists` means we could not prove the sentinel is
        // absent; treat that as present so a kill switch never fails open.
        let present = path.as_ref().try_exists().unwrap_or(true);
        if present {
            self.activate();
        }
        present
    }
}

impl Default for PanicState {
    /// The process-wide handle, so a policy that says nothing about panic still
    /// honours `h2h panic` and [`activate_panic`].
    fn default() -> Self {
        Self::shared()
    }
}

/// Activate panic mode on the process-wide latch. All subsequent evaluation
/// against policies holding the shared handle will deny.
pub fn activate_panic() {
    PanicState::shared().activate();
}

/// Deactivate panic mode on the process-wide latch, restoring normal
/// evaluation.
pub fn deactivate_panic() {
    PanicState::shared().deactivate();
}

/// Check if panic mode is currently active on the process-wide latch.
#[must_use]
pub fn is_panic_active() -> bool {
    PanicState::shared().is_active()
}

/// Get the built-in panic (deny-all) policy.
///
/// The panic policy is embedded at compile time from `rulesets/panic.yaml`,
/// via the generated `generated_builtins` module (see
/// `scripts/generate_rust_builtins.py`). Panics at runtime only if the
/// embedded YAML is somehow invalid (which would indicate a build-time defect).
pub fn panic_policy() -> crate::HushSpec {
    let yaml = crate::generated_builtins::PANIC_YAML;
    crate::HushSpec::parse(yaml).expect("panic policy must be valid")
}

/// Check a sentinel file for panic activation on the process-wide latch.
///
/// See [`PanicState::check_sentinel`], which this delegates to.
pub fn check_panic_sentinel(path: impl AsRef<Path>) -> bool {
    PanicState::shared().check_sentinel(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that touch the process-wide latch.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn activate_and_deactivate() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();

        assert!(!is_panic_active());
        activate_panic();
        assert!(is_panic_active());
        deactivate_panic();
        assert!(!is_panic_active());
    }

    #[test]
    fn scoped_handles_are_independent_of_the_shared_latch() {
        // No lock: this test must not touch the process-wide latch at all.
        let scoped = PanicState::new();
        assert!(!scoped.is_active());
        scoped.activate();
        assert!(scoped.is_active());
        assert!(!scoped.same_latch(&PanicState::shared()));

        let sibling = PanicState::new();
        assert!(!sibling.is_active(), "each new() latch is independent");

        let clone = scoped.clone();
        assert!(clone.is_active(), "clones share the latch");
        clone.deactivate();
        assert!(!scoped.is_active());
    }

    #[test]
    fn shared_handles_share_one_latch() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();

        let left = PanicState::shared();
        let right = PanicState::shared();
        assert!(left.same_latch(&right));
        left.activate();
        assert!(right.is_active());
        assert!(is_panic_active());
        right.deactivate();
        assert!(!is_panic_active());
    }

    #[test]
    fn panic_policy_parses() {
        // Does not touch global state -- no lock needed.
        let spec = panic_policy();
        assert_eq!(spec.name.as_deref(), Some("__hushspec_panic__"));
    }

    #[test]
    fn sentinel_file_activates_panic() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();

        let dir = std::env::temp_dir().join("hushspec_panic_test");
        let sentinel = dir.join(".hushspec_panic");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(&sentinel, "").unwrap();

        assert!(check_panic_sentinel(&sentinel));
        assert!(is_panic_active());

        // cleanup
        let _ = std::fs::remove_file(&sentinel);
        deactivate_panic();
    }

    #[test]
    fn sentinel_file_missing_does_not_activate() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();

        let path = std::env::temp_dir().join("hushspec_nonexistent_sentinel");
        let _ = std::fs::remove_file(&path);

        assert!(!check_panic_sentinel(&path));
        assert!(!is_panic_active());
    }

    #[test]
    fn panic_mode_denies_all_action_types() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();
        activate_panic();

        let spec = panic_policy();
        let action_types = [
            "tool_call",
            "egress",
            "file_read",
            "file_write",
            "patch_apply",
            "shell_command",
            "computer_use",
            "unknown_action",
        ];

        for action_type in action_types {
            let action = crate::EvaluationAction {
                action_type: action_type.to_string(),
                target: Some("anything".to_string()),
                ..Default::default()
            };
            let result = crate::evaluate(&spec, &action);
            assert_eq!(
                result.decision,
                crate::Decision::Deny,
                "expected deny for action type '{action_type}' during panic mode"
            );
            assert_eq!(result.matched_rule.as_deref(), Some("__hushspec_panic__"));
            assert_eq!(
                result.reason.as_deref(),
                Some("emergency panic mode is active")
            );
        }

        deactivate_panic();
    }

    #[test]
    fn deactivate_restores_normal_evaluation() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();

        // Create a permissive spec with no rules
        let yaml = r#"
hushspec: "0.1.0"
name: "permissive"
"#;
        let spec = crate::HushSpec::parse(yaml).unwrap();
        let action = crate::EvaluationAction {
            action_type: "tool_call".to_string(),
            target: Some("some_tool".to_string()),
            ..Default::default()
        };

        // Normal evaluation should allow
        let result = crate::evaluate(&spec, &action);
        assert_eq!(result.decision, crate::Decision::Allow);

        // Activate panic -- should deny
        activate_panic();
        let result = crate::evaluate(&spec, &action);
        assert_eq!(result.decision, crate::Decision::Deny);

        // Deactivate -- should allow again
        deactivate_panic();
        let result = crate::evaluate(&spec, &action);
        assert_eq!(result.decision, crate::Decision::Allow);
    }
}
