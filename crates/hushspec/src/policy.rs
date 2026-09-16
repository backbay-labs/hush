//! The recommended way into the SDK: `load → resolve → verify → validate →
//! compile`, in one place, so no caller has to remember the order.
//!
//! ```no_run
//! use hushspec::{EvaluationAction, Policy, ResolveOptions};
//!
//! let policy = Policy::from_path("rulesets/default.yaml")?
//!     .resolve(ResolveOptions::default())
//!     .compile()?;
//!
//! let action = EvaluationAction {
//!     action_type: "egress".to_string(),
//!     target: Some("api.example.com".to_string()),
//!     ..Default::default()
//! };
//! let decision = policy.evaluate(&action);
//! # Ok::<(), hushspec::PolicyError>(())
//! ```
//!
//! Every step is fail-closed: a document that will not load, will not resolve,
//! will not verify when verification is required, does not validate, or cannot
//! be compiled never becomes a [`CompiledPolicy`], so there is no path on which
//! an action is evaluated against a policy the engine does not fully
//! understand.
//!
//! The returned [`CompiledPolicy`] carries the [`Resolution`] it came from --
//! chain, signature status, content hash -- so
//! [`CompiledPolicy::evaluate_audited`] needs nothing else to write a receipt.

use std::path::Path;

use crate::compiled::{CompileError, CompiledPolicy};
use crate::panic::PanicState;
use crate::resolve::{LoadedSpec, MEMORY_SOURCE, Resolution, ResolveError, ResolveOptions};
use crate::schema::HushSpec;
use crate::validate::{ValidationError, validate};

#[cfg(feature = "signing")]
use crate::signing::Keyring;

/// A loader: resolves an `extends` reference to a document.
type Loader = dyn Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError> + Send + Sync;

/// Anything that can stop a document becoming a [`CompiledPolicy`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The policy file could not be read.
    #[error("failed to read HushSpec document at {path}: {message}")]
    Read {
        /// Path that could not be read.
        path: String,
        /// The underlying I/O error.
        message: String,
    },
    /// The document is not a well-formed HushSpec document.
    #[error("failed to parse HushSpec document at {origin}: {message}")]
    Parse {
        /// Where the document came from.
        origin: String,
        /// The parser's message.
        message: String,
    },
    /// Resolution (including verify-on-load) failed.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// The resolved document is not valid.
    #[error("policy failed validation: {}", .errors.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))]
    Validation {
        /// Every validation error, in document order.
        errors: Vec<ValidationError>,
    },
    /// The resolved, valid document could not be compiled.
    #[error(transparent)]
    Compile(#[from] CompileError),
}

/// Builder for a [`CompiledPolicy`].
///
/// `Policy::from_*` loads and parses; [`Policy::resolve`] and `verify`
/// *configure* resolution; [`Policy::compile`] runs resolution, validation and
/// compilation and hands back the compiled policy.
pub struct Policy {
    spec: HushSpec,
    source: Option<String>,
    loader: Option<Box<Loader>>,
    options: ResolveOptions,
    panic: PanicState,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("source", &self.source)
            .field("loader", &self.loader.is_some())
            .field("options", &self.options)
            .finish()
    }
}

impl Policy {
    /// Read and parse the policy file at `path`.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Read`] or [`PolicyError::Parse`].
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let display = path.display().to_string();
        // Canonicalize so relative `extends` resolve against the file's own
        // directory, exactly as `resolve_path_with_options` does.
        let canonical = std::fs::canonicalize(path).map_err(|error| PolicyError::Read {
            path: display.clone(),
            message: error.to_string(),
        })?;
        let content = std::fs::read_to_string(&canonical).map_err(|error| PolicyError::Read {
            path: display.clone(),
            message: error.to_string(),
        })?;
        let source = canonical.to_string_lossy().into_owned();
        let spec = HushSpec::parse(&content).map_err(|error| PolicyError::Parse {
            origin: source.clone(),
            message: error.to_string(),
        })?;
        Ok(Self::new(spec).with_source(source))
    }

    /// Parse a policy document held in memory.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Parse`].
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(document: &str) -> Result<Self, PolicyError> {
        let spec = HushSpec::parse(document).map_err(|error| PolicyError::Parse {
            origin: MEMORY_SOURCE.to_string(),
            message: error.to_string(),
        })?;
        Ok(Self::new(spec))
    }

    /// Start from an already-parsed document.
    #[must_use]
    pub fn from_spec(spec: HushSpec) -> Self {
        Self::new(spec)
    }

    fn new(spec: HushSpec) -> Self {
        Self {
            spec,
            source: None,
            loader: None,
            options: ResolveOptions::default(),
            panic: PanicState::default(),
        }
    }

    /// The document as loaded, before resolution. Useful for reporting on the
    /// leaf (its `extends` reference, its own hash) when resolution fails.
    #[must_use]
    pub fn spec(&self) -> &HushSpec {
        &self.spec
    }

    /// The name this document is known by in the resolution chain. Defaults to
    /// the canonical path for [`Policy::from_path`] and `"memory"` otherwise.
    #[must_use]
    pub fn source(&self) -> &str {
        self.source.as_deref().unwrap_or(MEMORY_SOURCE)
    }

    /// Name this document in the chain (a builtin reference, say). Set for you
    /// by [`Policy::from_path`].
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Resolve `extends` with this loader instead of the default
    /// builtin-then-file composite.
    #[must_use]
    pub fn with_loader<F>(mut self, loader: F) -> Self
    where
        F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError> + Send + Sync + 'static,
    {
        self.loader = Some(Box::new(loader));
        self
    }

    /// Give the compiled policy its own kill switch instead of the
    /// process-wide one (see [`PanicState`]).
    #[must_use]
    pub fn with_panic_state(mut self, state: PanicState) -> Self {
        self.panic = state;
        self
    }

    /// Resolve with `options`. Without this call, resolution runs with
    /// [`ResolveOptions::default`]: builtins and files, no verification.
    #[must_use]
    pub fn resolve(mut self, options: ResolveOptions) -> Self {
        self.options = options;
        self
    }

    /// Require every non-builtin document in the chain to carry a signature
    /// that verifies against `keyring` (signing spec 6.5). Sets
    /// `require_signature`, so an unverified document refuses to compile.
    #[cfg(feature = "signing")]
    #[must_use]
    pub fn verify(mut self, keyring: Keyring) -> Self {
        self.options.require_signature = true;
        self.options.keyring = Some(keyring);
        self
    }

    /// Verify opportunistically: record each document's verification outcome
    /// in the chain, but do not refuse an unsigned one.
    #[cfg(feature = "signing")]
    #[must_use]
    pub fn verify_opportunistically(mut self, keyring: Keyring) -> Self {
        self.options.keyring = Some(keyring);
        self
    }

    /// Resolve, validate and compile.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Resolve`] (including
    /// [`ResolveError::SignatureRequired`] when verification was required),
    /// [`PolicyError::Validation`], or [`PolicyError::Compile`].
    pub fn compile(self) -> Result<CompiledPolicy, PolicyError> {
        let Self {
            spec,
            source,
            loader,
            options,
            panic,
        } = self;

        let resolution = match loader {
            Some(loader) => {
                crate::resolve::resolve_with_options(&spec, source.as_deref(), &loader, &options)?
            }
            None => {
                let default = crate::resolve::create_composite_loader();
                crate::resolve::resolve_with_options(&spec, source.as_deref(), &default, &options)?
            }
        };

        Self::compile_resolution(resolution, panic)
    }

    /// Validate and compile a resolution someone else produced.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Validation`] or [`PolicyError::Compile`].
    pub fn compile_resolution(
        resolution: Resolution,
        panic: PanicState,
    ) -> Result<CompiledPolicy, PolicyError> {
        let validation = validate(&resolution.spec);
        if !validation.is_valid() {
            return Err(PolicyError::Validation {
                errors: validation.errors,
            });
        }
        Ok(CompiledPolicy::from_resolution(resolution)?.with_panic_state(panic))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvaluationAction;

    fn action(action_type: &str, target: &str) -> EvaluationAction {
        EvaluationAction {
            action_type: action_type.to_string(),
            target: Some(target.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn compiles_an_in_memory_document() {
        let policy = Policy::from_str(
            r#"
hushspec: "0.1.0"
name: test
rules:
  egress:
    allow: ["*.example.com"]
    default: block
"#,
        )
        .expect("parses")
        // A scoped latch: the panic tests arm the process-wide one, and the
        // lib test binary runs them concurrently with this.
        .with_panic_state(PanicState::new())
        .compile()
        .expect("compiles");

        assert_eq!(
            policy
                .evaluate(&action("egress", "api.example.com"))
                .decision,
            crate::Decision::Allow
        );
        assert_eq!(
            policy.evaluate(&action("egress", "evil.test")).decision,
            crate::Decision::Deny
        );
        assert_eq!(
            policy.resolution().expect("resolution").chain.len(),
            1,
            "a document with no extends has exactly one chain link"
        );
    }

    #[test]
    fn resolves_builtin_extends_through_the_default_loader() {
        let policy = Policy::from_str("hushspec: \"0.1.0\"\nextends: \"builtin:default\"\n")
            .expect("parses")
            .compile()
            .expect("compiles");
        let resolution = policy.resolution().expect("resolution");
        assert_eq!(resolution.chain.len(), 2);
        assert!(policy.spec().extends.is_none(), "extends is consumed");
    }

    #[test]
    fn refuses_an_invalid_document() {
        let error = Policy::from_str("hushspec: \"99.0.0\"\n")
            .expect("parses")
            .compile()
            .expect_err("an unsupported version must not compile");
        assert!(matches!(error, PolicyError::Validation { .. }), "{error}");
    }

    #[test]
    fn refuses_an_unresolvable_extends() {
        let error = Policy::from_str("hushspec: \"0.1.0\"\nextends: \"builtin:nope\"\n")
            .expect("parses")
            .compile()
            .expect_err("an unknown builtin must not compile");
        assert!(matches!(error, PolicyError::Resolve(_)), "{error}");
    }

    #[test]
    fn carries_a_scoped_panic_state() {
        let scoped = PanicState::new();
        let policy = Policy::from_str("hushspec: \"0.1.0\"\n")
            .expect("parses")
            .with_panic_state(scoped.clone())
            .compile()
            .expect("compiles");

        assert_eq!(
            policy.evaluate(&action("tool_call", "read")).decision,
            crate::Decision::Allow
        );
        scoped.activate();
        assert_eq!(
            policy.evaluate(&action("tool_call", "read")).decision,
            crate::Decision::Deny
        );
        assert!(
            !crate::panic::is_panic_active(),
            "a scoped latch must not arm the process-wide one"
        );
    }
}
