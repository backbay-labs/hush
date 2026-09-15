//! Policy bundle attestation (spec/hushspec-bundle.md).
//!
//! A signature says a policy was approved; a receipt says a decision was made
//! under it. Both name the policy by content hash, and neither carries the
//! document that hash identifies. A **bundle** does: it is a DSSE envelope
//! over an in-toto Statement whose predicate holds the resolved policy, every
//! hop of the `extends` chain that produced it, and the resolver that
//! produced them.
//!
//! # Wire format
//!
//! The envelope is ordinary [DSSE] and the payload an ordinary [in-toto
//! Statement v1], so `cosign verify-blob-attestation` and any in-toto
//! consumer read a bundle without knowing this specification. HushSpec fixes
//! two things DSSE leaves open: the payload bytes are the RFC 8785 canonical
//! serialization of the statement ([`crate::canonical::serialize_jcs`]), and
//! `keyid` is the signing specification's [`crate::signing::key_id`], so one
//! keyring serves policies, receipts, log entries, and bundles.
//!
//! [DSSE]: https://github.com/secure-systems-lab/dsse
//! [in-toto Statement v1]: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
//!
//! # Verification
//!
//! [`verify_bundle`] runs the four ordered checks of bundle spec 5.2 and
//! stops at the first failure, reporting the [`BundleReason`] that check
//! owns. Signature verification precedes the subject-digest check on purpose:
//! an edit in transit breaks the signature first, so `subject_digest_mismatch`
//! means an internally inconsistent statement that was signed anyway.
//!
//! # Feature flag
//!
//! This module is only available when the `signing` feature is enabled.

use crate::canonical::{self, CanonicalError};
use crate::resolve::{ChainLink, Resolution};
use crate::schema::HushSpec;
use crate::signing::{self, Keyring, SigningError, SigningKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::path::{Path, PathBuf};

/// The predicate format version this module produces and accepts.
pub const BUNDLE_VERSION: &str = "0.1";

/// The DSSE `payloadType` of every bundle.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The in-toto statement type of every bundle payload.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// The predicate type that names this specification.
pub const PREDICATE_TYPE: &str = "https://hushspec.dev/attestation/policy-bundle/v0.1";

/// The DSSE PAE version prefix (bundle spec 3.1).
const PAE_PREFIX: &str = "DSSEv1";

/// Default `resolver.tool` (bundle spec 4.2).
pub const RESOLVER_TOOL: &str = "h2h";

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Why a bundle could not be *produced*.
///
/// Verification failures are [`BundleVerifyError`], which carries a reason
/// code from the closed set of bundle spec 5.4.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("the policy has no canonical form: {0}")]
    Canonical(#[from] CanonicalError),

    #[error("{0}")]
    Signing(#[from] SigningError),

    #[error("malformed bundle: {0}")]
    Malformed(String),
}

/// The closed set of bundle verification reason codes (bundle spec 5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BundleReason {
    /// Check 1: not a well-formed bundle, statement, or predicate.
    MalformedBundle,
    /// Check 2: no signature names a key the keyring holds.
    UnknownKeyId,
    /// Check 2: a key was found but no signature verifies over the PAE.
    DsseSignatureMismatch,
    /// Check 3: `predicate.resolved` does not hash to the declared subject.
    SubjectDigestMismatch,
    /// Check 4: the policy the verifier re-resolved is not the bundled one.
    PolicyMismatch,
}

impl BundleReason {
    /// Every reason code, in check order.
    pub const ALL: [Self; 5] = [
        Self::MalformedBundle,
        Self::UnknownKeyId,
        Self::DsseSignatureMismatch,
        Self::SubjectDigestMismatch,
        Self::PolicyMismatch,
    ];

    /// The wire string, spelled as bundle spec 5.4 spells it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MalformedBundle => "malformed_bundle",
            Self::UnknownKeyId => "unknown_key_id",
            Self::DsseSignatureMismatch => "dsse_signature_mismatch",
            Self::SubjectDigestMismatch => "subject_digest_mismatch",
            Self::PolicyMismatch => "policy_mismatch",
        }
    }

    /// Parse a wire string back into a code. Unknown strings return `None`:
    /// the set is closed, so a code this build does not know is not a code.
    #[must_use]
    pub fn from_code(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == value)
    }
}

impl fmt::Display for BundleReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A verification failure, carrying the reason code of the check that failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleVerifyError {
    /// The bundle spec 5.4 code for the check that failed.
    pub reason: BundleReason,
    /// Free-text detail. Never load-bearing: consumers switch on `reason`.
    pub detail: String,
}

impl BundleVerifyError {
    fn new(reason: BundleReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// The reason code as the wire string of bundle spec 5.4.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.reason.as_str()
    }
}

impl fmt::Display for BundleVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.detail)
    }
}

impl std::error::Error for BundleVerifyError {}

// --------------------------------------------------------------------------
// The envelope (bundle spec 3)
// --------------------------------------------------------------------------

/// One DSSE signature over the payload's PAE.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    /// The signing key's `key_id` (signing spec 5.2).
    pub keyid: String,
    /// Standard base64 with padding of the 64 signature bytes.
    pub sig: String,
}

/// A policy bundle: a DSSE envelope carrying an in-toto statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    /// Always [`PAYLOAD_TYPE`].
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Standard base64 with padding of the statement's canonical bytes.
    pub payload: String,
    /// Zero or more signatures. Empty means unsigned, which is not evidence.
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    /// Parse a bundle from JSON text (bundle spec 5.2 check 1, envelope
    /// half).
    ///
    /// # Errors
    ///
    /// [`BundleReason::MalformedBundle`] when the text is not JSON, carries
    /// an unknown member, is missing a required one, or names a payload type
    /// this specification does not define.
    pub fn parse(json: &str) -> Result<Self, BundleVerifyError> {
        let envelope: Self = serde_json::from_str(json).map_err(|error| {
            BundleVerifyError::new(BundleReason::MalformedBundle, format!("{error}"))
        })?;
        if envelope.payload_type != PAYLOAD_TYPE {
            return Err(BundleVerifyError::new(
                BundleReason::MalformedBundle,
                format!(
                    "payloadType {:?}, expected {PAYLOAD_TYPE:?}",
                    envelope.payload_type
                ),
            ));
        }
        Ok(envelope)
    }

    /// Read and parse a bundle file.
    ///
    /// # Errors
    ///
    /// [`BundleError::Io`] when the file cannot be read, or
    /// [`BundleError::Malformed`] carrying the shape failure. A caller that
    /// needs the reason code reads the file itself and calls
    /// [`DsseEnvelope::parse`].
    pub fn load(path: &Path) -> Result<Self, BundleError> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text).map_err(|error| BundleError::Malformed(error.detail))
    }

    /// The decoded payload bytes.
    ///
    /// # Errors
    ///
    /// [`BundleReason::MalformedBundle`] when `payload` is not base64.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, BundleVerifyError> {
        BASE64.decode(&self.payload).map_err(|error| {
            BundleVerifyError::new(
                BundleReason::MalformedBundle,
                format!("payload is not standard base64: {error}"),
            )
        })
    }

    /// The decoded, shape-checked statement (bundle spec 5.2 check 1).
    ///
    /// # Errors
    ///
    /// [`BundleReason::MalformedBundle`].
    pub fn statement(&self) -> Result<Statement, BundleVerifyError> {
        let bytes = self.payload_bytes()?;
        let text = String::from_utf8(bytes).map_err(|error| {
            BundleVerifyError::new(
                BundleReason::MalformedBundle,
                format!("the payload is not UTF-8: {error}"),
            )
        })?;
        let statement: Statement = serde_json::from_str(&text).map_err(|error| {
            BundleVerifyError::new(
                BundleReason::MalformedBundle,
                format!("the payload is not a policy-bundle statement: {error}"),
            )
        })?;
        statement.check_shape()?;
        Ok(statement)
    }

    /// The bytes a signature covers: `PAE(payloadType, payload bytes)`
    /// (bundle spec 3.1).
    ///
    /// # Errors
    ///
    /// [`BundleReason::MalformedBundle`] when the payload is not base64.
    pub fn pae(&self) -> Result<Vec<u8>, BundleVerifyError> {
        Ok(pae(&self.payload_type, &self.payload_bytes()?))
    }

    /// The bundle as JSON text: pretty-printed, with a trailing newline.
    ///
    /// # Errors
    ///
    /// [`BundleError::Json`] if serialization fails.
    pub fn to_json(&self) -> Result<String, BundleError> {
        Ok(format!("{}\n", serde_json::to_string_pretty(self)?))
    }

    /// Write the bundle to a file.
    ///
    /// # Errors
    ///
    /// [`BundleError::Io`] or [`BundleError::Json`].
    pub fn save(&self, path: &Path) -> Result<(), BundleError> {
        std::fs::write(path, self.to_json()?)?;
        Ok(())
    }
}

/// The DSSE Pre-Authentication Encoding (bundle spec 3.1).
///
/// `PAE(t, b) = "DSSEv1" SP LEN(t) SP t SP LEN(b) SP b`, with lengths in
/// ASCII decimal over **bytes**. Binding the type into the signed bytes is
/// what stops a payload being replayed under a different type.
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "{PAE_PREFIX} {} {payload_type} {} ",
        payload_type.len(),
        payload.len()
    );
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    out
}

// --------------------------------------------------------------------------
// The statement (bundle spec 4)
// --------------------------------------------------------------------------

/// The digest of an in-toto subject. Only `sha256` is defined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectDigest {
    /// 64 lowercase hex digits: the content hash **without** its `sha256:`
    /// prefix, as in-toto requires.
    pub sha256: String,
}

/// The attested artifact: the canonical form of the resolved policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    /// Informational label: the policy's `name`, else the leaf file name.
    pub name: String,
    pub digest: SubjectDigest,
}

/// What produced the bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolver {
    /// `"h2h"` for the reference CLI.
    pub tool: String,
    pub version: String,
}

/// Identity of the resolved policy, the same fields a receipt's `policy`
/// block carries (receipt spec 4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyIdentity {
    /// `sha256:`-prefixed content hash of the resolved policy.
    pub content_hash: String,
    /// The resolved document's `hushspec` field.
    pub spec_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u64>,
}

/// The policy-bundle predicate (bundle spec 4.2).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundlePredicate {
    /// `"0.1"`.
    pub bundle_version: String,
    pub policy: PolicyIdentity,
    /// The `extends` chain, root first and leaf last.
    pub chain: Vec<ChainLink>,
    /// The canonical projection of the resolved document.
    pub resolved: Value,
    pub resolver: Resolver,
    /// RFC 3339 UTC, millisecond precision, `Z` suffix.
    pub created_at: String,
    /// The leaf policy's own signature status, when verification was
    /// attempted at bundling time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_verification: Option<crate::resolve::SignatureStatus>,
}

/// An in-toto Statement v1 carrying a policy-bundle predicate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    /// `"https://in-toto.io/Statement/v1"`.
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// Exactly one subject.
    pub subject: Vec<Subject>,
    /// [`PREDICATE_TYPE`].
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: PolicyBundlePredicate,
}

impl Statement {
    /// The payload bytes: the RFC 8785 canonical serialization of this
    /// statement, UTF-8 encoded (bundle spec 4).
    ///
    /// # Errors
    ///
    /// [`BundleError::Json`] or [`BundleError::Canonical`] for a value
    /// RFC 8785 cannot represent, which a statement's members never are.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, BundleError> {
        let value = serde_json::to_value(self)?;
        Ok(canonical::serialize_jcs(&value)?.into_bytes())
    }

    /// Everything bundle spec 5.2 check 1 constrains beyond the envelope.
    fn check_shape(&self) -> Result<(), BundleVerifyError> {
        let bad = |detail: String| BundleVerifyError::new(BundleReason::MalformedBundle, detail);

        if self.statement_type != STATEMENT_TYPE {
            return Err(bad(format!(
                "_type {:?}, expected {STATEMENT_TYPE:?}",
                self.statement_type
            )));
        }
        if self.predicate_type != PREDICATE_TYPE {
            return Err(bad(format!(
                "predicateType {:?}, expected {PREDICATE_TYPE:?}",
                self.predicate_type
            )));
        }
        if self.subject.len() != 1 {
            return Err(bad(format!(
                "a bundle attests exactly one subject, found {}",
                self.subject.len()
            )));
        }
        let subject = &self.subject[0];
        if subject.name.is_empty() {
            return Err(bad("the subject name is empty".to_string()));
        }
        if !is_hex_digest(&subject.digest.sha256) {
            return Err(bad(format!(
                "subject digest {:?} is not 64 lowercase hex characters",
                subject.digest.sha256
            )));
        }

        let predicate = &self.predicate;
        if predicate.bundle_version != BUNDLE_VERSION {
            return Err(bad(format!(
                "bundle_version {:?}, expected {BUNDLE_VERSION:?}",
                predicate.bundle_version
            )));
        }
        if !is_content_hash(&predicate.policy.content_hash) {
            return Err(bad(format!(
                "policy.content_hash {:?} is not sha256:<64 lowercase hex>",
                predicate.policy.content_hash
            )));
        }
        if predicate.policy.spec_version.is_empty() {
            return Err(bad("policy.spec_version is empty".to_string()));
        }
        if !is_millisecond_timestamp(&predicate.created_at) {
            return Err(bad(format!(
                "created_at {:?} is not RFC 3339 UTC with millisecond precision",
                predicate.created_at
            )));
        }
        if predicate.resolver.tool.is_empty() || predicate.resolver.version.is_empty() {
            return Err(bad(
                "resolver.tool and resolver.version are required and must be non-empty".to_string(),
            ));
        }
        if predicate.chain.is_empty() {
            return Err(bad(
                "the chain must hold at least one link (the policy itself)".to_string(),
            ));
        }
        for link in &predicate.chain {
            if link.source.is_empty() {
                return Err(bad("a chain link has an empty source".to_string()));
            }
            if !is_content_hash(&link.content_hash) {
                return Err(bad(format!(
                    "chain link {:?} has content_hash {:?}, not sha256:<64 lowercase hex>",
                    link.source, link.content_hash
                )));
            }
        }
        if !predicate.resolved.is_object() {
            return Err(bad("predicate.resolved is not a JSON object".to_string()));
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------
// Building (bundle spec 4)
// --------------------------------------------------------------------------

/// The choices a bundler makes beyond the resolution itself.
#[derive(Clone, Debug)]
pub struct BundleOptions {
    /// When the bundle was produced. Defaults to now, truncated to
    /// milliseconds. Pinning it is what makes a bundle byte-reproducible.
    pub created_at: Option<DateTime<Utc>>,
    /// `resolver.tool`.
    pub tool: String,
    /// `resolver.version`.
    pub version: String,
    /// Overrides the subject name, which otherwise comes from the policy.
    pub subject_name: Option<String>,
    /// Directory that filesystem chain sources are recorded relative to
    /// (bundle spec 4.4), so a bundle built in CI carries no workspace path.
    pub base_dir: Option<PathBuf>,
}

impl Default for BundleOptions {
    fn default() -> Self {
        Self {
            created_at: None,
            tool: RESOLVER_TOOL.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            subject_name: None,
            base_dir: None,
        }
    }
}

/// Build the statement for a resolved policy (bundle spec 4).
///
/// The subject digest is recomputed from the canonical projection that goes
/// into `predicate.resolved`, so the statement is internally consistent by
/// construction: there is no path by which the bundle names a hash of a
/// document other than the one it carries.
///
/// # Errors
///
/// [`BundleError::Canonical`] when the resolved document has no canonical
/// form, which for a [`Resolution`] means a resolver bug.
pub fn build_statement(
    resolution: &Resolution,
    options: &BundleOptions,
) -> Result<Statement, BundleError> {
    let resolved = canonical::canonical_value(&resolution.spec)?;
    let content_hash = canonical::digest(&canonical::serialize_jcs(&resolved)?);
    let created_at = options.created_at.unwrap_or_else(Utc::now);

    let chain: Vec<ChainLink> = resolution
        .chain
        .iter()
        .map(|link| ChainLink {
            source: relative_source(&link.source, options.base_dir.as_deref()),
            content_hash: link.content_hash.clone(),
            signature: link.signature.clone(),
        })
        .collect();

    let name = options
        .subject_name
        .clone()
        .or_else(|| resolution.spec.name.clone())
        .or_else(|| leaf_file_name(&chain))
        .unwrap_or_else(|| "policy".to_string());

    Ok(Statement {
        statement_type: STATEMENT_TYPE.to_string(),
        subject: vec![Subject {
            name,
            digest: SubjectDigest {
                sha256: content_hash
                    .strip_prefix(canonical::CONTENT_HASH_PREFIX)
                    .unwrap_or(&content_hash)
                    .to_string(),
            },
        }],
        predicate_type: PREDICATE_TYPE.to_string(),
        predicate: PolicyBundlePredicate {
            bundle_version: BUNDLE_VERSION.to_string(),
            policy: policy_identity(&resolution.spec, &content_hash),
            chain,
            resolved,
            resolver: Resolver {
                tool: options.tool.clone(),
                version: options.version.clone(),
            },
            created_at: created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            signature_verification: resolution.signature.clone(),
        },
    })
}

fn policy_identity(spec: &HushSpec, content_hash: &str) -> PolicyIdentity {
    PolicyIdentity {
        content_hash: content_hash.to_string(),
        spec_version: spec.hushspec.clone(),
        name: spec.name.clone(),
        policy_version: spec
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.policy_version)
            .map(|version| version as u64),
    }
}

/// The leaf's file name, for a policy that declares no `name`.
fn leaf_file_name(chain: &[ChainLink]) -> Option<String> {
    let source = &chain.last()?.source;
    Path::new(source)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

/// Record a filesystem source relative to `base` when it lies beneath it
/// (bundle spec 4.4). `builtin:` and URL sources are already portable and are
/// returned unchanged, as is any path outside `base`.
fn relative_source(source: &str, base: Option<&Path>) -> String {
    let Some(base) = base else {
        return source.to_string();
    };
    if source.starts_with("builtin:") || source.contains("://") {
        return source.to_string();
    }
    match Path::new(source).strip_prefix(base) {
        // A bundle is JSON read on every platform, so the separator is `/`.
        Ok(relative) => relative.to_string_lossy().replace('\\', "/"),
        Err(_) => source.to_string(),
    }
}

/// Wrap a statement in an unsigned envelope.
///
/// An unsigned bundle is not evidence (bundle spec 3): [`verify_bundle`]
/// rejects it. Callers that produce one MUST say so.
///
/// # Errors
///
/// As [`Statement::to_canonical_bytes`].
pub fn unsigned_envelope(statement: &Statement) -> Result<DsseEnvelope, BundleError> {
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE.to_string(),
        payload: BASE64.encode(statement.to_canonical_bytes()?),
        signatures: Vec::new(),
    })
}

/// Sign a statement, producing a one-signature bundle (bundle spec 3.1).
///
/// # Errors
///
/// As [`Statement::to_canonical_bytes`], or [`BundleError::Signing`] when the
/// key's id cannot be derived.
pub fn sign_statement(
    statement: &Statement,
    signing_key: &SigningKey,
) -> Result<DsseEnvelope, BundleError> {
    let payload = statement.to_canonical_bytes()?;
    let signature = signing_key.sign(&pae(PAYLOAD_TYPE, &payload));
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE.to_string(),
        payload: BASE64.encode(payload),
        signatures: vec![DsseSignature {
            keyid: signing::key_id(&signing_key.verifying_key())?,
            sig: BASE64.encode(signature.to_bytes()),
        }],
    })
}

/// Build and sign a bundle for a resolution in one step.
///
/// # Errors
///
/// As [`build_statement`] and [`sign_statement`].
pub fn bundle_resolution(
    resolution: &Resolution,
    signing_key: Option<&SigningKey>,
    options: &BundleOptions,
) -> Result<DsseEnvelope, BundleError> {
    let statement = build_statement(resolution, options)?;
    match signing_key {
        Some(key) => sign_statement(&statement, key),
        None => unsigned_envelope(&statement),
    }
}

// --------------------------------------------------------------------------
// Verification (bundle spec 5)
// --------------------------------------------------------------------------

/// What a verifier knows besides the bundle and the keyring.
#[derive(Clone, Debug)]
pub struct VerifyBundleOptions {
    /// The verifier's clock. A bundle carries no expiry, so this only stamps
    /// the report's `verified_at`.
    pub now: DateTime<Utc>,
}

impl Default for VerifyBundleOptions {
    fn default() -> Self {
        Self { now: Utc::now() }
    }
}

/// The claims of a bundle that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleVerified {
    /// Every key whose signature verified.
    pub key_ids: Vec<String>,
    /// The subject label.
    pub subject_name: String,
    /// The resolved policy's content hash, `sha256:`-prefixed.
    pub content_hash: String,
    pub policy_name: Option<String>,
    pub policy_version: Option<u64>,
    pub created_at: String,
    /// Number of `extends` hops the bundle records.
    pub chain_length: usize,
    /// Whether check 4 ran (a policy file was supplied).
    pub policy_checked: bool,
    /// The verifier's clock, in the receipt timestamp form.
    pub verified_at: String,
}

/// Run the four ordered checks of bundle spec 5.2, stopping at the first
/// failure.
///
/// `policy` is the caller's own resolution of the policy file to cross-check
/// against, or `None` to skip check 4. Passing a [`Resolution`] rather than a
/// path keeps the checks independent of how a caller loads policies.
///
/// # Errors
///
/// [`BundleVerifyError`] carrying the [`BundleReason`] of the check that
/// failed.
pub fn verify_bundle(
    envelope: &DsseEnvelope,
    keyring: &Keyring,
    policy: Option<&Resolution>,
    options: &VerifyBundleOptions,
) -> Result<BundleVerified, BundleVerifyError> {
    // 1. Shape.
    let statement = envelope.statement()?;
    let predicate = &statement.predicate;

    // 2. Signature. A bundle may carry several; one that verifies under a
    //    trusted key is enough, and the reason code distinguishes "we trust
    //    nobody who signed this" from "the signature is wrong".
    let pae_bytes = envelope.pae()?;
    let mut key_ids = Vec::new();
    let mut named_a_trusted_key = false;
    let mut mismatch_detail = String::new();
    for signature in &envelope.signatures {
        let Some(entry) = keyring.find(&signature.keyid) else {
            continue;
        };
        let Ok(verifying_key) = entry.verifying_key() else {
            continue;
        };
        // The declared id is never enough (signing spec 5.2).
        match signing::key_id(&verifying_key) {
            Ok(recomputed) if recomputed == signature.keyid => {}
            _ => continue,
        }
        named_a_trusted_key = true;
        let Some(bytes) = BASE64
            .decode(&signature.sig)
            .ok()
            .and_then(|raw| Signature::from_slice(&raw).ok())
        else {
            mismatch_detail = format!("signature by {} is not 64 bytes", signature.keyid);
            continue;
        };
        // `verify_strict` rejects small-order keys and malleable signatures.
        match verifying_key.verify_strict(&pae_bytes, &bytes) {
            Ok(()) => key_ids.push(signature.keyid.clone()),
            Err(error) => {
                mismatch_detail = format!(
                    "Ed25519 verification failed for {}: {error}",
                    signature.keyid
                );
            }
        }
    }
    if key_ids.is_empty() {
        if named_a_trusted_key {
            return Err(BundleVerifyError::new(
                BundleReason::DsseSignatureMismatch,
                mismatch_detail,
            ));
        }
        if envelope.signatures.is_empty() {
            return Err(BundleVerifyError::new(
                BundleReason::DsseSignatureMismatch,
                "the bundle is unsigned; an unsigned bundle is not evidence",
            ));
        }
        return Err(BundleVerifyError::new(
            BundleReason::UnknownKeyId,
            format!(
                "none of the {} signature(s) names a key in the keyring ({} trusted)",
                envelope.signatures.len(),
                keyring.keys.len()
            ),
        ));
    }

    // 3. Subject: the bundle must hash to what it claims to be about.
    let recomputed = canonical::serialize_jcs(&predicate.resolved)
        .map(|canonical| canonical::digest(&canonical))
        .map_err(|error| {
            BundleVerifyError::new(
                BundleReason::SubjectDigestMismatch,
                format!("predicate.resolved has no canonical form: {error}"),
            )
        })?;
    if recomputed != predicate.policy.content_hash {
        return Err(BundleVerifyError::new(
            BundleReason::SubjectDigestMismatch,
            format!(
                "predicate.resolved hashes to {recomputed}, but policy.content_hash is {}",
                predicate.policy.content_hash
            ),
        ));
    }
    let declared = &statement.subject[0].digest.sha256;
    let expected = recomputed
        .strip_prefix(canonical::CONTENT_HASH_PREFIX)
        .unwrap_or(&recomputed);
    if declared != expected {
        return Err(BundleVerifyError::new(
            BundleReason::SubjectDigestMismatch,
            format!(
                "the subject digest is {declared}, but predicate.resolved hashes to {expected}"
            ),
        ));
    }

    // 4. Policy: is the bundle about the policy the verifier holds?
    if let Some(resolution) = policy {
        compare_policy(predicate, resolution)?;
    }

    Ok(BundleVerified {
        key_ids,
        subject_name: statement.subject[0].name.clone(),
        content_hash: predicate.policy.content_hash.clone(),
        policy_name: predicate.policy.name.clone(),
        policy_version: predicate.policy.policy_version,
        created_at: predicate.created_at.clone(),
        chain_length: predicate.chain.len(),
        policy_checked: policy.is_some(),
        verified_at: options.now.to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

/// Check 4 (bundle spec 5.3): the resolved documents and the chain hashes
/// must agree. `source` is a provenance label and is never compared.
///
/// The resolved documents are compared through their **canonical forms**,
/// not as JSON values: a value tree that has been through a JSON round trip
/// can hold `10` where the projection held `10.0`, which RFC 8785 serializes
/// identically (canonical spec 4.3) but `serde_json::Value` does not consider
/// equal. Check 3 has already tied `predicate.policy.content_hash` to
/// `predicate.resolved`, so comparing hashes here is comparing the bytes.
fn compare_policy(
    predicate: &PolicyBundlePredicate,
    resolution: &Resolution,
) -> Result<(), BundleVerifyError> {
    let mismatch = |detail: String| BundleVerifyError::new(BundleReason::PolicyMismatch, detail);

    let resolved = canonical::content_hash(&resolution.spec)
        .map_err(|error| mismatch(format!("the policy has no canonical form: {error}")))?;
    if resolved != predicate.policy.content_hash {
        return Err(mismatch(format!(
            "the policy resolves to {resolved}, but the bundle attests {}",
            predicate.policy.content_hash
        )));
    }
    if resolution.chain.len() != predicate.chain.len() {
        return Err(mismatch(format!(
            "the policy resolves through {} document(s), the bundle records {}",
            resolution.chain.len(),
            predicate.chain.len()
        )));
    }
    for (actual, bundled) in resolution.chain.iter().zip(&predicate.chain) {
        if actual.content_hash != bundled.content_hash {
            return Err(mismatch(format!(
                "chain hop {:?} hashes to {}, but the bundle records {} for {:?}",
                actual.source, actual.content_hash, bundled.content_hash, bundled.source
            )));
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Shape helpers
// --------------------------------------------------------------------------

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_content_hash(value: &str) -> bool {
    value
        .strip_prefix(canonical::CONTENT_HASH_PREFIX)
        .is_some_and(is_hex_digest)
}

/// `YYYY-MM-DDTHH:MM:SS.sssZ`, the one timestamp form 0.2 accepts.
fn is_millisecond_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24 || bytes[23] != b'Z' {
        return false;
    }
    let shape = b"####-##-##T##:##:##.###Z";
    for (byte, expected) in bytes.iter().zip(shape) {
        let ok = match expected {
            b'#' => byte.is_ascii_digit(),
            other => byte == other,
        };
        if !ok {
            return false;
        }
    }
    DateTime::parse_from_rfc3339(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PAE example from the DSSE specification's own test vectors.
    #[test]
    fn pae_matches_the_dsse_definition() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
        // An empty payload still carries its length.
        assert_eq!(pae("a", b""), b"DSSEv1 1 a 0 ".to_vec());
        // Lengths are byte counts, not character counts.
        assert_eq!(pae("t", "é".as_bytes()), b"DSSEv1 1 t 2 \xc3\xa9".to_vec());
    }

    #[test]
    fn the_payload_type_prefix_is_the_one_the_spec_quotes() {
        let bytes = pae(PAYLOAD_TYPE, b"{}");
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text, "DSSEv1 28 application/vnd.in-toto+json 2 {}");
    }

    #[test]
    fn reason_codes_round_trip_through_their_wire_strings() {
        for reason in BundleReason::ALL {
            assert_eq!(BundleReason::from_code(reason.as_str()), Some(reason));
        }
        assert_eq!(BundleReason::from_code("not_a_code"), None);
    }

    #[test]
    fn timestamps_need_millisecond_precision_and_a_z() {
        assert!(is_millisecond_timestamp("2026-09-15T12:00:00.000Z"));
        for bad in [
            "2026-09-15T12:00:00Z",
            "2026-09-15T12:00:00.000+00:00",
            "2026-09-15T12:00:00.000000Z",
            "not a timestamp",
            "2026-13-15T12:00:00.000Z",
        ] {
            assert!(!is_millisecond_timestamp(bad), "{bad:?} should not parse");
        }
    }

    #[test]
    fn relative_sources_drop_the_workspace_prefix_but_keep_builtins() {
        let base = Path::new("/work/repo");
        assert_eq!(
            relative_source("/work/repo/library/healthcare/x.yaml", Some(base)),
            "library/healthcare/x.yaml"
        );
        assert_eq!(
            relative_source("builtin:strict", Some(base)),
            "builtin:strict"
        );
        assert_eq!(
            relative_source("https://example.com/p.yaml", Some(base)),
            "https://example.com/p.yaml"
        );
        assert_eq!(
            relative_source("/elsewhere/p.yaml", Some(base)),
            "/elsewhere/p.yaml"
        );
        assert_eq!(
            relative_source("/work/repo/p.yaml", None),
            "/work/repo/p.yaml"
        );
    }
}
