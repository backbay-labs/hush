//! Policy signatures, format 0.2 (spec/hushspec-signing.md).
//!
//! A signed policy lets an enforcement point prove that the controls it
//! applied are the controls an authorized party approved. This module
//! produces and checks the detached envelope that carries that proof.
//!
//! # What is signed
//!
//! The claim is the **content hash of the resolved policy** (canonical spec
//! 5), never the bytes of the file. Reformatting a signed policy therefore
//! keeps its signature valid, and changing a base policy pulled in through
//! `extends` invalidates every signature over the children that extend it --
//! which is the point: the enforced policy changed.
//!
//! The signing input is the RFC 8785 canonical form of the envelope with the
//! `signature` member absent (signing spec 4.1), produced by
//! [`crate::canonical::serialize_jcs`] so that policies and envelopes share
//! one canonicalizer.
//!
//! # Keys
//!
//! Private keys are PEM PKCS#8, public keys PEM SubjectPublicKeyInfo -- what
//! `openssl genpkey -algorithm ed25519` and `openssl pkey -pubout` write. A
//! key is named by `sha256:` plus the hex digest of its SPKI DER
//! ([`key_id`]), and a verifier always recomputes that id rather than
//! trusting the one a keyring declares.
//!
//! # Verification
//!
//! [`verify`] runs the ten ordered checks of signing spec 6.2 and stops at
//! the first failure, reporting the [`ReasonCode`] that check owns. Every
//! reason code is spelled exactly as signing spec 6.4 spells it, because a
//! receipt's `policy.signature.reason` and the CLI's exit message carry the
//! string verbatim.
//!
//! # Feature flag
//!
//! This module is only available when the `signing` feature is enabled.

use crate::canonical::{self, CanonicalError};
use crate::resolve::{ResolveError, resolve_from_path_with_builtins};
use crate::schema::HushSpec;
use crate::validate::validate;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer};
/// The Ed25519 key types, re-exported so callers need no direct dependency
/// on `ed25519-dalek`.
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;

/// The envelope format version this module produces and accepts.
pub const FORMAT_VERSION: &str = "0.2";

/// The only signature algorithm defined in format 0.2 (RFC 8032 pure
/// Ed25519: no pre-hash, no context).
pub const ALGORITHM: &str = "ed25519";

/// The keyring document version this module accepts (signing spec 5.3).
pub const KEYRING_VERSION: &str = "0.2";

/// Superseded envelope format, still readable so tooling can tell a 0.1
/// signature apart from a corrupt file (see [`LegacySignature`]).
pub const LEGACY_FORMAT_VERSION: &str = "0.1.0";

/// RECOMMENDED clock skew allowance for `signed_at` (signing spec 6.3).
pub const DEFAULT_MAX_CLOCK_SKEW_SECONDS: i64 = 300;

/// Length of a base64url-without-padding encoding of 64 signature bytes.
const SIGNATURE_B64_LEN: usize = 86;

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Why a signature could not be *produced*, a key could not be read, or a
/// keyring could not be loaded.
///
/// Verification failures are [`VerifyError`], which carries a reason code
/// from the closed set of signing spec 6.4.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SigningError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("the policy has no canonical form: {0}")]
    Canonical(#[from] CanonicalError),

    #[error("the policy's extends chain does not resolve: {0}")]
    Resolve(#[from] ResolveError),

    #[error("the policy is not valid: {0}")]
    InvalidPolicy(String),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("invalid keyring: {0}")]
    InvalidKeyring(String),

    #[error("malformed signature envelope: {0}")]
    MalformedEnvelope(String),
}

/// A verification failure, carrying the reason code of the check that failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError {
    /// The signing spec 6.4 code for the check that failed.
    pub reason: ReasonCode,
    /// Free-text detail. Never load-bearing: consumers switch on `reason`.
    pub detail: String,
}

impl VerifyError {
    fn new(reason: ReasonCode, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// The reason code as the wire string of signing spec 6.4.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.reason.as_str()
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.detail)
    }
}

impl std::error::Error for VerifyError {}

/// The closed set of verification reason codes (signing spec 6.4).
///
/// The set is closed on purpose: a verifier never invents a code, and a
/// consumer can exhaustively match on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReasonCode {
    /// Check 1: the envelope is not a well-formed 0.2 envelope.
    MalformedEnvelope,
    /// Check 2: `format_version` is not `"0.2"`.
    UnsupportedFormatVersion,
    /// Check 3: `algorithm` is not `"ed25519"`.
    UnsupportedAlgorithm,
    /// Check 4: no keyring entry matches, or its declared id is not its real one.
    UnknownKeyId,
    /// Check 5: the keyring entry is revoked.
    KeyRevoked,
    /// Check 6: `signed_at` is at or after the entry's `not_after`.
    KeyRetired,
    /// Check 7: `signed_at` is beyond `now` plus the allowed skew.
    SignedAtInFuture,
    /// Check 7: `now` is at or after `expires_at`.
    Expired,
    /// Check 8: Ed25519 verification of the signing input failed.
    SignatureMismatch,
    /// Check 9: the policy's content hash is not the envelope's, or the
    /// policy does not resolve or validate at all.
    ContentHashMismatch,
    /// Check 10: the envelope's `policy_version` is below the last seen one.
    PolicyVersionRollback,
}

impl ReasonCode {
    /// Every reason code, in check order.
    pub const ALL: [Self; 11] = [
        Self::MalformedEnvelope,
        Self::UnsupportedFormatVersion,
        Self::UnsupportedAlgorithm,
        Self::UnknownKeyId,
        Self::KeyRevoked,
        Self::KeyRetired,
        Self::SignedAtInFuture,
        Self::Expired,
        Self::SignatureMismatch,
        Self::ContentHashMismatch,
        Self::PolicyVersionRollback,
    ];

    /// The wire string, spelled as signing spec 6.4 spells it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MalformedEnvelope => "malformed_envelope",
            Self::UnsupportedFormatVersion => "unsupported_format_version",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::UnknownKeyId => "unknown_key_id",
            Self::KeyRevoked => "key_revoked",
            Self::KeyRetired => "key_retired",
            Self::SignedAtInFuture => "signed_at_in_future",
            Self::Expired => "expired",
            Self::SignatureMismatch => "signature_mismatch",
            Self::ContentHashMismatch => "content_hash_mismatch",
            Self::PolicyVersionRollback => "policy_version_rollback",
        }
    }

    /// Parse a wire string back into a code. Unknown strings return `None`:
    /// the set is closed, so a code this build does not know is not a code.
    #[must_use]
    pub fn from_code(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == value)
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// --------------------------------------------------------------------------
// Envelope (signing spec 4)
// --------------------------------------------------------------------------

/// A detached policy signature envelope, format 0.2.
///
/// Every member except `signature` is a signed claim, so editing any of them
/// after signing invalidates the envelope.
///
/// The member order below is the order the schema documents; it is also the
/// order [`Envelope::to_json`] writes. Neither is load-bearing: the signing
/// input sorts members per RFC 8785.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// `"0.2"`.
    pub format_version: String,
    /// `"ed25519"`.
    pub algorithm: String,
    /// `sha256:` + hex SHA-256 of the signing key's SPKI DER.
    pub key_id: String,
    /// RFC 3339 UTC, millisecond precision, `Z` suffix.
    pub signed_at: String,
    /// Optional expiry; the signature is invalid at or after this instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// The policy's `metadata.policy_version` at signing time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u64>,
    /// The policy's `name` at signing time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// Content hash of the *resolved* policy (canonical spec 5).
    pub content_hash: String,
    /// Human-readable signer identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// base64url without padding of the 64-byte Ed25519 signature.
    pub signature: String,
}

impl Envelope {
    /// Parse an envelope from the JSON text of a `.sig` file and check its
    /// shape (signing spec 6.2 check 1).
    ///
    /// # Errors
    ///
    /// [`ReasonCode::MalformedEnvelope`] when the text is not JSON, carries
    /// an unknown member, is missing a required one, or a member's value does
    /// not match the schema's pattern.
    ///
    /// `format_version` and `algorithm` are *not* checked here: signing spec
    /// 6.2 gives them checks 2 and 3, with their own reason codes, so an
    /// envelope naming a future version or a different algorithm parses
    /// cleanly and is then rejected by [`verify`] with the code that says so.
    pub fn parse(json: &str) -> Result<Self, VerifyError> {
        let envelope: Self = serde_json::from_str(json)
            .map_err(|error| VerifyError::new(ReasonCode::MalformedEnvelope, format!("{error}")))?;
        envelope.check_shape()?;
        Ok(envelope)
    }

    /// Read and parse a detached `.sig` file.
    ///
    /// # Errors
    ///
    /// [`SigningError::Io`] when the file cannot be read, or
    /// [`SigningError::MalformedEnvelope`] carrying the shape failure.
    pub fn load(path: &Path) -> Result<Self, SigningError> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text).map_err(|error| SigningError::MalformedEnvelope(error.detail))
    }

    /// Everything the schema constrains except the two `const` members, which
    /// checks 2 and 3 own.
    fn check_shape(&self) -> Result<(), VerifyError> {
        let bad = |detail: String| VerifyError::new(ReasonCode::MalformedEnvelope, detail);

        if !is_sha256_digest(&self.key_id) {
            return Err(bad(format!(
                "key_id {:?} is not sha256:<64 lowercase hex>",
                self.key_id
            )));
        }
        if !is_sha256_digest(&self.content_hash) {
            return Err(bad(format!(
                "content_hash {:?} is not sha256:<64 lowercase hex>",
                self.content_hash
            )));
        }
        if !is_millisecond_timestamp(&self.signed_at) {
            return Err(bad(format!(
                "signed_at {:?} is not RFC 3339 UTC with millisecond precision",
                self.signed_at
            )));
        }
        if let Some(expires_at) = &self.expires_at
            && !is_millisecond_timestamp(expires_at)
        {
            return Err(bad(format!(
                "expires_at {expires_at:?} is not RFC 3339 UTC with millisecond precision"
            )));
        }
        if self.signature.len() != SIGNATURE_B64_LEN
            || !self
                .signature
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(bad(format!(
                "signature is not {SIGNATURE_B64_LEN} base64url characters without padding"
            )));
        }
        if self.policy_name.as_ref().is_some_and(String::is_empty) {
            return Err(bad("policy_name is present but empty".to_string()));
        }
        if self.signer.as_ref().is_some_and(String::is_empty) {
            return Err(bad("signer is present but empty".to_string()));
        }
        Ok(())
    }

    /// The signing input: the RFC 8785 canonical form of this envelope with
    /// `signature` absent (signing spec 4.1).
    ///
    /// # Errors
    ///
    /// [`SigningError::Canonical`] only for a value RFC 8785 cannot
    /// represent, which an envelope's members never are.
    pub fn signing_input(&self) -> Result<String, SigningError> {
        let Value::Object(mut members) = serde_json::to_value(self)? else {
            unreachable!("an envelope serializes to a JSON object");
        };
        members.remove("signature");
        Ok(canonical::serialize_jcs(&Value::Object(members))?)
    }

    /// The envelope as the JSON text of a `.sig` file: pretty-printed, with a
    /// trailing newline.
    ///
    /// # Errors
    ///
    /// [`SigningError::Json`] if serialization fails.
    pub fn to_json(&self) -> Result<String, SigningError> {
        Ok(format!("{}\n", serde_json::to_string_pretty(self)?))
    }

    /// Write the envelope to a detached `.sig` file.
    ///
    /// # Errors
    ///
    /// [`SigningError::Io`] or [`SigningError::Json`].
    pub fn save(&self, path: &Path) -> Result<(), SigningError> {
        std::fs::write(path, self.to_json()?)?;
        Ok(())
    }

    fn signature_bytes(&self) -> Option<Signature> {
        let bytes = BASE64URL.decode(&self.signature).ok()?;
        Signature::from_slice(&bytes).ok()
    }
}

/// The detached signature path for `policy`, preferring `<policy>.sig` and
/// falling back to the 0.1 layout `<policy stem>.sig` (signing spec 7.1).
///
/// Returns `None` when neither exists.
#[must_use]
pub fn detached_signature_path(policy: &Path) -> Option<std::path::PathBuf> {
    let mut preferred = policy.to_path_buf().into_os_string();
    preferred.push(".sig");
    let preferred = std::path::PathBuf::from(preferred);
    if preferred.exists() {
        return Some(preferred);
    }
    let legacy = policy.with_extension("sig");
    if legacy.exists() {
        return Some(legacy);
    }
    None
}

/// The path `h2h sign` writes by default: `<policy>.sig` (signing spec 7.1).
#[must_use]
pub fn default_signature_path(policy: &Path) -> std::path::PathBuf {
    let mut path = policy.to_path_buf().into_os_string();
    path.push(".sig");
    std::path::PathBuf::from(path)
}

// --------------------------------------------------------------------------
// Keys (signing spec 5)
// --------------------------------------------------------------------------

/// Generate a fresh Ed25519 keypair from the OS entropy source.
#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// The DER SubjectPublicKeyInfo of a public key (44 bytes for Ed25519).
///
/// # Errors
///
/// [`SigningError::InvalidKey`] if the key cannot be encoded, which a valid
/// Ed25519 key never is.
pub fn spki_der(key: &VerifyingKey) -> Result<Vec<u8>, SigningError> {
    let document = key
        .to_public_key_der()
        .map_err(|error| SigningError::InvalidKey(format!("SPKI encoding failed: {error}")))?;
    Ok(document.as_bytes().to_vec())
}

/// The key identifier of a public key: `sha256:` + hex SHA-256 of its SPKI
/// DER (signing spec 5.2).
///
/// Deriving the id from the SPKI rather than the raw key bits ties the id to
/// the algorithm as well as the key.
///
/// # Errors
///
/// As [`spki_der`].
pub fn key_id(key: &VerifyingKey) -> Result<String, SigningError> {
    let der = spki_der(key)?;
    let mut hasher = Sha256::new();
    hasher.update(&der);
    Ok(format!(
        "{}{:x}",
        canonical::CONTENT_HASH_PREFIX,
        hasher.finalize()
    ))
}

/// Encode a private key as PEM PKCS#8 (`-----BEGIN PRIVATE KEY-----`).
///
/// # Errors
///
/// [`SigningError::InvalidKey`] if the key cannot be encoded.
pub fn private_key_pem(key: &SigningKey) -> Result<String, SigningError> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|error| SigningError::InvalidKey(format!("PKCS#8 encoding failed: {error}")))
}

/// Encode a public key as PEM SubjectPublicKeyInfo
/// (`-----BEGIN PUBLIC KEY-----`).
///
/// # Errors
///
/// [`SigningError::InvalidKey`] if the key cannot be encoded.
pub fn public_key_pem(key: &VerifyingKey) -> Result<String, SigningError> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|error| SigningError::InvalidKey(format!("SPKI encoding failed: {error}")))
}

/// Parse a PEM PKCS#8 private key.
///
/// Text before the `-----BEGIN` line is ignored, so a key file carrying a
/// human-readable header (as the published test keys do) still loads.
///
/// # Errors
///
/// [`SigningError::InvalidKey`] when the text holds no PKCS#8 Ed25519 key.
pub fn parse_private_key_pem(pem: &str) -> Result<SigningKey, SigningError> {
    let body = strip_pem_preamble(pem);
    SigningKey::from_pkcs8_pem(&body).map_err(|error| {
        SigningError::InvalidKey(format!(
            "expected a PEM PKCS#8 Ed25519 private key: {error}. \
             HushSpec 0.1 wrote a bespoke key file; convert it with `h2h keygen --convert`."
        ))
    })
}

/// Parse a PEM SubjectPublicKeyInfo public key.
///
/// Text before the `-----BEGIN` line is ignored.
///
/// # Errors
///
/// [`SigningError::InvalidKey`] when the text holds no SPKI Ed25519 key.
pub fn parse_public_key_pem(pem: &str) -> Result<VerifyingKey, SigningError> {
    let body = strip_pem_preamble(pem);
    VerifyingKey::from_public_key_pem(&body).map_err(|error| {
        SigningError::InvalidKey(format!(
            "expected a PEM SubjectPublicKeyInfo Ed25519 public key: {error}. \
             HushSpec 0.1 wrote a bespoke key file; convert it with `h2h keygen --convert`."
        ))
    })
}

/// Read a PEM PKCS#8 private key from a file.
///
/// # Errors
///
/// [`SigningError::Io`] or [`SigningError::InvalidKey`].
pub fn load_private_key(path: &Path) -> Result<SigningKey, SigningError> {
    parse_private_key_pem(&std::fs::read_to_string(path)?)
}

/// Read a PEM SPKI public key from a file.
///
/// # Errors
///
/// [`SigningError::Io`] or [`SigningError::InvalidKey`].
pub fn load_public_key(path: &Path) -> Result<VerifyingKey, SigningError> {
    parse_public_key_pem(&std::fs::read_to_string(path)?)
}

/// RFC 7468 allows explanatory text before the encapsulation boundary; the
/// strict decoder in `pem-rfc7468` does not, so drop it here.
fn strip_pem_preamble(pem: &str) -> String {
    match pem.find("-----BEGIN") {
        Some(start) => pem[start..].to_string(),
        None => pem.to_string(),
    }
}

// --------------------------------------------------------------------------
// Keyring (signing spec 5.3)
// --------------------------------------------------------------------------

/// One trusted public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    /// The declared id. A verifier recomputes it from `public_key` and never
    /// trusts an entry whose declared id differs.
    pub key_id: String,
    /// `"ed25519"`.
    pub algorithm: String,
    /// PEM SubjectPublicKeyInfo.
    pub public_key: String,
    /// Human-readable label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Retirement instant: signatures with `signed_at` at or after it are
    /// rejected, earlier ones stay valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Compromise: every signature by this key is rejected.
    #[serde(default, skip_serializing_if = "is_false")]
    pub revoked: bool,
}

impl TrustedKey {
    /// Build an entry from a public key, computing its id.
    ///
    /// # Errors
    ///
    /// As [`key_id`].
    pub fn from_verifying_key(
        key: &VerifyingKey,
        name: Option<String>,
    ) -> Result<Self, SigningError> {
        Ok(Self {
            key_id: key_id(key)?,
            algorithm: ALGORITHM.to_string(),
            public_key: public_key_pem(key)?,
            name,
            not_after: None,
            revoked: false,
        })
    }

    /// Parse this entry's `public_key`.
    ///
    /// # Errors
    ///
    /// [`SigningError::InvalidKey`].
    pub fn verifying_key(&self) -> Result<VerifyingKey, SigningError> {
        parse_public_key_pem(&self.public_key)
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

/// The set of public keys a verifier trusts.
///
/// Load one with [`Keyring::parse`] or [`Keyring::load`]: both validate the
/// document's shape and recompute every entry's `key_id`, rejecting the
/// keyring if any declared id is not the real one. A keyring a verifier
/// cannot fully trust is not a keyring it partly trusts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keyring {
    /// `"0.2"`.
    pub keyring_version: String,
    /// At least one key.
    pub keys: Vec<TrustedKey>,
}

impl Keyring {
    /// Parse and validate a keyring document.
    ///
    /// # Errors
    ///
    /// [`SigningError::InvalidKeyring`] for a document that does not match
    /// the keyring schema's shape, holds an unusable public key, or declares
    /// a `key_id` that is not the digest of its own `public_key`.
    pub fn parse(json: &str) -> Result<Self, SigningError> {
        let keyring: Self = serde_json::from_str(json)
            .map_err(|error| SigningError::InvalidKeyring(format!("{error}")))?;
        keyring.validate_shape()?;
        Ok(keyring)
    }

    /// Read and validate a keyring file.
    ///
    /// # Errors
    ///
    /// [`SigningError::Io`], or as [`Keyring::parse`].
    pub fn load(path: &Path) -> Result<Self, SigningError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// A one-key keyring built from a public key file's PEM text
    /// (signing spec 5.3: "A single public key file MAY be accepted by
    /// tooling as a one-key keyring with `key_id` recomputed from it").
    ///
    /// # Errors
    ///
    /// [`SigningError::InvalidKey`].
    pub fn from_public_key_pem(pem: &str) -> Result<Self, SigningError> {
        let key = parse_public_key_pem(pem)?;
        Self::from_verifying_keys([key])
    }

    /// A keyring over public keys already in hand.
    ///
    /// # Errors
    ///
    /// As [`key_id`].
    pub fn from_verifying_keys(
        keys: impl IntoIterator<Item = VerifyingKey>,
    ) -> Result<Self, SigningError> {
        let keys = keys
            .into_iter()
            .map(|key| TrustedKey::from_verifying_key(&key, None))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            keyring_version: KEYRING_VERSION.to_string(),
            keys,
        })
    }

    /// The entry with this exact id, if the keyring holds one.
    ///
    /// Selection is by exact match only: a verifier never tries another key
    /// when the named one is absent.
    #[must_use]
    pub fn find(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.iter().find(|entry| entry.key_id == key_id)
    }

    fn validate_shape(&self) -> Result<(), SigningError> {
        let bad = |detail: String| SigningError::InvalidKeyring(detail);

        if self.keyring_version != KEYRING_VERSION {
            return Err(bad(format!(
                "keyring_version {:?}, expected {KEYRING_VERSION:?}",
                self.keyring_version
            )));
        }
        if self.keys.is_empty() {
            return Err(bad("a keyring must hold at least one key".to_string()));
        }
        for entry in &self.keys {
            if entry.algorithm != ALGORITHM {
                return Err(bad(format!(
                    "key {:?} has algorithm {:?}, expected {ALGORITHM:?}",
                    entry.key_id, entry.algorithm
                )));
            }
            if !is_sha256_digest(&entry.key_id) {
                return Err(bad(format!(
                    "key_id {:?} is not sha256:<64 lowercase hex>",
                    entry.key_id
                )));
            }
            if let Some(not_after) = &entry.not_after
                && !is_millisecond_timestamp(not_after)
            {
                return Err(bad(format!(
                    "key {:?} has not_after {not_after:?}, which is not RFC 3339 UTC with \
                     millisecond precision",
                    entry.key_id
                )));
            }
            let key = entry
                .verifying_key()
                .map_err(|error| bad(format!("key {:?} is unusable: {error}", entry.key_id)))?;
            let recomputed = key_id(&key)?;
            if recomputed != entry.key_id {
                return Err(bad(format!(
                    "key {:?} declares an id that is not the digest of its own public key \
                     (recomputed {recomputed})",
                    entry.key_id
                )));
            }
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------
// The document a signature covers (signing spec 3)
// --------------------------------------------------------------------------

/// A policy resolved, validated, and hashed: what a signature actually
/// covers.
#[derive(Clone, Debug)]
pub struct ResolvedPolicy {
    /// The resolved document.
    pub spec: HushSpec,
    /// Its content hash (canonical spec 5), `sha256:`-prefixed.
    pub content_hash: String,
}

/// Resolve, validate, and hash the policy at `path`.
///
/// This is the one place that decides *what* a signature covers, so a signer
/// and a verifier cannot disagree (signing spec 10, "Hash, not bytes"):
/// `extends` is resolved through the builtin-then-filesystem loader, the
/// merged document is validated, and the hash is taken over its canonical
/// form -- from the value tree when the document is already resolved (the
/// path canonical spec 6 recommends and `h2h hash` uses), from the typed
/// model once resolution has produced one.
///
/// # Errors
///
/// [`SigningError::Io`], [`SigningError::Yaml`], [`SigningError::Resolve`],
/// [`SigningError::InvalidPolicy`], or [`SigningError::Canonical`].
pub fn load_resolved(path: &Path) -> Result<ResolvedPolicy, SigningError> {
    let text = std::fs::read_to_string(path)?;
    let spec = HushSpec::parse(&text)?;

    let (spec, content_hash) = if spec.extends.is_some() {
        let resolved = resolve_from_path_with_builtins(path)?;
        let hash = canonical::content_hash(&resolved)?;
        (resolved, hash)
    } else {
        let document: Value = serde_yaml::from_str(&text)?;
        let hash = canonical::content_hash_value(&document)?;
        (spec, hash)
    };

    let result = validate(&spec);
    if !result.is_valid() {
        let messages: Vec<String> = result
            .errors
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        return Err(SigningError::InvalidPolicy(messages.join("; ")));
    }

    Ok(ResolvedPolicy { spec, content_hash })
}

// --------------------------------------------------------------------------
// Signing (signing spec 4.2)
// --------------------------------------------------------------------------

/// The optional claims a signer chooses.
#[derive(Clone, Debug, Default)]
pub struct SignOptions {
    /// When the signature is made. Defaults to now, truncated to
    /// milliseconds.
    pub signed_at: Option<DateTime<Utc>>,
    /// When it stops being valid. Signers SHOULD set it for policies that
    /// are re-approved on a cadence, and MUST NOT set it beyond the
    /// deployment's approval interval.
    pub expires_at: Option<DateTime<Utc>>,
    /// Overrides the policy's own `metadata.policy_version`.
    pub policy_version: Option<u64>,
    /// Overrides the policy's own `name`.
    pub policy_name: Option<String>,
    /// Human-readable signer identity.
    pub signer: Option<String>,
}

/// Sign a content hash that is already in hand.
///
/// Prefer [`sign_policy`], which computes the hash the way a verifier will.
///
/// # Errors
///
/// [`SigningError::MalformedEnvelope`] when `content_hash` is not a
/// `sha256:` digest, or [`SigningError::Canonical`] from the signing input.
pub fn sign_content_hash(
    content_hash: &str,
    signing_key: &SigningKey,
    options: &SignOptions,
) -> Result<Envelope, SigningError> {
    if !is_sha256_digest(content_hash) {
        return Err(SigningError::MalformedEnvelope(format!(
            "content_hash {content_hash:?} is not sha256:<64 lowercase hex>"
        )));
    }

    let signed_at = options.signed_at.unwrap_or_else(Utc::now);
    let mut envelope = Envelope {
        format_version: FORMAT_VERSION.to_string(),
        algorithm: ALGORITHM.to_string(),
        key_id: key_id(&signing_key.verifying_key())?,
        signed_at: format_timestamp(signed_at),
        expires_at: options.expires_at.map(format_timestamp),
        policy_version: options.policy_version,
        policy_name: options.policy_name.clone(),
        content_hash: content_hash.to_string(),
        signer: options.signer.clone(),
        // Placeholder: `signing_input` drops the member before canonicalizing.
        signature: String::new(),
    };

    let input = envelope.signing_input()?;
    let signature = signing_key.sign(input.as_bytes());
    envelope.signature = BASE64URL.encode(signature.to_bytes());
    Ok(envelope)
}

/// Sign a **resolved** policy (signing spec 4.2).
///
/// `policy_name` and `policy_version` default to the policy's own `name` and
/// `metadata.policy_version`; [`SignOptions`] overrides either.
///
/// # Errors
///
/// [`SigningError::Canonical`] -- in particular [`CanonicalError::Unresolved`]
/// when the document still declares `extends`, because a signer that cannot
/// resolve the chain must refuse to sign -- or as [`sign_content_hash`].
pub fn sign_policy(
    policy: &HushSpec,
    signing_key: &SigningKey,
    options: &SignOptions,
) -> Result<Envelope, SigningError> {
    let content_hash = canonical::content_hash(policy)?;
    sign_resolved(
        &ResolvedPolicy {
            spec: policy.clone(),
            content_hash,
        },
        signing_key,
        options,
    )
}

/// Sign a policy already resolved and hashed by [`load_resolved`].
///
/// # Errors
///
/// As [`sign_content_hash`].
pub fn sign_resolved(
    policy: &ResolvedPolicy,
    signing_key: &SigningKey,
    options: &SignOptions,
) -> Result<Envelope, SigningError> {
    let mut options = options.clone();
    if options.policy_name.is_none() {
        // A policy that declares `name: ""` makes no name claim: the envelope
        // schema requires a present `policy_name` to be non-empty.
        options.policy_name = policy.spec.name.clone().filter(|name| !name.is_empty());
    }
    if options.policy_version.is_none() {
        options.policy_version = policy
            .spec
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.policy_version)
            .map(|version| version as u64);
    }
    sign_content_hash(&policy.content_hash, signing_key, &options)
}

// --------------------------------------------------------------------------
// Verification (signing spec 6)
// --------------------------------------------------------------------------

/// What a verifier knows besides the envelope, the policy, and the keyring.
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// The verifier's clock.
    pub now: DateTime<Utc>,
    /// Allowance for a signer's clock running fast (signing spec 6.3).
    pub max_clock_skew_seconds: i64,
    /// The last `policy_version` this verifier accepted **for this policy
    /// name**. Scoping the lookup by name is the caller's job; check 10 only
    /// compares the numbers.
    pub last_seen_version: Option<u64>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            now: Utc::now(),
            max_clock_skew_seconds: DEFAULT_MAX_CLOCK_SKEW_SECONDS,
            last_seen_version: None,
        }
    }
}

/// The claims of an envelope that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The key that signed it.
    pub key_id: String,
    /// When it was signed.
    pub signed_at: String,
    /// When it expires, if it does.
    pub expires_at: Option<String>,
    /// The content hash it covers.
    pub content_hash: String,
    /// The policy's name at signing time.
    pub policy_name: Option<String>,
    /// The policy's version at signing time. A verifier that accepts an
    /// envelope SHOULD record this as the new last-seen value.
    pub policy_version: Option<u64>,
    /// The declared signer.
    pub signer: Option<String>,
}

/// Run the ten ordered checks of signing spec 6.2, stopping at the first
/// failure.
///
/// `policy_content_hash` is the content hash of the resolved, validated
/// policy, or `None` when the policy does not resolve or validate at all --
/// which check 9 treats as a mismatch, there being no hash to compare.
/// Passing it in rather than a path keeps the checks independent of how a
/// caller loads policies, and lets an enforcement point verify the in-memory
/// document it is about to evaluate rather than a file it would re-read
/// (signing spec 10, "Time of check, time of use").
///
/// # Errors
///
/// [`VerifyError`] carrying the [`ReasonCode`] of the check that failed.
pub fn verify_content_hash(
    envelope: &Envelope,
    policy_content_hash: Option<&str>,
    keyring: &Keyring,
    options: &VerifyOptions,
) -> Result<Verified, VerifyError> {
    // 1. Envelope shape.
    envelope.check_shape()?;

    // 2. Format.
    if envelope.format_version != FORMAT_VERSION {
        return Err(VerifyError::new(
            ReasonCode::UnsupportedFormatVersion,
            format!(
                "format_version {:?}, expected {FORMAT_VERSION:?}",
                envelope.format_version
            ),
        ));
    }

    // 3. Algorithm.
    if envelope.algorithm != ALGORITHM {
        return Err(VerifyError::new(
            ReasonCode::UnsupportedAlgorithm,
            format!("algorithm {:?}, expected {ALGORITHM:?}", envelope.algorithm),
        ));
    }

    // 4. Key lookup. The declared id is never enough: recompute it from the
    //    public key the keyring actually holds.
    let unknown = |detail: String| VerifyError::new(ReasonCode::UnknownKeyId, detail);
    let entry = keyring.find(&envelope.key_id).ok_or_else(|| {
        unknown(format!(
            "no key {} in the keyring ({} trusted)",
            envelope.key_id,
            keyring.keys.len()
        ))
    })?;
    let verifying_key = entry
        .verifying_key()
        .map_err(|error| unknown(format!("key {} is unusable: {error}", entry.key_id)))?;
    let recomputed = key_id(&verifying_key)
        .map_err(|error| unknown(format!("key {} is unusable: {error}", entry.key_id)))?;
    if recomputed != envelope.key_id {
        return Err(unknown(format!(
            "keyring entry {} declares an id that is not the digest of its own public key \
             (recomputed {recomputed})",
            entry.key_id
        )));
    }

    // 5. Revocation.
    if entry.revoked {
        return Err(VerifyError::new(
            ReasonCode::KeyRevoked,
            format!("key {} is revoked", entry.key_id),
        ));
    }

    // 6. Retirement.
    let signed_at = parse_timestamp(&envelope.signed_at)
        .map_err(|detail| VerifyError::new(ReasonCode::MalformedEnvelope, detail))?;
    if let Some(not_after) = &entry.not_after {
        let not_after_instant = parse_timestamp(not_after)
            .map_err(|detail| unknown(format!("keyring entry {}: {detail}", entry.key_id)))?;
        if signed_at >= not_after_instant {
            return Err(VerifyError::new(
                ReasonCode::KeyRetired,
                format!(
                    "key {} was retired at {not_after}; the signature is dated {}",
                    entry.key_id, envelope.signed_at
                ),
            ));
        }
    }

    // 7. Time.
    let skew = Duration::try_seconds(options.max_clock_skew_seconds).ok_or_else(|| {
        VerifyError::new(
            ReasonCode::SignedAtInFuture,
            format!(
                "max_clock_skew_seconds {} is out of range",
                options.max_clock_skew_seconds
            ),
        )
    })?;
    if signed_at > options.now + skew {
        return Err(VerifyError::new(
            ReasonCode::SignedAtInFuture,
            format!(
                "signed_at {} is after {} plus {}s of allowed skew",
                envelope.signed_at,
                format_timestamp(options.now),
                options.max_clock_skew_seconds
            ),
        ));
    }
    if let Some(expires_at) = &envelope.expires_at {
        let expiry = parse_timestamp(expires_at)
            .map_err(|detail| VerifyError::new(ReasonCode::MalformedEnvelope, detail))?;
        if options.now >= expiry {
            return Err(VerifyError::new(
                ReasonCode::Expired,
                format!(
                    "the signature expired at {expires_at}; it is now {}",
                    format_timestamp(options.now)
                ),
            ));
        }
    }

    // 8. Signature.
    let mismatch = |detail: String| VerifyError::new(ReasonCode::SignatureMismatch, detail);
    let signature = envelope
        .signature_bytes()
        .ok_or_else(|| mismatch("signature is not 64 base64url-encoded bytes".to_string()))?;
    let input = envelope
        .signing_input()
        .map_err(|error| mismatch(format!("the signing input is not serializable: {error}")))?;
    // `verify_strict` rejects small-order / torsion public keys and the
    // non-canonical (malleable) signatures the permissive `verify` accepts.
    verifying_key
        .verify_strict(input.as_bytes(), &signature)
        .map_err(|error| mismatch(format!("Ed25519 verification failed: {error}")))?;

    // 9. Content.
    match policy_content_hash {
        Some(hash) if hash == envelope.content_hash => {}
        Some(hash) => {
            return Err(VerifyError::new(
                ReasonCode::ContentHashMismatch,
                format!(
                    "the envelope covers {}, but the resolved policy hashes to {hash}",
                    envelope.content_hash
                ),
            ));
        }
        None => {
            return Err(VerifyError::new(
                ReasonCode::ContentHashMismatch,
                "the policy does not resolve or validate, so it has no content hash to compare"
                    .to_string(),
            ));
        }
    }

    // 10. Rollback.
    if let (Some(last_seen), Some(current)) = (options.last_seen_version, envelope.policy_version)
        && current < last_seen
    {
        return Err(VerifyError::new(
            ReasonCode::PolicyVersionRollback,
            format!("policy_version {current} is below the last seen {last_seen}"),
        ));
    }

    Ok(Verified {
        key_id: envelope.key_id.clone(),
        signed_at: envelope.signed_at.clone(),
        expires_at: envelope.expires_at.clone(),
        content_hash: envelope.content_hash.clone(),
        policy_name: envelope.policy_name.clone(),
        policy_version: envelope.policy_version,
        signer: envelope.signer.clone(),
    })
}

/// Verify an envelope against a **resolved** policy, the mirror of
/// [`sign_policy`].
///
/// A document that still declares `extends`, or that fails validation, has no
/// content hash and is therefore a check-9 failure -- reported only after
/// checks 1 through 8 have passed.
///
/// # Errors
///
/// As [`verify_content_hash`].
pub fn verify_policy(
    envelope: &Envelope,
    policy: &HushSpec,
    keyring: &Keyring,
    options: &VerifyOptions,
) -> Result<Verified, VerifyError> {
    let hash = canonical::content_hash(policy).ok();
    verify_content_hash(envelope, hash.as_deref(), keyring, options)
}

/// Verify an envelope against the policy file at `path`.
///
/// A policy that will not resolve or validate is a check-9 failure
/// (`content_hash_mismatch`), reported only after checks 1 through 8 have
/// passed, so a forged envelope is never described in terms of the policy's
/// own problems.
///
/// # Errors
///
/// As [`verify_content_hash`].
pub fn verify_policy_at(
    path: &Path,
    envelope: &Envelope,
    keyring: &Keyring,
    options: &VerifyOptions,
) -> Result<Verified, VerifyError> {
    let resolved = load_resolved(path);
    let hash = resolved
        .as_ref()
        .ok()
        .map(|policy| policy.content_hash.as_str());
    verify_content_hash(envelope, hash, keyring, options).map_err(|error| {
        match (&resolved, error.reason) {
            (Err(cause), ReasonCode::ContentHashMismatch) => VerifyError::new(
                ReasonCode::ContentHashMismatch,
                format!("{}: {cause}", path.display()),
            ),
            _ => error,
        }
    })
}

// --------------------------------------------------------------------------
// Receipt signing (receipt spec 6)
// --------------------------------------------------------------------------

/// A receipt together with a signature over its receipt hash.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt {
    pub receipt: crate::receipt::DecisionReceipt,
    /// A 0.2 envelope whose `content_hash` is the receipt hash.
    pub signature: Envelope,
}

/// Sign a receipt: the envelope's `content_hash` is the receipt hash
/// (receipt spec 6), so the signature covers every field.
///
/// `policy_name` and `policy_version` are left unset unless `options`
/// provides them; a receipt already names its policy.
///
/// # Errors
///
/// [`SigningError::Canonical`] when the receipt cannot be canonicalized, or
/// as [`sign_content_hash`].
pub fn sign_receipt(
    receipt: &crate::receipt::DecisionReceipt,
    signing_key: &SigningKey,
    options: &SignOptions,
) -> Result<SignedReceipt, SigningError> {
    let hash = receipt.receipt_hash()?;
    let signature = sign_content_hash(&hash, signing_key, options)?;
    Ok(SignedReceipt {
        receipt: receipt.clone(),
        signature,
    })
}

/// Verify a receipt signature: the ten checks of signing spec 6.2 with the
/// receipt hash as the content hash.
///
/// # Errors
///
/// [`VerifyError`] carrying the reason code of the failed check; a receipt
/// that cannot be canonicalized is a `content_hash_mismatch`.
pub fn verify_receipt(
    signed: &SignedReceipt,
    keyring: &Keyring,
    options: &VerifyOptions,
) -> Result<Verified, VerifyError> {
    let hash = signed.receipt.receipt_hash().ok();
    verify_content_hash(&signed.signature, hash.as_deref(), keyring, options)
}

// --------------------------------------------------------------------------
// Format 0.1 compatibility (signing spec appendix A)
// --------------------------------------------------------------------------

/// A HushSpec 0.1 detached signature.
///
/// Kept readable so tooling can say "this is a 0.1 signature; re-sign the
/// policy" instead of reporting a generic parse failure. A 0.1 signature can
/// never be upgraded in place: its `content_hash` is over the file's bytes,
/// not over the canonical form of the resolved document, so it attests
/// something format 0.2 does not claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySignature {
    /// `"0.1.0"`.
    pub format_version: String,
    /// `"ed25519"`.
    pub algorithm: String,
    /// SHA-256 of the raw policy bytes, bare hex with no `sha256:` prefix.
    pub content_hash: String,
    /// Standard base64 with padding.
    pub signature: String,
    /// RFC 3339, any precision.
    pub signed_at: String,
    /// An opaque string the 0.1 signer chose.
    pub key_id: String,
    /// Human-readable signer identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

impl LegacySignature {
    /// Parse a 0.1 `.sig` document.
    ///
    /// # Errors
    ///
    /// [`SigningError::MalformedEnvelope`] when the text is not a 0.1
    /// envelope.
    pub fn parse(json: &str) -> Result<Self, SigningError> {
        let signature: Self = serde_json::from_str(json)
            .map_err(|error| SigningError::MalformedEnvelope(format!("{error}")))?;
        if signature.format_version != LEGACY_FORMAT_VERSION {
            return Err(SigningError::MalformedEnvelope(format!(
                "format_version {:?}, expected {LEGACY_FORMAT_VERSION:?}",
                signature.format_version
            )));
        }
        Ok(signature)
    }

    /// Whether this JSON text is a 0.1 signature, for the "re-sign it"
    /// message a 0.2 parse failure should carry.
    #[must_use]
    pub fn detect(json: &str) -> Option<Self> {
        Self::parse(json).ok()
    }
}

/// Convert a HushSpec 0.1 private key file -- a bespoke
/// `-----BEGIN HUSHSPEC PRIVATE KEY-----` wrapper around 32 raw base64 bytes,
/// or the bare base64 -- into a key that can be written as PEM PKCS#8.
///
/// # Errors
///
/// [`SigningError::InvalidKey`] when the text is not a 0.1 private key.
pub fn convert_legacy_private_key(content: &str) -> Result<SigningKey, SigningError> {
    let bytes = decode_legacy_key_body(content, "PRIVATE")?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Convert a HushSpec 0.1 public key file into a key that can be written as
/// PEM SubjectPublicKeyInfo.
///
/// # Errors
///
/// [`SigningError::InvalidKey`] when the text is not a 0.1 public key.
pub fn convert_legacy_public_key(content: &str) -> Result<VerifyingKey, SigningError> {
    let bytes = decode_legacy_key_body(content, "PUBLIC")?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| SigningError::InvalidKey(format!("invalid Ed25519 public key: {error}")))
}

fn decode_legacy_key_body(content: &str, kind: &str) -> Result<[u8; 32], SigningError> {
    let marker = format!("-----BEGIN HUSHSPEC {kind} KEY-----");
    let trimmed = content.trim();
    let body = if trimmed.contains(&marker) {
        trimmed
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>()
    } else if trimmed.contains("-----BEGIN") {
        return Err(SigningError::InvalidKey(format!(
            "expected a HushSpec 0.1 {} key file; this is already PEM",
            kind.to_lowercase()
        )));
    } else {
        trimmed.to_string()
    };

    let decoded = BASE64
        .decode(body.trim())
        .map_err(|error| SigningError::InvalidKey(format!("invalid base64: {error}")))?;
    decoded.try_into().map_err(|_| {
        SigningError::InvalidKey(format!(
            "a HushSpec 0.1 {} key is exactly 32 bytes",
            kind.to_lowercase()
        ))
    })
}

// --------------------------------------------------------------------------
// Shared helpers
// --------------------------------------------------------------------------

/// `sha256:` followed by 64 lowercase hex digits.
fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(canonical::CONTENT_HASH_PREFIX) else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`, and a real instant.
use crate::receipt::{format_timestamp, is_millisecond_timestamp};

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, String> {
    if !is_millisecond_timestamp(value) {
        return Err(format!(
            "{value:?} is not RFC 3339 UTC with millisecond precision"
        ));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|instant| instant.with_timezone(&Utc))
        .map_err(|error| format!("{value:?} is not a timestamp: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The published test keypair from `fixtures/signing/keys/`, inlined
    // rather than `include_str!`d because `cargo package` cannot reach files
    // outside the crate directory. TEST KEY -- DO NOT USE.
    const TEST_KEY_PEM: &str = "\
# TEST KEY -- DO NOT USE.
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGTPdfz6EVZtaJOI5QCAuV95QpjiCTsQwnJ3dZSakPlk
-----END PRIVATE KEY-----
";
    const TEST_PUB_PEM: &str = "\
# TEST KEY -- DO NOT USE.
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAoe42nUGYC2vRO56gfvX8YOl50EwsnCsN5tBwtwdULpo=
-----END PUBLIC KEY-----
";
    const TEST_KEY_ID: &str =
        "sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142";

    fn options() -> SignOptions {
        SignOptions {
            signed_at: Some(parse_timestamp("2026-09-15T09:00:00.000Z").unwrap()),
            ..SignOptions::default()
        }
    }

    #[test]
    fn key_id_matches_the_published_test_key() {
        let key = parse_public_key_pem(TEST_PUB_PEM).unwrap();
        assert_eq!(key_id(&key).unwrap(), TEST_KEY_ID);
    }

    #[test]
    fn spki_der_is_the_44_byte_ed25519_structure() {
        let key = parse_public_key_pem(TEST_PUB_PEM).unwrap();
        let der = spki_der(&key).unwrap();
        assert_eq!(der.len(), 44);
        assert_eq!(
            &der[..12],
            &[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
            ]
        );
        assert_eq!(&der[12..], key.to_bytes());
    }

    #[test]
    fn private_and_public_pem_round_trip() {
        let (signing_key, verifying_key) = generate_keypair();

        let private = private_key_pem(&signing_key).unwrap();
        assert!(private.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(
            parse_private_key_pem(&private).unwrap().to_bytes(),
            signing_key.to_bytes()
        );

        let public = public_key_pem(&verifying_key).unwrap();
        assert!(public.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(
            parse_public_key_pem(&public).unwrap().to_bytes(),
            verifying_key.to_bytes()
        );
    }

    #[test]
    fn pem_parsers_skip_an_explanatory_header() {
        // The published test keys carry a DO-NOT-USE comment block.
        assert!(TEST_KEY_PEM.starts_with('#'));
        let signing_key = parse_private_key_pem(TEST_KEY_PEM).unwrap();
        let verifying_key = parse_public_key_pem(TEST_PUB_PEM).unwrap();
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            verifying_key.to_bytes()
        );
    }

    #[test]
    fn signing_input_omits_the_signature_and_sorts_members() {
        let key = parse_private_key_pem(TEST_KEY_PEM).unwrap();
        let envelope = sign_content_hash(
            &format!("sha256:{}", "3".repeat(64)),
            &key,
            &SignOptions {
                policy_name: Some("p".to_string()),
                signer: Some("s".to_string()),
                ..options()
            },
        )
        .unwrap();

        let input = envelope.signing_input().unwrap();
        assert!(!input.contains("signature"));
        assert!(input.starts_with(r#"{"algorithm":"ed25519","content_hash":"#));
        assert!(input.ends_with(r#""signer":"s"}"#));
    }

    #[test]
    fn signing_is_deterministic() {
        let key = parse_private_key_pem(TEST_KEY_PEM).unwrap();
        let hash = format!("sha256:{}", "a".repeat(64));
        let first = sign_content_hash(&hash, &key, &options()).unwrap();
        let second = sign_content_hash(&hash, &key, &options()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.key_id, TEST_KEY_ID);
    }

    #[test]
    fn sign_rejects_a_hash_that_is_not_a_digest() {
        let key = parse_private_key_pem(TEST_KEY_PEM).unwrap();
        assert!(matches!(
            sign_content_hash("deadbeef", &key, &options()),
            Err(SigningError::MalformedEnvelope(_))
        ));
    }

    #[test]
    fn keyring_rejects_a_declared_id_that_is_not_the_real_one() {
        let keyring = format!(
            r#"{{"keyring_version":"0.2","keys":[{{"key_id":"sha256:{}","algorithm":"ed25519","public_key":{}}}]}}"#,
            "0".repeat(64),
            serde_json::to_string(&strip_pem_preamble(TEST_PUB_PEM)).unwrap()
        );
        let error = Keyring::parse(&keyring).unwrap_err().to_string();
        assert!(error.contains("not the digest"), "{error}");
    }

    #[test]
    fn keyring_from_a_single_public_key_recomputes_the_id() {
        let keyring = Keyring::from_public_key_pem(TEST_PUB_PEM).unwrap();
        assert_eq!(keyring.keys.len(), 1);
        assert_eq!(keyring.keys[0].key_id, TEST_KEY_ID);
        assert!(keyring.find(TEST_KEY_ID).is_some());
        assert!(keyring.find("sha256:not-a-key").is_none());
    }

    #[test]
    fn reason_codes_round_trip_through_their_wire_strings() {
        for code in ReasonCode::ALL {
            assert_eq!(ReasonCode::from_code(code.as_str()), Some(code));
        }
        assert_eq!(ReasonCode::from_code("no_such_code"), None);
    }

    #[test]
    fn legacy_key_conversion_recovers_the_same_key() {
        let (signing_key, verifying_key) = generate_keypair();
        let legacy_private = format!(
            "-----BEGIN HUSHSPEC PRIVATE KEY-----\n{}\n-----END HUSHSPEC PRIVATE KEY-----\n",
            BASE64.encode(signing_key.to_bytes())
        );
        let legacy_public = format!(
            "-----BEGIN HUSHSPEC PUBLIC KEY-----\n{}\n-----END HUSHSPEC PUBLIC KEY-----\n",
            BASE64.encode(verifying_key.to_bytes())
        );

        assert_eq!(
            convert_legacy_private_key(&legacy_private)
                .unwrap()
                .to_bytes(),
            signing_key.to_bytes()
        );
        assert_eq!(
            convert_legacy_public_key(&legacy_public)
                .unwrap()
                .to_bytes(),
            verifying_key.to_bytes()
        );
    }

    #[test]
    fn legacy_key_conversion_refuses_a_pem_key() {
        let error = convert_legacy_private_key(TEST_KEY_PEM)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already PEM"), "{error}");
    }

    #[test]
    fn digest_and_timestamp_shapes() {
        assert!(is_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_sha256_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(!is_sha256_digest(&"a".repeat(64)));
        assert!(!is_sha256_digest("sha256:abc"));

        assert!(is_millisecond_timestamp("2026-09-15T09:00:00.000Z"));
        assert!(!is_millisecond_timestamp("2026-09-15T09:00:00Z"));
        assert!(!is_millisecond_timestamp("2026-09-15T09:00:00.000+00:00"));
        assert!(!is_millisecond_timestamp("2026-13-15T09:00:00.000Z"));
    }
}
