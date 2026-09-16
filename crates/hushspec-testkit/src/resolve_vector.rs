//! The resolution vectors of `fixtures/core/resolve/` (core spec 2.3, receipt
//! spec 4.2).
//!
//! Each vector is an inline leaf document whose `extends` references only
//! builtins, so every SDK resolves it with its embedded rulesets and no
//! filesystem. The expectation is either the resolved content hash plus the
//! chain links (root first, the leaf recorded as `memory`), or a rejection
//! reason.
//!
//! The reader lives here rather than in a test file because two runners read
//! the same directory: the conformance runner, and the generator in
//! `crates/hushspec/tests/resolve_vectors.rs` that writes the committed
//! vectors. One reader means they cannot disagree about what a vector says.

use hushspec::{HushSpec, ResolveError, ResolveOptions, create_composite_loader};
use serde::{Deserialize, Serialize};

/// The vector format this reader understands.
pub const VECTORS_VERSION: &str = "0.1.0";

/// One resolution vector: a leaf document and what resolving it must produce.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveVector {
    /// The vector format version, [`VECTORS_VERSION`].
    pub hushspec_resolve: String,
    /// What the case demonstrates. Informational.
    pub description: String,
    /// The leaf document, inline.
    pub policy: serde_yaml::Value,
    pub expect: ResolveExpect,
}

/// What resolving a vector's `policy` must produce.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveExpect {
    /// Whether the chain resolves at all. Redundant with `rejects` and
    /// checked against it: a vector that disagrees with itself says nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolves: Option<bool>,
    /// The merged document's content hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// Every hop, root first, each hashed on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<ResolveLink>>,
    /// The reason code the refusal must report, for a chain that is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejects: Option<String>,
}

/// One expected chain link.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveLink {
    pub source: String,
    pub content_hash: String,
}

/// The reason a rejection is reported under, in the vocabulary the vectors
/// use.
///
/// `None` for a failure the vocabulary does not name -- an I/O, parse, HTTP or
/// canonicalization failure, none of which an inline vector can provoke. A
/// caller reports that as a failure rather than inventing a code, so a vector
/// can never pass by producing something nobody expected.
#[must_use]
pub fn reason_code(error: &ResolveError) -> Option<&'static str> {
    match error {
        ResolveError::DigestMismatch { .. } => Some("digest_mismatch"),
        ResolveError::InvalidPin { .. } => Some("invalid_pin"),
        ResolveError::Cycle { .. } => Some("cycle"),
        ResolveError::MaxDepth => Some("max_depth"),
        ResolveError::NotFound { .. } => Some("not_found"),
        ResolveError::SignatureRequired { .. } => Some("missing_signature"),
        ResolveError::Read { .. }
        | ResolveError::Parse { .. }
        | ResolveError::Http { .. }
        | ResolveError::Canonical { .. } => None,
    }
}

/// Resolve a vector's document under the default options, the way every SDK's
/// vector runner does.
///
/// # Errors
///
/// A message naming what went wrong, for a document that does not re-encode
/// or does not parse.
pub fn resolve_vector_policy(
    vector: &ResolveVector,
) -> Result<Result<hushspec::Resolution, ResolveError>, String> {
    let yaml = serde_yaml::to_string(&vector.policy)
        .map_err(|error| format!("the policy does not re-encode as YAML: {error}"))?;
    let spec =
        HushSpec::parse(&yaml).map_err(|error| format!("the policy does not parse: {error}"))?;
    Ok(hushspec::resolve_with_options(
        &spec,
        None,
        &create_composite_loader(),
        &ResolveOptions::default(),
    ))
}

/// Run one vector against the resolver, returning a one-line description of
/// the outcome for a runner to print.
///
/// # Errors
///
/// A message naming the disagreement, for a vector whose outcome, hash, chain
/// or self-consistency does not hold.
pub fn check(vector: &ResolveVector) -> Result<String, String> {
    if vector.hushspec_resolve != VECTORS_VERSION {
        return Err(format!(
            "unsupported hushspec_resolve version {}, this runner reads {VECTORS_VERSION}",
            vector.hushspec_resolve
        ));
    }
    if let Some(resolves) = vector.expect.resolves
        && resolves == vector.expect.rejects.is_some()
    {
        return Err(format!(
            "expect.resolves is {resolves}, but expect.rejects is {}",
            if vector.expect.rejects.is_some() {
                "set"
            } else {
                "absent"
            }
        ));
    }

    match (&vector.expect.rejects, resolve_vector_policy(vector)?) {
        (Some(expected), Err(error)) => match reason_code(&error) {
            Some(actual) if actual == expected => Ok(format!("Correctly rejected: {expected}")),
            Some(actual) => Err(format!(
                "expected rejection {expected}, got {actual}: {error}"
            )),
            None => Err(format!(
                "expected rejection {expected}, but {error} has no reason code the vectors name"
            )),
        },
        (Some(expected), Ok(_)) => Err(format!("expected rejection {expected}, but it resolved")),
        (None, Err(error)) => Err(format!("expected to resolve, got {error}")),
        (None, Ok(resolution)) => {
            if let Some(expected) = &vector.expect.content_hash
                && expected != &resolution.content_hash
            {
                return Err(format!(
                    "content_hash: expected {expected}, got {}",
                    resolution.content_hash
                ));
            }
            if let Some(expected) = &vector.expect.chain {
                let actual = chain_of(&resolution);
                if &actual != expected {
                    return Err(format!("chain: expected {expected:?}, got {actual:?}"));
                }
            }
            Ok(format!("OK ({} link(s))", resolution.chain.len()))
        }
    }
}

/// A resolution's chain in the vector's own shape, for comparing or writing.
#[must_use]
pub fn chain_of(resolution: &hushspec::Resolution) -> Vec<ResolveLink> {
    resolution
        .chain
        .iter()
        .map(|link| ResolveLink {
            source: link.source.clone(),
            content_hash: link.content_hash.clone(),
        })
        .collect()
}
