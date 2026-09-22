use crate::{HushSpec, canonical, merge};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "signing")]
use crate::signing::{Envelope, Keyring, VerifyOptions, verify_content_hash};

/// Maximum depth of an `extends` chain. Beyond this the resolver fails closed
/// rather than recursing until the stack overflows. Shipped policies are depth
/// <= 2; 32 is far above any realistic composition. Identical across all SDKs.
const MAX_EXTENDS_DEPTH: usize = 32;

/// A loaded HushSpec document plus its canonical source identifier.
#[derive(Clone, Debug)]
pub struct LoadedSpec {
    pub source: String,
    pub spec: HushSpec,
}

/// Errors raised while resolving `extends`.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("failed to read HushSpec document at {path}: {message}")]
    Read { path: String, message: String },
    #[error("failed to parse HushSpec document at {path}: {message}")]
    Parse { path: String, message: String },
    #[error("circular extends detected: {chain}")]
    Cycle { chain: String },
    #[error("extends chain exceeds maximum depth of 32")]
    MaxDepth,
    #[error("{message}")]
    Http { message: String },
    #[error("could not resolve reference '{reference}': {message}")]
    NotFound { reference: String, message: String },
    /// The `#sha256:` fragment on an `extends` reference is not a well-formed
    /// digest (core spec 2.3).
    #[error("invalid digest pin on '{reference}': {message}")]
    InvalidPin { reference: String, message: String },
    /// The loaded base document's own content hash does not match the pin the
    /// child declared (core spec 2.3, reason `digest_mismatch`).
    #[error(
        "digest_mismatch: '{document}' hashes to {actual}, but the extends reference pins {expected}"
    )]
    DigestMismatch {
        document: String,
        expected: String,
        actual: String,
    },
    /// A document in the chain has no canonical form, so it cannot be hashed
    /// or verified.
    #[error("no canonical form for '{document}': {message}")]
    Canonical { document: String, message: String },
    /// `require_signature` was set and a document in the chain did not carry
    /// a signature that verifies (signing spec 6.5). `status.reason` says why.
    #[error("signature required for '{document}': {}", status.reason.as_deref().unwrap_or("unverified"))]
    SignatureRequired {
        document: String,
        status: SignatureStatus,
    },
}

// --------------------------------------------------------------------------
// Verify-on-load and chain provenance (signing spec 6.5, receipt spec 4.2)
// --------------------------------------------------------------------------

/// Outcome of signature verification for one document at load time.
///
/// Mirrors `SignatureStatus` in the receipt schema: `verified` is true only
/// when an envelope was present, its key was in the keyring, and every check
/// of the signing spec passed. `reason` is the signing-spec reason code, or one
/// of the load-time conditions `missing_signature`, `no_keyring`,
/// `signing_unavailable`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureStatus {
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SignatureStatus {
    /// A failed outcome carrying a reason code.
    #[must_use]
    pub fn failed(reason: &str, key_id: Option<String>) -> Self {
        Self {
            verified: false,
            key_id,
            verified_at: None,
            reason: Some(reason.to_string()),
        }
    }
}

/// One document of a resolved `extends` chain, root first.
///
/// `content_hash` is the document canonicalized **on its own**, with its
/// `extends` and `merge_strategy` stripped (receipt spec 4.2), so an auditor
/// can check that a specific base was in force without re-resolving.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainLink {
    pub source: String,
    pub content_hash: String,
    /// Verification outcome for this document, when verification was
    /// attempted. Builtins are never verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureStatus>,
}

/// A resolved policy with its provenance.
#[derive(Clone, Debug)]
pub struct Resolution {
    /// The merged document: `extends` and `merge_strategy` are consumed by
    /// resolution, so neither appears here (core spec 2.3).
    pub spec: HushSpec,
    /// Content hash of `spec` (canonical spec 5).
    pub content_hash: String,
    /// Every document that was merged, root first, leaf last. A policy with
    /// no `extends` has exactly one link: itself.
    pub chain: Vec<ChainLink>,
    /// The leaf's verification outcome (the same value as the last link's).
    pub signature: Option<SignatureStatus>,
}

impl Resolution {
    /// Wrap a document that is already resolved (no `extends`) as a
    /// single-link resolution. `source` names it in the chain (`"memory"`
    /// when the caller has no better name).
    ///
    /// # Errors
    ///
    /// [`ResolveError::Canonical`] when the document has no canonical form,
    /// including when it still declares `extends`.
    pub fn from_resolved(spec: &HushSpec, source: Option<&str>) -> Result<Self, ResolveError> {
        let source = source.unwrap_or(MEMORY_SOURCE).to_string();
        let content_hash =
            canonical::content_hash(spec).map_err(|error| ResolveError::Canonical {
                document: source.clone(),
                message: error.to_string(),
            })?;
        // The wrapped document is a resolution output too, so it carries no
        // resolution instructions (core spec 2.3). `extends` was already
        // refused by the hash above; `merge_strategy` is inert here and is
        // cleared so every `Resolution.spec` looks the same.
        let mut spec = spec.clone();
        spec.merge_strategy = None;
        Ok(Self {
            spec,
            content_hash: content_hash.clone(),
            chain: vec![ChainLink {
                source,
                content_hash,
                signature: None,
            }],
            signature: None,
        })
    }

    /// Whether the policy was produced by merging an `extends` chain (the
    /// receipt then records the chain as `extends_chain`).
    #[must_use]
    pub fn had_extends(&self) -> bool {
        self.chain.len() > 1
    }
}

/// Source name recorded for a document that was not loaded from anywhere.
pub const MEMORY_SOURCE: &str = "memory";

/// Finds the detached signature for a source: the envelope's JSON bytes, or
/// `None` when the source has no signature the locator knows how to find.
pub type SignatureLocator = dyn Fn(&str) -> Result<Option<Vec<u8>>, ResolveError> + Send + Sync;

/// How to resolve: whether signatures are required, which keys are trusted,
/// and how to find detached envelopes.
///
/// The default resolves with no verification at all, which is what
/// [`resolve_with_loader`] and the `resolve_from_path*` helpers do.
#[derive(Default)]
pub struct ResolveOptions {
    /// Refuse to resolve unless every document loaded from an untrusted
    /// source (anything but `builtin:`) either carries a `#sha256:` pin that
    /// matches or a detached envelope that verifies against `keyring`
    /// (signing spec 6.5). Fail-closed: without a keyring nothing verifies.
    pub require_signature: bool,
    /// Trusted keys. When set and `require_signature` is false, verification
    /// runs opportunistically and its outcome is recorded.
    #[cfg(feature = "signing")]
    pub keyring: Option<Keyring>,
    /// Clock, skew, and rollback inputs for verification.
    #[cfg(feature = "signing")]
    pub verify: Option<VerifyOptions>,
    /// Where to look for detached envelopes. `None` uses the default: a file
    /// source tries `<path>.sig` then `<stem>.sig` (signing spec 7.1); other
    /// sources have no default location.
    pub signature_locator: Option<Box<SignatureLocator>>,
}

impl std::fmt::Debug for ResolveOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("ResolveOptions");
        debug.field("require_signature", &self.require_signature);
        #[cfg(feature = "signing")]
        {
            debug.field("keyring", &self.keyring.as_ref().map(|k| k.keys.len()));
        }
        debug
            .field("signature_locator", &self.signature_locator.is_some())
            .finish()
    }
}

impl ResolveOptions {
    /// Options that verify every non-builtin document against `keyring` and
    /// refuse to resolve when one does not verify.
    #[cfg(feature = "signing")]
    #[must_use]
    pub fn requiring(keyring: Keyring) -> Self {
        Self {
            require_signature: true,
            keyring: Some(keyring),
            verify: None,
            signature_locator: None,
        }
    }
}

/// Split `reference#sha256:<hex>` into the reference and its pin.
///
/// Every fragment is read as a pin: core spec 2.3 requires a malformed
/// fragment to be rejected, so anything after the last `#` that is not exactly
/// `sha256:` followed by 64 lowercase hex digits refuses the load. Treating it
/// as part of the reference would turn a typo'd pin into an unpinned load.
///
/// # Errors
///
/// [`ResolveError::InvalidPin`] for a fragment that is present but is not a
/// well-formed `sha256:` digest.
pub fn split_digest_pin(reference: &str) -> Result<(&str, Option<&str>), ResolveError> {
    let Some((base, fragment)) = reference.rsplit_once('#') else {
        return Ok((reference, None));
    };
    let invalid = |message: &str| ResolveError::InvalidPin {
        reference: reference.to_string(),
        message: message.to_string(),
    };
    let Some(hex) = fragment.strip_prefix("sha256:") else {
        return Err(invalid(
            "expected a fragment of the form #sha256:<64 lowercase hex>",
        ));
    };
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(invalid("digest must be 64 lowercase hex characters"));
    }
    if base.is_empty() {
        return Err(invalid("reference before the pin is empty"));
    }
    Ok((base, Some(fragment)))
}

/// The content hash of a document canonicalized on its own, with `extends`
/// and `merge_strategy` stripped (receipt spec 4.2; the value a digest pin
/// names, core spec 2.3).
///
/// # Errors
///
/// [`ResolveError::Canonical`] when the document has no canonical form.
pub fn own_content_hash(spec: &HushSpec, source: &str) -> Result<String, ResolveError> {
    let mut own = spec.clone();
    own.extends = None;
    own.merge_strategy = None;
    canonical::content_hash(&own).map_err(|error| ResolveError::Canonical {
        document: source.to_string(),
        message: error.to_string(),
    })
}

/// Default detached-envelope lookup for file sources (signing spec 7.1).
#[cfg(feature = "signing")]
fn default_locate_signature(source: &str) -> Result<Option<Vec<u8>>, ResolveError> {
    if source.starts_with("builtin:")
        || source == MEMORY_SOURCE
        || source.starts_with("https://")
        || source.starts_with("http://")
    {
        return Ok(None);
    }
    let path = Path::new(source);
    let candidates = [
        PathBuf::from(format!("{source}.sig")),
        path.with_extension("sig"),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            let bytes = fs::read(&candidate).map_err(|error| ResolveError::Read {
                path: candidate.display().to_string(),
                message: error.to_string(),
            })?;
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

/// Verify one document of the chain against its resolved content hash.
///
/// Returns `Ok(None)` when verification was not attempted (builtins; no
/// keyring and no requirement), `Ok(Some(status))` when it was, and
/// `Err(SignatureRequired)` when `require_signature` is set and neither a
/// matching pin nor a valid signature vouches for the document.
fn verify_hop(
    source: &str,
    resolved_hash: &str,
    options: &ResolveOptions,
    pinned: bool,
) -> Result<Option<SignatureStatus>, ResolveError> {
    if source.starts_with("builtin:") {
        return Ok(None);
    }
    let required = options.require_signature && !pinned;

    #[cfg(feature = "signing")]
    {
        if options.keyring.is_none() && !options.require_signature {
            return Ok(None);
        }
        let located = match &options.signature_locator {
            Some(locator) => locator(source)?,
            None => default_locate_signature(source)?,
        };
        let status = match (located, &options.keyring) {
            (None, _) => SignatureStatus::failed("missing_signature", None),
            (Some(_), None) => SignatureStatus::failed("no_keyring", None),
            (Some(bytes), Some(keyring)) => {
                let text = String::from_utf8_lossy(&bytes);
                match Envelope::parse(&text) {
                    Err(error) => SignatureStatus::failed(error.reason_code(), None),
                    Ok(envelope) => {
                        let verify = options.verify.clone().unwrap_or_default();
                        match verify_content_hash(&envelope, Some(resolved_hash), keyring, &verify)
                        {
                            Ok(verified) => SignatureStatus {
                                verified: true,
                                key_id: Some(verified.key_id),
                                verified_at: Some(
                                    verify
                                        .now
                                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                                ),
                                reason: None,
                            },
                            Err(error) => SignatureStatus::failed(
                                error.reason_code(),
                                Some(envelope.key_id.clone()),
                            ),
                        }
                    }
                }
            }
        };
        if required && !status.verified {
            return Err(ResolveError::SignatureRequired {
                document: source.to_string(),
                status,
            });
        }
        Ok(Some(status))
    }

    #[cfg(not(feature = "signing"))]
    {
        let _ = resolved_hash;
        if !options.require_signature {
            return Ok(None);
        }
        // Verification was attempted and this build has no backend to do it
        // with, so the outcome is recorded either way (signing spec 6.5): a
        // pinned hop carries `signing_unavailable` rather than nothing at all,
        // which a reader could only take for "no check was configured".
        let status = SignatureStatus::failed("signing_unavailable", None);
        if required {
            return Err(ResolveError::SignatureRequired {
                document: source.to_string(),
                status,
            });
        }
        Ok(Some(status))
    }
}

/// Resolve a parsed spec with verify-on-load and digest pinning.
///
/// `chain` is root first; each hop is pinned, verified, or both according to
/// `options` (signing spec 6.5, core spec 2.3). A `#sha256:` pin is checked
/// **always**, whether or not signatures are required.
///
/// Resolution walks the chain leaf to root (loading, cycle- and pin-checking
/// each document), then folds root to leaf: merge, hash the merged document,
/// and verify the document's own signature against that hash. The walk is
/// iterative so the depth cap, not the native stack, bounds a long chain.
///
/// # Errors
///
/// The loader's errors, [`ResolveError::Cycle`], [`ResolveError::MaxDepth`],
/// [`ResolveError::InvalidPin`], [`ResolveError::DigestMismatch`],
/// [`ResolveError::Canonical`], or [`ResolveError::SignatureRequired`].
pub fn resolve_with_options<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
    options: &ResolveOptions,
) -> Result<Resolution, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
{
    struct Hop {
        source: String,
        spec: HushSpec,
        pinned: bool,
    }

    // 1. Walk leaf -> root.
    let leaf_source = source.unwrap_or(MEMORY_SOURCE).to_string();
    let mut hops: Vec<Hop> = vec![Hop {
        source: leaf_source.clone(),
        spec: spec.clone(),
        pinned: false,
    }];
    let mut seen: Vec<String> = source.map(str::to_string).into_iter().collect();
    loop {
        let current = hops.last().expect("at least the leaf");
        let Some(reference) = current.spec.extends.as_deref() else {
            break;
        };
        // Fail closed on unbounded (acyclic) chains.
        if hops.len() > MAX_EXTENDS_DEPTH {
            return Err(ResolveError::MaxDepth);
        }
        let (reference, pin) = split_digest_pin(reference)?;
        let from = (current.source != MEMORY_SOURCE).then_some(current.source.as_str());
        let loaded = loader(reference, from)?;
        if let Some(index) = seen.iter().position(|entry| entry == &loaded.source) {
            let mut cycle = seen[index..].to_vec();
            cycle.push(loaded.source);
            return Err(ResolveError::Cycle {
                chain: cycle.join(" -> "),
            });
        }
        if let Some(pin) = pin {
            let actual = own_content_hash(&loaded.spec, &loaded.source)?;
            if actual != pin {
                return Err(ResolveError::DigestMismatch {
                    document: loaded.source,
                    expected: pin.to_string(),
                    actual,
                });
            }
        }
        seen.push(loaded.source.clone());
        hops.push(Hop {
            source: loaded.source,
            spec: loaded.spec,
            pinned: pin.is_some(),
        });
    }

    // 2. Fold root -> leaf.
    let mut resolved: Option<HushSpec> = None;
    let mut chain = Vec::with_capacity(hops.len());
    let mut signature = None;
    for hop in hops.iter().rev() {
        let merged = match resolved.take() {
            None => hop.spec.clone(),
            Some(parent) => merge(&parent, &hop.spec),
        };
        let resolved_hash =
            canonical::content_hash(&merged).map_err(|error| ResolveError::Canonical {
                document: hop.source.clone(),
                message: error.to_string(),
            })?;
        let status = verify_hop(&hop.source, &resolved_hash, options, hop.pinned)?;
        chain.push(ChainLink {
            source: hop.source.clone(),
            content_hash: own_content_hash(&hop.spec, &hop.source)?,
            signature: status.clone(),
        });
        signature = status;
        resolved = Some(merged);
    }
    // A resolved document declares neither `extends` nor `merge_strategy`
    // (core spec 2.3): `merge` consumes both, and a one-hop chain never went
    // through `merge` at all, so the leaf is cleaned here as well. Canonical
    // form already ignores both fields, so the hash below does not move.
    let mut resolved = resolved.expect("at least the leaf");
    resolved.extends = None;
    resolved.merge_strategy = None;
    let content_hash =
        canonical::content_hash(&resolved).map_err(|error| ResolveError::Canonical {
            document: leaf_source,
            message: error.to_string(),
        })?;
    Ok(Resolution {
        spec: resolved,
        content_hash,
        chain,
        signature,
    })
}

/// Embedded built-in ruleset YAML strings.
///
/// Accepts either the bare name (`"default"`) or the prefixed form
/// (`"builtin:default"`). The prefix is stripped exactly once, so
/// `"builtin:builtin:default"` is not a built-in.
///
/// The YAML itself lives in the generated `generated_builtins` module (see
/// `scripts/generate_rust_builtins.py`) rather than behind `include_str!`,
/// because `rulesets/` sits outside the crate directory and therefore is not
/// part of the published crate.
pub fn load_builtin(name: &str) -> Option<&'static str> {
    let resolved = name.strip_prefix("builtin:").unwrap_or(name);
    crate::generated_builtins::BUILTIN_RULESETS
        .iter()
        .find(|(builtin, _)| *builtin == resolved)
        .map(|(_, yaml)| *yaml)
}

pub const BUILTIN_NAMES: &[&str] = crate::generated_builtins::BUILTIN_NAMES;

fn try_load_builtin(reference: &str) -> Option<Result<LoadedSpec, ResolveError>> {
    let yaml = load_builtin(reference)?;
    let source = if reference.starts_with("builtin:") {
        reference.to_string()
    } else {
        format!("builtin:{reference}")
    };
    Some(
        HushSpec::parse(yaml)
            .map(|spec| LoadedSpec { source, spec })
            .map_err(|error| ResolveError::Parse {
                path: reference.to_string(),
                message: error.to_string(),
            }),
    )
}

/// Loading an `extends` base over HTTPS (core spec 2.6.4).
///
/// A policy may name its base by URL (`extends: "https://policies.example/base.yaml"`,
/// core spec 2.3). Fetching one is a request an attacker partly controls -- the
/// URL comes out of a document -- so this loader is the narrowest thing that can
/// still do the job:
///
/// * **HTTPS only.** `http:` is refused outright. A base fetched in the clear is
///   a base anyone on the path can rewrite, and the resolver would merge it.
/// * **No redirects.** A 3xx is an error, not a hop to follow: a redirect is the
///   server asking to move the request somewhere the checks never saw.
/// * **The address is checked, then pinned.** The host is resolved first and
///   every address it resolves to is checked against [`is_blocked_address`]; the
///   connection then goes to the address that was checked, with the original
///   hostname still used for SNI, certificate validation and the `Host` header.
///   A name that re-resolves to `127.0.0.1` between the check and the connect --
///   DNS rebinding -- reaches nothing.
/// * **Bounded.** A byte cap on the body, a connect timeout, and a read timeout.
/// * **Optionally allowlisted.** [`HttpLoaderConfig::allowed_hosts`] narrows the
///   reachable hosts to a fixed set, which is what a deployment that knows its
///   policy server should do.
///
/// Integrity is not this module's job and it does not pretend otherwise. A URL
/// is a location, never an identity: what makes a remote base trustworthy is the
/// `#sha256:` digest pin on the reference (core spec 2.3) or a detached
/// signature, both enforced by the resolver around this loader.
/// [`fetch_signature`] supplies the other half, fetching `<url>.sig` under the
/// same rules (signing spec 7.1).
#[cfg(feature = "http")]
pub mod http {
    use super::*;
    use std::io::Read as _;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;

    /// How long to wait for the TCP connection, in milliseconds.
    pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;

    /// How long to wait for response bytes once connected, in milliseconds.
    pub const DEFAULT_READ_TIMEOUT_MS: u64 = 10_000;

    /// Largest response body accepted, in bytes. A policy is a small document;
    /// a megabyte is already far beyond any real one, and the cap is what stops
    /// a hostile server feeding the resolver until it runs out of memory.
    pub const DEFAULT_MAX_SIZE: usize = 1_048_576;

    /// The two well-known cloud instance-metadata endpoints, named so the intent
    /// is readable even though [`BLOCKED_NETWORKS`] already covers both
    /// (`169.254.0.0/16` and `fc00::/7`). Reaching one from a URL an agent
    /// supplied is the classic server-side request forgery credential theft.
    pub const CLOUD_METADATA_ADDRESSES: [&str; 2] = ["169.254.169.254", "fd00:ec2::254"];

    /// Every network a policy URL may not resolve to (core spec 2.6.4). A host
    /// that resolves to any of these is refused *after* DNS, because the danger
    /// is the address and not the name: `internal.example.com` and a name that
    /// resolves to `10.0.0.5` are the same request.
    pub const BLOCKED_NETWORKS: &[(IpAddr, u8)] = &[
        // IPv4
        (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8), // "this network", and 0.0.0.0 itself
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8), // RFC 1918
        (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10), // RFC 6598 carrier-grade NAT
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8), // loopback
        (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16), // link-local, including cloud metadata
        (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12), // RFC 1918
        (IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)), 24), // IETF protocol assignments
        (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16), // RFC 1918
        (IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15), // benchmarking
        (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 4), // multicast
        (IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0)), 4), // reserved, including the broadcast address
        // IPv6
        (IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 128), // unspecified
        (IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 128), // loopback
        (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7), // unique local
        (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10), // link-local
        (IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)), 8), // multicast
    ];

    /// Default number of cached URLs: two maximum-depth chains.
    pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 64;

    /// How the HTTPS loader behaves. The defaults are the safe ones.
    #[derive(Clone, Debug)]
    pub struct HttpLoaderConfig {
        /// Milliseconds to wait for the TCP connection.
        pub connect_timeout_ms: u64,
        /// Milliseconds to wait for response bytes once connected.
        pub read_timeout_ms: u64,
        /// Largest response body accepted, in bytes.
        pub max_size: usize,
        /// Whether to verify the server certificate. Off is for test harnesses
        /// only and is never appropriate in a deployment: a policy fetched over
        /// an unverified connection is a policy anyone on the path can rewrite.
        pub verify_tls: bool,
        /// Value of an `Authorization` header to send, when the policy server
        /// needs one.
        pub auth_header: Option<String>,
        /// When set, the only hosts this loader will fetch from. A host outside
        /// it is refused before DNS. Matching is exact and case-insensitive; it
        /// is a list of host names, not a suffix rule, because
        /// `evil-example.com` ends in neither `example.com` nor anything else a
        /// suffix test would be safe about.
        pub allowed_hosts: Option<Vec<String>>,
        /// Where `ETag` revalidation state lives. `None` disables it.
        pub cache_dir: Option<PathBuf>,
        /// How many URLs the cache keeps. The oldest entries are evicted
        /// first once the cap is reached, so a chain of documents cannot
        /// grow the cache without bound.
        pub cache_max_entries: usize,
    }

    impl Default for HttpLoaderConfig {
        fn default() -> Self {
            Self {
                connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
                read_timeout_ms: DEFAULT_READ_TIMEOUT_MS,
                max_size: DEFAULT_MAX_SIZE,
                verify_tls: true,
                auth_header: None,
                allowed_hosts: None,
                cache_dir: None,
                cache_max_entries: DEFAULT_CACHE_MAX_ENTRIES,
            }
        }
    }

    /// A URL that passed every check, with the address the request will dial.
    #[derive(Clone, Debug)]
    pub struct HttpTarget {
        /// The URL as the caller gave it.
        pub url: String,
        /// The host as written, without IPv6 brackets. Used for SNI, the
        /// certificate check and the `Host` header.
        pub host: String,
        /// The address the socket goes to.
        pub address: SocketAddr,
    }

    // ---------------------------------------------------------------------
    // Address checks
    // ---------------------------------------------------------------------

    /// The IPv4 address inside an IPv6 one, for both the IPv4-mapped
    /// (`::ffff:a.b.c.d`) and the deprecated IPv4-compatible (`::a.b.c.d`)
    /// forms. `None` when there is none, and for `::` and `::1`, which the IPv6
    /// entries of [`BLOCKED_NETWORKS`] already cover.
    fn embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
        if let Some(mapped) = v6.to_ipv4_mapped() {
            return Some(mapped);
        }
        let segments = v6.segments();
        if segments[..6].iter().any(|&segment| segment != 0) {
            return None;
        }
        let low = (u32::from(segments[6]) << 16) | u32::from(segments[7]);
        if low <= 1 {
            return None; // :: (unspecified) and ::1 (loopback)
        }
        Some(Ipv4Addr::from(low))
    }

    fn masked_v4(address: Ipv4Addr, prefix: u8) -> u32 {
        let bits = u32::from(address);
        match prefix {
            0 => 0,
            _ => bits & (u32::MAX << (32 - u32::from(prefix))),
        }
    }

    fn masked_v6(address: Ipv6Addr, prefix: u8) -> u128 {
        let bits = u128::from(address);
        match prefix {
            0 => 0,
            _ => bits & (u128::MAX << (128 - u32::from(prefix))),
        }
    }

    fn in_network(address: &IpAddr, network: &IpAddr, prefix: u8) -> bool {
        match (address, network) {
            (IpAddr::V4(address), IpAddr::V4(network)) => {
                masked_v4(*address, prefix) == masked_v4(*network, prefix)
            }
            (IpAddr::V6(address), IpAddr::V6(network)) => {
                masked_v6(*address, prefix) == masked_v6(*network, prefix)
            }
            _ => false,
        }
    }

    /// Whether `address` is one a policy URL may not reach (core spec 2.6.4).
    ///
    /// Blocks every network in [`BLOCKED_NETWORKS`]: the unspecified address,
    /// loopback, the RFC 1918 private ranges, link-local (which is where the
    /// cloud metadata endpoint lives), carrier-grade NAT, the IETF protocol
    /// assignments, the benchmarking range, multicast, the reserved range, and
    /// the IPv6 unique-local and link-local ranges.
    ///
    /// IPv6 forms that carry an IPv4 address in their low 32 bits are unwrapped
    /// first and judged on the address inside. Both the IPv4-*mapped* form
    /// (`::ffff:127.0.0.1`) and the deprecated IPv4-*compatible* form
    /// (`::7f00:1`, which is `127.0.0.1`) would otherwise slip past a check that
    /// only looked at IPv6 ranges.
    #[must_use]
    pub fn is_blocked_address(address: &IpAddr) -> bool {
        let address = match address {
            IpAddr::V6(v6) => embedded_ipv4(v6).map_or(*address, IpAddr::V4),
            IpAddr::V4(_) => *address,
        };
        BLOCKED_NETWORKS
            .iter()
            .any(|(network, prefix)| in_network(&address, network, *prefix))
    }

    // ---------------------------------------------------------------------
    // URL validation
    // ---------------------------------------------------------------------

    /// Check `url_str` and resolve its host, or say why not (core spec 2.6.4).
    ///
    /// The order matters: scheme, then host, then the allowlist, then DNS, then
    /// the address check. Every address the name resolves to must be acceptable,
    /// not merely the first -- a name with one public and one private address is
    /// a name that reaches the private one. The address returned is the one the
    /// connection is pinned to.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Http`] for a URL that is malformed, is not `https:`, has
    /// no host, is outside the allowlist, does not resolve, or resolves to a
    /// blocked address.
    pub fn validate_url(
        url_str: &str,
        config: &HttpLoaderConfig,
    ) -> Result<HttpTarget, ResolveError> {
        let parsed = url::Url::parse(url_str).map_err(|error| ResolveError::Http {
            message: format!("invalid URL '{url_str}': {error}"),
        })?;

        if parsed.scheme() != "https" {
            return Err(ResolveError::Http {
                message: format!("only HTTPS URLs are allowed, got '{}'", parsed.scheme()),
            });
        }

        let host = parsed.host().ok_or_else(|| ResolveError::Http {
            message: format!("URL '{url_str}' has no host"),
        })?;
        let host_name = match &host {
            url::Host::Domain(domain) => (*domain).to_string(),
            url::Host::Ipv4(address) => address.to_string(),
            url::Host::Ipv6(address) => address.to_string(),
        };
        if host_name.is_empty() {
            return Err(ResolveError::Http {
                message: format!("URL '{url_str}' has no host"),
            });
        }

        if let Some(allowed) = &config.allowed_hosts
            && !allowed
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(&host_name))
        {
            return Err(ResolveError::Http {
                message: format!("host '{host_name}' is not in the allowlist of this loader"),
            });
        }

        let port = parsed.port_or_known_default().unwrap_or(443);

        // An IP literal is already an address; only a name goes to the
        // resolver, and every address it answers with must clear the list.
        let addresses: Vec<SocketAddr> = match &host {
            url::Host::Ipv4(address) => vec![SocketAddr::new(IpAddr::V4(*address), port)],
            url::Host::Ipv6(address) => vec![SocketAddr::new(IpAddr::V6(*address), port)],
            url::Host::Domain(domain) => std::net::ToSocketAddrs::to_socket_addrs(&(*domain, port))
                .map_err(|error| ResolveError::Http {
                    message: format!("failed to resolve host '{host_name}': {error}"),
                })?
                .collect(),
        };

        let Some(&address) = addresses.first() else {
            return Err(ResolveError::Http {
                message: format!("host '{host_name}' did not resolve to any addresses"),
            });
        };

        for candidate in &addresses {
            if is_blocked_address(&candidate.ip()) {
                return Err(ResolveError::Http {
                    message: format!(
                        "SSRF protection: host '{host_name}' resolves to private IP {}",
                        candidate.ip()
                    ),
                });
            }
        }

        Ok(HttpTarget {
            url: url_str.to_string(),
            host: host_name,
            address,
        })
    }

    // ---------------------------------------------------------------------
    // The transport
    // ---------------------------------------------------------------------

    /// A client that dials only `target.address`.
    ///
    /// The request still carries the original host, so the `Host` header, the
    /// SNI name and the certificate check all use it; only the socket goes to
    /// the address [`validate_url`] already approved. That is what closes DNS
    /// rebinding: the name is resolved once, judged once, and connected to once.
    /// Redirects are refused rather than followed, and the connect and read
    /// budgets are separate, so a server that accepts and then stalls does not
    /// inherit the connect timeout's patience.
    fn pinned_client(
        target: &HttpTarget,
        config: &HttpLoaderConfig,
    ) -> Result<reqwest::blocking::Client, ResolveError> {
        let connect = Duration::from_millis(config.connect_timeout_ms);
        let read = Duration::from_millis(config.read_timeout_ms);
        let mut builder = reqwest::blocking::Client::builder()
            .connect_timeout(connect)
            .timeout(connect + read)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(!config.verify_tls);

        // A name is pinned to the checked address; an IP literal never reaches
        // the resolver in the first place.
        if target.host.parse::<IpAddr>().is_err() {
            builder = builder.resolve(&target.host, target.address);
        }

        builder.build().map_err(|error| ResolveError::Http {
            message: format!("failed to build HTTP client: {error}"),
        })
    }

    /// What a response status means to this loader.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum StatusOutcome {
        /// A body to read.
        Body,
        /// The cached body is still current.
        NotModified,
        /// There is nothing at this URL, and the caller asked to be told so
        /// rather than to fail.
        Missing,
        /// A hop the loader will not take, carrying the `Location` offered.
        Redirect(String),
        /// Anything else, which is a failure.
        Failed,
    }

    /// Classify a response status (core spec 2.6.4).
    ///
    /// A 3xx is a refusal in its own right rather than a generic failure: a
    /// redirect would reissue the request somewhere the scheme check, the
    /// allowlist and the address check never saw, and even a same-host one moves
    /// the request to a location the deployment never named.
    fn classify_status(status: u16, location: &str, missing_is_none: bool) -> StatusOutcome {
        match status {
            304 => StatusOutcome::NotModified,
            300..=399 => StatusOutcome::Redirect(location.to_string()),
            404 | 410 if missing_is_none => StatusOutcome::Missing,
            200..=299 => StatusOutcome::Body,
            _ => StatusOutcome::Failed,
        }
    }

    /// What one GET produced.
    struct FetchResult {
        /// The body, empty on a revalidation or a miss.
        body: String,
        /// The `ETag` the server returned, when it returned one.
        etag: Option<String>,
        /// The server said the cached body is still current.
        revalidated: bool,
        /// There is nothing at this URL.
        missing: bool,
    }

    /// Perform one GET of `target` under `config`.
    fn fetch(
        target: &HttpTarget,
        config: &HttpLoaderConfig,
        etag: Option<&str>,
        missing_is_none: bool,
    ) -> Result<FetchResult, ResolveError> {
        let mut request = pinned_client(target, config)?
            .get(&target.url)
            .header("Accept", "application/yaml, text/yaml, */*");
        if let Some(auth) = &config.auth_header {
            request = request.header("Authorization", auth);
        }
        if let Some(etag) = etag {
            request = request.header("If-None-Match", etag);
        }

        let url_str = &target.url;
        let response = request.send().map_err(|error| ResolveError::Http {
            message: format!("HTTP request to '{url_str}' failed: {error}"),
        })?;

        let status = response.status();
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();

        match classify_status(status.as_u16(), &location, missing_is_none) {
            StatusOutcome::NotModified => {
                return Ok(FetchResult {
                    body: String::new(),
                    etag: etag.map(String::from),
                    revalidated: true,
                    missing: false,
                });
            }
            StatusOutcome::Redirect(location) => {
                return Err(ResolveError::Http {
                    message: format!(
                        "HTTP request to '{url_str}' was redirected to '{location}'; \
                         redirects are not followed"
                    ),
                });
            }
            StatusOutcome::Missing => {
                return Ok(FetchResult {
                    body: String::new(),
                    etag: None,
                    revalidated: false,
                    missing: true,
                });
            }
            StatusOutcome::Failed => {
                return Err(ResolveError::Http {
                    message: format!("HTTP request to '{url_str}' returned status {status}"),
                });
            }
            StatusOutcome::Body => {}
        }

        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(String::from);

        // One byte past the cap on purpose: a body of exactly `max_size` is
        // fine, and anything longer is refused without ever being held whole.
        let mut body = Vec::new();
        response
            .take(config.max_size as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| ResolveError::Http {
                message: format!("failed to read response from '{url_str}': {error}"),
            })?;
        if body.len() > config.max_size {
            return Err(ResolveError::Http {
                message: format!(
                    "response from '{url_str}' exceeds maximum size of {} bytes",
                    config.max_size
                ),
            });
        }
        let body = String::from_utf8(body).map_err(|error| ResolveError::Http {
            message: format!("response from '{url_str}' is not valid UTF-8: {error}"),
        })?;

        Ok(FetchResult {
            body,
            etag,
            revalidated: false,
            missing: false,
        })
    }

    // ---------------------------------------------------------------------
    // Revalidation state
    // ---------------------------------------------------------------------

    #[derive(serde::Serialize, serde::Deserialize)]
    struct CacheEntry {
        etag: String,
        url: String,
    }

    fn cache_key(url: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        url.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    fn read_cache(cache_dir: &Path, url: &str) -> Option<(String, String)> {
        let key = cache_key(url);
        let meta_path = cache_dir.join(format!("{key}.meta.json"));
        let body_path = cache_dir.join(format!("{key}.yaml"));

        let meta_content = fs::read_to_string(&meta_path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&meta_content).ok()?;
        if entry.url != url {
            return None;
        }
        let body = fs::read_to_string(&body_path).ok()?;
        Some((entry.etag, body))
    }

    fn write_cache(
        cache_dir: &Path,
        url: &str,
        etag: &str,
        body: &str,
        max_entries: usize,
    ) -> Result<(), std::io::Error> {
        fs::create_dir_all(cache_dir)?;
        let key = cache_key(url);
        let entry = CacheEntry {
            etag: etag.to_string(),
            url: url.to_string(),
        };
        fs::write(
            cache_dir.join(format!("{key}.meta.json")),
            serde_json::to_string(&entry).unwrap_or_default(),
        )?;
        fs::write(cache_dir.join(format!("{key}.yaml")), body)?;
        evict_oldest(cache_dir, max_entries)
    }

    /// Keep at most `max_entries` cached URLs, dropping the oldest metadata
    /// files and their bodies first.
    fn evict_oldest(cache_dir: &Path, max_entries: usize) -> Result<(), std::io::Error> {
        let mut entries: Vec<(std::time::SystemTime, PathBuf)> = fs::read_dir(cache_dir)?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let is_meta = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".meta.json"));
                if !is_meta {
                    return None;
                }
                let modified = entry.metadata().and_then(|meta| meta.modified()).ok()?;
                Some((modified, path))
            })
            .collect();
        if entries.len() <= max_entries {
            return Ok(());
        }
        entries.sort();
        for (_, meta_path) in entries.iter().take(entries.len() - max_entries) {
            let body_path = meta_path.with_file_name(
                meta_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.replace(".meta.json", ".yaml"))
                    .unwrap_or_default(),
            );
            let _ = fs::remove_file(meta_path);
            let _ = fs::remove_file(body_path);
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Loaders
    // ---------------------------------------------------------------------

    /// Fetch a HushSpec document over HTTPS (core spec 2.6.4).
    ///
    /// The scheme, allowlist and address checks run before a socket is opened,
    /// the connection is pinned to the address that was checked, redirects are
    /// refused, the body is capped, and an `ETag` is revalidated with
    /// `If-None-Match` when `config.cache_dir` is set. A 304 answered without a
    /// cached body to revalidate is a failure, never an empty document.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Http`] for any refusal or transport failure, and
    /// [`ResolveError::Parse`] for a body that is not a HushSpec document.
    pub fn load_from_https(
        url_str: &str,
        config: &HttpLoaderConfig,
    ) -> Result<LoadedSpec, ResolveError> {
        let target = validate_url(url_str, config)?;

        let cached = config
            .cache_dir
            .as_ref()
            .and_then(|dir| read_cache(dir, url_str));

        let result = fetch(
            &target,
            config,
            cached.as_ref().map(|(etag, _)| etag.as_str()),
            false,
        )?;

        let body = if result.revalidated {
            match &cached {
                Some((_, body)) => body.clone(),
                None => {
                    return Err(ResolveError::Http {
                        message: format!(
                            "HTTP request to '{url_str}' returned status 304 without a cached \
                             response to revalidate"
                        ),
                    });
                }
            }
        } else {
            if let (Some(etag), Some(cache_dir)) = (&result.etag, &config.cache_dir) {
                let _ = write_cache(
                    cache_dir,
                    url_str,
                    etag,
                    &result.body,
                    config.cache_max_entries,
                );
            }
            result.body
        };

        let spec = HushSpec::parse(&body).map_err(|error| ResolveError::Parse {
            path: url_str.to_string(),
            message: error.to_string(),
        })?;

        Ok(LoadedSpec {
            source: url_str.to_string(),
            spec,
        })
    }

    /// Fetch the detached envelope beside a policy URL (signing spec 7.1).
    ///
    /// The sidecar is fetched under exactly the rules the policy was: HTTPS
    /// only, the same allowlist, the same address check and pinning, no
    /// redirects, the same caps. A `.sig` URL must never be able to reach
    /// somewhere the policy URL could not.
    ///
    /// A missing sidecar is `Ok(None)`, not an error: "this policy is unsigned"
    /// is a fact the caller decides what to do with -- `require_signature` turns
    /// it into a refusal, opportunistic verification just records nothing. Every
    /// *other* failure is an error, because a 500 or an oversized body says
    /// nothing about whether a signature exists.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Http`] for any refusal or transport failure other than a
    /// 404 or 410.
    pub fn fetch_signature(
        url_str: &str,
        config: &HttpLoaderConfig,
    ) -> Result<Option<Vec<u8>>, ResolveError> {
        let target = validate_url(url_str, config)?;
        let result = fetch(&target, config, None, true)?;
        if result.missing {
            return Ok(None);
        }
        Ok(Some(result.body.into_bytes()))
    }

    /// A [`SignatureLocator`] for URL sources: `<source>.sig`, or `None` when
    /// there is none, which is what the resolver reads as `missing_signature`.
    /// A non-URL source is left to the caller's other locators.
    #[must_use]
    pub fn signature_locator(config: HttpLoaderConfig) -> Box<SignatureLocator> {
        Box::new(move |source: &str| {
            if !source.starts_with("https://") {
                return Ok(None);
            }
            fetch_signature(&format!("{source}.sig"), &config)
        })
    }

    /// Create a composite loader that chains: builtin -> file -> HTTPS.
    ///
    /// Reference dispatch:
    /// - `builtin:*` or bare names matching a builtin -> builtin loader
    /// - `https://` -> HTTPS loader
    /// - `http://` -> refused, naming the scheme
    /// - everything else -> filesystem loader
    pub fn create_default_loader(
        config: HttpLoaderConfig,
    ) -> impl Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError> {
        move |reference: &str, from: Option<&str>| -> Result<LoadedSpec, ResolveError> {
            // 1. Explicit builtin prefix
            if reference.starts_with("builtin:") {
                return match try_load_builtin(reference) {
                    Some(result) => result,
                    None => Err(ResolveError::NotFound {
                        reference: reference.to_string(),
                        message: "unknown builtin ruleset".to_string(),
                    }),
                };
            }

            if reference.starts_with("https://") {
                return load_from_https(reference, &config);
            }

            // `http:` is answered here rather than by the filesystem loader, so
            // the refusal names the scheme instead of reporting a missing file.
            if reference.starts_with("http://") {
                return Err(ResolveError::Http {
                    message: "only HTTPS URLs are allowed, got 'http'".to_string(),
                });
            }

            if !reference.contains('/')
                && !reference.contains('\\')
                && !reference.contains('.')
                && let Some(result) = try_load_builtin(reference)
            {
                return result;
            }

            load_from_filesystem(reference, from)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn address(text: &str) -> IpAddr {
            text.parse().expect("test address should parse")
        }

        #[test]
        fn blocks_every_reserved_ipv4_family() {
            for text in [
                "0.0.0.0",
                "0.1.2.3",
                "10.0.0.1",
                "100.64.0.1",
                "100.127.255.255",
                "127.0.0.1",
                "127.1.2.3",
                "169.254.1.1",
                "169.254.169.254",
                "172.16.0.1",
                "172.31.255.255",
                "192.0.0.1",
                "192.168.1.1",
                "198.18.0.1",
                "198.19.255.255",
                "224.0.0.1",
                "239.255.255.250",
                "240.0.0.1",
                "255.255.255.255",
            ] {
                assert!(
                    is_blocked_address(&address(text)),
                    "{text} must not be reachable"
                );
            }
        }

        #[test]
        fn blocks_every_reserved_ipv6_family() {
            for text in [
                "::",
                "::1",
                "fc00::1",
                "fd00::1",
                "fd00:ec2::254",
                "fe80::1",
                "ff02::1",
            ] {
                assert!(
                    is_blocked_address(&address(text)),
                    "{text} must not be reachable"
                );
            }
        }

        #[test]
        fn blocks_ipv4_inside_ipv6() {
            for text in [
                // IPv4-mapped
                "::ffff:127.0.0.1",
                "::ffff:10.0.0.1",
                "::ffff:169.254.169.254",
                // Deprecated IPv4-compatible
                "::7f00:1",
                "::a9fe:a9fe",
                "::a00:1",
            ] {
                assert!(
                    is_blocked_address(&address(text)),
                    "{text} must not be reachable"
                );
            }
        }

        #[test]
        fn blocks_the_cloud_metadata_endpoints() {
            for text in CLOUD_METADATA_ADDRESSES {
                assert!(
                    is_blocked_address(&address(text)),
                    "the cloud metadata endpoint {text} is reachable"
                );
            }
        }

        #[test]
        fn leaves_public_addresses_reachable() {
            for text in [
                "8.8.8.8",
                "1.1.1.1",
                "93.184.216.34",
                "11.0.0.1",
                "172.32.0.1",
                "198.20.0.1",
                "223.255.255.255",
                "2606:4700:4700::1111",
                // An IPv4-compatible form wrapping a public address stays public.
                "::808:808",
            ] {
                assert!(
                    !is_blocked_address(&address(text)),
                    "{text} is a public address and must be reachable"
                );
            }
        }

        #[test]
        fn rejects_non_https_schemes() {
            let config = HttpLoaderConfig::default();
            for url in [
                "http://example.com/policy.yaml",
                "ftp://example.com/policy.yaml",
                "file:///etc/passwd",
            ] {
                let message = validate_url(url, &config)
                    .expect_err("non-HTTPS scheme should be refused")
                    .to_string();
                assert!(
                    message.contains("only HTTPS URLs are allowed"),
                    "unexpected refusal for '{url}': {message}"
                );
            }
        }

        #[test]
        fn rejects_blocked_literal_hosts_without_dns() {
            let config = HttpLoaderConfig::default();
            for url in [
                "https://127.0.0.1/policy.yaml",
                "https://10.0.0.1/policy.yaml",
                "https://169.254.169.254/latest/meta-data/",
                "https://100.64.0.1/policy.yaml",
                "https://[::1]/policy.yaml",
                "https://[fc00::1]/policy.yaml",
                "https://[fe80::1]/policy.yaml",
                "https://[::ffff:127.0.0.1]/policy.yaml",
            ] {
                let message = validate_url(url, &config)
                    .expect_err("blocked address should be refused")
                    .to_string();
                assert!(
                    message.contains("SSRF protection"),
                    "unexpected refusal for '{url}': {message}"
                );
            }
        }

        #[test]
        fn allowlist_is_checked_before_dns() {
            let config = HttpLoaderConfig {
                allowed_hosts: Some(vec!["Policies.Example.COM".to_string()]),
                ..HttpLoaderConfig::default()
            };
            // A host outside the allowlist is refused without a lookup, so this
            // asserts the refusal rather than a resolution failure.
            let message = validate_url("https://evil.invalid/policy.yaml", &config)
                .expect_err("host outside the allowlist should be refused")
                .to_string();
            assert!(
                message.contains("is not in the allowlist"),
                "unexpected refusal: {message}"
            );
        }

        #[test]
        fn allowlist_matching_is_case_insensitive_and_exact() {
            let config = HttpLoaderConfig {
                allowed_hosts: Some(vec!["policies.example.com".to_string()]),
                ..HttpLoaderConfig::default()
            };
            // A suffix of an allowed host is a different host.
            let message = validate_url("https://evil-policies.example.com.invalid/p.yaml", &config)
                .expect_err("a longer host is not the allowed host")
                .to_string();
            assert!(message.contains("is not in the allowlist"));
        }

        #[test]
        fn pins_the_checked_address_for_a_literal_host() {
            let config = HttpLoaderConfig::default();
            let target =
                validate_url("https://8.8.8.8:8443/policy.yaml", &config).expect("public literal");
            assert_eq!(target.host, "8.8.8.8");
            assert_eq!(target.address, "8.8.8.8:8443".parse().unwrap());
        }

        #[test]
        fn redirects_are_refused_rather_than_followed() {
            for status in [301, 302, 303, 307, 308] {
                assert_eq!(
                    classify_status(status, "https://elsewhere.invalid/", false),
                    StatusOutcome::Redirect("https://elsewhere.invalid/".to_string()),
                    "status {status} must be refused"
                );
            }
        }

        #[test]
        fn status_classification_covers_the_remaining_cases() {
            assert_eq!(classify_status(200, "", false), StatusOutcome::Body);
            assert_eq!(classify_status(304, "", false), StatusOutcome::NotModified);
            assert_eq!(classify_status(500, "", false), StatusOutcome::Failed);
            // Only a signature lookup reads 404 and 410 as "there is none".
            assert_eq!(classify_status(404, "", false), StatusOutcome::Failed);
            assert_eq!(classify_status(404, "", true), StatusOutcome::Missing);
            assert_eq!(classify_status(410, "", true), StatusOutcome::Missing);
        }

        #[test]
        fn default_config_is_the_safe_one() {
            let config = HttpLoaderConfig::default();
            assert!(config.verify_tls, "TLS verification must default to on");
            assert!(config.allowed_hosts.is_none());
            assert_eq!(config.max_size, DEFAULT_MAX_SIZE);
            assert_eq!(config.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
            assert_eq!(config.read_timeout_ms, DEFAULT_READ_TIMEOUT_MS);
        }

        #[test]
        fn pinned_client_builds_with_the_loader_policy() {
            // The redirect policy, the two timeout budgets and the pinned
            // address are all set on the client, where no response can change
            // them; that they are is what this asserts.
            let config = HttpLoaderConfig::default();
            let target = validate_url("https://8.8.8.8/policy.yaml", &config).expect("literal");
            assert!(pinned_client(&target, &config).is_ok());
        }

        #[test]
        fn http_loader_rejects_plain_http() {
            let loader = create_default_loader(HttpLoaderConfig::default());
            let message = loader("http://example.com/policy.yaml", None)
                .expect_err("plain http should be refused")
                .to_string();
            assert!(message.contains("only HTTPS URLs are allowed"));
        }

        #[test]
        fn signature_locator_ignores_non_url_sources() {
            let locate = signature_locator(HttpLoaderConfig::default());
            assert!(
                locate("policy.yaml")
                    .expect("a path is not this locator's")
                    .is_none()
            );
            assert!(
                locate("builtin:strict")
                    .expect("a builtin has no sidecar")
                    .is_none()
            );
        }

        #[test]
        fn etag_cache_round_trip() {
            let dir = std::env::temp_dir().join(format!(
                "hushspec-cache-test-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock should be after the epoch")
                    .as_nanos()
            ));

            let url = "https://example.com/test-policy.yaml";
            let etag = "\"abc123\"";
            let body = "hushspec: \"0.1.0\"\nname: cached\n";

            write_cache(&dir, url, etag, body, DEFAULT_CACHE_MAX_ENTRIES)
                .expect("cache write should succeed");

            let (cached_etag, cached_body) = read_cache(&dir, url).expect("cache read should hit");
            assert_eq!(cached_etag, etag);
            assert_eq!(cached_body, body);

            assert!(read_cache(&dir, "https://other.com/policy.yaml").is_none());

            fs::remove_dir_all(&dir).expect("cache directory should be removable");
        }

        #[test]
        fn evicts_the_oldest_entries_past_the_cap() {
            let dir = std::env::temp_dir().join(format!(
                "hushspec-cache-evict-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock should be after the epoch")
                    .as_nanos()
            ));
            let urls: Vec<String> = (0..4)
                .map(|i| format!("https://example.com/policy-{i}.yaml"))
                .collect();
            for (i, url) in urls.iter().enumerate() {
                write_cache(&dir, url, "\"etag\"", "hushspec: \"0.1.0\"\n", usize::MAX)
                    .expect("cache write should succeed");
                let written =
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000 + i as u64);
                fs::OpenOptions::new()
                    .write(true)
                    .open(dir.join(format!("{}.meta.json", cache_key(url))))
                    .and_then(|file| file.set_modified(written))
                    .expect("modification time should be settable");
            }

            evict_oldest(&dir, 2).expect("eviction should succeed");

            assert!(read_cache(&dir, &urls[0]).is_none());
            assert!(read_cache(&dir, &urls[1]).is_none());
            assert!(read_cache(&dir, &urls[2]).is_some());
            assert!(read_cache(&dir, &urls[3]).is_some());
            assert!(!dir.join(format!("{}.yaml", cache_key(&urls[0]))).exists());

            fs::remove_dir_all(&dir).expect("cache directory should be removable");
        }
    }
}

/// Create a composite loader that chains: builtin -> file.
///
/// Reference dispatch:
/// - `builtin:*` or bare names matching a builtin -> builtin loader
/// - everything else -> filesystem loader
///
/// When the `http` feature is enabled, use
/// [`http::create_default_loader`] instead for HTTPS support.
pub fn create_composite_loader() -> impl Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>
{
    move |reference: &str, from: Option<&str>| -> Result<LoadedSpec, ResolveError> {
        if reference.starts_with("builtin:") {
            return match try_load_builtin(reference) {
                Some(result) => result,
                None => Err(ResolveError::NotFound {
                    reference: reference.to_string(),
                    message: "unknown builtin ruleset".to_string(),
                }),
            };
        }

        if reference.starts_with("https://") || reference.starts_with("http://") {
            return Err(ResolveError::Http {
                message: "HTTP-based policy loading requires the 'http' feature".to_string(),
            });
        }

        if !reference.contains('/')
            && !reference.contains('\\')
            && !reference.contains('.')
            && let Some(result) = try_load_builtin(reference)
        {
            return result;
        }

        load_from_filesystem(reference, from)
    }
}

/// Resolve a parsed spec using a caller-provided loader, with no
/// verification (see [`resolve_with_options`] for verify-on-load).
pub fn resolve_with_loader<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
{
    resolve_with_options(spec, source, loader, &ResolveOptions::default()).map(|r| r.spec)
}

pub fn resolve_from_path(path: impl AsRef<Path>) -> Result<HushSpec, ResolveError> {
    let path = canonical_path(path.as_ref())?;
    let spec = load_spec_from_file(&path)?;
    resolve_with_loader(&spec, Some(&path.to_string_lossy()), &load_from_filesystem)
}

/// Resolve a HushSpec document using the composite loader (builtin + file).
///
/// This supports `extends: builtin:default` in addition to filesystem paths.
pub fn resolve_from_path_with_builtins(path: impl AsRef<Path>) -> Result<HushSpec, ResolveError> {
    resolve_path_with_options(path, &ResolveOptions::default()).map(|r| r.spec)
}

/// Resolve the policy file at `path` with the composite loader and full
/// provenance: chain links, content hash, and verification outcome.
///
/// # Errors
///
/// As [`resolve_with_options`], plus [`ResolveError::Read`] and
/// [`ResolveError::Parse`] for the leaf file itself.
pub fn resolve_path_with_options(
    path: impl AsRef<Path>,
    options: &ResolveOptions,
) -> Result<Resolution, ResolveError> {
    let path = canonical_path(path.as_ref())?;
    let spec = load_spec_from_file(&path)?;
    let loader = create_composite_loader();
    resolve_with_options(&spec, Some(&path.to_string_lossy()), &loader, options)
}

fn load_from_filesystem(reference: &str, from: Option<&str>) -> Result<LoadedSpec, ResolveError> {
    let path = resolve_reference_path(reference, from);
    let canonical = canonical_path(&path)?;
    let spec = load_spec_from_file(&canonical)?;
    Ok(LoadedSpec {
        source: canonical.to_string_lossy().into_owned(),
        spec,
    })
}

fn resolve_reference_path(reference: &str, from: Option<&str>) -> PathBuf {
    let candidate = PathBuf::from(reference);
    if candidate.is_absolute() {
        return candidate;
    }

    match from
        .map(PathBuf::from)
        .and_then(|path| path.parent().map(Path::to_path_buf))
    {
        Some(parent) => parent.join(candidate),
        None => candidate,
    }
}

fn canonical_path(path: &Path) -> Result<PathBuf, ResolveError> {
    fs::canonicalize(path).map_err(|error| ResolveError::Read {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn load_spec_from_file(path: &Path) -> Result<HushSpec, ResolveError> {
    let content = fs::read_to_string(path).map_err(|error| ResolveError::Read {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    HushSpec::parse(&content).map_err(|error| ResolveError::Parse {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_loader_resolves_all_rulesets() {
        for name in BUILTIN_NAMES {
            let yaml = load_builtin(name);
            assert!(yaml.is_some(), "builtin '{name}' should exist");
            let spec = HushSpec::parse(yaml.unwrap());
            assert!(spec.is_ok(), "builtin '{name}' should parse: {spec:?}");
        }
    }

    #[test]
    fn builtin_loader_with_prefix() {
        for name in BUILTIN_NAMES {
            let prefixed = format!("builtin:{name}");
            let yaml = load_builtin(&prefixed);
            assert!(yaml.is_some(), "builtin '{prefixed}' should exist");
        }
    }

    #[test]
    fn builtin_loader_returns_none_for_unknown() {
        assert!(load_builtin("nonexistent").is_none());
        assert!(load_builtin("builtin:nonexistent").is_none());
    }

    #[test]
    fn try_load_builtin_returns_loaded_spec() {
        let result = try_load_builtin("builtin:default");
        assert!(result.is_some());
        let loaded = result.unwrap().unwrap();
        assert_eq!(loaded.source, "builtin:default");
        assert_eq!(loaded.spec.name.as_deref(), Some("default"));
    }

    #[test]
    fn try_load_builtin_bare_name() {
        let result = try_load_builtin("strict");
        assert!(result.is_some());
        let loaded = result.unwrap().unwrap();
        assert_eq!(loaded.source, "builtin:strict");
        assert_eq!(loaded.spec.name.as_deref(), Some("strict"));
    }

    #[test]
    fn composite_loader_resolves_builtins() {
        let loader = create_composite_loader();
        let loaded = loader("builtin:default", None).unwrap();
        assert_eq!(loaded.source, "builtin:default");
        assert_eq!(loaded.spec.name.as_deref(), Some("default"));
    }

    #[test]
    fn composite_loader_resolves_bare_builtin_names() {
        let loader = create_composite_loader();
        // "default" has no dots, slashes, or backslashes, so should be
        // tried as a builtin first.
        let loaded = loader("default", None).unwrap();
        assert_eq!(loaded.source, "builtin:default");
    }

    #[test]
    fn extends_builtin_default_end_to_end() {
        let child = HushSpec::parse(
            r#"
hushspec: "0.1.0"
extends: builtin:default
name: my-policy
rules:
  egress:
    allow: [custom.example.com]
    default: allow
"#,
        )
        .unwrap();

        let loader = create_composite_loader();
        let resolved = resolve_with_loader(&child, Some("memory://child"), &loader).unwrap();

        assert!(resolved.extends.is_none());
        assert_eq!(resolved.name.as_deref(), Some("my-policy"));
        let rules = resolved.rules.as_ref().unwrap();
        assert!(rules.forbidden_paths.is_some());
        let egress = rules.egress.as_ref().unwrap();
        assert!(egress.allow.contains(&"custom.example.com".to_string()));
    }

    #[test]
    fn composite_loader_rejects_http_without_feature() {
        let loader = create_composite_loader();
        let result = loader("https://example.com/policy.yaml", None);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("http") || msg.contains("HTTP"));
    }

    // ---- S2: extends chain depth cap ----

    /// An in-memory spec that optionally extends `parent`.
    fn chain_spec(extends: Option<&str>) -> HushSpec {
        let yaml = match extends {
            Some(parent) => format!("hushspec: \"0.1.0\"\nextends: \"{parent}\"\nname: n\n"),
            None => "hushspec: \"0.1.0\"\nname: n\n".to_string(),
        };
        HushSpec::parse(&yaml).expect("chain spec parses")
    }

    /// Map `spec_0..spec_{len-1}` where each extends the next; `spec_{len-1}` is the leaf.
    fn chain_specs(len: usize) -> std::collections::HashMap<String, HushSpec> {
        let mut specs = std::collections::HashMap::new();
        for i in 0..len {
            let parent = (i + 1 < len).then(|| format!("spec_{}", i + 1));
            specs.insert(format!("spec_{i}"), chain_spec(parent.as_deref()));
        }
        specs
    }

    /// A loader that resolves references against an in-memory spec map.
    fn map_loader(
        specs: std::collections::HashMap<String, HushSpec>,
    ) -> impl Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError> {
        move |reference: &str, _from: Option<&str>| {
            specs
                .get(reference)
                .cloned()
                .map(|spec| LoadedSpec {
                    source: reference.to_string(),
                    spec,
                })
                .ok_or_else(|| ResolveError::NotFound {
                    reference: reference.to_string(),
                    message: "not in test map".to_string(),
                })
        }
    }

    #[test]
    fn extends_chain_depth_cap_rejects_deep_chain() {
        let specs = chain_specs(40);
        let root = specs["spec_0"].clone();
        let loader = map_loader(specs);
        let err = resolve_with_loader(&root, Some("spec_0"), &loader)
            .expect_err("40-deep chain must fail closed, not overflow the stack");
        assert!(
            matches!(err, ResolveError::MaxDepth),
            "expected MaxDepth, got {err:?}"
        );
        assert_eq!(err.to_string(), "extends chain exceeds maximum depth of 32");
    }

    #[test]
    fn extends_chain_depth_three_still_resolves() {
        let specs = chain_specs(3);
        let root = specs["spec_0"].clone();
        let loader = map_loader(specs);
        let resolved = resolve_with_loader(&root, Some("spec_0"), &loader)
            .expect("3-deep chain resolves cleanly");
        assert!(resolved.extends.is_none());
    }
}
