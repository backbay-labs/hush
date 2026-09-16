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
    /// The merged document (`extends` consumed).
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
        Ok(Self {
            spec: spec.clone(),
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
        if required {
            return Err(ResolveError::SignatureRequired {
                document: source.to_string(),
                status: SignatureStatus::failed("signing_unavailable", None),
            });
        }
        Ok(None)
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
    let resolved = resolved.expect("at least the leaf");
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

#[cfg(feature = "http")]
pub mod http {
    use super::*;
    use std::io::Read as _;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[derive(Clone, Debug)]
    pub struct HttpLoaderConfig {
        pub timeout_ms: u64,
        pub max_size: usize,
        pub verify_tls: bool,
        pub auth_header: Option<String>,
        pub cache_dir: Option<PathBuf>,
    }

    impl Default for HttpLoaderConfig {
        fn default() -> Self {
            Self {
                timeout_ms: 10_000,
                max_size: 1_048_576, // 1 MB
                verify_tls: true,
                auth_header: None,
                cache_dir: None,
            }
        }
    }

    /// Extract the embedded IPv4 address from a deprecated IPv4-*compatible*
    /// IPv6 address (`::a.b.c.d`, i.e. all high 96 bits zero, low 32 bits the
    /// IPv4). Returns `None` for `::` and `::1` (handled elsewhere) and for the
    /// IPv4-*mapped* form (`::ffff:a.b.c.d`, where segment 5 is `0xffff`).
    fn ipv4_compatible(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
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

    fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()          // 127.0.0.0/8
                    || v4.is_private()     // 10/8, 172.16/12, 192.168/16
                    || v4.is_link_local()  // 169.254/16
                    || v4.is_unspecified() // 0.0.0.0
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()          // ::1
                    || v6.is_unspecified() // ::
                    || v6.is_unique_local() // fc00::/7
                    || v6.is_unicast_link_local() // fe80::/10
                    // IPv4-mapped addresses (::ffff:a.b.c.d)
                    || v6.to_ipv4_mapped().is_some_and(|v4| {
                        v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
                    })
                    // Deprecated IPv4-compatible addresses (::a.b.c.d)
                    || ipv4_compatible(v6).is_some_and(|v4| {
                        v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
                    })
            }
        }
    }

    /// SSRF protection: require HTTPS and reject private IPs.
    fn validate_url(url_str: &str) -> Result<url::Url, ResolveError> {
        let parsed = url::Url::parse(url_str).map_err(|e| ResolveError::Http {
            message: format!("invalid URL '{url_str}': {e}"),
        })?;

        if parsed.scheme() != "https" {
            return Err(ResolveError::Http {
                message: format!("only HTTPS URLs are allowed, got '{}'", parsed.scheme()),
            });
        }

        let host = parsed.host_str().ok_or_else(|| ResolveError::Http {
            message: format!("URL '{url_str}' has no host"),
        })?;

        let addrs: Vec<std::net::SocketAddr> =
            std::net::ToSocketAddrs::to_socket_addrs(&(host, 443))
                .map_err(|e| ResolveError::Http {
                    message: format!("failed to resolve host '{host}': {e}"),
                })?
                .collect();

        if addrs.is_empty() {
            return Err(ResolveError::Http {
                message: format!("host '{host}' did not resolve to any addresses"),
            });
        }

        for addr in &addrs {
            if is_private_ip(&addr.ip()) {
                return Err(ResolveError::Http {
                    message: format!(
                        "SSRF protection: host '{host}' resolves to private IP {}",
                        addr.ip()
                    ),
                });
            }
        }

        Ok(parsed)
    }

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
    ) -> Result<(), std::io::Error> {
        fs::create_dir_all(cache_dir)?;
        let key = cache_key(url);
        let entry = CacheEntry {
            etag: etag.to_string(),
            url: url.to_string(),
        };
        fs::write(
            cache_dir.join(format!("{key}.meta.json")),
            serde_json::to_string(&entry).unwrap(),
        )?;
        fs::write(cache_dir.join(format!("{key}.yaml")), body)?;
        Ok(())
    }

    /// Fetch a HushSpec document over HTTPS.
    ///
    /// Enforces HTTPS-only, SSRF protection, timeout, and max body size.
    /// Supports ETag-based caching when `config.cache_dir` is set.
    pub fn load_from_https(
        url_str: &str,
        config: &HttpLoaderConfig,
    ) -> Result<LoadedSpec, ResolveError> {
        let _validated_url = validate_url(url_str)?;

        let timeout = std::time::Duration::from_millis(config.timeout_ms);
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .map_err(|e| ResolveError::Http {
                message: format!("failed to build HTTP client: {e}"),
            })?;

        let mut request = client.get(url_str);

        if let Some(ref auth) = config.auth_header {
            request = request.header("Authorization", auth);
        }

        let cached = config
            .cache_dir
            .as_ref()
            .and_then(|dir| read_cache(dir, url_str));

        if let Some((ref etag, _)) = cached {
            request = request.header("If-None-Match", etag.as_str());
        }

        let response = request.send().map_err(|e| ResolveError::Http {
            message: format!("HTTP request to '{url_str}' failed: {e}"),
        })?;

        let status = response.status();

        if status == reqwest::StatusCode::NOT_MODIFIED
            && let Some((_, ref body)) = cached
        {
            let spec = HushSpec::parse(body).map_err(|e| ResolveError::Parse {
                path: url_str.to_string(),
                message: e.to_string(),
            })?;
            return Ok(LoadedSpec {
                source: url_str.to_string(),
                spec,
            });
        }

        if !status.is_success() {
            return Err(ResolveError::Http {
                message: format!("HTTP request to '{url_str}' returned status {status}"),
            });
        }

        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let mut body = Vec::new();
        let mut reader = response.take(config.max_size as u64 + 1);
        reader
            .read_to_end(&mut body)
            .map_err(|e| ResolveError::Http {
                message: format!("failed to read response from '{url_str}': {e}"),
            })?;

        if body.len() > config.max_size {
            return Err(ResolveError::Http {
                message: format!(
                    "response from '{url_str}' exceeds maximum size of {} bytes",
                    config.max_size
                ),
            });
        }

        let body_str = String::from_utf8(body).map_err(|e| ResolveError::Http {
            message: format!("response from '{url_str}' is not valid UTF-8: {e}"),
        })?;

        if let (Some(etag_val), Some(cache_dir)) = (&etag, &config.cache_dir) {
            let _ = write_cache(cache_dir, url_str, etag_val, &body_str);
        }

        let spec = HushSpec::parse(&body_str).map_err(|e| ResolveError::Parse {
            path: url_str.to_string(),
            message: e.to_string(),
        })?;

        Ok(LoadedSpec {
            source: url_str.to_string(),
            spec,
        })
    }

    /// Create a composite loader that chains: builtin -> file -> HTTPS.
    ///
    /// Reference dispatch:
    /// - `builtin:*` or bare names matching a builtin -> builtin loader
    /// - `https://` -> HTTP loader
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

        #[test]
        fn rejects_http_urls() {
            let result = validate_url("http://example.com/policy.yaml");
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("only HTTPS URLs are allowed"));
        }

        #[test]
        fn rejects_private_ips_localhost() {
            let result = validate_url("https://127.0.0.1/policy.yaml");
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("SSRF protection") || msg.contains("private IP"));
        }

        #[test]
        fn rejects_private_ips_10_network() {
            let result = validate_url("https://10.0.0.1/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_private_ips_172_network() {
            let result = validate_url("https://172.16.0.1/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_private_ips_192_168_network() {
            let result = validate_url("https://192.168.1.1/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv6_loopback() {
            let result = validate_url("https://[::1]/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv6_unique_local() {
            let result = validate_url("https://[fc00::1]/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv6_link_local() {
            let result = validate_url("https://[fe80::1]/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn accepts_valid_https_url() {
            // This test requires network access so we just validate the URL
            // parsing without actually connecting.
            let parsed = url::Url::parse("https://example.com/policy.yaml");
            assert!(parsed.is_ok());
            let url = parsed.unwrap();
            assert_eq!(url.scheme(), "https");
        }

        #[test]
        fn http_loader_rejects_plain_http() {
            let config = HttpLoaderConfig::default();
            let loader = create_default_loader(config);
            let result = loader("http://example.com/policy.yaml", None);
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("only HTTPS URLs are allowed"));
        }

        #[test]
        fn is_private_ip_checks() {
            use std::net::{Ipv4Addr, Ipv6Addr};

            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0xfc00, 0, 0, 0, 0, 0, 0, 1
            ))));
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0xfe80, 0, 0, 0, 0, 0, 0, 1
            ))));
            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));

            assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
            assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        }

        #[test]
        fn is_private_ip_ipv4_compatible() {
            // Deprecated IPv4-compatible form `::a.b.c.d` must be flagged when the
            // embedded IPv4 is private.
            // ::a9fe:a9fe -> 169.254.169.254 (link-local / cloud metadata)
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe
            ))));
            // ::7f00:1 -> 127.0.0.1 (loopback)
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0, 0x7f00, 0x0001
            ))));
            // ::0a00:1 -> 10.0.0.1 (private)
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0, 0x0a00, 0x0001
            ))));
            // IPv4-mapped form is still handled: ::ffff:127.0.0.1
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001
            ))));

            // A compatible form wrapping a PUBLIC IPv4 stays public.
            // ::0808:0808 -> 8.8.8.8
            assert!(!is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0, 0x0808, 0x0808
            ))));
            // A genuine public IPv6 stays public.
            assert!(!is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
            ))));
        }

        #[test]
        fn etag_cache_round_trip() {
            let dir = std::env::temp_dir().join(format!(
                "hushspec-cache-test-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));

            let url = "https://example.com/test-policy.yaml";
            let etag = "\"abc123\"";
            let body = "hushspec: \"0.1.0\"\nname: cached\n";

            write_cache(&dir, url, etag, body).unwrap();

            let (cached_etag, cached_body) = read_cache(&dir, url).unwrap();
            assert_eq!(cached_etag, etag);
            assert_eq!(cached_body, body);

            assert!(read_cache(&dir, "https://other.com/policy.yaml").is_none());

            fs::remove_dir_all(&dir).unwrap();
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
