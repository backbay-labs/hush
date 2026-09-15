//! Integration tests for the `http` feature's `extends: https://...` loader
//! (`crates/hushspec/src/resolve.rs`, `pub mod http`).
//!
//! What this file does NOT cover, and why: the loader's SSRF guard
//! (`validate_url`) rejects any URL whose host resolves to a private,
//! loopback, link-local, or unspecified IP address *before* an HTTP request
//! is ever sent -- see the assertions below, which exercise exactly that
//! rejection through the public API. `HttpLoaderConfig` has no
//! `allow_private` (or equivalent) escape hatch, and `validate_url` /
//! `is_private_ip` / `cache_key` / `read_cache` / `write_cache` are all
//! private to `resolve::http` (not `pub`), so an external integration test
//! cannot reach them directly either.
//!
//! Net effect: a `std::net::TcpListener` bound to `127.0.0.1` (or any other
//! loopback/private address, which is the only kind of address a same-host
//! test listener can bind to without root/network namespace tricks) is
//! unreachable from `load_from_https` -- `validate_url` fails closed on the
//! private-IP check before a connection is ever attempted. Per the work
//! order, the loader itself is not modified to add an escape hatch (that is
//! a product decision outside this task's scope, and doing so would weaken
//! the SSRF guard for every caller, not just tests). So this file covers
//! what the public API surface allows without a live server: SSRF/URL
//! rejection behavior (offline -- IP literals resolve locally, no network
//! access required) and `HttpLoaderConfig` default-value validation.
//!
//! ETag caching returning the cached body on 304, size-limit rejection,
//! non-2xx -> error, and content-hash-mismatch -> error all require a
//! reachable server and so are blocked by the above for the reasons stated.

#![cfg(feature = "http")]

use hushspec::resolve::ResolveError;
use hushspec::resolve::http::{HttpLoaderConfig, create_default_loader, load_from_https};

// --- HttpLoaderConfig: config validation ---

#[test]
fn http_loader_config_default_values() {
    let config = HttpLoaderConfig::default();
    assert_eq!(config.timeout_ms, 10_000);
    assert_eq!(
        config.max_size, 1_048_576,
        "default max size should be 1 MiB"
    );
    assert!(config.verify_tls, "TLS verification must default to on");
    assert!(config.auth_header.is_none());
    assert!(config.cache_dir.is_none());
}

#[test]
fn http_loader_config_is_independently_constructible() {
    // Every field is `pub`, so callers can override without a builder --
    // pin that surface since it's what embedding SDKs/CLIs rely on.
    let config = HttpLoaderConfig {
        timeout_ms: 500,
        max_size: 4096,
        verify_tls: false,
        auth_header: Some("Bearer abc".to_string()),
        cache_dir: Some(std::env::temp_dir()),
    };
    assert_eq!(config.timeout_ms, 500);
    assert_eq!(config.max_size, 4096);
    assert!(!config.verify_tls);
    assert_eq!(config.auth_header.as_deref(), Some("Bearer abc"));
    assert!(config.cache_dir.is_some());
}

// --- SSRF / URL validation via the public loader (offline: IP literals and
// `localhost` resolve locally, no outbound network access needed) ---

fn assert_rejected(url: &str) {
    let config = HttpLoaderConfig::default();
    let result = load_from_https(url, &config);
    assert!(result.is_err(), "expected '{url}' to be rejected, got Ok");
    match result.unwrap_err() {
        ResolveError::Http { message } => {
            assert!(
                message.contains("SSRF protection")
                    || message.contains("private IP")
                    || message.contains("only HTTPS URLs are allowed")
                    || message.contains("no host")
                    || message.contains("invalid URL")
                    // Environments without an IPv6 stack (common in
                    // containers/CI) fail DNS resolution for IPv6 literals
                    // before `is_private_ip` ever runs. Still fail-closed
                    // (Err either way), just for a different reason.
                    || message.contains("failed to resolve host"),
                "unexpected rejection message for '{url}': {message}"
            );
        }
        other => panic!("expected ResolveError::Http for '{url}', got {other:?}"),
    }
}

#[test]
fn https_loader_rejects_loopback_ipv4() {
    assert_rejected("https://127.0.0.1/policy.yaml");
}

#[test]
fn https_loader_rejects_localhost_hostname() {
    // "localhost" resolves via the local hosts database, not the network.
    assert_rejected("https://localhost/policy.yaml");
}

#[test]
fn https_loader_rejects_rfc1918_10_network() {
    assert_rejected("https://10.0.0.1/policy.yaml");
}

#[test]
fn https_loader_rejects_rfc1918_172_network() {
    assert_rejected("https://172.16.0.1/policy.yaml");
}

#[test]
fn https_loader_rejects_rfc1918_192_168_network() {
    assert_rejected("https://192.168.1.1/policy.yaml");
}

#[test]
fn https_loader_rejects_link_local_ipv4() {
    // 169.254.169.254 is also the AWS/GCP/Azure metadata endpoint -- the
    // canonical SSRF target.
    assert_rejected("https://169.254.169.254/policy.yaml");
}

#[test]
fn https_loader_rejects_ipv6_loopback() {
    assert_rejected("https://[::1]/policy.yaml");
}

#[test]
fn https_loader_rejects_ipv6_unique_local() {
    assert_rejected("https://[fc00::1]/policy.yaml");
}

#[test]
fn https_loader_rejects_ipv6_link_local() {
    assert_rejected("https://[fe80::1]/policy.yaml");
}

#[test]
fn https_loader_rejects_plain_http_scheme() {
    let config = HttpLoaderConfig::default();
    let result = load_from_https("http://example.com/policy.yaml", &config);
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(message.contains("only HTTPS URLs are allowed"));
}

#[test]
fn https_loader_rejects_malformed_url() {
    let config = HttpLoaderConfig::default();
    let result = load_from_https("not a url", &config);
    assert!(result.is_err());
}

#[test]
fn https_loader_rejects_url_with_no_host() {
    let config = HttpLoaderConfig::default();
    // `https:///policy.yaml` parses but yields an empty host.
    let result = load_from_https("https:///policy.yaml", &config);
    assert!(result.is_err());
}

// --- create_default_loader dispatch: same guard reached through the
// composite-loader entry point most callers actually use ---

#[test]
fn default_loader_rejects_private_ip_https_reference() {
    let loader = create_default_loader(HttpLoaderConfig::default());
    let result = loader("https://192.168.1.1/policy.yaml", None);
    assert!(result.is_err());
}

#[test]
fn default_loader_rejects_plain_http_reference() {
    let loader = create_default_loader(HttpLoaderConfig::default());
    let result = loader("http://example.com/policy.yaml", None);
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(message.contains("only HTTPS URLs are allowed"));
}

#[test]
fn default_loader_still_resolves_builtins_alongside_https_support() {
    // The `http` feature only adds a dispatch branch; builtin/file resolution
    // must be unaffected.
    let loader = create_default_loader(HttpLoaderConfig::default());
    let loaded = loader("builtin:default", None).expect("builtin should still resolve");
    assert_eq!(loaded.source, "builtin:default");
}
