//! Integration tests for the `http` feature's `extends: https://...` loader
//! (`crates/hushspec/src/resolve.rs`, `pub mod http`), covering the rules of
//! core spec 2.6.4 that can be checked without a server.
//!
//! What this file does NOT cover, and why: the loader refuses any URL whose
//! host resolves to a blocked address *before* it opens a socket -- see the
//! assertions below, which exercise exactly that refusal through the public
//! API. `HttpLoaderConfig` has no escape hatch that would permit a blocked
//! address, so a `std::net::TcpListener` bound to `127.0.0.1` (the only kind of
//! address a same-host test listener can bind to without root or
//! network-namespace tricks) is unreachable from `load_from_https`. Adding one
//! would weaken the address check for every caller, so the transport paths that
//! need a reachable server -- the cached body returned on a 304, the size cap,
//! a non-2xx becoming an error -- are covered by the unit tests in
//! `resolve::http` and by the conformance fixtures instead.
//!
//! Everything here runs offline: IP literals never reach a resolver, and the
//! allowlist is checked before DNS.

#![cfg(feature = "http")]

use hushspec::resolve::ResolveError;
use hushspec::resolve::http::{
    CLOUD_METADATA_ADDRESSES, DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_MAX_SIZE,
    DEFAULT_READ_TIMEOUT_MS, HttpLoaderConfig, create_default_loader, is_blocked_address,
    load_from_https, signature_locator, validate_url,
};

// --- HttpLoaderConfig: config validation ---

#[test]
fn http_loader_config_default_values() {
    let config = HttpLoaderConfig::default();
    assert_eq!(config.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
    assert_eq!(config.read_timeout_ms, DEFAULT_READ_TIMEOUT_MS);
    assert_eq!(config.max_size, DEFAULT_MAX_SIZE, "the cap is 1 MiB");
    assert!(config.verify_tls, "TLS verification must default to on");
    assert!(config.auth_header.is_none());
    assert!(
        config.allowed_hosts.is_none(),
        "no allowlist means every host that clears the address check"
    );
    assert!(config.cache_dir.is_none());
}

// --- Address classification (core spec 2.6.4) ---

#[test]
fn every_blocked_family_is_unreachable() {
    for text in [
        "0.0.0.0",
        "0.1.2.3",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.1",
        "192.168.1.1",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::7f00:1",
        "::a9fe:a9fe",
    ] {
        let address = text.parse().expect("test address should parse");
        assert!(is_blocked_address(&address), "{text} must not be reachable");
    }
}

#[test]
fn cloud_metadata_endpoints_are_unreachable() {
    for text in CLOUD_METADATA_ADDRESSES {
        let address = text.parse().expect("test address should parse");
        assert!(
            is_blocked_address(&address),
            "the cloud metadata endpoint {text} is reachable"
        );
    }
}

#[test]
fn public_addresses_stay_reachable() {
    for text in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2606:4700:4700::1111"] {
        let address = text.parse().expect("test address should parse");
        assert!(!is_blocked_address(&address), "{text} must be reachable");
    }
}

// --- URL validation through the public loader (offline: IP literals and
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
                    // containers/CI) fail DNS resolution for a name that only
                    // has an IPv6 answer before the address check ever runs.
                    // Still fail-closed (Err either way), just for a different
                    // reason.
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
fn https_loader_rejects_carrier_grade_nat() {
    assert_rejected("https://100.64.0.1/policy.yaml");
}

#[test]
fn https_loader_rejects_link_local_ipv4() {
    // 169.254.169.254 is also the cloud metadata endpoint -- the canonical
    // server-side request forgery target.
    assert_rejected("https://169.254.169.254/latest/meta-data/");
}

#[test]
fn https_loader_rejects_multicast_and_reserved() {
    assert_rejected("https://224.0.0.1/policy.yaml");
    assert_rejected("https://240.0.0.1/policy.yaml");
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
fn https_loader_rejects_ipv4_mapped_loopback() {
    // The mapped form is unwrapped and judged on the address inside.
    assert_rejected("https://[::ffff:127.0.0.1]/policy.yaml");
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
    assert_rejected("not a url");
}

#[test]
fn https_loader_rejects_url_with_no_host() {
    // `https:///policy.yaml` parses but yields an empty host.
    assert_rejected("https:///policy.yaml");
}

// --- Allowlist and pinning ---

#[test]
fn allowlist_refuses_an_unlisted_host_before_dns() {
    let config = HttpLoaderConfig {
        allowed_hosts: Some(vec!["policies.example.com".to_string()]),
        ..HttpLoaderConfig::default()
    };
    // `.invalid` never resolves, so a lookup would fail with a different
    // message; the allowlist refusal is what must come back.
    let message = load_from_https("https://elsewhere.invalid/policy.yaml", &config)
        .expect_err("an unlisted host should be refused")
        .to_string();
    assert!(
        message.contains("is not in the allowlist"),
        "unexpected refusal: {message}"
    );
}

#[test]
fn allowlist_matches_case_insensitively() {
    let config = HttpLoaderConfig {
        allowed_hosts: Some(vec!["8.8.8.8".to_string()]),
        ..HttpLoaderConfig::default()
    };
    // A listed host passes the allowlist and goes on to the address check; the
    // point is that it is not refused *by the allowlist*.
    let target = validate_url("https://8.8.8.8/policy.yaml", &config)
        .expect("a listed public host should pass every check");
    assert_eq!(target.host, "8.8.8.8");
}

#[test]
fn the_checked_address_is_the_one_carried_forward() {
    let config = HttpLoaderConfig::default();
    let target = validate_url("https://8.8.8.8:8443/policy.yaml", &config)
        .expect("a public literal should pass");
    assert_eq!(
        target.address,
        "8.8.8.8:8443".parse().expect("socket address should parse"),
        "the connection is pinned to the address that was checked"
    );
    assert_eq!(
        target.host, "8.8.8.8",
        "the host is kept for SNI, certificate validation and the Host header"
    );
}

// --- Signature sidecars (signing spec 7.1) ---

#[test]
fn signature_locator_refuses_a_blocked_sidecar_url() {
    let locate = signature_locator(HttpLoaderConfig::default());
    let message = locate("https://127.0.0.1/policy.yaml")
        .expect_err("a sidecar must not reach where the policy could not")
        .to_string();
    assert!(message.contains("SSRF protection"), "{message}");
}

#[test]
fn signature_locator_leaves_non_url_sources_alone() {
    let locate = signature_locator(HttpLoaderConfig::default());
    assert!(
        locate("policy.yaml")
            .expect("a path is not this locator's to find")
            .is_none()
    );
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
