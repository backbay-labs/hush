"""HTTPS ``extends`` loading (:mod:`hushspec.http_loader`).

Two halves, because they need different things to be true.

The URL and address checks are pure: every rule the loader enforces before it
opens a socket is exercised directly, with no server involved. That is where
the SSRF surface actually lives -- the loopback, private, link-local, CGNAT,
multicast, unspecified and IPv4-in-IPv6 forms, the scheme check, the allowlist.

The fetch, revalidation and size-cap paths need a server, and
:mod:`http.server` over TLS needs a certificate authority a test client trusts.
Rather than mint one, these tests use the loader's documented test-only
``allow_insecure_loopback`` escape hatch against ``http://127.0.0.1``. That the
escape hatch is *needed* -- that the loader refuses plain ``http`` and loopback
without it -- is itself asserted below.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from typing import Iterator, Optional

import pytest

from hushspec.http_loader import (
    BLOCKED_NETWORKS,
    CLOUD_METADATA_ADDRESSES,
    DEFAULT_MAX_SIZE,
    EtagCache,
    HttpLoaderConfig,
    HttpLoadError,
    create_default_loader,
    create_http_loader,
    fetch_signature,
    install_https_loader,
    is_blocked_address,
    validate_url,
)
from hushspec.canonical import content_hash
from hushspec.parse import parse_or_raise
from hushspec.provider import HttpProvider, PolicyProvider
from hushspec.resolve import (
    ResolveRejected,
    create_composite_loader,
    default_signature_locator,
    resolve_with_options_or_raise,
    unregister_scheme_loader,
)

POLICY = 'hushspec: "0.2.0"\nname: remote-base\n'
EXTENDS_BUILTIN = 'hushspec: "0.2.0"\nname: remote-leaf\nextends: "builtin:strict"\n'
EXTENDS_REMOTE = (
    'hushspec: "0.2.0"\nname: remote-leaf\n'
    'extends: "https://policies.invalid/other.yaml"\n'
)
SIGNATURE = '{"format_version": "0.2"}'


# --------------------------------------------------------------------------- #
# Address classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.1.2.3",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.1.1",
        "169.254.169.254",  # the cloud metadata endpoint
        "100.64.0.1",  # carrier-grade NAT
        "100.127.255.255",
        "224.0.0.1",  # multicast
        "239.255.255.250",
        "255.255.255.255",  # broadcast
        "::",
        "::1",
        "fc00::1",
        "fd00::1",
        "fd00:ec2::254",  # the IPv6 metadata endpoint
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:10.0.0.1",
        "::ffff:7f00:1",  # the same, in hextet form
        "::7f00:1",  # deprecated IPv4-compatible loopback
        "::a9fe:a9fe",  # IPv4-compatible cloud metadata
        "fe80::1%eth0",  # a zone id never makes an address reachable
    ],
)
def test_blocked_addresses(address: str) -> None:
    assert is_blocked_address(address), f"{address} must not be reachable"


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "172.32.0.1", "11.0.0.1"],
)
def test_public_addresses_are_allowed(address: str) -> None:
    assert not is_blocked_address(address)


def test_an_unparseable_address_is_blocked() -> None:
    # A resolver that cannot tell what it is about to connect to does not
    # connect.
    assert is_blocked_address("not-an-address")
    assert is_blocked_address("")


def test_the_cloud_metadata_endpoints_are_inside_the_blocked_networks() -> None:
    for address in CLOUD_METADATA_ADDRESSES:
        assert is_blocked_address(address)
    assert BLOCKED_NETWORKS, "the blocked set must not be empty"


# --------------------------------------------------------------------------- #
# URL validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/policy.yaml",
        "ftp://example.com/policy.yaml",
        "file:///etc/passwd",
        "gopher://example.com/policy.yaml",
    ],
)
def test_only_https_is_accepted(url: str) -> None:
    with pytest.raises(HttpLoadError, match="only HTTPS URLs are allowed"):
        validate_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/policy.yaml",
        "https://10.0.0.1/policy.yaml",
        "https://172.16.0.1/policy.yaml",
        "https://192.168.1.1/policy.yaml",
        "https://169.254.169.254/latest/meta-data/",
        "https://100.64.0.1/policy.yaml",
        "https://[::1]/policy.yaml",
        "https://[fc00::1]/policy.yaml",
        "https://[fe80::1]/policy.yaml",
        "https://[::ffff:127.0.0.1]/policy.yaml",
    ],
)
def test_ssrf_targets_are_refused(url: str) -> None:
    with pytest.raises(HttpLoadError, match="SSRF protection"):
        validate_url(url)


def test_a_url_with_no_host_is_refused() -> None:
    with pytest.raises(HttpLoadError, match="has no host"):
        validate_url("https:///policy.yaml")


def test_an_unresolvable_host_is_refused() -> None:
    with pytest.raises(HttpLoadError, match="failed to resolve host"):
        validate_url("https://this-host-does-not-exist.invalid/policy.yaml")


def test_the_allowlist_is_checked_before_dns() -> None:
    config = HttpLoaderConfig(allowed_hosts=("policies.example.com",))
    # The host does not resolve, so a refusal naming the allowlist proves the
    # allowlist ran first.
    with pytest.raises(HttpLoadError, match="is not in the allowlist"):
        validate_url("https://elsewhere.invalid/policy.yaml", config)


def test_the_allowlist_is_case_insensitive_and_exact() -> None:
    config = HttpLoaderConfig(allowed_hosts=("Policies.INVALID",))
    # A suffix is not a match: `evil-policies.invalid` is a different host.
    with pytest.raises(HttpLoadError, match="is not in the allowlist"):
        validate_url("https://evil-policies.invalid/policy.yaml", config)
    # The allowed host passes the allowlist whatever its case, and then fails
    # on DNS instead -- which is the proof that the allowlist let it through.
    with pytest.raises(HttpLoadError, match="failed to resolve host"):
        validate_url("https://policies.invalid/policy.yaml", config)


def test_loopback_needs_the_test_only_option() -> None:
    insecure = "http://127.0.0.1:1/policy.yaml"
    with pytest.raises(HttpLoadError, match="only HTTPS URLs are allowed"):
        validate_url(insecure)
    # With the escape hatch the scheme and the loopback address are both
    # permitted -- and nothing else is.
    target = validate_url(insecure, HttpLoaderConfig(allow_insecure_loopback=True))
    assert target.host == "127.0.0.1"


def test_the_loopback_escape_hatch_does_not_open_other_private_addresses() -> None:
    config = HttpLoaderConfig(allow_insecure_loopback=True)
    with pytest.raises(HttpLoadError, match="SSRF protection"):
        validate_url("http://10.0.0.1/policy.yaml", config)
    with pytest.raises(HttpLoadError, match="SSRF protection"):
        validate_url("http://169.254.169.254/latest/meta-data/", config)


def test_the_validated_target_pins_the_address_the_request_will_dial() -> None:
    target = validate_url(
        "http://127.0.0.1:8443/policy.yaml", HttpLoaderConfig(allow_insecure_loopback=True)
    )
    # The request connects to this address, not to a second DNS answer: that is
    # what closes the rebinding window between the check and the connect.
    assert target.address == "127.0.0.1"
    assert target.port == 8443


# --------------------------------------------------------------------------- #
# Fetching, against a loopback server
# --------------------------------------------------------------------------- #


class _Server:
    """A loopback HTTP server serving one policy, its sidecar, and edge cases."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        self.conditional: list[Optional[str]] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: object) -> None:  # noqa: D102
                pass

            def _send(self, status: int, body: bytes = b"", **headers: str) -> None:
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name.replace("_", "-"), value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                outer.requests.append(self.path)
                if self.path == "/base.yaml":
                    conditional = self.headers.get("If-None-Match")
                    outer.conditional.append(conditional)
                    if conditional == '"v1"':
                        self.send_response(304)
                        self.send_header("ETag", '"v1"')
                        self.end_headers()
                        return
                    self._send(200, POLICY.encode(), ETag='"v1"')
                elif self.path == "/extends-builtin.yaml":
                    self._send(200, EXTENDS_BUILTIN.encode())
                elif self.path == "/extends-remote.yaml":
                    self._send(200, EXTENDS_REMOTE.encode())
                elif self.path == "/base.yaml.sig":
                    self._send(200, SIGNATURE.encode())
                elif self.path == "/oversized.yaml":
                    self._send(200, b"x" * (DEFAULT_MAX_SIZE + 10))
                elif self.path == "/redirect.yaml":
                    self._send(302, Location=f"{outer.base}/base.yaml")
                elif self.path == "/broken.yaml":
                    self._send(200, b"hushspec: [unclosed\n")
                elif self.path == "/error.yaml":
                    self._send(503)
                elif self.path == "/authed.yaml":
                    if self.headers.get("Authorization") != "Bearer token":
                        self._send(401)
                    else:
                        self._send(200, POLICY.encode())
                else:
                    self._send(404)

        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def server() -> Iterator[_Server]:
    running = _Server()
    try:
        yield running
    finally:
        running.stop()


@pytest.fixture
def config() -> HttpLoaderConfig:
    return HttpLoaderConfig(allow_insecure_loopback=True)


def test_fetches_and_parses_a_policy(server: _Server, config: HttpLoaderConfig) -> None:
    loaded = create_http_loader(config)(f"{server.base}/base.yaml")
    assert loaded.spec.name == "remote-base"
    # The source is the URL, so a detached signature is looked for beside it
    # and a receipt's chain names where the document came from.
    assert loaded.source == f"{server.base}/base.yaml"


def test_revalidates_with_if_none_match(server: _Server, config: HttpLoaderConfig) -> None:
    loader = create_http_loader(config)
    url = f"{server.base}/base.yaml"
    assert loader(url).spec.name == "remote-base"
    assert loader(url).spec.name == "remote-base"
    # The server is always asked -- a changed policy is always refetched -- but
    # the second ask carries the etag and comes back 304 with no body.
    assert server.conditional == [None, '"v1"']


def test_a_separate_cache_does_not_revalidate(server: _Server) -> None:
    url = f"{server.base}/base.yaml"
    create_http_loader(HttpLoaderConfig(allow_insecure_loopback=True))(url)
    create_http_loader(HttpLoaderConfig(allow_insecure_loopback=True))(url)
    assert server.conditional == [None, None]


def test_a_shared_cache_is_shared(server: _Server) -> None:
    cache = EtagCache()
    url = f"{server.base}/base.yaml"
    for _ in range(2):
        create_http_loader(
            HttpLoaderConfig(allow_insecure_loopback=True, cache=cache)
        )(url)
    assert server.conditional == [None, '"v1"']
    cache.clear()
    create_http_loader(HttpLoaderConfig(allow_insecure_loopback=True, cache=cache))(url)
    assert server.conditional[-1] is None


def test_an_oversized_body_is_refused(server: _Server, config: HttpLoaderConfig) -> None:
    with pytest.raises(HttpLoadError, match="exceeds maximum size"):
        create_http_loader(config)(f"{server.base}/oversized.yaml")


def test_the_size_cap_is_configurable(server: _Server) -> None:
    small = HttpLoaderConfig(allow_insecure_loopback=True, max_size=4)
    with pytest.raises(HttpLoadError, match="exceeds maximum size of 4 bytes"):
        create_http_loader(small)(f"{server.base}/base.yaml")


def test_a_redirect_is_refused(server: _Server, config: HttpLoaderConfig) -> None:
    # A 3xx would reissue the request somewhere the scheme, allowlist and
    # address checks never saw.
    with pytest.raises(HttpLoadError, match="redirects are not followed"):
        create_http_loader(config)(f"{server.base}/redirect.yaml")


def test_an_error_status_is_reported(server: _Server, config: HttpLoaderConfig) -> None:
    with pytest.raises(HttpLoadError, match="returned status 503"):
        create_http_loader(config)(f"{server.base}/error.yaml")


def test_a_missing_policy_is_an_error(server: _Server, config: HttpLoaderConfig) -> None:
    with pytest.raises(HttpLoadError, match="returned status 404"):
        create_http_loader(config)(f"{server.base}/missing.yaml")


def test_an_unparseable_body_is_refused(server: _Server, config: HttpLoaderConfig) -> None:
    with pytest.raises(HttpLoadError, match="failed to parse HushSpec"):
        create_http_loader(config)(f"{server.base}/broken.yaml")


def test_the_auth_header_is_sent(server: _Server) -> None:
    unauthenticated = HttpLoaderConfig(allow_insecure_loopback=True)
    with pytest.raises(HttpLoadError, match="returned status 401"):
        create_http_loader(unauthenticated)(f"{server.base}/authed.yaml")
    authenticated = HttpLoaderConfig(
        allow_insecure_loopback=True, auth_header="Bearer token"
    )
    assert create_http_loader(authenticated)(f"{server.base}/authed.yaml").spec.name


# --------------------------------------------------------------------------- #
# Detached signatures (signing spec 7.1)
# --------------------------------------------------------------------------- #


def test_fetches_the_sidecar_signature(server: _Server, config: HttpLoaderConfig) -> None:
    assert fetch_signature(f"{server.base}/base.yaml.sig", config) == SIGNATURE.encode()


def test_a_missing_signature_is_none_not_an_error(
    server: _Server, config: HttpLoaderConfig
) -> None:
    # "This policy is unsigned" is a fact the caller decides what to do with.
    assert fetch_signature(f"{server.base}/absent.yaml.sig", config) is None


def test_a_failing_signature_fetch_still_raises(
    server: _Server, config: HttpLoaderConfig
) -> None:
    # A 503 says nothing about whether a signature exists, so it is not "none".
    with pytest.raises(HttpLoadError, match="returned status 503"):
        fetch_signature(f"{server.base}/error.yaml", config)


def test_a_signature_url_obeys_the_same_rules() -> None:
    # A `.sig` URL must never reach somewhere the policy URL could not.
    with pytest.raises(HttpLoadError, match="SSRF protection"):
        fetch_signature("https://169.254.169.254/policy.yaml.sig")
    with pytest.raises(HttpLoadError, match="only HTTPS URLs are allowed"):
        fetch_signature("http://example.com/policy.yaml.sig")


# --------------------------------------------------------------------------- #
# Registering the scheme with the resolver
# --------------------------------------------------------------------------- #


def test_the_default_loader_refuses_urls_until_a_scheme_is_installed() -> None:
    with pytest.raises(ValueError, match="install_https_loader"):
        create_composite_loader()("https://policies.example.com/base.yaml", None)


def test_installing_the_scheme_teaches_the_default_loader(server: _Server) -> None:
    config = HttpLoaderConfig(allow_insecure_loopback=True)
    install_https_loader(config)
    try:
        url = f"{server.base}/base.yaml"
        assert create_composite_loader()(url, None).spec.name == "remote-base"
        # And the default signature locator now finds `<url>.sig`.
        assert default_signature_locator(url) == SIGNATURE.encode()
        assert default_signature_locator(f"{server.base}/absent.yaml") is None
    finally:
        unregister_scheme_loader("https")
        unregister_scheme_loader("http")

    with pytest.raises(ValueError, match="install_https_loader"):
        create_composite_loader()(f"{server.base}/base.yaml", None)


def test_the_default_loader_still_serves_builtins_and_files(server: _Server) -> None:
    loader = create_default_loader(HttpLoaderConfig(allow_insecure_loopback=True))
    assert loader("builtin:strict", None).source == "builtin:strict"
    assert loader(f"{server.base}/base.yaml", None).spec.name == "remote-base"


def test_a_builtin_source_never_looks_for_a_remote_signature() -> None:
    install_https_loader(HttpLoaderConfig(allow_insecure_loopback=True))
    try:
        assert default_signature_locator("builtin:strict") is None
        assert default_signature_locator("memory") is None
    finally:
        unregister_scheme_loader("https")
        unregister_scheme_loader("http")


# --------------------------------------------------------------------------- #
# HttpProvider
# --------------------------------------------------------------------------- #


def test_http_provider_loads_and_names_its_source(
    server: _Server, config: HttpLoaderConfig
) -> None:
    provider = HttpProvider(f"{server.base}/base.yaml", config=config)
    resolution = provider.load()
    assert resolution.spec.name == "remote-base"
    assert provider.source == f"{server.base}/base.yaml"
    assert [link.source for link in resolution.chain] == [provider.source]
    assert resolution.content_hash == content_hash(resolution.spec)


def test_http_provider_refetches_on_every_load(
    server: _Server, config: HttpLoaderConfig
) -> None:
    provider = HttpProvider(f"{server.base}/base.yaml", config=config)
    provider.load()
    provider.load()
    # Always ask; the etag means the second ask costs no body.
    assert server.conditional == [None, '"v1"']


def test_http_provider_resolves_a_builtin_base(
    server: _Server, config: HttpLoaderConfig
) -> None:
    resolution = HttpProvider(f"{server.base}/extends-builtin.yaml", config=config).load()
    assert resolution.spec.extends is None
    assert [link.source for link in resolution.chain] == [
        "builtin:strict",
        f"{server.base}/extends-builtin.yaml",
    ]


def test_http_provider_refuses_a_remote_base(
    server: _Server, config: HttpLoaderConfig
) -> None:
    # A base named from a document that itself came over the network is a
    # second location the deployment never named: fail closed.
    provider = HttpProvider(f"{server.base}/extends-remote.yaml", config=config)
    with pytest.raises(ValueError, match="failed to resolve 'extends:"):
        provider.load()


def test_http_provider_carries_the_ssrf_rules(config: HttpLoaderConfig) -> None:
    with pytest.raises(HttpLoadError, match="SSRF protection"):
        HttpProvider("http://169.254.169.254/policy.yaml", config=config).load()
    with pytest.raises(HttpLoadError, match="only HTTPS URLs are allowed"):
        HttpProvider("http://example.com/policy.yaml").load()


def test_http_provider_satisfies_the_provider_protocol(
    server: _Server, config: HttpLoaderConfig
) -> None:
    provider = HttpProvider(f"{server.base}/base.yaml", config=config)
    assert isinstance(provider, PolicyProvider)


# --------------------------------------------------------------------------- #
# Digest pinning over the network (core spec 2.3)
# --------------------------------------------------------------------------- #
#
# A URL is a location, never an identity. What makes a remote base trustworthy
# is the `#sha256:` pin on the reference, which the resolver strips before the
# loader sees it and checks against what came back -- so pinning has to work
# over HTTPS exactly as it does for a file, with no help from the loader.


def _pinned_leaf(url: str, digest: str) -> object:
    return parse_or_raise(
        f'hushspec: "0.2.0"\nname: pinned-leaf\nextends: "{url}#{digest}"\n'
    )


def test_a_matching_digest_pin_resolves(server: _Server, config: HttpLoaderConfig) -> None:
    url = f"{server.base}/base.yaml"
    loader = create_http_loader(config)
    base = loader(url).spec
    resolution = resolve_with_options_or_raise(
        _pinned_leaf(url, f"sha256:{content_hash(base)[len('sha256:'):]}"),
        source="memory",
        loader=loader,
    )
    assert resolution.chain[0].source == url
    assert resolution.spec.name == "pinned-leaf"


def test_a_mismatched_digest_pin_is_fatal(server: _Server, config: HttpLoaderConfig) -> None:
    url = f"{server.base}/base.yaml"
    with pytest.raises(ResolveRejected) as excinfo:
        resolve_with_options_or_raise(
            _pinned_leaf(url, "sha256:" + "0" * 64),
            source="memory",
            loader=create_http_loader(config),
        )
    assert excinfo.value.code == "digest_mismatch"
