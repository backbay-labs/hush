"""Loading an ``extends`` base over HTTPS.

A policy may name its base by URL (``extends: "https://policies.example/base.yaml"``,
core spec 2.3). Fetching one is a request an attacker partly controls -- the
URL comes out of a document -- so this loader is written to be the narrowest
thing that can still do the job:

* **HTTPS only.** ``http:`` is refused outright. A base fetched in the clear is
  a base anyone on the path can rewrite, and the resolver would merge it.
* **No redirects.** A 3xx is an error, not a hop to follow: a redirect is the
  server asking to move the request somewhere the SSRF checks never saw.
* **The address is checked, then pinned.** The host is resolved first and every
  address it resolves to is checked (:func:`is_blocked_address`); the request
  then connects to the address that was checked, with the original hostname
  still used for SNI, certificate validation and the ``Host`` header. A name
  that re-resolves to ``127.0.0.1`` between the check and the connect -- DNS
  rebinding -- reaches nothing.
* **Bounded.** A byte cap on the body, a connect timeout, and a read timeout.
* **Optionally allowlisted.** :attr:`HttpLoaderConfig.allowed_hosts` narrows
  the reachable hosts to a fixed set, which is what a deployment that knows its
  policy server should do.

Integrity is not this module's job and it does not pretend otherwise. A URL is
a location, never an identity: what makes a remote base trustworthy is the
``#sha256:`` digest pin on the reference (core spec 2.3) or a detached
signature, both enforced by :mod:`hushspec.resolve` around this loader. The pin
is stripped from the reference before the loader ever sees it and checked
against the document that comes back, so pinning works here exactly as it does
for a file. :func:`fetch_signature` supplies the other half, fetching
``<url>.sig`` under the same rules (signing spec 7.1).

Nothing registers itself on import. :func:`install_https_loader` installs the
``https:`` scheme into the resolver's default loaders; until it is called a URL
reference is refused, which is the fail-closed default.

Standard library only: :mod:`urllib.request` with a custom opener.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit

from hushspec.parse import parse
from hushspec.resolve import (
    LoadedSpec,
    Resolver,
    create_composite_loader,
    register_scheme_loader,
)

__all__ = [
    "DEFAULT_CONNECT_TIMEOUT_S",
    "DEFAULT_MAX_SIZE",
    "DEFAULT_READ_TIMEOUT_S",
    "BLOCKED_NETWORKS",
    "CLOUD_METADATA_ADDRESSES",
    "HttpLoaderConfig",
    "HttpLoadError",
    "EtagCache",
    "create_http_loader",
    "create_default_loader",
    "fetch_signature",
    "install_https_loader",
    "is_blocked_address",
    "signature_locator",
    "validate_url",
]

#: How long to wait for the TCP connection, in seconds.
DEFAULT_CONNECT_TIMEOUT_S = 10.0

#: How long to wait for response bytes once connected, in seconds.
DEFAULT_READ_TIMEOUT_S = 10.0

#: Largest response body accepted, in bytes. A policy is a small document; a
#: megabyte is already far beyond any real one, and the cap is what stops a
#: hostile server from feeding the resolver until it runs out of memory.
DEFAULT_MAX_SIZE = 1_048_576

#: The two well-known cloud instance-metadata endpoints, named so the intent is
#: readable even though :data:`BLOCKED_NETWORKS` already covers both
#: (``169.254.0.0/16`` and ``fc00::/7``). Reaching one from a URL an agent
#: supplied is the classic SSRF credential theft.
CLOUD_METADATA_ADDRESSES = ("169.254.169.254", "fd00:ec2::254")

#: Every network a policy URL may not resolve to. A host that resolves to any
#: of these is refused *after* DNS, because the danger is the address, not the
#: name: ``internal.example.com`` and a name that resolves to ``10.0.0.5`` are
#: the same request.
BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        # IPv4
        "0.0.0.0/8",  # "this network", and 0.0.0.0 itself
        "10.0.0.0/8",  # RFC 1918
        "100.64.0.0/10",  # RFC 6598 carrier-grade NAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, including cloud metadata
        "172.16.0.0/12",  # RFC 1918
        "192.0.0.0/24",  # IETF protocol assignments
        "192.168.0.0/16",  # RFC 1918
        "198.18.0.0/15",  # benchmarking
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, including 255.255.255.255 broadcast
        # IPv6
        "::/128",  # unspecified
        "::1/128",  # loopback
        "fc00::/7",  # unique local, including the IPv6 metadata endpoint
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
)


class HttpLoadError(ValueError):
    """A policy could not be fetched over HTTPS.

    Raised for every refusal this module makes -- a non-HTTPS URL, a blocked
    address, a redirect, an oversized body, a transport failure. The resolver
    turns it into a ``not_found`` rejection for the reference, as it does for
    any loader failure, so a base that cannot be fetched is never merged as if
    it said nothing.
    """


# --------------------------------------------------------------------------- #
# Address checks
# --------------------------------------------------------------------------- #


def is_blocked_address(ip: str) -> bool:
    """Whether *ip* is an address a policy URL may not reach.

    Blocks the unspecified address, loopback, RFC 1918 private ranges,
    link-local (which is where the cloud metadata endpoint lives), carrier-grade
    NAT, multicast, IPv6 unique-local, and the reserved ranges -- see
    :data:`BLOCKED_NETWORKS`.

    IPv6 forms that carry an IPv4 address in their low 32 bits are unwrapped
    first and judged on the address inside. Both the IPv4-*mapped* form
    (``::ffff:127.0.0.1``) and the deprecated IPv4-*compatible* form
    (``::7f00:1``, which is ``127.0.0.1``) would otherwise slip past a check
    that only looked at IPv6 ranges.

    An address that cannot be parsed is blocked: a resolver that cannot tell
    what it is about to connect to does not connect.
    """
    try:
        address: Any = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return True

    if isinstance(address, ipaddress.IPv6Address):
        embedded = address.ipv4_mapped or _ipv4_compatible(address)
        if embedded is not None:
            return is_blocked_address(str(embedded))

    return any(address in network for network in BLOCKED_NETWORKS)


def _ipv4_compatible(address: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """The IPv4 address inside a deprecated IPv4-compatible ``::a.b.c.d``.

    ``None`` for ``::`` and ``::1``, which the IPv6 rules already cover, and for
    the IPv4-mapped ``::ffff:`` form, which :attr:`~ipaddress.IPv6Address.ipv4_mapped`
    handles.
    """
    packed = int(address)
    if packed >> 32 != 0 or packed <= 1:
        return None
    return ipaddress.IPv4Address(packed & 0xFFFFFFFF)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


class EtagCache:
    """An in-memory ``ETag`` cache, keyed by URL (spec section 2.3 revalidation).

    A cached body is only ever returned on a ``304 Not Modified``, so the server
    is always asked. That keeps the loader honest -- a policy that changed is
    always refetched -- while a policy that did not change costs one conditional
    request instead of a full body.

    Entries live in memory for the life of the loader: nothing is written to
    disk, so a policy body never outlives the process that fetched it. The
    cache is **bounded**, and has to be: a URL comes out of a document, a body
    may be as large as :data:`DEFAULT_MAX_SIZE`, and an unbounded map keyed on
    something an attacker names is a memory-exhaustion primitive. Past
    :attr:`max_entries` the oldest entry is dropped, which costs a full body on
    the next fetch of that URL and nothing else.
    """

    #: Entries kept before the oldest is evicted. A chain is capped at 32
    #: documents (core spec 2.6.2), so this holds two whole chains.
    DEFAULT_MAX_ENTRIES = 64

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[str, str]] = {}

    def get(self, url: str) -> Optional[tuple[str, str]]:
        """``(etag, body)`` for *url*, or ``None``."""
        with self._lock:
            return self._entries.get(url)

    def put(self, url: str, etag: str, body: str) -> None:
        with self._lock:
            # A `dict` keeps insertion order, so the first key is the oldest.
            # Rewriting a URL already held replaces it in place rather than
            # counting against the bound again.
            self._entries[url] = (etag, body)
            while len(self._entries) > self.max_entries:
                del self._entries[next(iter(self._entries))]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


@dataclass
class HttpLoaderConfig:
    """How the HTTPS loader behaves. The defaults are the safe ones."""

    #: Seconds to wait for the TCP connection.
    connect_timeout_s: float = DEFAULT_CONNECT_TIMEOUT_S
    #: Seconds allowed for the whole response once connected. The status
    #: line, the headers and the body share this budget, so a peer that
    #: delivers a byte just inside every timeout cannot hold the load open.
    read_timeout_s: float = DEFAULT_READ_TIMEOUT_S
    #: Largest response body accepted, in bytes.
    max_size: int = DEFAULT_MAX_SIZE
    #: Value of an ``Authorization`` header to send, when the policy server
    #: needs one.
    auth_header: Optional[str] = None
    #: When set, the only hosts this loader will fetch from. A host outside it
    #: is refused before DNS. Matching is exact and case-insensitive; it is a
    #: list of host names, not a suffix rule, because ``evil-example.com``
    #: ends in neither ``example.com`` nor anything else a suffix test would
    #: be safe about.
    allowed_hosts: Optional[tuple[str, ...]] = None
    #: The ``ETag`` cache. A fresh one per loader by default; share one between
    #: loaders to share revalidation.
    cache: EtagCache = field(default_factory=EtagCache)
    #: **Test only.** Permit ``http://127.0.0.1`` and ``http://[::1]``, which
    #: every other rule in this module exists to forbid.
    #:
    #: A test server needs a certificate authority a test client trusts, and
    #: :mod:`http.server` over TLS is awkward enough that the fetch, ETag and
    #: size-cap paths would otherwise go untested. Setting this turns off the
    #: HTTPS requirement and the address check *for loopback only*: every other
    #: host, and every other blocked address, is still refused. It is never
    #: appropriate in a deployment -- a policy fetched in the clear is a policy
    #: anyone on the path can rewrite -- and the loader refuses a plain-``http``
    #: or loopback URL unless it is set. Even then plain ``http`` reaches only
    #: loopback addresses; any other target must be HTTPS.
    allow_insecure_loopback: bool = False
    #: TLS context. ``None`` uses the default verifying context. A test that
    #: serves HTTPS from a self-signed certificate passes its own.
    #: The loader sets its ``sslsocket_class`` so every receive draws on the
    #: read budget; a context that already names another socket type is
    #: refused.
    ssl_context: Optional[ssl.SSLContext] = None


@dataclass(frozen=True)
class _Target:
    """A URL that passed every check, with the address the request will dial."""

    url: str
    scheme: str
    host: str
    port: int
    address: str


# --------------------------------------------------------------------------- #
# URL validation and SSRF checks
# --------------------------------------------------------------------------- #


def validate_url(url: str, config: Optional[HttpLoaderConfig] = None) -> _Target:
    """Check *url* and resolve its host, or raise :class:`HttpLoadError`.

    The order matters: scheme, then host, then the allowlist, then DNS, then
    the address check. Every address the name resolves to must be acceptable,
    not merely the first -- a name with one public and one private address is a
    name that reaches the private one.
    """
    config = config or HttpLoaderConfig()
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise HttpLoadError(f"invalid URL '{url}': {exc}") from exc

    if parsed.scheme == "https":
        default_port = 443
    elif parsed.scheme == "http" and config.allow_insecure_loopback:
        default_port = 80
    else:
        raise HttpLoadError(
            f"only HTTPS URLs are allowed, got '{parsed.scheme}'"
        )
    # The exemption is about where the request may go, not which scheme
    # carried it: a loopback *HTTPS* test server needs it too, and that is the
    # arrangement under which the pinned connection's certificate check can be
    # exercised at all.
    loopback_exemption = config.allow_insecure_loopback

    host = parsed.hostname
    if not host:
        raise HttpLoadError(f"URL '{url}' has no host")

    if config.allowed_hosts is not None and host.lower() not in {
        allowed.lower() for allowed in config.allowed_hosts
    }:
        raise HttpLoadError(
            f"host '{host}' is not in the allowlist of this loader"
        )

    try:
        port = parsed.port or default_port
    except ValueError as exc:
        raise HttpLoadError(f"invalid URL '{url}': {exc}") from exc

    try:
        resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise HttpLoadError(f"failed to resolve host '{host}': {exc}") from exc
    addresses = [info[4][0] for info in resolved]
    if not addresses:
        raise HttpLoadError(f"host '{host}' did not resolve to any addresses")

    for address in addresses:
        if is_blocked_address(address):
            # The loopback exemption is deliberately the narrowest one that
            # lets a test server be reached: loopback and nothing else.
            if not (loopback_exemption and _is_loopback(address)):
                raise HttpLoadError(
                    f"SSRF protection: host '{host}' resolves to private IP {address}"
                )
        # Plain HTTP is permitted only where the exemption points: a loopback
        # test server. A public address in the clear is a policy anyone on the
        # path can rewrite, whatever the option says about loopback.
        if parsed.scheme == "http" and not _is_loopback(address):
            raise HttpLoadError(
                f"plain HTTP is allowed only to loopback addresses; host '{host}' "
                f"resolves to {address}"
            )

    return _Target(
        url=url,
        scheme=parsed.scheme,
        host=host,
        port=port,
        address=addresses[0],
    )


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# The transport
# --------------------------------------------------------------------------- #


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Turn every 3xx into a refusal (never a hop to follow).

    A redirect asks the client to reissue the request somewhere the scheme
    check, the allowlist and the address check never saw. Following one -- even
    to the same host -- would let a server that passed those checks hand the
    request to one that would not.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise HttpLoadError(
            f"HTTP request to '{req.full_url}' was redirected to '{newurl}'; "
            "redirects are not followed"
        )


class _ReadBudget:
    """A socket whose receives share one deadline.

    Before each receive the timeout is set to the time left, so a peer that
    delivers a byte just inside every timeout cannot hold the read open past
    the budget (core spec 2.6.4). Until :meth:`start_read_budget` is called
    the socket behaves as a plain one.
    """

    _budget_s: Optional[float] = None
    _deadline: Optional[float] = None

    def start_read_budget(self, seconds: float) -> None:
        """Start the budget now and set the timeout to it, so an operation
        that runs before the first receive, the TLS handshake, draws on it too:
        ``do_handshake`` applies the socket timeout as one deadline across its
        own retries.
        """
        self._budget_s = seconds
        self._deadline = time.monotonic() + seconds
        self._spend()

    def continue_read_budget(self, previous: "_ReadBudget") -> None:
        """Carry the budget of the socket this one was wrapped over."""
        self._budget_s = previous._budget_s
        self._deadline = previous._deadline
        self._spend()

    def _exhausted(self) -> TimeoutError:
        return TimeoutError(f"the read budget of {self._budget_s:g} s is exhausted")

    def _spend(self) -> None:
        if self._deadline is None:
            return
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise self._exhausted()
        self.settimeout(remaining)  # type: ignore[attr-defined]

    def recv(self, *args: Any, **kwargs: Any) -> bytes:
        self._spend()
        try:
            return super().recv(*args, **kwargs)  # type: ignore[misc]
        except TimeoutError as exc:
            raise (self._exhausted() if self._deadline is not None else exc) from exc

    def recv_into(self, *args: Any, **kwargs: Any) -> int:
        self._spend()
        try:
            return super().recv_into(*args, **kwargs)  # type: ignore[misc]
        except TimeoutError as exc:
            raise (self._exhausted() if self._deadline is not None else exc) from exc


class _BudgetedSocket(_ReadBudget, socket.socket):
    pass


class _BudgetedSSLSocket(_ReadBudget, ssl.SSLSocket):
    pass


def _budgeted_context(context: Optional[ssl.SSLContext]) -> ssl.SSLContext:
    """*context*, or a default one, wrapping sockets in :class:`_BudgetedSSLSocket`.

    ``sslsocket_class`` is the documented hook for the socket type a context
    creates. A context that already names another type is refused rather than
    silently given a read budget it may not honour.
    """
    context = context or ssl.create_default_context()
    if context.sslsocket_class is ssl.SSLSocket:
        context.sslsocket_class = _BudgetedSSLSocket
    elif context.sslsocket_class is not _BudgetedSSLSocket:
        raise HttpLoadError(
            "ssl_context.sslsocket_class must be ssl.SSLSocket; the loader wraps "
            "sockets in its own subclass to bound the read"
        )
    return context


def _connection_factory(target: _Target, config: HttpLoaderConfig):
    """An ``http.client`` connection class that dials the validated address.

    The class is handed the real host name, so the ``Host`` header, the SNI
    name and the certificate check all use it; only the socket goes to the
    address :func:`validate_url` already approved. That is what closes DNS
    rebinding: the name is resolved once, judged once, and connected to once.
    """
    secure = target.scheme == "https"
    base = http.client.HTTPSConnection if secure else http.client.HTTPConnection
    context = _budgeted_context(config.ssl_context) if secure else None

    class _PinnedConnection(base):  # type: ignore[valid-type,misc]
        def __init__(self, host: str, **kwargs: Any) -> None:
            kwargs.pop("context", None)
            kwargs.pop("check_hostname", None)
            kwargs["timeout"] = config.connect_timeout_s
            if secure:
                kwargs["context"] = context
            super().__init__(host, **kwargs)

        def connect(self) -> None:
            family = socket.AF_INET6 if ":" in target.address else socket.AF_INET
            sock: Any = _BudgetedSocket(family, socket.SOCK_STREAM)
            sock.settimeout(config.connect_timeout_s)
            sock.connect((target.address, target.port))
            # Separate budgets: getting connected is not the same wait as
            # getting bytes, and a server that accepts and then stalls must not
            # inherit the connect timeout's patience. From here on the TLS
            # handshake, the status line, the headers and the body draw on one
            # budget.
            sock.start_read_budget(config.read_timeout_s)
            if secure and context is not None:
                plain = sock
                sock = context.wrap_socket(plain, server_hostname=target.host)
                sock.continue_read_budget(plain)
            self.sock = sock

    return _PinnedConnection


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, target: _Target, config: HttpLoaderConfig) -> None:
        super().__init__()
        self._factory = _connection_factory(target, config)

    def https_open(self, req):  # noqa: ANN001
        return self.do_open(self._factory, req)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, target: _Target, config: HttpLoaderConfig) -> None:
        super().__init__()
        self._factory = _connection_factory(target, config)

    def http_open(self, req):  # noqa: ANN001
        return self.do_open(self._factory, req)


@dataclass(frozen=True)
class _Fetched:
    """What one GET produced.

    ``revalidated`` marks a ``304``, which comes back with an empty body
    because the caller holds the cached one. ``missing`` is set only when the
    caller asked for ``missing_is_none`` and the server answered 404 or 410,
    which is how :func:`fetch_signature` reads "there is no signature here"
    without treating every other failure as one.
    """

    status: int
    body: str
    etag: Optional[str]
    revalidated: bool = False
    missing: bool = False


def _fetch(
    target: _Target,
    config: HttpLoaderConfig,
    *,
    etag: Optional[str],
    missing_is_none: bool,
) -> _Fetched:
    """Perform one GET of *target* under *config*."""
    headers = {"Accept": "application/yaml, text/yaml, */*"}
    if config.auth_header:
        headers["Authorization"] = config.auth_header
    if etag:
        headers["If-None-Match"] = etag

    handler: urllib.request.BaseHandler = (
        _PinnedHTTPSHandler(target, config)
        if target.scheme == "https"
        else _PinnedHTTPHandler(target, config)
    )
    # An empty ProxyHandler replaces the default one, which would route the
    # request through a proxy named in the environment (``HTTPS_PROXY``,
    # ``ALL_PROXY``) that resolves the host a second time on its side; the
    # loader always dials the validated address itself.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), handler, _RefuseRedirects()
    )
    request = urllib.request.Request(target.url, headers=headers, method="GET")

    try:
        with opener.open(request, timeout=config.read_timeout_s) as response:
            return _Fetched(
                status=response.status,
                body=_read_capped(response, target.url, config.max_size),
                etag=response.headers.get("ETag"),
            )
    except urllib.error.HTTPError as exc:
        with exc:
            if exc.code == 304:
                return _Fetched(status=304, body="", etag=etag, revalidated=True)
            if missing_is_none and exc.code in (404, 410):
                return _Fetched(status=exc.code, body="", etag=None, missing=True)
            raise HttpLoadError(
                f"HTTP request to '{target.url}' returned status {exc.code}"
            ) from exc
    except HttpLoadError:
        # A redirect refusal is the answer, not a transport failure to be
        # re-described as one.
        raise
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise HttpLoadError(f"HTTP request to '{target.url}' failed: {exc}") from exc


def _read_capped(response: Any, url: str, max_size: int) -> str:
    """Read at most *max_size* bytes, refusing a body that wants more.

    One byte past the cap is read on purpose: a body of exactly ``max_size``
    bytes is fine, and anything longer is refused without ever holding it.
    """
    raw = response.read(max_size + 1)
    if len(raw) > max_size:
        raise HttpLoadError(
            f"response from '{url}' exceeds maximum size of {max_size} bytes"
        )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HttpLoadError(f"response from '{url}' is not valid UTF-8: {exc}") from exc


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #


def create_http_loader(config: Optional[HttpLoaderConfig] = None) -> Resolver:
    """A loader that serves ``https:`` references and refuses everything else.

    Pass it to :func:`~hushspec.resolve.resolve_with_options` as ``loader`` when
    URLs are the only references a policy may use, or let
    :func:`create_default_loader` chain it behind the builtin and filesystem
    loaders.
    """
    settings = config or HttpLoaderConfig()

    def _loader(reference: str, _source: Optional[str] = None) -> LoadedSpec:
        target = validate_url(reference, settings)
        cached = settings.cache.get(reference)
        result = _fetch(
            target,
            settings,
            etag=cached[0] if cached else None,
            missing_is_none=False,
        )

        body = result.body
        if result.revalidated:
            if cached is None:
                raise HttpLoadError(
                    f"HTTP request to '{reference}' returned status 304 "
                    "without a cached response to revalidate"
                )
            body = cached[1]
        elif result.etag:
            settings.cache.put(reference, result.etag, body)

        ok, parsed = parse(body)
        if not ok:
            raise HttpLoadError(f"failed to parse HushSpec at {reference}: {parsed}")
        return LoadedSpec(source=reference, spec=parsed)

    return _loader


def create_default_loader(config: Optional[HttpLoaderConfig] = None) -> Resolver:
    """The composite loader plus ``https:``: builtin, then file, then HTTPS.

    The same dispatch the reference implementation uses, so a policy resolves
    the same way whichever SDK loads it.
    """
    settings = config or HttpLoaderConfig()
    composite = create_composite_loader()
    https = create_http_loader(settings)

    def _loader(reference: str, source: Optional[str] = None) -> LoadedSpec:
        # `http:` goes to the HTTPS loader too, so the refusal a caller sees is
        # this module's ("only HTTPS URLs are allowed") rather than the
        # composite loader's "no transport installed", which would be wrong: a
        # transport *is* installed, and it declined the scheme.
        if reference.startswith(("https://", "http://")):
            return https(reference, source)
        return composite(reference, source)

    return _loader


def fetch_signature(
    url: str, config: Optional[HttpLoaderConfig] = None
) -> Optional[bytes]:
    """Fetch the detached envelope beside a policy URL (signing spec 7.1).

    The sidecar lives at ``<url>.sig`` and is fetched under exactly the rules
    the policy was: HTTPS only, the same allowlist, the same address check, no
    redirects, the same caps. A ``.sig`` URL must never be able to reach
    somewhere the policy URL could not.

    A missing sidecar is ``None``, not an error: "this policy is unsigned" is a
    fact the caller decides what to do with -- ``require_signature`` turns it
    into a refusal, opportunistic verification just records nothing. Every
    *other* failure raises, because a 500 or an oversized body says nothing
    about whether a signature exists.
    """
    settings = config or HttpLoaderConfig()
    target = validate_url(url, settings)
    result = _fetch(target, settings, etag=None, missing_is_none=True)
    if result.missing:
        return None
    return result.body.encode("utf-8")


def _split_query(source: str) -> tuple[str, str]:
    """*source* split at its query or fragment, so a suffix is carried over
    rather than having a sidecar name appended to it."""
    cut = min((source.find(mark) for mark in "?#" if mark in source), default=-1)
    return (source, "") if cut == -1 else (source[:cut], source[cut:])


def _preferred_sidecar_url(source: str) -> str:
    """The ``<source>.sig`` sidecar URL signing spec 7.1 prefers, with the
    ``.sig`` on the path rather than on a query the URL may carry."""
    base, suffix = _split_query(source)
    return f"{base}.sig{suffix}"


def _stem_sidecar_url(source: str) -> Optional[str]:
    """The ``<stem>.sig`` sidecar URL signing spec 7.1 also names, for a URL
    whose last path segment carries an extension: ``policy.yaml`` beside
    ``policy.sig``. ``None`` when there is no extension to replace, since the
    candidate would then be ``<source>.sig`` again.
    """
    base, suffix = _split_query(source)
    scheme = base.find("://")
    if scheme == -1 or base.find("/", scheme + 3) == -1:
        return None
    segment_start = base.rfind("/") + 1
    segment = base[segment_start:]
    dot = segment.rfind(".")
    if dot <= 0:
        return None
    return f"{base[:segment_start]}{segment[:dot]}.sig{suffix}"


def fetch_sidecar(
    source: str, config: Optional[HttpLoaderConfig] = None
) -> Optional[bytes]:
    """Fetch the detached envelope beside a policy URL: ``<source>.sig`` first,
    then the ``<stem>.sig`` sidecar of a 0.1 layout, the preference order
    signing spec 7.1 makes normative. ``None`` when neither exists.
    """
    settings = config or HttpLoaderConfig()
    preferred = fetch_signature(_preferred_sidecar_url(source), settings)
    if preferred is not None:
        return preferred
    stem = _stem_sidecar_url(source)
    return None if stem is None else fetch_signature(stem, settings)


def signature_locator(
    config: Optional[HttpLoaderConfig] = None,
):
    """A :data:`~hushspec.resolve.SignatureLocator` for URL sources.

    Returns the sidecar :func:`fetch_sidecar` finds, or ``None`` when there is
    none, which is what the resolver reads as `missing_signature`.
    """
    settings = config or HttpLoaderConfig()

    def _locate(source: str) -> Optional[bytes]:
        return fetch_sidecar(source, settings)

    return _locate


def install_https_loader(config: Optional[HttpLoaderConfig] = None) -> None:
    """Teach the resolver's default loaders to serve ``https:`` references.

    Until this is called a URL in ``extends`` is refused with a message saying
    the default loader has no HTTP client -- the fail-closed default, because
    fetching policy over the network is a deployment decision, not something a
    document should be able to turn on for itself.

    Afterwards :func:`~hushspec.resolve.create_composite_loader`,
    :func:`~hushspec.resolve.resolve_file` and every provider built on them
    fetch ``https:`` bases through this module, and the resolver's default
    signature locator looks for ``<url>.sig``.
    """
    settings = config or HttpLoaderConfig()
    register_scheme_loader(
        "https",
        create_http_loader(settings),
        signature_locator=signature_locator(settings),
    )
    if settings.allow_insecure_loopback:
        register_scheme_loader(
            "http",
            create_http_loader(settings),
            signature_locator=signature_locator(settings),
        )
