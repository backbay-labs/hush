package hushspec

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Loading an `extends` base over HTTPS.
//
// A policy may name its base by URL (`extends: "https://policies.example/base.yaml"`,
// core spec 2.3). Fetching one is a request an attacker partly controls -- the
// URL comes out of a document -- so this loader is written to be the narrowest
// thing that can still do the job:
//
//   - HTTPS only. `http:` is refused outright. A base fetched in the clear is a
//     base anyone on the path can rewrite, and the resolver would merge it.
//   - No redirects. A 3xx is an error, not a hop to follow: a redirect is the
//     server asking to move the request somewhere the checks never saw.
//   - The address is checked, then pinned. The host is resolved first and every
//     address it resolves to is checked ([IsBlockedAddress]); the request then
//     dials the address that was checked, with the original hostname still used
//     for SNI, certificate validation and the Host header. A name that
//     re-resolves to 127.0.0.1 between the check and the connect -- DNS
//     rebinding -- reaches nothing.
//   - Bounded. A byte cap on the body, a connect timeout, and a read timeout.
//   - Optionally allowlisted. HTTPLoaderConfig.AllowedHosts narrows the
//     reachable hosts to a fixed set, which is what a deployment that knows its
//     policy server should do.
//
// Integrity is not this file's job and it does not pretend otherwise. A URL is a
// location, never an identity: what makes a remote base trustworthy is the
// `#sha256:` digest pin on the reference (core spec 2.3) or a detached
// signature, both enforced by the resolver around this loader. The pin is
// stripped from the reference before the loader sees it and checked against the
// document that comes back, so pinning works here exactly as it does for a
// file. [FetchSignature] supplies the other half, fetching `<url>.sig` under the
// same rules (signing spec 7.1).
//
// Nothing registers itself at init. [InstallHTTPSLoader] installs the `https:`
// scheme into the resolver's default loaders; until it is called a URL
// reference is refused, which is the fail-closed default.

const (
	// DefaultHTTPConnectTimeout is how long to wait for the TCP connection.
	DefaultHTTPConnectTimeout = 10 * time.Second
	// DefaultHTTPReadTimeout is how long to wait for response bytes once
	// connected.
	DefaultHTTPReadTimeout = 10 * time.Second
	// DefaultHTTPMaxSize is the largest response body accepted, in bytes. A
	// policy is a small document; a megabyte is already far beyond any real
	// one, and the cap is what stops a hostile server feeding the resolver
	// until it runs out of memory.
	DefaultHTTPMaxSize = 1 << 20
)

// CloudMetadataAddresses names the two well-known cloud instance-metadata
// endpoints, so the intent is readable even though blockedNetworks already
// covers both (169.254.0.0/16 and fc00::/7). Reaching one from a URL an agent
// supplied is the classic SSRF credential theft.
var CloudMetadataAddresses = []string{"169.254.169.254", "fd00:ec2::254"}

// blockedNetworks is every network a policy URL may not resolve to. A host that
// resolves to any of these is refused *after* DNS, because the danger is the
// address and not the name: `internal.example.com` and a name that resolves to
// 10.0.0.5 are the same request.
var blockedNetworks = mustParseCIDRs(
	// IPv4
	"0.0.0.0/8",      // "this network", and 0.0.0.0 itself
	"10.0.0.0/8",     // RFC 1918
	"100.64.0.0/10",  // RFC 6598 carrier-grade NAT
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local, including cloud metadata
	"172.16.0.0/12",  // RFC 1918
	"192.0.0.0/24",   // IETF protocol assignments
	"192.168.0.0/16", // RFC 1918
	"198.18.0.0/15",  // benchmarking
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved, including the 255.255.255.255 broadcast
	// IPv6
	"::/128",    // unspecified
	"::1/128",   // loopback
	"fc00::/7",  // unique local, including the IPv6 metadata endpoint
	"fe80::/10", // link-local
	"ff00::/8",  // multicast
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("hushspec: bad blocked network %q: %v", cidr, err))
		}
		networks = append(networks, network)
	}
	return networks
}

// HTTPLoadError is a policy that could not be fetched over HTTPS.
//
// Every refusal this file makes is one of these -- a non-HTTPS URL, a blocked
// address, a redirect, an oversized body, a transport failure. The resolver
// turns it into a not-found rejection for the reference, as it does for any
// loader failure, so a base that cannot be fetched is never merged as if it
// said nothing.
type HTTPLoadError struct {
	Message string
}

func (e *HTTPLoadError) Error() string { return e.Message }

func httpErr(format string, args ...any) *HTTPLoadError {
	return &HTTPLoadError{Message: fmt.Sprintf(format, args...)}
}

// --------------------------------------------------------------------------
// Address checks
// --------------------------------------------------------------------------

// IsBlockedAddress reports whether ip is an address a policy URL may not reach.
//
// It blocks the unspecified address, loopback, the RFC 1918 private ranges,
// link-local (which is where the cloud metadata endpoint lives), carrier-grade
// NAT, multicast, IPv6 unique-local, and the reserved ranges.
//
// IPv6 forms that carry an IPv4 address in their low 32 bits are unwrapped
// first and judged on the address inside. Both the IPv4-*mapped* form
// (::ffff:127.0.0.1) and the deprecated IPv4-*compatible* form (::7f00:1, which
// is 127.0.0.1) would otherwise slip past a check that only looked at IPv6
// ranges.
//
// An address that cannot be parsed is blocked: a resolver that cannot tell what
// it is about to connect to does not connect.
func IsBlockedAddress(ip string) bool {
	if zone := strings.IndexByte(ip, '%'); zone >= 0 {
		ip = ip[:zone]
	}
	address := net.ParseIP(ip)
	if address == nil {
		return true
	}
	if embedded := embeddedIPv4(address); embedded != nil {
		address = embedded
	}
	for _, network := range blockedNetworks {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

// embeddedIPv4 is the IPv4 address inside an IPv6 one, for both the
// IPv4-mapped (::ffff:a.b.c.d) and the deprecated IPv4-compatible (::a.b.c.d)
// forms. nil when there is none, and for :: and ::1, which the IPv6 rules
// already cover.
func embeddedIPv4(address net.IP) net.IP {
	if mapped := address.To4(); mapped != nil {
		// Already IPv4, or the IPv4-mapped form Go normalizes to it.
		return nil
	}
	for _, octet := range address[:12] {
		if octet != 0 {
			return nil
		}
	}
	low := uint32(address[12])<<24 | uint32(address[13])<<16 |
		uint32(address[14])<<8 | uint32(address[15])
	if low <= 1 {
		return nil // :: (unspecified) and ::1 (loopback)
	}
	return net.IPv4(address[12], address[13], address[14], address[15])
}

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

// HTTPEtagCache is an in-memory ETag cache keyed by URL (core spec 2.3
// revalidation).
//
// A cached body is only ever returned on a 304 Not Modified, so the server is
// always asked. That keeps the loader honest -- a policy that changed is always
// refetched -- while a policy that did not change costs one conditional request
// instead of a full body.
//
// Entries live in memory for the life of the cache: nothing is written to disk,
// so a policy body never outlives the process that fetched it. It is safe for
// concurrent use.
//
// The cache is bounded, and has to be: a URL comes out of a document, a body
// may be as large as [DefaultHTTPMaxSize], and an unbounded map keyed on
// something an attacker names is a memory-exhaustion primitive. Past MaxEntries
// the oldest entry is dropped, which costs a full body on the next fetch of
// that URL and nothing else.
type HTTPEtagCache struct {
	// MaxEntries is how many entries are kept before the oldest is evicted.
	// Zero means [DefaultHTTPEtagCacheEntries], so the zero value of the
	// struct is a usable bounded cache.
	MaxEntries int

	mu      sync.RWMutex
	entries map[string]httpCacheEntry
	// order holds the keys in insertion order, because a Go map has none.
	order []string
}

// DefaultHTTPEtagCacheEntries is how many revalidation entries a cache keeps by
// default. A chain is capped at 32 documents (core spec 2.6.2), so this holds
// two whole chains.
const DefaultHTTPEtagCacheEntries = 64

type httpCacheEntry struct {
	etag string
	body string
}

// NewHTTPEtagCache is an empty cache holding [DefaultHTTPEtagCacheEntries]
// entries, ready to use.
func NewHTTPEtagCache() *HTTPEtagCache {
	return &HTTPEtagCache{entries: map[string]httpCacheEntry{}}
}

// Get is the cached (etag, body) for url, if any.
func (c *HTTPEtagCache) Get(url string) (string, string, bool) {
	if c == nil {
		return "", "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[url]
	return entry.etag, entry.body, ok
}

// Put records a body against the etag the server returned for it, evicting the
// oldest entry once the cache is full.
func (c *HTTPEtagCache) Put(url, etag, body string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]httpCacheEntry{}
	}
	// Rewriting a URL already held replaces it in place rather than counting
	// against the bound again.
	if _, held := c.entries[url]; !held {
		c.order = append(c.order, url)
	}
	c.entries[url] = httpCacheEntry{etag: etag, body: body}

	limit := c.MaxEntries
	if limit <= 0 {
		limit = DefaultHTTPEtagCacheEntries
	}
	for len(c.order) > limit {
		delete(c.entries, c.order[0])
		c.order = c.order[1:]
	}
}

// Clear forgets every entry.
func (c *HTTPEtagCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]httpCacheEntry{}
	c.order = nil
}

// HTTPLoaderConfig says how the HTTPS loader behaves. The zero value is usable
// and is the safe one: HTTPS only, no allowlist, the default caps and timeouts.
type HTTPLoaderConfig struct {
	// ConnectTimeout bounds establishing the TCP connection. Zero means
	// [DefaultHTTPConnectTimeout].
	ConnectTimeout time.Duration
	// ReadTimeout bounds waiting for response bytes once connected. Zero means
	// [DefaultHTTPReadTimeout].
	ReadTimeout time.Duration
	// MaxSize is the largest response body accepted, in bytes. Zero means
	// [DefaultHTTPMaxSize].
	MaxSize int64
	// AuthHeader is the value of an Authorization header to send, when the
	// policy server needs one.
	AuthHeader string
	// AllowedHosts, when non-empty, is the only set of hosts this loader will
	// fetch from; a host outside it is refused before DNS. Matching is exact
	// and case-insensitive -- a list of host names, not a suffix rule, because
	// `evil-example.com` ends in neither `example.com` nor anything else a
	// suffix test would be safe about.
	AllowedHosts []string
	// Cache is the ETag cache. Nil means no revalidation; share one cache
	// between loaders to share it.
	Cache *HTTPEtagCache
	// AllowInsecureLoopback is TEST ONLY. It permits loopback addresses and the
	// `http:` scheme, which every other rule here exists to forbid.
	//
	// A test server listens on 127.0.0.1, so without this the loader's own
	// fetch, ETag and size-cap paths could not be exercised against
	// httptest.NewTLSServer. Setting it turns off the HTTPS requirement and the
	// address check *for loopback only*: every other host, and every other
	// blocked address, is still refused. It is never appropriate in a
	// deployment -- a policy fetched in the clear is a policy anyone on the
	// path can rewrite.
	AllowInsecureLoopback bool
	// TLSClientConfig overrides the default TLS settings. A test that serves
	// HTTPS from a generated certificate passes the one
	// httptest.Server.Client() carries. ServerName is left for the transport to
	// fill in from the request URL, so the certificate is always checked
	// against the hostname the policy named and never against the pinned
	// address.
	TLSClientConfig *tls.Config
}

func (c HTTPLoaderConfig) connectTimeout() time.Duration {
	if c.ConnectTimeout <= 0 {
		return DefaultHTTPConnectTimeout
	}
	return c.ConnectTimeout
}

func (c HTTPLoaderConfig) readTimeout() time.Duration {
	if c.ReadTimeout <= 0 {
		return DefaultHTTPReadTimeout
	}
	return c.ReadTimeout
}

func (c HTTPLoaderConfig) maxSize() int64 {
	if c.MaxSize <= 0 {
		return DefaultHTTPMaxSize
	}
	return c.MaxSize
}

// HTTPTarget is a URL that passed every check, with the address the request
// will dial.
type HTTPTarget struct {
	URL     string
	Scheme  string
	Host    string
	Port    int
	Address string
}

// --------------------------------------------------------------------------
// URL validation and SSRF checks
// --------------------------------------------------------------------------

// ValidateURL checks rawURL and resolves its host, or reports why not.
//
// The order matters: scheme, then host, then the allowlist, then DNS, then the
// address check. Every address the name resolves to must be acceptable, not
// merely the first -- a name with one public and one private address is a name
// that reaches the private one.
func ValidateURL(rawURL string, config HTTPLoaderConfig) (*HTTPTarget, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, httpErr("invalid URL '%s': %v", rawURL, err)
	}

	loopbackExemption := false
	defaultPort := 443
	switch {
	case parsed.Scheme == "https":
	case parsed.Scheme == "http" && config.AllowInsecureLoopback:
		defaultPort = 80
		loopbackExemption = true
	default:
		return nil, httpErr("only HTTPS URLs are allowed, got '%s'", parsed.Scheme)
	}
	if config.AllowInsecureLoopback {
		// The exemption is about where the request may go, not which scheme
		// carried it: a loopback HTTPS test server needs it too.
		loopbackExemption = true
	}

	host := parsed.Hostname()
	if host == "" {
		return nil, httpErr("URL '%s' has no host", rawURL)
	}

	if len(config.AllowedHosts) > 0 && !hostAllowed(host, config.AllowedHosts) {
		return nil, httpErr("host '%s' is not in the allowlist of this loader", host)
	}

	port := defaultPort
	if text := parsed.Port(); text != "" {
		parsedPort, err := strconv.Atoi(text)
		if err != nil || parsedPort <= 0 || parsedPort > 65535 {
			return nil, httpErr("invalid URL '%s': bad port %q", rawURL, text)
		}
		port = parsedPort
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.connectTimeout())
	defer cancel()
	addresses, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, httpErr("failed to resolve host '%s': %v", host, err)
	}
	if len(addresses) == 0 {
		return nil, httpErr("host '%s' did not resolve to any addresses", host)
	}

	for _, address := range addresses {
		if !IsBlockedAddress(address) {
			continue
		}
		// The loopback exemption is deliberately the narrowest one that lets a
		// test server be reached: loopback and nothing else.
		if loopbackExemption && isLoopbackAddress(address) {
			continue
		}
		return nil, httpErr(
			"SSRF protection: host '%s' resolves to private IP %s", host, address)
	}

	return &HTTPTarget{
		URL:     rawURL,
		Scheme:  parsed.Scheme,
		Host:    host,
		Port:    port,
		Address: addresses[0],
	}, nil
}

func hostAllowed(host string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(host, candidate) {
			return true
		}
	}
	return false
}

func isLoopbackAddress(ip string) bool {
	address := net.ParseIP(ip)
	return address != nil && address.IsLoopback()
}

// --------------------------------------------------------------------------
// The transport
// --------------------------------------------------------------------------

// errHTTPRedirect marks a response the loader refused to follow.
var errHTTPRedirect = errors.New("redirect")

// newPinnedClient is an HTTP client that dials only target.Address.
//
// The request still carries the original host, so the Host header, the SNI name
// and the certificate check all use it; only the socket goes to the address
// [ValidateURL] already approved. That is what closes DNS rebinding: the name is
// resolved once, judged once, and connected to once.
func newPinnedClient(target *HTTPTarget, config HTTPLoaderConfig) *http.Client {
	dialer := &net.Dialer{Timeout: config.connectTimeout()}
	pinned := net.JoinHostPort(target.Address, strconv.Itoa(target.Port))

	var tlsConfig *tls.Config
	if config.TLSClientConfig != nil {
		// Clone so the caller's config is never mutated, and leave ServerName
		// empty for the transport to fill in from the URL.
		tlsConfig = config.TLSClientConfig.Clone()
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, pinned)
		},
		TLSClientConfig: tlsConfig,
		// Separate budgets: getting connected is not the same wait as getting
		// bytes, and a server that accepts and then stalls must not inherit the
		// connect timeout's patience.
		TLSHandshakeTimeout:   config.connectTimeout(),
		ResponseHeaderTimeout: config.readTimeout(),
		DisableKeepAlives:     true,
		Proxy:                 nil,
	}
	return &http.Client{
		Transport: transport,
		// Hand a 3xx back rather than following it: a redirect would reissue
		// the request somewhere the scheme, allowlist and address checks never
		// saw, and even a same-host one moves the request to a location the
		// deployment never named.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: config.connectTimeout() + config.readTimeout(),
	}
}

// httpFetchResult is what one GET produced. Missing is true only when the
// caller asked for it and the server answered 404 or 410.
type httpFetchResult struct {
	Status      int
	Body        string
	Etag        string
	Missing     bool
	Revalidated bool
}

// fetchHTTP performs one GET of target under config.
func fetchHTTP(target *HTTPTarget, config HTTPLoaderConfig, etag string, missingIsNone bool) (*httpFetchResult, error) {
	ctx, cancel := context.WithTimeout(
		context.Background(), config.connectTimeout()+config.readTimeout())
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return nil, httpErr("invalid URL '%s': %v", target.URL, err)
	}
	request.Header.Set("Accept", "application/yaml, text/yaml, */*")
	if config.AuthHeader != "" {
		request.Header.Set("Authorization", config.AuthHeader)
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}

	response, err := newPinnedClient(target, config).Do(request)
	if err != nil {
		return nil, httpErr("HTTP request to '%s' failed: %v", target.URL, err)
	}
	// Closed, not drained: draining buys connection reuse, and this transport
	// sets DisableKeepAlives, so the only thing a drain would buy on the
	// oversized path is reading another megabyte from a hostile server.
	defer func() { _ = response.Body.Close() }()

	switch {
	case response.StatusCode == http.StatusNotModified:
		return &httpFetchResult{Status: response.StatusCode, Etag: etag, Revalidated: true}, nil
	case response.StatusCode >= 300 && response.StatusCode < 400:
		return nil, httpErr(
			"HTTP request to '%s' was redirected to '%s'; redirects are not followed",
			target.URL, response.Header.Get("Location"))
	case missingIsNone && (response.StatusCode == http.StatusNotFound ||
		response.StatusCode == http.StatusGone):
		return &httpFetchResult{Status: response.StatusCode, Missing: true}, nil
	case response.StatusCode < 200 || response.StatusCode >= 300:
		return nil, httpErr(
			"HTTP request to '%s' returned status %d", target.URL, response.StatusCode)
	}

	// One byte past the cap on purpose: a body of exactly MaxSize is fine, and
	// anything longer is refused without ever being held whole.
	limit := config.maxSize()
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, httpErr("failed to read response from '%s': %v", target.URL, err)
	}
	if int64(len(body)) > limit {
		return nil, httpErr(
			"response from '%s' exceeds maximum size of %d bytes", target.URL, limit)
	}
	if !utf8.Valid(body) {
		return nil, httpErr("response from '%s' is not valid UTF-8", target.URL)
	}

	return &httpFetchResult{
		Status: response.StatusCode,
		Body:   string(body),
		Etag:   response.Header.Get("ETag"),
	}, nil
}

// --------------------------------------------------------------------------
// Loaders
// --------------------------------------------------------------------------

// NewHTTPLoader is a loader that serves `https:` references and refuses
// everything else.
//
// Pass it to [ResolveWithOptions] as the loader when URLs are the only
// references a policy may use, or let [NewDefaultLoader] chain it behind the
// builtin and filesystem loaders.
func NewHTTPLoader(config HTTPLoaderConfig) ResolveLoader {
	return func(reference string, _ string) (*LoadedSpec, error) {
		target, err := ValidateURL(reference, config)
		if err != nil {
			return nil, err
		}

		cachedEtag, cachedBody, cached := config.Cache.Get(reference)
		result, err := fetchHTTP(target, config, cachedEtag, false)
		if err != nil {
			return nil, err
		}

		body := result.Body
		switch {
		case result.Revalidated && cached:
			body = cachedBody
		case result.Revalidated:
			return nil, httpErr(
				"HTTP request to '%s' returned status 304 without a cached response to revalidate",
				reference)
		case result.Etag != "":
			config.Cache.Put(reference, result.Etag, body)
		}

		spec, err := Parse(body)
		if err != nil {
			return nil, httpErr("failed to parse HushSpec at %s: %v", reference, err)
		}
		return &LoadedSpec{Source: reference, Spec: spec}, nil
	}
}

// NewDefaultLoader is the composite loader plus `https:`: builtin, then file,
// then HTTPS. It is the dispatch the reference implementation uses, so a policy
// resolves the same way whichever SDK loads it.
func NewDefaultLoader(config HTTPLoaderConfig) ResolveLoader {
	composite := createCompositeLoader()
	https := NewHTTPLoader(config)
	return func(reference string, from string) (*LoadedSpec, error) {
		// `http:` goes to the HTTPS loader too, so the refusal a caller sees is
		// this file's ("only HTTPS URLs are allowed") rather than the composite
		// loader's "no transport installed", which would be wrong: a transport
		// *is* installed, and it declined the scheme.
		if strings.HasPrefix(reference, "https://") || strings.HasPrefix(reference, "http://") {
			return https(reference, from)
		}
		return composite(reference, from)
	}
}

// FetchSignature gets the detached envelope beside a policy URL (signing spec
// 7.1).
//
// The sidecar lives at `<url>.sig` and is fetched under exactly the rules the
// policy was: HTTPS only, the same allowlist, the same address check, no
// redirects, the same caps. A `.sig` URL must never be able to reach somewhere
// the policy URL could not.
//
// The bool reports whether a signature was found. A missing sidecar is
// (nil, false, nil), not an error: "this policy is unsigned" is a fact the
// caller decides what to do with -- RequireSignature turns it into a refusal,
// opportunistic verification just records nothing. Every *other* failure is an
// error, because a 500 or an oversized body says nothing about whether a
// signature exists.
func FetchSignature(rawURL string, config HTTPLoaderConfig) ([]byte, bool, error) {
	target, err := ValidateURL(rawURL, config)
	if err != nil {
		return nil, false, err
	}
	result, err := fetchHTTP(target, config, "", true)
	if err != nil {
		return nil, false, err
	}
	if result.Missing {
		return nil, false, nil
	}
	return []byte(result.Body), true, nil
}

// HTTPSignatureLocator is a [SignatureLocator] for URL sources: it looks for
// `<source>.sig` and reports not-found when there is none, which is what the
// resolver reads as `missing_signature`.
func HTTPSignatureLocator(config HTTPLoaderConfig) SignatureLocator {
	return func(source string) ([]byte, bool, error) {
		return FetchSignature(source+".sig", config)
	}
}

// InstallHTTPSLoader teaches the resolver's default loaders to serve `https:`
// references.
//
// Until it is called a URL in `extends` is refused with a message saying the
// composite loader has no HTTP client -- the fail-closed default, because
// fetching policy over the network is a deployment decision, not something a
// document should be able to turn on for itself.
//
// Afterwards [ResolveFile], [NewFileProvider] and everything built on them
// fetch `https:` bases through this loader, and [DefaultSignatureLocator] looks
// for `<url>.sig`.
func InstallHTTPSLoader(config HTTPLoaderConfig) {
	loader := NewHTTPLoader(config)
	locator := HTTPSignatureLocator(config)
	RegisterSchemeLoader("https", loader, locator)
	if config.AllowInsecureLoopback {
		RegisterSchemeLoader("http", loader, locator)
	}
}
