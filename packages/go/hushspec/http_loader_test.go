package hushspec

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// HTTPS `extends` loading (http_loader.go).
//
// Two halves, because they need different things to be true.
//
// The URL and address checks are pure: every rule the loader enforces before it
// opens a socket is exercised directly, with no server involved. That is where
// the SSRF surface actually lives -- the loopback, private, link-local, CGNAT,
// multicast, unspecified and IPv4-in-IPv6 forms, the scheme check, the
// allowlist.
//
// The fetch, revalidation and size-cap paths run against httptest.NewTLSServer,
// which serves real HTTPS from a generated certificate on 127.0.0.1. The test
// passes the server's own client TLS config so the certificate verifies, and
// the loader's documented test-only AllowInsecureLoopback so the address check
// permits loopback. That the option is *needed* -- that the loader refuses
// loopback without it -- is itself asserted below.

const httpTestPolicy = "hushspec: \"0.2.0\"\nname: remote-base\n"

const httpTestExtendsBuiltin = "hushspec: \"0.2.0\"\nname: remote-leaf\nextends: \"builtin:strict\"\n"

const httpTestExtendsRemote = "hushspec: \"0.2.0\"\nname: remote-leaf\n" +
	"extends: \"https://policies.invalid/other.yaml\"\n"

const httpTestSignature = `{"format_version": "0.2"}`

func TestHTTPDNSLookupHonorsTheConnectBudget(t *testing.T) {
	previous := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = previous })
	var attempts atomic.Int32
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			attempts.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	started := time.Now()
	_, err := ValidateURL("https://dns-budget.invalid/policy.yaml", HTTPLoaderConfig{
		ConnectTimeout: 50 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "failed to resolve") {
		t.Fatalf("stalled resolver accepted: %v", err)
	}
	if attempts.Load() == 0 || time.Since(started) > time.Second {
		t.Fatal("DNS did not run under the configured connection deadline")
	}
}

func TestHTTPFetchDoesNotRenewAnExpiredDNSConnectBudget(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(w, httpTestPolicy)
	}))
	defer server.Close()
	config := HTTPLoaderConfig{
		AllowInsecureLoopback: true,
		TLSClientConfig:       server.Client().Transport.(*http.Transport).TLSClientConfig,
		ConnectTimeout:        time.Second,
	}
	target, err := ValidateURL(server.URL, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []bool{false, true} {
		_, err = fetchHTTP(target, config, "", sidecar, time.Now().Add(-time.Millisecond))
		if err == nil || !strings.Contains(err.Error(), "connect budget") {
			t.Fatalf("expired DNS/connect budget accepted (sidecar=%v): %v", sidecar, err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("a request was issued after the DNS/connect deadline")
	}
}

func TestHTTPClientKeepsOnlyTheRemainingConnectBudget(t *testing.T) {
	config := HTTPLoaderConfig{ConnectTimeout: time.Hour, ReadTimeout: time.Second}
	deadline := time.Now().Add(100 * time.Millisecond)
	client := newPinnedClient(&HTTPTarget{Address: "127.0.0.1", Port: 443}, config, deadline)
	transport := client.Transport.(*http.Transport)
	if transport.TLSHandshakeTimeout <= 0 || transport.TLSHandshakeTimeout > 100*time.Millisecond {
		t.Fatalf("TLS renewed the elapsed DNS budget: %v", transport.TLSHandshakeTimeout)
	}
	if client.Timeout <= time.Second || client.Timeout > 1100*time.Millisecond {
		t.Fatalf("request renewed the elapsed DNS budget: %v", client.Timeout)
	}
}

// --------------------------------------------------------------------------
// Address classification
// --------------------------------------------------------------------------

func TestIsBlockedAddress(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "0.0.0.0", "0.1.2.3",
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.1.1", "169.254.169.254", // link-local and cloud metadata
		"100.64.0.1", "100.127.255.255", // carrier-grade NAT
		"224.0.0.1", "239.255.255.250", // multicast
		"255.255.255.255", // broadcast
		"::", "::1",       // unspecified and loopback
		"fc00::1", "fd00::1", "fd00:ec2::254", // unique local, IPv6 metadata
		"fe80::1", "ff02::1", // link-local and multicast
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", // IPv4-mapped
		"::7f00:1",           // deprecated IPv4-compatible loopback
		"::a9fe:a9fe",        // IPv4-compatible cloud metadata
		"fe80::1%eth0",       // a zone id never makes an address reachable
		"not-an-address", "", // unparseable is unreachable
	}
	for _, address := range blocked {
		if !IsBlockedAddress(address) {
			t.Errorf("%q must not be reachable", address)
		}
	}

	allowed := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34",
		"2606:4700:4700::1111", "172.32.0.1", "11.0.0.1",
	}
	for _, address := range allowed {
		if IsBlockedAddress(address) {
			t.Errorf("%q is a public address and must be reachable", address)
		}
	}
}

func TestCloudMetadataAddressesAreBlocked(t *testing.T) {
	for _, address := range CloudMetadataAddresses {
		if !IsBlockedAddress(address) {
			t.Errorf("the cloud metadata endpoint %q is reachable", address)
		}
	}
}

// --------------------------------------------------------------------------
// URL validation
// --------------------------------------------------------------------------

func TestValidateURLAcceptsOnlyHTTPS(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/policy.yaml",
		"ftp://example.com/policy.yaml",
		"file:///etc/passwd",
		"gopher://example.com/policy.yaml",
	} {
		_, err := ValidateURL(raw, HTTPLoaderConfig{})
		if err == nil || !strings.Contains(err.Error(), "only HTTPS URLs are allowed") {
			t.Errorf("ValidateURL(%q) = %v, want an HTTPS-only refusal", raw, err)
		}
	}
}

func TestValidateURLRefusesSSRFTargets(t *testing.T) {
	for _, raw := range []string{
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
	} {
		_, err := ValidateURL(raw, HTTPLoaderConfig{})
		if err == nil || !strings.Contains(err.Error(), "SSRF protection") {
			t.Errorf("ValidateURL(%q) = %v, want an SSRF refusal", raw, err)
		}
	}
}

func TestValidateURLRefusesAHostlessURL(t *testing.T) {
	_, err := ValidateURL("https:///policy.yaml", HTTPLoaderConfig{})
	if err == nil || !strings.Contains(err.Error(), "has no host") {
		t.Errorf("a hostless URL was accepted: %v", err)
	}
}

func TestValidateURLRefusesAnUnresolvableHost(t *testing.T) {
	_, err := ValidateURL("https://this-host-does-not-exist.invalid/p.yaml", HTTPLoaderConfig{})
	if err == nil || !strings.Contains(err.Error(), "failed to resolve host") {
		t.Errorf("an unresolvable host was accepted: %v", err)
	}
}

func TestValidateURLChecksTheAllowlistBeforeDNS(t *testing.T) {
	config := HTTPLoaderConfig{AllowedHosts: []string{"policies.invalid"}}
	// The host does not resolve, so a refusal naming the allowlist proves the
	// allowlist ran first.
	_, err := ValidateURL("https://elsewhere.invalid/p.yaml", config)
	if err == nil || !strings.Contains(err.Error(), "is not in the allowlist") {
		t.Errorf("a host outside the allowlist was accepted: %v", err)
	}
	// A suffix is not a match: `evil-policies.invalid` is a different host.
	_, err = ValidateURL("https://evil-policies.invalid/p.yaml", config)
	if err == nil || !strings.Contains(err.Error(), "is not in the allowlist") {
		t.Errorf("a suffix matched the allowlist: %v", err)
	}
	// The allowed host passes the allowlist whatever its case, and then fails
	// on DNS instead -- which is the proof the allowlist let it through.
	_, err = ValidateURL("https://Policies.INVALID/p.yaml",
		HTTPLoaderConfig{AllowedHosts: []string{"policies.invalid"}})
	if err == nil || !strings.Contains(err.Error(), "failed to resolve host") {
		t.Errorf("the allowed host was refused by the allowlist: %v", err)
	}
}

func TestLoopbackNeedsTheTestOnlyOption(t *testing.T) {
	const insecure = "http://127.0.0.1:1/policy.yaml"
	if _, err := ValidateURL(insecure, HTTPLoaderConfig{}); err == nil ||
		!strings.Contains(err.Error(), "only HTTPS URLs are allowed") {
		t.Errorf("plain http was accepted without the escape hatch: %v", err)
	}
	if _, err := ValidateURL("https://127.0.0.1:1/policy.yaml", HTTPLoaderConfig{}); err == nil ||
		!strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("loopback was accepted without the escape hatch: %v", err)
	}
	target, err := ValidateURL(insecure, HTTPLoaderConfig{AllowInsecureLoopback: true})
	if err != nil {
		t.Fatalf("the escape hatch did not permit loopback: %v", err)
	}
	// The request dials this address, not a second DNS answer: that is what
	// closes the rebinding window between the check and the connect.
	if target.Address != "127.0.0.1" || target.Port != 1 {
		t.Errorf("target = %+v, want the pinned loopback address and port", target)
	}
}

func TestTheLoopbackEscapeHatchDoesNotOpenPlainHTTPToPublicAddresses(t *testing.T) {
	config := HTTPLoaderConfig{AllowInsecureLoopback: true}
	if _, err := ValidateURL("http://8.8.8.8/policy.yaml", config); err == nil ||
		!strings.Contains(err.Error(), "plain HTTP is allowed only to loopback") {
		t.Errorf("plain HTTP to a public address was accepted: %v", err)
	}
	// HTTPS to a public address is still permitted under the option.
	target, err := ValidateURL("https://8.8.8.8/policy.yaml", config)
	if err != nil || target.Address != "8.8.8.8" {
		t.Errorf("HTTPS to a public address was refused: %v", err)
	}
}

func TestTheLoopbackEscapeHatchOpensNothingElse(t *testing.T) {
	config := HTTPLoaderConfig{AllowInsecureLoopback: true}
	for _, raw := range []string{
		"http://10.0.0.1/policy.yaml",
		"http://169.254.169.254/latest/meta-data/",
		"https://192.168.1.1/policy.yaml",
	} {
		_, err := ValidateURL(raw, config)
		if err == nil || !strings.Contains(err.Error(), "SSRF protection") {
			t.Errorf("ValidateURL(%q) = %v, want an SSRF refusal", raw, err)
		}
	}
}

// --------------------------------------------------------------------------
// Fetching, against a loopback TLS server
// --------------------------------------------------------------------------

// httpTestServer is an HTTPS server serving one policy, its sidecar, and the
// edge cases the loader has to refuse.
type httpTestServer struct {
	*httptest.Server
	mu          sync.Mutex
	conditional []string
}

func (s *httpTestServer) conditionalRequests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.conditional...)
}

func newHTTPTestServer(t *testing.T) *httpTestServer {
	t.Helper()
	server := &httpTestServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/base.yaml", func(w http.ResponseWriter, r *http.Request) {
		conditional := r.Header.Get("If-None-Match")
		server.mu.Lock()
		server.conditional = append(server.conditional, conditional)
		server.mu.Unlock()
		w.Header().Set("ETag", `"v1"`)
		if conditional == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fmt.Fprint(w, httpTestPolicy)
	})
	mux.HandleFunc("/base.yaml.sig", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, httpTestSignature)
	})
	mux.HandleFunc("/stem.sig", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, httpTestSignature)
	})
	mux.HandleFunc("/extends-builtin.yaml", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, httpTestExtendsBuiltin)
	})
	mux.HandleFunc("/extends-remote.yaml", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, httpTestExtendsRemote)
	})
	mux.HandleFunc("/oversized.yaml", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", DefaultHTTPMaxSize+10))
	})
	mux.HandleFunc("/redirect.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/base.yaml", http.StatusFound)
	})
	mux.HandleFunc("/broken.yaml", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hushspec: [unclosed\n")
	})
	mux.HandleFunc("/error.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/authed.yaml", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, httpTestPolicy)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server.Server = httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return server
}

// config trusts the test server's generated certificate and permits the
// loopback address it listens on, and nothing else.
func (s *httpTestServer) config() HTTPLoaderConfig {
	transport, _ := s.Client().Transport.(*http.Transport)
	var tlsConfig *tls.Config
	if transport != nil {
		tlsConfig = transport.TLSClientConfig
	}
	return HTTPLoaderConfig{
		AllowInsecureLoopback: true,
		TLSClientConfig:       tlsConfig,
		Cache:                 NewHTTPEtagCache(),
	}
}

func TestHTTPLoaderFetchesAndParses(t *testing.T) {
	server := newHTTPTestServer(t)
	loaded, err := NewHTTPLoader(server.config())(server.URL+"/base.yaml", "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if stringValue(loaded.Spec.Name) != "remote-base" {
		t.Errorf("name = %q, want remote-base", stringValue(loaded.Spec.Name))
	}
	// The source is the URL, so a detached signature is looked for beside it
	// and a receipt's chain names where the document came from.
	if loaded.Source != server.URL+"/base.yaml" {
		t.Errorf("source = %q, want the URL", loaded.Source)
	}
}

func TestHTTPLoaderRevalidatesWithIfNoneMatch(t *testing.T) {
	server := newHTTPTestServer(t)
	loader := NewHTTPLoader(server.config())
	url := server.URL + "/base.yaml"
	for i := 0; i < 2; i++ {
		loaded, err := loader(url, "")
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		if stringValue(loaded.Spec.Name) != "remote-base" {
			t.Fatalf("load %d returned %q", i, stringValue(loaded.Spec.Name))
		}
	}
	// The server is always asked -- a changed policy is always refetched -- but
	// the second ask carries the etag and comes back 304 with no body.
	if got := server.conditionalRequests(); len(got) != 2 || got[0] != "" || got[1] != `"v1"` {
		t.Errorf("conditional requests = %q, want ['', '\"v1\"']", got)
	}
}

func TestHTTPLoaderWithoutACacheAlwaysRefetches(t *testing.T) {
	server := newHTTPTestServer(t)
	config := server.config()
	config.Cache = nil
	loader := NewHTTPLoader(config)
	for i := 0; i < 2; i++ {
		if _, err := loader(server.URL+"/base.yaml", ""); err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
	}
	for _, conditional := range server.conditionalRequests() {
		if conditional != "" {
			t.Errorf("a loader with no cache sent If-None-Match: %q", conditional)
		}
	}
}

func TestHTTPLoaderRefusesAnOversizedBody(t *testing.T) {
	server := newHTTPTestServer(t)
	_, err := NewHTTPLoader(server.config())(server.URL+"/oversized.yaml", "")
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("an oversized body was accepted: %v", err)
	}
}

func TestHTTPLoaderSizeCapIsConfigurable(t *testing.T) {
	server := newHTTPTestServer(t)
	config := server.config()
	config.MaxSize = 4
	_, err := NewHTTPLoader(config)(server.URL+"/base.yaml", "")
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size of 4 bytes") {
		t.Errorf("the configured cap was not applied: %v", err)
	}
}

func TestHTTPLoaderRefusesARedirect(t *testing.T) {
	server := newHTTPTestServer(t)
	// A 3xx would reissue the request somewhere the scheme, allowlist and
	// address checks never saw.
	_, err := NewHTTPLoader(server.config())(server.URL+"/redirect.yaml", "")
	if err == nil || !strings.Contains(err.Error(), "redirects are not followed") {
		t.Errorf("a redirect was followed: %v", err)
	}
}

func TestHTTPLoaderReportsErrorStatuses(t *testing.T) {
	server := newHTTPTestServer(t)
	loader := NewHTTPLoader(server.config())
	for path, want := range map[string]string{
		"/error.yaml":   "returned status 503",
		"/missing.yaml": "returned status 404",
	} {
		_, err := loader(server.URL+path, "")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("load(%s) = %v, want %q", path, err, want)
		}
	}
}

func TestHTTPLoaderRefusesAnUnparseableBody(t *testing.T) {
	server := newHTTPTestServer(t)
	_, err := NewHTTPLoader(server.config())(server.URL+"/broken.yaml", "")
	if err == nil || !strings.Contains(err.Error(), "failed to parse HushSpec") {
		t.Errorf("an unparseable body was accepted: %v", err)
	}
}

func TestHTTPLoaderSendsTheAuthHeader(t *testing.T) {
	server := newHTTPTestServer(t)
	if _, err := NewHTTPLoader(server.config())(server.URL+"/authed.yaml", ""); err == nil ||
		!strings.Contains(err.Error(), "returned status 401") {
		t.Errorf("an unauthenticated fetch succeeded: %v", err)
	}
	config := server.config()
	config.AuthHeader = "Bearer token"
	if _, err := NewHTTPLoader(config)(server.URL+"/authed.yaml", ""); err != nil {
		t.Errorf("the auth header was not sent: %v", err)
	}
}

func TestHTTPLoaderRefusesANonURLReference(t *testing.T) {
	server := newHTTPTestServer(t)
	_, err := NewHTTPLoader(server.config())("builtin:strict", "")
	if err == nil || !strings.Contains(err.Error(), "only HTTPS URLs are allowed") {
		t.Errorf("the HTTPS loader served a non-URL reference: %v", err)
	}
}

// --------------------------------------------------------------------------
// Detached signatures (signing spec 7.1)
// --------------------------------------------------------------------------

func TestFetchSignature(t *testing.T) {
	server := newHTTPTestServer(t)
	data, found, err := FetchSignature(server.URL+"/base.yaml.sig", server.config())
	if err != nil || !found || string(data) != httpTestSignature {
		t.Fatalf("FetchSignature = (%q, %v, %v), want the sidecar", data, found, err)
	}
}

// TestFetchSidecarFallsBackToTheStemSidecar covers the 0.1 layout that keeps
// `policy.sig` beside `policy.yaml`; the preferred `policy.yaml.sig` is tried
// first (signing spec 7.1).
func TestFetchSidecarFallsBackToTheStemSidecar(t *testing.T) {
	server := newHTTPTestServer(t)
	data, found, err := FetchSidecar(server.URL+"/stem.yaml", server.config())
	if err != nil || !found || string(data) != httpTestSignature {
		t.Fatalf("FetchSidecar = (%q, %v, %v), want the stem sidecar", data, found, err)
	}
	if _, found, err := FetchSidecar(server.URL+"/absent.yaml", server.config()); err != nil || found {
		t.Fatalf("expected no sidecar for an unsigned policy, got found=%v err=%v", found, err)
	}
	if _, found, err := HTTPSignatureLocator(server.config())(server.URL + "/stem.yaml"); err != nil || !found {
		t.Fatalf("the locator must find the stem sidecar, got found=%v err=%v", found, err)
	}
}

func TestPreferredSidecarURLKeepsAQueryAfterTheSuffix(t *testing.T) {
	if got := preferredSidecarURL("https://policies.example/policy.yaml?v=2"); got != "https://policies.example/policy.yaml.sig?v=2" {
		t.Errorf("preferredSidecarURL with a query = %q", got)
	}
	if got := preferredSidecarURL("https://policies.example/policy.yaml"); got != "https://policies.example/policy.yaml.sig" {
		t.Errorf("preferredSidecarURL = %q", got)
	}
}

func TestStemSidecarURLReplacesTheLastExtensionOnly(t *testing.T) {
	cases := map[string]string{
		"https://policies.example/team/policy.yaml": "https://policies.example/team/policy.sig",
		"https://policies.example/policy.yaml?v=2":  "https://policies.example/policy.sig?v=2",
	}
	for source, want := range cases {
		if got, ok := stemSidecarURL(source); !ok || got != want {
			t.Errorf("stemSidecarURL(%q) = (%q, %v), want %q", source, got, ok, want)
		}
	}
	for _, source := range []string{"https://policies.example/policy", "https://policies.example"} {
		if got, ok := stemSidecarURL(source); ok {
			t.Errorf("stemSidecarURL(%q) = %q, want none", source, got)
		}
	}
}

func TestFetchSignatureTreatsAMissingSidecarAsNone(t *testing.T) {
	server := newHTTPTestServer(t)
	// "This policy is unsigned" is a fact the caller decides what to do with.
	data, found, err := FetchSignature(server.URL+"/absent.yaml.sig", server.config())
	if err != nil || found || data != nil {
		t.Errorf("FetchSignature = (%q, %v, %v), want not-found and no error", data, found, err)
	}
}

func TestFetchSignatureStillFailsOnOtherErrors(t *testing.T) {
	server := newHTTPTestServer(t)
	// A 503 says nothing about whether a signature exists, so it is not "none".
	_, _, err := FetchSignature(server.URL+"/error.yaml", server.config())
	if err == nil || !strings.Contains(err.Error(), "returned status 503") {
		t.Errorf("a failing signature fetch was read as unsigned: %v", err)
	}
}

func TestSignatureURLsObeyTheSameRules(t *testing.T) {
	// A `.sig` URL must never reach somewhere the policy URL could not.
	if _, _, err := FetchSignature("https://169.254.169.254/p.yaml.sig", HTTPLoaderConfig{}); err == nil ||
		!strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("a sidecar fetch reached the metadata endpoint: %v", err)
	}
	if _, _, err := FetchSignature("http://example.com/p.yaml.sig", HTTPLoaderConfig{}); err == nil ||
		!strings.Contains(err.Error(), "only HTTPS URLs are allowed") {
		t.Errorf("a sidecar was fetched in the clear: %v", err)
	}
}

// --------------------------------------------------------------------------
// Registering the scheme with the resolver
// --------------------------------------------------------------------------

func TestTheCompositeLoaderRefusesURLsUntilASchemeIsInstalled(t *testing.T) {
	_, err := createCompositeLoader()("https://policies.invalid/base.yaml", "")
	if err == nil || !strings.Contains(err.Error(), "InstallHTTPSLoader") {
		t.Errorf("a URL was served without a registered transport: %v", err)
	}
}

func TestInstallHTTPSLoaderTeachesTheCompositeLoader(t *testing.T) {
	server := newHTTPTestServer(t)
	InstallHTTPSLoader(server.config())
	t.Cleanup(func() {
		UnregisterSchemeLoader("https")
		UnregisterSchemeLoader("http")
	})

	url := server.URL + "/base.yaml"
	loaded, err := createCompositeLoader()(url, "")
	if err != nil {
		t.Fatalf("the composite loader did not serve the URL: %v", err)
	}
	if stringValue(loaded.Spec.Name) != "remote-base" {
		t.Errorf("name = %q, want remote-base", stringValue(loaded.Spec.Name))
	}

	// And the default signature locator now finds `<url>.sig`.
	data, found, err := DefaultSignatureLocator(url)
	if err != nil || !found || string(data) != httpTestSignature {
		t.Errorf("DefaultSignatureLocator = (%q, %v, %v), want the sidecar", data, found, err)
	}
	if _, found, err := DefaultSignatureLocator(server.URL + "/absent.yaml"); err != nil || found {
		t.Errorf("a missing sidecar was reported as found: %v", err)
	}
	// A builtin never looks for a remote signature.
	if _, found, _ := DefaultSignatureLocator("builtin:strict"); found {
		t.Errorf("a builtin reported a detached signature")
	}
}

func TestUnregisterSchemeLoaderRestoresTheRefusal(t *testing.T) {
	server := newHTTPTestServer(t)
	InstallHTTPSLoader(server.config())
	UnregisterSchemeLoader("https")
	UnregisterSchemeLoader("http")
	_, err := createCompositeLoader()(server.URL+"/base.yaml", "")
	if err == nil || !strings.Contains(err.Error(), "InstallHTTPSLoader") {
		t.Errorf("the refusal was not restored: %v", err)
	}
}

func TestNewDefaultLoaderStillServesBuiltinsAndFiles(t *testing.T) {
	server := newHTTPTestServer(t)
	loader := NewDefaultLoader(server.config())
	builtin, err := loader("builtin:strict", "")
	if err != nil || builtin.Source != "builtin:strict" {
		t.Fatalf("the default loader lost builtins: %v", err)
	}
	remote, err := loader(server.URL+"/base.yaml", "")
	if err != nil || stringValue(remote.Spec.Name) != "remote-base" {
		t.Fatalf("the default loader did not serve the URL: %v", err)
	}
}

// --------------------------------------------------------------------------
// HTTPProvider
// --------------------------------------------------------------------------

func TestHTTPProviderLoads(t *testing.T) {
	server := newHTTPTestServer(t)
	provider := NewHTTPProvider(server.URL+"/base.yaml", server.config(), ResolveOptions{})
	resolution, err := provider.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if stringValue(resolution.Spec.Name) != "remote-base" {
		t.Errorf("name = %q, want remote-base", stringValue(resolution.Spec.Name))
	}
	if provider.Source() != server.URL+"/base.yaml" {
		t.Errorf("source = %q, want the URL", provider.Source())
	}
	if len(resolution.Chain) != 1 || resolution.Chain[0].Source != provider.Source() {
		t.Errorf("chain = %+v, want one link naming the URL", resolution.Chain)
	}
	if want, _ := ContentHash(resolution.Spec); resolution.ContentHash != want {
		t.Errorf("content hash = %q, want %q", resolution.ContentHash, want)
	}
}

func TestHTTPProviderRefetchesOnEveryLoad(t *testing.T) {
	server := newHTTPTestServer(t)
	provider := NewHTTPProvider(server.URL+"/base.yaml", server.config(), ResolveOptions{})
	for i := 0; i < 2; i++ {
		if _, err := provider.Load(); err != nil {
			t.Fatalf("Load %d: %v", i, err)
		}
	}
	// Always ask; the etag means the second ask costs no body.
	if got := server.conditionalRequests(); len(got) != 2 || got[1] != `"v1"` {
		t.Errorf("conditional requests = %q, want the second to revalidate", got)
	}
}

func TestHTTPProviderResolvesABuiltinBase(t *testing.T) {
	server := newHTTPTestServer(t)
	provider := NewHTTPProvider(server.URL+"/extends-builtin.yaml", server.config(), ResolveOptions{})
	resolution, err := provider.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if resolution.Spec.Extends != nil {
		t.Errorf("the resolved policy still declares extends")
	}
	want := []string{"builtin:strict", server.URL + "/extends-builtin.yaml"}
	for i, link := range resolution.Chain {
		if link.Source != want[i] {
			t.Errorf("chain[%d].source = %q, want %q", i, link.Source, want[i])
		}
	}
}

func TestHTTPProviderRefusesARemoteBase(t *testing.T) {
	server := newHTTPTestServer(t)
	// A base named from a document that itself came over the network is a
	// second location the deployment never named: fail closed.
	provider := NewHTTPProvider(server.URL+"/extends-remote.yaml", server.config(), ResolveOptions{})
	_, err := provider.Load()
	if err == nil || !strings.Contains(err.Error(), "failed to resolve 'extends:") {
		t.Errorf("a remote base was merged: %v", err)
	}
}

func TestHTTPProviderCarriesTheSSRFRules(t *testing.T) {
	provider := NewHTTPProvider("https://169.254.169.254/p.yaml", HTTPLoaderConfig{}, ResolveOptions{})
	if _, err := provider.Load(); err == nil || !strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("the provider reached the metadata endpoint: %v", err)
	}
	insecure := NewHTTPProvider("http://example.com/p.yaml", HTTPLoaderConfig{}, ResolveOptions{})
	if _, err := insecure.Load(); err == nil ||
		!strings.Contains(err.Error(), "only HTTPS URLs are allowed") {
		t.Errorf("the provider fetched in the clear: %v", err)
	}
}

func TestHTTPProviderSatisfiesThePolicyProviderInterface(t *testing.T) {
	var _ PolicyProvider = NewHTTPProvider("https://policies.invalid/p.yaml",
		HTTPLoaderConfig{}, ResolveOptions{})
}

// --------------------------------------------------------------------------
// Digest pinning over the network (core spec 2.3)
// --------------------------------------------------------------------------
//
// A URL is a location, never an identity. What makes a remote base trustworthy
// is the `#sha256:` pin on the reference, which the resolver strips before the
// loader sees it and checks against what came back -- so pinning has to work
// over HTTPS exactly as it does for a file, with no help from the loader.

func pinnedLeaf(t *testing.T, url, digest string) *HushSpec {
	t.Helper()
	spec, err := Parse(fmt.Sprintf(
		"hushspec: \"0.2.0\"\nname: pinned-leaf\nextends: %q\n", url+"#"+digest))
	if err != nil {
		t.Fatalf("parse the pinned leaf: %v", err)
	}
	return spec
}

func TestAMatchingDigestPinResolvesOverHTTPS(t *testing.T) {
	server := newHTTPTestServer(t)
	loader := NewHTTPLoader(server.config())
	url := server.URL + "/base.yaml"

	loaded, err := loader(url, "")
	if err != nil {
		t.Fatalf("load the base: %v", err)
	}
	pin, err := OwnContentHash(loaded.Spec)
	if err != nil {
		t.Fatalf("hash the base: %v", err)
	}

	resolution, err := ResolveWithOptions(
		pinnedLeaf(t, url, pin), MemorySource, loader, ResolveOptions{})
	if err != nil {
		t.Fatalf("a matching pin was rejected: %v", err)
	}
	if resolution.Chain[0].Source != url || stringValue(resolution.Spec.Name) != "pinned-leaf" {
		t.Errorf("resolution = %+v, want the pinned base merged under the leaf", resolution.Chain)
	}
}

func TestAMismatchedDigestPinIsFatalOverHTTPS(t *testing.T) {
	server := newHTTPTestServer(t)
	url := server.URL + "/base.yaml"
	_, err := ResolveWithOptions(
		pinnedLeaf(t, url, "sha256:"+strings.Repeat("0", 64)),
		MemorySource, NewHTTPLoader(server.config()), ResolveOptions{})
	reason, ok := ResolveReason(err)
	if !ok || reason != ReasonDigestMismatch {
		t.Errorf("a mismatched pin resolved: err=%v reason=%q", err, reason)
	}
}

// TestAStrayServerNameDoesNotMoveTheCertificateCheck pins which name the
// certificate is checked against. The transport dials the vetted address, so
// the only thing naming the certificate is ServerName -- and it has to come
// from the URL, never from the caller's TLS config, or a policy server could
// be reached with a certificate issued for something else entirely. The
// config here carries a name the test server's certificate does not cover: the
// load must still succeed, which it can only do if the name was dropped.
func TestAStrayServerNameDoesNotMoveTheCertificateCheck(t *testing.T) {
	server := newHTTPTestServer(t)
	config := server.config()
	config.TLSClientConfig = config.TLSClientConfig.Clone()
	config.TLSClientConfig.ServerName = "elsewhere.invalid"

	if _, err := NewHTTPLoader(config)(server.URL+"/base.yaml", ""); err != nil {
		t.Fatalf("a stray ServerName reached the handshake: %v", err)
	}
	// And the caller's own config is left as it was.
	if config.TLSClientConfig.ServerName != "elsewhere.invalid" {
		t.Error("the loader mutated the caller's TLS config")
	}
}

// --------------------------------------------------------------------------
// The ETag cache
// --------------------------------------------------------------------------

// TestHTTPEtagCacheIsBounded pins the eviction rule. A URL comes out of a
// document and a body may be [DefaultHTTPMaxSize], so an unbounded map keyed on
// one is a memory-exhaustion primitive; past the bound the oldest entry goes,
// which costs a full body on the next fetch of that URL and nothing else.
func TestHTTPEtagCacheIsBounded(t *testing.T) {
	cache := &HTTPEtagCache{MaxEntries: 3}
	for index := 0; index < 5; index++ {
		cache.Put(fmt.Sprintf("https://policies.example/%d.yaml", index),
			fmt.Sprintf("%q", fmt.Sprintf("v%d", index)), httpTestPolicy)
	}
	for _, evicted := range []string{"0", "1"} {
		if _, _, ok := cache.Get("https://policies.example/" + evicted + ".yaml"); ok {
			t.Errorf("entry %s should have been evicted", evicted)
		}
	}
	etag, body, ok := cache.Get("https://policies.example/4.yaml")
	if !ok || etag != `"v4"` || body != httpTestPolicy {
		t.Errorf("newest entry = (%q, %q, %v), want the policy under v4", etag, body, ok)
	}
}

// TestHTTPEtagCacheRewriteDoesNotCountTwice covers the other half of the bound:
// revalidating a URL already held replaces it in place rather than pushing an
// older, still-live entry out.
func TestHTTPEtagCacheRewriteDoesNotCountTwice(t *testing.T) {
	cache := &HTTPEtagCache{MaxEntries: 2}
	cache.Put("https://policies.example/a.yaml", `"v1"`, httpTestPolicy)
	for revision := 0; revision < 5; revision++ {
		cache.Put("https://policies.example/b.yaml",
			fmt.Sprintf("%q", fmt.Sprintf("v%d", revision)), httpTestPolicy)
	}
	if _, _, ok := cache.Get("https://policies.example/a.yaml"); !ok {
		t.Error("the older entry should still be held")
	}
	if etag, _, _ := cache.Get("https://policies.example/b.yaml"); etag != `"v4"` {
		t.Errorf("etag = %q, want the latest", etag)
	}
}
