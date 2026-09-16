package hushspec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Policy resolution, verification on load, and digest pinning
// (spec/hushspec-signing.md sections 6.5 and 7.1, spec/hushspec-receipt.md
// section 4.2).
//
// Resolution flattens an `extends` chain into the single document an engine
// enforces. That merge is a trust decision: every hop contributes rules, so a
// base policy fetched from somewhere untrusted can silently relax the leaf.
// Signing section 6.5 therefore requires an enforcement point configured with
// `require_signature` to cover *every* hop loaded from an untrusted source,
// not just the leaf.
//
// Two mechanisms satisfy a hop, and a hop needs only one of them:
//
//   - A detached signature ([ResolveOptions.SignatureLocator] finds the `.sig`
//     file, [VerifyPolicy] checks it against the keyring).
//   - A digest pin written into the reference itself:
//     `extends: "base.yaml#sha256:<64 hex>"`. The child names the exact bytes
//     it was authored against, so a changed base is rejected without any key
//     material. A pin is checked *always*, signatures or not: a mismatched
//     pin is a rejected resolution even for a caller that never asked for
//     signature checks, because the child has stated what it expects and the
//     loader found something else.
//
// `builtin:` hops are embedded in this binary and need neither (section 6.5).
//
// [Resolution] records what happened so a receipt can carry it: the resolved
// document's content hash, the chain root first and leaf last with each hop's
// own hash, and the signature outcome per hop. Receipt section 4.2 defines a
// hop's hash as that document canonicalized *on its own*, with its own
// `extends` and `merge_strategy` stripped -- an auditor can then confirm a
// specific base was in force without re-resolving anything.

// LoadedSpec pairs a parsed HushSpec with the canonical path it was loaded from.
type LoadedSpec struct {
	Source string
	Spec   *HushSpec
}

// maxExtendsDepth caps the length of an extends chain. Cycle detection only
// catches an exact repeat of a prior source; a long but acyclic chain would
// otherwise recurse without bound and overflow the stack. 32 is far above
// any realistic composition depth (shipped policies are depth <= 2).
const maxExtendsDepth = 32

// ReasonDigestMismatch is the reason code for a hop whose loaded document does
// not hash to the digest its referrer pinned. It is a resolver-level code:
// spec/hushspec-signing.md section 6.4 enumerates the envelope checks, and a
// digest pin is checked before and independently of any envelope.
const ReasonDigestMismatch = "digest_mismatch"

// ReasonMissingSignature is the reason code recorded for a hop that required a
// signature and had none to check: no `.sig` file was found next to it and it
// carried no digest pin. Also a resolver-level code.
const ReasonMissingSignature = "missing_signature"

// ReasonNoKeyring is recorded when a detached envelope was found but no
// keyring was configured to check it against (signing spec section 6.5).
const ReasonNoKeyring = "no_keyring"

// ResolveLoader loads a HushSpec referenced by an extends field.
// reference is the extends value with any digest pin already stripped; from is
// the source of the referencing document.
type ResolveLoader func(reference string, from string) (*LoadedSpec, error)

// SignatureLocator finds the detached signature envelope for a document the
// resolver loaded. source is the source string as the loader reported it.
//
// It reports (bytes, true, nil) when an envelope was found, (nil, false, nil)
// when the document simply has no signature, and an error only when a
// candidate location existed but could not be read -- an error fails the whole
// resolution, so a locator must not turn "absent" into one.
type SignatureLocator func(source string) ([]byte, bool, error)

// ResolveOptions configures verification on load. The zero value reproduces
// the unverified resolver: chain hops are merged, digest pins are still
// enforced, and no signature is looked for.
type ResolveOptions struct {
	// RequireSignature makes resolution fail closed unless every non-`builtin:`
	// hop is satisfied -- by a matching digest pin, or by a detached envelope
	// that verifies valid against the keyring (spec section 6.5). The failure
	// is a [SignatureRequiredError] naming the first unsatisfied hop.
	RequireSignature bool
	// Keyring is the set of trusted keys. It overrides Verify.Keyring when
	// both are set. A nil Keyring with no Verify.Keyring and no
	// Verify.PublicKeyPEM means no key is trusted, so under RequireSignature
	// only digest pins can satisfy a hop.
	Keyring *Keyring
	// Verify carries the remaining verifier inputs of spec section 6.1: Now,
	// MaxClockSkewSeconds and LastSeenVersion. LastSeenVersion is applied to
	// every hop that is verified, so a caller that tracks versions per policy
	// name should set it only when the chain has one relevant policy name.
	Verify VerifyOptions
	// SignatureLocator finds each hop's detached envelope. Nil means
	// [DefaultSignatureLocator].
	SignatureLocator SignatureLocator
}

// SignatureStatus is the outcome of signature verification for one document,
// shaped for `receipt.policy.signature` (spec/hushspec-receipt.md section 4.2
// and $defs.SignatureStatus of the 0.2 receipt schema).
//
// Verified is true only when an envelope was present, its key was in the
// trusted keyring, and every check of signing section 6.2 passed. Reason
// carries the first failed check's code and is empty exactly when Verified is
// true.
//
// VerifiedAt records when the *verifier* ran, not when the signer signed: the
// envelope's own `signed_at` is a claim of the signer, trustworthy only once
// Verified is true, so the schema records the verifier's clock instead. It is
// set only on success.
type SignatureStatus struct {
	Verified   bool   `json:"verified"`
	KeyID      string `json:"key_id,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// FailedSignature is the status recorded for a document whose verification
// failed at the check named by reason.
//
// keyID is what the envelope *claimed*, which is worth recording even though
// nothing about it was trusted -- it is how a rotation mistake stays
// distinguishable from an attack. It is dropped unless it is a well-formed
// key id: the receipt schema admits only `sha256:` plus 64 lowercase hex, and
// an envelope that failed its own shape check may carry anything at all.
func FailedSignature(reason, keyID string) SignatureStatus {
	if !digestPinPattern.MatchString(keyID) {
		keyID = ""
	}
	return SignatureStatus{Verified: false, KeyID: keyID, Reason: reason}
}

// ChainLink is one document of a resolved `extends` chain, shaped for
// `receipt.policy.extends_chain[]` (spec/hushspec-receipt.md section 4.2).
//
// ContentHash is the hash of *this document alone*, canonicalized with its own
// `extends` and `merge_strategy` stripped -- not the hash of the chain merged
// up to this point. Signature is nil when verification was not attempted for
// the hop (no keys configured, or a `builtin:` source).
type ChainLink struct {
	Source      string           `json:"source"`
	ContentHash string           `json:"content_hash"`
	Signature   *SignatureStatus `json:"signature,omitempty"`
}

// Resolution is the result of [ResolveWithOptions]: the document to enforce
// plus the evidence about where it came from. It is an in-memory result, not a
// wire type; a receipt builder copies Chain and Signature into the receipt's
// policy summary.
//
// Chain is ordered root first, leaf last, and always contains at least the
// leaf. A receipt records `extends_chain` only when the policy actually
// extended something, that is when len(Chain) > 1.
//
// Signature is the leaf's outcome -- what `receipt.policy.signature` carries.
// It is nil when verification was not attempted.
type Resolution struct {
	// Spec is the merged document: resolution consumes `extends` and
	// `merge_strategy`, so neither is ever set on it (core spec 2.3).
	Spec        *HushSpec
	ContentHash string
	Chain       []ChainLink
	Signature   *SignatureStatus
}

// MemorySource is the source recorded for a document that was not loaded from
// anywhere -- one the caller built or parsed in memory. The resolve vectors
// (fixtures/core/resolve) pin it as the leaf's chain source, so every SDK
// spells an in-memory leaf the same way.
const MemorySource = "memory"

// NewResolutionFromResolved wraps a document that is already resolved (no
// `extends`) as a single-link resolution, which is what a receipt builder
// needs for a policy it did not load through the resolver. source names the
// document in the chain; "" means [MemorySource].
func NewResolutionFromResolved(spec *HushSpec, source string) (*Resolution, error) {
	if spec == nil {
		return nil, errors.New("cannot resolve a nil HushSpec document")
	}
	if source == "" {
		source = MemorySource
	}
	contentHash, err := ContentHash(spec)
	if err != nil {
		return nil, fmt.Errorf("no canonical form for %s: %w", describeSource(source), err)
	}
	return &Resolution{
		// A resolution's document carries no resolution instructions, however
		// it was obtained: ContentHash above already refused a lingering
		// `extends`, and `merge_strategy` is inert here (core spec 2.3).
		Spec:        resolvedDocument(spec),
		ContentHash: contentHash,
		Chain:       []ChainLink{{Source: source, ContentHash: contentHash}},
	}, nil
}

// HadExtends reports whether the policy was produced by merging an `extends`
// chain. A receipt records `extends_chain` only then (receipt spec 4.2).
func (r *Resolution) HadExtends() bool {
	return r != nil && len(r.Chain) > 1
}

// OwnContentHash is the content hash of a single chain document on its own,
// canonicalized with its `extends` and `merge_strategy` stripped (receipt spec
// 4.2) -- the value a `#sha256:` digest pin names (core spec 2.3).
func OwnContentHash(spec *HushSpec) (string, error) {
	return hopContentHash(spec)
}

// Resolver-level reason codes. spec/hushspec-signing.md section 6.4 enumerates
// the envelope checks; these name the failures resolution itself can report,
// and are the vocabulary the fixtures/core/resolve vectors use.
const (
	// ReasonInvalidPin is a `#...` fragment on an `extends` reference that is
	// not a well-formed `sha256:<64 lowercase hex>` digest.
	ReasonInvalidPin = "invalid_pin"
	// ReasonNotFound is a reference no loader could serve.
	ReasonNotFound = "not_found"
	// ReasonCycle is an extends chain that revisits a document.
	ReasonCycle = "cycle"
	// ReasonMaxDepth is an extends chain longer than [maxExtendsDepth].
	ReasonMaxDepth = "max_depth"
)

// InvalidPinError reports an `extends` reference whose digest-pin fragment is
// not a well-formed content hash. It is raised before anything is loaded: a
// fragment that looks like a pin but is malformed must never be guessed at.
type InvalidPinError struct {
	Reference string
	Message   string
}

func (e *InvalidPinError) Error() string {
	return fmt.Sprintf("invalid digest pin on %q: %s", e.Reference, e.Message)
}

// NotFoundError reports a reference no loader could serve. A dangling
// `extends` is never resolved as the leaf alone -- that would silently enforce
// a policy missing everything its base contributed.
type NotFoundError struct {
	Reference string
	Message   string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("could not resolve reference %q: %s", e.Reference, e.Message)
}

// CycleError reports an extends chain that revisits a document.
type CycleError struct {
	Chain string
}

func (e *CycleError) Error() string {
	return "circular extends detected: " + e.Chain
}

// MaxDepthError reports an extends chain longer than the depth cap.
type MaxDepthError struct{}

func (e *MaxDepthError) Error() string {
	return fmt.Sprintf("extends chain exceeds maximum depth of %d", maxExtendsDepth)
}

// ResolveReason maps a resolution failure onto its reason code, so a vector
// runner or a CLI reports the same vocabulary the spec uses. It reports false
// for an error that carries no code of its own (an I/O or parse failure).
//
// The codes below are the ones only the walk can produce; everything a
// verifier also produces comes from [ReasonFromError], so one error never
// reports two different codes depending on which helper read it.
func ResolveReason(err error) (string, bool) {
	var pinErr *InvalidPinError
	if errors.As(err, &pinErr) {
		return ReasonInvalidPin, true
	}
	var notFoundErr *NotFoundError
	if errors.As(err, &notFoundErr) {
		return ReasonNotFound, true
	}
	var cycleErr *CycleError
	if errors.As(err, &cycleErr) {
		return ReasonCycle, true
	}
	var depthErr *MaxDepthError
	if errors.As(err, &depthErr) {
		return ReasonMaxDepth, true
	}
	return ReasonFromError(err)
}

// SignatureRequiredError reports the first chain hop that [ResolveOptions]
// required a signature for and that could not be satisfied. Status is what a
// receipt should record for the refusal: Verified is false and Reason names
// the failed check, or [ReasonMissingSignature] when there was no envelope at
// all.
type SignatureRequiredError struct {
	Source string
	Status SignatureStatus
}

func (e *SignatureRequiredError) Error() string {
	reason := e.Status.Reason
	if reason == "" {
		reason = ReasonMissingSignature
	}
	return fmt.Sprintf(
		"policy signature required but not valid for %s (%s)",
		describeSource(e.Source), reason,
	)
}

// DigestMismatchError reports a hop whose loaded document does not hash to the
// digest its referrer pinned. Expected is the pinned value, Actual the hash of
// what the loader returned -- both "sha256:"-prefixed content hashes.
type DigestMismatchError struct {
	Source   string
	Expected string
	Actual   string
}

func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf(
		"digest pin mismatch (%s) for %s: pinned %s, loaded %s",
		ReasonDigestMismatch, describeSource(e.Source), e.Expected, e.Actual,
	)
}

// Resolve flattens the extends chain of a parsed HushSpec by repeatedly loading
// and merging parent documents via the provided loader.
//
// It is [ResolveWithOptions] with default options: no signature is looked for,
// but digest pins in `extends` references are still enforced.
func Resolve(spec *HushSpec, source string, loader ResolveLoader) (*HushSpec, error) {
	if spec == nil {
		return nil, nil
	}
	resolution, err := resolveChain(spec, source, loader, ResolveOptions{}, false)
	if err != nil {
		return nil, err
	}
	return resolution.Spec, nil
}

// ResolveFile loads a HushSpec from disk and flattens its extends chain.
func ResolveFile(path string) (*HushSpec, error) {
	spec, source, err := loadSpecFile(path)
	if err != nil {
		return nil, err
	}
	return Resolve(spec, source, createCompositeLoader())
}

// ResolveFileWithOptions loads a HushSpec from disk and resolves it under opts,
// which is the shape a verify-on-load caller wants: the returned
// [Resolution.Spec] is the document to enforce, and the rest is the evidence to
// record. The leaf's own path is the source, so the default signature locator
// looks for its `.sig` sidecar.
func ResolveFileWithOptions(path string, opts ResolveOptions) (*Resolution, error) {
	spec, source, err := loadSpecFile(path)
	if err != nil {
		return nil, err
	}
	return ResolveWithOptions(spec, source, createCompositeLoader(), opts)
}

// ResolveWithOptions flattens an extends chain, enforcing digest pins and (when
// opts asks for it) signatures on every hop, and returns the resolved document
// together with the chain evidence.
//
// source is the leaf's source as the caller knows it -- a path for a document
// read from disk, "" for one built in memory. It is what the loader resolves
// relative references against and what the signature locator is given, so a
// leaf resolved with an empty source can carry no detached signature and fails
// closed under RequireSignature.
//
// A nil loader means the composite loader: `builtin:` from the embedded
// rulesets, everything else from the filesystem.
func ResolveWithOptions(spec *HushSpec, source string, loader ResolveLoader, opts ResolveOptions) (*Resolution, error) {
	if spec == nil {
		return nil, errors.New("cannot resolve a nil HushSpec document")
	}
	return resolveChain(spec, source, loader, opts, true)
}

// DefaultSignatureLocator reads a detached envelope from beside the policy
// file, per spec/hushspec-signing.md section 7.1: `<path>.sig` first, then the
// 0.1-compatible `<stem>.sig` (so `policy.yaml` is matched by both
// `policy.yaml.sig` and `policy.sig`, preferring the former).
//
// `builtin:` sources have no sidecar and report not-found. A URL source is
// `<url>.sig`, fetched by whatever [RegisterSchemeLoader] installed for its
// scheme -- fetching a signature over the network must happen under the same
// rules as fetching the policy did, so it belongs to the transport rather than
// here. With no transport registered a URL source reports not-found, exactly as
// a reference to one would be refused. Not-found is not silently permissive --
// under [ResolveOptions.RequireSignature] an unpinned hop with no envelope
// fails.
func DefaultSignatureLocator(source string) ([]byte, bool, error) {
	switch {
	case source == "",
		source == MemorySource,
		strings.HasPrefix(source, "builtin:"):
		return nil, false, nil
	}

	if locator, ok := locatorForScheme(source); ok {
		return locator(source)
	}
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		return nil, false, nil
	}

	for _, candidate := range signatureSidecarPaths(source) {
		data, err := os.ReadFile(candidate)
		if err == nil {
			return data, true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, false, fmt.Errorf("failed to read signature %s: %w", candidate, err)
		}
	}
	return nil, false, nil
}

// signatureSidecarPaths lists the detached-signature locations for a policy
// path in lookup order (spec section 7.1).
func signatureSidecarPaths(path string) []string {
	appended := path + ".sig"
	stem := strings.TrimSuffix(path, filepath.Ext(path)) + ".sig"
	if stem == appended || filepath.Ext(path) == "" {
		return []string{appended}
	}
	return []string{appended, stem}
}

// schemeLoaders holds the loaders registered for URL schemes, and the
// signature locators that go with them. A transport lives outside this file --
// http_loader.go is the one this SDK ships -- and registers itself here, so the
// built-in loaders gain a scheme without this file growing a network client.
// Empty until something registers, which is why a URL reference is refused by
// default.
var schemeLoaders = struct {
	sync.RWMutex
	loaders  map[string]ResolveLoader
	locators map[string]SignatureLocator
}{
	loaders:  map[string]ResolveLoader{},
	locators: map[string]SignatureLocator{},
}

// RegisterSchemeLoader serves `<scheme>://` references through loader in the
// loaders [ResolveFile] and [NewFileProvider] use by default.
//
// Registering a scheme is a deployment decision, never a document's: a policy
// that names an `https:` base is refused until the process loading it has said
// that fetching over the network is acceptable.
//
// locator, when non-nil, is consulted by [DefaultSignatureLocator] for sources
// with this scheme, so a transport that can fetch a policy can also fetch the
// `<source>.sig` beside it (signing spec 7.1).
func RegisterSchemeLoader(scheme string, loader ResolveLoader, locator SignatureLocator) {
	schemeLoaders.Lock()
	defer schemeLoaders.Unlock()
	schemeLoaders.loaders[scheme] = loader
	if locator != nil {
		schemeLoaders.locators[scheme] = locator
	} else {
		delete(schemeLoaders.locators, scheme)
	}
}

// UnregisterSchemeLoader undoes [RegisterSchemeLoader], restoring the refusal.
func UnregisterSchemeLoader(scheme string) {
	schemeLoaders.Lock()
	defer schemeLoaders.Unlock()
	delete(schemeLoaders.loaders, scheme)
	delete(schemeLoaders.locators, scheme)
}

// referenceScheme is the URL scheme of a reference, or "" when it is not a URL.
func referenceScheme(reference string) string {
	scheme, _, found := strings.Cut(reference, "://")
	if !found || scheme == "" {
		return ""
	}
	return scheme
}

// loaderForScheme is the loader registered for a reference's scheme, if any.
func loaderForScheme(reference string) (ResolveLoader, bool) {
	scheme := referenceScheme(reference)
	if scheme == "" {
		return nil, false
	}
	schemeLoaders.RLock()
	defer schemeLoaders.RUnlock()
	loader, ok := schemeLoaders.loaders[scheme]
	return loader, ok
}

// locatorForScheme is the signature locator registered for a source's scheme.
func locatorForScheme(source string) (SignatureLocator, bool) {
	scheme := referenceScheme(source)
	if scheme == "" {
		return nil, false
	}
	schemeLoaders.RLock()
	defer schemeLoaders.RUnlock()
	locator, ok := schemeLoaders.locators[scheme]
	return locator, ok
}

// createCompositeLoader serves `builtin:<name>` references from the embedded
// rulesets and everything else from the filesystem. A bare name with no path
// separators or dots is tried as a builtin before falling back to the
// filesystem.
func createCompositeLoader() ResolveLoader {
	return func(reference string, from string) (*LoadedSpec, error) {
		if strings.HasPrefix(reference, "builtin:") {
			spec, ok := LoadBuiltin(reference)
			if !ok {
				return nil, &NotFoundError{
					Reference: reference,
					Message:   "unknown builtin ruleset",
				}
			}
			return &LoadedSpec{Source: reference, Spec: spec}, nil
		}

		if loader, ok := loaderForScheme(reference); ok {
			return loader(reference, from)
		}

		// Reject HTTP(S) references explicitly rather than letting them fall
		// through to the filesystem loader, which would try to open a file
		// literally named "https://...". No transport is registered, so say so
		// plainly.
		if strings.HasPrefix(reference, "https://") || strings.HasPrefix(reference, "http://") {
			return nil, fmt.Errorf(
				"HTTP-based policy loading is not supported by the composite loader "+
					"until InstallHTTPSLoader is called: %q", reference)
		}

		if !strings.ContainsAny(reference, `/\.`) {
			if spec, ok := LoadBuiltin(reference); ok {
				return &LoadedSpec{Source: "builtin:" + reference, Spec: spec}, nil
			}
		}

		return loadFromFilesystem(reference, from)
	}
}

// resolveHop is one document of the chain, with the pin its referrer declared
// for it ("" when unpinned; the leaf is never pinned because nothing refers to
// it).
type resolveHop struct {
	source string
	spec   *HushSpec
	pin    string
}

// resolveChain walks the extends chain leaf-to-root, then merges and verifies
// root-to-leaf.
//
// withHashes distinguishes the two entry points. [ResolveWithOptions] needs
// every hop's hash and the resolved hash for its evidence; plain [Resolve]
// needs neither, and hashing there would add a failure mode (canonicalization
// can refuse a document) to a call that never had one. Pinned hops are hashed
// either way -- a pin is checked always.
func resolveChain(
	spec *HushSpec,
	source string,
	loader ResolveLoader,
	opts ResolveOptions,
	withHashes bool,
) (*Resolution, error) {
	if loader == nil {
		loader = createCompositeLoader()
	}
	locate := opts.SignatureLocator
	if locate == nil {
		locate = DefaultSignatureLocator
	}
	verifyOpts, verifyEnabled := opts.verifyOptions()

	hops, err := collectHops(spec, source, loader)
	if err != nil {
		return nil, err
	}

	resolution := &Resolution{Chain: make([]ChainLink, 0, len(hops))}
	var resolved *HushSpec
	for index, hop := range hops {
		// The hop's own hash: this document canonicalized alone, with
		// `extends` and `merge_strategy` stripped (receipt section 4.2). It is
		// what a digest pin names and what the chain link records.
		var own string
		if withHashes || hop.pin != "" {
			own, err = hopContentHash(hop.spec)
			if err != nil {
				return nil, fmt.Errorf("failed to hash %s: %w", describeSource(hop.source), err)
			}
		}
		if hop.pin != "" && hop.pin != own {
			return nil, &DigestMismatchError{Source: hop.source, Expected: hop.pin, Actual: own}
		}

		// Merge as we descend so `resolved` is exactly this hop's own resolved
		// document: that is what its signature covers (the signature is over
		// the resolved content hash, spec section 3), and at the leaf it is
		// the document the caller will enforce.
		if index == 0 {
			// The root is cleaned on the way in: a resolved document declares
			// neither resolution field (core spec 2.3), Merge clears both for
			// every longer chain, and a one-hop chain never reaches Merge.
			resolved = resolvedDocument(hop.spec)
		} else {
			resolved = Merge(resolved, hop.spec)
		}

		var status *SignatureStatus
		if verifyEnabled && !strings.HasPrefix(hop.source, "builtin:") {
			status, err = verifyHopSignature(hop.source, resolved, locate, verifyOpts)
			if err != nil {
				return nil, err
			}
			// Verification was attempted, so the outcome is always recorded
			// (signing spec section 6.5): a hop with no envelope carries
			// missing_signature rather than "nothing was checked".
			if status == nil {
				failed := FailedSignature(ReasonMissingSignature, "")
				status = &failed
			}
			// A matching pin satisfies the hop on its own; otherwise the hop
			// needs an envelope that verified valid.
			if opts.RequireSignature && hop.pin == "" && !status.Verified {
				return nil, &SignatureRequiredError{Source: hop.source, Status: *status}
			}
		}

		resolution.Chain = append(resolution.Chain, ChainLink{
			Source:      hop.source,
			ContentHash: own,
			Signature:   status,
		})
		resolution.Signature = status
	}

	resolution.Spec = resolved
	if withHashes {
		resolution.ContentHash, err = ContentHash(resolved)
		if err != nil {
			return nil, fmt.Errorf("failed to hash the resolved policy: %w", err)
		}
	}
	return resolution, nil
}

// collectHops walks `extends` from the leaf to the root and returns the chain
// root first, leaf last. It enforces cycle detection and the depth cap before
// anything is hashed or verified.
func collectHops(spec *HushSpec, source string, loader ResolveLoader) ([]resolveHop, error) {
	if source == "" {
		source = MemorySource
	}
	hops := []resolveHop{{source: source, spec: spec}}

	stack := []string{source}

	current, currentSource := spec, source
	for depth := 0; current.Extends != nil; depth++ {
		// Cycle detection only catches an exact repeat of a prior source; a
		// long acyclic chain would otherwise recurse without bound. Fail
		// closed with a clean error before doing any further loading once the
		// cap is hit.
		if depth >= maxExtendsDepth {
			return nil, &MaxDepthError{}
		}

		reference, pin, err := splitDigestPin(*current.Extends)
		if err != nil {
			return nil, err
		}

		// A document built in memory resolves relative references against the
		// process's working directory, exactly as an empty source did.
		from := currentSource
		if from == MemorySource {
			from = ""
		}
		loaded, err := loader(reference, from)
		if err != nil {
			return nil, err
		}
		if loaded == nil || loaded.Spec == nil {
			return nil, fmt.Errorf("loader returned no document for extends %q", reference)
		}

		for index, entry := range stack {
			if entry == loaded.Source {
				cycle := append(slices.Clone(stack[index:]), loaded.Source)
				return nil, &CycleError{Chain: strings.Join(cycle, " -> ")}
			}
		}

		stack = append(stack, loaded.Source)
		hops = append(hops, resolveHop{source: loaded.Source, spec: loaded.Spec, pin: pin})
		current, currentSource = loaded.Spec, loaded.Source
	}

	slices.Reverse(hops)
	return hops, nil
}

// verifyHopSignature locates and checks one hop's detached envelope against
// resolved, the hop's own resolved document. A hop with no envelope yields a
// nil status: "nothing was checked", which the caller turns into a refusal only
// when signatures are required.
func verifyHopSignature(
	source string,
	resolved *HushSpec,
	locate SignatureLocator,
	opts VerifyOptions,
) (*SignatureStatus, error) {
	data, found, err := locate(source)
	if err != nil {
		return nil, fmt.Errorf("failed to locate the signature for %s: %w", describeSource(source), err)
	}
	if !found {
		return nil, nil
	}
	if opts.Keyring == nil && len(opts.PublicKeyPEM) == 0 {
		status := FailedSignature(ReasonNoKeyring, "")
		return &status, nil
	}

	// Parse first so the envelope's `signed_at` claim can be recorded even
	// when a later check fails. An envelope too malformed to parse still maps
	// onto a reason code, which VerifyPolicyBytes recovers along with whatever
	// key id it claimed.
	env, parseErr := ParseEnvelope(data)
	if parseErr != nil {
		result := VerifyPolicyBytes(resolved, data, opts)
		status := FailedSignature(result.Reason, result.KeyID)
		return &status, nil
	}
	result := VerifyPolicy(resolved, env, opts)
	if !result.OK {
		status := FailedSignature(result.Reason, result.KeyID)
		return &status, nil
	}
	return &SignatureStatus{
		Verified:   true,
		KeyID:      result.KeyID,
		VerifiedAt: FormatTimestamp(verifierClock(opts)),
	}, nil
}

// verifierClock is the instant a verification outcome is stamped with: the
// verifier's configured clock, or now when it has none.
func verifierClock(opts VerifyOptions) time.Time {
	if opts.Now.IsZero() {
		return time.Now()
	}
	return opts.Now
}

// verifyOptions folds ResolveOptions.Keyring into the verifier inputs and
// reports whether any key material was configured at all. With none, and
// without RequireSignature, no signature is looked for: the unverified
// resolver must not start stat-ing for `.sig` files.
func (opts ResolveOptions) verifyOptions() (VerifyOptions, bool) {
	verify := opts.Verify
	if opts.Keyring != nil {
		verify.Keyring = opts.Keyring
	}
	enabled := opts.RequireSignature || verify.Keyring != nil || len(verify.PublicKeyPEM) > 0
	return verify, enabled
}

// hopContentHash hashes one chain document on its own, with `extends` and
// `merge_strategy` stripped (spec/hushspec-receipt.md section 4.2). The
// canonical projection drops both fields anyway; clearing `extends` is what
// lets an unresolved document be canonicalized at all.
func hopContentHash(spec *HushSpec) (string, error) {
	if spec == nil {
		return "", errors.New("cannot hash a nil HushSpec document")
	}
	return ContentHash(resolvedDocument(spec))
}

// resolvedDocument is a document with its resolution instructions cleared.
// `extends` and `merge_strategy` say how to assemble a policy, not what it
// permits, so they never appear in what an engine enforces or in what a chain
// link hashes (core spec 2.3). A shallow copy is enough: only the two scalar
// fields change, and neither canonicalization nor merging writes through the
// shared pointers.
func resolvedDocument(spec *HushSpec) *HushSpec {
	if spec == nil || (spec.Extends == nil && spec.MergeStrategy == "") {
		return spec
	}
	own := *spec
	own.Extends = nil
	own.MergeStrategy = ""
	return &own
}

var (
	// digestPinPattern is a content hash as spec/hushspec-canonical.md
	// section 5 defines it -- the same value the pin fragment carries.
	digestPinPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// digestPinFragmentPattern matches anything shaped like an
	// `<algorithm>:<digest>` fragment. A fragment that looks like a pin but is
	// not a well-formed sha256 one is an error, never a filename: guessing
	// would drop the pin the author asked for.
	digestPinFragmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*:[0-9A-Za-z]+$`)
)

// splitDigestPin separates an extends reference from its optional digest pin:
// `base.yaml#sha256:<64 hex>` becomes ("base.yaml", "sha256:<64 hex>").
func splitDigestPin(reference string) (string, string, error) {
	index := strings.LastIndex(reference, "#")
	if index < 0 {
		return reference, "", nil
	}
	ref, fragment := reference[:index], reference[index+1:]
	if !digestPinFragmentPattern.MatchString(fragment) {
		return reference, "", nil
	}
	if !digestPinPattern.MatchString(fragment) {
		return "", "", &InvalidPinError{
			Reference: reference,
			Message: fmt.Sprintf(
				"%q is not \"sha256:\" followed by 64 lowercase hex digits", fragment),
		}
	}
	if ref == "" {
		return "", "", &InvalidPinError{
			Reference: reference,
			Message:   fmt.Sprintf("digest pin %q has no reference to pin", fragment),
		}
	}
	return ref, fragment, nil
}

// loadSpecFile reads and parses the document at path, returning it with the
// canonical (absolute, symlink-resolved) path it was read from.
func loadSpecFile(path string) (*HushSpec, string, error) {
	source, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve path %q: %w", path, err)
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return nil, "", fmt.Errorf("failed to canonicalize %q: %w", source, err)
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read HushSpec at %s: %w", source, err)
	}
	spec, err := Parse(string(content))
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse HushSpec at %s: %w", source, err)
	}
	return spec, source, nil
}

// loadFromFilesystem resolves a relative reference against the referring
// document's directory and loads it.
func loadFromFilesystem(reference string, from string) (*LoadedSpec, error) {
	resolvedPath := reference
	if !filepath.IsAbs(reference) && from != "" {
		resolvedPath = filepath.Join(filepath.Dir(from), reference)
	}
	spec, canonical, err := loadSpecFile(resolvedPath)
	if err != nil {
		return nil, err
	}
	return &LoadedSpec{Source: canonical, Spec: spec}, nil
}

// describeSource names a document in an error message. A document built in
// memory has no source, and "" reads as a missing word.
func describeSource(source string) string {
	if source == "" || source == MemorySource {
		return "the in-memory policy document"
	}
	return source
}
