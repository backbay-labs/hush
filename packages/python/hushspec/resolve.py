"""``extends`` resolution, verification on load, and digest pinning.

Resolution walks a policy's ``extends`` chain to its root, merges back down,
and -- when asked -- proves that every hop it merged is the document the policy
author meant.

Two independent proofs are supported, both from ``spec/hushspec-signing.md``
section 6.5:

* **Digest pinning.** ``extends: "base.yaml#sha256:<64 hex>"`` names the exact
  content hash the referenced document must have. The fragment is stripped
  before the reference is loaded; the loaded document is then canonicalized on
  its own and compared. A mismatch is always fatal, signatures or not: a pin is
  a statement about bytes, and a base that no longer matches is either a
  tampered file or a stale pin. Neither is safe to merge.
* **Detached signatures.** Each hop's ``<source>.sig`` envelope is verified
  against a trusted keyring (``spec/hushspec-signing.md`` section 6.2). With
  ``require_signature`` every hop that is not ``builtin:`` must carry either a
  matching pin or a valid signature, and resolution fails closed otherwise.
  Without it, a keyring still buys opportunistic verification whose outcome is
  recorded and never blocks the load.

:class:`Resolution` carries the evidence: the resolved document, its content
hash, and the chain of hops -- root first, leaf last -- each with the content
hash of *that* document canonicalized on its own with ``extends`` and
``merge_strategy`` stripped (``spec/hushspec-receipt.md`` section 4.2). An
auditor reading a receipt can therefore confirm that a specific base policy was
in force without re-resolving anything.

:func:`resolve`, :func:`resolve_or_raise` and :func:`resolve_file` are
unchanged: thin wrappers that resolve with default options and return just the
merged document. They do not hash and do not verify -- except for a digest pin,
which is enforced everywhere because it is part of the reference itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from hushspec.builtins import load_builtin
from hushspec.canonical import CanonicalError, content_hash
from hushspec.error_codes import ERROR_EXTENDS, ERROR_IO, ErrorMessage, code_of
from hushspec.merge import merge
from hushspec.parse import parse
from hushspec.schema import HushSpec
from hushspec.signing import (
    DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    Keyring,
    MalformedEnvelope,
    SigningError,
    SigningUnavailable,
    format_timestamp,
    load_keyring,
    parse_envelope,
    verify_policy,
)

# Package-internal: the lazy Ed25519 backend probe. `require_signature` has to
# fail with `SigningUnavailable` *before* any hop is examined, so that a missing
# `cryptography` can never be mistaken for a policy that simply has no signature
# (which would otherwise be reported as `missing_signature`).
from hushspec.signing import _coerce_moment, _ed25519


@dataclass
class LoadedSpec:
    source: str
    spec: HushSpec


Resolver = Callable[[str, str | None], LoadedSpec]

#: Locates the detached signature envelope for a chain hop, by the source the
#: loader reported. Returns the envelope bytes/JSON text, or ``None`` when the
#: hop has no envelope.
SignatureLocator = Callable[[str], bytes | str | None]

# Maximum length of an `extends` chain. Resolvers only detect exact-repeat
# cycles, so a long *acyclic* chain would otherwise recurse unbounded until a
# stack overflow. 32 is far above any realistic composition (shipped policies
# are depth <= 2); the same limit is enforced identically across all four SDKs.
_MAX_EXTENDS_DEPTH = 32

#: Chain-link source recorded for a document that came from memory rather than
#: from a loader (``HushGuard.from_yaml``, a provider handing back a parsed
#: spec). It is also what a :data:`SignatureLocator` is asked about, so a caller
#: can still supply an envelope for an in-memory policy. The spelling is
#: normative: ``fixtures/core/resolve/`` pins the leaf of an in-memory chain as
#: ``memory`` in every SDK.
MEMORY_SOURCE = "memory"

#: Deprecated alias of :data:`MEMORY_SOURCE`, kept so callers that imported the
#: pre-0.2 spelling keep working.
INLINE_SOURCE = MEMORY_SOURCE

#: The fragment that turns an ``extends`` reference into a pinned one.
DIGEST_PIN_MARKER = "#sha256:"

# Greedy on the reference so the *last* `#sha256:` wins: a path may legally
# contain a `#`, but a pin is always the trailing fragment.
_PIN_RE = re.compile(r"^(?P<ref>.+)#(?P<digest>sha256:[^#]*)$")
_CONTENT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: A digest pin was present and the hop hashed to something else. Always fatal.
REASON_DIGEST_MISMATCH = "digest_mismatch"
#: ``require_signature`` was set and the hop had neither a pin nor an envelope.
REASON_MISSING_SIGNATURE = "missing_signature"
#: The ``#sha256:`` fragment is not a well-formed content hash.
REASON_INVALID_PIN = "invalid_pin"
#: Deprecated spelling of :data:`REASON_INVALID_PIN`. The resolve vectors
#: (``fixtures/core/resolve/pin-malformed.yaml``) name the rejection
#: ``invalid_pin``, so that is the code every SDK reports.
REASON_MALFORMED_DIGEST_PIN = REASON_INVALID_PIN
#: An envelope was found but the Ed25519 backend is missing, so it could not be
#: checked. Only reachable opportunistically: under ``require_signature`` the
#: missing backend raises :class:`~hushspec.signing.SigningUnavailable`.
REASON_SIGNING_UNAVAILABLE = "signing_unavailable"

#: Reasons this module can report beyond the signing spec's section 6.4 codes.
RESOLVE_REASON_CODES = (
    REASON_DIGEST_MISMATCH,
    REASON_MISSING_SIGNATURE,
    REASON_INVALID_PIN,
    REASON_SIGNING_UNAVAILABLE,
)

#: A reference no loader could serve.
REJECT_NOT_FOUND = "not_found"
#: The chain refers back to a document already on it.
REJECT_CYCLE = "cycle"
#: The chain is longer than :data:`_MAX_EXTENDS_DEPTH`.
REJECT_MAX_DEPTH = "max_depth"
#: ``require_signature`` was set and a hop could not be proven.
REJECT_SIGNATURE_REQUIRED = "signature_required"
#: Rejection codes reported by :attr:`ResolveRejected.code`, the vocabulary of
#: ``fixtures/core/resolve/*.yaml``'s ``expect.rejects``.
RESOLVE_REJECT_CODES = (
    REASON_DIGEST_MISMATCH,
    REASON_INVALID_PIN,
    REJECT_NOT_FOUND,
    REJECT_CYCLE,
    REJECT_MAX_DEPTH,
    REJECT_SIGNATURE_REQUIRED,
)


# --------------------------------------------------------------------------- #
# Options and results
# --------------------------------------------------------------------------- #


@dataclass
class VerifyOptions:
    """Verifier inputs for signature checks (signing spec section 6.1)."""

    #: Verifier clock; defaults to now at each check.
    now: datetime | str | None = None
    #: Tolerance for a signer's clock running fast (signing spec section 6.3).
    max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS
    #: Last accepted ``policy_version``, enabling the rollback check. Applied to
    #: every hop whose envelope carries one, not only the leaf.
    last_seen_version: int | None = None


@dataclass
class ResolveOptions:
    """How much proof resolution demands of the chain it merges."""

    #: Refuse to resolve unless every non-``builtin:`` hop is pinned or signed.
    require_signature: bool = False
    #: Trusted public keys. Anything :func:`~hushspec.signing.load_keyring`
    #: accepts (a :class:`~hushspec.signing.Keyring`, a keyring mapping, JSON
    #: text, or a bare public-key PEM).
    keyring: Keyring | None = None
    #: Verifier clock and rollback inputs.
    verify: VerifyOptions | None = None
    #: Where a hop's detached envelope lives. Defaults to
    #: :func:`default_signature_locator`.
    signature_locator: SignatureLocator | None = None


@dataclass(frozen=True)
class SignatureStatus:
    """The outcome of signature verification for one document.

    ``verified`` is true only when an envelope was present, its key was in the
    trusted keyring, and every check of signing spec section 6.2 passed --
    exactly the receipt spec's section 4.2 definition. ``reason`` is a signing
    spec section 6.4 code or one of :data:`RESOLVE_REASON_CODES`.
    """

    key_id: str | None = None
    verified: bool = False
    reason: str | None = None
    #: When verification ran, in the receipt's timestamp spelling. Set only when
    #: an envelope was actually checked against a keyring; it is the verifier's
    #: clock, never the signer's ``signed_at``.
    verified_at: str | None = None


@dataclass(frozen=True)
class ChainLink:
    """One document in a resolved ``extends`` chain (receipt spec section 4.2).

    ``content_hash`` is *this* document canonicalized on its own, with its own
    ``extends`` and ``merge_strategy`` stripped -- not the merged result -- so
    it is comparable to a digest pin naming it.
    """

    source: str
    content_hash: str
    signature: SignatureStatus | None = None


@dataclass(frozen=True)
class Resolution:
    """A resolved policy and the evidence gathered while resolving it."""

    #: The merged document. Never carries ``extends``.
    spec: HushSpec
    #: Content hash of :attr:`spec` (canonical spec section 5).
    content_hash: str
    #: Every hop that was merged, root first and the leaf last. A policy with no
    #: ``extends`` has a one-link chain holding only itself; a receipt omits
    #: ``extends_chain`` in that case (see :attr:`extends_chain`).
    chain: list[ChainLink] = field(default_factory=list)
    #: The leaf's signature outcome, or ``None`` when none was attempted.
    signature: SignatureStatus | None = None

    @property
    def extends_chain(self) -> list[ChainLink]:
        """The chain as a receipt records it: empty when there was no ``extends``."""
        return self.chain if len(self.chain) > 1 else []

    def had_extends(self) -> bool:
        """Whether the policy was produced by merging an ``extends`` chain.

        A receipt records ``extends_chain`` only then (receipt spec 4.2).
        """
        return len(self.chain) > 1

    @classmethod
    def from_resolved(
        cls, spec: HushSpec, source: str | None = None
    ) -> "Resolution":
        """Wrap an already-resolved document as a one-link resolution.

        ``source`` names it in the chain; :data:`MEMORY_SOURCE` when the caller
        has no better name. Raises :class:`~hushspec.canonical.CanonicalError`
        when the document has no canonical form, which includes a document that
        still declares ``extends``.
        """
        label = source if source is not None else MEMORY_SOURCE
        digest = content_hash(spec)
        return cls(
            spec=spec,
            content_hash=digest,
            chain=[ChainLink(source=label, content_hash=digest)],
            signature=None,
        )


class ResolveRejected(ValueError):
    """Resolution refused the chain, with the reason code the vectors name.

    ``code`` is one of :data:`RESOLVE_REJECT_CODES` -- the vocabulary of
    ``expect.rejects`` in ``fixtures/core/resolve/*.yaml``. It subclasses
    :class:`ValueError` so the tuple-returning entry points and every existing
    caller keep catching it.

    ``error_code`` is the coarser error-code-registry identifier
    (``spec/registries/error-codes.yaml``): every resolution refusal is E010,
    whichever of the specific codes above named it.
    """

    #: The error-code-registry identifier for a resolution refusal.
    error_code: str = ERROR_EXTENDS

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        #: The rejection code (:data:`RESOLVE_REJECT_CODES`).
        self.code = code


class PolicyVerificationError(ResolveRejected):
    """A chain hop could not be proven to be the document it claims to be.

    Raised fail-closed: resolution stops, nothing is merged, and no evaluation
    happens against a document that failed its own integrity check.
    """

    def __init__(self, message: str, *, source: str, status: SignatureStatus) -> None:
        reason = status.reason
        code = (
            reason
            if reason in (REASON_DIGEST_MISMATCH, REASON_INVALID_PIN)
            else REJECT_SIGNATURE_REQUIRED
        )
        super().__init__(message, code=code)
        #: The hop that failed, as the loader reported it.
        self.source = source
        #: Why, in the form a receipt records (``verified`` is always false).
        self.status = status

    @property
    def reason(self) -> str | None:
        return self.status.reason


# --------------------------------------------------------------------------- #
# Public resolution API
# --------------------------------------------------------------------------- #


def resolve(
    spec: HushSpec,
    *,
    source: str | None = None,
    loader: Resolver | None = None,
) -> tuple[bool, HushSpec | str]:
    """Resolve ``extends`` with default options: merge only, no verification.

    Digest pins are still enforced -- a pin is part of the reference, so
    honouring it is resolution and not verification -- but nothing is hashed for
    a chain that carries no pin, and no signature check is attempted.
    """
    ok, result = _resolve_tuple(spec, source=source, loader=loader, options=None)
    return (True, result.spec) if ok else (False, result)


def resolve_or_raise(
    spec: HushSpec,
    *,
    source: str | None = None,
    loader: Resolver | None = None,
) -> HushSpec:
    ok, result = resolve(spec, source=source, loader=loader)
    if not ok:
        raise ValueError(result)
    return result


def resolve_file(path: str | Path) -> tuple[bool, HushSpec | str]:
    source = str(Path(path).resolve())
    try:
        content = Path(source).read_text(encoding="utf-8")
    except OSError as exc:
        # A transport-level failure, not a statement about the document:
        # nothing was parsed (error-code registry, E000).
        return False, ErrorMessage(
            f"failed to read HushSpec at {source}: {exc}", ERROR_IO
        )
    ok, parsed = parse(content)
    if not ok:
        return False, ErrorMessage(
            f"failed to parse HushSpec at {source}: {parsed}", code_of(parsed)
        )
    return resolve(parsed, source=source, loader=_create_composite_loader())


def resolve_with_options(
    spec: HushSpec,
    *,
    source: str | None = None,
    loader: Resolver | None = None,
    options: ResolveOptions | None = None,
) -> tuple[bool, Resolution | str]:
    """Resolve, hash every hop, and verify as far as ``options`` demands.

    Returns ``(True, resolution)`` or ``(False, message)``, in the style of
    :func:`resolve`. :class:`~hushspec.signing.SigningUnavailable` propagates
    instead of becoming a message: a missing crypto backend is a broken
    verifier, not a verdict about the policy.

    Use :func:`resolve_with_options_or_raise` when the failure itself matters --
    it raises :class:`PolicyVerificationError`, which names the hop and carries
    the :class:`SignatureStatus` a receipt records.
    """
    return _resolve_tuple(spec, source=source, loader=loader, options=options)


def resolve_with_options_or_raise(
    spec: HushSpec,
    *,
    source: str | None = None,
    loader: Resolver | None = None,
    options: ResolveOptions | None = None,
) -> Resolution:
    """Resolve and verify, raising on any failure.

    Raises :class:`PolicyVerificationError` when a hop fails its pin or its
    signature, :class:`~hushspec.signing.SigningUnavailable` when
    ``require_signature`` is set without an Ed25519 backend, and
    :class:`ValueError` when the chain itself cannot be resolved.
    """
    prepared = _prepare(options)
    stack = [source] if source is not None else []
    resolved, chain = _resolve_inner(
        spec,
        source,
        loader or _create_composite_loader(),
        stack,
        prepared=prepared,
    )
    leaf = chain[-1] if chain else None
    return Resolution(
        spec=resolved,
        content_hash=_content_hash_or_fail(resolved, source),
        chain=chain,
        signature=leaf.signature if leaf is not None else None,
    )


def _resolve_tuple(
    spec: HushSpec,
    *,
    source: str | None,
    loader: Resolver | None,
    options: ResolveOptions | None,
) -> tuple[bool, Resolution | str]:
    if options is not None:
        try:
            return True, resolve_with_options_or_raise(
                spec, source=source, loader=loader, options=options
            )
        except SigningUnavailable:
            raise
        except ValueError as exc:
            return False, str(exc)

    # Merge-only: no hashing, no verification, no chain -- the historical
    # `resolve()` behaviour, kept off the hot path that difftest and the
    # evaluator fixtures run.
    try:
        stack = [source] if source is not None else []
        resolved, chain = _resolve_inner(
            spec, source, loader or _create_composite_loader(), stack, prepared=None
        )
    except ValueError as exc:
        return False, str(exc)
    return True, Resolution(spec=resolved, content_hash="", chain=chain)


# --------------------------------------------------------------------------- #
# The walk
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Prepared:
    """Validated options, resolved once for the whole walk."""

    require_signature: bool
    keyring: Keyring | None
    verify: VerifyOptions
    locator: SignatureLocator


def _prepare(options: ResolveOptions | None) -> _Prepared:
    options = options or ResolveOptions()
    keyring = load_keyring(options.keyring) if options.keyring is not None else None
    if options.require_signature:
        if keyring is None:
            # The leaf can never be pinned -- nothing references it -- so
            # `require_signature` without trusted keys can only ever fail.
            # Saying so now beats failing at the leaf with `missing_signature`.
            raise SigningError(
                "require_signature needs a keyring: there is no default trust, and the "
                "leaf policy can only be proven by a signature"
            )
        # Fail on a missing backend before any hop is judged (see the import
        # note at the top of this module).
        _ed25519()
    return _Prepared(
        require_signature=options.require_signature,
        keyring=keyring,
        verify=options.verify or VerifyOptions(),
        locator=options.signature_locator or default_signature_locator,
    )


def _resolve_inner(
    spec: HushSpec,
    source: str | None,
    loader: Resolver,
    stack: list[str],
    depth: int = 0,
    *,
    prepared: _Prepared | None = None,
    pin: str | None = None,
) -> tuple[HushSpec, list[ChainLink]]:
    """Merge this document's chain and return ``(resolved, chain)``.

    ``pin`` is the digest the *referring* document demanded of this one. The
    chain comes back root first and leaf last, and is empty when ``prepared`` is
    ``None`` (there is nothing to record).
    """
    own_hash = ""
    if prepared is not None or pin is not None:
        own_hash = _content_hash_or_fail(_own_document(spec), source)
    if pin is not None and pin != own_hash:
        # Checked before the parent chain is touched: a document that is not
        # what it was pinned to be does not get to say what it extends.
        raise PolicyVerificationError(
            f"digest pin mismatch for {_label(source)}: pinned {pin}, document hashes "
            f"to {own_hash}",
            source=_label(source),
            status=SignatureStatus(verified=False, reason=REASON_DIGEST_MISMATCH),
        )

    chain: list[ChainLink] = []
    if spec.extends is None:
        resolved = spec
    else:
        if depth >= _MAX_EXTENDS_DEPTH:
            raise ResolveRejected(
                f"extends chain exceeds maximum depth of {_MAX_EXTENDS_DEPTH}",
                code=REJECT_MAX_DEPTH,
            )

        reference, parent_pin = _split_digest_pin(spec.extends, source)
        try:
            loaded = loader(reference, source)
        except ResolveRejected:
            raise
        except Exception as exc:
            # Anything a loader raises means the reference could not be served.
            raise ResolveRejected(str(exc), code=REJECT_NOT_FOUND) from exc

        if loaded.source in stack:
            cycle = stack[stack.index(loaded.source) :] + [loaded.source]
            raise ResolveRejected(
                f"circular extends detected: {' -> '.join(cycle)}", code=REJECT_CYCLE
            )

        stack.append(loaded.source)
        parent, chain = _resolve_inner(
            loaded.spec,
            loaded.source,
            loader,
            stack,
            depth + 1,
            prepared=prepared,
            pin=parent_pin,
        )
        stack.pop()
        resolved = merge(parent, spec)

    if prepared is None:
        return resolved, chain

    # A signature covers the *resolved* document (signing spec section 3), so
    # the hop is verified only once its own parents are merged in; the pin above
    # covers the document on its own.
    status = _verify_hop(source, resolved, pinned=pin is not None, prepared=prepared)
    chain.append(
        ChainLink(source=_label(source), content_hash=own_hash, signature=status)
    )
    return resolved, chain


def _own_document(spec: HushSpec) -> HushSpec:
    """This document alone, with the resolution-only fields stripped.

    Receipt spec section 4.2: a chain link's hash is the document canonicalized
    on its own, without its ``extends`` and ``merge_strategy``. Canonical
    projection drops ``merge_strategy`` anyway and *refuses* a document that
    still declares ``extends``, so both are cleared here.
    """
    if spec.extends is None and spec.merge_strategy is None:
        return spec
    return replace(spec, extends=None, merge_strategy=None)


def _content_hash_or_fail(spec: HushSpec, source: str | None) -> str:
    try:
        return content_hash(spec)
    except CanonicalError as exc:
        raise ValueError(f"cannot hash the policy at {_label(source)}: {exc}") from exc


def _label(source: str | None) -> str:
    return source if source is not None else INLINE_SOURCE


def _split_digest_pin(reference: str, source: str | None) -> tuple[str, str | None]:
    """Split ``<ref>#sha256:<hex>`` into the reference and the pinned digest.

    A reference with no ``#sha256:`` fragment comes back unchanged. A fragment
    that is present but malformed is fatal rather than ignored: silently loading
    the base would turn a typo in a pin into no integrity check at all.
    """
    if DIGEST_PIN_MARKER not in reference:
        return reference, None
    match = _PIN_RE.match(reference)
    if match is None or not _CONTENT_HASH_RE.match(match.group("digest")):
        raise PolicyVerificationError(
            f"malformed digest pin in 'extends: {reference}' at {_label(source)}: "
            "expected '<reference>#sha256:<64 lowercase hex>'",
            source=_label(source),
            status=SignatureStatus(verified=False, reason=REASON_INVALID_PIN),
        )
    return match.group("ref"), match.group("digest")


# --------------------------------------------------------------------------- #
# Verification of one hop (signing spec section 6.5)
# --------------------------------------------------------------------------- #


def _verify_hop(
    source: str | None,
    resolved: HushSpec,
    *,
    pinned: bool,
    prepared: _Prepared,
) -> SignatureStatus | None:
    """Verify one hop, or report why it could not be verified.

    ``builtin:`` hops are embedded in the engine and need no separate
    verification (signing spec section 6.5). For everything else:

    * With a keyring, a located envelope is always verified and its outcome
      recorded, whether or not verification is required.
    * With ``require_signature``, a hop is *required* to prove itself only when
      it is not pinned: ``required = require_signature and not pinned``. A
      matching digest pin is a proof about the exact bytes of the document, so
      it satisfies the hop on its own; the envelope, when there is one, is still
      verified opportunistically and its outcome recorded.
    """
    label = _label(source)
    if source is not None and source.startswith("builtin:"):
        return None
    if prepared.keyring is None and not prepared.require_signature:
        return None

    required = prepared.require_signature and not pinned

    status: SignatureStatus | None = None
    envelope = prepared.locator(label)
    if envelope is not None:
        status = _verify_envelope(resolved, envelope, prepared)

    if not required:
        return status
    if status is not None and status.verified:
        return status

    failure = status or SignatureStatus(verified=False, reason=REASON_MISSING_SIGNATURE)
    detail = (
        "no signature envelope was found"
        if status is None
        else "signature verification failed"
    )
    # The reason code is part of the message as well as of `status`, so the
    # tuple-returning entry points do not lose it.
    raise PolicyVerificationError(
        f"refusing to load {label}: {detail} ({failure.reason})",
        source=label,
        status=failure,
    )


def _verify_envelope(
    resolved: HushSpec, envelope: Any, prepared: _Prepared
) -> SignatureStatus:
    try:
        parsed = parse_envelope(envelope)
    except MalformedEnvelope as exc:
        return SignatureStatus(verified=False, reason=exc.reason)
    except (UnicodeDecodeError, ValueError):
        return SignatureStatus(verified=False, reason="malformed_envelope")

    # One instant for the check and for what the receipt records, so
    # `verified_at` names the moment the ten checks were actually run
    # (receipt spec 4.2) rather than the signer's `signed_at`.
    moment = _coerce_moment(prepared.verify.now, "now") or datetime.now(timezone.utc)
    try:
        result = verify_policy(
            resolved,
            parsed,
            keyring=prepared.keyring,
            now=moment,
            max_clock_skew_seconds=prepared.verify.max_clock_skew_seconds,
            last_seen_version=prepared.verify.last_seen_version,
        )
    except SigningUnavailable:
        # Unreachable under `require_signature` (the backend was probed in
        # `_prepare`); opportunistically, an envelope that cannot be checked is
        # recorded as unverified rather than raised, since the load was never
        # gated on it.
        if prepared.require_signature:
            raise
        return SignatureStatus(
            key_id=parsed.key_id,
            verified=False,
            reason=REASON_SIGNING_UNAVAILABLE,
        )
    return SignatureStatus(
        key_id=result.key_id or parsed.key_id,
        verified=result.valid,
        reason=result.reason,
        verified_at=format_timestamp(moment) if result.valid else None,
    )


def default_signature_locator(source: str) -> bytes | None:
    """Find a hop's detached envelope on disk (signing spec section 7.1).

    For a file source, ``<path>.sig`` is preferred and ``<stem>.sig`` accepted
    for 0.1 layouts -- ``policy.yaml.sig`` first, then ``policy.sig``.
    ``builtin:`` sources have no envelope.

    ``https:`` sources would be ``<url>.sig``, but this SDK ships no HTTP client
    (the built-in loaders refuse URLs outright), so they resolve to ``None``
    here: fetching a signature over the network is a decision for the same code
    that fetched the policy, and it belongs in a caller-supplied
    :data:`SignatureLocator`.
    """
    if source.startswith(("builtin:", "http://", "https://")) or source == INLINE_SOURCE:
        return None

    candidates = [Path(f"{source}.sig")]
    try:
        stem_sibling = Path(source).with_suffix(".sig")
    except ValueError:  # pragma: no cover - only for a path with an empty name
        stem_sibling = None
    if stem_sibling is not None and stem_sibling != candidates[0]:
        candidates.append(stem_sibling)

    for candidate in candidates:
        try:
            return candidate.read_bytes()
        except OSError:
            continue
    return None


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #


def create_builtin_loader() -> Resolver:
    """Loader that serves only ``builtin:<name>`` (and bare builtin names) from
    the embedded rulesets and refuses everything else.

    The default for callers with no filesystem root to resolve relative
    references against -- ``HushGuard.from_yaml()``, a provider handing back an
    already-parsed spec. Refusing (rather than guessing a root, or silently
    dropping the base) keeps those paths fail-closed: a policy whose base
    cannot be loaded is never evaluated as if the base said nothing.
    """

    def _loader(reference: str, _source: str | None = None) -> LoadedSpec:
        spec = load_builtin(reference)
        if spec is not None:
            source = reference if reference.startswith("builtin:") else f"builtin:{reference}"
            return LoadedSpec(source=source, spec=spec)
        if reference.startswith("builtin:"):
            raise ValueError(f"unknown builtin ruleset '{reference}'")
        raise ValueError(
            f"cannot resolve 'extends: {reference}': this loader only serves builtin "
            "rulesets (pass a `base_dir` to resolve relative paths, or a custom `loader`)"
        )

    return _loader


def create_composite_loader() -> Resolver:
    """Public alias for the builtin + filesystem loader."""
    return _create_composite_loader()


def _create_composite_loader() -> Resolver:
    """Loader that serves `builtin:<name>` references from the embedded
    rulesets and everything else from the filesystem. A bare name with no path
    separators or dots is tried as a builtin before falling back to the
    filesystem.

    `http://`/`https://` references are rejected outright: this loader has no
    HTTP client, so silently handing a URL to the filesystem loader would fail
    with a confusing "no such file or directory" error instead of a clear one.
    """

    def _loader(reference: str, source: str | None) -> LoadedSpec:
        if reference.startswith("builtin:"):
            spec = load_builtin(reference)
            if spec is None:
                raise ValueError(f"unknown builtin ruleset '{reference}'")
            return LoadedSpec(source=reference, spec=spec)

        if reference.startswith("http://") or reference.startswith("https://"):
            raise ValueError(
                "HTTP-based policy loading is not supported by the default "
                f"loader; provide a custom `loader` for '{reference}'"
            )

        if "/" not in reference and "\\" not in reference and "." not in reference:
            spec = load_builtin(reference)
            if spec is not None:
                return LoadedSpec(source=f"builtin:{reference}", spec=spec)

        return _load_from_filesystem(reference, source)

    return _loader


def _load_from_filesystem(reference: str, source: str | None) -> LoadedSpec:
    path = Path(reference)
    if not path.is_absolute():
        path = Path(source).parent / path if source is not None else path.resolve()
    canonical = path.resolve()
    content = canonical.read_text(encoding="utf-8")
    ok, parsed = parse(content)
    if not ok:
        raise ValueError(f"failed to parse HushSpec at {canonical}: {parsed}")
    return LoadedSpec(source=str(canonical), spec=parsed)
