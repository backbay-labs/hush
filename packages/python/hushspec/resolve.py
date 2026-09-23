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

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from hushspec.builtins import load_builtin
from hushspec.canonical import CanonicalError, content_hash, is_content_hash
from hushspec.error_codes import ERROR_EXTENDS, ERROR_IO, ErrorMessage, code_of
from hushspec.merge import merge
from hushspec.parse import parse
from hushspec.schema import HushSpec
from hushspec.signing import (
    DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    REASON_CODES,
    Keyring,
    MalformedEnvelope,
    SigningUnavailable,
    format_timestamp,
    load_keyring,
    parse_envelope,
    verify_policy,
)

# Package-internal: the lazy Ed25519 backend probe. A load that has keys to
# check against fails with `SigningUnavailable` *before* any hop is examined, so
# that a missing `cryptography` can never be mistaken for a policy that simply
# has no signature (which would otherwise be reported as `missing_signature`).
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

#: The fragment that turns an ``extends`` reference into a pinned one. The pin
#: is always the fragment after the last ``#``.
DIGEST_PIN_MARKER = "#sha256:"

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
#: An envelope was found but there is no keyring to check it against.
REASON_NO_KEYRING = "no_keyring"
#: An envelope was found but the Ed25519 backend is missing, so it could not be
#: checked.
REASON_SIGNING_UNAVAILABLE = "signing_unavailable"

#: Reasons this module can report beyond the signing spec's section 6.4 codes.
#: These are the five load-time conditions of signing spec section 6.5, the set
#: every SDK records on a hop it attempted to verify.
RESOLVE_REASON_CODES = (
    REASON_DIGEST_MISMATCH,
    REASON_MISSING_SIGNATURE,
    REASON_INVALID_PIN,
    REASON_NO_KEYRING,
    REASON_SIGNING_UNAVAILABLE,
)

#: The closed set a verification on load records on a hop: the five load-time
#: conditions of signing spec section 6.5 plus the envelope checks of section
#: 6.4. A reason outside it is not one a receipt may carry.
LOAD_REASON_CODES = RESOLVE_REASON_CODES + tuple(REASON_CODES)

#: A reference no loader could serve.
REJECT_NOT_FOUND = "not_found"
#: The chain refers back to a document already on it.
REJECT_CYCLE = "cycle"
#: The chain is longer than :data:`_MAX_EXTENDS_DEPTH`.
REJECT_MAX_DEPTH = "max_depth"
#: Rejection codes reported by :attr:`ResolveRejected.code`, the vocabulary of
#: ``fixtures/core/resolve/*.yaml``'s ``expect.rejects``.
RESOLVE_REJECT_CODES = (
    REASON_DIGEST_MISMATCH,
    REASON_INVALID_PIN,
    REJECT_NOT_FOUND,
    REJECT_CYCLE,
    REJECT_MAX_DEPTH,
    REASON_MISSING_SIGNATURE,
    REASON_NO_KEYRING,
    REASON_SIGNING_UNAVAILABLE,
)


def load_reason_of(status: "SignatureStatus | None") -> str:
    """The reason an unverified *status* names, as a member of the closed set.

    A status that names none, or one outside the section 6.4 and 6.5 codes,
    reads as ``missing_signature``: the hop proved nothing, and that is all a
    caller can act on.
    """
    reason = status.reason if status is not None else None
    if reason is not None and reason in LOAD_REASON_CODES:
        return reason
    return REASON_MISSING_SIGNATURE


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
    #: Whether the referring document pinned this one by digest and the digest
    #: matched (core spec 2.3). A pin is checked before anything else, so a
    #: true value is proof the document is the one the author named, and
    #: signing spec 6.5 accepts it in place of an envelope.
    #:
    #: Evidence for a re-check inside one process only: it stays out of the
    #: receipt and bundle wire formats.
    pinned: bool = False


@dataclass(frozen=True)
class Resolution:
    """A resolved policy and the evidence gathered while resolving it."""

    #: The merged document. Resolution consumes ``extends`` and
    #: ``merge_strategy``, so it never carries either (core spec 2.3).
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
            # A resolution's document carries no resolution instructions,
            # however it was obtained: the hash above already refused a
            # lingering ``extends``, and ``merge_strategy`` is inert here.
            spec=_own_document(spec),
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

    def __init__(
        self,
        message: str,
        *,
        source: str,
        status: SignatureStatus,
        resolution: "Resolution | None" = None,
    ) -> None:
        super().__init__(message, code=load_reason_of(status))
        #: The hop that failed, as the loader reported it.
        self.source = source
        #: Why, in the form a receipt records (``verified`` is always false).
        self.status = status
        #: What was loaded, when the chain merged and only verification failed,
        #: so a caller that must keep going -- a guard that refuses every action
        #: but still reports the hash of what it was handed (signing spec
        #: section 6.5) -- has the document without ever being able to mistake
        #: it for a verified one. ``None`` when the chain did not merge at all.
        self.resolution = resolution

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

    Omitting ``options`` still hashes: the defaults ask for no verification,
    not for a :class:`Resolution` with no content hash. Use :func:`resolve`
    for the merge-only path.
    """
    return _resolve_tuple(
        spec, source=source, loader=loader, options=options or ResolveOptions()
    )


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
    try:
        resolved, chain = _resolve_inner(
            spec,
            source,
            loader or _create_composite_loader(),
            stack,
            prepared=prepared,
        )
    except PolicyVerificationError as exc:
        if prepared.require_signature:
            exc.resolution = _unverified_resolution(spec, source, loader, options)
        raise
    leaf = chain[-1] if chain else None
    return Resolution(
        spec=resolved,
        content_hash=_content_hash_or_fail(resolved, source),
        chain=chain,
        signature=leaf.signature if leaf is not None else None,
    )


def _unverified_resolution(
    spec: HushSpec,
    source: str | None,
    loader: Resolver | None,
    options: ResolveOptions | None,
) -> Resolution | None:
    """The chain as it merges when signatures are not *required*.

    Signatures are still verified where they are found, so every hop keeps the
    outcome a receipt records. ``None`` when the chain does not resolve at all:
    a digest pin is honoured whether or not signatures are required, so a pin
    failure leaves no document to report.
    """
    relaxed = replace(options, require_signature=False) if options else ResolveOptions()
    try:
        return resolve_with_options_or_raise(
            spec, source=source, loader=loader, options=relaxed
        )
    except ValueError:
        return None


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
            return False, _resolve_error(exc)

    # Merge-only: no hashing, no verification, no chain -- the historical
    # `resolve()` behaviour, kept off the hot path that difftest and the
    # evaluator fixtures run.
    try:
        stack = [source] if source is not None else []
        resolved, chain = _resolve_inner(
            spec, source, loader or _create_composite_loader(), stack, prepared=None
        )
    except ValueError as exc:
        return False, _resolve_error(exc)
    return True, Resolution(spec=resolved, content_hash="", chain=chain)


def _resolve_error(exc: ValueError) -> ErrorMessage:
    """A resolution failure as a message that keeps its registry code.

    Every refusal from the walk is an ``extends`` failure (E010). Returning a
    bare string would leave a caller reading the default parse code off a
    message that never came from the parser.
    """
    return ErrorMessage(str(exc), getattr(exc, "error_code", ERROR_EXTENDS))


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
    if options.require_signature and keyring is not None:
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
        # A resolved document declares neither resolution field (core spec
        # 2.3). `merge` clears both for every longer chain; a one-hop chain
        # never reaches `merge`, so it is cleaned here.
        resolved = _own_document(spec)
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
        ChainLink(
            source=_label(source),
            content_hash=own_hash,
            signature=status,
            pinned=pin is not None,
        )
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
    return source if source is not None else MEMORY_SOURCE


def _split_digest_pin(reference: str, source: str | None) -> tuple[str, str | None]:
    """Split ``<ref>#sha256:<hex>`` into the reference and the pinned digest.

    A reference with no ``#`` fragment comes back unchanged. Every fragment is
    read as a pin: core spec 2.3 requires a malformed fragment to be rejected,
    so anything after the last ``#`` that is not exactly ``sha256:`` followed by
    64 lowercase hex digits is fatal rather than ignored. Loading the base
    anyway would turn a typo in a pin into no integrity check at all.
    """
    reference_part, marker, digest = reference.rpartition("#")
    if not marker:
        return reference, None
    if not reference_part or not is_content_hash(digest):
        raise PolicyVerificationError(
            f"malformed digest pin in 'extends: {reference}' at {_label(source)}: "
            "expected '<reference>#sha256:<64 lowercase hex>'",
            source=_label(source),
            status=SignatureStatus(verified=False, reason=REASON_INVALID_PIN),
        )
    return reference_part, digest


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

    envelope = prepared.locator(label)
    # Verification was attempted, so the outcome is always recorded (signing
    # spec section 6.5): a hop with no envelope carries ``missing_signature``
    # rather than nothing at all, which a reader could only take for "no check
    # was configured", and one whose envelope has nothing to be checked against
    # carries ``no_keyring``.
    if envelope is None:
        status = SignatureStatus(verified=False, reason=REASON_MISSING_SIGNATURE)
    elif prepared.keyring is None:
        status = SignatureStatus(verified=False, reason=REASON_NO_KEYRING)
    else:
        status = _verify_envelope(resolved, envelope, prepared)

    if not required or status.verified:
        return status

    if envelope is None:
        detail = "no signature envelope was found"
    elif prepared.keyring is None:
        detail = "a signature envelope was found but no keyring was configured"
    else:
        detail = "signature verification failed"
    # The reason code is part of the message as well as of `status`, so the
    # tuple-returning entry points do not lose it.
    raise PolicyVerificationError(
        f"refusing to load {label}: {detail} ({status.reason})",
        source=label,
        status=status,
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
        # Unreachable under `require_signature`: `_prepare` probes the backend
        # when a keyring is configured, and without one `_verify_hop` records
        # `no_keyring` before reaching this call. Opportunistically, an envelope
        # that cannot be checked is recorded as unverified rather than raised,
        # since the load was never gated on it.
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

    A URL source is ``<url>.sig``, fetched by whatever
    :func:`register_scheme_loader` installed for its scheme -- fetching a
    signature over the network must happen under the same rules as fetching the
    policy did, so it belongs to the transport rather than here. With no
    transport registered a URL source resolves to ``None``, exactly as a
    reference to one would be refused.
    """
    if source.startswith("builtin:") or source == MEMORY_SOURCE:
        return None

    locator = _registered_for(source, _SCHEME_SIGNATURE_LOCATORS)
    if locator is not None:
        return locator(source)
    if source.startswith(("http://", "https://")):
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


#: Loaders registered for a URL scheme, and the signature locators that go with
#: them. A transport lives outside this module -- :mod:`hushspec.http_loader`
#: is the one this SDK ships -- and registers itself here, so the built-in
#: loaders gain a scheme without this module growing a network client or a
#: dependency. Empty until something registers, which is why a URL reference is
#: refused by default.
_SCHEME_LOADERS: dict[str, Resolver] = {}
_SCHEME_SIGNATURE_LOCATORS: dict[str, SignatureLocator] = {}


def register_scheme_loader(
    scheme: str,
    loader: Resolver,
    *,
    signature_locator: SignatureLocator | None = None,
) -> None:
    """Serve ``<scheme>://`` references through *loader* in the default loaders.

    Registering a scheme is a deployment decision, never a document's: a policy
    that names an ``https:`` base is refused until the process that loads it
    has said that fetching over the network is acceptable.

    ``signature_locator`` is consulted by :func:`default_signature_locator` for
    sources with this scheme, so a transport that can fetch a policy can also
    fetch the ``<source>.sig`` beside it (signing spec section 7.1).
    """
    _SCHEME_LOADERS[scheme] = loader
    if signature_locator is not None:
        _SCHEME_SIGNATURE_LOCATORS[scheme] = signature_locator
    else:
        _SCHEME_SIGNATURE_LOCATORS.pop(scheme, None)


def unregister_scheme_loader(scheme: str) -> None:
    """Undo :func:`register_scheme_loader`, restoring the refusal."""
    _SCHEME_LOADERS.pop(scheme, None)
    _SCHEME_SIGNATURE_LOCATORS.pop(scheme, None)


def _registered_for(reference: str, table: dict[str, Any]) -> Any | None:
    """The entry registered for *reference*'s scheme, if any."""
    scheme, separator, _rest = reference.partition("://")
    return table.get(scheme) if separator else None


def create_composite_loader() -> Resolver:
    """Public alias for the builtin + filesystem loader."""
    return _create_composite_loader()


def _create_composite_loader() -> Resolver:
    """Loader that serves `builtin:<name>` references from the embedded
    rulesets and everything else from the filesystem. A bare name with no path
    separators or dots is tried as a builtin before falling back to the
    filesystem.

    A URL reference is served by the loader :func:`register_scheme_loader`
    installed for its scheme, and refused outright when none is installed: this
    module ships no HTTP client, and silently handing a URL to the filesystem
    loader would fail with a confusing "no such file or directory" instead of a
    clear refusal. :func:`hushspec.http_loader.install_https_loader` is what
    installs ``https:``.
    """

    def _loader(reference: str, source: str | None) -> LoadedSpec:
        if reference.startswith("builtin:"):
            spec = load_builtin(reference)
            if spec is None:
                raise ValueError(f"unknown builtin ruleset '{reference}'")
            return LoadedSpec(source=reference, spec=spec)

        registered = _registered_for(reference, _SCHEME_LOADERS)
        if registered is not None:
            return registered(reference, source)

        if reference.startswith("http://") or reference.startswith("https://"):
            raise ValueError(
                "HTTP-based policy loading is not supported by the default "
                f"loader; call hushspec.http_loader.install_https_loader() or "
                f"provide a custom `loader` for '{reference}'"
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
