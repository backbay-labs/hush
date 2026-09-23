"""The HushSpec error-code registry (``spec/registries/error-codes.yaml``).

The stable identifiers a conformant implementation reports when it refuses a
document, so "the document was rejected" can be checked as "rejected for this
reason". Every ``invalid/`` vector under ``fixtures/`` carries a
``<name>.expect.yaml`` sidecar naming the code its rejection MUST carry, and
``tests/test_shared_fixtures.py`` asserts it.

A registered code's meaning never changes. A code may stop being emitted; it is
never reused for a different condition.

Where the codes surface in this SDK:

* :func:`hushspec.parse` returns an :class:`ErrorMessage` -- a ``str`` that
  also carries ``.code`` -- so existing callers that treat the failure as text
  keep working.
* :class:`hushspec.validate.ValidationError` carries ``.code`` alongside the
  ``.kind`` slug that names the specific check.
* :class:`hushspec.resolve.ResolveRejected` carries ``.error_code``
  (:data:`ERROR_EXTENDS`) next to its own resolve-vector ``.code``.
"""

from __future__ import annotations

__all__ = [
    "ERROR_CODES",
    "ERROR_IO",
    "ERROR_PARSE",
    "ERROR_UNSUPPORTED_VERSION",
    "ERROR_DUPLICATE_PATTERN_NAME",
    "ERROR_CONSTRAINT_VIOLATION",
    "ERROR_INVALID_REGEX",
    "ERROR_EXTENDS",
    "ERROR_INVALID_DATE",
    "ErrorMessage",
]

#: Input could not be read. A transport-level failure, not a statement about
#: the document: nothing was parsed.
ERROR_IO = "E000"

#: The input is not a single YAML 1.2 Core document that deserializes into the
#: HushSpec model: a syntax error, a profile violation, a missing required
#: field, an unknown field at any nesting level, a value of the wrong type, or
#: an unknown enum variant.
ERROR_PARSE = "E001"

#: The ``hushspec`` field names a version this engine does not accept.
ERROR_UNSUPPORTED_VERSION = "E002"

#: Two entries of ``rules.secret_patterns.patterns`` share a ``name``.
ERROR_DUPLICATE_PATTERN_NAME = "E003"

#: A structural constraint of core Section 7 or of an extension module is
#: violated -- a ``when`` that nests too deeply or names a bad timezone, day,
#: time, capability or counter; a posture ``initial`` naming no defined state;
#: a timeout transition with no ``after``; a duplicate origins profile id; an
#: origins ``match`` enum outside its set; a detection threshold outside its
#: range; a ``metadata.controls`` entry with an ill-formed framework id or an
#: empty ``rule_paths``.
ERROR_CONSTRAINT_VIOLATION = "E004"

#: A pattern field holds a regular expression outside the HushSpec regex
#: profile (core Section 3.14).
ERROR_INVALID_REGEX = "E005"

#: The ``extends`` chain could not be resolved.
ERROR_EXTENDS = "E010"

#: A ``metadata`` date field is not an ISO 8601 calendar date.
ERROR_INVALID_DATE = "E011"

#: Every registered code, in registry order.
ERROR_CODES: tuple[str, ...] = (
    ERROR_IO,
    ERROR_PARSE,
    ERROR_UNSUPPORTED_VERSION,
    ERROR_DUPLICATE_PATTERN_NAME,
    ERROR_CONSTRAINT_VIOLATION,
    ERROR_INVALID_REGEX,
    ERROR_EXTENDS,
    ERROR_INVALID_DATE,
)


class ErrorMessage(str):
    """A failure message that also carries its registry code.

    A ``str`` subclass rather than a wrapper object, because the failure
    channel it travels on is the message itself: ``parse()`` returns
    ``(False, message)`` and callers print it, match on it, and pass it to
    ``ValueError``. Subclassing keeps every one of those working while
    ``.code`` becomes available to callers that want to branch on the reason
    rather than on the wording.
    """

    __slots__ = ("code",)

    def __new__(cls, message: str, code: str = ERROR_PARSE) -> "ErrorMessage":
        # A real check, not an `assert`: the closed registry is a guarantee to
        # every consumer of a failure message, and `python -O` strips asserts.
        if code not in ERROR_CODES:
            raise ValueError(f"{code!r} is not a registered error code")
        self = super().__new__(cls, message)
        self.code = code
        return self


def code_of(message: object, default: str = ERROR_PARSE) -> str:
    """The registry code carried by *message*, or *default* when it carries none."""
    return getattr(message, "code", default)
