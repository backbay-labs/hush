"""The error-code registry as this SDK reports it (core spec 8, Level 1).

``spec/registries/error-codes.yaml`` is the normative list; this file checks
that the constants match it entry for entry, and that the two channels a
refusal travels on -- ``parse()``'s message and ``ValidationError`` -- both
carry the code the registry defines for the condition they describe.

The per-vector assertions live in ``test_shared_fixtures.py``, which reads
each ``invalid/`` vector's ``.expect.yaml`` sidecar.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hushspec import parse, parse_or_raise, resolve_file, validate
from hushspec.error_codes import (
    ERROR_CODES,
    ERROR_CONSTRAINT_VIOLATION,
    ERROR_DUPLICATE_PATTERN_NAME,
    ERROR_EXTENDS,
    ERROR_INVALID_DATE,
    ERROR_INVALID_REGEX,
    ERROR_IO,
    ERROR_PARSE,
    ERROR_UNSUPPORTED_VERSION,
    ErrorMessage,
    code_of,
)
from hushspec.parse import CoreSafeLoader
from hushspec.resolve import ResolveRejected
from hushspec.validate import ValidationError

REPO_ROOT = Path(__file__).resolve().parents[3]
REGISTRY = REPO_ROOT / "spec" / "registries" / "error-codes.yaml"


def test_the_constants_match_the_published_registry() -> None:
    if not REGISTRY.is_file():
        pytest.skip(f"{REGISTRY} is not available outside the repository")
    registry = yaml.load(REGISTRY.read_text(encoding="utf-8"), Loader=CoreSafeLoader)
    published = [entry["code"] for entry in registry["codes"]]
    assert list(ERROR_CODES) == published


def test_an_error_message_is_a_string_that_also_carries_its_code() -> None:
    message = ErrorMessage("something went wrong", ERROR_CONSTRAINT_VIOLATION)
    assert message == "something went wrong"
    assert isinstance(message, str)
    assert message.code == ERROR_CONSTRAINT_VIOLATION
    assert f"{message}!" == "something went wrong!"


def test_an_error_message_refuses_an_unregistered_code() -> None:
    with pytest.raises(ValueError, match="'E999' is not a registered error code"):
        ErrorMessage("nope", "E999")


def test_code_of_falls_back_for_a_plain_string() -> None:
    assert code_of("plain") == ERROR_PARSE
    assert code_of("plain", ERROR_IO) == ERROR_IO


class TestParseCodes:
    @pytest.mark.parametrize(
        ("document", "code"),
        [
            ("name: no-version\n", ERROR_PARSE),
            ("- not\n- a mapping\n", ERROR_PARSE),
            ("{{{{ invalid yaml", ERROR_PARSE),
            ('hushspec: "0.1.0"\nbogus: 1\n', ERROR_PARSE),
            ("hushspec: 0.1\n", ERROR_UNSUPPORTED_VERSION),
            (
                'hushspec: "0.1.0"\nrules:\n  secret_patterns:\n    patterns:\n'
                '      - {name: a, pattern: "x", severity: critical}\n'
                '      - {name: a, pattern: "y", severity: critical}\n',
                ERROR_DUPLICATE_PATTERN_NAME,
            ),
            (
                'hushspec: "0.1.0"\nrules:\n  shell_commands:\n'
                '    forbidden_patterns: ["["]\n',
                ERROR_INVALID_REGEX,
            ),
            (
                'hushspec: "0.1.0"\nextensions:\n  posture:\n    initial: nope\n'
                "    states:\n      a:\n        capabilities: []\n"
                "    transitions: []\n",
                ERROR_CONSTRAINT_VIOLATION,
            ),
        ],
    )
    def test_the_failure_carries_its_registry_code(self, document, code) -> None:
        ok, result = parse(document)
        assert ok is False
        assert result.code == code, str(result)

    def test_the_code_rides_on_the_raising_form_too(self) -> None:
        with pytest.raises(ValueError) as caught:
            parse_or_raise("hushspec: 0.1\n")
        assert caught.value.code == ERROR_UNSUPPORTED_VERSION


class TestValidationCodes:
    @pytest.mark.parametrize(
        ("kind", "code"),
        [
            ("unsupported_version", ERROR_UNSUPPORTED_VERSION),
            ("duplicate_pattern_name", ERROR_DUPLICATE_PATTERN_NAME),
            ("invalid_regex", ERROR_INVALID_REGEX),
            ("invalid_date", ERROR_INVALID_DATE),
            ("invalid_condition", ERROR_CONSTRAINT_VIOLATION),
            ("anything_else", ERROR_CONSTRAINT_VIOLATION),
        ],
    )
    def test_each_kind_maps_to_its_registry_code(self, kind, code) -> None:
        assert ValidationError(kind, "message").code == code

    def test_a_validation_error_still_prints_as_its_message(self) -> None:
        assert str(ValidationError("invalid_condition", "boom")) == "boom"

    def test_an_unsupported_version_reports_e002(self) -> None:
        spec = parse_or_raise('hushspec: "9.9.9"\nname: v\n')
        errors = validate(spec).errors
        assert errors and errors[0].code == ERROR_UNSUPPORTED_VERSION

    def test_a_bad_metadata_date_reports_e011(self) -> None:
        spec = parse_or_raise(
            'hushspec: "0.1.0"\nname: v\nmetadata:\n  expiry_date: "not-a-date"\n'
        )
        errors = validate(spec).errors
        assert errors and errors[0].code == ERROR_INVALID_DATE

    def test_a_bad_condition_reports_e004(self) -> None:
        spec = parse_or_raise(
            'hushspec: "0.1.0"\nrules:\n  tool_access:\n'
            "    when:\n      capability: Shell\n    block: [deploy]\n"
        )
        errors = validate(spec).errors
        assert errors and errors[0].code == ERROR_CONSTRAINT_VIOLATION


class TestIoAndResolveCodes:
    def test_an_unreadable_file_reports_e000(self, tmp_path) -> None:
        ok, err = resolve_file(tmp_path / "absent.yaml")
        assert ok is False
        assert err.code == ERROR_IO

    def test_a_readable_but_unparsable_file_keeps_the_parse_code(self, tmp_path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("hushspec: 0.1\n")
        ok, err = resolve_file(path)
        assert ok is False
        assert err.code == ERROR_UNSUPPORTED_VERSION

    def test_every_resolution_refusal_is_e010(self) -> None:
        # The specific `code` names which resolve check failed; `error_code` is
        # the coarser registry identifier all of them share.
        rejection = ResolveRejected("nope", code="not_found")
        assert rejection.code == "not_found"
        assert rejection.error_code == ERROR_EXTENDS
