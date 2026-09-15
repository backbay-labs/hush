"""HushGuard must never hold a policy whose `extends` is unresolved."""

from __future__ import annotations

from pathlib import Path

import pytest

from hushspec.evaluate import Decision, EvaluationAction
from hushspec.middleware import HushGuard
from hushspec.parse import parse_or_raise
from hushspec.receipt import compute_policy_hash
from hushspec.resolve import resolve_file

REPO_ROOT = Path(__file__).resolve().parents[3]

BUILTIN_CHILD = """
hushspec: "0.1.0"
extends: "builtin:strict"
name: leaf
rules:
  egress:
    allow: ["api.example.com"]
    default: block
"""

BASE_POLICY = """
hushspec: "0.1.0"
name: base
rules:
  tool_access:
    allow: [read_file]
    default: block
"""


def test_from_file_resolves_library_policy_against_builtin_base():
    # recommended.yaml declares secret_patterns/patch_integrity/shell_commands/
    # tool_access and inherits forbidden_paths + egress from builtin:default.
    path = REPO_ROOT / "library/general/recommended.yaml"
    on_disk = parse_or_raise(path.read_text())
    assert on_disk.extends == "builtin:default"
    assert on_disk.rules is not None and on_disk.rules.forbidden_paths is None

    guard = HushGuard.from_file(str(path))
    spec = guard._policy

    assert spec.extends is None
    # A rule block the leaf policy does not define at all.
    assert spec.rules is not None and spec.rules.forbidden_paths is not None
    assert "**/.ssh/**" in spec.rules.forbidden_paths.patterns
    assert spec.rules.egress is not None
    # ...and it is enforced: loaded unresolved, this read was allowed.
    result = guard.evaluate(EvaluationAction(type="file_read", target="/home/dev/.ssh/id_rsa"))
    assert result.decision == Decision.DENY


def test_from_file_resolves_hipaa_base_and_hashes_resolved_document():
    path = REPO_ROOT / "library/healthcare/hipaa-base.yaml"
    guard = HushGuard.from_file(str(path))
    assert guard._policy.extends is None

    ok, resolved = resolve_file(path)
    assert ok
    assert compute_policy_hash(guard._policy) == compute_policy_hash(resolved)


def test_from_file_resolves_relative_extends_against_policy_directory(tmp_path):
    (tmp_path / "base.yaml").write_text(BASE_POLICY)
    (tmp_path / "child.yaml").write_text(
        'hushspec: "0.1.0"\nextends: base.yaml\nname: child\n'
        'rules:\n  egress:\n    allow: ["api.example.com"]\n    default: block\n'
    )

    guard = HushGuard.from_file(str(tmp_path / "child.yaml"))
    assert guard._policy.extends is None
    assert guard.evaluate(EvaluationAction(type="tool_call", target="read_file")).decision == (
        Decision.ALLOW
    )
    assert guard.evaluate(EvaluationAction(type="tool_call", target="shell_exec")).decision == (
        Decision.DENY
    )


def test_from_yaml_resolves_builtin_references_by_default():
    guard = HushGuard.from_yaml(BUILTIN_CHILD)
    spec = guard._policy
    assert spec.extends is None
    assert spec.rules is not None and spec.rules.forbidden_paths is not None
    assert "/etc/shadow" in spec.rules.forbidden_paths.patterns
    assert guard.evaluate(
        EvaluationAction(type="file_read", target="/etc/shadow")
    ).decision == Decision.DENY


def test_from_yaml_rejects_unknown_builtin_base():
    with pytest.raises(ValueError, match="unknown builtin ruleset"):
        HushGuard.from_yaml('hushspec: "0.1.0"\nextends: "builtin:nope"\nname: leaf\n')


def test_from_yaml_rejects_file_base_without_base_dir():
    with pytest.raises(ValueError, match="only serves builtin rulesets"):
        HushGuard.from_yaml('hushspec: "0.1.0"\nextends: "./base.yaml"\nname: leaf\n')


def test_from_yaml_resolves_file_base_with_base_dir(tmp_path):
    (tmp_path / "base.yaml").write_text(BASE_POLICY)
    guard = HushGuard.from_yaml(
        'hushspec: "0.1.0"\nextends: "./base.yaml"\nname: leaf\n',
        base_dir=str(tmp_path),
    )
    assert guard._policy.extends is None
    assert guard.evaluate(
        EvaluationAction(type="tool_call", target="read_file")
    ).decision == Decision.ALLOW


def test_from_yaml_rejects_missing_file_base_under_base_dir(tmp_path):
    with pytest.raises(ValueError, match="failed to resolve policy"):
        HushGuard.from_yaml(
            'hushspec: "0.1.0"\nextends: "./missing.yaml"\nname: leaf\n',
            base_dir=str(tmp_path),
        )


def test_constructor_rejects_unresolvable_policy():
    leaf = parse_or_raise('hushspec: "0.1.0"\nextends: "./base.yaml"\nname: leaf\n')
    with pytest.raises(ValueError, match="failed to resolve policy"):
        HushGuard(leaf)


def test_swap_policy_rejects_unresolved_policy():
    guard = HushGuard.from_yaml(
        'hushspec: "0.1.0"\nname: allow-all\n'
        'rules:\n  tool_access:\n    default: allow\n'
    )
    leaf = parse_or_raise('hushspec: "0.1.0"\nextends: "./nope.yaml"\nname: leaf\n')
    with pytest.raises(ValueError, match="failed to resolve policy"):
        guard.swap_policy(leaf)
    # The previously resolved policy stays in force.
    assert guard.evaluate(
        EvaluationAction(type="tool_call", target="anything")
    ).decision == Decision.ALLOW


def test_compute_policy_hash_refuses_unresolvable_policy():
    leaf = parse_or_raise('hushspec: "0.1.0"\nextends: "./base.yaml"\nname: leaf\n')
    with pytest.raises(ValueError, match="cannot hash an unresolved policy"):
        compute_policy_hash(leaf)


def test_compute_policy_hash_resolves_builtin_base():
    leaf = parse_or_raise(BUILTIN_CHILD)
    guard = HushGuard.from_yaml(BUILTIN_CHILD)
    assert compute_policy_hash(leaf) == compute_policy_hash(guard._policy)
