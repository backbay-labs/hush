from __future__ import annotations

from pathlib import Path

from hushspec import LoadedSpec, parse_or_raise, resolve, resolve_file


class TestResolve:
    def test_resolve_file_merges_extends_chain(self, tmp_path: Path):
        (tmp_path / "base.yaml").write_text(
            """
hushspec: "0.1.0"
name: base
rules:
  tool_access:
    allow: [read_file]
    default: block
"""
        )
        (tmp_path / "child.yaml").write_text(
            """
hushspec: "0.1.0"
extends: base.yaml
name: child
rules:
  egress:
    allow: [api.example.com]
    default: allow
"""
        )

        ok, result = resolve_file(tmp_path / "child.yaml")
        assert ok, result
        assert result.extends is None
        assert result.name == "child"
        assert result.rules is not None
        assert result.rules.tool_access is not None
        assert result.rules.tool_access.allow == ["read_file"]
        assert result.rules.tool_access.default.value == "block"
        assert result.rules.egress is not None
        assert result.rules.egress.allow == ["api.example.com"]
        assert result.rules.egress.default.value == "allow"

    def test_resolve_file_detects_cycles(self, tmp_path: Path):
        (tmp_path / "a.yaml").write_text(
            """
hushspec: "0.1.0"
extends: b.yaml
"""
        )
        (tmp_path / "b.yaml").write_text(
            """
hushspec: "0.1.0"
extends: a.yaml
"""
        )

        ok, result = resolve_file(tmp_path / "a.yaml")
        assert not ok
        assert "circular extends detected" in result

    def test_resolve_supports_custom_loader(self):
        child = parse_or_raise(
            """
hushspec: "0.1.0"
extends: parent
"""
        )

        ok, result = resolve(
            child,
            source="memory://child",
            loader=lambda reference, _: LoadedSpec(
                source=f"memory://{reference}",
                spec=parse_or_raise(
                    """
hushspec: "0.1.0"
name: parent
"""
                ),
            ),
        )

        assert ok, result
        assert result.extends is None
        assert result.name == "parent"

    def test_resolves_builtin_extends(self):
        child = parse_or_raise(
            'hushspec: "0.1.0"\n'
            "name: child\n"
            'extends: "builtin:strict"\n'
            "rules:\n"
            "  egress:\n"
            "    default: allow\n"
        )
        ok, resolved = resolve(child)
        assert ok, resolved
        # tool_access is inherited from builtin:strict (child does not define it)
        assert resolved.rules.tool_access is not None
        assert resolved.rules.tool_access.default.value == "block"
        # the child's egress replaces the builtin's
        assert resolved.rules.egress.default.value == "allow"

    def test_resolves_bare_builtin_name(self):
        child = parse_or_raise('hushspec: "0.1.0"\nname: c\nextends: strict\n')
        ok, resolved = resolve(child)
        assert ok, resolved
        assert resolved.rules.tool_access.default.value == "block"

    def test_unknown_builtin_extends_errors(self):
        child = parse_or_raise(
            'hushspec: "0.1.0"\nname: x\nextends: "builtin:nope"\n'
        )
        ok, err = resolve(child)
        assert not ok
        assert "nope" in err
