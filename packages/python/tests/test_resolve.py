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

    def test_rejects_http_extends(self):
        # The default composite loader has no HTTP client -- an http(s)://
        # extends reference must be rejected with a clear error rather than
        # silently handed to the filesystem loader (which would fail with a
        # confusing "no such file or directory" instead).
        child = parse_or_raise(
            'hushspec: "0.1.0"\nname: x\n'
            'extends: "http://example.com/policy.yaml"\n'
        )
        ok, err = resolve(child)
        assert not ok
        assert "HTTP" in err

    def test_rejects_https_extends(self):
        child = parse_or_raise(
            'hushspec: "0.1.0"\nname: x\n'
            'extends: "https://example.com/policy.yaml"\n'
        )
        ok, err = resolve(child)
        assert not ok
        assert "HTTP" in err


class TestExtendsDepthCap:
    def test_long_acyclic_chain_errors_at_depth_cap(self):
        # S2: an acyclic `extends` chain longer than the cap (32) must fail
        # closed with a clean error rather than recurse until a stack overflow.
        # 40 distinct specs, each extending the next; the 40th is terminal.
        total = 40
        specs: dict[str, object] = {}
        for i in range(total):
            if i < total - 1:
                specs[f"spec-{i}"] = parse_or_raise(
                    f'hushspec: "0.1.0"\nname: spec-{i}\nextends: spec-{i + 1}\n'
                )
            else:
                specs[f"spec-{i}"] = parse_or_raise(
                    f'hushspec: "0.1.0"\nname: spec-{i}\n'
                )

        def loader(reference: str, _source):
            return LoadedSpec(source=f"memory://{reference}", spec=specs[reference])

        ok, err = resolve(specs["spec-0"], source="memory://spec-0", loader=loader)
        assert not ok
        assert isinstance(err, str)
        assert "exceeds maximum depth of 32" in err

    def test_depth_three_chain_resolves(self):
        # A short chain (child -> spec-1 -> spec-2 -> spec-3) is well under the
        # cap and must resolve, merging the whole chain end-to-end.
        specs = {
            "spec-1": parse_or_raise(
                'hushspec: "0.1.0"\nname: spec-1\nextends: spec-2\n'
            ),
            "spec-2": parse_or_raise(
                'hushspec: "0.1.0"\nname: spec-2\nextends: spec-3\n'
            ),
            "spec-3": parse_or_raise(
                'hushspec: "0.1.0"\nname: spec-3\n'
                "rules:\n"
                "  tool_access:\n"
                "    default: block\n"
            ),
        }
        child = parse_or_raise(
            'hushspec: "0.1.0"\nname: child\nextends: spec-1\n'
        )

        def loader(reference: str, _source):
            return LoadedSpec(source=f"memory://{reference}", spec=specs[reference])

        ok, resolved = resolve(child, source="memory://child", loader=loader)
        assert ok, resolved
        assert resolved.extends is None
        assert resolved.name == "child"
        # Rule from the deepest ancestor (spec-3) is inherited through the chain.
        assert resolved.rules is not None
        assert resolved.rules.tool_access is not None
        assert resolved.rules.tool_access.default.value == "block"
