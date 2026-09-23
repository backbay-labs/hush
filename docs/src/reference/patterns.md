# Pattern grammars

Patterns are portable only when their field's grammar is respected. A tool
allowlist does not accept a glob just because a path rule does.

| Pattern class | Fields | Matching |
| --- | --- | --- |
| Path glob | Forbidden paths, path allowlists, secret skip paths | Normalized path segments |
| Host pattern | Egress and browser host lists, origin egress | Normalized DNS host or exact IP |
| Regex | Secret patterns, shell patterns, patch patterns, extra credential patterns | Restricted portable regex |
| Exact string | Tool names, input types, browser verbs, language IDs | No wildcard expansion |

The normative algorithms are [core section 3.14](../../../spec/hushspec-core.md#314-pattern-matching);
the wire and identifier grammars are in [Grammars](../../../spec/hushspec-grammars.md).

## Paths

Normalize NFC, convert backslashes to slashes, collapse dot segments, and strip
a trailing slash before matching. `*` and `?` do not cross a slash; `**`
can cross path segments. Brackets and braces are literal, not shell expansions.
Matching is case-sensitive regardless of the host filesystem. This is lexical
normalization, not filesystem resolution: the host must handle symlinks and
TOCTOU when opening the actual file.

An exception in `forbidden_paths` exempts only that block. It does not exempt
the action from a path allowlist or content scan.

## Hosts

Extract the host, strip scheme/userinfo/port/path/query, lowercase, remove a
trailing dot, and apply IDNA conversion. `*.example.com` matches one label;
`**.example.com` matches one or more. Neither implies the apex `example.com`.
IP literals require exact matches. Block entries take precedence over allows.

A matching hostname is an authorization decision, not a DNS or network sandbox.
For fetching policies, use the separately bounded HTTPS loaders and their
resolved-address protections.

## Regular expressions

The portable profile disallows lookaround, backreferences and POSIX classes.
It permits named groups but uses ASCII `\d`, `\w`, `\s`, `\b` and
ASCII-only case-insensitive folding. The maximum pattern length is 2048 bytes.
Use single-quoted YAML for literal regex backslashes, or double the backslash
inside a double-quoted YAML string.

```yaml
hushspec: "1.0.0"
name: token-output-gate
rules:
  secret_patterns:
    patterns:
      - name: synthetic-token
        pattern: 'TEST_TOKEN_[A-Z0-9]{16}'
        severity: error
```

Validate the actual YAML bytes with `h2h validate --strict policy.yaml`.
A regex that compiles in one language's native engine can still be outside
the portable profile. See [error codes](errors.md) for `E005`.
