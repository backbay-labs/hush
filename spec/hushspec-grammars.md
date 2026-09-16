# HushSpec Grammars

**Version:** 1.0.0
**Status:** Stable
**Date:** 2026-09-15
**Companion to:** HushSpec Core, Posture, Origins, Detection, Receipt, Signing

---

## 1. Introduction

This document collects, in ABNF (RFC 5234, with the core rules `ALPHA`, `DIGIT`, `HEXDIG`, `DQUOTE`, and `VCHAR`), the grammars that the HushSpec family defines in prose elsewhere. Where a grammar and its prose disagree, the prose in the defining specification is normative and the grammar here is an erratum candidate (`errata.md`).

Each production is followed by examples that MUST match (marked +) and examples that MUST NOT (marked -). Where a fixture already pins the behavior, the fixture is cited.

Conformant implementations are not required to implement these grammars as parsers. They are required to accept and reject the same strings.

### 1.1 Shared Productions

```abnf
lower       = %x61-7A                 ; a-z
identifier  = lower *( lower / DIGIT / "_" )
dotted-id   = identifier *( "." identifier )
scalar      = %x00-D7FF / %xE000-10FFFF             ; any Unicode scalar value
non-slash   = %x00-2E / %x30-D7FF / %xE000-10FFFF   ; any scalar value except "/"
non-dot     = %x00-2D / %x2F-D7FF / %xE000-10FFFF   ; any scalar value except "."
```

`dotted-id` is the identifier grammar of Core Section 3.13 for capability names and counter names.

- `+ file_access`, `+ audit.reads_per_minute`
- `- FileAccess` (uppercase), `- 1st` (leading digit), `- a..b` (empty segment)

Fixture: `fixtures/core/invalid/when-capability-bad-name.yaml`, `fixtures/core/invalid/when-rate-bad-counter.yaml`.

---

## 2. Path Globs (Core Section 3.14.1)

### 2.1 Normalized Paths

The subject of a path match is the normalized target path. After the transformation of Core Section 3.14.1 it has this shape:

```abnf
normalized-path = "/" / [ "/" ] path-segments
path-segments   = path-segment *( "/" path-segment )
path-segment    = 1*non-slash
```

A normalized path contains no `\`, no empty segment, no `.` segment, no `..` segment (except leading `..` in a relative path), and no trailing `/` unless it is `/`.

- `+ /home/user/.env`, `+ src/main.rs`, `+ ../shared/config`
- `- /home//user` (empty segment), `- /home/user/` (trailing slash), `- C:\Users` (separator)

### 2.2 Patterns

```abnf
path-glob     = [ "/" ] glob-segments
glob-segments = glob-segment *( "/" glob-segment )
glob-segment  = "**" / 1*glob-atom
glob-atom     = "*" / "?" / glob-literal
glob-literal  = non-slash              ; "*" and "?" excluded by the alternatives above
```

`*` matches zero or more `non-slash`; `?` matches exactly one `non-slash`; `**` as a whole segment matches zero or more complete segments, so `a/**/b` matches `a/b`, `a/x/b`, and `a/x/y/b`; `**` inside a segment matches any sequence of scalar values including `/`. Every other character is literal, including `[`, `{`, `(`, `.`, `+`, `^`, `$`, `|`, and `\`. Patterns are anchored at both ends.

- `+ **/.env` matches `.env`, `a/.env`, `a/b/.env`
- `+ /home/**` matches `/home/x` and `/home/x/y`; `- /home/**` does not match `/home`
- `+ src/*.rs` matches `src/main.rs`; `- src/*.rs` does not match `src/a/b.rs`
- `+ [abc]` matches the literal path `[abc]` only

Fixture: `fixtures/core/evaluation/path-normalization-lexical.test.yaml`, `fixtures/core/evaluation/forbidden-paths-leading-globstar.test.yaml`.

---

## 3. Host Patterns (Core Section 3.14.2)

### 3.1 Normalized Hosts

```abnf
normalized-host = dns-host / ipv4-literal / ipv6-literal
dns-host        = label *( "." label )
label           = let-dig [ *( let-dig / "-" ) let-dig ]
let-dig         = lower / DIGIT
ipv4-literal    = dec-octet 3( "." dec-octet )
dec-octet       = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35
ipv6-literal    = "[" IPv6address "]"    ; IPv6address per RFC 3986 Section 3.2.2
```

A normalized host is lowercase, has no trailing `.`, no port, no userinfo, no path, and every non-ASCII label converted to its A-label (`xn--...`).

- `+ api.example.com`, `+ xn--caf-dma.example.com`, `+ 192.168.1.1`, `+ [2001:db8::1]`
- `- API.example.com` (case), `- example.com.` (trailing dot), `- example.com:443` (port), `- café.example.com` (U-label)

### 3.2 Patterns

```abnf
host-pattern   = pattern-label *( "." pattern-label )
pattern-label  = "**" / 1*pattern-atom
pattern-atom   = "*" / lower / DIGIT / "-"
```

`*` matches one or more `non-dot` scalar values within a single label and MAY appear inside a label; `**` as a whole label matches one or more labels; everything else is literal. Patterns are anchored at both ends. A wildcard never implies the apex host, and wildcards never match IP literals.

- `+ *.example.com` matches `api.example.com`; `- *.example.com` does not match `a.b.example.com` or `example.com`
- `+ api-*.example.com` matches `api-1.example.com`
- `+ **.example.com` matches `a.b.example.com`; `- **.example.com` does not match `example.com`
- `+ 10.0.0.1` matches only `10.0.0.1`; `- *.0.0.1` does not match `10.0.0.1`

Fixture: `fixtures/core/evaluation/egress-host-normalization.test.yaml`.

---

## 4. Tool Identifiers (Core Section 3.7)

```abnf
tool-id = *scalar
```

A tool identifier is any string; the specification constrains neither its characters nor its length, and an empty entry matches only an action whose tool name is empty. Tool names are compared for equality after NFC normalization of both sides. There is no wildcard form; `*` in a tool list is the literal name `*`.

- `+ read_file`, `+ mcp__github__create_issue`, `+ Deploy`, `+ read file`
- `- Read_File` does not match `read_file` (case), `- read_*` does not match `read_file` (no wildcards)

Fixture: `fixtures/core/evaluation/tool-glob-literal.test.yaml`, `fixtures/core/evaluation/tool-allowlist-deny.test.yaml`.

---

## 5. Rule Paths and Rule Identifiers

Rule paths name a rule block, a field within it, or one entry of a named list. They appear as `matched_rule` in decisions and receipts (Receipt Section 4.5), as `rule_path` in rule traces (Receipt Section 4.3), as lint locations, as enforcement override keys (Core Section 6.2), and as `rule_paths` in control mappings (Core Section 2.5.1).

```abnf
rule-path      = block-path / extension-path / engine-rule
block-path     = "rules" [ "." block-name *( "." segment ) ]
block-name     = "forbidden_paths" / "path_allowlist" / "egress" / "secret_patterns"
               / "patch_integrity" / "shell_commands" / "tool_access" / "computer_use"
               / "remote_desktop_channels" / "input_injection" / "browser_automation"
               / "code_execution"
extension-path = "extensions" [ "." extension-name *( "." segment ) ]
extension-name = "posture" / "origins" / "detection"
segment        = name [ index ]
name           = 1*name-char
name-char      = %x00-2D / %x2F-5A / %x5C-D7FF / %xE000-10FFFF   ; any scalar value except "." and "["
index          = "[" 1*DIGIT "]"
engine-rule    = "__hushspec_panic__" / "__unknown_action_type__"
               / "__hushspec_policy_unverified__" / "detection"
```

A path descends from a rule block or an extension module one segment at a time. A segment is a schema field name (`rules.egress.default`) or the `name` or `id` of a named entry written verbatim (`rules.secret_patterns.patterns.aws_access_key`, `extensions.origins.profiles.ci.egress.block`, `extensions.posture.states.locked.capabilities`). A list of unnamed entries is addressed by a zero-based `index` on the field that holds it (`rules.shell_commands.forbidden_patterns[0]`). Because entry names are verbatim, a name that contains `.` or `[` yields a path that cannot be split unambiguously; authors SHOULD avoid such names. Control mappings address named entries with a bracketed selector instead (Section 6).

The four `engine-rule` values are reserved: three name engine stages that precede rule evaluation, and `detection` is the `matched_rule` of a decision the detection pipeline produced. The closed set of `rule_block` identifiers a receipt's trace may carry is the registry `spec/registries/rule-paths.yaml`.

- `+ rules.egress`, `+ rules.egress.allow`, `+ rules.secret_patterns.patterns.aws_access_key`, `+ rules.tool_access.max_args_size`, `+ rules.patch_integrity.forbidden_patterns[2]`, `+ extensions.origins.profiles.ci.tool_access.allow`, `+ extensions.posture.states.locked.capabilities`, `+ __hushspec_panic__`
- `- rules.Egress` (case), `- rules.egress.allow[` (unterminated index), `- rule.egress` (prefix)

Fixture: `fixtures/receipts/expected/` (every `matched_rule` and `rule_path` in the expected receipts).

---

## 6. Control Mapping Paths (Core Section 2.5.1)

A control mapping's `rule_paths` entries use the grammar of Core Section 2.5.1: the `block-path` and `extension-path` shapes of Section 5 without the `engine-rule` alternative, except that a named entry is addressed by a bracketed selector holding its `name` or `id` (`rules.secret_patterns.patterns[ssn]`) rather than by a verbatim segment. `rules` alone maps a control to every rule block; `extensions.posture` maps it to the whole extension.

- `+ rules`, `+ rules.egress`, `+ rules.secret_patterns.patterns[ssn]`, `+ extensions.posture`
- `- __hushspec_panic__` (not a document path), `- rules.egress.allow[*]` (no wildcards)

Fixture: `fixtures/core/valid/metadata-controls.yaml`, `fixtures/core/invalid/metadata-controls-empty-paths.yaml`.

---

## 7. Capabilities and Counters (Core Section 3.13, Posture Section 3)

```abnf
capability   = dotted-id
counter-name = dotted-id
```

The standard capabilities are listed in Posture Section 3.1 and in the registry `spec/registries/capabilities.yaml`, which is open: an engine MAY define further capabilities, and a policy MAY name them.

---

## 8. Version Strings (Core Section 2.2)

```abnf
hushspec-version = major "." minor "." patch
major            = 1*DIGIT
minor            = 1*DIGIT
patch            = 1*DIGIT
```

Pre-release and build suffixes are not permitted in a document's `hushspec` field. An engine declares the `major.minor` pairs it supports and MUST accept every patch of each (Core Section 2.2).

- `+ 0.2.0`, `+ 1.0.3`
- `- 0.2` (two components), `- 1.0.0-rc.1` (suffix), `- v1.0.0`

Fixture: `fixtures/core/invalid/float-version.yaml`, `fixtures/core/valid/version-patch-accept.yaml`.

---

## 9. Regex Profile (Core Section 3.14.3)

The profile is a subset of RE2 syntax. The grammar below is the accepted surface; the semantics (ASCII-only class escapes, end-of-text `$`, ASCII case folding under `i`) are defined in Core Section 3.14.3 and are not expressible in ABNF.

```abnf
regex          = [ flags ] alternation
flags          = "(?" 1*( "i" / "m" / "s" ) ")"
alternation    = concatenation *( "|" concatenation )
concatenation  = *piece
piece          = atom [ quantifier [ "?" ] ]
quantifier     = "?" / "*" / "+" / "{" count "}"
count          = 1*DIGIT [ "," [ 1*DIGIT ] ]
atom           = literal / escape / class-escape / any / bracket / assertion / group
literal        = %x20-23 / %x25-27 / %x2C-2D / %x2F-3E / %x40-5A / %x5F-7A / %x7E / %x80-10FFFF
                 ; any scalar value except the metacharacters \ . [ ] ( ) | ? * + { } ^ $
escape         = "\" ( "t" / "n" / "r" / "f" / "v" / punct / "x" 2HEXDIG )
punct          = %x21-2F / %x3A-40 / %x5B-60 / %x7B-7E
class-escape   = "\" ( "d" / "D" / "w" / "W" / "s" / "S" )
any            = "."
assertion      = "^" / "$" / "\b" / "\B"
group          = "(" [ "?:" ] alternation ")"
bracket        = "[" [ "^" ] 1*bracket-item "]"
bracket-item   = class-escape / bracket-range / bracket-atom
bracket-range  = bracket-atom "-" bracket-atom
bracket-atom   = escape / %x20-5B / %x5E-D7FF / %xE000-10FFFF   ; any scalar value except "]" and "\"
```

Constraints the grammar cannot express, all normative in Core Section 3.14.3: no lookaround, backreferences, possessive quantifiers, atomic groups, conditionals, named groups, `\A`, `\z`, `\Z`, `\G`, `\p{...}`, or flag groups after the first character; a quantified group whose body is itself unbounded is rejected. The specification sets no length limit on a pattern.

- `+ (?i)ignore (all )?previous instructions`, `+ [0-9]{3}-[0-9]{2}-[0-9]{4}`, `+ \bsecret\b`
- `- (?=rm)` (lookahead), `- (a+)+` (nested unbounded), `- foo(?i)bar` (mid-pattern flag), `- \p{L}` (property class)

Fixture: `fixtures/core/evaluation/regex-dialect.test.yaml`, `fixtures/core/invalid/regex-mid-pattern-flag.yaml`.

---

## 10. YAML Profile Checklist (Core Section 2.4)

A conformant parser accepts a document only when all of the following hold. The list restates Core Section 2.4 so that implementers can check it item by item.

1. The stream contains exactly one document.
2. Scalars resolve under the YAML 1.2 Core schema: `yes`, `no`, `on`, `off`, `y`, and `n` are strings.
3. No mapping has a duplicate key at any depth.
4. No anchor, alias, or merge key is present.
5. The `hushspec` value is a string.
6. The input is at most 1 MiB, nests at most 32 levels, and contains at most 100,000 nodes, unless the engine documents different limits.
7. Indentation uses spaces only; a byte order mark, if present, is ignored.

Fixture: `fixtures/core/invalid/yaml-alias.yaml`, `fixtures/core/invalid/yaml-bool-yes.yaml`, `fixtures/core/invalid/yaml-multi-doc.yaml`, `fixtures/core/invalid/yaml-duplicate-key.yaml`.

---

## 11. Detector Identifiers (Detection Section 9)

```abnf
detector-id      = detector-name "@" detector-version
detector-name    = identifier
detector-version = 1*DIGIT
```

- `+ regex_injection@1`, `+ heuristic_injection@1`
- `- regex_injection` (no version), `- Regex-Injection@1` (case, hyphen)

---

## 12. Media Types (Core Section 11; registry `spec/registries/media-types.yaml`)

```abnf
hushspec-media-type = "application/vnd.hushspec" [ "." subtype ] "+" suffix
subtype             = "receipt" / "log" / "signature" / "keyring" / "bundle"
suffix              = "yaml" / "json" / "jsonl"
```

Only the combinations listed in the registry are defined.
