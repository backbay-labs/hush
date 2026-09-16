# HushSpec Vertical Policy Library

Curated, compliance-mapped HushSpec policies for regulated industries and common deployment scenarios. Each policy is a valid HushSpec document that can be used directly or extended via the `extends` field.

> **DISCLAIMER:** These policies are starting points, not certified compliance solutions. Organizations MUST review and customize each policy for their specific environment, threat model, and regulatory requirements. Engage qualified compliance professionals (HIPAA Privacy Officers, QSAs, 3PAOs, etc.) before deploying in production.

## Policies

| Policy | Builtin reference | Frameworks (registry id) | Description |
|--------|-------------------|--------------------------|-------------|
| HIPAA Base | `builtin:library/healthcare/hipaa-base` | `hipaa-2013` | PHI protection, restricted egress to health endpoints, clinical data pattern detection |
| SOC2 Base | `builtin:library/finance/soc2-base` | `soc2-tsc-2017` | Access controls, change management, transmission security for SOC2-audited environments |
| PCI-DSS | `builtin:library/finance/pci-dss` | `pci-dss-4.0` | Card number detection (Visa, MC, Amex, Discover), CVV/track data blocking, CDE path protection |
| FedRAMP Base | `builtin:library/government/fedramp-base` | `nist-800-53-r5` | .gov/.mil egress default, CUI path protection, minimal tool access |
| FERPA Student | `builtin:library/education/ferpa-student` | `ferpa` | Student PII detection, education record path protection, approved LMS egress |
| CI/CD Hardened | `builtin:library/devops/cicd-hardened` | `owasp-llm-top10-2025`, `iso-27001-2022` | Pipeline-safe egress (registries only), CI token detection, build/test tools only |
| Air-Gapped | `builtin:library/general/air-gapped` | `iso-27001-2022`, `owasp-llm-top10-2025` | Zero egress, zero shell, read-only tools |
| Recommended | `builtin:library/general/recommended` | `owasp-llm-top10-2025`, `nist-ai-rmf-1.0` | Sensible defaults with broad secret detection and patch limits |

Each policy's file is `<vertical>/<name>.yaml` under this directory, and its
builtin reference is `builtin:library/<vertical>/<name>` -- the same string in
every SDK.

## Structured Control Mappings

Every policy declares which control it implements, and where, in `metadata.controls`
(core spec 2.5) rather than only in comments:

```yaml
metadata:
  controls:
    - framework: hipaa-2013
      control_id: "164.312(e)(1)"
      rule_paths:
        - rules.egress
      notes: "Transmission Security. Egress defaults to block."
```

`framework` is an id from [`spec/registries/frameworks.yaml`](../spec/registries/frameworks.yaml),
which also carries the `control_id_pattern` each framework's ids must match. Each
`rule_paths` entry is a dot path into the **resolved** document -- `rules`,
`rules.egress`, `rules.egress.allow`, `rules.secret_patterns.patterns[ssn]`,
`extensions.posture` -- so a policy may map a rule block it inherits from its base.

Mappings are declarative: they never influence evaluation. They are enforced by
tooling instead:

| Code | Severity | Check |
|------|----------|-------|
| L011 | warning  | A rule block has no control mapping (only once the policy declares any) |
| L012 | error    | A `rule_paths` entry resolves to nothing in the resolved document |
| L013 | warning  | The framework is unregistered, or the control id does not match its pattern |

```bash
# Every library policy is clean under the full gate.
h2h lint --fail-on-warnings library/*/*.yaml

# The control -> rule-path matrix and rule-block coverage for one policy.
h2h audit --controls library/healthcare/hipaa-base.yaml
h2h audit --controls --format json --strict library/finance/pci-dss.yaml
```

## Usage

### Direct use

Every library policy is **embedded in all four SDKs** as
`builtin:library/<vertical>/<name>`, so `extends` resolves it with no file
system, no network, and no checkout of this repository:

```yaml
hushspec: "0.1.0"
name: my-org-policy
extends: "builtin:library/healthcare/hipaa-base"
merge_strategy: deep_merge

rules:
  # Override or add rules specific to your organization
  egress:
    allow:
      - "api.my-ehr-vendor.com"
      - "*.my-org.com"
    default: block
```

The same reference works from each SDK's loader:

```rust
let yaml = hushspec::load_builtin("builtin:library/healthcare/hipaa-base").unwrap();
```

```typescript
import { loadBuiltin } from '@hushspec/core';
const spec = loadBuiltin('builtin:library/healthcare/hipaa-base');
```

```python
from hushspec.builtins import load_builtin
spec = load_builtin("builtin:library/healthcare/hipaa-base")
```

```go
spec, ok := hushspec.LoadBuiltin("builtin:library/healthcare/hipaa-base")
```

A relative file reference (`extends: "library/healthcare/hipaa-base.yaml"`)
still works when this repository is on disk; the builtin reference is the
portable form.

### As a starting point

Copy a library policy and customize it:

```bash
cp library/finance/soc2-base.yaml my-policy.yaml
# Edit my-policy.yaml to match your control environment
hushspec validate my-policy.yaml
```

### Validation

All library policies pass the HushSpec validator:

```bash
cargo run -p hushspec-cli -- validate library/**/*.yaml
```

## Directory Structure

```
library/
  healthcare/
    hipaa-base.yaml           # HIPAA Security Rule compliance
  finance/
    soc2-base.yaml            # SOC2 Trust Services Criteria
    pci-dss.yaml              # PCI-DSS v4.0 payment data
  government/
    fedramp-base.yaml         # FedRAMP / NIST 800-53
  education/
    ferpa-student.yaml        # FERPA student data protection
  devops/
    cicd-hardened.yaml        # CI/CD pipeline hardening
  general/
    air-gapped.yaml           # Zero-network isolation
    recommended.yaml          # Production baseline
  README.md                   # This file
```

## Test Suites

Every policy has a control-tagged evaluation suite at
`fixtures/library/<vertical>/<name>.test.yaml`. Each case declares the control
it proves, in the same `framework` / `control_id` vocabulary as
`metadata.controls`, so a passing run is evidence for a specific control
rather than a green tick:

```yaml
- description: "PHI directories are unreachable"
  controls:
    - framework: hipaa-2013
      control_id: "164.312(a)(1)"
  tags: ["deny", "forbidden-paths"]
  action:
    type: file_read
    target: "/srv/app/patient-records/2026.csv"
  expect:
    decision: deny
    matched_rule: rules.forbidden_paths.patterns
```

The suites cover every rule block and every named secret pattern of each
resolved policy, and CI gates that:

```bash
# Every case, with 100% rule coverage required.
h2h test --fixtures fixtures/library --fail-on-uncovered

# One policy, as a JUnit report.
h2h test fixtures/library/finance/pci-dss.test.yaml \
  --format junit --report-file target/pci-dss.xml
```

## Contribution Guidelines

When adding a new policy to the library:

1. **Valid HushSpec.** The policy MUST parse and validate successfully with `hushspec validate`.
2. **Comment headers.** Include a comment block at the top of the file with:
   - The compliance framework and specific control mappings
   - A disclaimer noting this is a starting point, not a certification
3. **Structured mappings.** Declare `metadata.controls` so every rule block the
   resolved policy contains is mapped to at least one control, every `rule_paths`
   entry resolves, and every `framework`/`control_id` pair is registered in
   `spec/registries/frameworks.yaml`. Keep the inline `# --- CONTROL: ... ---`
   comments as well: they are what a reader sees next to the rules.
   `h2h lint --fail-on-warnings <your-file>` must be clean (L011, L012, L013).
4. **Extends.** Use `extends: "builtin:default"` or `extends: "builtin:strict"` as the base unless the policy requires standalone operation.
5. **Realistic patterns.** Use practical, tested regex patterns. Avoid placeholders or overly broad patterns that produce excessive false positives.
6. **Focused scope.** Keep policies auditable. A single policy should address one compliance framework or deployment scenario, not try to cover everything.
7. **Embed it.** The generators discover `library/*/*.yaml`, so regenerate the
   four embedded tables and commit them:

   ```bash
   python3 scripts/generate_rust_builtins.py
   python3 scripts/generate_ts_builtins.py
   python3 scripts/generate_python_builtins.py
   python3 scripts/generate_go_builtins.py
   ```

8. **Test.** Add `fixtures/library/<vertical>/<name>.test.yaml` with a case per
   control, covering every rule block and every named secret pattern, and run:

   ```bash
   cargo run -p hushspec-cli -- validate <your-file>
   cargo run -p hushspec-cli -- test --fixtures fixtures/library --fail-on-uncovered
   ```

## Compliance Control Matrix

Every policy declares its control mappings in `metadata.controls`, so this matrix is
derived from the policies rather than maintained alongside them. Regenerate the
per-policy view with:

```bash
h2h audit --controls library/healthcare/hipaa-base.yaml
h2h audit --controls --format json library/finance/pci-dss.yaml
```

### Family Educational Rights and Privacy Act (`ferpa`)

| Control | Policy | Rule paths |
|---------|--------|------------|
| `99.3` | `education/ferpa-student.yaml` | `rules.forbidden_paths`, `rules.secret_patterns` |
| `99.30` | `education/ferpa-student.yaml` | `rules.patch_integrity` |
| `99.31` | `education/ferpa-student.yaml` | `rules.tool_access` |
| `99.33` | `education/ferpa-student.yaml` | `rules.egress`, `rules.shell_commands` |

### HIPAA Security and Privacy Rules (`hipaa-2013`)

| Control | Policy | Rule paths |
|---------|--------|------------|
| `164.312(a)(1)` | `healthcare/hipaa-base.yaml` | `rules.forbidden_paths`, `rules.tool_access` |
| `164.312(b)` | `healthcare/hipaa-base.yaml` | `rules.forbidden_paths.patterns` |
| `164.312(c)(1)` | `healthcare/hipaa-base.yaml` | `rules.patch_integrity` |
| `164.312(e)(1)` | `healthcare/hipaa-base.yaml` | `rules.egress` |
| `164.502` | `healthcare/hipaa-base.yaml` | `rules.egress.block`, `rules.shell_commands` |
| `164.514(b)(2)` | `healthcare/hipaa-base.yaml` | `rules.secret_patterns` |

### ISO/IEC 27001 Annex A (`iso-27001-2022`)

| Control | Policy | Rule paths |
|---------|--------|------------|
| `A.5.15` | `general/air-gapped.yaml` | `rules.forbidden_paths`, `rules.tool_access` |
| `A.8.12` | `general/air-gapped.yaml` | `rules.secret_patterns` |
| `A.8.20` | `general/air-gapped.yaml` | `rules.egress` |
| `A.8.32` | `devops/cicd-hardened.yaml` | `rules.patch_integrity` |
| `A.8.32` | `general/air-gapped.yaml` | `rules.patch_integrity` |

### NIST SP 800-53 Security and Privacy Controls (`nist-800-53-r5`)

| Control | Policy | Rule paths |
|---------|--------|------------|
| `AC-3` | `government/fedramp-base.yaml` | `rules.forbidden_paths` |
| `AC-6` | `government/fedramp-base.yaml` | `rules.tool_access` |
| `AU-9` | `government/fedramp-base.yaml` | `rules.forbidden_paths.patterns` |
| `CM-3` | `government/fedramp-base.yaml` | `rules.patch_integrity` |
| `CM-7` | `government/fedramp-base.yaml` | `rules.shell_commands` |
| `SC-28` | `government/fedramp-base.yaml` | `rules.secret_patterns` |
| `SC-7` | `government/fedramp-base.yaml` | `rules.egress` |

### NIST AI Risk Management Framework (`nist-ai-rmf-1.0`)

| Control | Policy | Rule paths |
|---------|--------|------------|
| `MANAGE 2.2` | `general/recommended.yaml` | `rules.patch_integrity` |

### OWASP Top 10 for Large Language Model Applications (`owasp-llm-top10-2025`)

| Control | Policy | Rule paths |
|---------|--------|------------|
| `LLM02` | `devops/cicd-hardened.yaml` | `rules.forbidden_paths`, `rules.secret_patterns` |
| `LLM02` | `general/recommended.yaml` | `rules.secret_patterns`, `rules.forbidden_paths` |
| `LLM03` | `devops/cicd-hardened.yaml` | `rules.egress` |
| `LLM03` | `general/recommended.yaml` | `rules.egress` |
| `LLM06` | `devops/cicd-hardened.yaml` | `rules.tool_access`, `rules.shell_commands` |
| `LLM06` | `general/air-gapped.yaml` | `rules.shell_commands` |
| `LLM06` | `general/recommended.yaml` | `rules.tool_access`, `rules.shell_commands` |

### Payment Card Industry Data Security Standard (`pci-dss-4.0`)

| Control | Policy | Rule paths |
|---------|--------|------------|
| `10.2` | `finance/pci-dss.yaml` | `rules.shell_commands` |
| `3.2` | `finance/pci-dss.yaml` | `rules.secret_patterns.patterns` |
| `3.4` | `finance/pci-dss.yaml` | `rules.secret_patterns` |
| `4.1` | `finance/pci-dss.yaml` | `rules.egress` |
| `6.3` | `finance/pci-dss.yaml` | `rules.patch_integrity` |
| `7.1` | `finance/pci-dss.yaml` | `rules.forbidden_paths`, `rules.tool_access` |

### AICPA SOC 2 Trust Services Criteria (`soc2-tsc-2017`)

| Control | Policy | Rule paths |
|---------|--------|------------|
| `CC6.1` | `finance/soc2-base.yaml` | `rules.forbidden_paths`, `rules.egress` |
| `CC6.3` | `finance/soc2-base.yaml` | `rules.tool_access` |
| `CC7.1` | `finance/soc2-base.yaml` | `rules.secret_patterns`, `rules.shell_commands` |
| `CC7.2` | `finance/soc2-base.yaml` | `rules.egress.allow` |
| `CC8.1` | `finance/soc2-base.yaml` | `rules.patch_integrity` |
