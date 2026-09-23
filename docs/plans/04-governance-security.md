# RFC-04: Governance, Policy Signing, Emergency Overrides, and ReDoS Protection

**Status:** Historical design record (Draft)
**Authors:** Security Architecture Team
**Date:** 2026-03-15
**HushSpec Version:** 0.1.0

---

> **Delivery status:** See [the delivery ledger](STATUS.md#numbered-plan-reconciliation). Governance/signing/panic artifacts are implemented on the open stack, not merged or published. Enterprise RBAC/OIDC/LDAP, lifecycle service, and keyless/X.509 scope remain explicit deferrals; provider watch recovery has a local verification record, with hosted qualification pending.

## 1. Executive Summary

HushSpec defines portable security rules at the tool boundary of AI agent runtimes. As adoption grows beyond individual developers into enterprise environments -- where policies govern thousands of agent sessions across regulated industries -- four capabilities become essential:

1. **RBAC and Policy Governance.** Organizations need to control who can author, approve, and deploy security policies. Without governance, a single developer can weaken protections for production agent fleets. Separation of duties is a compliance requirement in SOX, PCI-DSS, HIPAA, and ISO 27001 contexts.

2. **Policy Signing and Provenance.** Policies distributed across teams, registries, and CI/CD pipelines must be verifiable. A tampered `default.yaml` that removes `forbidden_paths` patterns or broadens `egress.allow` lists is indistinguishable from a legitimate update without cryptographic provenance.

3. **Emergency Overrides.** When an active compromise is detected -- a prompt injection bypasses detection, or an agent begins exfiltrating data through an allowed egress domain -- operators need a mechanism to instantly restrict all agent activity to deny-all without redeploying policies.

4. **ReDoS Protection.** HushSpec documents contain user-authored regular expressions in `secret_patterns[].pattern`, `shell_commands.forbidden_patterns[]`, and `patch_integrity.forbidden_patterns[]`. A malicious or careless pattern can cause catastrophic backtracking in SDKs that use backtracking regex engines (TypeScript, Python), creating a denial-of-service vector against the evaluator itself.

This RFC specifies mechanisms for each pillar. The design preserves HushSpec's core property -- engine-neutral, portable security declarations -- while enabling the trust, governance, and safety guarantees that enterprise deployments require.

### Scope and Non-Goals

**In scope:**
- Schema extensions for governance metadata and signatures
- Policy signing specification, verification API, and CLI workflow
- Emergency override protocol with multiple activation mechanisms
- Regex safety requirements across all four SDKs
- Compliance control mappings (SOX, NIST CSF, ISO 27001:2022, PCI-DSS, HIPAA)
- Implementation roadmap prioritized by safety criticality

**Out of scope:**
- Runtime enforcement architectures (engine-specific)
- Key management infrastructure (PKI deployment)
- Specific LDAP/OIDC/SAML integration code (hooks are defined; implementations are engine-specific)
- Audit log storage and retention (engine-specific)
- Policy registry protocol (future RFC)

---

## 2. Policy Signing and Provenance

### 2.1 Threat Model

Without signing, the following attacks are possible:

| Attack | Vector | Impact |
|--------|--------|--------|
| Policy tampering | Modify YAML on disk or in transit | Security rules weakened silently |
| Policy impersonation | Substitute attacker-controlled policy | Agent operates under attacker's rules |
| Extends chain poisoning | Replace base policy referenced via `extends` | Inherited rules compromised |
| Rollback attack | Replace current policy with an older, weaker version | Known-weak rules reactivated |
| Replay attack | Re-use a valid signature from a different document | Signature validation passes for wrong content |

### 2.2 Signature Algorithm

HushSpec specifies **Ed25519** (EdDSA over Curve25519) as the REQUIRED signature algorithm for v0.x. Ed25519 is chosen for:

- Deterministic signatures (no nonce reuse risk)
- Small key and signature sizes (32-byte keys, 64-byte signatures)
- High performance (suitable for per-request verification)
- Wide availability across all target platforms (Rust `ed25519-dalek`, Node.js `@noble/ed25519`, Python `PyNaCl`, Go `crypto/ed25519`)

Future versions MAY add support for additional algorithms (e.g., Ed448, ECDSA P-256) via an `algorithm` field. Implementations MUST reject unknown algorithm values (fail-closed).

### 2.3 Signature Format

HushSpec supports two signature formats. Implementations MUST support both.

#### 2.3.1 Detached Signature File

A detached signature file is stored alongside the policy document with a `.sig` suffix:

```
rulesets/
  production.yaml
  production.yaml.sig
```

The `.sig` file is a JSON object conforming to `HushSpec-Sig/1.0`:

```json
{
  "$schema": "https://hushspec.dev/schemas/hushspec-sig.v1.schema.json",
  "format_version": "1.0",
  "algorithm": "ed25519",
  "signature": "<base64url-encoded 64-byte signature, no padding>",
  "signed_at": "2026-03-15T10:30:00Z",
  "key_id": "org-security-2026Q1",
  "signer": "security-team@example.com",
  "policy_version": 7
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `format_version` | string | REQUIRED | Signature format version. MUST be `"1.0"` for this specification. |
| `algorithm` | string | REQUIRED | Signature algorithm. MUST be `"ed25519"` for v0.x. |
| `signature` | string | REQUIRED | Base64url-encoded signature bytes (no padding, per RFC 4648 Section 5). |
| `signed_at` | string | REQUIRED | ISO 8601 UTC timestamp of when the signature was created. |
| `key_id` | string | REQUIRED | Opaque identifier for the signing key, used for key lookup. |
| `signer` | string | OPTIONAL | Human-readable identity of the signer (email, OIDC subject). |
| `policy_version` | integer | OPTIONAL | Monotonically increasing version counter. When present, verifiers MUST reject signatures with a `policy_version` lower than the previously accepted version for the same policy name (rollback protection). |
| `sigstore` | object | OPTIONAL | Sigstore/cosign metadata (see Section 2.6). |

The signature is computed over the raw bytes of the policy document file (not a parsed/re-serialized form). This preserves byte-exact verification regardless of YAML parser behavior.

#### 2.3.2 Inline Metadata Signature

An inline signature is embedded in the policy document under a new optional top-level field `metadata`:

```yaml
hushspec: "0.1.0"
name: "production-agent-policy"

metadata:
  signature:
    algorithm: ed25519
    value: "<base64url-encoded 64-byte signature>"
    signed_at: "2026-03-15T10:30:00Z"
    key_id: "org-security-2026Q1"
    signer: "security-team@example.com"

rules:
  # ...
```

When computing the inline signature, the `metadata.signature` block is excluded from the signed content. Implementations MUST:

1. Parse the document.
2. Remove the `metadata.signature` block.
3. Re-serialize the document to canonical YAML (see Appendix B for canonical serialization rules).
4. Compute the Ed25519 signature over the canonical bytes.

The canonical serialization requirement is necessary because inline signatures cannot rely on byte-exact file content (the signature itself is part of the file). This is more complex than detached signatures and is provided as a convenience; **detached signatures are RECOMMENDED for production use** due to their simplicity and avoidance of canonical serialization ambiguities.

### 2.4 Schema Changes

The `HushSpec` struct gains an optional `metadata` field:

```yaml
# Addition to top-level HushSpec document
metadata:
  author: "string"                    # OPTIONAL: policy author identity
  approved_by: "string"              # OPTIONAL: approver identity
  approval_date: "string"            # OPTIONAL: ISO 8601 date
  version: 1                         # OPTIONAL: monotonic policy version counter
  classification: "string"           # OPTIONAL: internal | public | restricted | confidential
  change_ticket: "string"            # OPTIONAL: change management reference (e.g., JIRA, ServiceNow)
  content_hash: "string"             # OPTIONAL: SHA-256 hash of policy content
  lifecycle_state: "string"          # OPTIONAL: draft | review | approved | deployed | deprecated | archived
  signature:                         # OPTIONAL: cryptographic signature
    algorithm: "string"              # REQUIRED when signature present: "ed25519"
    value: "string"                  # REQUIRED when signature present: base64url signature
    signed_at: "string"             # REQUIRED when signature present: ISO 8601 timestamp
    key_id: "string"                # REQUIRED when signature present: key identifier for lookup
    signer: "string"                # OPTIONAL: signer identity
```

**JSON Schema addition** to `hushspec-core.v0.schema.json`:

```json
{
  "properties": {
    "metadata": {
      "$ref": "#/$defs/Metadata"
    }
  },
  "$defs": {
    "Metadata": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "author": { "type": "string" },
        "approved_by": { "type": "string" },
        "approval_date": { "type": "string", "format": "date-time" },
        "version": { "type": "integer", "minimum": 1 },
        "classification": {
          "type": "string",
          "enum": ["internal", "public", "restricted", "confidential"]
        },
        "change_ticket": { "type": "string" },
        "content_hash": {
          "type": "string",
          "pattern": "^sha256:[a-f0-9]{64}$"
        },
        "lifecycle_state": {
          "type": "string",
          "enum": ["draft", "review", "approved", "deployed", "deprecated", "archived"]
        },
        "signature": { "$ref": "#/$defs/Signature" }
      }
    },
    "Signature": {
      "type": "object",
      "additionalProperties": false,
      "required": ["algorithm", "value", "signed_at", "key_id"],
      "properties": {
        "algorithm": {
          "type": "string",
          "enum": ["ed25519"]
        },
        "value": {
          "type": "string",
          "pattern": "^[A-Za-z0-9_-]+$",
          "description": "Base64url-encoded signature, no padding."
        },
        "signed_at": { "type": "string", "format": "date-time" },
        "key_id": { "type": "string", "minLength": 1 },
        "signer": { "type": "string" }
      }
    }
  }
}
```

**Rust model addition** to `generated_models.rs`:

```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_ticket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<LifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureBlock {
    pub algorithm: SignatureAlgorithm,
    pub value: String,
    pub signed_at: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Internal,
    Public,
    Restricted,
    Confidential,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Draft,
    Review,
    Approved,
    Deployed,
    Deprecated,
    Archived,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
}
```

The `HushSpec` struct in `generated_models.rs` gains:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub metadata: Option<Metadata>,
```

### 2.5 Verification API

Each SDK exposes signing and verification functions:

**Rust:**
```rust
/// Sign a policy file (detached mode).
pub fn sign_detached(
    policy_bytes: &[u8],
    private_key: &[u8; 64],  // Ed25519 expanded secret key
    key_id: &str,
    signer: Option<&str>,
    policy_version: Option<u64>,
) -> Result<DetachedSignature, SignatureError>;

/// Verify a detached signature against policy bytes and a trusted public key.
pub fn verify_detached(
    policy_bytes: &[u8],
    signature: &DetachedSignature,
    public_key: &[u8; 32],
) -> Result<VerificationOutcome, SignatureError>;

/// Verify an inline signature within a parsed HushSpec document.
pub fn verify_inline(
    spec: &HushSpec,
    public_key: &[u8; 32],
) -> Result<VerificationOutcome, SignatureError>;

/// Outcome of signature verification.
pub struct VerificationOutcome {
    pub valid: bool,
    pub key_id: String,
    pub signed_at: String,
    pub signer: Option<String>,
}
```

**TypeScript:**
```typescript
interface VerificationOutcome {
  valid: boolean;
  keyId: string;
  signedAt: string;
  signer?: string;
}

function signDetached(
    policyBytes: Uint8Array,
    privateKey: Uint8Array,
    keyId: string,
    options?: { signer?: string; policyVersion?: number },
): Promise<DetachedSignature>;

function verifyDetached(
    policyBytes: Uint8Array,
    signature: DetachedSignature,
    publicKey: Uint8Array,
): Promise<VerificationOutcome>;

function verifyInline(
    spec: HushSpec,
    publicKey: Uint8Array,
): Promise<VerificationOutcome>;
```

**Python:**
```python
@dataclass
class VerificationOutcome:
    valid: bool
    key_id: str
    signed_at: str
    signer: str | None

def sign_detached(
    policy_bytes: bytes,
    private_key: bytes,
    key_id: str,
    *,
    signer: str | None = None,
    policy_version: int | None = None,
) -> DetachedSignature: ...

def verify_detached(
    policy_bytes: bytes,
    signature: DetachedSignature,
    public_key: bytes,
) -> VerificationOutcome: ...

def verify_inline(
    spec: HushSpec,
    public_key: bytes,
) -> VerificationOutcome: ...
```

**Go:**
```go
type VerificationOutcome struct {
    Valid    bool
    KeyID   string
    SignedAt string
    Signer  string
}

func SignDetached(policyBytes, privateKey []byte, keyID string, opts *SignOptions) (*DetachedSignature, error)
func VerifyDetached(policyBytes []byte, sig *DetachedSignature, publicKey []byte) (*VerificationOutcome, error)
func VerifyInline(spec *HushSpec, publicKey []byte) (*VerificationOutcome, error)
```

### 2.6 Sigstore/Cosign Integration

For open-source rulesets distributed via registries, HushSpec supports Sigstore's keyless signing model. This eliminates the need for long-lived signing keys.

**Signing with cosign:**

```bash
# Keyless signing (uses OIDC identity)
cosign sign-blob --output-signature production.yaml.sig.raw \
    --output-certificate production.yaml.crt \
    rulesets/production.yaml

# Wrap into HushSpec .sig format
hushspec sign --sigstore \
    --signature production.yaml.sig.raw \
    --certificate production.yaml.crt \
    rulesets/production.yaml
```

**Verification with cosign:**

```bash
# Verify via Sigstore transparency log
cosign verify-blob --signature production.yaml.sig.raw \
    --certificate production.yaml.crt \
    --certificate-identity security-team@example.com \
    --certificate-oidc-issuer https://accounts.google.com \
    rulesets/production.yaml
```

The `.sig` file format extends to include Sigstore metadata:

```json
{
  "format_version": "1.0",
  "algorithm": "ed25519",
  "signature": "<base64url signature>",
  "signed_at": "2026-03-15T10:30:00Z",
  "key_id": "sigstore-keyless",
  "signer": "security-team@example.com",
  "sigstore": {
    "certificate": "<base64-encoded Fulcio certificate>",
    "transparency_log_entry": "<Rekor log entry UUID>",
    "issuer": "https://accounts.google.com",
    "subject": "security-team@example.com",
    "log_index": 12345678
  }
}
```

When `sigstore` is present, verifiers:
1. Validate the Fulcio certificate against the Sigstore root of trust.
2. Verify the signature using the public key embedded in the certificate.
3. Check the transparency log entry in Rekor to confirm the signature was logged.
4. Verify the `issuer` and `subject` match the expected OIDC identity.

### 2.7 X.509 Certificate Chain Support

For enterprise deployments integrated with existing PKI, verifiers MAY accept X.509 certificate chains. This is engine-specific and outside the core specification, but the `.sig` format accommodates it:

```json
{
  "format_version": "1.0",
  "algorithm": "ed25519",
  "signature": "<base64url signature>",
  "signed_at": "2026-03-15T10:30:00Z",
  "key_id": "org-pki-leaf-2026",
  "signer": "CN=security-team,O=Example Corp",
  "x509": {
    "certificate_chain": ["<base64 leaf cert>", "<base64 intermediate>", "<base64 root>"]
  }
}
```

### 2.8 Key Management Recommendations

| Concern | Recommendation |
|---------|---------------|
| Key generation | Generate Ed25519 keys on hardware security modules (HSMs) or secure enclaves where available. Use `ssh-keygen -t ed25519` for development. |
| Key storage | Store private keys in secrets managers (Vault, AWS KMS, GCP KMS). Never commit private keys. |
| Key rotation | Rotate signing keys quarterly. Old public keys remain trusted for verification of existing signatures until policies are re-signed. |
| Key revocation | Maintain a revocation list (CRL or OCSP-like). Verifiers MUST check revocation before accepting a signature. The `key_id` field enables revocation lookup. |
| Separation | Use distinct keys for different environments (dev, staging, production). |
| Emergency rotation | Maintain a pre-generated emergency key pair, stored offline, for use if the primary key is compromised. |

### 2.9 End-to-End Signing Workflow

```
1. Author writes policy:
   $ vim rulesets/production.yaml

2. Validate the policy:
   $ hushspec validate rulesets/production.yaml
   OK: document is valid (score: 85/100)

3. Sign the policy (detached):
   $ hushspec sign rulesets/production.yaml \
       --key ~/.hushspec/signing-key.pem \
       --key-id org-security-2026Q1 \
       --policy-version 7

   Output: rulesets/production.yaml.sig

4. Commit and distribute via git:
   $ git add rulesets/production.yaml rulesets/production.yaml.sig
   $ git commit -m "feat(policy): update production egress allowlist"
   $ git push

5. CI pipeline verifies signature:
   $ hushspec verify rulesets/production.yaml \
       --sig rulesets/production.yaml.sig \
       --trusted-keys keys/trusted-keys.json
   OK: signature valid (key_id=org-security-2026Q1, signer=security-team@example.com)

6. Consumer verifies on load:
   let policy_bytes = std::fs::read("rulesets/production.yaml")?;
   let sig = hushspec::load_detached_signature("rulesets/production.yaml.sig")?;
   let public_key = load_trusted_key("org-security-2026Q1")?;
   let outcome = hushspec::verify_detached(&policy_bytes, &sig, &public_key)?;
   assert!(outcome.valid, "signature verification failed");

   // Parse and use only after verification succeeds
   let policy = hushspec::parse(&policy_bytes)?;
   let result = hushspec::evaluate(&policy, &action);

7. Signature verification failure handling:
   - Log the failure with full context (key_id, signer, timestamp).
   - Reject the policy (fail-closed).
   - If panic mode is configured, activate it.
   - Alert the security operations team.
```

### 2.10 Verification in Extends Chains

When a policy uses `extends`, every document in the chain MUST be independently verifiable. The `resolve_with_loader` function (in `crates/hushspec/src/resolve.rs`) currently loads base policies via a caller-provided loader. Signed resolution extends this:

```rust
pub fn resolve_with_verified_loader<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
    trusted_keys: &[PublicKey],
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<(LoadedSpec, Option<DetachedSignature>), ResolveError>,
```

Each loaded spec's signature is verified against the trusted key set before merging. If any document in the chain fails verification, the entire resolve operation fails (fail-closed). The verification order is root-to-leaf:

```
[root] --extends--> [parent] --extends--> [child]
  |                    |                     |
  verify signature     verify signature      verify signature
  verify hash          verify hash           verify hash
  (fail = abort)       (fail = abort)        (fail = abort)
```

### 2.11 Rollback Protection

The `policy_version` field in the detached signature (and `metadata.version` in inline metadata) provides rollback protection:

1. Verifiers MUST maintain a per-policy-name version counter (the highest `policy_version` accepted for each policy name).
2. When verifying a signature, if `policy_version` is present and is less than the stored counter for that policy name, verification MUST fail.
3. On successful verification, the stored counter is updated to `max(stored, policy_version)`.
4. If `policy_version` is absent, rollback protection is not enforced (but SHOULD trigger a warning in production).

The version counter store is engine-specific (file, database, key-value store). Engines MUST document their storage mechanism.

---

## 3. Policy Governance and RBAC

### 3.1 Governance Metadata

The `metadata` block (defined in Section 2.4) carries governance fields:

| Field | Type | Purpose |
|-------|------|---------|
| `metadata.author` | string | Identity of the policy author (email, username, or OIDC subject) |
| `metadata.approved_by` | string | Identity of the approver who authorized deployment |
| `metadata.approval_date` | string (ISO 8601) | Timestamp of approval |
| `metadata.version` | integer | Monotonically increasing policy version counter |
| `metadata.classification` | enum | Data classification: `internal`, `public`, `restricted`, `confidential` |
| `metadata.change_ticket` | string | Reference to change management system (e.g., JIRA ticket, ServiceNow change) |
| `metadata.content_hash` | string | SHA-256 hash of policy content (hex-encoded), excluding the metadata block itself |
| `metadata.lifecycle_state` | enum | Current lifecycle state: `draft`, `review`, `approved`, `deployed`, `deprecated`, `archived` |

These fields are OPTIONAL in the schema but RECOMMENDED for production deployments. Engines MAY enforce that specific metadata fields are present before accepting a policy (e.g., require `approved_by` for `classification: restricted` policies).

### 3.2 RBAC Model

HushSpec defines a reference RBAC model for policy management. This model is normative for HushSpec governance tooling (CLI, policy management APIs). Engine-specific enforcement is RECOMMENDED but not REQUIRED at the spec level.

#### 3.2.1 Roles

| Role | Description | Typical Assignment |
|------|-------------|--------------------|
| `viewer` | Can read policies and their metadata | All team members |
| `author` | Can create and modify policy drafts | Security engineers, platform team |
| `reviewer` | Can review, comment on, and request changes to policies | Senior engineers, security leads |
| `approver` | Can approve policies for deployment and sign them | Security team leads, CISO delegates |
| `deployer` | Can deploy approved policies to target environments | Platform operations, CI/CD service accounts |
| `admin` | Full control including key management, role assignment, and emergency overrides | Security operations, platform administrators |
| `auditor` | Read-only access to all policies, metadata, audit logs, and signature verification status | Compliance team, external auditors |

#### 3.2.2 Permissions Matrix

| Permission | viewer | author | reviewer | approver | deployer | admin | auditor |
|-----------|--------|--------|----------|----------|----------|-------|---------|
| `policy:read` | Y | Y | Y | Y | Y | Y | Y |
| `policy:create` | - | Y | - | - | - | Y | - |
| `policy:update` | - | Y | - | - | - | Y | - |
| `policy:delete` | - | - | - | - | - | Y | - |
| `policy:review` | - | - | Y | Y | - | Y | - |
| `policy:approve` | - | - | - | Y | - | Y | - |
| `policy:deploy` | - | - | - | - | Y | Y | - |
| `policy:sign` | - | - | - | Y | - | Y | - |
| `policy:revoke` | - | - | - | Y | - | Y | - |
| `emergency:activate` | - | - | - | Y | - | Y | - |
| `emergency:deactivate` | - | - | - | - | - | Y | - |
| `key:manage` | - | - | - | - | - | Y | - |
| `role:assign` | - | - | - | - | - | Y | - |
| `audit:read` | - | - | - | - | - | Y | Y |

#### 3.2.3 Separation of Duties

The following constraints MUST be enforced by governance tooling:

1. **Author != Approver.** The identity in `metadata.author` MUST differ from `metadata.approved_by`. A policy author cannot approve their own changes. This is a hard constraint; tooling MUST reject self-approved policies.

2. **Author != Deployer.** For `classification: restricted` or `classification: confidential` policies, the person who deploys MUST NOT be the same as the author. This ensures no single actor can create and activate a weakened policy.

3. **Approver must hold `approver` role.** The identity in `metadata.approved_by` must be a principal with the `approver` or `admin` role at the time of approval.

4. **Classification escalation requires additional approval.** Changing `metadata.classification` from a less restrictive to a more restrictive level (e.g., `internal` to `restricted`) requires approval from an `admin` role principal.

5. **Signing requires approval.** A policy MUST be in `approved` or `deployed` lifecycle state before it can be signed. The signer (in the signature block) SHOULD be the approver or an automated signing service acting on the approver's authority.

6. **Emergency override requires `emergency:activate` permission.** Only principals with the `approver` or `admin` role may activate emergency overrides. Only `admin` may deactivate them (preventing premature resumption).

#### 3.2.4 RBAC Configuration Schema

Governance tooling uses a configuration file to define role assignments:

```yaml
# .hushspec/rbac.yaml
roles:
  viewer:
    principals:
      - "team:engineering"
  author:
    principals:
      - "user:alice@example.com"
      - "user:bob@example.com"
      - "group:security-engineers"
  reviewer:
    principals:
      - "user:carol@example.com"
      - "group:senior-engineers"
  approver:
    principals:
      - "user:diana@example.com"
      - "group:ciso-delegates"
  deployer:
    principals:
      - "service:ci-pipeline"
      - "user:ops-lead@example.com"
  admin:
    principals:
      - "user:ciso@example.com"
  auditor:
    principals:
      - "group:compliance-team"
      - "user:external-auditor@audit-firm.com"
```

Principal identifiers use a `type:value` format where type is one of `user`, `group`, `team`, or `service`. Resolution of these identifiers to actual identities is engine-specific and integrates with the enterprise identity systems described in Section 3.5.

### 3.3 Policy Lifecycle States

```
                  +-----------+
                  |   draft   |<---+
                  +-----+-----+    |
                        |          |
                  submit for       |
                  review           |
                        |          |
                  +-----v-----+    |
                  |  review    |---+ (reject -> back to draft)
                  +-----+-----+
                        |
                     approve
                        |
                  +-----v-----+
                  |  approved  |
                  +-----+-----+
                        |
                      deploy
                        |
                  +-----v-----+
                  |  deployed  |
                  +-----+-----+
                        |
                   deprecate
                        |
                  +-----v-----+
                  | deprecated |
                  +-----+-----+
                        |
                    archive
                        |
                  +-----v-----+
                  |  archived  |
                  +-----------+
```

#### 3.3.1 State Transition Rules

| Transition | Required Role | Required Conditions |
|-----------|---------------|---------------------|
| draft -> review | `author` | `metadata.author` is set |
| review -> draft (reject) | `reviewer` | Rejection reason provided |
| review -> approved | `approver` | `metadata.approved_by` set; author != approver |
| approved -> deployed | `deployer` | Signature present and valid; `metadata.change_ticket` RECOMMENDED |
| deployed -> deprecated | `approver` or `admin` | Replacement policy identified (RECOMMENDED) |
| deprecated -> archived | `admin` | No active agents reference this policy |
| Any -> draft (revert) | `admin` | Audit log entry with reason |

#### 3.3.2 Automatic Transitions

Engines MAY implement automatic transitions:

| Trigger | Transition | Condition |
|---------|-----------|-----------|
| Signature expiry | deployed -> deprecated | `signed_at` + configured max-age exceeded |
| Scheduled deprecation | deployed -> deprecated | `metadata.deprecation_date` reached (engine-specific field) |
| Inactivity | deprecated -> archived | No evaluations against this policy for N days |

State transitions are recorded in the audit log with:
- Timestamp (ISO 8601 UTC)
- Actor identity (who triggered the transition)
- Previous state
- New state
- Reason (optional free-text)
- Change ticket reference (if applicable)

### 3.4 Git-Based Governance Workflow (Recommended)

For organizations using version control as the source of truth for policies, the following workflow maps governance to git primitives:

| Governance Concept | Git Primitive |
|-------------------|--------------|
| Draft | Feature branch |
| Review | Pull request review |
| Approval | PR approval by authorized reviewer (GitHub/GitLab required reviewers) |
| Signing | CI pipeline step post-approval |
| Deployment | Merge to `main` / protected branch |
| Audit trail | Git history + PR comments + signature files |
| Rollback | Git revert (creates new version, not destructive) |
| Separation of duties | Branch protection rules + CODEOWNERS |
| Version counter | Git tag or commit count on `main` for the policy file |

**Example CODEOWNERS file:**

```
# /rulesets/ policies require security team approval
/rulesets/ @security-team

# Strict and production policies require CISO delegate
/rulesets/strict.yaml @ciso-delegates
/rulesets/production*.yaml @ciso-delegates
```

**Example branch protection:**
- Require 2 approvals from `@security-team` for changes to `rulesets/`
- Require status checks (validation, signing, ReDoS lint) to pass
- Disallow force push to `main`
- Require linear history
- Dismiss stale approvals when new commits are pushed

**Example CI pipeline (GitHub Actions):**

```yaml
name: Policy Governance
on:
  pull_request:
    paths: ['rulesets/**']

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate policy documents
        run: hushspec validate rulesets/*.yaml
      - name: Lint for ReDoS patterns
        run: hushspec lint --redos-check rulesets/*.yaml
      - name: Check metadata completeness
        run: hushspec lint --require-metadata author,classification rulesets/*.yaml
      - name: Verify separation of duties
        run: |
          # Ensure PR author is not the approver
          if [ "${{ github.event.pull_request.user.login }}" = "${{ github.event.review.user.login }}" ]; then
            echo "ERROR: Author cannot approve their own policy change"
            exit 1
          fi

  sign-on-merge:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Sign changed policies
        run: |
          for f in $(git diff --name-only HEAD~1 -- rulesets/); do
            hushspec sign "$f" \
              --key <(echo "${{ secrets.HUSHSPEC_SIGNING_KEY }}") \
              --key-id "${{ vars.HUSHSPEC_KEY_ID }}"
          done
      - name: Commit signatures
        run: |
          git add rulesets/*.sig
          git commit -m "chore: sign updated policies"
          git push
```

### 3.5 Enterprise Integration Points

HushSpec governance tooling (CLI and SDKs) provides hooks for enterprise identity systems:

| Integration | Mechanism | Purpose | Standard |
|-------------|-----------|---------|----------|
| OIDC | Token exchange | Authenticate policy authors and approvers via SSO | OpenID Connect 1.0 |
| LDAP | Group membership query | Resolve RBAC roles from directory groups | RFC 4511 |
| SAML | Assertion validation | Enterprise SSO for web-based policy management UIs | SAML 2.0 |
| SCIM | User/group sync | Synchronize RBAC role assignments from identity provider | RFC 7644 |
| OAuth 2.0 | Client credentials | Service-to-service authentication for CI/CD pipelines | RFC 6749 |

The identity resolved from these systems populates `metadata.author` and `metadata.approved_by` fields. The canonical identity format is the OIDC `sub` claim or email address.

**Integration architecture:**

```
+----------------+     +-----------+     +------------------+
| Identity       | --> | HushSpec  | --> | RBAC             |
| Provider       |     | Auth      |     | Engine           |
| (OIDC/LDAP/    |     | Adapter   |     | (role lookup,    |
|  SAML/SCIM)    |     |           |     |  permission      |
+----------------+     +-----------+     |  check)          |
                                         +--------+---------+
                                                  |
                                         +--------v---------+
                                         | Policy           |
                                         | Operations       |
                                         | (create, approve,|
                                         |  sign, deploy)   |
                                         +------------------+
```

---

## 4. Emergency Override / Kill Switch

### 4.1 Motivation

Security incidents demand immediate response. Between detecting a compromise and deploying a new policy, there is a window during which agents continue operating under the compromised policy. The emergency override mechanism closes this window.

**Requirements:**
- Activation MUST take effect within one evaluation cycle (no batching delay).
- Activation MUST NOT require redeployment, restart, or re-parsing of policies.
- Multiple independent activation mechanisms MUST be supported (defense in depth).
- All activations and deactivations MUST produce audit log entries.
- Recovery MUST re-verify the active policy before resuming.

### 4.2 Panic Mode Specification

HushSpec defines a **panic mode** that, when activated, overrides the active policy with a deny-all posture. All action types receive a `deny` decision regardless of the loaded policy's rules.

#### 4.2.1 Panic Policy Document

A panic policy is a valid HushSpec document that denies every action type:

```yaml
# PANIC POLICY - deny all agent actions
hushspec: "0.1.0"
name: "__hushspec_panic__"
description: "Emergency deny-all override. Activated by operator."

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**"

  path_allowlist:
    enabled: true
    read: []
    write: []
    patch: []

  egress:
    enabled: true
    allow: []
    block:
      - "**"
    default: block

  secret_patterns:
    enabled: true
    patterns: []

  shell_commands:
    enabled: true
    forbidden_patterns:
      - ".*"

  tool_access:
    enabled: true
    allow: []
    block: []
    default: block

  patch_integrity:
    enabled: true
    max_additions: 0
    max_deletions: 0
    forbidden_patterns:
      - ".*"

  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions: []

  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: false
    drive_mapping: false

  input_injection:
    enabled: true
    allowed_types: []
```

The name `__hushspec_panic__` is reserved. Parsers SHOULD warn if a non-panic policy uses this name. All ten rule blocks are explicitly configured to deny, ensuring that even if new rule blocks are added in future spec versions, the panic policy's explicit deny-all intent is clear.

#### 4.2.2 Named Emergency Policies

Beyond full deny-all, operators may pre-define named emergency policies for specific scenarios:

```yaml
# Egress lockdown: block all outbound traffic, allow read-only file operations
hushspec: "0.1.0"
name: "__hushspec_emergency_egress_lockdown__"
description: "Emergency egress lockdown - block all outbound, read-only tools allowed"

rules:
  egress:
    enabled: true
    allow: []
    default: block

  tool_access:
    enabled: true
    allow:
      - read_file
      - list_directory
    default: block

  shell_commands:
    enabled: true
    forbidden_patterns:
      - ".*"  # Block all shell commands during egress lockdown
```

```yaml
# Data exfiltration response: block all writes and egress, allow reads
hushspec: "0.1.0"
name: "__hushspec_emergency_data_protection__"
description: "Emergency data protection - prevent all outbound data flow"

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**"

  path_allowlist:
    enabled: true
    read:
      - "**"
    write: []
    patch: []

  egress:
    enabled: true
    allow: []
    default: block

  secret_patterns:
    enabled: true
    patterns: []

  tool_access:
    enabled: true
    allow:
      - read_file
      - list_directory
      - search
    default: block
```

Named emergency policies MUST use the prefix `__hushspec_emergency_` to distinguish them from normal policies. Engines SHOULD pre-validate emergency policies at startup to ensure they are ready for instant activation.

### 4.3 Activation Mechanisms

Engines MUST support at least one activation mechanism. Engines SHOULD support at least two for resilience. All mechanisms are functionally equivalent: they cause the evaluator to use the emergency policy instead of the active policy.

When multiple mechanisms are active simultaneously, the most restrictive policy wins. Specifically: if any mechanism specifies `__hushspec_panic__`, the deny-all panic policy is used regardless of what other mechanisms specify.

#### 4.3.1 File-Based Sentinel

The simplest and most portable mechanism. The engine monitors for the existence of a sentinel file:

```bash
# Activate deny-all panic mode:
touch /var/run/hushspec/panic

# Activate named emergency policy:
echo "egress_lockdown" > /var/run/hushspec/panic

# Deactivate panic mode:
rm /var/run/hushspec/panic
```

**Implementation requirements:**
- The sentinel file path MUST be configurable (default: `/var/run/hushspec/panic` on Unix, `%PROGRAMDATA%\hushspec\panic` on Windows).
- The engine MUST check for the sentinel file before each evaluation call. File stat operations are inexpensive; full reads are needed only when the file exists.
- If the sentinel file contains content, it is interpreted as the name of a pre-registered emergency policy.
- If the sentinel file is empty or contains `__hushspec_panic__`, the built-in deny-all panic policy is used.
- The sentinel file SHOULD be on a tmpfs/ramfs to survive disk I/O issues but not survive reboots (ephemeral by default).

#### 4.3.2 Signal-Based (Unix)

For long-running evaluator processes on Unix systems:

```bash
# Activate panic mode:
kill -USR1 <evaluator_pid>

# Deactivate panic mode:
kill -USR2 <evaluator_pid>
```

- `SIGUSR1`: Enter panic mode (deny-all).
- `SIGUSR2`: Exit panic mode (return to active policy, after re-verification).

**Implementation requirements:**
- Signal handlers MUST be async-signal-safe. The handler sets an atomic flag; the evaluator checks the flag before each evaluation.
- On receipt of `SIGUSR1`, the engine MUST log the activation event before entering panic mode.
- On receipt of `SIGUSR2`, the engine MUST log the deactivation event and re-verify the active policy before exiting panic mode.
- Signal-based activation does not support named emergency policies (it always activates deny-all). Use the file-based mechanism for named policies.

#### 4.3.3 API-Based

For engines that expose an HTTP control plane:

```
POST /api/v1/panic
Content-Type: application/json
Authorization: Bearer <token>

{
  "activate": true,
  "policy": "__hushspec_panic__",
  "reason": "Suspected data exfiltration via api.example.com",
  "operator": "security-oncall@example.com",
  "ttl_seconds": 3600
}
```

```
DELETE /api/v1/panic
Content-Type: application/json
Authorization: Bearer <token>

{
  "reason": "Incident resolved, resuming normal operations",
  "operator": "security-oncall@example.com"
}
```

**Implementation requirements:**
- The `/api/v1/panic` endpoint MUST require authentication. RECOMMENDED: mTLS or OAuth 2.0 bearer token with the `emergency:activate` permission.
- The POST body MUST include `reason` and `operator` fields for audit purposes.
- The optional `ttl_seconds` field specifies automatic deactivation after the given duration. If omitted, panic mode persists until explicitly deactivated.
- The endpoint MUST respond with 200 and a confirmation body before the panic takes effect. The response includes the activation timestamp and a correlation ID for audit trail linkage.
- A `GET /api/v1/panic` endpoint SHOULD be provided for querying current panic mode status.

**Response:**
```json
{
  "activated": true,
  "correlation_id": "incident-2026-03-15-001",
  "activated_at": "2026-03-15T10:30:00Z",
  "policy": "__hushspec_panic__",
  "expires_at": "2026-03-15T11:30:00Z"
}
```

#### 4.3.4 Environment Variable Override

For container and serverless deployments where file systems are ephemeral:

```bash
# Activate panic mode before process start:
HUSHSPEC_PANIC=1 ./agent-runtime

# Activate with named emergency policy:
HUSHSPEC_PANIC=egress_lockdown ./agent-runtime
```

**Implementation requirements:**
- The `HUSHSPEC_PANIC` environment variable is checked at startup AND MAY be re-checked periodically (configurable interval, default: 30 seconds).
- Any truthy value (`1`, `true`, `yes`) activates the built-in deny-all panic policy.
- Any other non-empty value is interpreted as a named emergency policy.
- In Kubernetes deployments, this can be updated via ConfigMap changes with pod annotation-based reload.

#### 4.3.5 Distributed Kill Switch (Multi-Node)

For deployments spanning multiple nodes, engines SHOULD support a distributed activation mechanism:

```bash
# Redis-based distributed panic
HUSHSPEC_PANIC_BACKEND=redis://sentinel:6379/0
HUSHSPEC_PANIC_KEY=hushspec:panic:production
```

Engines that support distributed backends MUST:
- Poll the backend at a configurable interval (default: 5 seconds, max: 30 seconds).
- Accept the same value format as the file-based sentinel (`__hushspec_panic__` or named policy).
- Continue in panic mode if the backend is unreachable (fail-closed).
- Log backend connectivity issues at WARN level.

### 4.4 Recovery Procedure

Exiting panic mode is a controlled process that requires verification:

1. **Confirm incident resolution.** The operator MUST confirm that the root cause has been addressed.

2. **Remove the activation trigger.** Delete the sentinel file, send `SIGUSR2`, call `DELETE /api/v1/panic`, or restart without `HUSHSPEC_PANIC`.

3. **Policy re-verification.** After panic mode deactivation, engines MUST:
   a. Re-load the active policy from its source.
   b. Re-validate the policy (schema, constraints, regex safety).
   c. Re-verify the policy's signature against the trusted key set (if signing is configured).
   d. If any step fails, the engine MUST remain in panic mode and log the failure.

4. **Gradual resumption (RECOMMENDED).** In high-security environments, engines SHOULD support gradual resumption:
   - Resume with a restricted emergency policy first (e.g., `__hushspec_emergency_data_protection__`).
   - Monitor for anomalies for a configurable period (default: 15 minutes).
   - Then switch to the full active policy.

5. **Log the recovery event.** The audit log records who deactivated panic mode, when, why, and whether re-verification succeeded.

### 4.5 Panic Mode Forensics

While panic mode is active, engines MUST log all denied actions for forensic analysis:

```json
{
  "event": "panic_mode_denial",
  "timestamp": "2026-03-15T10:31:15Z",
  "action_type": "egress",
  "target": "api.suspicious-domain.com",
  "session_id": "agent-session-12345",
  "agent_id": "production-agent-fleet-node-7",
  "active_panic_policy": "__hushspec_panic__"
}
```

This forensic log is critical for post-incident analysis -- it reveals what the compromised agent was attempting to do during the incident window.

### 4.6 Audit Logging of Override Events

Every panic mode activation and deactivation MUST produce an audit log entry:

```json
{
  "event": "panic_mode_activated",
  "timestamp": "2026-03-15T10:30:00Z",
  "correlation_id": "incident-2026-03-15-001",
  "mechanism": "file_sentinel",
  "policy": "__hushspec_panic__",
  "operator": "security-oncall@example.com",
  "reason": "Suspected prompt injection bypass on agent fleet",
  "previous_policy": "production-agent-policy",
  "previous_policy_hash": "sha256:a1b2c3d4...",
  "ttl_seconds": null
}
```

### 4.7 Example: Runtime Integration

```rust
use hushspec::{evaluate, HushSpec, EvaluationAction, Decision};
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::Path;

static PANIC_MODE: AtomicBool = AtomicBool::new(false);

fn evaluate_with_panic_check(
    active_policy: &HushSpec,
    panic_policy: &HushSpec,
    sentinel_path: &Path,
    action: &EvaluationAction,
) -> hushspec::EvaluationResult {
    // Check multiple activation mechanisms (defense in depth)
    let panic_active = PANIC_MODE.load(Ordering::Acquire)  // signal-based
        || sentinel_path.exists()                            // file-based
        || std::env::var("HUSHSPEC_PANIC").is_ok();         // env-based

    let policy = if panic_active {
        // Log denied action for forensics
        log::warn!(
            "panic_mode_denial: action_type={} target={:?}",
            action.action_type,
            action.target,
        );
        panic_policy
    } else {
        active_policy
    };

    evaluate(policy, action)
}
```

---

## 5. ReDoS Protection

### 5.1 Regex Fields in HushSpec

The following fields accept user-provided regular expressions that are compiled and evaluated at runtime:

| Field Path | Rule Block | Purpose | Used In |
|-----------|-----------|---------|---------|
| `rules.secret_patterns.patterns[].pattern` | `SecretPatternsRule` | Detect secrets in content | `evaluate_secret_patterns()` in `evaluate.rs` (line 451) |
| `rules.shell_commands.forbidden_patterns[]` | `ShellCommandsRule` | Block dangerous shell commands | `evaluate_shell_rule()` in `evaluate.rs` (line 544) |
| `rules.patch_integrity.forbidden_patterns[]` | `PatchIntegrityRule` | Forbid patterns in patch content | `evaluate_patch_integrity()` in `evaluate.rs` (line 488) |

**Regex validation at parse time** is already implemented in all four SDKs:

| SDK | Validation Location | Method |
|-----|---------------------|--------|
| Rust | `validate.rs` line 382 | `regex::Regex::new(pattern)` |
| TypeScript | `validate.ts` line 792 | `new RegExp(pattern)` |
| Python | `raw_validate.py` line 712 | `re.compile(pattern)` |
| Go | `validate.go` line 360 | `regexp.Compile(pattern)` |

**Additional regex construction from user input** occurs in:

| Location | Input Source | Risk |
|----------|-------------|------|
| `evaluate.rs` `glob_matches()` (line 961) | Glob patterns from `forbidden_paths.patterns`, `forbidden_paths.exceptions`, `egress.allow`, `egress.block`, `tool_access.allow/block/require_confirmation`, `path_allowlist.read/write/patch`, `secret_patterns.skip_paths` | **Low** -- glob-to-regex conversion produces simple patterns (`*` -> `[^/]*`, `**` -> `.*`, `?` -> `.`) with no backtracking risk. However, the conversion SHOULD be audited to confirm no user-controlled quantifiers can be injected. |

### 5.2 Threat Model

**Attacker profile:** A malicious or careless policy author who supplies a regular expression with exponential backtracking complexity.

**Attack vector:** A HushSpec document containing a pathological regex is loaded by an evaluator. When the evaluator checks action content against the pattern, the regex engine enters catastrophic backtracking, consuming CPU for minutes or hours on a single evaluation.

**Impact:**
- Denial of service against the evaluator process
- Agent operations blocked while evaluator is unresponsive
- In multi-tenant environments, one tenant's bad regex affects all tenants sharing the evaluator
- Potential amplification: if the evaluator retries on timeout, each retry re-triggers the backtracking
- In the worst case, a ReDoS pattern in `shell_commands.forbidden_patterns` could prevent the evaluator from ever completing a shell command check, effectively blocking all agent operations

**Example pathological patterns:**

```yaml
# Exponential backtracking: O(2^n)
pattern: "(a+)+"

# Polynomial backtracking: O(n^3)
pattern: "a*a*a*b"

# Nested quantifiers with alternation
pattern: "(.*|.*)+"

# Realistic-looking but dangerous secret pattern
pattern: "(?:key|token|secret)\\s*[:=]\\s*[\"']?([a-zA-Z0-9+/=]*)*[\"']?"
```

### 5.3 SDK-Specific Risk Assessment

| SDK | Regex Engine | Engine Type | ReDoS Risk | Supports Backreferences | Supports Lookaround | Notes |
|-----|-------------|-------------|------------|------------------------|---------------------|-------|
| **Rust** | `regex` crate (v1.x) | NFA-based (RE2 semantics) | **None** | No | No | Guarantees O(mn) worst-case. Safe by design. Rejects patterns with backreferences/lookaround at compile time. |
| **Go** | `regexp` (stdlib) | NFA-based (RE2 semantics) | **None** | No | No | RE2 semantics. Guarantees O(mn) worst-case. Safe by design. |
| **TypeScript** | `RegExp` (V8) | Backtracking (PCRE-like) | **Critical** | Yes | Yes | V8 uses backtracking. Pathological patterns cause exponential time. No built-in timeout. |
| **Python** | `re` (stdlib) | Backtracking (PCRE-like) | **Critical** | Yes | Yes | Python `re` uses backtracking. Pathological patterns cause exponential time. No built-in timeout. |

The Rust and Go SDKs are safe by construction because their regex engines use Thompson NFA simulation, which guarantees O(mn) worst-case time complexity where m is the pattern length and n is the input length. These engines reject patterns containing backreferences, lookahead, and lookbehind at compile time, providing an implicit RE2 subset enforcement.

The TypeScript and Python SDKs are vulnerable because they use backtracking engines that support the full PCRE feature set but have exponential worst-case time complexity. The current validation in these SDKs (`new RegExp(pattern)` and `re.compile(pattern)`) only checks syntax validity, not safety.

### 5.4 Mitigation Strategies

HushSpec requires a layered defense: (1) restrict the allowed regex subset, (2) enforce evaluation timeouts, (3) perform static complexity analysis, and (4) provide runtime safeguards. Strategies 1 and 2 are REQUIRED; strategies 3 and 4 are RECOMMENDED.

#### 5.4.1 Strategy 1: RE2-Compatible Regex Subset (REQUIRED)

HushSpec specifies that all regex patterns in policy documents MUST be compatible with the RE2 syntax subset. This is the intersection of features supported by all four SDKs' safe engines.

**Allowed features:**
- Character classes: `[abc]`, `[a-z]`, `[^x]`, POSIX classes `[:alpha:]`
- Quantifiers: `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}`
- Alternation: `a|b`
- Grouping: `(abc)`, `(?:abc)` (non-capturing), `(?P<name>abc)` (named groups)
- Anchors: `^`, `$`
- Escape sequences: `\d`, `\w`, `\s` (and their negations `\D`, `\W`, `\S`)
- Word boundary: `\b` (note: behavior varies slightly between engines; see below)
- Dot: `.`
- Case-insensitive flag: `(?i)`
- Multi-line flag: `(?m)`
- Dot-matches-newline flag: `(?s)`

**Disallowed features (MUST cause document rejection -- fail-closed):**
- Backreferences: `\1`, `\2`, `\k<name>`
- Lookahead: `(?=...)`, `(?!...)`
- Lookbehind: `(?<=...)`, `(?<!...)`
- Atomic groups: `(?>...)`
- Possessive quantifiers: `*+`, `++`, `?+`
- Conditional patterns: `(?(cond)yes|no)`
- Recursive patterns: `(?R)`, `(?1)`
- Subroutine calls: `\g<name>`

**Word boundary note:** The `\b` assertion is RE2-compatible and safe, but its behavior at Unicode boundaries varies between engines. Policy authors SHOULD prefer explicit character class boundaries (e.g., `(?:^|[^A-Za-z0-9])` instead of `\b`) for cross-engine consistency.

**Validation implementation:**

The Rust and Go SDKs already enforce RE2 compatibility implicitly -- their regex engines reject disallowed features at compile time. No changes needed.

For TypeScript and Python, explicit RE2 subset validation MUST be added:

**TypeScript:**
```typescript
const RE2_DISALLOWED = /\\[1-9]|\\k<|\(\?[=!]|\(\?<[=!]|\(\?>|\*\+|\+\+|\?\+|\(\?\(|\(\?R|\(\?\d|\(\?P=|\\g</;

function validateRegexRE2(pattern: string, path: string, ctx: ValidationContext): void {
  // First check syntax
  try { new RegExp(pattern); } catch (e) {
    addError(ctx, 'invalid_regex', `${path}: invalid regex: ${e}`);
    return;
  }
  // Then check RE2 compatibility
  if (RE2_DISALLOWED.test(pattern)) {
    addError(ctx, 'non_re2_regex',
      `${path}: pattern uses features not in the RE2 subset (backreferences, lookaround, etc.)`);
  }
}
```

**Python:**
```python
import re as _re

_RE2_DISALLOWED = _re.compile(
    r"\\[1-9]|\\k<|\(\?[=!]|\(\?<[=!]|\(\?>|\*\+|\+\+|\?\+|\(\?\(|\(\?R|\(\?\d|\(\?P=|\\g<"
)

def _validate_regex_re2(pattern: str, errors: list[str], path: str) -> None:
    try:
        _re.compile(pattern)
    except _re.error as exc:
        errors.append(f"{path} must be a valid regular expression: {exc}")
        return
    if _RE2_DISALLOWED.search(pattern):
        errors.append(
            f"{path}: pattern uses features not in the RE2 subset "
            "(backreferences, lookaround, etc.)"
        )
```

**Specification language for `hushspec-core.md` Section 7, Validation Requirements:**

> **6. Regex validity.** All fields designated as regex patterns MUST be syntactically valid regular expressions conforming to the RE2 syntax subset (as defined in the RE2 specification). Specifically, patterns MUST NOT contain backreferences, lookahead, lookbehind, atomic groups, possessive quantifiers, conditional patterns, recursive patterns, or subroutine calls. Patterns containing any of these features MUST cause document rejection (fail-closed). Engines SHOULD document any additional restrictions they impose on regex syntax.

#### 5.4.2 Strategy 2: Evaluation Timeout (REQUIRED for TypeScript and Python)

Even with RE2 subset enforcement, defense in depth requires evaluation timeouts. Timeouts protect against:
- Bugs in the RE2 subset validation that allow a dangerous pattern through.
- Extremely long (but technically safe) patterns matched against very large inputs.
- Future spec changes that introduce new regex-accepting fields.

**TypeScript implementation (RECOMMENDED: use `re2` npm package):**

```typescript
// Option A: RE2 bindings (preferred -- guarantees linear time)
import RE2 from 're2';

function safeRegexMatch(pattern: string, input: string): boolean {
  const regex = new RE2(pattern);
  return regex.test(input);
}

// Option B: Native RegExp with AbortController timeout (Node 20+, fallback)
function safeRegexMatchWithTimeout(
    pattern: string, input: string, timeoutMs: number = 1000,
): boolean {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('regex timeout')), timeoutMs);
    try {
      const regex = new RegExp(pattern);
      resolve(regex.test(input));
    } finally {
      clearTimeout(timer);
    }
  });
}
```

**Python implementation (RECOMMENDED: use `google-re2` or `re2` package):**

```python
# Option A: google-re2 package (preferred -- C++ RE2 bindings)
# Install: pip install google-re2
import re2

def safe_regex_match(pattern: str, text: str) -> bool:
    return bool(re2.search(pattern, text))

# Option B: re2-wheels package (easier install, pre-built wheels)
# Install: pip install re2-wheels

# Option C: signal-based timeout (Unix only, fallback)
import re
import signal

def safe_regex_match_with_timeout(
    pattern: str, text: str, timeout_seconds: float = 1.0,
) -> bool:
    def handler(signum, frame):
        raise TimeoutError(f"Regex evaluation timed out after {timeout_seconds}s")
    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    try:
        return bool(re.search(pattern, text))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
```

**Recommended timeout values:**

| Context | Timeout | Rationale |
|---------|---------|-----------|
| Single pattern evaluation | 100ms | Most legitimate patterns complete in microseconds |
| Total evaluation per action | 1000ms | Allows ~10 patterns at 100ms each |
| Parse-time regex compilation | 50ms | Compilation should be fast |

When a timeout fires, the evaluation MUST return `deny` (fail-closed) and log a warning with the pattern that timed out.

#### 5.4.3 Strategy 3: Regex Complexity Analysis at Parse Time (RECOMMENDED)

In addition to RE2 subset enforcement, implementations SHOULD perform static complexity analysis to catch patterns that, while technically RE2-compatible, are unnecessarily complex:

```rust
/// Complexity metrics for a regular expression.
pub struct RegexComplexity {
    /// Length of the pattern string in bytes.
    pub pattern_length: usize,
    /// Maximum nesting depth of quantifiers (e.g., `(a*)*` = depth 2).
    pub max_quantifier_depth: usize,
    /// Whether the pattern contains nested quantifiers.
    pub has_nested_quantifiers: bool,
    /// Estimated NFA state count (approximation).
    pub estimated_state_count: usize,
    /// Number of alternation branches at the top level.
    pub alternation_count: usize,
}

/// Analyze the complexity of a regex pattern.
pub fn analyze_regex_complexity(pattern: &str) -> RegexComplexity;

/// Check whether a pattern is within the configured complexity budget.
pub fn is_regex_within_budget(
    complexity: &RegexComplexity,
    budget: &RegexBudget,
) -> Result<(), RegexBudgetExceeded>;
```

**Default budget:**

| Metric | Limit | Rationale |
|--------|-------|-----------|
| `max_pattern_length` | 1024 characters | Prevents absurdly long patterns |
| `max_quantifier_depth` | 3 | Deeper nesting increases state space exponentially |
| `max_estimated_states` | 10,000 | Limits NFA size and memory usage |
| `nested_quantifiers` | Warn (not reject) | Primary source of exponential behavior in backtracking engines; benign in NFA engines |
| `max_alternation_branches` | 100 | Limits alternation explosion |

The budget is configurable per-engine. Engines MUST document their default budget.

#### 5.4.4 Strategy 4: Runtime Regex Caching (RECOMMENDED)

Regex compilation is expensive. Engines SHOULD cache compiled regex objects:

```rust
use std::collections::HashMap;
use std::sync::RwLock;

struct RegexCache {
    cache: RwLock<HashMap<String, regex::Regex>>,
    max_entries: usize,
}

impl RegexCache {
    fn get_or_compile(&self, pattern: &str) -> Result<regex::Regex, regex::Error> {
        // Check cache first
        if let Some(regex) = self.cache.read().unwrap().get(pattern) {
            return Ok(regex.clone());
        }
        // Compile and cache
        let regex = regex::Regex::new(pattern)?;
        let mut cache = self.cache.write().unwrap();
        if cache.len() < self.max_entries {
            cache.insert(pattern.to_string(), regex.clone());
        }
        Ok(regex)
    }
}
```

Currently, `evaluate.rs` calls `Regex::new()` on every evaluation (lines 472, 499, 555). This is correct but wasteful. Caching is an optimization that also reduces the window for ReDoS in backtracking engines (compile once, not per-evaluation).

### 5.5 Schema Extension: Regex Timeout Configuration

An optional field allows policy documents to specify regex evaluation timeouts:

```yaml
hushspec: "0.1.0"
name: "production"

rules:
  secret_patterns:
    enabled: true
    regex_timeout_ms: 200    # Per-pattern timeout in milliseconds
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
```

**Schema addition** (new optional fields on `SecretPatternsRule`, `ShellCommandsRule`, and `PatchIntegrityRule`):

```json
{
  "SecretPatternsRule": {
    "properties": {
      "regex_timeout_ms": {
        "type": "integer",
        "minimum": 1,
        "maximum": 10000,
        "default": 1000,
        "description": "Per-pattern regex evaluation timeout in milliseconds."
      }
    }
  },
  "ShellCommandsRule": {
    "properties": {
      "regex_timeout_ms": {
        "type": "integer",
        "minimum": 1,
        "maximum": 10000,
        "default": 1000
      }
    }
  },
  "PatchIntegrityRule": {
    "properties": {
      "regex_timeout_ms": {
        "type": "integer",
        "minimum": 1,
        "maximum": 10000,
        "default": 1000
      }
    }
  }
}
```

**Implementation note:** Adding `regex_timeout_ms` to the schema requires updating `generated_models.rs`, the TypeScript types, the Python dataclass, and the Go struct. Since `deny_unknown_fields` is used on all serde structs, the field MUST be added to all four SDKs simultaneously to avoid breaking compatibility. This is tracked in Phase 1 of the roadmap.

Engines that use safe regex engines (Rust, Go) MAY ignore this field since their engines guarantee linear-time evaluation. Engines that use backtracking engines (TypeScript, Python) MUST honor it.

### 5.6 Lint Rule for Dangerous Patterns

The `hushspec lint` CLI command (proposed) SHOULD include a regex safety lint:

```
$ hushspec lint rulesets/production.yaml

WARN: rules.secret_patterns.patterns[3].pattern contains nested quantifiers
      Pattern: "(?:key|token)\\s*[:=]\\s*([a-zA-Z0-9]*)*"
      Suggestion: Remove nested quantifier. Use "(?:key|token)\\s*[:=]\\s*[a-zA-Z0-9]*"

ERROR: rules.shell_commands.forbidden_patterns[0] exceeds complexity budget
       Pattern length: 2048 (max: 1024)
       Quantifier depth: 5 (max: 3)

ERROR: rules.secret_patterns.patterns[1].pattern uses non-RE2 features
       Pattern: "(?<=password:)\\s*\\S+"
       Feature: lookbehind (?<=...)
       Suggestion: Rewrite without lookbehind: "password:\\s*\\S+"
```

### 5.7 Audit of Built-In Rulesets

All patterns in the current built-in rulesets (`rulesets/*.yaml`) have been audited and are RE2-compatible:

| Ruleset | secret_patterns | patch_integrity.forbidden_patterns | shell_commands.forbidden_patterns | Total Regex | RE2 Compatible | Max Pattern Length | Nested Quantifiers |
|---------|----------------|-----------------------------------|----------------------------------|-------------|----------------|--------------------|--------------------|
| `default.yaml` | 4 | 4 | 0 | 8 | Yes | 63 chars | None |
| `strict.yaml` | 8 | 8 | 0 | 16 | Yes | 63 chars | None |
| `permissive.yaml` | 0 | 0 | 0 | 0 | N/A | N/A | N/A |
| `ai-agent.yaml` | 5 | 2 | 3 | 10 | Yes | 63 chars | None |
| `cicd.yaml` | 3 | 0 | 0 | 3 | Yes | 52 chars | None |
| `remote-desktop.yaml` | 0 | 0 | 0 | 0 | N/A | N/A | N/A |

**Pattern-level findings:**

- The `(?i)` case-insensitive flag used in patterns like `"(?i)disable[\\s_\\-]?(security|auth|ssl|tls)"` is RE2-compatible.
- The `\\s+` and `\\s*` quantifiers are safe (no nesting, bounded character classes).
- The `[A-Za-z0-9]{16}` bounded repetitions are safe.
- The `[a-zA-Z0-9-]*` unbounded repetition in `strict.yaml`'s `slack_token` pattern is safe (single character class, no nesting).
- The `curl.*\\|.*bash` pattern in `ai-agent.yaml` uses `.*` twice with a literal separator -- safe in RE2 engines, and the backtracking risk in PCRE engines is low because the literal `|` provides a strong anchor.
- No patterns use backreferences, lookahead, lookbehind, or any other non-RE2 features.

**Verdict:** All 37 regex patterns across all built-in rulesets are RE2-compatible and within the default complexity budget. No remediation needed.

---

## 6. Policy Integrity and Tamper Detection

### 6.1 Content Hashing

Every HushSpec document can be content-addressed via SHA-256 hashing. The hash is computed over the canonical form of the document (sorted keys, no comments, no trailing whitespace, LF line endings, `metadata` block excluded).

The `metadata.content_hash` field stores this hash:

```yaml
hushspec: "0.1.0"
name: "production"
metadata:
  content_hash: "sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1a"
```

### 6.2 Content-Addressable Policy References

The `extends` field currently accepts opaque string references. This RFC proposes an optional content-addressed reference format:

```yaml
extends: "sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1a"
```

When a content-addressed reference is used:

1. The engine resolves the reference to a policy document (resolution strategy is engine-specific).
2. The engine computes the SHA-256 hash of the resolved document.
3. If the computed hash does not match the reference, the engine MUST reject the document (fail-closed).

This prevents extends chain poisoning: even if an attacker replaces the base policy file, the hash mismatch causes rejection.

### 6.3 Integrity Verification in Extends Chains

When resolving an extends chain, each document's `metadata.content_hash` (if present) is verified:

```
[root] --extends--> [parent] --extends--> [child]
  |                    |                     |
  verify hash          verify hash           verify hash
  verify signature     verify signature      verify signature
```

The `resolve_with_loader` function in `crates/hushspec/src/resolve.rs` is extended to accept an optional integrity verifier:

```rust
pub trait IntegrityVerifier {
    /// Verify that the document's content matches its declared hash.
    fn verify_hash(&self, spec: &HushSpec, expected_hash: &str) -> Result<(), IntegrityError>;
    /// Verify the cryptographic signature on the document.
    fn verify_signature(
        &self,
        spec_bytes: &[u8],
        signature: &SignatureBlock,
    ) -> Result<(), IntegrityError>;
}
```

### 6.4 Hash Algorithm

SHA-256 is the REQUIRED hash algorithm for v0.x. Hashes are encoded as `sha256:<hex-encoded-digest>` (lowercase hex, 64 characters). Future versions MAY add support for additional algorithms (SHA-384, SHA-512, BLAKE3) via the `<algorithm>:<digest>` prefix scheme.

---

## 7. Secure Defaults

### 7.1 Minimum Security Requirements

For production deployments, HushSpec recommends a minimum set of rules. Engines MAY enforce these as requirements.

**Required rules checklist:**

| # | Requirement | Field Path | Rationale |
|---|------------|-----------|-----------|
| 1 | Forbidden paths MUST include credential patterns | `rules.forbidden_paths.patterns` | Prevent credential exfiltration |
| 2 | Egress default MUST be `block` | `rules.egress.default` | Prevent unauthorized data exfiltration |
| 3 | At least one secret pattern MUST be configured | `rules.secret_patterns.patterns` | Detect accidental secret exposure |
| 4 | Shell command restrictions SHOULD be configured | `rules.shell_commands.forbidden_patterns` | Prevent destructive operations |
| 5 | Tool access default SHOULD be `block` in production | `rules.tool_access.default` | Principle of least privilege |
| 6 | Computer use MUST NOT be in `observe` mode in production | `rules.computer_use.mode` | Observe mode does not enforce |
| 7 | `metadata.classification` SHOULD be set | `metadata.classification` | Data classification for compliance |
| 8 | `metadata.author` MUST be set for `restricted`/`confidential` policies | `metadata.author` | Accountability and audit trail |
| 9 | Policy SHOULD be signed for production | `metadata.signature` | Tamper detection |

### 7.2 Security Scoring

A policy security score (0-100) provides a quick assessment:

| Category | Points | Criteria |
|----------|--------|----------|
| Path protection | 0-15 | `forbidden_paths` configured with credential patterns |
| Egress control | 0-15 | `egress.default: block` + explicit allow list |
| Secret detection | 0-15 | Secret patterns configured with critical severity |
| Shell restrictions | 0-10 | `shell_commands.forbidden_patterns` non-empty |
| Tool access control | 0-15 | Allowlist mode or explicit block list |
| Patch integrity | 0-10 | `patch_integrity` configured with limits |
| Policy metadata | 0-10 | `metadata.author`, `approved_by`, `classification` present |
| Signature | 0-10 | Valid signature present and verified |

**Score interpretation:**

| Score | Rating | Guidance |
|-------|--------|----------|
| 0-30 | Critical | Not suitable for any deployment |
| 31-50 | Low | Development only |
| 51-70 | Medium | Staging environments |
| 71-85 | High | Production with monitoring |
| 86-100 | Very High | Production, regulated environments |

---

## 8. Implementation Roadmap

### Phase 1: ReDoS Protection (Immediate -- v0.1.1)

**Timeline:** 2 weeks
**Priority:** P0 (security vulnerability -- this is a denial-of-service vector in TypeScript and Python SDKs)

| Task | SDK | Effort | Description |
|------|-----|--------|-------------|
| Add RE2 subset validation | TypeScript | 2 days | Add `RE2_DISALLOWED` regex check in `validate.ts` `validateRegex()` (line 792). Reject patterns with backreferences, lookahead/behind. |
| Add RE2 subset validation | Python | 2 days | Add `_RE2_DISALLOWED` regex check in `raw_validate.py` `_validate_regex()` (line 712). Reject patterns with backreferences, lookahead/behind. |
| Add `re2` npm package | TypeScript | 1 day | Replace `new RegExp()` in `resolve.ts` evaluation path with RE2 for pattern matching. Add as optional peer dependency with fallback. |
| Add `google-re2` package | Python | 1 day | Replace `re.search()` in `resolve.py` evaluation path with RE2. Add as optional dependency with fallback + timeout. |
| Document RE2 safety | Rust, Go | 0.5 day | Document that `regex` (Rust) and `regexp` (Go) are safe by construction. Add to SDK README and inline docs. |
| Add regex complexity lint | All | 2 days | Static analysis for pattern length (max 1024), nesting depth (max 3), nested quantifiers (warn). |
| Add `regex_timeout_ms` schema field | All | 1 day | Add field to `SecretPatternsRule`, `ShellCommandsRule`, `PatchIntegrityRule` in all four SDKs simultaneously. |
| Audit built-in rulesets | N/A | 0.5 day | Verify all 37 patterns in `rulesets/*.yaml` are RE2-compatible (already verified in this RFC, codify as test). |
| Add ReDoS test vectors | All | 1 day | Add conformance test fixtures that verify pathological patterns are rejected. |

### Phase 2: Emergency Override Protocol (v0.1.1)

**Timeline:** 2 weeks
**Priority:** P0 (safety-critical -- operators need this before signing infrastructure)

| Task | Effort | Description |
|------|--------|-------------|
| Define panic policy document | 0.5 day | Standard deny-all YAML with all 10 rule blocks. Ship in `rulesets/__panic__.yaml`. |
| File-based sentinel implementation | 2 days | Reference implementation in Rust evaluator. Configurable sentinel path. |
| Environment variable override | 0.5 day | `HUSHSPEC_PANIC` check at startup and periodic re-check. |
| Signal-based implementation (Unix) | 1 day | `SIGUSR1`/`SIGUSR2` handler in Rust with async-signal-safe atomic flag. |
| API-based implementation spec | 1 day | HTTP endpoint specification with auth requirements. Reference implementation optional for v0.1.1. |
| Audit logging specification | 1 day | Event format, required fields, log integration points. |
| Recovery procedure documentation | 0.5 day | Step-by-step guide with re-verification requirements. |
| Panic mode test fixtures | 1 day | Test vectors for conformance testing. Verify deny-all behavior. |

### Phase 3: Policy Metadata Schema Extension (v0.2.0)

**Timeline:** 3 weeks
**Priority:** P1

| Task | Effort | Description |
|------|--------|-------------|
| Define `Metadata`, `SignatureBlock`, `LifecycleState` in model generator | 2 days | Update `scripts/generate_sdk_models.py` to emit types for all SDKs. |
| Add `metadata` field to `HushSpec` struct | 1 day | Update `generated_models.rs`, TypeScript types, Python dataclass, Go struct. |
| Update JSON Schema | 1 day | Add `Metadata`, `Signature`, `LifecycleState` definitions to `schemas/hushspec-core.v0.schema.json`. |
| Add `metadata` validation | 2 days | Validate `classification` enum, `approval_date` format, `content_hash` format, `lifecycle_state` enum, author != approved_by constraint. |
| Update merge logic | 1 day | Define merge behavior for `metadata` (child replaces base) in `merge.rs`, `merge.ts`, `merge.py`, `merge.go`. |
| Update spec prose | 1 day | Add metadata section to `spec/hushspec-core.md`. |
| Content hash computation | 2 days | Canonical serialization and SHA-256 hashing in all SDKs. |

### Phase 4: Signing Specification (v0.2.0)

**Timeline:** 4 weeks
**Priority:** P1

| Task | Effort | Description |
|------|--------|-------------|
| `sign_detached()` implementation | 3 days | Rust (`ed25519-dalek`), TypeScript (`@noble/ed25519`), Python (`PyNaCl`), Go (`crypto/ed25519`). |
| `verify_detached()` implementation | 2 days | Verification + `VerificationOutcome` struct in all SDKs. |
| `verify_inline()` implementation | 3 days | Canonical serialization + verification in all SDKs. |
| Rollback protection | 1 day | `policy_version` counter storage and verification. |
| `hushspec sign` CLI command | 2 days | Sign a policy file, produce `.sig` detached signature. |
| `hushspec verify` CLI command | 1 day | Verify a policy file against a public key or trusted key set. |
| Signed resolve integration | 2 days | Extend `resolve_with_loader` to accept signature verifier. |
| Sigstore/cosign integration (optional) | 3 days | Keyless signing via Fulcio + Rekor transparency log. |
| Documentation | 2 days | Signing workflow guide, key management guide, cosign integration guide. |

### Phase 5: Governance Tooling (v0.3.0)

**Timeline:** 6 weeks
**Priority:** P2

| Task | Effort | Description |
|------|--------|-------------|
| `hushspec lint` CLI | 3 days | Policy linting: security score, regex safety, metadata completeness, RE2 compatibility check. |
| `hushspec audit` CLI | 2 days | Show policy history, signature verification status, lifecycle state. |
| Policy lifecycle state machine | 3 days | Draft/review/approved/deployed/deprecated/archived with transition validation. |
| Git-based governance workflow docs | 2 days | CODEOWNERS, branch protection, CI integration examples (GitHub Actions, GitLab CI). |
| Separation of duties validation | 2 days | author != approver check in validation. CI check integration. |
| RBAC configuration schema | 2 days | `.hushspec/rbac.yaml` format and validation. |

### Phase 6: Enterprise RBAC Integration (v0.4.0)

**Timeline:** 8 weeks
**Priority:** P3

| Task | Effort | Description |
|------|--------|-------------|
| RBAC model specification | 2 days | Roles, permissions, constraints, configuration schema. |
| OIDC token exchange integration | 3 days | Authenticate authors/approvers. Populate `metadata.author` from OIDC `sub` claim. |
| LDAP group membership resolver | 3 days | Map directory groups to RBAC roles. Cache with configurable TTL. |
| SCIM user/group sync | 2 days | Synchronize role assignments from identity provider. |
| Policy management API | 5 days | CRUD + approval workflow REST API with RBAC enforcement. |
| Web UI for policy management | 10 days | Policy editor, approval workflow, audit viewer, security score dashboard. |

---

## 9. Compliance Considerations

### 9.1 SOX Compliance (Sarbanes-Oxley)

SOX Section 404 requires internal controls over financial reporting systems. AI agents that interact with financial data or systems are in scope.

| SOX Requirement | HushSpec Control | Implementation |
|----------------|-----------------|----------------|
| Separation of duties (Section 404) | `metadata.author` != `metadata.approved_by` | Enforced by validation + RBAC |
| Change management (Section 302) | `metadata.change_ticket` | Links policy changes to change records |
| Access controls (Section 404) | RBAC roles and permissions | `approver` role required for deployment |
| Audit trail (Section 302) | Signature chain + git history + audit log | Immutable record of all policy changes |
| Periodic review (Section 404) | Policy lifecycle states | `deprecated` state triggers review |
| Management certification (Section 302) | `metadata.approved_by` + `metadata.approval_date` | Documented approval by authorized principal |

### 9.2 NIST Cybersecurity Framework (CSF 2.0) Alignment

| NIST CSF 2.0 Function | Category | Subcategory | HushSpec Mapping |
|----------------------|----------|-------------|-----------------|
| **Govern** | GV.OC | Organizational Context | Policy inventory via `metadata.classification` |
| **Govern** | GV.RM | Risk Management Strategy | RBAC model, separation of duties, policy lifecycle |
| **Govern** | GV.PO | Policy | HushSpec policy documents as machine-readable security policy |
| **Identify** | ID.AM | Asset Management | Policy inventory, `metadata.classification` |
| **Protect** | PR.AA | Identity Management and Access Control | `rules.tool_access`, `rules.forbidden_paths`, `rules.path_allowlist`, RBAC |
| **Protect** | PR.DS | Data Security | `rules.secret_patterns`, `rules.egress` |
| **Protect** | PR.PS | Platform Security | Policy signing, content hashing, extends chain verification |
| **Protect** | PR.IR | Technology Infrastructure Resilience | `regex_timeout_ms`, ReDoS protection, panic mode recovery |
| **Detect** | DE.CM | Continuous Monitoring | `extensions.detection` (prompt injection, jailbreak, threat intel) |
| **Detect** | DE.AE | Adverse Event Analysis | Panic mode forensic logging |
| **Respond** | RS.MA | Incident Management | Emergency override / panic mode |
| **Respond** | RS.MI | Incident Mitigation | Panic policy with deny-all posture |
| **Respond** | RS.AN | Incident Analysis | Panic mode forensic logs, audit trail |
| **Recover** | RC.RP | Incident Recovery Planning | Panic mode recovery procedure, gradual resumption |

### 9.3 ISO 27001:2022 Control Mapping

| ISO 27001:2022 Control | Control Name | HushSpec Mapping |
|------------------------|-------------|-----------------|
| 5.1 | Policies for information security | HushSpec policy documents |
| 5.2 | Information security roles and responsibilities | RBAC roles, separation of duties |
| 5.3 | Segregation of duties | `metadata.author` != `metadata.approved_by`; author != deployer |
| 5.9 | Inventory of information and other associated assets | `metadata.classification`, policy inventory |
| 5.10 | Acceptable use of information and other associated assets | `rules.tool_access`, `rules.path_allowlist` |
| 5.23 | Information security for use of cloud services | `rules.egress` with default deny for cloud API access |
| 5.36 | Compliance with policies, rules and standards for information security | `hushspec lint` security scoring, conformance testing |
| 6.1 | Screening | RBAC role assignment with identity verification |
| 8.2 | Privileged access rights | `approver` and `admin` roles, RBAC permissions matrix |
| 8.3 | Information access restriction | `rules.forbidden_paths`, `rules.egress`, `rules.tool_access` |
| 8.4 | Access to source code | `rules.path_allowlist` for repository access control |
| 8.5 | Secure authentication | Ed25519 signing, OIDC/LDAP integration |
| 8.9 | Configuration management | Policy lifecycle states, `metadata.version`, content hashing |
| 8.15 | Logging | Audit logging, panic mode events, forensic logs |
| 8.16 | Monitoring activities | `extensions.detection`, panic mode forensic logging |
| 8.24 | Use of cryptography | Ed25519 signing, SHA-256 hashing |
| 8.25 | Secure development lifecycle | `rules.patch_integrity`, `rules.secret_patterns` |
| 8.28 | Secure coding | ReDoS protection, regex complexity budgets |

### 9.4 PCI-DSS v4.0 Considerations

For AI agents processing payment card data:

| PCI-DSS Requirement | HushSpec Control |
|---------------------|-----------------|
| Req 1.2: Network security controls | `rules.egress` with default deny |
| Req 3.4: Protect stored account data | `rules.secret_patterns` for PAN detection |
| Req 6.2: Bespoke and custom software security | ReDoS protection, regex complexity limits |
| Req 6.3: Security vulnerabilities identified and addressed | `hushspec lint` security scoring, ReDoS lint |
| Req 7.2: Access to system components restricted | `rules.tool_access` with allowlist mode |
| Req 8.3: Strong authentication | Policy signing, RBAC with OIDC |
| Req 10.2: Audit logs capture details | Audit logging, panic mode events |
| Req 11.3: Vulnerabilities identified and addressed | `hushspec lint` continuous validation |
| Req 12.10: Incident response | Emergency override / panic mode with documented recovery |

### 9.5 HIPAA Security Rule Considerations

For AI agents processing protected health information (PHI):

| HIPAA Security Rule | Standard | HushSpec Control |
|---------------------|----------|-----------------|
| 164.312(a)(1) | Access Control | `rules.tool_access`, `rules.path_allowlist`, RBAC |
| 164.312(a)(2)(i) | Unique User Identification | `metadata.author`, `metadata.approved_by` with OIDC subject |
| 164.312(a)(2)(iii) | Automatic Logoff | Posture extension timeout transitions |
| 164.312(a)(2)(iv) | Encryption and Decryption | Ed25519 signing, SHA-256 hashing |
| 164.312(b) | Audit Controls | Audit logging, policy lifecycle tracking |
| 164.312(c)(1) | Integrity | Content hashing, signature verification |
| 164.312(c)(2) | Mechanism to Authenticate ePHI | Content-addressed policy references |
| 164.312(d) | Person or Entity Authentication | OIDC/LDAP integration, policy signing |
| 164.312(e)(1) | Transmission Security | `rules.egress` controlling data transmission |
| 164.312(e)(2)(i) | Integrity Controls | Extends chain verification, content hashing |
| 164.308(a)(5)(ii)(C) | Security Incident Procedures | Emergency override / panic mode |
| 164.308(a)(6) | Security Incident Procedures | Audit logging, panic mode forensics |

---

## Appendix A: Detached Signature File Format

```
{
  "$schema": "https://hushspec.dev/schemas/hushspec-sig.v1.schema.json",
  "format_version": "1.0",
  "algorithm": "ed25519",
  "signature": "<base64url without padding>",
  "signed_at": "<ISO 8601 UTC timestamp>",
  "key_id": "<opaque key identifier>",
  "signer": "<identity string>",
  "policy_version": <integer, optional>,
  "sigstore": {
    "certificate": "<base64 Fulcio certificate, optional>",
    "transparency_log_entry": "<Rekor UUID, optional>",
    "issuer": "<OIDC issuer URL, optional>",
    "subject": "<OIDC subject, optional>",
    "log_index": <integer, optional>
  },
  "x509": {
    "certificate_chain": ["<base64 leaf cert>", "<base64 intermediate>", "<base64 root>"]
  }
}
```

**JSON Schema for `.sig` files:**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "HushSpec Detached Signature",
  "type": "object",
  "required": ["format_version", "algorithm", "signature", "signed_at", "key_id"],
  "additionalProperties": false,
  "properties": {
    "$schema": { "type": "string" },
    "format_version": { "type": "string", "const": "1.0" },
    "algorithm": { "type": "string", "enum": ["ed25519"] },
    "signature": { "type": "string", "pattern": "^[A-Za-z0-9_-]+$" },
    "signed_at": { "type": "string", "format": "date-time" },
    "key_id": { "type": "string", "minLength": 1 },
    "signer": { "type": "string" },
    "policy_version": { "type": "integer", "minimum": 1 },
    "sigstore": {
      "type": "object",
      "properties": {
        "certificate": { "type": "string" },
        "transparency_log_entry": { "type": "string" },
        "issuer": { "type": "string", "format": "uri" },
        "subject": { "type": "string" },
        "log_index": { "type": "integer", "minimum": 0 }
      },
      "additionalProperties": false
    },
    "x509": {
      "type": "object",
      "properties": {
        "certificate_chain": {
          "type": "array",
          "items": { "type": "string" },
          "minItems": 1
        }
      },
      "additionalProperties": false
    }
  }
}
```

## Appendix B: Canonical YAML Serialization Rules

For inline signature computation and content hash computation, the document MUST be serialized to canonical form:

1. All keys sorted lexicographically at every nesting level.
2. No YAML comments.
3. No trailing whitespace on any line.
4. LF (U+000A) line endings only (no CR+LF).
5. No trailing newline at end of file.
6. Strings quoted with double quotes only when required by YAML 1.2 (i.e., when the value could be misinterpreted as another type).
7. Booleans as `true`/`false` (not `yes`/`no`/`on`/`off`).
8. Numbers in their simplest form (no leading zeros, no trailing zeros after decimal).
9. The `metadata.signature` block is omitted.
10. Empty arrays serialized as `[]` (flow style).
11. Empty objects serialized as `{}` (flow style).
12. No YAML aliases or anchors.

**Reference implementation guidance:** Use `serde_yaml` (Rust), `js-yaml` with `sortKeys: true` (TypeScript), `PyYAML` with `default_flow_style=False, allow_unicode=True` and key sorting (Python), `gopkg.in/yaml.v3` with custom encoder (Go). Each SDK MUST include canonical serialization test vectors to verify cross-engine consistency.

## Appendix C: ReDoS-Vulnerable Pattern Examples

The following patterns are included for testing ReDoS detection. They MUST be rejected by conformant implementations.

```yaml
# Test vector 1: nested quantifiers (backreference in backtracking engines)
pattern: "(a+)+"
rejection_reason: "nested quantifiers"

# Test vector 2: overlapping alternation with quantifier
pattern: "(a|a)*"
rejection_reason: "nested quantifiers with overlapping alternation"

# Test vector 3: exponential backtracking
pattern: "([a-zA-Z]+)*@"
rejection_reason: "nested quantifiers"

# Test vector 4: polynomial backtracking
pattern: "a*a*a*a*b"
rejection_reason: "complexity budget exceeded (quantifier depth 4)"

# Test vector 5: realistic-looking but dangerous
pattern: "(?:password|secret)\\s*=\\s*[\"']?([^\"'\\s]*)*[\"']?"
rejection_reason: "nested quantifiers"

# Test vector 6: lookahead (non-RE2)
pattern: "(?=.*[A-Z])(?=.*[0-9]).{8,}"
rejection_reason: "lookahead not in RE2 subset"

# Test vector 7: lookbehind (non-RE2)
pattern: "(?<=password:)\\s*\\S+"
rejection_reason: "lookbehind not in RE2 subset"

# Test vector 8: backreference (non-RE2)
pattern: "(\\w+)\\s+\\1"
rejection_reason: "backreference not in RE2 subset"

# Test vector 9: possessive quantifier (non-RE2)
pattern: "[a-z]++[0-9]"
rejection_reason: "possessive quantifier not in RE2 subset"

# Test vector 10: atomic group (non-RE2)
pattern: "(?>abc|ab)c"
rejection_reason: "atomic group not in RE2 subset"
```

## Appendix D: Emergency Override Audit Log Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "HushSpec Emergency Override Audit Event",
  "type": "object",
  "required": ["event", "timestamp", "mechanism"],
  "additionalProperties": false,
  "properties": {
    "event": {
      "type": "string",
      "enum": [
        "panic_mode_activated",
        "panic_mode_deactivated",
        "emergency_policy_loaded",
        "panic_mode_denial",
        "panic_mode_recovery_started",
        "panic_mode_recovery_completed",
        "panic_mode_recovery_failed"
      ]
    },
    "timestamp": { "type": "string", "format": "date-time" },
    "correlation_id": { "type": "string" },
    "mechanism": {
      "type": "string",
      "enum": ["file_sentinel", "signal", "api", "environment_variable", "distributed"]
    },
    "policy": { "type": "string" },
    "operator": { "type": "string" },
    "reason": { "type": "string" },
    "previous_policy": { "type": "string" },
    "previous_policy_hash": { "type": "string" },
    "ttl_seconds": { "type": "integer", "minimum": 0 },
    "action_type": {
      "type": "string",
      "description": "For panic_mode_denial events: the action type that was denied."
    },
    "target": {
      "type": "string",
      "description": "For panic_mode_denial events: the target of the denied action."
    },
    "session_id": {
      "type": "string",
      "description": "For panic_mode_denial events: the agent session that attempted the action."
    }
  }
}
```

## Appendix E: RBAC Configuration Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "HushSpec RBAC Configuration",
  "type": "object",
  "required": ["roles"],
  "additionalProperties": false,
  "properties": {
    "roles": {
      "type": "object",
      "properties": {
        "viewer": { "$ref": "#/$defs/RoleAssignment" },
        "author": { "$ref": "#/$defs/RoleAssignment" },
        "reviewer": { "$ref": "#/$defs/RoleAssignment" },
        "approver": { "$ref": "#/$defs/RoleAssignment" },
        "deployer": { "$ref": "#/$defs/RoleAssignment" },
        "admin": { "$ref": "#/$defs/RoleAssignment" },
        "auditor": { "$ref": "#/$defs/RoleAssignment" }
      },
      "additionalProperties": false
    }
  },
  "$defs": {
    "RoleAssignment": {
      "type": "object",
      "required": ["principals"],
      "additionalProperties": false,
      "properties": {
        "principals": {
          "type": "array",
          "items": {
            "type": "string",
            "pattern": "^(user|group|team|service):.+$"
          }
        }
      }
    }
  }
}
```
