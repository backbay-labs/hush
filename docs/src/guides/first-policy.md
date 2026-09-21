# Writing Your First Policy

This guide walks through building a HushSpec policy from scratch.

## Step 1: Start Minimal

Every HushSpec document needs exactly one required field:

```yaml
hushspec: "1.0.0"
```

This is a valid document. It declares no rules, so no actions are restricted.

## Step 2: Add Metadata

Give your policy a name and description:

```yaml
hushspec: "1.0.0"
name: "my-first-policy"
description: "A starter policy for development"
```

## Step 3: Block Sensitive Paths

The most common first rule. Block access to credentials and secrets:

```yaml
hushspec: "1.0.0"
name: "my-first-policy"

rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/credentials*"
    exceptions:
      - "**/.env.example"
```

## Step 4: Control Network Egress

Restrict which domains the agent can reach:

```yaml
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"

  egress:
    allow:
      - "api.openai.com"
      - "*.anthropic.com"
      - "**.googleapis.com"
    default: "block"
```

With `default: "block"`, any domain not in the `allow` list is denied.

## Step 5: Add Secret Detection

Catch secrets before they get written to files:

```yaml
rules:
  # ... previous rules ...

  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN (RSA |EC )?PRIVATE KEY-----"
        severity: critical
      - name: generic_token
        pattern: "(?i)(token|secret|password)\\s*[=:]\\s*['\"]?[a-z0-9]{20,}"
        severity: warn
```

## Step 6: Control Tool Access

Block dangerous tools and require confirmation for sensitive ones:

```yaml
rules:
  # ... previous rules ...

  tool_access:
    block:
      - shell_exec
      - run_command
    require_confirmation:
      - deploy
      - database_write
    default: "allow"
```

## The Complete Policy

```yaml
hushspec: "1.0.0"
name: "my-first-policy"
description: "Development policy with basic protections"

rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
    exceptions:
      - "**/.env.example"

  egress:
    allow:
      - "api.openai.com"
      - "*.anthropic.com"
    default: "block"

  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN (RSA |EC )?PRIVATE KEY-----"
        severity: critical

  shell_commands:
    forbidden_patterns:
      - "rm\\s+-rf\\s+/"
      - "curl.*\\|.*sh"

  tool_access:
    block:
      - shell_exec
    require_confirmation:
      - deploy
    default: "allow"
```

## Next Steps

- Extend a built-in policy instead of starting from scratch -- see [Merge Semantics](../merge-semantics.md)
- Add [Posture](../extensions/posture.md) for budget limits and state machines
- Use this policy with [Clawdstrike](clawdstrike.md)
