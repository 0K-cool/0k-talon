# Security Radar Rule Generation Workflow

**Purpose:** When Security Radar detects a novel risk, draft detection rule(s) for automated enforcement in Vex-Talon's config system.
**Trigger:** AI detects a security risk during any work that has no existing pattern coverage.
**Approval:** All generated rules require user approval before applying.

---

## Step 1: Classify the Risk

Determine which config target(s) the rule belongs in:

| Risk Type | Config Target | Default Location |
|-----------|--------------|-----------------|
| Prompt injection pattern | Injection Patterns | `~/.vex-talon/config/injection/patterns.json` |
| Data exfiltration vector | Egress Config | `~/.vex-talon/config/egress/config.json` |
| Vulnerable code pattern | Code Enforcer | `~/.vex-talon/config/code-enforcer/patterns.json` |
| Malicious package | Supply Chain | `~/.vex-talon/config/supply-chain/config.json` |
| XSS / output injection | Output Sanitizer | `~/.vex-talon/config/output-sanitizer/patterns.json` |
| Image-based attack | Image Safety | `~/.vex-talon/config/image-safety/config.json` |
| Skill injection | Skill Scanner | `~/.vex-talon/config/skill-scanner/config.json` |

A single risk may require rules in multiple configs.

---

## Step 2: Draft the Rule

Read the target config file first to match the existing pattern structure, then draft a rule in the correct format.

---

## Step 3: Rule Formats Reference

### Injection Pattern (JSON)
```json
{
  "pattern": "regex_pattern_here",
  "name": "Descriptive Name",
  "severity": "CRITICAL",
  "category": "instruction_override | jailbreak | encoding | context_manipulation | data_exfiltration | role_hijack | delimiter_injection",
  "description": "What this pattern detects"
}
```

### Egress Blocked Destination (JSON)
```json
{
  "pattern": "domain\\.com",
  "name": "Service Name",
  "severity": "CRITICAL",
  "description": "Why this destination is blocked"
}
```

### Code Enforcer Pattern (JSON)
```json
{
  "pattern": "regex_for_vulnerable_code",
  "name": "Vulnerability Name",
  "severity": "CRITICAL",
  "category": "sql_injection | command_injection | hardcoded_secret | path_traversal | unsafe_deserialization | prompt_injection",
  "description": "What this detects",
  "fix": "Secure alternative"
}
```

### Supply Chain Blocklist (JSON)
```json
{
  "name": "package-name",
  "ecosystem": "npm | pip | cargo | go",
  "reason": "Why this package is blocked",
  "severity": "CRITICAL",
  "reference": "URL to advisory"
}
```

---

## Step 4: Present for Approval

Present the drafted rule(s) to the user:

```
SECURITY RADAR: New Rule Proposal

Risk: [description]
Detected during: [what work triggered this]
Config target: [file path]

Proposed rule:
[formatted rule]

Approve? (yes/no/modify)
```

---

## Step 5: Apply on Approval

1. Read the target config file
2. Add the new rule in the correct location
3. Validate JSON: `python3 -c "import json; json.load(open('file'))"`
4. Configs are auto-reloaded by hooks (60-second cache TTL)

---

## Step 6: Verify

After applying, test that the rule works:
- For injection patterns: confirm the pattern matches the example attack string
- For egress rules: confirm the destination would be blocked
- For code enforcer: confirm the vulnerable code pattern is detected

---

**Version:** 1.0.0
**Created:** 2026-03-06
