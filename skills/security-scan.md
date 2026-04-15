---
name: security-scan
description: Run comprehensive security analysis on code files for vulnerabilities, injection patterns, and policy violations
---

# 0K-Talon Security Scan Skill

Analyze code for security vulnerabilities using the 21-layer defense-in-depth architecture.

## When to Use

- Before committing security-sensitive code
- During code review
- When analyzing untrusted files
- For security audits

## Capabilities

### Code Analysis (L0, L2)
- SQL injection detection
- Command injection patterns
- Hardcoded secrets (API keys, passwords)
- Unsafe deserialization
- Path traversal vulnerabilities

### Injection Scanning (L4)
- 89+ prompt injection patterns
- Instruction override detection
- Jailbreak attempts
- Context manipulation
- Encoding-based attacks

### Output Analysis (L5)
- XSS vectors (innerHTML, v-html)
- Dangerous functions (eval, document.write)
- javascript: URL schemes

### Supply Chain (L14)
- Known malicious packages
- Typosquatting detection
- npm/pip audit integration

## Analysis Process

1. **File Classification**
   - Determine file type and applicable scanners
   - Load relevant pattern configs

2. **Multi-Layer Scan**
   - Run each applicable security layer
   - Collect findings with severity ratings

3. **Report Generation**
   - Summarize findings by severity
   - Provide remediation guidance
   - Map to OWASP/ATLAS frameworks

## Output Format

```
🔴 CRITICAL: [count] findings requiring immediate attention
🟠 HIGH: [count] significant security issues
🟡 MEDIUM: [count] potential vulnerabilities
🟢 LOW: [count] informational findings

[Detailed findings with file:line references and remediation steps]
```

## Framework Coverage

- **OWASP LLM 2025**: LLM01-LLM10 (9/10 coverage)
- **OWASP Agentic 2026**: Full coverage
- **MITRE ATLAS**: 18+ technique mappings
