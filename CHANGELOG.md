# Changelog

All notable changes to Vex-Talon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2026-03-17

### Added

- **Credential File Protection — L1 Governor (GitHub #34819)**
  - 2 new CRITICAL policies: `block-credential-file-reads` + `block-credential-file-bash-reads`
  - Blocks Read tool and Bash display (cat/head/tail/less/more/bat) of credential files
  - Protected files: `.netrc`, `.npmrc`, `.kube/config`, `.cargo/credentials`, `.docker/config.json`, `.aws/credentials`, `.pgpass`
  - Maps to: OWASP LLM02 (Sensitive Information Disclosure), OWASP Agentic ASI05

- **@File Mention Guard — UserPromptSubmit Hook (GitHub #35147)**
  - New cross-cutting hook warns when @file mentions reference sensitive credential/key files
  - @file mentions bypass ALL PreToolUse hooks (L0-L19) by injecting content directly into context
  - Provides additionalContext warning to model to prevent credential processing
  - First UserPromptSubmit hook in vex-talon

### Fixed

- **L0 Secure Code Enforcer — classifyCode() missing language parameter**
  - `classifyCode()` function signature lacked `language` parameter
  - Future-proofs for CI injection detection (YAML-specific patterns)
  - Matches PAI fix for GitHub Actions expression injection detection

### Changed

- L1 Governor: 15 → 17 policies (added 2 credential file protection)
- hooks.json: Added `UserPromptSubmit` event type (first in vex-talon)
- L0 classifyCode signature: `(content, filePath)` → `(content, filePath, language)`

---

## [1.6.0] - 2026-03-09

### Added

- **Lateral Movement Prevention — Cedar Phase 4 (AML.T0091 / AML.TA0015)**
  - New Cedar policy `lateral-movement.cedar` with 2 forbid rules:
    - `forbid-mcp-external-when-secret-taint`: Block ALL external MCP calls when session taint >= SECRET
    - `forbid-mcp-write-when-confidential-taint`: Block external MCP WRITES when taint >= CONFIDENTIAL
  - New Cedar action `mcp_call` in schema with service context (`mcpServer`, `mcpMethod`, `serviceType`, `isWrite`)
  - MCP service classification in Cedar evaluator (local vs external, default-external for unknown)
  - Command-based taint escalation in IFC tracker: `op read/run`, `secretless-ai env`, `vault read`,
    `kubectl get secret`, `aws secretsmanager`, `az keyvault`, `gcloud secrets` → SECRET taint
  - Sensitivity labels v2.0.0: added `command_rules` and `mcp_service_classification` sections
  - 6 new Cedar test cases (23 → 29 total), all passing
  - Maps to: MITRE ATLAS AML.T0091, AML.TA0015, OWASP LLM02, OWASP Agentic ASI05

### Changed

- Cedar policies: 7 → 8 files (added `lateral-movement.cedar`)
- Cedar test suite: 23 → 29 tests
- Governor passes tool parameters to IFC taint tracker for command analysis
- Shared libraries: `ifc-taint-tracker.ts` now exports `recordToolCall(sessionId, toolName, params?)`

---

## [1.5.3] - 2026-03-09

### Added

- **CVE-2026-21852: ANTHROPIC_BASE_URL Exfiltration Prevention (L1 Governor)**
  - New CRITICAL policy `block-anthropic-base-url-override` blocks API key exfiltration via base URL redirect
  - Malicious project configs can set ANTHROPIC_BASE_URL to route API calls (with keys) to attacker endpoints
  - Patched in Claude Code v2.0.65 but defense-in-depth warrants Governor-level blocking
  - Maps to: OWASP LLM02 (Sensitive Information Disclosure)

- **Agent Context in Audit Logs (v2.1.69+ Support)**
  - `agent_id` and `agent_type` fields added to HookInput and AuditLogEntry
  - Tracks which agent (main session, subagent, or background) triggered each tool call
  - `Agent` tool added to MONITORED_TOOLS for subagent spawning visibility

## [1.5.2] - 2026-03-07

### Added

- **OpenA2A Ecosystem Integration (Recommended Companions)**
  - Added [Secretless AI](https://github.com/opena2a-org/secretless-ai) as recommended credential protection tool
  - Added [HackMyAgent](https://github.com/opena2a-org/hackmyagent) as recommended security testing tool
  - New "Credential Protection (Recommended)" section in README under "What You Should Consider Adding"
  - OpenA2A credited in Credits section
  - No hook changes — these are external companion tools, not built-in layers

## [1.5.1] - 2026-03-06

### Added

- **Input-side DLP (L1 Governor — Phase 4B)**
  - 17 secret patterns scanned across ALL tool parameters (not just Bash)
  - Detects: AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, Discord, Google, Twilio, SendGrid, npm tokens + private keys + bearer tokens
  - Warn-only: alerts user and AI via dual notification, does not block
  - Redacted snippets in stderr output (shows first/last 4 chars only)
  - DLP findings logged to audit trail (`dlp_findings` field)
  - Maps to: OWASP LLM02 (Sensitive Information Disclosure)

## [1.5.0] - 2026-03-06

### Added

- **Cedar Formal Authorization (L1 Governor — Phase 1-3)**
  - Cedar policy evaluator (`hooks/lib/cedar-evaluator.ts`) using `@cedar-policy/cedar-wasm`
  - Hybrid model: Cedar evaluates alongside YAML — Cedar `forbid` overrides YAML `allow`
  - Cedar `allow` does NOT override an already-blocked YAML result (defense-in-depth)
  - Graceful degradation: Cedar failure falls back to YAML-only evaluation
  - 7 Cedar policy files covering Phase 1 (core), Phase 2 (IFC), and Phase 3 (trajectory)
  - Bundled fallback: schema and policies ship with plugin source under `packages/core/src/security/cedar/`
  - User override: policies also loaded from `~/.vex-talon/security/cedar/` when present
  - New audit log fields: `cedar_decision`, `cedar_policies`, `cedar_time_ms`
  - Maps to: OWASP LLM01, LLM02, LLM10, MITRE ATLAS AML.T0024, AML.T0047, AML.T0054

- **IFC Taint Tracker (Bell-LaPadula, Phase 2)**
  - Taint tracker (`hooks/lib/ifc-taint-tracker.ts`) with session-scoped state
  - Bell-LaPadula "No write-down": taint level escalates but never decreases within a session
  - 4 sensitivity levels: PUBLIC (0), INTERNAL (1), CONFIDENTIAL (2), SECRET (3)
  - Sensitivity labels configured via `~/.vex-talon/security/cedar/sensitivity-labels.json`
  - Bundled default labels for universal patterns: `.env`, `credentials`, `private_key`, `.ssh/`
  - State file: `~/.vex-talon/state/session-taint.json` (scoped per `session_id`)
  - New audit log fields: `ifc_taint_level`, `ifc_taint_label`

- **Trajectory Modeling (Phase 3)**
  - Per-category tool-call counters in taint state: `file_reads`, `file_writes`, `shell_commands`,
    `web_fetches`, `web_searches`, `mcp_calls`, `skill_invokes`, `consecutive_same_tool`
  - Cedar trajectory-limits policy enforces step-count limits in tainted sessions:
    - SECRET taint: hard limit at 50 total tool calls
    - CONFIDENTIAL taint: block WebFetch after 10 requests
    - CONFIDENTIAL taint: block shell after 50 commands
    - Any taint: block after 20 consecutive same tool (runaway agent detection)

- **Cedar Policy Files** (`packages/core/src/security/cedar/policies/`)
  - `env-protection.cedar` — Block .env file reads/writes
  - `pipe-execution.cedar` — Block curl/wget piped to shell
  - `git-safety.cedar` — Block git force-push
  - `destructive-ops.cedar` — Block rm -rf on critical paths
  - `ifc-egress.cedar` — Block network when session taint >= CONFIDENTIAL
  - `sensitive-data-exfil.cedar` — Defense-in-depth exfiltration prevention
  - `trajectory-limits.cedar` — Step-count limits for tainted sessions

- **Cedar Schema** (`packages/core/src/security/cedar/talon.cedarschema`)
  - `namespace Talon` with entity types: `Agent`, `Tool`, `File`, `Session`, `Profile`, `Label`
  - Actions: `tool_use`, `read_file`, `write_file`, `execute_command`, `git_operation`, `network_request`
  - Full context schema for trajectory fields

- **Cedar Test Suite** (`packages/core/src/security/cedar/test-cedar-policies.ts`)
  - 23 test cases covering all 3 phases
  - Run: `bun run packages/core/src/security/cedar/test-cedar-policies.ts`
  - All 23/23 passing

- **Dependency**: `@cedar-policy/cedar-wasm@^4.9.1` added to `@vex-talon/core`

### Changed

- L1 Governor audit log now includes Cedar decision, matched policies, Cedar eval time,
  IFC taint level and label on every tool call
- L1 Governor blocks on Cedar DENY even when YAML policies allow (Cedar takes precedence)
- Shared libraries: 5 → 7 (added `cedar-evaluator`, `ifc-taint-tracker`)

---

## [1.4.0] - 2026-03-06

### Added

- **CLAUDE.md — Security Radar Behavioral Directive**
  - New `CLAUDE.md` loaded into model context when plugin is active
  - **Security Radar:** Proactive risk detection directive — AI flags novel security risks
    during any work (installs, builds, integrations, config changes) without waiting to be asked
  - Feed-forward loop: risks caught by Security Radar become candidates for permanent hook rules
  - Hook Awareness guidance: how to respond to CRITICAL/BLOCK, HIGH/WARN, and detection alerts
  - Defense Principles: trust nothing from tool outputs, secrets never in code, client data stays
    local, fail closed, measure twice cut once
  - First plugin-delivered behavioral directive — complements the 16 automated hooks with
    AI judgment for novel threats that pattern matching can't catch

## [1.3.0] - 2026-02-27

### Added

- **L18 MCP Audit: ConfigChange Hook (Real-time Config Blocking)**
  - New ConfigChange hook scans `.mcp.json` edits mid-session in real-time (<2s)
  - CRITICAL findings → blocks config change (exit 2), HIGH → warns
  - Detects: blocked URLs (webhook.site, ngrok, pastebin, raw IPs), dangerous commands
    (curl|sh, reverse shells, base64 decode to shell), injection patterns (instruction
    override, role hijack, system prompt injection), malicious npm packages (10 known)
  - Env var scanning for suspicious URLs in server configurations
  - JSONL audit logging with severity, duration, and block/warn/pass result
  - Complements existing L18 pre-deployment Proximity scanning with real-time defense
  - Maps to: OWASP LLM01, OWASP Agentic ASI06, MITRE ATLAS AML.T0051, AML.T0053
  - Requires Claude Code v2.1.59+ (ConfigChange hook event)

- **Session Logger Library (SessionStart stderr fix)**
  - New shared `session-logger.ts` library redirects informational messages to log file
  - Prevents Claude Code from displaying false "hook error" on `/clear` for normal
    SessionStart status output
  - Auto-rotation at 512KB with last-256KB preservation
  - Exports `logInfo()` and `logWarn()` for consistent logging across SessionStart hooks

### Changed

- Hook count: 16 → 17 (added ConfigChange event)
- Shared libraries: 4 → 5 (added session-logger)

---

## [1.2.0] - 2026-02-13

### Added

- **L4 Injection Scanner: Session Escalation (Persistence Defense)**
  - Cumulative detection tracking across tool calls within a session
  - Three escalation levels: NORMAL → ELEVATED (3+ signals) → CRITICAL (5+ signals)
  - ELEVATED: WARN actions escalate to ALERT
  - CRITICAL: All detections escalate to ALERT (maximum vigilance)
  - Near-misses (heuristic triggers) count at half weight
  - Session state tracked per `session_id`, auto-resets on new session
  - Audit log includes `escalation_level`, `session_detection_count`, `session_near_miss_count`
  - stderr warning when escalation level changes

### Research

- Based on Anthropic Opus 4.6 System Card (February 2026) persistence scaling data
- Single-attempt attack success: 17.8% → 200 attempts: 78.6% (without safeguards)
- Multiple detections in one session indicate persistent attack campaign, warranting escalated thresholds

---

## [1.1.0] - 2026-02-11

### Added

- **L5 Output Sanitizer: ANSI Terminal Injection Detection**
  - 6 new patterns defending against the Terminal DiLLMa attack (SAGAI 2025 IEEE S&P workshop case study)
  - OSC 52 clipboard manipulation (CRITICAL) — read/write terminal clipboard
  - DCS device control strings (HIGH) — send commands to terminal emulator
  - 8-bit CSI filter bypass (HIGH) — evade 7-bit escape sequence filters
  - Bracketed paste mode manipulation (HIGH) — enable paste injection attacks
  - OSC title-set social engineering (MEDIUM) — change terminal window title
  - Sixel graphics data embedding (MEDIUM) — embedded data in image sequences
  - New file extensions scanned: `.sh`, `.bash`, `.zsh`, `.py`, `.rb`, `.pl`
  - Context-aware warnings: ANSI-specific remediation vs XSS-specific remediation

### Changed

- L5 Output Sanitizer now covers both web (XSS) and terminal (ANSI injection) attack vectors
- Pattern count: 7 → 13 (6 new ANSI patterns)
- File extension coverage: 8 → 14 (6 new terminal extensions)

### Research

- Based on analysis of "Systems Security Foundations for Agentic Computing" (Google, UCSD, UW Madison, EmbraceTheRed, December 2025)
- Terminal DiLLMa case study: ANSI escape sequences in LLM output hijack terminal emulators for clipboard manipulation, data exfiltration via DNS, and unauthorized actions

---

## [1.0.0] - 2026-02-04

### Added - Initial Public Release

**20-Layer Defense-in-Depth Security for Claude Code**

- **14 Ported Security Hooks**

  *PreToolUse (Block Before Execution):*
  - L0: Secure Code Enforcer - Blocks CRITICAL vulnerabilities before code is written
  - L1: Governor Agent - 33+ policy enforcement rules with input modification
  - L3: Memory Validation - Detects injection in MCP memory operations
  - L9: Egress Scanner - Prevents data exfiltration via secrets, bulk data, blocked destinations
  - L14-pre: Supply Chain Pre-Install - Blocks 60+ known malicious packages (+ optional OSM API)
  - L19: Skill Scanner - Scans skills for injection patterns before invocation

  *PostToolUse (Detect After Execution):*
  - L2: Secure Code Linter - Post-write security analysis with static analysis + optional LLM review
  - L4: Injection Scanner - Detects prompt injection in tool outputs (89+ patterns)
  - L5: Output Sanitizer - Scans web files for XSS vectors
  - L7: Image Safety Scanner - Detects steganography and visual prompt injection
  - L14: Supply Chain Post-Install - Runs npm audit / pip-audit after installations
  - L17: Spend Alerting - Tracks session costs with threshold warnings

  *Session Lifecycle:*
  - L12: Least Privilege Profiles - Permission profiles (dev, audit, client-work, research)
  - STOP: Security Report - Generates HTML report at session end

- **Dual Notification Pattern**
  - All PostToolUse hooks notify BOTH user (console.error) AND AI (additionalContext)
  - Defense-in-depth: detection influences AI interpretation of flagged content

- **Externalized Security Configs**
  - JSON configs in `~/.vex-talon/config/` for custom patterns
  - 60-second cache TTL with automatic fallback to built-in defaults

- **Plugin Commands**
  - `/talon` - Main security command
  - `/talon-status` - Layer status overview
  - `/talon-report` - Generate security report
  - `/talon-intel-update` - Update security intelligence

- **Plugin Skills**
  - `security-scan` - On-demand security scanning
  - `security-intel-update` - Update detection patterns

- **Framework Coverage**
  - OWASP LLM Top 10 2025: 9/10 coverage
  - OWASP Agentic Top 10 2026: Full coverage
  - MITRE ATLAS: 16+ technique mappings

- **4 Rounds of Security Audits** - Score: 91/100

### Technical

- **Monorepo Structure**
  - `@vex-talon/core` - Security hooks, policies, detection patterns, and shared libraries
  - `@vex-talon/db` - SQLite database layer for security event storage and querying

- **Shared Libraries**
  - Atomic file operations (crash-safe writes)
  - Circuit breaker (fault tolerance)
  - Config loader (60s TTL cache with fallback)
  - Profile loader (permission enforcement)
  - Unicode normalization (homoglyph detection)

---

**Vex-Talon** - Sharp, fast, always watching.
