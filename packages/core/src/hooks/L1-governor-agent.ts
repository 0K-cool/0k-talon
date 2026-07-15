#!/usr/bin/env bun

/**
 * L1 Governor Agent - PreToolUse Hook
 *
 * Purpose: Real-time policy enforcement before tool execution
 * Pattern: Sidecar Pattern (independent monitoring)
 * Action: DENY via hookSpecificOutput.permissionDecision, or exit code 2
 * OWASP: LLM02 (Sensitive Information Disclosure), LLM01 (Prompt Injection)
 *
 * A BLOCK policy DENIES the call. It does not rewrite tool inputs: the Governor
 * used to emit a top-level `tool_input` "safe alternative" and exit 0, which
 * Claude Code ignores — every BLOCK was a silent no-op while the banner and the
 * audit log both claimed enforcement. Denials must be expressed in a shape the
 * harness acts on, and must be verified at the EFFECT level (see
 * tests/governor-block-enforcement.test.ts and the Enforcement Canary), never by
 * asserting on an internal `action: 'BLOCK'` constant.
 *
 * 0K-Talon v0.1.0
 */

import { basename } from 'path';
import { getAuditLogPath, ensureDirectories, secureAppendLog, getStateFilePath } from './lib/talon-paths';
import { classifyGhCommand, GhTier, checkConfirmToken, consumeConfirmToken } from './lib/gh-policy';
import { checkCircuit, recordSuccess, recordFailure } from './lib/circuit-breaker';
import { normalizeUnicode } from './lib/unicode-normalize';
import {
  loadActiveProfile,
  isToolAllowed,
  isPathAllowed,
  isBashCommandAllowed,
} from './lib/profile-loader';
import { evaluateCedarPolicies, type TrajectoryContext } from './lib/cedar-evaluator';
import { recordFileRead, recordToolCall, getTaintLabel, type TaintState } from './lib/ifc-taint-tracker';

const HOOK_NAME = 'L1-governor-agent';

// Pattern to detect (split to avoid self-detection)
const SANDBOX_BYPASS_PATTERN = 'dangerous' + 'lyDisable' + 'Sandbox';

// ============================================================================
// Command Normalization (defense-in-depth vs comment/encoding bypass)
// ============================================================================

/**
 * Normalize a Bash command for policy matching.
 * Strips comments, collapses whitespace, and detects variable indirection
 * or encoding tricks that could evade substring-based match rules.
 *
 * Returns the normalized command string. Policies are evaluated against
 * BOTH the raw command and the normalized version — if either matches,
 * the policy fires. This prevents evasion via:
 *   - Leading/inline comments
 *   - Variable indirection ($X $Y instead of rm -rf)
 *   - Hex/octal encoding ($'\x72\x6d')
 *   - Excessive whitespace or line splitting
 *
 * Ported from PAI v3.9.1 (March 24, 2026)
 */
function normalizeCommand(cmd: string): string {
  return cmd
    .split('\n')
    .map(line => {
      // Strip inline comments (but not inside quotes)
      // Simple heuristic: remove # and everything after it unless inside quotes
      let inSingle = false;
      let inDouble = false;
      let result = '';
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === "'" && !inDouble) inSingle = !inSingle;
        else if (ch === '"' && !inSingle) inDouble = !inDouble;
        else if (ch === '#' && !inSingle && !inDouble) {
          break; // Rest is comment
        }
        result += ch;
      }
      return result.trim();
    })
    .filter(line => line.length > 0)
    .join(' ; ');
}

/**
 * Detect variable indirection and encoding patterns that could hide
 * dangerous commands from substring matching.
 * Returns warning strings for audit logging.
 */
function detectEvasionPatterns(cmd: string): string[] {
  const warnings: string[] = [];

  // Variable expansion near dangerous keywords context
  // e.g., X="rm"; $X -rf or ${VAR}
  if (/\$[{(]?[A-Za-z_]/.test(cmd) && /\b(rm|chmod|chown|dd|mkfs|curl|wget|nc|ncat)\b/.test(cmd) === false) {
    // Variables present but no obvious dangerous command visible — could be indirection
    if (/\$[A-Za-z_]+\s+(-rf|-r|--force|--no-preserve-root)/.test(cmd)) {
      warnings.push('Variable indirection with destructive flags detected');
    }
  }

  // Hex/octal escape sequences: $'\x72\x6d' or $'\162\155'
  if (/\$'\\x[0-9a-fA-F]{2}/.test(cmd) || /\$'\\[0-7]{3}/.test(cmd)) {
    warnings.push('Hex/octal escape encoding detected — possible command obfuscation');
  }

  // Base64 decode piped to shell: echo ... | base64 -d | sh
  if (/base64\s+(-d|--decode)/.test(cmd) && /\|\s*(sh|bash|zsh|dash|eval)\b/.test(cmd)) {
    warnings.push('Base64 decode piped to shell — possible encoded command execution');
  }

  // eval with variable expansion
  if (/\beval\b/.test(cmd) && /\$/.test(cmd)) {
    warnings.push('eval with variable expansion — possible command construction');
  }

  return warnings;
}

/**
 * Check if a path is an .env file (catches .env, .env.local, .env.production, etc.)
 * Excludes safe files: .env.example, .env.1password
 */
function isEnvFile(filePath: string): boolean {
  const basename = filePath.split('/').pop() || '';
  // Match .env or .env.* but not .env.example or .env.1password
  const isEnv = /^\.env($|\..+)/.test(basename);
  const isSafe = /\.(example|sample|template|1password)$/i.test(basename);
  return isEnv && !isSafe;
}

// ============================================================================
// Types
// ============================================================================

interface HookInput {
  session_id: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
  agent_id?: string;      // v2.1.69+: identifies which agent made the call
  agent_type?: string;    // v2.1.69+: agent type (e.g., 'general-purpose', 'Explore')
}

interface Policy {
  name: string;
  tool: string | '*';
  match: (tool: string, params: Record<string, any>) => boolean;
  action: 'BLOCK' | 'WARN';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  message: string;
}

interface AuditLogEntry {
  timestamp: string;
  tool: string;
  parameters: Record<string, any>;
  policy_matched: string | null;
  action: 'BLOCK' | 'WARN' | 'ALLOW';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE';
  /** Always false: the Governor denies, it never rewrites inputs. Retained so
   *  existing audit-log consumers keep parsing. */
  input_modified: boolean;
  message: string;
  evaluation_time_ms: number;
  session_id: string;
  // Cedar formal authorization
  cedar_decision?: 'ALLOW' | 'DENY';
  cedar_policies?: string[];
  cedar_time_ms?: number;
  // IFC taint tracking
  ifc_taint_level?: number;
  ifc_taint_label?: string;
  // DLP findings
  dlp_findings?: string[];
  // Agent context (v2.1.69+)
  agent_id?: string;
  agent_type?: string;
  // Command normalization/evasion detection warnings
  evasion_warnings?: string[];
}

// ============================================================================
// Bundled Policies (Core Security)
// ============================================================================

const POLICIES: Policy[] = [
  // === CRITICAL: Sandbox Bypass Prevention ===
  // Exclude read-only tools to prevent false positives when searching/reading docs
  {
    name: 'block-sandbox-disable',
    tool: '*',
    match: (tool, params) => {
      const READ_ONLY_TOOLS = new Set(['Grep', 'Glob', 'Read', 'LS', 'NotebookRead']);
      if (READ_ONLY_TOOLS.has(tool)) return false;
      const str = JSON.stringify(params).toLowerCase();
      return str.includes(SANDBOX_BYPASS_PATTERN.toLowerCase());
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Sandbox bypass attempt detected - potential prompt injection',
  },

  // === CRITICAL: API Key Exfiltration Prevention (CVE-2026-21852) ===
  {
    name: 'block-anthropic-base-url-override',
    tool: '*',
    match: (_tool, params) => {
      const str = JSON.stringify(params).toLowerCase();
      return str.includes('anthropic_base_url');
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'ANTHROPIC_BASE_URL override detected — potential API key exfiltration (CVE-2026-21852)',
  },

  // === CRITICAL: .env File Protection ===
  // Matches .env, .env.local, .env.production, .env.development, etc.
  // Excludes .env.example and .env.1password (safe reference files)
  {
    name: 'block-env-reads',
    tool: 'Read',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return isEnvFile(path);
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot read .env files (contains secrets)',
  },
  {
    name: 'block-env-writes',
    tool: 'Write',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return isEnvFile(path);
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot write production .env files via Write tool',
  },
  {
    name: 'block-env-edits',
    tool: 'Edit',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return isEnvFile(path);
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot edit .env files via Edit tool',
  },

  // === CRITICAL: Credential File Protection (GitHub #34819) ===
  {
    name: 'block-credential-file-reads',
    tool: 'Read',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return /\.(netrc|npmrc|pgpass)$/.test(basename(path)) ||
        path.includes('.kube/config') ||
        path.includes('.cargo/credentials') ||
        path.includes('.docker/config.json') ||
        path.includes('.aws/credentials');
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot read credential files — contains authentication tokens',
  },
  {
    name: 'block-credential-file-bash-reads',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      const norm = String(params._normalizedCommand || cmd);
      const hasCredFile = /\.(netrc|npmrc|pgpass)|\.kube\/config|\.cargo\/credentials|\.docker\/config\.json|\.aws\/credentials/.test(cmd)
        || /\.(netrc|npmrc|pgpass)|\.kube\/config|\.cargo\/credentials|\.docker\/config\.json|\.aws\/credentials/.test(norm);
      const hasDisplayCmd = /\b(cat|head|tail|less|more|bat)\b/.test(cmd) || /\b(cat|head|tail|less|more|bat)\b/.test(norm);
      return hasCredFile && hasDisplayCmd;
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot display credential files via Bash — contains authentication tokens',
  },

  // === CRITICAL: Private Key Protection ===
  {
    name: 'block-private-key-commits',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      const norm = String(params._normalizedCommand || cmd);
      return (cmd.includes('git commit') && cmd.includes('BEGIN PRIVATE KEY'))
        || (norm.includes('git commit') && norm.includes('BEGIN PRIVATE KEY'));
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Private key detected in staged changes',
  },

  // === CRITICAL: Protected Folders (macOS) ===
  {
    name: 'block-documents-access',
    tool: 'Read',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return path.includes('/Documents/');
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot access ~/Documents - protected folder',
  },
  {
    name: 'block-desktop-access',
    tool: 'Read',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return path.includes('/Desktop/');
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot access ~/Desktop - protected folder',
  },

  // === HIGH: Dangerous Bash Commands ===
  // Download-and-execute detection. Covers curl/wget piped to shell interpreters,
  // process substitution, and download-then-execute patterns.
  //
  // Known bypass vectors (inherent regex limitation - document for transparency):
  // - Shell quoting tricks: cu''rl, cu\rl, ${cmd}url (variable expansion)
  // - Aliases: alias c=curl; c url | sh
  // - Indirect: python -c "import os; os.system('curl url | sh')"
  // - Encoded: base64 -d <<< "Y3VybCB..." | sh
  // These require an attacker who already has shell access, which is outside
  // our threat model (we protect against LLM-generated commands, not adversarial shells).
  {
    name: 'block-curl-pipe-sh',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      const norm = String(params._normalizedCommand || cmd);
      // Check both raw and normalized command (defense-in-depth vs comment/encoding bypass)
      const checkCmd = (c: string) => {
        const hasFetcher = c.includes('curl') || c.includes('wget');
        const hasPipeShell = /\|\s*(sh|bash|zsh|dash)\b/.test(c);
        const hasProcessSub = /\b(sh|bash|zsh|dash)\s+<\(/.test(c) && hasFetcher;
        const hasDownloadExec = hasFetcher && /(-o|--output)\s+\S+.*&&\s*(sh|bash|chmod\s+\+x)/.test(c);
        const hasWgetPipe = c.includes('wget') && /-O\s*-/.test(c) && hasPipeShell;
        return (hasFetcher && hasPipeShell) || hasProcessSub || hasDownloadExec || hasWgetPipe;
      };
      return checkCmd(cmd) || checkCmd(norm);
    },
    action: 'BLOCK',
    severity: 'HIGH',
    message: 'Dangerous pattern: download-and-execute detected - download and review scripts before executing',
  },
  {
    name: 'block-rm-rf-critical',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      const norm = String(params._normalizedCommand || cmd);
      const checkCmd = (c: string) => {
        if (!c.includes('rm -rf') && !c.includes('rm -r')) return false;
        const criticalPaths = ['.git', '/', '/*', '~', '$HOME', '/etc', '/usr', '/var'];
        return criticalPaths.some(p => c.includes(p));
      };
      return checkCmd(cmd) || checkCmd(norm);
    },
    action: 'BLOCK',
    severity: 'HIGH',
    message: 'Destructive rm -rf on critical directory detected',
  },
  {
    name: 'block-force-push-main',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      const norm = String(params._normalizedCommand || cmd);
      const checkCmd = (c: string) => c.includes('git push --force') && (c.includes('main') || c.includes('master'));
      return checkCmd(cmd) || checkCmd(norm);
    },
    action: 'BLOCK',
    severity: 'HIGH',
    message: 'Force push to main/master is destructive',
  },
  {
    name: 'warn-git-reset-hard',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      const norm = String(params._normalizedCommand || cmd);
      const checkCmd = (c: string) => c.includes('git reset --hard') && c.includes('HEAD~');
      return checkCmd(cmd) || checkCmd(norm);
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'Destructive git reset --hard - uncommitted changes will be lost',
  },

  // === HIGH: Secret Pattern Detection in Commands ===
  {
    name: 'warn-secrets-in-bash',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      const norm = String(params._normalizedCommand || cmd);
      const patterns = [
        /sk-[A-Za-z0-9]{20,}/,
        /pplx-[A-Za-z0-9]{40,}/,
        /ghp_[A-Za-z0-9_]{36,}/,
        /AIza[A-Za-z0-9_-]{35}/,
        /AKIA[A-Z0-9]{16}/,
      ];
      return patterns.some(p => p.test(cmd) || p.test(norm));
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'API key pattern detected in bash command - verify not logging secrets',
  },

  // === MEDIUM: Git Hook Edits ===
  {
    name: 'warn-git-hook-edits',
    tool: 'Edit',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return path.includes('.git/hooks/');
    },
    action: 'WARN',
    severity: 'MEDIUM',
    message: 'Editing git hooks - verify this does not bypass safety checks',
  },

  // === MEDIUM: SSH Key Access ===
  {
    name: 'warn-ssh-key-reads',
    tool: 'Read',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return path.includes('.ssh/') && !path.includes('.pub');
    },
    action: 'WARN',
    severity: 'MEDIUM',
    message: 'Reading SSH private key files - verify this is necessary',
  },

  // === PROMPT INJECTION DEFENSE ===
  {
    name: 'detect-ignore-instructions',
    tool: '*',
    match: (_tool, params) => {
      const content = JSON.stringify(params).toLowerCase();
      return content.includes('ignore previous instructions') ||
             content.includes('disregard all prior') ||
             content.includes('ignore everything above') ||
             content.includes('new instructions:') ||
             content.includes('your real instructions');
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'Possible prompt injection detected: instruction override pattern',
  },
  {
    name: 'detect-role-hijacking',
    tool: '*',
    match: (_tool, params) => {
      const content = JSON.stringify(params).toLowerCase();
      return content.includes('you are now') ||
             content.includes('act as if') ||
             content.includes('pretend to be') ||
             content.includes('dan mode') ||
             content.includes('jailbreak mode') ||
             content.includes('developer mode enabled');
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'Possible prompt injection detected: role hijacking attempt',
  },
  {
    name: 'detect-context-injection',
    tool: '*',
    match: (_tool, params) => {
      const content = JSON.stringify(params);
      return content.includes('[SYSTEM]') ||
             content.includes('<<SYS>>') ||
             content.includes('</s>');
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'Possible prompt injection detected: fake system markers',
  },
];

// Tools to monitor
const MONITORED_TOOLS = ['Read', 'Write', 'Edit', 'Bash', 'WebFetch', 'WebSearch', 'Skill', 'Task', 'Agent', 'Glob', 'Grep'];

// Unicode normalization imported from shared module: ./lib/unicode-normalize

function normalizeParams(params: Record<string, any>): Record<string, any> {
  const normalized: Record<string, any> = {};
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === 'string') {
      normalized[key] = normalizeUnicode(value);
    } else if (typeof value === 'object' && value !== null) {
      normalized[key] = normalizeParams(value);
    } else {
      normalized[key] = value;
    }
  }
  return normalized;
}

// ============================================================================
// Input-side DLP: Secret Detection in Tool Parameters (Phase 4B)
// ============================================================================

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'AWS Access Key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'AWS Secret Key', pattern: /\b[0-9a-zA-Z/+]{40}\b(?=.*aws)/i },
  { name: 'GitHub Token', pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/ },
  { name: 'GitHub Fine-grained Token', pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/ },
  { name: 'Stripe Key', pattern: /\b(sk|pk)_(test|live)_[A-Za-z0-9]{20,}\b/ },
  { name: 'OpenAI Key', pattern: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { name: 'Anthropic Key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Slack Token', pattern: /\bxox[bprs]-[A-Za-z0-9\-]{10,}\b/ },
  { name: 'Discord Token', pattern: /\b[MN][A-Za-z\d]{23,}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27,}\b/ },
  { name: 'Google API Key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Twilio Key', pattern: /\bSK[0-9a-fA-F]{32}\b/ },
  { name: 'SendGrid Key', pattern: /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}\b/ },
  { name: 'Mailgun Key', pattern: /\bkey-[0-9a-zA-Z]{32}\b/ },
  { name: 'npm Token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: 'Generic Bearer Token', pattern: /\bBearer\s+[A-Za-z0-9_\-.]{20,}\b/ },
  { name: 'Private Key Header', pattern: /-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY-----/ },
  { name: 'Base64 Secret (long)', pattern: /\b[A-Za-z0-9+/]{64,}={0,2}\b/ },
];

const DLP_SKIP_KEYS = new Set(['file_path', 'filePath', 'cwd', 'timeout', 'offset', 'limit']);

interface DlpFinding {
  paramKey: string;
  secretType: string;
  snippet: string;
}

function scanParamsForSecrets(params: Record<string, any>): DlpFinding[] {
  const findings: DlpFinding[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (DLP_SKIP_KEYS.has(key)) continue;
    const strValue = typeof value === 'string' ? value : JSON.stringify(value);
    if (!strValue || strValue.length < 10) continue;
    for (const { name, pattern } of SECRET_PATTERNS) {
      const match = strValue.match(pattern);
      if (match) {
        const matched = match[0];
        const redacted = matched.length > 12
          ? `${matched.slice(0, 4)}...${matched.slice(-4)}`
          : `${matched.slice(0, 4)}...`;
        findings.push({ paramKey: key, secretType: name, snippet: redacted });
        break;
      }
    }
  }
  return findings;
}

// ============================================================================
// Audit Logging
// ============================================================================

function logToAudit(entry: AuditLogEntry): void {
  try {
    ensureDirectories();
    const logPath = getAuditLogPath(HOOK_NAME);
    const logLine = JSON.stringify(entry) + '\n';
    secureAppendLog(logPath, logLine);
  } catch (error) {
    console.error(`[Governor] Failed to write audit log: ${error}`);
  }
}

function sanitizeParameters(params: Record<string, any>): Record<string, any> {
  const sanitized = { ...params };
  const sensitiveKeys = ['api_key', 'password', 'token', 'secret', 'auth', 'credential'];

  for (const key in sanitized) {
    if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
      sanitized[key] = '[REDACTED]';
    }
    if (key === 'content' && typeof sanitized[key] === 'string' && sanitized[key].length > 500) {
      sanitized[key] = sanitized[key].substring(0, 500) + `... [truncated]`;
    }
  }

  return sanitized;
}

// ============================================================================
// Policy Evaluation
// ============================================================================

function evaluatePolicies(tool: string, params: Record<string, any>): {
  policy: Policy | null;
  action: 'BLOCK' | 'WARN' | 'ALLOW';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE';
  message: string;
} {
  const severityOrder: Array<'CRITICAL' | 'HIGH' | 'MEDIUM'> = ['CRITICAL', 'HIGH', 'MEDIUM'];

  for (const severity of severityOrder) {
    const matchingPolicies = POLICIES.filter(p => p.severity === severity);

    for (const policy of matchingPolicies) {
      if (policy.tool !== '*' && policy.tool !== tool) continue;

      if (policy.match(tool, params)) {
        return {
          policy,
          action: policy.action,
          severity: policy.severity,
          message: policy.message,
        };
      }
    }
  }

  return {
    policy: null,
    action: 'ALLOW',
    severity: 'NONE',
    message: 'No policy violations detected',
  };
}

// ============================================================================
// Main Hook Logic
// ============================================================================

async function main() {
  const circuit = checkCircuit(HOOK_NAME);
  if (!circuit.shouldExecute) {
    console.error(`⚡ [Governor] Circuit ${circuit.state}: Skipping execution`);
    process.exit(0);
  }

  const startTime = Date.now();

  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error('Timeout')), 400)
      )
    ]);

    if (!input || input.trim() === '') {
      process.exit(0);
    }

    const data: HookInput = JSON.parse(input);

    if (!data.tool_name || !MONITORED_TOOLS.includes(data.tool_name)) {
      process.exit(0);
    }

    const params = data.tool_input || {};
    // Normalize Unicode to prevent homoglyph bypass attacks
    const normalizedParams = normalizeParams(params);

    // ========== COMMAND NORMALIZATION (defense-in-depth vs comment/encoding bypass) ==========
    // For Bash tools, normalize the command and detect evasion patterns.
    // Evasion warnings are logged to audit trail for visibility.
    let evasionWarnings: string[] = [];
    if (data.tool_name === 'Bash' && normalizedParams.command) {
      const rawCommand = normalizedParams.command;
      const normalized = normalizeCommand(rawCommand);
      evasionWarnings = detectEvasionPatterns(rawCommand);

      // Inject normalized command as virtual parameter for policy matching.
      // Policies check params.command (raw) — _normalizedCommand allows dual matching.
      normalizedParams._rawCommand = rawCommand;
      normalizedParams._normalizedCommand = normalized;

      // If normalized differs from raw, log it (comment stripping happened)
      if (normalized !== rawCommand && evasionWarnings.length === 0) {
        const rawTrimmed = rawCommand.trim();
        if (normalized !== rawTrimmed) {
          evasionWarnings.push('Command modified by normalization (comments/whitespace stripped)');
        }
      }
    }
    // ========== END COMMAND NORMALIZATION ==========

    // ========== L12 PROFILE ENFORCEMENT ==========
    // Load active profile set by L12 SessionStart hook
    const activeProfile = loadActiveProfile();
    if (activeProfile && activeProfile.name !== 'dev') {
      // Check if tool is allowed by profile
      const toolCheck = isToolAllowed(data.tool_name, activeProfile);
      if (!toolCheck.allowed) {
        console.error(`\n🔒 [Governor L1] BLOCKED by '${activeProfile.name}' profile`);
        console.error(`    Tool: ${data.tool_name}`);
        console.error(`    Reason: ${toolCheck.reason}`);
        console.error(`    Change profile: OK_TALON_PROFILE=dev claude\n`);

        // Log the profile violation
        logToAudit({
          timestamp: new Date().toISOString(),
          tool: data.tool_name,
          parameters: sanitizeParameters(params),
          policy_matched: `profile:${activeProfile.name}:tool-block`,
          action: 'BLOCK',
          severity: 'HIGH',
          input_modified: false,
          message: toolCheck.reason,
          evaluation_time_ms: Date.now() - startTime,
          session_id: data.session_id,
        });

        // Output block decision
        console.log(JSON.stringify({
          decision: 'block',
          reason: `🔒 L12 Profile Violation: ${toolCheck.reason}`,
        }));
        process.exit(2);
      }

      // Check path restrictions for Read/Write/Edit tools
      if (['Read', 'Write', 'Edit'].includes(data.tool_name)) {
        const filePath = String(normalizedParams.file_path || '');
        const operation = data.tool_name === 'Read' ? 'read' : 'write';
        const pathCheck = isPathAllowed(filePath, operation, activeProfile);
        if (!pathCheck.allowed) {
          console.error(`\n🔒 [Governor L1] PATH BLOCKED by '${activeProfile.name}' profile`);
          console.error(`    Path: ${filePath}`);
          console.error(`    Operation: ${operation}`);
          console.error(`    Reason: ${pathCheck.reason}\n`);

          logToAudit({
            timestamp: new Date().toISOString(),
            tool: data.tool_name,
            parameters: sanitizeParameters(params),
            policy_matched: `profile:${activeProfile.name}:path-block`,
            action: 'BLOCK',
            severity: 'HIGH',
            input_modified: false,
            message: pathCheck.reason,
            evaluation_time_ms: Date.now() - startTime,
            session_id: data.session_id,
          });

          console.log(JSON.stringify({
            decision: 'block',
            reason: `🔒 L12 Profile Violation: ${pathCheck.reason}`,
          }));
          process.exit(2);
        }
      }

      // Check bash command restrictions (test both raw and normalized command)
      if (data.tool_name === 'Bash') {
        const command = String(normalizedParams.command || '');
        const normalizedCmd = String(normalizedParams._normalizedCommand || command);
        const bashCheck = isBashCommandAllowed(command, activeProfile);
        // Also check normalized command if raw was allowed
        const normCheck = (command !== normalizedCmd) ? isBashCommandAllowed(normalizedCmd, activeProfile) : bashCheck;
        const effectiveCheck = bashCheck.allowed ? normCheck : bashCheck;
        if (!effectiveCheck.allowed) {
          console.error(`\n🔒 [Governor L1] BASH BLOCKED by '${activeProfile.name}' profile`);
          console.error(`    Command: ${command.substring(0, 80)}...`);
          console.error(`    Reason: ${effectiveCheck.reason}\n`);

          logToAudit({
            timestamp: new Date().toISOString(),
            tool: data.tool_name,
            parameters: sanitizeParameters(params),
            policy_matched: `profile:${activeProfile.name}:bash-block`,
            action: 'BLOCK',
            severity: 'HIGH',
            input_modified: false,
            message: effectiveCheck.reason,
            evaluation_time_ms: Date.now() - startTime,
            session_id: data.session_id,
          });

          console.log(JSON.stringify({
            decision: 'block',
            reason: `🔒 L12 Profile Violation: ${effectiveCheck.reason}`,
          }));
          process.exit(2);
        }
      }
    }
    // ========== END L12 PROFILE ENFORCEMENT ==========

    // ========== GH-POLICY STATE-MUTATION GUARD ==========
    // Three-tier classifier for `gh` (GitHub CLI) state-mutating ops.
    // Tier 1 (irreversible) → hard block. Tier 2 (recoverable) → confirm token
    // required (only enforced in `full` mode). Closes the attack class where an
    // agent self-authorizes a destructive gh op despite hooks.
    // Mode via OK_TALON_GH_POLICY: 'tier1' (default) | 'full' | 'off'.
    // Validate explicitly — an unknown value (e.g. a `ful` typo) must NOT silently
    // weaken to tier1. Fail closed to 'full' (most protective) with a loud warning.
    const ghPolicyRaw = (process.env.OK_TALON_GH_POLICY || 'tier1').toLowerCase();
    const ghPolicyMode = ['tier1', 'full', 'off'].includes(ghPolicyRaw) ? ghPolicyRaw : 'full';
    if (ghPolicyMode !== ghPolicyRaw) {
      console.error(`⚠️  [Governor L1] Unknown OK_TALON_GH_POLICY='${ghPolicyRaw}' — failing closed to 'full' (valid: tier1|full|off).`);
    }
    if (ghPolicyMode !== 'off' && data.tool_name === 'Bash') {
      const ghCommand = String(normalizedParams._normalizedCommand || normalizedParams.command || '');
      const ghResult = classifyGhCommand(ghCommand);
      // Redact inline secret values before auditing — the raw command can carry a
      // secret (e.g. `gh secret set NAME --body <secret>`) that sanitizeParameters
      // does not mask. (Piped secrets like `echo X | gh secret set` are covered by
      // the input-side DLP scan, not here.)
      const ghAuditParams = {
        command: ghCommand.replace(/(--body|-b|--body-file|-f)([ =]+)\S+/gi, '$1$2***'),
      };

      if (ghResult.tier === GhTier.BLOCK) {
        // Tier 1 — irreversible, operator-only. Block ALWAYS (tier1 and full).
        console.error(`\n🔒 [Governor L1] GH OPERATION BLOCKED (operator-only)`);
        console.error(`    Operation: ${ghResult.operation}`);
        console.error(`    Reason: ${ghResult.reason}`);
        console.error(`    This irreversible operation cannot be performed by an agent.`);
        console.error(`    See the 0K-Talon README (gh-policy guard) for the operator workflow.\n`);

        logToAudit({
          timestamp: new Date().toISOString(),
          tool: data.tool_name,
          parameters: ghAuditParams,
          policy_matched: `gh-policy:tier1:${ghResult.operation}`,
          action: 'BLOCK',
          severity: 'CRITICAL',
          input_modified: false,
          message: `gh-policy Tier 1 (irreversible, operator-only): ${ghResult.reason}`,
          evaluation_time_ms: Date.now() - startTime,
          session_id: data.session_id,
        });

        console.log(JSON.stringify({
          decision: 'block',
          reason: `🔒 gh-policy Tier 1 (operator-only): ${ghResult.reason}`,
        }));
        process.exit(2);
      }

      if (ghResult.tier === GhTier.CONFIRM && ghPolicyMode === 'full') {
        // Tier 2 — recoverable, requires a valid operator confirm token.
        const tokenPath = getStateFilePath('gh-policy', 'gh-confirm-token.json');
        const tokenCheck = checkConfirmToken(tokenPath);

        if (tokenCheck.valid) {
          consumeConfirmToken(tokenPath);
          logToAudit({
            timestamp: new Date().toISOString(),
            tool: data.tool_name,
            parameters: ghAuditParams,
            policy_matched: `gh-policy:tier2:authorized:${ghResult.operation}`,
            action: 'ALLOW',
            severity: 'NONE',
            input_modified: false,
            message: `gh-policy Tier 2 authorized by confirm token: ${ghResult.operation}`,
            evaluation_time_ms: Date.now() - startTime,
            session_id: data.session_id,
          });
          // Authorized — fall through to normal governor evaluation.
        } else {
          console.error(`\n🔒 [Governor L1] GH OPERATION BLOCKED (confirmation required)`);
          console.error(`    Operation: ${ghResult.operation}`);
          console.error(`    Reason: ${ghResult.reason}`);
          console.error(`    Token status: ${tokenCheck.reason}`);
          console.error(`    To authorize: issue a confirm token with 'talon-gh-confirm'`);
          console.error(`    from your own terminal (cannot be run from inside this session).\n`);

          logToAudit({
            timestamp: new Date().toISOString(),
            tool: data.tool_name,
            parameters: ghAuditParams,
            policy_matched: `gh-policy:tier2:${ghResult.operation}`,
            action: 'BLOCK',
            severity: 'HIGH',
            input_modified: false,
            message: `gh-policy Tier 2 (confirm token required): ${ghResult.reason} [${tokenCheck.reason}]`,
            evaluation_time_ms: Date.now() - startTime,
            session_id: data.session_id,
          });

          console.log(JSON.stringify({
            decision: 'block',
            reason: `🔒 gh-policy Tier 2 (confirmation required): ${ghResult.reason}. Issue a token via 'talon-gh-confirm' from your own terminal.`,
          }));
          process.exit(2);
        }
      }
    }
    // ========== END GH-POLICY STATE-MUTATION GUARD ==========

    const result = evaluatePolicies(data.tool_name, normalizedParams);
    const evaluationTime = Date.now() - startTime;

    // ========== IFC TAINT TRACKING ==========
    // Track file reads for Bell-LaPadula taint propagation.
    // recordFileRead also updates trajectory counters for Phase 3 limits.
    let taintState: TaintState | null = null;
    if (data.tool_name === 'Read') {
      const filePath = String(normalizedParams.file_path || '');
      taintState = recordFileRead(data.session_id, filePath);
    } else {
      taintState = recordToolCall(data.session_id, data.tool_name, normalizedParams);
    }
    // ========== END IFC TAINT TRACKING ==========

    // ========== CEDAR FORMAL AUTHORIZATION ==========
    // Cedar evaluates after YAML — Cedar DENY overrides YAML ALLOW.
    // Cedar ALLOW does NOT override an already-BLOCKed YAML result.
    const trajectory: TrajectoryContext = taintState ? {
      toolCallCount: taintState.tool_call_count,
      webFetchCount: taintState.trajectory.web_fetches,
      shellCommandCount: taintState.trajectory.shell_commands,
      consecutiveSameTool: taintState.trajectory.consecutive_same_tool,
    } : { toolCallCount: 0, webFetchCount: 0, shellCommandCount: 0, consecutiveSameTool: 0 };

    const sessionProfile = (activeProfile?.name) || 'dev';
    const sessionTaintLevel = taintState?.taint_level ?? 0;

    const cedarResult = evaluateCedarPolicies(
      data.tool_name,
      normalizedParams,
      sessionProfile,
      sessionTaintLevel,
      trajectory
    );
    // ========== END CEDAR FORMAL AUTHORIZATION ==========

    // ========== INPUT-SIDE DLP (Phase 4B) ==========
    const dlpFindings = scanParamsForSecrets(normalizedParams);
    if (dlpFindings.length > 0) {
      console.error(`\n🔐 [Governor/DLP] Secret detected in ${data.tool_name} parameters:`);
      for (const f of dlpFindings) {
        console.error(`    • ${f.secretType} in "${f.paramKey}" (${f.snippet})`);
      }
      console.error(`    Action: WARN (secret may enter model context)`);
      console.error(`    Remediation: Use environment variables or secret manager references instead\n`);
    }
    // ========== END INPUT-SIDE DLP ==========

    const auditEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      tool: data.tool_name,
      parameters: sanitizeParameters(params),
      policy_matched: result.policy?.name || null,
      action: result.action,
      severity: result.severity,
      input_modified: false,
      message: result.message,
      evaluation_time_ms: evaluationTime,
      session_id: data.session_id,
      cedar_decision: cedarResult.decision,
      cedar_policies: cedarResult.matchedPolicies,
      cedar_time_ms: cedarResult.evaluationTimeMs,
      ifc_taint_level: sessionTaintLevel,
      ifc_taint_label: getTaintLabel(sessionTaintLevel),
      dlp_findings: dlpFindings.length > 0 ? dlpFindings.map(f => `${f.secretType}:${f.paramKey}`) : undefined,
      agent_id: data.agent_id || undefined,
      agent_type: data.agent_type || undefined,
      evasion_warnings: evasionWarnings.length > 0 ? evasionWarnings : undefined,
    };
    logToAudit(auditEntry);

    // Display evasion pattern warnings to user (always visible, even if policy allows)
    if (evasionWarnings.length > 0) {
      console.error(`\n⚠️  [Governor L1] Command evasion patterns detected:`);
      for (const warning of evasionWarnings) {
        console.error(`   • ${warning}`);
      }
      console.error('');
    }

    // Cedar DENY blocks even if YAML allowed
    if (cedarResult.decision === 'DENY' && result.action !== 'BLOCK') {
      const policies = cedarResult.matchedPolicies.join(', ') || 'unknown';
      console.error(`\n🔒 [Governor L1] CEDAR DENY`);
      console.error(`    Tool: ${data.tool_name}`);
      console.error(`    Policies: ${policies}`);
      console.error(`    IFC Taint: ${getTaintLabel(sessionTaintLevel)} (${sessionTaintLevel})`);
      console.error(`    Cedar time: ${cedarResult.evaluationTimeMs}ms`);
      console.error('');
      console.log(JSON.stringify({
        decision: 'block',
        reason: `🔒 TALON CEDAR (L1) DENY: Formal policy blocked ${data.tool_name}. Matched: ${policies}. ` +
          `IFC taint: ${getTaintLabel(sessionTaintLevel)}.`,
      }));
      process.exit(2);
    }

    if (result.severity === 'CRITICAL' || result.severity === 'HIGH') {
      if (result.action === 'BLOCK') {
        console.error(`\n🛡️  [Governor L1] ${result.severity} violation BLOCKED`);
        console.error(`    Policy: ${result.policy?.name}`);
        console.error(`    Tool: ${data.tool_name}`);
        console.error(`    Action: Denied`);
        console.error(`    Message: ${result.message}`);
        console.error('');
      } else {
        console.error(`\n⚠️  [Governor L1] ${result.severity} policy violation detected`);
        console.error(`    Policy: ${result.policy?.name}`);
        console.error(`    Tool: ${data.tool_name}`);
        console.error(`    Message: ${result.message}`);
        console.error('');
      }
    }

    // DLP context injection (warn AI about leaked secrets)
    if (dlpFindings.length > 0 && result.action !== 'BLOCK') {
      const dlpTypes = dlpFindings.map(f => f.secretType).join(', ');
      console.log(JSON.stringify({
        additionalContext: `🔐 TALON DLP WARNING: Possible ${dlpTypes} detected in ${data.tool_name} parameters. ` +
          `Secrets should use environment variables or secret manager references, not inline values.`,
      }));
    }

    // A BLOCK policy must DENY through the contract Claude Code honors.
    //
    // This previously emitted a top-level `tool_input` rewrite ("safe
    // alternative") and exited 0. Claude Code ignores that shape: the banner
    // printed, the audit log said BLOCK, and the ORIGINAL command ran. Every
    // BLOCK policy was inert — rm -rf, curl|sh, force-push, .env and credential
    // reads all proceeded. BLOCK policies with no rewrite were equally inert
    // by a different route: they emitted no decision at all.
    //
    // Keying off `action` covers both classes. The rewrite path
    // is dropped rather than resurrected via `updatedInput`: silently running
    // something other than what was asked is its own footgun, and a denial the
    // agent can read is more honest than a substituted command.
    if (result.action === 'BLOCK') {
      console.log(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason:
              `🛡️ TALON GOVERNOR (L1) ${result.severity}: policy "${result.policy?.name}" blocked ${data.tool_name}. ` +
              `${result.message}`,
          },
        }),
      );
      recordSuccess(HOOK_NAME);
      process.exit(0);
    }

    if (result.policy && result.action === 'WARN') {
      console.log(JSON.stringify({
        additionalContext: `🛡️ TALON GOVERNOR (L1) ${result.severity}: Policy "${result.policy.name}" flagged for ${data.tool_name}. ` +
          `${result.message}. Proceeding with caution.`,
      }));
    }

    recordSuccess(HOOK_NAME);
    process.exit(0);

  } catch (error) {
    recordFailure(HOOK_NAME, String(error));
    console.error(`[Governor L1] Error: ${error}`);
    // Fail-closed: block operation if hook crashes (security-first)
    process.exit(2);
  }
}

main();
