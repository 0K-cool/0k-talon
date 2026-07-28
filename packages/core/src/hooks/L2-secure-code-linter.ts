#!/usr/bin/env bun

/**
 * L2 Secure Code Linter - PostToolUse Hook
 *
 * Purpose: Analyze code AFTER Write/Edit operations for security issues
 * Pattern: Sidecar Pattern (post-execution monitoring)
 * Action: ALERT (cannot block - content already in context)
 * OWASP: LLM02 (Sensitive Information Disclosure)
 *
 * Provides behavioral defense - alerts the model to security issues
 * so it can self-correct or warn the user.
 *
 * 0K-Talon v0.1.0
 */

import { extname, basename } from 'path';
import { getAuditLogPath, ensureDirectories, secureAppendLog } from './lib/talon-paths';
import { checkCircuit, recordSuccess, recordFailure } from './lib/circuit-breaker';
import { isL2SmartTier, isL2ClassifierEnabled, resolveL2Backend } from './lib/classifier';
import {
  decideRevert,
  isWarnOnlyPath,
  llmSecurityReview,
  quarantineFile,
  revertFile,
  readReviewableContent,
  type LLMVerdictLabel,
  type LLMConfidence,
  type PromptFinding,
} from './lib/l2-security-review';

const HOOK_NAME = 'L2-secure-code-linter';

// ============================================================================
// Types
// ============================================================================

interface HookInput {
  session_id: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
  tool_result?: {
    success?: boolean;
    error?: string;
    content?: string;
  };
}

interface SecurityFinding {
  rule: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
  line?: number;
  suggestion?: string;
}

interface AuditLogEntry {
  timestamp: string;
  tool: string;
  file_path: string;
  findings: SecurityFinding[];
  highest_severity: string;
  evaluation_time_ms: number;
  session_id: string;
  // Smart-tier (OK_TALON_L2_CLASSIFIER=smart) fields. All optional —
  // populated only when the LLM-review + confidence-aware revert tier runs.
  smart_tier?: boolean;
  llm_verdict?: LLMVerdictLabel;
  llm_confidence?: LLMConfidence;
  llm_failed?: boolean;
  llm_latency_ms?: number;
  reverted?: boolean;
  revert_method?: 'git' | 'delete';
  revert_reason?: string;
  quarantine_path?: string;
}

// ============================================================================
// Security Patterns
// ============================================================================

interface SecurityPattern {
  name: string;
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
  suggestion: string;
  languages: string[];
}

const SECURITY_PATTERNS: SecurityPattern[] = [
  // === CRITICAL: Hardcoded Secrets ===
  {
    name: 'hardcoded-api-key',
    pattern: /(['"`])(?:sk-[A-Za-z0-9]{20,}|pplx-[A-Za-z0-9]{40,}|ghp_[A-Za-z0-9_]{36,}|AIza[A-Za-z0-9_-]{35}|AKIA[A-Z0-9]{16})\1/,
    severity: 'CRITICAL',
    message: 'Hardcoded API key detected',
    suggestion: 'Use environment variables: process.env.API_KEY or os.getenv("API_KEY")',
    languages: ['*'],
  },
  {
    name: 'hardcoded-password',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"`][^'"`]{4,}['"`]/i,
    severity: 'CRITICAL',
    message: 'Hardcoded password detected',
    suggestion: 'Use environment variables or secure secret management',
    languages: ['*'],
  },
  {
    name: 'hardcoded-secret',
    pattern: /(?:secret|token|credential)\s*[=:]\s*['"`][A-Za-z0-9+/=]{20,}['"`]/i,
    severity: 'CRITICAL',
    message: 'Hardcoded secret/token detected',
    suggestion: 'Use environment variables or secure secret management',
    languages: ['*'],
  },

  // === CRITICAL: Injection Vulnerabilities ===
  {
    name: 'sql-injection',
    pattern: /(?:execute|query|raw)\s*\(\s*[`'"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\$\{|[`'"]\s*\+\s*\w+/i,
    severity: 'CRITICAL',
    message: 'Potential SQL injection: string concatenation in query',
    suggestion: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [userId])',
    languages: ['ts', 'js', 'py'],
  },
  {
    name: 'command-injection-shell-true',
    pattern: /subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*True/,
    severity: 'CRITICAL',
    message: 'Command injection risk: shell=True with user input',
    suggestion: 'Use subprocess with argument list: subprocess.run(["cmd", arg1, arg2])',
    languages: ['py'],
  },
  {
    name: 'command-injection-exec',
    pattern: /(?:exec|eval|execSync|spawnSync)\s*\([^)]*\$\{|(?:exec|eval)\s*\([^)]*\+/,
    severity: 'CRITICAL',
    message: 'Command injection risk: dynamic command execution',
    suggestion: 'Use spawn with argument arrays instead of exec with string interpolation',
    languages: ['ts', 'js'],
  },

  // === HIGH: Path Traversal ===
  {
    name: 'path-traversal',
    pattern: /(?:readFile|writeFile|open|join)\s*\([^)]*(?:req\.|params\.|query\.|\$\{)/,
    severity: 'HIGH',
    message: 'Potential path traversal: user input in file path',
    suggestion: 'Validate and sanitize paths: path.resolve(baseDir, path.basename(userInput))',
    languages: ['ts', 'js', 'py'],
  },

  // === HIGH: Unsafe Deserialization ===
  {
    name: 'unsafe-pickle',
    pattern: /pickle\.loads?\s*\(/,
    severity: 'HIGH',
    message: 'Unsafe deserialization: pickle can execute arbitrary code',
    suggestion: 'Use JSON or other safe serialization formats for untrusted data',
    languages: ['py'],
  },
  {
    name: 'unsafe-eval-json',
    pattern: /eval\s*\(\s*(?:JSON\.stringify|.*\.json)/i,
    severity: 'HIGH',
    message: 'Unsafe eval on JSON data',
    suggestion: 'Use JSON.parse() instead of eval() for JSON data',
    languages: ['ts', 'js'],
  },

  // === HIGH: XSS Vectors ===
  {
    name: 'xss-innerhtml',
    pattern: /\.innerHTML\s*=\s*(?!\s*['"`]\s*['"`])/,
    severity: 'HIGH',
    message: 'XSS risk: innerHTML assignment with dynamic content',
    suggestion: 'Use textContent for text, or sanitize HTML with DOMPurify',
    languages: ['ts', 'js'],
  },
  {
    name: 'xss-document-write',
    pattern: /document\.write\s*\(/,
    severity: 'HIGH',
    message: 'XSS risk: document.write can inject arbitrary HTML',
    suggestion: 'Use DOM methods like createElement/appendChild instead',
    languages: ['ts', 'js'],
  },

  // === MEDIUM: Weak Cryptography ===
  {
    name: 'weak-crypto-md5',
    pattern: /(?:createHash|hashlib\.md5|MD5|Md5)\s*\(/,
    severity: 'MEDIUM',
    message: 'Weak cryptography: MD5 is not collision-resistant',
    suggestion: 'Use SHA-256 or better for security-sensitive hashing',
    languages: ['*'],
  },
  {
    name: 'weak-crypto-sha1',
    pattern: /(?:createHash\(['"`]sha1|hashlib\.sha1|SHA1|Sha1)\s*\(/,
    severity: 'MEDIUM',
    message: 'Weak cryptography: SHA-1 is deprecated for security use',
    suggestion: 'Use SHA-256 or SHA-3 for security-sensitive hashing',
    languages: ['*'],
  },

  // === MEDIUM: Missing Validation ===
  {
    name: 'no-input-validation',
    pattern: /(?:req\.body|req\.query|req\.params)\.[a-zA-Z]+(?!\s*\?\?|\s*\|\||\.trim\(\)|\.validate)/,
    severity: 'MEDIUM',
    message: 'User input used without apparent validation',
    suggestion: 'Validate and sanitize all user input before use',
    languages: ['ts', 'js'],
  },

  // === LOW: Debugging Code ===
  {
    name: 'debug-console-log',
    pattern: /console\.log\s*\([^)]*(?:password|secret|token|key|credential)/i,
    severity: 'LOW',
    message: 'Potential secret logged to console',
    suggestion: 'Remove debug logging of sensitive data before production',
    languages: ['ts', 'js'],
  },
];

// ============================================================================
// Code Analysis
// ============================================================================

function analyzeCode(content: string, filePath: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const ext = extname(filePath).slice(1).toLowerCase();

  // Map extensions to language identifiers
  const langMap: Record<string, string> = {
    'ts': 'ts', 'tsx': 'ts', 'mts': 'ts',
    'js': 'js', 'jsx': 'js', 'mjs': 'js',
    'py': 'py', 'python': 'py',
  };
  const lang = langMap[ext] || ext;

  const lines = content.split('\n');

  for (const pattern of SECURITY_PATTERNS) {
    // Check if pattern applies to this language
    if (!pattern.languages.includes('*') && !pattern.languages.includes(lang)) {
      continue;
    }

    // Check each line for matches
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;

      // Skip comments
      if (line.trim().startsWith('//') || line.trim().startsWith('#') || line.trim().startsWith('*')) {
        continue;
      }

      if (pattern.pattern.test(line)) {
        findings.push({
          rule: pattern.name,
          severity: pattern.severity,
          message: pattern.message,
          line: i + 1,
          suggestion: pattern.suggestion,
        });
        // Only report first occurrence of each pattern
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
    // Silent fail for logging
  }
}

// ============================================================================
// Main Hook Logic
// ============================================================================

async function main() {
  const circuit = checkCircuit(HOOK_NAME);
  if (!circuit.shouldExecute) {
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

    // Only analyze Write and Edit operations
    if (!data.tool_name || !['Write', 'Edit'].includes(data.tool_name)) {
      process.exit(0);
    }

    // Only analyze code files
    const filePath = data.tool_input?.file_path || '';
    const codeExtensions = ['.ts', '.tsx', '.js', '.jsx', '.py', '.mts', '.mjs'];
    if (!codeExtensions.some(ext => filePath.endsWith(ext))) {
      process.exit(0);
    }

    // Skip if operation failed
    if (data.tool_result?.success === false) {
      process.exit(0);
    }

    // Get the content that was written
    let content = '';
    if (data.tool_name === 'Write') {
      content = data.tool_input?.content || '';
    } else if (data.tool_name === 'Edit') {
      content = data.tool_input?.new_string || '';
    }

    if (!content) {
      process.exit(0);
    }

    // Analyze for security issues
    const findings = analyzeCode(content, filePath);

    const evaluationTime = Date.now() - startTime;

    // Determine highest severity
    let highestSeverity = 'NONE';
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    for (const sev of severityOrder) {
      if (findings.some(f => f.severity === sev)) {
        highestSeverity = sev;
        break;
      }
    }

    // ========================================================================
    // SMART TIER (opt-in): LLM security review + confidence-aware revert
    //
    // Gated behind OK_TALON_L2_CLASSIFIER=smart. When off (default), the
    // entire block below is skipped: no LLM call, no revert, no quarantine —
    // L2 stays the pure static-analysis alerter it has always been.
    // ========================================================================
    const smartMode = isL2SmartTier();
    const warnOnly = isWarnOnlyPath(filePath);
    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;

    let llmVerdict: LLMVerdictLabel | null = null;
    let llmConfidence: LLMConfidence | null = null;
    let llmFailed = false;
    let llmLatencyMs = 0;

    // Run the LLM review only when: smart tier on, a usable backend exists,
    // and no static CRITICAL already triggered a Tier-1 revert (skip the
    // call — we'd revert anyway). Warn-only paths still run the review for
    // visibility, but decideRevert will keep the file regardless.
    if (smartMode && criticalCount === 0 && isL2ClassifierEnabled()) {
      const reviewContent = readReviewableContent(filePath);
      const backend = resolveL2Backend();
      if (reviewContent && backend) {
        const langMap2: Record<string, string> = {
          ts: 'typescript', tsx: 'typescript', mts: 'typescript',
          js: 'javascript', jsx: 'javascript', mjs: 'javascript',
          py: 'python',
        };
        const ext2 = extname(filePath).slice(1).toLowerCase();
        const language = langMap2[ext2] || ext2 || 'unknown';
        const promptFindings: PromptFinding[] = findings.map(f => ({
          severity: f.severity, rule: f.rule, message: f.message, line: f.line,
        }));
        const review = await llmSecurityReview({
          code: reviewContent,
          filePath,
          language,
          findings: promptFindings,
          backend,
          apiKey: process.env.ANTHROPIC_API_KEY,
        });
        llmVerdict = review.verdict?.verdict ?? null;
        llmConfidence = review.verdict?.confidence ?? null;
        llmFailed = review.failed;
        llmLatencyMs = review.latencyMs;
      }
    }

    // Pure decision: should we revert?
    const decision = decideRevert({
      smartMode,
      staticErrors: criticalCount,
      llmVerdict,
      llmConfidence,
      llmFailed,
      isWarnOnlyPath: warnOnly,
    });

    let reverted = false;
    let revertMethod: 'git' | 'delete' | undefined;
    let quarantinePath: string | undefined;
    if (decision.revert) {
      // Quarantine BEFORE reverting so the flagged code is recoverable.
      const q = quarantineFile(filePath);
      quarantinePath = q ?? undefined;
      const r = revertFile(filePath);
      reverted = r.success;
      revertMethod = r.method ?? undefined;
    }

    // Log to audit (with smart-tier fields when the tier ran)
    const auditEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      tool: data.tool_name,
      file_path: filePath,
      findings,
      highest_severity: highestSeverity,
      evaluation_time_ms: evaluationTime,
      session_id: data.session_id,
    };
    if (smartMode) {
      auditEntry.smart_tier = true;
      if (llmVerdict) auditEntry.llm_verdict = llmVerdict;
      if (llmConfidence) auditEntry.llm_confidence = llmConfidence;
      auditEntry.llm_failed = llmFailed;
      if (llmLatencyMs) auditEntry.llm_latency_ms = llmLatencyMs;
      auditEntry.reverted = reverted;
      if (revertMethod) auditEntry.revert_method = revertMethod;
      auditEntry.revert_reason = decision.reason;
      if (quarantinePath) auditEntry.quarantine_path = quarantinePath;
    }
    logToAudit(auditEntry);

    // ========================================================================
    // OUTPUT
    // ========================================================================

    // A revert is high-stakes and must NEVER be silent: surface it loudly via
    // console.error (human) AND additionalContext (model-facing). Talon has no
    // Discord/webhook by design — this is the notification.
    if (reverted) {
      console.error(`\n🔄 [Code Linter L2] FILE REVERTED — ${basename(filePath)}`);
      console.error(`   Reason: ${decision.reason}`);
      console.error(
        `   Method: ${revertMethod === 'git' ? 'git checkout (restored to last commit)' : 'deleted (new file)'}`,
      );
      if (quarantinePath) console.error(`   Quarantine: ${quarantinePath}`);
      console.error(`   Fix the issue and write again.\n`);

      console.log(JSON.stringify({
        continue: true,
        hookSpecificOutput: {
          hookEventName: 'PostToolUse',
          additionalContext:
            `⚠️ TALON L2 AUTO-REVERT: "${filePath}" was ` +
            `${revertMethod === 'delete' ? 'DELETED' : 'reverted via git'} — ${decision.reason}. ` +
            `If this is a FALSE POSITIVE (e.g. security-tool code that contains detection patterns), ` +
            `review the quarantined copy${quarantinePath ? ` at ${quarantinePath}` : ''} and re-apply, ` +
            `or add the path to WARN_ONLY_PATHS in lib/l2-security-review.ts. ` +
            `Static findings: ${findings.map(f => f.rule).join(', ') || 'none'}.`,
        },
      }));
      recordSuccess(HOOK_NAME);
      process.exit(0);
    }

    // Smart tier, file KEPT but the LLM flagged a concern (LOW-confidence
    // UNSAFE, warn-only path, or a fail in a warn-only path). Warn loudly so
    // the kept-but-flagged file isn't invisible.
    if (smartMode && (llmVerdict === 'UNSAFE' || (llmFailed && warnOnly))) {
      console.error(`\n⚠️  [Code Linter L2] LLM flagged a concern but file KEPT — ${basename(filePath)}`);
      console.error(`   ${decision.reason}`);
      console.error(`   Review manually; auto-revert was skipped.\n`);
    }

    // Static behavioral-defense alert for CRITICAL or HIGH findings.
    // (Unchanged from off-mode behavior — preserves the no-regression contract.)
    if (findings.length > 0 && (highestSeverity === 'CRITICAL' || highestSeverity === 'HIGH')) {
      console.error(`\n🔍 [Code Linter L2] Security issues detected in ${basename(filePath)}`);

      // Group by severity
      const critical = findings.filter(f => f.severity === 'CRITICAL');
      const high = findings.filter(f => f.severity === 'HIGH');

      if (critical.length > 0) {
        console.error('\n  🚨 CRITICAL:');
        for (const f of critical) {
          console.error(`     Line ${f.line || '?'}: ${f.message}`);
          console.error(`     → ${f.suggestion}`);
        }
      }

      if (high.length > 0) {
        console.error('\n  ⚠️  HIGH:');
        for (const f of high) {
          console.error(`     Line ${f.line || '?'}: ${f.message}`);
          console.error(`     → ${f.suggestion}`);
        }
      }

      console.error('\n  📋 Action: Review and fix security issues before committing.\n');

      // Output additionalContext for behavioral defense
      const context = {
        hookSpecificOutput: {
          hookEventName: 'PostToolUse',
          additionalContext: `SECURITY ALERT: ${findings.length} security issue(s) found in ${basename(filePath)}. ` +
            `${critical.length} CRITICAL, ${high.length} HIGH. ` +
            `Review and fix before proceeding. Issues: ${findings.map(f => f.rule).join(', ')}`
        },
      };
      console.log(JSON.stringify(context));
    }

    recordSuccess(HOOK_NAME);
    process.exit(0);

  } catch (error) {
    recordFailure(HOOK_NAME, String(error));
    process.exit(0);
  }
}

main();
