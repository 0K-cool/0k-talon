#!/usr/bin/env bun
/**
 * Subagent DLP Scanner (SubagentStop)
 *
 * Phase 5 of #21460 mitigation — Subagent Isolation.
 * Scans content returned by subagents for sensitive patterns before
 * it gets incorporated into the parent context.
 *
 * NON-BLOCKING — alerts only, never prevents output from returning.
 * Regex-based scanning (no LLM calls) for speed.
 *
 * Logs to: ~/.vex-talon/logs/subagent-dlp.jsonl
 *
 * Maps to:
 * - OWASP LLM02 (Sensitive Information Disclosure)
 * - OWASP Agentic ASI03 (Identity & Privilege Abuse)
 * - MITRE ATLAS AML.T0096 (AI Service API)
 *
 * @version 1.0.0 (vex-talon)
 * @date 2026-04-13
 */

import { existsSync, mkdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { LOGS_DIR, secureAppendLog } from './lib/talon-paths';

const HOOK_NAME = 'subagent-dlp-scanner';
const DLP_LOG = join(LOGS_DIR, 'subagent-dlp.jsonl');

// --- DLP Pattern Categories ---

const DLP_PATTERNS: Array<{ category: string; pattern: RegExp; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' }> = [
  // Secrets and credentials
  { category: 'aws_key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'CRITICAL' },
  { category: 'aws_secret', pattern: /(?:aws_secret|secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}/gi, severity: 'CRITICAL' },
  { category: 'github_token', pattern: /gh[ps]_[A-Za-z0-9_]{36,}/g, severity: 'CRITICAL' },
  { category: 'github_classic', pattern: /ghp_[A-Za-z0-9]{36}/g, severity: 'CRITICAL' },
  { category: 'anthropic_key', pattern: /sk-ant-[A-Za-z0-9-]{80,}/g, severity: 'CRITICAL' },
  { category: 'openai_key', pattern: /sk-[A-Za-z0-9]{48,}/g, severity: 'CRITICAL' },
  { category: 'stripe_key', pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g, severity: 'CRITICAL' },
  { category: 'private_key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: 'CRITICAL' },
  { category: 'op_reference', pattern: /op:\/\/[A-Za-z0-9/_-]+/g, severity: 'HIGH' },
  { category: 'generic_secret', pattern: /(?:password|secret|token|api_key)\s*[:=]\s*['"][^'"]{8,}['"]/gi, severity: 'HIGH' },

  // PII patterns
  { category: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'CRITICAL' },
  { category: 'email_address', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, severity: 'MEDIUM' },
  { category: 'phone_us', pattern: /\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g, severity: 'MEDIUM' },
  { category: 'credit_card', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g, severity: 'CRITICAL' },

  // Client data indicators
  { category: 'client_work_path', pattern: /output\/client-work\/[^\s'"]+/g, severity: 'HIGH' },
  { category: 'confidential_marker', pattern: /\b(?:CONFIDENTIAL|PRIVILEGED|ATTORNEY.CLIENT|HIPAA|PHI)\b/gi, severity: 'HIGH' },
];

// High-entropy string detector (catches random tokens/keys not matched by specific patterns)
function hasHighEntropyStrings(text: string): Array<{ value: string; entropy: number }> {
  const findings: Array<{ value: string; entropy: number }> = [];
  // Match strings that look like API keys: 32+ chars, alphanumeric with some special chars
  const candidates = text.match(/\b[A-Za-z0-9+/=_-]{32,}\b/g) || [];

  for (const candidate of candidates) {
    // Skip common non-secret long strings (hex hashes, pure alpha words)
    if (candidate.match(/^[0-9a-f]{32,}$/i)) continue; // Pure hex (likely a hash)
    if (candidate.match(/^[A-Za-z]+$/)) continue; // Pure alpha (likely a word)

    const entropy = shannonEntropy(candidate);
    if (entropy > 4.5) { // High entropy threshold
      findings.push({ value: candidate.substring(0, 12) + '...', entropy: Math.round(entropy * 100) / 100 });
    }
  }
  return findings.slice(0, 5); // Limit to 5 findings
}

function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

interface DlpFinding {
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  count: number;
  preview: string; // Redacted preview
}

function scanContent(text: string): DlpFinding[] {
  const findings: DlpFinding[] = [];

  for (const { category, pattern, severity } of DLP_PATTERNS) {
    // Reset regex state
    pattern.lastIndex = 0;
    const matches = text.match(pattern);
    if (matches && matches.length > 0) {
      // Redact the match for logging (show first 4 chars + mask)
      const preview = matches[0].substring(0, 4) + '****' + (matches[0].length > 8 ? matches[0].substring(matches[0].length - 4) : '');
      findings.push({ category, severity, count: matches.length, preview });
    }
  }

  // High-entropy check
  const entropyFindings = hasHighEntropyStrings(text);
  if (entropyFindings.length > 0) {
    findings.push({
      category: 'high_entropy_string',
      severity: 'HIGH',
      count: entropyFindings.length,
      preview: entropyFindings.map(f => `${f.value} (H=${f.entropy})`).join(', ')
    });
  }

  return findings;
}

async function main() {
  let input = '';
  try {
    const decoder = new TextDecoder();
    const reader = Bun.stdin.stream().getReader();
    const timeout = new Promise<void>(resolve => setTimeout(resolve, 2000));
    const read = (async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        input += decoder.decode(value, { stream: true });
      }
    })();
    await Promise.race([read, timeout]);
  } catch {
    process.exit(0);
  }

  if (!input.trim()) {
    process.exit(0);
  }

  let event: Record<string, any>;
  try {
    event = JSON.parse(input);
  } catch {
    process.exit(0);
  }

  // Get transcript path and extract subagent output
  const transcriptPath = event.transcript_path;
  if (!transcriptPath || !existsSync(transcriptPath)) {
    process.exit(0);
  }

  let subagentOutput = '';
  try {
    const transcript = readFileSync(transcriptPath, 'utf-8');
    const lines = transcript.trim().split('\n');

    // Collect all assistant content from the subagent transcript
    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        if (entry.type === 'assistant' && entry.message?.content) {
          for (const content of entry.message.content) {
            if (content.type === 'text') {
              subagentOutput += content.text + '\n';
            }
          }
        }
        // Also check tool results that may contain sensitive data
        if (entry.type === 'user' && entry.message?.content) {
          for (const content of entry.message.content) {
            if (content.type === 'tool_result' && typeof content.content === 'string') {
              subagentOutput += content.content + '\n';
            }
          }
        }
      } catch {
        // Skip unparseable lines
      }
    }
  } catch {
    process.exit(0);
  }

  if (!subagentOutput || subagentOutput.length < 10) {
    process.exit(0);
  }

  // Run DLP scan
  const findings = scanContent(subagentOutput);

  if (findings.length === 0) {
    process.exit(0);
  }

  // Ensure log directory exists
  if (!existsSync(LOGS_DIR)) {
    mkdirSync(LOGS_DIR, { recursive: true, mode: 0o700 });
  }

  // Build audit entry
  const maxSeverity = findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
    : findings.some(f => f.severity === 'HIGH') ? 'HIGH' : 'MEDIUM';

  const auditEntry = {
    timestamp: new Date().toISOString(),
    event: 'SubagentStop',
    hook: HOOK_NAME,
    transcript: transcriptPath,
    output_length: subagentOutput.length,
    findings_count: findings.length,
    max_severity: maxSeverity,
    findings: findings.map(f => ({ category: f.category, severity: f.severity, count: f.count, preview: f.preview })),
    action: 'ALERT', // Non-blocking — always alert, never block
    session_id: event.session_id || process.env.CLAUDE_CODE_SESSION_ID || 'unknown',
  };

  // Log to DLP audit file (secure permissions)
  try {
    secureAppendLog(DLP_LOG, JSON.stringify(auditEntry) + '\n');
  } catch (err) {
    console.error(`[${HOOK_NAME}] Failed to write log: ${err}`);
  }

  // Alert to stderr for session visibility
  const severityEmoji = maxSeverity === 'CRITICAL' ? '🔴' : maxSeverity === 'HIGH' ? '🟠' : '🟡';
  console.error(`\n${severityEmoji} [Subagent DLP] ${maxSeverity} — ${findings.length} finding(s) in subagent output:`);
  for (const f of findings) {
    console.error(`  ${f.severity}: ${f.category} (${f.count}x) — ${f.preview}`);
  }
  console.error(`  Action: LOGGED (non-blocking). Review: ${DLP_LOG}\n`);
}

main().catch(() => process.exit(0));
