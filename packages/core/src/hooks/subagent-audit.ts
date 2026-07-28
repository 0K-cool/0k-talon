#!/usr/bin/env bun

/**
 * Subagent Audit Hook (TaskCreated)
 *
 * Mitigation for anthropics/claude-code#21460: Subagent tool calls bypass
 * ALL PreToolUse hooks. Since we can't prevent the bypass, we detect and
 * log every subagent spawn for audit trail and anomaly detection.
 *
 * Layer: Cross-cutting (feeds L8 Evaluator, L17 Spend Alerting)
 * Event: TaskCreated (v2.1.84+)
 * Action: OBSERVE (log + alert) — does not block
 *
 * Maps to:
 * - OWASP ASI03 (Identity & Privilege Abuse)
 * - MITRE ATLAS AML.T0096 (AI Service API)
 *
 * @version 1.0.0 (0k-talon)
 * @date 2026-04-02
 */

import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { TALON_DIR, secureAppendLog } from './lib/talon-paths';

const HOOK_NAME = 'subagent-audit';
const LOG_DIR = join(TALON_DIR, 'logs');
const AUDIT_LOG = join(LOG_DIR, 'subagent-audit.jsonl');

// High-risk subagent types with full tool access
const HIGH_RISK_TYPES = new Set([
  'general-purpose',
  'pentester',
  'engineer',
]);

// Sensitive prompt patterns that may indicate misuse or exfiltration
const SENSITIVE_PATTERNS: RegExp[] = [
  /(?:api[_-]?key|secret|token|password|credential)/i,
  /(?:exfiltrat|steal|extract.*data|send.*to)/i,
  /(?:curl|wget|fetch).*(?:external|remote)/i,
  /(?:rm\s+-rf|delete|destroy|drop)/i,
  /(?:bypass|disable|skip).*(?:hook|security|guard)/i,
];

function truncate(str: string, maxLen: number): string {
  if (!str || str.length <= maxLen) return str || '';
  return str.substring(0, maxLen) + '...[truncated]';
}

function checkSensitivePatterns(prompt: string): string[] {
  const matches: string[] = [];
  for (const pattern of SENSITIVE_PATTERNS) {
    if (pattern.test(prompt)) {
      matches.push(pattern.source);
    }
  }
  return matches;
}

async function main() {
  // Read stdin
  let input = '';
  try {
    const decoder = new TextDecoder();
    const reader = Bun.stdin.stream().getReader();
    const timeout = new Promise<void>(resolve => setTimeout(resolve, 1000));
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
    console.log(JSON.stringify({ continue: true }));
    process.exit(0);
  }

  let event: Record<string, any>;
  try {
    event = JSON.parse(input);
  } catch {
    console.log(JSON.stringify({ continue: true }));
    process.exit(0);
  }

  // Extract subagent details
  const toolInput = event.tool_input || {};
  const agentType = toolInput.subagent_type || toolInput.type || 'unknown';
  const agentName = toolInput.name || 'unnamed';
  const prompt = toolInput.prompt || '';
  const description = toolInput.description || '';
  const model = toolInput.model || 'inherited';
  const runInBackground = toolInput.run_in_background || false;
  const isolation = toolInput.isolation || 'none';

  // Risk assessment
  const isHighRisk = HIGH_RISK_TYPES.has(agentType);
  const sensitiveMatches = checkSensitivePatterns(prompt);
  const hasSensitiveContent = sensitiveMatches.length > 0;

  let riskLevel = 'LOW';
  if (isHighRisk && hasSensitiveContent) riskLevel = 'CRITICAL';
  else if (hasSensitiveContent) riskLevel = 'HIGH';
  else if (isHighRisk) riskLevel = 'MEDIUM';

  // Build audit entry
  const auditEntry = {
    timestamp: new Date().toISOString(),
    event: 'TaskCreated',
    hook: HOOK_NAME,
    agent_type: agentType,
    agent_name: agentName,
    description: truncate(description, 200),
    prompt_preview: truncate(prompt, 500),
    prompt_length: prompt.length,
    model,
    run_in_background: runInBackground,
    isolation,
    risk_level: riskLevel,
    sensitive_patterns: sensitiveMatches,
    hook_bypass_warning: true,
    session_id: event.session_id || process.env.CLAUDE_CODE_SESSION_ID || 'unknown',
  };

  // Ensure log directory exists
  if (!existsSync(LOG_DIR)) {
    mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 });
  }

  // Append to audit log (secure permissions)
  try {
    secureAppendLog(AUDIT_LOG, JSON.stringify(auditEntry) + '\n');
  } catch (err) {
    console.error(`[${HOOK_NAME}] Failed to write log: ${err}`);
  }

  // Stderr output for session awareness
  const riskEmoji = riskLevel === 'CRITICAL' ? '🔴' : riskLevel === 'HIGH' ? '🟠' : riskLevel === 'MEDIUM' ? '🟡' : '🟢';
  console.error(`${riskEmoji} [Subagent Audit] ${agentType}/${agentName} spawned (risk: ${riskLevel})${hasSensitiveContent ? ' ⚠️ SENSITIVE: ' + sensitiveMatches.join(', ') : ''}`);

  // For CRITICAL risk, warn on STDERR — the only channel that reaches anyone
  // from this event.
  //
  // Previously the bypass warning existed ONLY in a top-level
  // `additionalContext`, which Claude Code ignores (verified against the
  // v2.1.220 binary: TaskCreated has no hookSpecificOutput variant at all, so
  // it cannot be nested either — see 0K-cool/vex#126). The stderr line above
  // fires for every risk level and carries no bypass text. Net effect: the
  // warning reached NEITHER the operator NOR the model, while README.md:122
  // stated it reached the operator.
  //
  // Emitting it on stderr makes the documented behaviour true.
  if (riskLevel === 'CRITICAL') {
    console.error(
      `⚠️ SUBAGENT SECURITY ALERT (#21460): A ${agentType} subagent "${agentName}" was ` +
      `spawned with sensitive content patterns (${sensitiveMatches.join(', ')}). ` +
      `This subagent's tool calls bypass all PreToolUse hooks. Exercise caution with its output.`
    );
  }
  console.log(JSON.stringify({ continue: true }));
}

main().catch(() => {
  console.log(JSON.stringify({ continue: true }));
});
