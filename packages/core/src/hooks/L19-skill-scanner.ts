#!/usr/bin/env bun

/**
 * L19: Skill Scanner - PreToolUse Hook
 *
 * Part of 0K-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: Scan skills at invocation for injection patterns and dangerous commands.
 * Pattern: Sidecar Pattern (monitoring before tool execution)
 *
 * Detects:
 * - Frontmatter injection (name/description hijacking)
 * - Content injection (NOVA patterns, instruction override)
 * - Dangerous commands (reverse shells, data exfil)
 * - Credential patterns
 * - External URLs to untrusted destinations
 *
 * Maps to:
 * - OWASP LLM01 (Prompt Injection)
 * - OWASP Agentic ASI04 (Dependency Chain Attack)
 *
 * @version 0.1.0 (0k-talon)
 * @date 2026-02-04
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { ensureTalonDirs, getAuditLogPath, secureAppendLog } from './lib/talon-paths';

const HOOK_NAME = 'L19-skill-scanner';

interface HookInput {
  session_id: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
}

interface Finding {
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  pattern: string;
  detail: string;
}

// Injection patterns
const INJECTION_PATTERNS = [
  { regex: /ignore\s+(all\s+)?(previous|prior)/i, severity: 'CRITICAL' as const, category: 'injection' },
  { regex: /disregard\s+(all\s+)?(previous|prior|your)/i, severity: 'CRITICAL' as const, category: 'injection' },
  { regex: /new\s+instructions?\s*:/i, severity: 'CRITICAL' as const, category: 'injection' },
  { regex: /system\s*:\s*you\s+are/i, severity: 'CRITICAL' as const, category: 'injection' },
  { regex: /<\|?system\|?>/i, severity: 'CRITICAL' as const, category: 'injection' },
];

// Dangerous command patterns
const DANGEROUS_COMMANDS = [
  { regex: /curl\s+[^|]*\|\s*(ba)?sh/i, severity: 'CRITICAL' as const, category: 'command', detail: 'Pipe to shell' },
  { regex: /wget\s+[^|]*\|\s*(ba)?sh/i, severity: 'CRITICAL' as const, category: 'command', detail: 'Pipe to shell' },
  { regex: /rm\s+-rf\s+[\/~]/i, severity: 'CRITICAL' as const, category: 'command', detail: 'Recursive delete' },
  { regex: /nc\s+-[el]/i, severity: 'CRITICAL' as const, category: 'command', detail: 'Netcat listener' },
  { regex: /\/dev\/tcp\//i, severity: 'CRITICAL' as const, category: 'command', detail: 'Bash reverse shell' },
  { regex: /mkfifo.*nc/i, severity: 'CRITICAL' as const, category: 'command', detail: 'Named pipe shell' },
];

// Credential patterns
const CREDENTIAL_PATTERNS = [
  { regex: /["']sk-[a-zA-Z0-9]{20,}["']/i, severity: 'CRITICAL' as const, category: 'credential', detail: 'OpenAI key' },
  { regex: /["']ghp_[a-zA-Z0-9]{36}["']/i, severity: 'CRITICAL' as const, category: 'credential', detail: 'GitHub token' },
  { regex: /["']AKIA[A-Z0-9]{16}["']/i, severity: 'CRITICAL' as const, category: 'credential', detail: 'AWS key' },
  { regex: /password\s*[=:]\s*["'][^"']{8,}["']/i, severity: 'HIGH' as const, category: 'credential', detail: 'Hardcoded password' },
];

// Suspicious URLs
const SUSPICIOUS_URLS = [
  { regex: /pastebin\.com/i, severity: 'HIGH' as const, category: 'url', detail: 'Pastebin URL' },
  { regex: /webhook\.site/i, severity: 'HIGH' as const, category: 'url', detail: 'Webhook.site URL' },
  { regex: /ngrok\.io/i, severity: 'MEDIUM' as const, category: 'url', detail: 'Ngrok tunnel' },
  { regex: /requestbin\./i, severity: 'HIGH' as const, category: 'url', detail: 'RequestBin URL' },
];

function scanSkillContent(content: string): Finding[] {
  const findings: Finding[] = [];

  // Check injection patterns
  for (const p of INJECTION_PATTERNS) {
    const match = content.match(p.regex);
    if (match) {
      findings.push({
        category: p.category,
        severity: p.severity,
        pattern: match[0].substring(0, 50),
        detail: 'Instruction override attempt',
      });
    }
  }

  // Check dangerous commands
  for (const p of DANGEROUS_COMMANDS) {
    const match = content.match(p.regex);
    if (match) {
      findings.push({
        category: p.category,
        severity: p.severity,
        pattern: match[0].substring(0, 50),
        detail: p.detail,
      });
    }
  }

  // Check credentials
  for (const p of CREDENTIAL_PATTERNS) {
    const match = content.match(p.regex);
    if (match) {
      findings.push({
        category: p.category,
        severity: p.severity,
        pattern: '[REDACTED]',
        detail: p.detail,
      });
    }
  }

  // Check suspicious URLs
  for (const p of SUSPICIOUS_URLS) {
    const match = content.match(p.regex);
    if (match) {
      findings.push({
        category: p.category,
        severity: p.severity,
        pattern: match[0],
        detail: p.detail,
      });
    }
  }

  return findings;
}

function logToAudit(entry: any): void {
  try {
    ensureTalonDirs();
    secureAppendLog(getAuditLogPath(HOOK_NAME), JSON.stringify(entry) + '\n');
  } catch {}
}

function outputBlock(findings: Finding[], skillName: string): void {
  const critical = findings.filter(f => f.severity === 'CRITICAL');

  console.error('\n🛑 TALON L19: SKILL BLOCKED');
  console.error(`   Skill: ${skillName}`);
  for (const f of findings.slice(0, 5)) {
    const emoji = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡';
    console.error(`   ${emoji} [${f.category}] ${f.detail}`);
  }
  console.error('   ❌ Skill invocation blocked for security\n');

  console.log(JSON.stringify({
    decision: 'block',
    reason: `TALON L19: Skill "${skillName}" blocked - ${critical.map(f => f.detail).join(', ')}`,
  }));
}

function outputWarn(findings: Finding[], skillName: string): void {
  console.error('\n⚠️  TALON L19: SKILL WARNING');
  console.error(`   Skill: ${skillName}`);
  for (const f of findings.slice(0, 3)) {
    const emoji = f.severity === 'HIGH' ? '🟠' : '🟡';
    console.error(`   ${emoji} [${f.category}] ${f.detail}`);
  }
  console.error('   Review skill content before proceeding\n');

  const topFindings = findings.slice(0, 3).map(f => `[${f.severity}] ${f.detail}`).join('; ');
  console.log(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      additionalContext: `⚠️ TALON SKILL SCANNER (L19) ${findings[0]?.severity || 'HIGH'}: Skill "${skillName}" has ${findings.length} finding(s). ` +
        `${topFindings}. Review skill content before proceeding.`,
    },
  }));
}

async function main() {
  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 300)),
    ]);
    if (!input?.trim()) process.exit(0);

    const data: HookInput = JSON.parse(input);

    // Only scan Skill tool invocations
    if (data.tool_name !== 'Skill') {
      process.exit(0);
    }

    const skillName = data.tool_input?.skill || '';
    if (!skillName) {
      process.exit(0);
    }

    // Try to find and read the skill file
    // Skills are typically in .claude/skills/<name>/skill.md
    const possiblePaths = [
      join(process.cwd(), '.claude', 'skills', skillName, 'skill.md'),
      join(process.cwd(), 'skills', skillName, 'skill.md'),
      join(process.cwd(), 'skills', `${skillName}.md`),
    ];

    let skillContent = '';
    for (const path of possiblePaths) {
      if (existsSync(path)) {
        try {
          skillContent = readFileSync(path, 'utf-8');
          break;
        } catch {}
      }
    }

    if (!skillContent) {
      // Can't find skill file - allow but log
      logToAudit({
        timestamp: new Date().toISOString(),
        session_id: data.session_id,
        skill: skillName,
        status: 'NOT_FOUND',
        findings: [],
      });
      process.exit(0);
    }

    const findings = scanSkillContent(skillContent);

    // Log to audit
    logToAudit({
      timestamp: new Date().toISOString(),
      session_id: data.session_id,
      skill: skillName,
      findings,
      severity: findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' :
                findings.some(f => f.severity === 'HIGH') ? 'HIGH' :
                findings.length > 0 ? 'MEDIUM' : 'NONE',
    });

    if (findings.length === 0) {
      process.exit(0);
    }

    // Block on CRITICAL, warn on HIGH/MEDIUM
    if (findings.some(f => f.severity === 'CRITICAL')) {
      outputBlock(findings, skillName);
      process.exit(2);
    } else {
      outputWarn(findings, skillName);
      process.exit(0);
    }
  } catch {
    // Fail-closed: block operation if hook crashes (security-first)
    process.exit(2);
  }
}

main();
