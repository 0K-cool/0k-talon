#!/usr/bin/env bun

/**
 * L5: Output Sanitizer - PostToolUse Hook
 *
 * Part of 0K-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: Scan web and terminal files for unsafe output patterns after write.
 * Pattern: Sidecar Pattern (monitoring after tool execution)
 *
 * Detects:
 * - XSS vectors: innerHTML, dangerouslySetInnerHTML, eval(), document.write
 * - ANSI terminal injection: OSC 52 clipboard, DCS device control, 8-bit CSI,
 *   bracketed paste manipulation, title social engineering, Sixel graphics
 *
 * Maps to:
 * - OWASP LLM05 (Improper Output Handling)
 * - Terminal DiLLMa (SAGAI 2025 case study #6)
 *
 * @version 0.2.0 (0k-talon)
 * @date 2026-02-11
 */

import { extname } from 'path';
import { ensureTalonDirs, getAuditLogPath, secureAppendLog } from './lib/talon-paths';

const HOOK_NAME = 'L5-output-sanitizer';

interface HookInput {
  session_id: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
}

interface Finding {
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  match: string;
}

// Web and terminal file extensions to scan
const WEB_EXTENSIONS = ['.html', '.htm', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.sh', '.bash', '.zsh', '.py', '.rb', '.pl'];
const WRITE_TOOLS = ['Write', 'Edit'];

// Unsafe DOM and terminal output patterns (compiled at runtime to avoid false positive in source)
const UNSAFE_PATTERNS = [
  // XSS / DOM injection
  { name: 'Direct DOM injection', regex: '\\.innerHTML\\s*=', severity: 'CRITICAL' as const },
  { name: 'React unsafe HTML', regex: 'dangerouslySetInnerHTML', severity: 'CRITICAL' as const },
  { name: 'Vue unsafe HTML', regex: 'v-html\\s*=', severity: 'CRITICAL' as const },
  { name: 'Document write', regex: 'document\\.write\\s*\\(', severity: 'CRITICAL' as const },
  { name: 'Dynamic eval', regex: '\\beval\\s*\\(', severity: 'CRITICAL' as const },
  { name: 'Script URL', regex: 'href\\s*=\\s*["\']javascript:', severity: 'HIGH' as const },
  { name: 'jQuery HTML insert', regex: '\\$\\([^)]+\\)\\.html\\s*\\(', severity: 'HIGH' as const },
  // ANSI terminal injection (Terminal DiLLMa defense)
  { name: 'ANSI OSC52 clipboard', regex: '\\\\x1b\\]52;|\\\\033\\]52;|\\\\e\\]52;', severity: 'CRITICAL' as const },
  { name: 'ANSI DCS device control', regex: '\\\\x1bP[^\\\\"\']*|\\\\033P[^\\\\"\']*', severity: 'HIGH' as const },
  { name: 'ANSI 8-bit CSI bypass', regex: '\\\\x9b', severity: 'HIGH' as const },
  { name: 'ANSI bracketed paste', regex: '\\\\x1b\\[\\?2004[hl]|\\\\033\\[\\?2004[hl]', severity: 'HIGH' as const },
  { name: 'ANSI title manipulation', regex: '\\\\x1b\\][012];|\\\\033\\][012];|\\\\e\\][012];', severity: 'MEDIUM' as const },
  { name: 'ANSI Sixel graphics', regex: '\\\\x1bPq|\\\\033Pq', severity: 'MEDIUM' as const },
];

function scanContent(content: string): Finding[] {
  const findings: Finding[] = [];
  for (const p of UNSAFE_PATTERNS) {
    const regex = new RegExp(p.regex, 'i');
    const match = content.match(regex);
    if (match) {
      findings.push({ name: p.name, severity: p.severity, match: match[0].substring(0, 30) });
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

function displayWarning(findings: Finding[], filePath: string): void {
  const hasAnsi = findings.some(f => f.name.startsWith('ANSI'));
  const label = hasAnsi ? 'Unsafe output patterns' : 'Unsafe DOM patterns';
  console.error(`\n⚠️  TALON L5: ${label} detected in ${filePath}`);
  for (const f of findings.slice(0, 5)) {
    const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡';
    console.error(`   ${icon} ${f.name}`);
  }
  if (hasAnsi) {
    console.error('   Remove ANSI escape sequences — clipboard/paste/device control injection risk');
  } else {
    console.error('   Consider using textContent or a sanitization library');
  }
  console.error('');
}

async function main() {
  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 300)),
    ]);
    if (!input?.trim()) process.exit(0);

    const data: HookInput = JSON.parse(input);
    if (!data.tool_name || !WRITE_TOOLS.includes(data.tool_name)) process.exit(0);

    const filePath = data.tool_input?.file_path || '';
    const content = data.tool_input?.content || data.tool_input?.new_string || '';
    const ext = extname(filePath).toLowerCase();

    if (!WEB_EXTENSIONS.includes(ext) || content.length < 20) process.exit(0);

    const findings = scanContent(content);
    if (findings.length === 0) process.exit(0);

    logToAudit({
      timestamp: new Date().toISOString(),
      tool: data.tool_name,
      file_path: filePath,
      session_id: data.session_id,
      findings,
    });

    displayWarning(findings, filePath);

    // Output JSON with additionalContext so the AI is aware of XSS patterns
    const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
    const patternNames = findings.slice(0, 3).map(f => f.name).join(', ');

    const hasAnsi = findings.some(f => f.name.startsWith('ANSI'));
    const ansiWarning = hasAnsi ? 'ANSI terminal injection detected — remove dangerous escape sequences. ' : '';
    const xssWarning = findings.some(f => !f.name.startsWith('ANSI'))
      ? 'Use textContent instead of innerHTML, or sanitize with DOMPurify. Do NOT use dangerouslySetInnerHTML or document.write with user input. '
      : '';

    console.log(JSON.stringify({
      continue: true,
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        additionalContext: `⚠️ TALON L5: Unsafe output patterns detected in "${filePath}": ${patternNames}. ` +
          `${criticalFindings.length > 0 ? 'CRITICAL risk! ' : ''}` +
          ansiWarning + xssWarning,
      },
    }));

    process.exit(0);
  } catch {
    // PostToolUse: content already in context, blocking serves no purpose.
    // Fail-open is correct here (unlike PreToolUse hooks which fail-closed).
    process.exit(0);
  }
}

main();
