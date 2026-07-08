#!/usr/bin/env bun

/**
 * L3-memory-file-validation.ts — PreToolUse hook: block memory-FILE poisoning.
 *
 * Complements L3-memory-validation.ts (which covers MCP memory tools, detection-only
 * due to Claude Code #3514/#4669). This hook covers Write/Edit/MultiEdit to memory
 * FILES (paths containing /memory/ or ending MEMORY.md). Write/Edit are ordinary
 * PreToolUse tools — not affected by the MCP-blocking bugs — so this HARD-BLOCKS via
 * exit code 2.
 *
 * The scanner is the vendored, dependency-free core shared with Mnemosyne
 * (./vendor/memory-scanner-core.ts) — one implementation, no runtime dependency on
 * Mnemosyne, kept in lock-step by the vendor drift-check CI step. This hook is the
 * Talon harness: stdin in, exit-2 banner on a finding.
 *
 * Security mapping:
 *   OWASP Agentic 2026 ASI06 (Memory and Context Manipulation)
 *   MITRE ATLAS AML.T0064 (Data Poisoning)
 */

import { ensureTalonDirs, getAuditLogPath, secureAppendLog } from './lib/talon-paths';
import {
  type HookInput,
  WRITE_TOOLS,
  extractFilePath,
  extractContent,
  isMemoryFile,
  validateMemoryWrite,
} from './vendor/memory-scanner-core';

const HOOK_NAME = 'L3-memory-file-validation';

function logToAudit(entry: unknown): void {
  try {
    ensureTalonDirs();
    secureAppendLog(getAuditLogPath(HOOK_NAME), JSON.stringify(entry) + '\n');
  } catch {
    // Audit logging is best-effort; never block on a logging failure.
  }
}

function outputBlockBanner(filePath: string, reason: string): void {
  console.error('');
  console.error('╔══════════════════════════════════════════════════════════════════╗');
  console.error('║  🛑 TALON L3: MEMORY-FILE POISONING BLOCKED 🛑                   ║');
  console.error('╠══════════════════════════════════════════════════════════════════╣');
  console.error(`║  File: ${filePath.slice(0, 58).padEnd(58)}║`);
  console.error('╠══════════════════════════════════════════════════════════════════╣');
  for (const line of reason.match(/.{1,62}/g) ?? [reason]) {
    console.error(`║  ${line.padEnd(62)}║`);
  }
  console.error('╚══════════════════════════════════════════════════════════════════╝');
  console.error('');
}

async function main(): Promise<void> {
  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 300)),
    ]);
    if (!input?.trim()) process.exit(0);

    const data: HookInput = JSON.parse(input);
    const toolName = data.tool_name ?? '';

    // Only gate content-writing tools targeting memory files
    if (!WRITE_TOOLS.has(toolName)) process.exit(0);

    const toolInput = data.tool_input ?? {};
    const filePath = extractFilePath(toolName, toolInput);
    if (!isMemoryFile(filePath)) process.exit(0);

    const content = extractContent(toolName, toolInput);
    if (!content) process.exit(0);

    const verdict = validateMemoryWrite(filePath, content);
    if (verdict.decision === 'block') {
      logToAudit({
        timestamp: new Date().toISOString(),
        session_id: data.session_id,
        tool: toolName,
        file_path: filePath,
        action: 'BLOCK',
        reason: verdict.reason,
      });
      outputBlockBanner(filePath, verdict.reason);
      process.exit(2); // Write/Edit hard-block — the write is prevented.
    }

    process.exit(0);
  } catch {
    // Fail-open on parse/timeout/unexpected errors — never block the user by accident.
    process.exit(0);
  }
}

main();
