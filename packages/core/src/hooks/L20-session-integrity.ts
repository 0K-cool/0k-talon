#!/usr/bin/env bun

/**
 * L20 Session Integrity — SessionStart Hook
 *
 * Protects against session file fabrication attacks (0din Fabricator toolkit).
 * Two defenses:
 *   1. File permissions: lock session JSONL files to read-only after creation
 *   2. Integrity hashing: SHA-256 hash on write, verify on load
 *
 * If tampering is detected, warns via additionalContext but does NOT block
 * (session may have been legitimately modified by Claude Code itself).
 *
 * Threat model: https://0din.ai/blog/your-ai-agent-has-a-memory-problem
 * Tool: github.com/0din-ai/coding-agent-fabricator
 *
 * OWASP Agentic 2026: ASI06 (Memory and Context Manipulation)
 * MITRE ATLAS: AML.T0064 (Data Poisoning)
 *
 * 0K-Talon v0.2.0
 */

import { existsSync, readdirSync, statSync, chmodSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { createHash } from 'crypto';
import { STATE_DIR, ensureDirectories, getAuditLogPath, secureAppendLog } from './lib/talon-paths';

// ============================================================================
// Types
// ============================================================================

interface HookInput {
  session_id?: string;
  cwd?: string;
}

interface IntegrityRecord {
  file: string;
  hash: string;
  size: number;
  mtime: string;
  locked: boolean;
}

// ============================================================================
// Constants
// ============================================================================

const INTEGRITY_DIR = join(STATE_DIR, 'session-integrity');
const CLAUDE_SESSIONS_DIR = join(homedir(), '.claude', 'projects');
const HOOK_NAME = 'L20-session-integrity';

// Fabrication detection heuristics
const FABRICATION_PATTERNS = {
  // Placeholder UUIDs instead of cryptographic hashes
  placeholderIds: /msg_(?:corrected|fabricated|modified|injected)_\d+/,
  // Suspiciously uniform timestamps (automated generation)
  uniformTimestamps: /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d{3}Z.*?\1/,
  // Authorization claim injection in session content
  authClaims: /AUTHORIZED:\s*.{0,30}(?:access|grant|approv|admin)/i,
  // Approval policy override markers
  policyOverride: /approval_policy:\s*never/i,
  // Explicit fabrication markers
  fabricationMarker: /(?:fabricat|manufactur|synthetic|forged)\s+(?:session|conversation|exchange)/i,
};

// ============================================================================
// Hashing
// ============================================================================

function hashFile(filePath: string): string {
  const content = readFileSync(filePath);
  return createHash('sha256').update(content).digest('hex');
}

function getIntegrityPath(sessionDir: string): string {
  // Sanitize the session dir name for use as a filename
  const name = sessionDir.replace(/[^a-zA-Z0-9._-]/g, '_');
  return join(INTEGRITY_DIR, `${name}.json`);
}

function loadIntegrityRecords(sessionDir: string): Record<string, IntegrityRecord> {
  const path = getIntegrityPath(sessionDir);
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return {};
  }
}

function saveIntegrityRecords(sessionDir: string, records: Record<string, IntegrityRecord>): void {
  if (!existsSync(INTEGRITY_DIR)) {
    mkdirSync(INTEGRITY_DIR, { recursive: true, mode: 0o700 });
  }
  const path = getIntegrityPath(sessionDir);
  writeFileSync(path, JSON.stringify(records, null, 2), { mode: 0o600 });
}

// ============================================================================
// Fabrication Detection
// ============================================================================

function scanForFabricationArtifacts(filePath: string): string[] {
  const findings: string[] = [];
  try {
    const content = readFileSync(filePath, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());

    // Check for placeholder message IDs
    for (const line of lines) {
      if (FABRICATION_PATTERNS.placeholderIds.test(line)) {
        findings.push('Placeholder message IDs detected (non-cryptographic)');
        break;
      }
    }

    // Check for authorization claim injection
    if (FABRICATION_PATTERNS.authClaims.test(content)) {
      findings.push('Authorization claim injection detected in session');
    }

    // Check for policy override markers
    if (FABRICATION_PATTERNS.policyOverride.test(content)) {
      findings.push('Approval policy override marker detected');
    }

    // Check for explicit fabrication markers
    if (FABRICATION_PATTERNS.fabricationMarker.test(content)) {
      findings.push('Explicit fabrication/synthetic content marker detected');
    }

    // Check timestamp distribution (automated = uniform intervals)
    const timestamps: number[] = [];
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        if (obj.timestamp) {
          timestamps.push(new Date(obj.timestamp).getTime());
        }
      } catch { /* not every line is JSON */ }
    }
    if (timestamps.length >= 5) {
      const intervals = [];
      for (let i = 1; i < timestamps.length; i++) {
        // noUncheckedIndexedAccess: both indices are in-bounds by the loop
        // condition, but the compiler cannot prove it. Guard explicitly rather
        // than asserting non-null.
        const cur = timestamps[i];
        const prev = timestamps[i - 1];
        if (cur === undefined || prev === undefined) continue;
        intervals.push(cur - prev);
      }
      // If all intervals are identical (within 10ms), likely fabricated
      const uniqueIntervals = new Set(intervals.map(i => Math.round(i / 10)));
      if (uniqueIntervals.size === 1 && intervals.length >= 4) {
        findings.push(`Uniform timestamp intervals (${intervals[0]}ms) — possible automated fabrication`);
      }
    }
  } catch {
    // Can't read file — don't flag
  }
  return findings;
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  let raw = '';
  try {
    raw = await Bun.stdin.text();
  } catch {
    console.log(JSON.stringify({ continue: true }));
    return;
  }

  let input: HookInput = {};
  try {
    input = JSON.parse(raw || '{}');
  } catch {
    console.log(JSON.stringify({ continue: true }));
    return;
  }

  ensureDirectories();
  if (!existsSync(INTEGRITY_DIR)) {
    mkdirSync(INTEGRITY_DIR, { recursive: true, mode: 0o700 });
  }

  const warnings: string[] = [];
  const auditEntries: string[] = [];

  // Scan all project session directories
  if (!existsSync(CLAUDE_SESSIONS_DIR)) {
    console.log(JSON.stringify({ continue: true }));
    return;
  }

  let projectDirs: string[];
  try {
    projectDirs = readdirSync(CLAUDE_SESSIONS_DIR)
      .filter(d => d.startsWith('-'))
      .map(d => join(CLAUDE_SESSIONS_DIR, d));
  } catch {
    console.log(JSON.stringify({ continue: true }));
    return;
  }

  let filesChecked = 0;
  let filesLocked = 0;
  let tamperDetected = 0;
  let fabricationFound = 0;

  for (const projectDir of projectDirs) {
    const records = loadIntegrityRecords(projectDir);

    // Find JSONL session files
    let sessionFiles: string[];
    try {
      sessionFiles = readdirSync(projectDir)
        .filter(f => f.endsWith('.jsonl'))
        .map(f => join(projectDir, f));
    } catch {
      continue;
    }

    let recordsChanged = false;

    for (const filePath of sessionFiles) {
      filesChecked++;
      const filename = filePath.split('/').pop() || '';

      try {
        const stat = statSync(filePath);
        const currentHash = hashFile(filePath);

        // Check if we have a prior integrity record
        if (records[filename]) {
          const prior = records[filename];
          if (prior.hash !== currentHash) {
            tamperDetected++;
            const warning = `Session file modified externally: ${filename} (hash mismatch)`;
            warnings.push(warning);
            auditEntries.push(JSON.stringify({
              timestamp: new Date().toISOString(),
              hook: HOOK_NAME,
              event: 'tamper_detected',
              file: filePath,
              expected_hash: prior.hash,
              actual_hash: currentHash,
              prior_size: prior.size,
              current_size: stat.size,
            }));

            // Scan for fabrication artifacts
            const artifacts = scanForFabricationArtifacts(filePath);
            if (artifacts.length > 0) {
              fabricationFound++;
              warnings.push(`  Fabrication artifacts: ${artifacts.join('; ')}`);
              auditEntries.push(JSON.stringify({
                timestamp: new Date().toISOString(),
                hook: HOOK_NAME,
                event: 'fabrication_detected',
                file: filePath,
                artifacts,
              }));
            }
          }
        }

        // Update integrity record
        records[filename] = {
          file: filePath,
          hash: currentHash,
          size: stat.size,
          mtime: stat.mtime.toISOString(),
          locked: false,
        };
        recordsChanged = true;

        // Lock old session files (not the current session) to read-only.
        // Current session needs write access for Claude Code to append.
        //
        // Two defects fixed here (ported from 0K-cool/vex PR #10):
        //  1. `filename.includes(currentSessionId)` was a substring match — a
        //     short/attacker-crafted session_id could match multiple filenames
        //     and skip locking on all of them (ATLAS AML.T0064 bypass vector).
        //     Exact equality closes it.
        //  2. When `currentSessionId` is empty (stdin JSON missing session_id),
        //     the old `length > 10` guard evaluated to false → isCurrentSession
        //     became false → the ACTIVE session got locked to 0o400 → Claude
        //     Code hits EACCES on the next append. Fail-open here: if we can't
        //     identify the current session, skip the chmod entirely.
        const currentSessionId = input.session_id || '';
        const sessionIdResolvable = currentSessionId.length > 10;
        const isCurrentSession =
          sessionIdResolvable && filename === `${currentSessionId}.jsonl`;

        if (sessionIdResolvable && !isCurrentSession) {
          try {
            chmodSync(filePath, 0o400); // read-only
            records[filename].locked = true;
            filesLocked++;
          } catch {
            // Can't chmod — might not own the file
          }
        }
      } catch {
        // Skip files we can't access
      }
    }

    if (recordsChanged) {
      saveIntegrityRecords(projectDir, records);
    }
  }

  // Write audit log
  if (auditEntries.length > 0) {
    const logPath = getAuditLogPath(HOOK_NAME);
    for (const entry of auditEntries) {
      secureAppendLog(logPath, entry + '\n');
    }
  }

  // Log summary to stderr
  const summary = `[${HOOK_NAME}] ${filesChecked} files checked, ${filesLocked} locked, ${tamperDetected} tamper, ${fabricationFound} fabrication`;
  console.error(summary);

  // Build output
  if (warnings.length > 0) {
    const warningText = [
      `[0K-Talon Session Integrity] ${tamperDetected} session file(s) modified externally:`,
      ...warnings,
      '',
      'This may indicate session fabrication (0din Fabricator or similar).',
      'Review the modified files before trusting their conversation history.',
    ].join('\n');

    console.log(JSON.stringify({
      continue: true,
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: warningText,
      },
    }));
  } else {
    console.log(JSON.stringify({ continue: true }));
  }
}

// Entrypoint guard. Was `import.meta.main`, which tsc rejects under
// module: NodeNext (this package has no "type": "module", so TS treats
// these as CommonJS) — TS1470, and it broke `pnpm build`.
// Bun provides __filename in ESM files, and these hooks run via
// `bun run <path>.ts` per hooks.json, so this is equivalent at runtime.
// The guard matters: tests import from this module and must not run main().
if (process.argv[1] === __filename) {
  main();
}
