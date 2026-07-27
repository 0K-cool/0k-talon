#!/usr/bin/env bun

/**
 * L9: Egress Data Scanner - PreToolUse Hook
 *
 * Part of 0K-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: Scan outbound data for secrets/PII and detect bulk exfiltration attempts.
 * Pattern: Sidecar Pattern (monitoring before tool execution)
 *
 * Scans: WebFetch, WebSearch, Bash (curl/wget/http commands)
 *
 * Detection Categories:
 * 1. SECRET PATTERNS: API keys, passwords, private keys, tokens
 * 2. PII PATTERNS: SSN, credit cards, emails
 * 3. BULK EXFILTRATION: Large payloads, cumulative session data
 * 4. BLOCKED DESTINATIONS: Pastebin, webhook.site, ngrok, raw IPs
 *
 * Actions:
 * - CRITICAL: BLOCK (secrets, bulk exfil, blocked destinations)
 * - HIGH: WARN (tokens, large payloads)
 * - MEDIUM: LOG (minor anomalies)
 *
 * Maps to:
 * - OWASP LLM02 (Sensitive Information Disclosure)
 * - MITRE ATLAS AML.T0035 (Exfiltration via ML Inference API)
 * - MITRE ATLAS AML.T0057 (LLM Data Leakage)
 *
 * @version 0.1.0 (0k-talon)
 * @date 2026-02-04
 */

import {
  ensureTalonDirs,
  getAuditLogPath,
  getStateFilePath,
  secureAppendLog,
} from './lib/talon-paths';
import { atomicUpdateJsonFile, readJsonFileSync } from './lib/atomic-file';
import { checkCircuit, recordSuccess, recordFailure } from './lib/circuit-breaker';

const HOOK_NAME = 'L9-egress-scanner';

// ============================================================================
// Types
// ============================================================================

interface HookInput {
  session_id: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
}

interface ScanFinding {
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  match: string;
  category: 'SECRET' | 'PII' | 'BULK_EXFIL' | 'DESTINATION';
}

interface SessionState {
  session_id: string;
  total_egress_bytes: number;
  request_count: number;
  destinations: string[];
  last_updated: string;
}

interface AuditEntry {
  timestamp: string;
  tool: string;
  session_id: string;
  egress_bytes: number;
  findings: ScanFinding[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE';
  action: 'BLOCK' | 'WARN' | 'LOG';
  destination?: string;
}

// ============================================================================
// Configuration
// ============================================================================

const EGRESS_TOOLS = ['WebFetch', 'WebSearch', 'Bash'];

// Thresholds
const SINGLE_TRANSFER_LIMIT = 500 * 1024;  // 500KB block
const SINGLE_TRANSFER_WARN = 50 * 1024;    // 50KB warn
const SESSION_TRANSFER_LIMIT = 20 * 1024 * 1024;  // 20MB session block
const BASE64_LIMIT = 10 * 1024;  // 10KB base64 block

// ============================================================================
// Bundled Secret Patterns
// ============================================================================

const SECRET_PATTERNS = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'CRITICAL' as const },
  { name: 'AWS Secret Key', pattern: /[A-Za-z0-9\/+=]{40}(?=.*aws)/i, severity: 'CRITICAL' as const },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/, severity: 'CRITICAL' as const },
  { name: 'OpenAI Key', pattern: /sk-[a-zA-Z0-9]{20,}/, severity: 'CRITICAL' as const },
  { name: 'Anthropic Key', pattern: /sk-ant-[a-zA-Z0-9-_]{40,}/, severity: 'CRITICAL' as const },
  { name: 'Stripe Live Key', pattern: /sk_live_[a-zA-Z0-9]{24,}/, severity: 'CRITICAL' as const },
  { name: 'Stripe Test Key', pattern: /sk_test_[a-zA-Z0-9]{24,}/, severity: 'HIGH' as const },
  { name: 'Slack Bot Token', pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/, severity: 'CRITICAL' as const },
  { name: 'Slack User Token', pattern: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/, severity: 'CRITICAL' as const },
  { name: 'Private Key', pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: 'CRITICAL' as const },
  { name: 'Generic API Key', pattern: /api[_-]?key["']?\s*[:=]\s*["'][^"']{20,}/, severity: 'HIGH' as const },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+\/=]*/, severity: 'HIGH' as const },
  { name: 'Password Assignment', pattern: /(?:password|passwd|pwd)["']?\s*[:=]\s*(?:["'][^"']{8,}["']|\S{8,})/i, severity: 'HIGH' as const },
];

// ============================================================================
// Bundled PII Patterns
// ============================================================================

const PII_PATTERNS = [
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/, severity: 'HIGH' as const },
  { name: 'Credit Card', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/, severity: 'HIGH' as const },
  { name: 'Email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, severity: 'MEDIUM' as const },
];

// ============================================================================
// Blocked Destinations
// ============================================================================

const BLOCKED_DESTINATIONS = [
  { pattern: /pastebin\.com/i, name: 'Pastebin', severity: 'CRITICAL' as const },
  { pattern: /webhook\.site/i, name: 'Webhook.site', severity: 'CRITICAL' as const },
  { pattern: /\.ngrok\.io/i, name: 'Ngrok', severity: 'HIGH' as const },
  { pattern: /requestbin\./i, name: 'RequestBin', severity: 'HIGH' as const },
  { pattern: /pipedream\.net/i, name: 'Pipedream', severity: 'HIGH' as const },
  { pattern: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, name: 'Raw IP', severity: 'HIGH' as const },
];

// ============================================================================
// State Management
// ============================================================================

function loadSessionState(sessionId: string): SessionState {
  const statePath = getStateFilePath(HOOK_NAME, 'session.json');
  const state = readJsonFileSync<Record<string, SessionState>>(statePath, {});
  return state[sessionId] || {
    session_id: sessionId,
    total_egress_bytes: 0,
    request_count: 0,
    destinations: [],
    last_updated: new Date().toISOString(),
  };
}

const MAX_SESSIONS = 50;

function saveSessionState(state: SessionState): void {
  const statePath = getStateFilePath(HOOK_NAME, 'session.json');
  // Use atomicUpdateJsonFile to prevent TOCTOU race conditions
  atomicUpdateJsonFile<Record<string, SessionState>>(
    statePath,
    (current) => {
      current[state.session_id] = state;
      // Evict oldest sessions if over limit to prevent unbounded growth
      const keys = Object.keys(current);
      if (keys.length > MAX_SESSIONS) {
        const sorted = keys.sort((a, b) =>
          (current[a]?.last_updated || '').localeCompare(current[b]?.last_updated || '')
        );
        for (const key of sorted.slice(0, keys.length - MAX_SESSIONS)) {
          delete current[key];
        }
      }
      return current;
    },
    { [state.session_id]: state }
  );
}

// ============================================================================
// Scanning Logic
// ============================================================================

function extractEgressData(toolName: string, toolInput: Record<string, any>): {
  content: string;
  destination: string | null;
  bytes: number;
} {
  let content = '';
  let destination: string | null = null;

  if (toolName === 'WebFetch' || toolName === 'WebSearch') {
    destination = toolInput.url || toolInput.query || null;
    content = JSON.stringify(toolInput);
  } else if (toolName === 'Bash') {
    const cmd = toolInput.command || '';
    content = cmd;

    // Extract URL from curl/wget commands
    const urlMatch = cmd.match(/(?:curl|wget)\s+(?:[^\s]+\s+)*["']?(https?:\/\/[^\s"']+)/i);
    if (urlMatch) {
      destination = urlMatch[1];
    }
  }

  return {
    content,
    destination,
    bytes: Buffer.byteLength(content, 'utf8'),
  };
}

function scanForSecrets(content: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  for (const { name, pattern, severity } of SECRET_PATTERNS) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        name,
        severity,
        match: match[0].substring(0, 20) + '...',
        category: 'SECRET',
      });
    }
  }

  return findings;
}

function scanForPII(content: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  for (const { name, pattern, severity } of PII_PATTERNS) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        name,
        severity,
        match: '[REDACTED]',
        category: 'PII',
      });
    }
  }

  return findings;
}

function checkDestination(destination: string | null): ScanFinding | null {
  if (!destination) return null;

  for (const { pattern, name, severity } of BLOCKED_DESTINATIONS) {
    if (pattern.test(destination)) {
      return {
        name: `Blocked destination: ${name}`,
        severity,
        match: destination.substring(0, 50),
        category: 'DESTINATION',
      };
    }
  }

  return null;
}

function checkBulkExfil(bytes: number, sessionState: SessionState): ScanFinding[] {
  const findings: ScanFinding[] = [];

  // Check single transfer
  if (bytes > SINGLE_TRANSFER_LIMIT) {
    findings.push({
      name: 'Large single transfer',
      severity: 'CRITICAL',
      match: `${(bytes / 1024).toFixed(1)}KB exceeds ${(SINGLE_TRANSFER_LIMIT / 1024)}KB limit`,
      category: 'BULK_EXFIL',
    });
  } else if (bytes > SINGLE_TRANSFER_WARN) {
    findings.push({
      name: 'Large transfer warning',
      severity: 'MEDIUM',
      match: `${(bytes / 1024).toFixed(1)}KB approaching limit`,
      category: 'BULK_EXFIL',
    });
  }

  // Check session cumulative
  const totalAfter = sessionState.total_egress_bytes + bytes;
  if (totalAfter > SESSION_TRANSFER_LIMIT) {
    findings.push({
      name: 'Session egress limit exceeded',
      severity: 'CRITICAL',
      match: `${(totalAfter / 1024 / 1024).toFixed(1)}MB exceeds ${(SESSION_TRANSFER_LIMIT / 1024 / 1024)}MB session limit`,
      category: 'BULK_EXFIL',
    });
  }

  return findings;
}

function checkBase64(content: string): ScanFinding | null {
  // Look for large base64 blobs
  const base64Match = content.match(/[A-Za-z0-9+\/=]{100,}/);
  if (base64Match && base64Match[0].length > BASE64_LIMIT) {
    return {
      name: 'Large base64 blob',
      severity: 'HIGH',
      match: `${base64Match[0].length} bytes encoded data`,
      category: 'BULK_EXFIL',
    };
  }
  return null;
}

// ============================================================================
// Audit Logging
// ============================================================================

function logToAudit(entry: AuditEntry): void {
  try {
    ensureTalonDirs();
    const auditPath = getAuditLogPath(HOOK_NAME);
    secureAppendLog(auditPath, JSON.stringify(entry) + '\n');
  } catch {
    // Silent failure
  }
}

// ============================================================================
// Block/Warn Output
// ============================================================================

function outputBlock(findings: ScanFinding[], destination: string | null): void {
  const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');

  const blockReason = `🛑 TALON L9: Data exfiltration BLOCKED

${destination ? `Destination: ${destination}\n` : ''}
Findings:
${findings.map(f => `  • [${f.severity}] ${f.name}: ${f.match}`).join('\n')}

This egress request has been blocked to prevent:
- Secret/credential leakage
- PII exfiltration
- Bulk data transfer to untrusted destinations

If this is legitimate, verify the destination and content are safe.`;

  console.error('\n┌─────────────────────────────────────────────────────────────┐');
  console.error('│  🛑 TALON L9: EGRESS BLOCKED                                │');
  console.error('├─────────────────────────────────────────────────────────────┤');
  if (destination) {
    console.error(`│  Destination: ${destination.substring(0, 45)}`);
  }
  console.error('│                                                             │');
  for (const finding of criticalFindings.slice(0, 4)) {
    console.error(`│    🚨 ${finding.name.substring(0, 50)}`);
  }
  console.error('│                                                             │');
  console.error('│  ❌ Egress BLOCKED to protect secrets/data                  │');
  console.error('└─────────────────────────────────────────────────────────────┘\n');

  console.log(JSON.stringify({
    decision: 'block',
    reason: blockReason,
  }));
}

// ============================================================================
// Main Hook Logic
// ============================================================================

async function main() {
  try {
    // Check circuit breaker
    const circuit = checkCircuit(HOOK_NAME);
    if (!circuit.shouldExecute) {
      process.exit(0);
    }

    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error('Timeout')), 300)
      ),
    ]);

    if (!input || input.trim() === '') {
      process.exit(0);
    }

    const data: HookInput = JSON.parse(input);

    // Only scan egress tools
    if (!data.tool_name || !EGRESS_TOOLS.includes(data.tool_name)) {
      process.exit(0);
    }

    const toolInput = data.tool_input || {};
    const { content, destination, bytes } = extractEgressData(data.tool_name, toolInput);

    if (bytes < 10) {
      process.exit(0);
    }

    // Load session state
    const sessionState = loadSessionState(data.session_id);

    // Run all scans
    const findings: ScanFinding[] = [];

    findings.push(...scanForSecrets(content));
    findings.push(...scanForPII(content));
    findings.push(...checkBulkExfil(bytes, sessionState));

    const destFinding = checkDestination(destination);
    if (destFinding) findings.push(destFinding);

    const base64Finding = checkBase64(content);
    if (base64Finding) findings.push(base64Finding);

    // Determine severity and action
    const hasCritical = findings.some(f => f.severity === 'CRITICAL');
    const hasHigh = findings.some(f => f.severity === 'HIGH');

    let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE' = 'NONE';
    let action: 'BLOCK' | 'WARN' | 'LOG' = 'LOG';

    if (hasCritical) {
      severity = 'CRITICAL';
      action = 'BLOCK';
    } else if (hasHigh) {
      severity = 'HIGH';
      action = 'WARN';
    } else if (findings.length > 0) {
      severity = 'MEDIUM';
      action = 'LOG';
    }

    // Update session state
    sessionState.total_egress_bytes += bytes;
    sessionState.request_count++;
    if (destination && !sessionState.destinations.includes(destination) && sessionState.destinations.length < 100) {
      sessionState.destinations.push(destination);
    }
    sessionState.last_updated = new Date().toISOString();
    saveSessionState(sessionState);

    // Log to audit
    logToAudit({
      timestamp: new Date().toISOString(),
      tool: data.tool_name,
      session_id: data.session_id,
      egress_bytes: bytes,
      findings,
      severity,
      action,
      destination: destination || undefined,
    });

    // Output block or warning
    if (action === 'BLOCK') {
      outputBlock(findings, destination);
      recordSuccess(HOOK_NAME);
      process.exit(2);
    }

    if (action === 'WARN') {
      const categories = [...new Set(findings.map(f => f.category))];
      const findingNames = findings.slice(0, 3).map(f => f.name).join(', ');
      console.error(`\n⚠️  TALON L9: Egress warning - ${findings.map(f => f.name).join(', ')}\n`);
      console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          additionalContext: `🚨 TALON EGRESS SCANNER (L9) HIGH: Potential data exfiltration detected in ${data.tool_name}. ` +
            `Categories: ${categories.join(', ')}. Findings: ${findingNames}. ` +
            `Session egress: ${(sessionState.total_egress_bytes / 1024).toFixed(1)}KB. Proceeding with caution.`,
        },
      }));
    }

    recordSuccess(HOOK_NAME);
    process.exit(0);
  } catch (error) {
    recordFailure(HOOK_NAME, error instanceof Error ? error.message : 'Unknown error');
    // Fail-closed: block operation if hook crashes (security-first)
    process.exit(2);
  }
}

main();
