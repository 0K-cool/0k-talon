#!/usr/bin/env bun

/**
 * L14: Supply Chain Scanner - PostToolUse Hook
 *
 * Part of 0K-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: Monitor package installations for known malicious packages.
 * Pattern: Sidecar Pattern (monitoring after tool execution)
 *
 * Maps to:
 * - OWASP LLM03 (Supply Chain Vulnerabilities)
 * - MITRE ATLAS AML.T0047 (ML Supply Chain Compromise)
 *
 * @version 0.1.0 (0k-talon)
 * @date 2026-02-04
 */

import { ensureTalonDirs, getAuditLogPath, secureAppendLog } from './lib/talon-paths';
import { loadSupplyChainConfig } from './lib/config-loader';

const HOOK_NAME = 'L14-supply-chain-scanner';

interface HookInput {
  session_id: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
}

// Known compromised packages - hardcoded baseline merged with external config
const HARDCODED_PACKAGES: Record<string, string> = {
  'npm:colors': 'Protestware - infinite loop',
  'npm:faker': 'Protestware - deleted code',
  'npm:event-stream': 'Cryptominer injection',
  'npm:ua-parser-js': 'Cryptominer in specific versions',
  'npm:coa': 'Credential stealer',
  'npm:rc': 'Credential stealer',
  'npm:node-ipc': 'Protestware',
  'npm:crossenv': 'Typosquat of cross-env',
  'npm:mongose': 'Typosquat of mongoose',
  'pypi:colourama': 'Typosquat of colorama',
};

// Merge hardcoded + external config for expanded coverage
function getMaliciousPackages(): Record<string, string> {
  const merged = { ...HARDCODED_PACKAGES };
  try {
    const config = loadSupplyChainConfig();
    if (config.maliciousPackages) {
      for (const pkg of config.maliciousPackages) {
        merged[`${pkg.ecosystem}:${pkg.name}`] = pkg.reason;
      }
    }
  } catch {
    // Config load failed, use hardcoded only
  }
  return merged;
}

const MALICIOUS_PACKAGES = getMaliciousPackages();

function detectPackageManager(cmd: string): 'npm' | 'pypi' | null {
  if (/npm\s+(install|i|add)/i.test(cmd)) return 'npm';
  if (/yarn\s+add/i.test(cmd)) return 'npm';
  if (/pnpm\s+(add|install)/i.test(cmd)) return 'npm';
  if (/pip\s+install/i.test(cmd)) return 'pypi';
  return null;
}

function extractPackages(cmd: string, _ecosystem: string): string[] {
  const packages: string[] = [];
  // Extract package names (simplified)
  const parts = cmd.split(/\s+/);
  let capture = false;
  for (const part of parts) {
    if (/^(install|i|add)$/.test(part)) {
      capture = true;
      continue;
    }
    if (capture && !part.startsWith('-') && part.length > 0) {
      packages.push(part.replace(/@[^@]+$/, '')); // Remove version
    }
  }
  return packages;
}

function checkMalicious(packages: string[], ecosystem: string): Array<{ pkg: string; reason: string }> {
  const detected: Array<{ pkg: string; reason: string }> = [];
  for (const pkg of packages) {
    const key = `${ecosystem}:${pkg.toLowerCase()}`;
    if (MALICIOUS_PACKAGES[key]) {
      detected.push({ pkg, reason: MALICIOUS_PACKAGES[key] });
    }
  }
  return detected;
}

function logToAudit(entry: any): void {
  try {
    ensureTalonDirs();
    secureAppendLog(getAuditLogPath(HOOK_NAME), JSON.stringify(entry) + '\n');
  } catch {}
}

function displayWarning(malicious: Array<{ pkg: string; reason: string }>): void {
  console.error('\n🚨 TALON L14: MALICIOUS PACKAGE DETECTED');
  for (const m of malicious) {
    console.error(`   🔴 ${m.pkg}: ${m.reason}`);
  }
  console.error('   ⚠️  Remove immediately!\n');
}

async function main() {
  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 300)),
    ]);
    if (!input?.trim()) process.exit(0);

    const data: HookInput = JSON.parse(input);
    if (data.tool_name !== 'Bash') process.exit(0);

    const cmd = data.tool_input?.command || '';
    const ecosystem = detectPackageManager(cmd);
    if (!ecosystem) process.exit(0);

    const packages = extractPackages(cmd, ecosystem);
    if (packages.length === 0) process.exit(0);

    const malicious = checkMalicious(packages, ecosystem);

    logToAudit({
      timestamp: new Date().toISOString(),
      session_id: data.session_id,
      command: cmd.substring(0, 100),
      packages,
      malicious: malicious.map(m => m.pkg),
    });

    if (malicious.length > 0) {
      displayWarning(malicious);

      // Output JSON with additionalContext so the AI is aware of malicious packages
      const pkgList = malicious.map(m => `${m.pkg} (${m.reason})`).join('; ');
      console.log(JSON.stringify({
        continue: true,
        hookSpecificOutput: {
          hookEventName: 'PostToolUse',
          additionalContext: `🚨 TALON L14: MALICIOUS PACKAGES DETECTED! ${pkgList}. ` +
            `These packages are KNOWN COMPROMISED. Remove them immediately with '${ecosystem} remove ${malicious.map(m => m.pkg).join(' ')}'. ` +
            `Do NOT continue using these packages.`,
        },
      }));
    } else {
      console.log(JSON.stringify({ continue: true }));
    }

    process.exit(0);
  } catch {
    process.exit(0);
  }
}

main();
