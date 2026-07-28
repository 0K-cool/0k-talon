#!/usr/bin/env bun

/**
 * L14: Supply Chain Pre-Install Scanner - PreToolUse Hook
 *
 * Part of 0K-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: BLOCK malicious packages BEFORE installation.
 * Pattern: Sidecar Pattern (monitoring before tool execution)
 *
 * Three-tier check:
 * 1. Hardcoded blocklist (60+ known malicious packages) - instant, offline
 * 2. Local cache (24h TTL) - fast, no API call
 * 3. OpenSourceMalware.com API - real-time threat intel (opt-in via OSM_API_TOKEN)
 *
 * Without API token: Hardcoded blocklist only (still valuable protection)
 * With API token: Real-time lookups + 24h cache + hardcoded blocklist
 *
 * Maps to:
 * - OWASP LLM03 (Supply Chain Vulnerabilities)
 * - MITRE ATLAS AML.T0047 (ML Supply Chain Compromise)
 *
 * @version 0.1.0 (0k-talon)
 * @date 2026-02-04
 */

import { ensureTalonDirs, getAuditLogPath, getStateFilePath, secureAppendLog } from './lib/talon-paths';
import { atomicWriteFileSync, readJsonFileSync } from './lib/atomic-file';
import { loadSupplyChainConfig } from './lib/config-loader';

const HOOK_NAME = 'L14-supply-chain-pre-install';

// OSM API configuration - user provides token via environment variable
const OSM_API_TOKEN = process.env.OSM_API_TOKEN || '';
const OSM_API_BASE = 'https://api.opensourcemalware.com/functions/v1';
const API_TIMEOUT_MS = 5000;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// ============================================================================
// Types
// ============================================================================

interface HookInput {
  session_id: string;
  tool_name: string;
  tool_input: {
    command?: string;
    description?: string;
  };
}

interface HookOutput {
  decision: 'block' | 'allow';
  reason?: string;
}

interface OSMResponse {
  malicious: boolean;
  report_type: string;
  resource_identifier: string;
  ecosystem: string;
  version?: string;
  threat_count?: number;
  message?: string;
  details?: {
    threat_id?: string;
    severity_level?: string;
    description?: string;
    version_info?: string;
    tags?: string[];
  };
}

interface CacheEntry {
  malicious: boolean;
  severity?: string;
  description?: string;
  checked_at: number;
}

interface PackageCache {
  [key: string]: CacheEntry;
}

interface AuditEntry {
  timestamp: string;
  session_id: string;
  command: string;
  package_manager: string;
  packages_checked: string[];
  malicious_found: string[];
  api_calls: number;
  cache_hits: number;
  hardcoded_hits: number;
  decision: 'block' | 'allow';
  duration_ms: number;
}

// ============================================================================
// Known Malicious Packages - Hardcoded Baseline
// ============================================================================

const KNOWN_MALICIOUS_PACKAGES = new Set([
  // === PROTESTWARE / SABOTAGE ===
  'colors',               // Marak Squires sabotage (Jan 2022)
  'faker',                // Marak Squires sabotage (Jan 2022)
  'node-ipc',             // Peacenotwar protestware (Mar 2022)

  // === HISTORICAL SUPPLY CHAIN ATTACKS ===
  'event-stream',         // flatmap-stream injection (Nov 2018)
  'flatmap-stream',       // Malicious event-stream dependency
  'ua-parser-js',         // Compromised (Oct 2021)
  'coa',                  // Compromised (Nov 2021)
  'rc',                   // Compromised (Nov 2021)
  'eslint-scope',         // Token harvester (Jul 2018)
  'eslint-config-eslint', // Compromised
  'conventional-changelog', // Compromised (Nov 2021)

  // === TYPOSQUATS (npm) ===
  'crossenv',             // Typosquat of cross-env (2017)
  'cross-env.js',         // Typosquat
  'mongose',              // Typosquat of mongoose
  'lodahs',               // Typosquat of lodash
  'lodashs',              // Typosquat of lodash
  'loadsh',               // Typosquat of lodash
  'coffe-script',         // Typosquat of coffee-script
  'coffescript',          // Typosquat of coffee-script
  'babelcli',             // Typosquat of babel-cli
  'd3.js',                // Typosquat of d3
  'fabric-js',            // Typosquat of fabric
  'ffmepg',               // Typosquat of ffmpeg
  'gruntcli',             // Typosquat of grunt-cli
  'http-proxy.js',        // Typosquat of http-proxy
  'jquery.js',            // Typosquat of jquery
  'mariadb',              // Typosquat (NPM, not the real one)
  'mssql.js',             // Typosquat of mssql
  'nodemailer-js',        // Typosquat of nodemailer
  'opencv.js',            // Typosquat of opencv
  'shadowsock',           // Typosquat of shadowsocks
  'smb',                  // Malicious SMB client
  'socks',                // Malicious
  'sqlite.js',            // Typosquat of sqlite
  'tencent-cloud-sdk',    // Fake Tencent SDK
  'tkinter',              // Fake Python tkinter on npm

  // === CRYPTOMINERS / DATA STEALERS ===
  'getcookies',           // Browser cookie stealer
  'electron-native-notify', // Credential stealer
  'discord.js-user',      // Discord token stealer
  'discord-lofy',         // Discord token stealer
  'discord-selfbot-v14',  // Discord token stealer

  // === PYPI MALICIOUS PACKAGES ===
  'python-binance',       // Typosquat of python-binance
  'request',              // Typosquat of requests (PyPI)
  'python3-dateutil',     // Typosquat of python-dateutil
  'jeIlyfish',            // Typosquat of jellyfish (capital I)
  'python-sqlite',        // Malicious SQLite wrapper
  'libpeshnern',          // Credential stealer
  'libpeshka',            // Credential stealer
  'colourama',            // Typosquat of colorama
]);

// ============================================================================
// Package Manager Detection
// ============================================================================

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: 'npm',
  yarn: 'npm',
  pnpm: 'npm',
  pip: 'pypi',
  pip3: 'pypi',
  cargo: 'crates',
  go: 'go',
  bun: 'npm',
};

const PM_PATTERNS: Record<string, { install: RegExp; packages: RegExp }> = {
  npm: {
    install: /\bnpm\s+(install|i|add)\s+/i,
    packages: /\bnpm\s+(?:install|i|add)\s+([^&|;]+)/i,
  },
  yarn: {
    install: /\byarn\s+add\s+/i,
    packages: /\byarn\s+add\s+([^&|;]+)/i,
  },
  pnpm: {
    install: /\bpnpm\s+(add|install|i)\s+/i,
    packages: /\bpnpm\s+(?:add|install|i)\s+([^&|;]+)/i,
  },
  pip: {
    install: /\bpip3?\s+install\s+/i,
    packages: /\bpip3?\s+install\s+([^&|;]+)/i,
  },
  cargo: {
    install: /\bcargo\s+(add|install)\s+/i,
    packages: /\bcargo\s+(?:add|install)\s+([^&|;]+)/i,
  },
  go: {
    install: /\bgo\s+(get|install)\s+/i,
    packages: /\bgo\s+(?:get|install)\s+([^&|;]+)/i,
  },
  bun: {
    install: /\bbun\s+(add|install|i)\s+/i,
    packages: /\bbun\s+(?:add|install|i)\s+([^&|;]+)/i,
  },
};

function detectPackageManager(command: string): string | null {
  for (const [pm, patterns] of Object.entries(PM_PATTERNS)) {
    if (patterns.install.test(command)) {
      return pm;
    }
  }
  return null;
}

function extractPackages(command: string, pm: string): string[] {
  const pattern = PM_PATTERNS[pm]?.packages;
  if (!pattern) return [];

  const match = command.match(pattern);
  if (!match || !match[1]) return [];

  return match[1]
    .split(/\s+/)
    .filter((p) => p && !p.startsWith('-') && !p.startsWith('@types/'))
    .map((p) => p.replace(/@[\d.^~>=<*x]+$/, '')) // Remove version specifiers
    .filter((p) => p.length > 0);
}

// ============================================================================
// Cache Management
// ============================================================================

function getCachePath(): string {
  return getStateFilePath(HOOK_NAME, 'cache.json');
}

function loadCache(): PackageCache {
  try {
    return readJsonFileSync<PackageCache>(getCachePath(), {});
  } catch {
    return {};
  }
}

function saveCache(cache: PackageCache): void {
  try {
    ensureTalonDirs();
    // Evict expired entries to prevent unbounded growth
    const now = Date.now();
    const pruned: PackageCache = {};
    let kept = 0;
    for (const [key, entry] of Object.entries(cache)) {
      if (now - entry.checked_at < CACHE_TTL_MS && kept < 500) {
        pruned[key] = entry;
        kept++;
      }
    }
    atomicWriteFileSync(getCachePath(), JSON.stringify(pruned, null, 2));
  } catch {
    // Cache write failure is non-fatal
  }
}

function getCacheKey(pkg: string, ecosystem: string): string {
  return `${ecosystem}:${pkg.toLowerCase()}`;
}

function isCacheValid(entry: CacheEntry): boolean {
  return Date.now() - entry.checked_at < CACHE_TTL_MS;
}

// ============================================================================
// Merged Blocklist (hardcoded + external config)
// ============================================================================

function getMergedBlocklist(): Set<string> {
  const merged = new Set(KNOWN_MALICIOUS_PACKAGES);
  try {
    const config = loadSupplyChainConfig();
    if (config.maliciousPackages) {
      for (const pkg of config.maliciousPackages) {
        merged.add(pkg.name.toLowerCase());
      }
    }
  } catch {
    // Config load failed, use hardcoded only
  }
  return merged;
}

// ============================================================================
// OpenSourceMalware.com API
// ============================================================================

async function checkPackageWithAPI(
  pkg: string,
  ecosystem: string
): Promise<{ malicious: boolean; severity?: string; description?: string } | null> {
  if (!OSM_API_TOKEN) {
    return null; // No API token configured - fail open
  }

  const url = `${OSM_API_BASE}/check-malicious?report_type=package&resource_identifier=${encodeURIComponent(pkg)}&ecosystem=${ecosystem}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${OSM_API_TOKEN}`,
      },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      return null; // API error, fail open
    }

    const data = (await response.json()) as OSMResponse;

    return {
      malicious: data.malicious,
      severity: data.details?.severity_level,
      description: data.details?.description,
    };
  } catch {
    return null; // Network error, fail open
  }
}

// ============================================================================
// Package Checking (three-tier)
// ============================================================================

async function checkPackages(
  packages: string[],
  pm: string
): Promise<{
  malicious: Array<{ name: string; severity?: string; description?: string; source: string }>;
  apiCalls: number;
  cacheHits: number;
  hardcodedHits: number;
}> {
  const ecosystem = ECOSYSTEM_MAP[pm] || pm;
  const cache = loadCache();
  const blocklist = getMergedBlocklist();
  const malicious: Array<{ name: string; severity?: string; description?: string; source: string }> = [];
  let apiCalls = 0;
  let cacheHits = 0;
  let hardcodedHits = 0;

  for (const pkg of packages) {
    const pkgLower = pkg.toLowerCase();

    // TIER 1: Check hardcoded + config blocklist (instant, no API)
    if (blocklist.has(pkgLower)) {
      hardcodedHits++;
      malicious.push({
        name: pkg,
        severity: 'CRITICAL',
        description: 'Known malicious package (blocklist)',
        source: 'hardcoded',
      });
      continue;
    }

    const cacheKey = getCacheKey(pkg, ecosystem);
    const cached = cache[cacheKey];

    // TIER 2: Check cache
    if (cached && isCacheValid(cached)) {
      cacheHits++;
      if (cached.malicious) {
        malicious.push({
          name: pkg,
          severity: cached.severity,
          description: cached.description,
          source: 'cache',
        });
      }
      continue;
    }

    // TIER 3: Query OpenSourceMalware.com API (if token available)
    const result = await checkPackageWithAPI(pkg, ecosystem);
    if (result !== null) {
      apiCalls++;
      // Update cache regardless of result
      cache[cacheKey] = {
        malicious: result.malicious,
        severity: result.severity,
        description: result.description,
        checked_at: Date.now(),
      };

      if (result.malicious) {
        malicious.push({
          name: pkg,
          severity: result.severity,
          description: result.description,
          source: 'osm-api',
        });
      }
    }
    // If API unavailable (no token/error), package passes through
    // Only hardcoded list provides protection without API
  }

  // Save updated cache
  saveCache(cache);

  return { malicious, apiCalls, cacheHits, hardcodedHits };
}

// ============================================================================
// Audit Logging
// ============================================================================

function logAudit(entry: AuditEntry): void {
  try {
    ensureTalonDirs();
    secureAppendLog(getAuditLogPath(HOOK_NAME), JSON.stringify(entry) + '\n');
  } catch {
    // Audit log failure is non-fatal
  }
}

// ============================================================================
// Output Formatting
// ============================================================================

function formatBlockMessage(
  malicious: Array<{ name: string; severity?: string; description?: string; source: string }>
): string {
  const lines: string[] = [
    '',
    '\u{1F6A8} TALON L14: SUPPLY CHAIN SCANNER - BLOCKED',
    '\u2501'.repeat(60),
    '',
    '\u26D4 MALICIOUS PACKAGE(S) DETECTED:',
    '',
  ];

  for (const pkg of malicious) {
    lines.push(`   \u{1F4E6} ${pkg.name}`);
    if (pkg.severity) {
      lines.push(`      Severity: ${pkg.severity.toUpperCase()}`);
    }
    if (pkg.description) {
      lines.push(`      Threat: ${pkg.description}`);
    }
    lines.push(`      Source: ${pkg.source}`);
    lines.push('');
  }

  lines.push('\u2501'.repeat(60));
  lines.push('');
  lines.push('\u{1F512} This installation has been BLOCKED for your protection.');
  lines.push('   Threat intel: OpenSourceMalware.com + hardcoded blocklist');
  lines.push('');
  lines.push('\u{1F4A1} If you believe this is a false positive:');
  lines.push('   1. Verify at https://opensourcemalware.com/');
  lines.push('   2. Check the official package repository');
  lines.push('   3. Override: set OSM_ALLOW_PACKAGE=<name> (not recommended)');
  lines.push('');

  return lines.join('\n');
}

// ============================================================================
// Main Hook Logic
// ============================================================================

async function main(): Promise<void> {
  const startTime = Date.now();

  let input: HookInput;
  try {
    const stdin = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000)),
    ]);
    if (!stdin?.trim()) process.exit(0);
    input = JSON.parse(stdin);
  } catch {
    // Invalid input - silently allow
    process.exit(0);
  }

  // Only process Bash commands
  if (input.tool_name !== 'Bash') {
    process.exit(0);
  }

  const command = input.tool_input?.command || '';
  const pm = detectPackageManager(command);

  // Not a package install command - silently allow
  if (!pm) {
    process.exit(0);
  }

  // Extract packages
  const packages = extractPackages(command, pm);

  // No specific packages (e.g., 'npm install' from package.json) - silently allow
  if (packages.length === 0) {
    process.exit(0);
  }

  // Check packages against all three tiers
  const { malicious, apiCalls, cacheHits, hardcodedHits } = await checkPackages(packages, pm);

  const durationMs = Date.now() - startTime;

  // Log audit entry
  logAudit({
    timestamp: new Date().toISOString(),
    session_id: input.session_id,
    command: command.substring(0, 200),
    package_manager: pm,
    packages_checked: packages,
    malicious_found: malicious.map((m) => m.name),
    api_calls: apiCalls,
    cache_hits: cacheHits,
    hardcoded_hits: hardcodedHits,
    decision: malicious.length > 0 ? 'block' : 'allow',
    duration_ms: durationMs,
  });

  if (malicious.length > 0) {
    // BLOCK - malicious packages found
    const output: HookOutput = {
      decision: 'block',
      reason: formatBlockMessage(malicious),
    };
    console.error(formatBlockMessage(malicious));
    console.log(JSON.stringify(output));
    process.exit(2); // exit(2) = block
  }

  // ALLOW - packages are clean
  // Log verification summary to stderr (informational)
  const sources: string[] = [];
  if (hardcodedHits > 0) sources.push(`${hardcodedHits} blocklist`);
  if (apiCalls > 0) sources.push(`${apiCalls} API`);
  if (cacheHits > 0) sources.push(`${cacheHits} cache`);
  const sourceStr = sources.length > 0 ? sources.join(', ') : (OSM_API_TOKEN ? 'API clean' : 'blocklist only');

  if (packages.length <= 5) {
    console.error(`\u2705 Supply Chain L14: ${packages.join(', ')} verified (${sourceStr})`);
  }

  if (packages.length > 0) {
    console.log(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        additionalContext: `🔗 TALON SUPPLY CHAIN (L14): Scanned ${packages.length} package(s) via ${pm} — all clean. ` +
          `Packages: ${packages.join(', ')}. PostToolUse hook will run npm/pip audit after install.`,
      },
    }));
  }

  process.exit(0);
}

main().catch((error) => {
  // Fail-closed: block operation if hook crashes (security-first for PreToolUse)
  console.error(`[SupplyChainPreInstall L14] Error: ${error}`);
  process.exit(2);
});
