#!/usr/bin/env node
/**
 * 0K-Talon Unified Security Config Loader
 * @version 0.1.0
 */

import { existsSync, readFileSync, statSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { isRedosVulnerable } from '../hooks/lib/redos-guard';

export interface ConfigMetadata {
  version: string;
  lastUpdated: string;
  source?: string;
  description?: string;
}

export interface SecurityConfig<T> {
  metadata: ConfigMetadata;
  patterns: T;
}

export interface InjectionPattern {
  id: string;
  category: 'instruction_override' | 'jailbreak' | 'encoding' | 'context_manipulation';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pattern: string;
  description: string;
  examples?: string[];
}

export interface InjectionConfig extends SecurityConfig<InjectionPattern[]> {}

export interface VulnerabilityPattern {
  id: string;
  pattern: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  remediation?: string;
  owaspMapping?: string;
}

export interface CodeEnforcerConfig extends SecurityConfig<{
  sqlInjection: VulnerabilityPattern[];
  commandInjection: VulnerabilityPattern[];
  secretPatterns: VulnerabilityPattern[];
  pathTraversal: VulnerabilityPattern[];
  unsafeDeserialization: VulnerabilityPattern[];
  promptInjection: VulnerabilityPattern[];
  xssVectors: VulnerabilityPattern[];
  weakCrypto: VulnerabilityPattern[];
  authPatterns: VulnerabilityPattern[];
  codeExtensions?: Record<string, string>;
}> {
  skipPaths?: string[];
}

export interface MaliciousPackage {
  name: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  severity: 'CRITICAL' | 'HIGH';
  reason: string;
  dateAdded: string;
}

export interface SupplyChainConfig extends SecurityConfig<{
  maliciousPackages: MaliciousPackage[];
  trustedRegistries: string[];
  auditThresholds: { critical: number; high: number; moderate: number };
}> {}

const configCache = new Map<string, { config: unknown; loadedAt: number; fileMtime: number }>();
const CACHE_TTL_MS = 60000;

function getConfigBasePath(): string {
  const customPath = process.env.OK_TALON_CONFIG_PATH;
  if (customPath) {
    // Validate: must be absolute, no traversal, under HOME or CWD
    const resolved = resolve(customPath);
    const home = process.env.HOME || '';
    const cwd = process.cwd();
    if (resolved.includes('..') || (!resolved.startsWith(home) && !resolved.startsWith(cwd))) {
      console.error(`[ConfigLoader] OK_TALON_CONFIG_PATH rejected: must be under HOME or CWD. Using default.`);
    } else {
      return resolved;
    }
  }
  // The working directory is deliberately NOT consulted: a workspace that
  // could supply its own detection config could switch detection off. See
  // hooks/lib/talon-paths.ts for the same boundary on the loader hooks use.
  return join(dirname(__dirname), 'configs');
}

const CONFIG_BASE_PATH = getConfigBasePath();

export function loadConfig<T>(configPath: string, defaultConfig: T): T {
  const fullPath = join(CONFIG_BASE_PATH, configPath);
  const cached = configCache.get(fullPath);
  if (cached && Date.now() - cached.loadedAt < CACHE_TTL_MS) {
    try {
      if (statSync(fullPath).mtimeMs === cached.fileMtime) return cached.config as T;
    } catch { return cached.config as T; }
  }
  if (existsSync(fullPath)) {
    try {
      const parsed = JSON.parse(readFileSync(fullPath, 'utf-8'));
      const stat = statSync(fullPath);
      configCache.set(fullPath, { config: parsed, loadedAt: Date.now(), fileMtime: stat.mtimeMs });
      return parsed as T;
    } catch { /* fall through */ }
  }
  configCache.set(fullPath, { config: defaultConfig, loadedAt: Date.now(), fileMtime: 0 });
  return defaultConfig;
}

export function clearConfigCache(): void { configCache.clear(); }

const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

/**
 * Validate loaded config patterns at runtime.
 * Checks: non-empty pattern string, valid severity, regex compilation, ReDoS heuristic.
 * Returns filtered array with invalid entries removed, or empty if all invalid.
 */
export function validatePatterns<T extends { pattern: string; severity?: string }>(
  patterns: T[],
  configName: string
): T[] {
  if (!Array.isArray(patterns)) return [];
  return patterns.filter((p, i) => {
    if (!p.pattern || typeof p.pattern !== 'string') return false;
    if (p.severity && !VALID_SEVERITIES.has(p.severity)) return false;
    try { new RegExp(p.pattern, 'gi'); } catch { return false; }
    // ReDoS guard: reject nested UNBOUNDED quantifiers. Fail LOUD — a dropped
    // pattern is a coverage gap to rewrite, never a silent disappearance.
    if (isRedosVulnerable(p.pattern)) {
      console.error(
        `🛑 [ConfigLoader] ${configName}[${i}]: DROPPED ReDoS-vulnerable pattern (nested unbounded quantifier): ${p.pattern.slice(0, 80)} — rewrite with bounded quantifiers to restore coverage.`
      );
      return false;
    }
    return true;
  });
}

export function compilePattern(pattern: string, flags = 'gi'): RegExp {
  return new RegExp(pattern, flags);
}

export function loadInjectionConfig(): InjectionConfig {
  return loadConfig('injection/patterns.json', {
    metadata: { version: '0.1.0', lastUpdated: '2026-02-03', description: '0K-Talon defaults' },
    patterns: [],
  });
}

export function loadCodeEnforcerConfig(): CodeEnforcerConfig {
  return loadConfig('code-enforcer/patterns.json', {
    metadata: { version: '0.1.0', lastUpdated: '2026-02-03', description: '0K-Talon defaults' },
    patterns: {
      sqlInjection: [], commandInjection: [], secretPatterns: [], pathTraversal: [],
      unsafeDeserialization: [], promptInjection: [], xssVectors: [], weakCrypto: [], authPatterns: [],
    },
  });
}

export function loadSupplyChainConfig(): SupplyChainConfig {
  return loadConfig('supply-chain/config.json', {
    metadata: { version: '0.1.0', lastUpdated: '2026-02-03', description: '0K-Talon defaults' },
    patterns: {
      maliciousPackages: [],
      trustedRegistries: ['registry.npmjs.org', 'pypi.org', 'crates.io'],
      auditThresholds: { critical: 0, high: 0, moderate: 5 },
    },
  });
}

export { CONFIG_BASE_PATH };
