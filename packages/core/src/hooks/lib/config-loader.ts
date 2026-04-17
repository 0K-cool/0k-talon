/**
 * 0K-Talon Config Loader
 *
 * Loads security configurations from external JSON files with bundled defaults.
 * Part of the 0k-talon plugin - portable security for Claude Code.
 *
 * @version 0.1.0
 * @date 2026-02-04
 */

import { existsSync, readFileSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { CONFIG_DIR } from './talon-paths';

// ============================================================================
// Types
// ============================================================================

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

// Injection Patterns
export type PatternTier = 'plugin' | 'full';

export interface InjectionPattern {
  id: string;
  category: 'instruction_override' | 'jailbreak' | 'encoding' | 'context_manipulation';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pattern: string;
  description: string;
  examples?: string[];
  source?: string;
  /**
   * Pattern tier (plugin=default, full=opt-in). Absent = plugin (safest default).
   * Set by classify-injection-tiers.py at build time.
   */
  tier?: PatternTier;
}

/**
 * Resolve the active pattern tier from OK_TALON_PATTERN_TIER env var.
 * Default: 'plugin' — matches the blog's "200+ out of the box" promise
 * and minimizes FP noise for new adopters.
 *
 * Set OK_TALON_PATTERN_TIER=full to opt into the expanded 454-pattern set
 * (includes broad NOVA single-word rules and LOW-severity 0din patterns).
 */
export function getActivePatternTier(): PatternTier {
  const envTier = (process.env.OK_TALON_PATTERN_TIER || 'plugin').toLowerCase();
  return envTier === 'full' ? 'full' : 'plugin';
}

/**
 * Filter patterns by active tier. Rules:
 *  - Active tier 'full': keep all patterns regardless of tier field
 *  - Active tier 'plugin': keep only patterns with tier='plugin' OR missing tier
 *    (missing tier defaults to plugin for backward-compat with manual patterns)
 */
export function filterByTier<T extends { tier?: PatternTier }>(
  patterns: T[],
  active: PatternTier,
): T[] {
  if (active === 'full') return patterns;
  return patterns.filter((p) => p.tier === undefined || p.tier === 'plugin');
}

// Code Enforcer Patterns
export interface VulnerabilityPattern {
  id: string;
  pattern: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  remediation?: string;
  owaspMapping?: string;
  atlasMapping?: string;
}

// Egress Scanner Types
export interface SecretPattern {
  name: string;
  pattern: string;
  severity: 'CRITICAL' | 'HIGH';
  description?: string;
}

export interface BlockedDestination {
  pattern: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description?: string;
}

// Supply Chain Types
export interface MaliciousPackage {
  name: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  severity: 'CRITICAL' | 'HIGH';
  reason: string;
}

// ============================================================================
// Config Cache
// ============================================================================

interface CacheEntry<T> {
  config: T;
  loadedAt: number;
  fileMtime: number;
}

const configCache = new Map<string, CacheEntry<unknown>>();
const CACHE_TTL_MS = 60000; // 1 minute

// ============================================================================
// Config Paths
// ============================================================================

// Look for configs in multiple locations. Both paths are tried per-file
// by loadConfig (via userOverrideOrBundled), so a user override populates
// ONLY the files they actually drop in — other files still load from the
// bundled package. This matters because `ensureDirectories()` creates
// CONFIG_DIR eagerly, so the directory existing doesn't imply it has
// real content.
function getConfigBasePath(): string {
  // Kept for backward compatibility — new loadConfig path resolves
  // per-file via resolveConfigFile() below.
  const bundledPath = join(dirname(__dirname), 'config');
  if (existsSync(bundledPath)) return bundledPath;
  return CONFIG_DIR;
}

// Per-file resolver: prefer user-provided override at CONFIG_DIR, fall
// back to bundled package path. Returns an absolute path or null if
// the file exists in neither location.
function resolveConfigFile(relativePath: string): string | null {
  const userPath = join(CONFIG_DIR, relativePath);
  if (existsSync(userPath)) return userPath;
  const bundledPath = join(dirname(__dirname), 'config', relativePath);
  if (existsSync(bundledPath)) return bundledPath;
  return null;
}

// ============================================================================
// Core Loader
// ============================================================================

export function loadConfig<T>(
  configPath: string,
  defaultConfig: T
): T {
  const fullPath = resolveConfigFile(configPath);
  // Cache key: resolved file path when found, relative path on miss.
  // This lets the miss case cache a sentinel so repeated failed lookups
  // don't re-probe the filesystem within the TTL window.
  const cacheKey = fullPath || configPath;

  // Cache check — runs BEFORE the miss-path early return so the miss
  // cache actually gets consulted. mtime check only applies to hits.
  const cached = configCache.get(cacheKey) as CacheEntry<T> | undefined;
  if (cached) {
    const now = Date.now();
    if (now - cached.loadedAt < CACHE_TTL_MS) {
      if (!fullPath) return cached.config; // miss sentinel still fresh
      try {
        const stat = statSync(fullPath);
        if (stat.mtimeMs === cached.fileMtime) {
          return cached.config;
        }
      } catch {
        return cached.config;
      }
    }
  }

  if (!fullPath) {
    return cacheAndReturn(cacheKey, defaultConfig, 0);
  }

  try {
    const content = readFileSync(fullPath, 'utf-8');
    const parsed = JSON.parse(content);
    const stat = statSync(fullPath);
    return cacheAndReturn(fullPath, parsed as T, stat.mtimeMs);
  } catch (error) {
    console.error(`[ConfigLoader] Error loading ${configPath}, using defaults`);
    return cacheAndReturn(fullPath, defaultConfig, 0);
  }
}

function cacheAndReturn<T>(path: string, config: T, mtime: number): T {
  configCache.set(path, {
    config,
    loadedAt: Date.now(),
    fileMtime: mtime,
  });
  return config;
}

export function clearConfigCache(): void {
  configCache.clear();
}

// ============================================================================
// Runtime Validation
// ============================================================================

const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const VALID_CATEGORIES = new Set([
  'instruction_override',
  'jailbreak',
  'encoding',
  'context_manipulation',
]);

/**
 * Validate a loaded config has expected structure.
 * Returns sanitized config or null if invalid.
 *
 * Checks:
 * - patterns array/object exists and has expected shape
 * - severity values are from known enum
 * - regex patterns compile without error and aren't ReDoS-prone
 */
export function validatePatterns<T extends { pattern: string; severity?: string; category?: string }>(
  patterns: T[],
  configName: string
): T[] {
  if (!Array.isArray(patterns)) {
    console.error(`[ConfigLoader] ${configName}: patterns is not an array, using defaults`);
    return [];
  }

  return patterns.filter((p, i) => {
    // Verify pattern field exists and is a non-empty string
    if (!p.pattern || typeof p.pattern !== 'string') {
      console.error(`[ConfigLoader] ${configName}[${i}]: missing or invalid pattern field, skipping`);
      return false;
    }

    // Verify severity is valid if present
    if (p.severity && !VALID_SEVERITIES.has(p.severity)) {
      console.error(`[ConfigLoader] ${configName}[${i}]: invalid severity "${p.severity}", skipping`);
      return false;
    }

    // Verify category is valid if present (silent typos like "jailbreaks"
    // would otherwise load but fail category-based filtering downstream).
    if (p.category && !VALID_CATEGORIES.has(p.category)) {
      console.error(`[ConfigLoader] ${configName}[${i}]: invalid category "${p.category}", skipping`);
      return false;
    }

    // Test regex compiles and isn't suspiciously complex (ReDoS heuristic)
    try {
      new RegExp(p.pattern, 'gi');
    } catch {
      console.error(`[ConfigLoader] ${configName}[${i}]: invalid regex "${p.pattern}", skipping`);
      return false;
    }

    // ReDoS heuristic: reject patterns with nested quantifiers like (a+)+ or (a*)*
    if (/(\+|\*|\{)\)(\+|\*|\{)/.test(p.pattern) || /(\+|\*)\{/.test(p.pattern)) {
      console.error(`[ConfigLoader] ${configName}[${i}]: potential ReDoS pattern detected, skipping`);
      return false;
    }

    return true;
  });
}

// ============================================================================
// Pattern Converters
// ============================================================================

export function compilePatterns<T extends { pattern: string }>(
  patterns: T[]
): (T & { compiledPattern: RegExp })[] {
  return patterns.map(p => ({
    ...p,
    compiledPattern: new RegExp(p.pattern, 'gi'),
  }));
}

export function compilePattern(pattern: string, flags = 'gi'): RegExp {
  return new RegExp(pattern, flags);
}

// ============================================================================
// Bundled Default Patterns (Core set for plugin)
// ============================================================================

// Critical injection patterns (bundled)
const DEFAULT_INJECTION_PATTERNS: InjectionPattern[] = [
  {
    id: 'INJ-001',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: 'ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions?|rules?|directives?)',
    description: 'Instruction override attempt',
  },
  {
    id: 'INJ-002',
    category: 'jailbreak',
    severity: 'CRITICAL',
    pattern: 'you\\s+are\\s+(now|no\\s+longer)\\s+(DAN|a\\s+new\\s+AI|unrestricted)',
    description: 'Role hijacking/DAN jailbreak',
  },
  {
    id: 'INJ-003',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: 'system\\s*:\\s*you\\s+are|<\\|?system\\|?>',
    description: 'System prompt injection',
  },
  {
    id: 'INJ-004',
    category: 'context_manipulation',
    severity: 'HIGH',
    pattern: '(begin|start)\\s+(new\\s+)?(conversation|session|context)',
    description: 'Context reset attempt',
  },
  {
    id: 'INJ-005',
    category: 'encoding',
    severity: 'HIGH',
    pattern: 'base64\\s*decode|atob\\s*\\(|from\\s*base64',
    description: 'Encoding bypass attempt',
  },
  {
    id: 'INJ-006',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: '</?(user|assistant|system)>|\\[/?INST\\]',
    description: 'Message boundary injection',
  },
  {
    id: 'INJ-007',
    category: 'jailbreak',
    severity: 'HIGH',
    pattern: 'pretend\\s+(to\\s+be|you\\s+are)|act\\s+as\\s+if|roleplay\\s+as',
    description: 'Role manipulation',
  },
  {
    id: 'INJ-008',
    category: 'instruction_override',
    severity: 'HIGH',
    pattern: 'disregard\\s+(your|all|the)\\s+(instructions|rules|guidelines)',
    description: 'Instruction disregard command',
  },
];

// Critical code patterns (bundled)
const DEFAULT_CODE_PATTERNS = {
  sqlInjection: [
    {
      id: 'SQL-001',
      pattern: 'execute\\s*\\(\\s*["\']\\s*SELECT.*\\+|format\\s*\\(.*SELECT',
      severity: 'CRITICAL' as const,
      description: 'SQL injection via string concatenation',
      remediation: 'Use parameterized queries with placeholders',
      owaspMapping: 'A03:2021 Injection',
    },
  ],
  commandInjection: [
    {
      id: 'CMD-001',
      pattern: 'subprocess.*shell\\s*=\\s*True|os\\.system\\s*\\(|exec\\s*\\([^)]*\\$',
      severity: 'CRITICAL' as const,
      description: 'Command injection via shell execution',
      remediation: 'Use subprocess with shell=False and argument list',
      owaspMapping: 'A03:2021 Injection',
    },
  ],
  secretPatterns: [
    {
      id: 'SEC-001',
      pattern: '(api[_-]?key|secret|password|token)\\s*[=:]\\s*["\'][^"\']{8,}["\']',
      severity: 'CRITICAL' as const,
      description: 'Hardcoded secret detected',
      remediation: 'Use environment variables or secret management',
      owaspMapping: 'A02:2021 Cryptographic Failures',
    },
  ],
  pathTraversal: [
    {
      id: 'PATH-001',
      pattern: '\\.\\.\\/|\\.\\.\\\\',
      severity: 'HIGH' as const,
      description: 'Path traversal pattern',
      remediation: 'Validate and sanitize file paths',
      owaspMapping: 'A01:2021 Broken Access Control',
    },
  ],
};

// Egress scanner defaults
const DEFAULT_SECRET_PATTERNS: SecretPattern[] = [
  { name: 'AWS Key', pattern: 'AKIA[0-9A-Z]{16}', severity: 'CRITICAL' },
  { name: 'GitHub Token', pattern: 'gh[pousr]_[A-Za-z0-9_]{36,255}', severity: 'CRITICAL' },
  { name: 'Generic API Key', pattern: 'api[_-]?key["\']?\\s*[:=]\\s*["\'][^"\']{20,}', severity: 'HIGH' },
  { name: 'Private Key', pattern: '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', severity: 'CRITICAL' },
  { name: 'JWT', pattern: 'eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_.+/=]*', severity: 'HIGH' },
];

const DEFAULT_BLOCKED_DESTINATIONS: BlockedDestination[] = [
  { pattern: 'pastebin\\.com', name: 'Pastebin', severity: 'CRITICAL' },
  { pattern: 'webhook\\.site', name: 'Webhook.site', severity: 'CRITICAL' },
  { pattern: '\\.ngrok\\.io', name: 'Ngrok', severity: 'HIGH' },
  { pattern: 'requestbin\\.', name: 'RequestBin', severity: 'HIGH' },
  { pattern: '^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', name: 'Raw IP', severity: 'HIGH' },
];

// Supply chain defaults
const DEFAULT_MALICIOUS_PACKAGES: MaliciousPackage[] = [
  { name: 'colors', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Protestware - infinite loop' },
  { name: 'faker', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Protestware - deleted code' },
  { name: 'event-stream', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Cryptominer injection' },
  { name: 'ua-parser-js', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Cryptominer in v0.7.29' },
  { name: 'coa', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Compromised - credential stealer' },
  { name: 'rc', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Compromised - credential stealer' },
];

// ============================================================================
// Specialized Loaders
// ============================================================================

/**
 * Merge injection patterns from three sources with first-wins ID and
 * pattern-string precedence: manual > NOVA > 0din.
 *
 * Exposed for test isolation — lets tests verify the collision
 * invariant with synthetic inputs rather than mutating real JSON files.
 */
export function mergeInjectionPatterns(
  manual: InjectionPattern[],
  nova: InjectionPattern[],
  odin: InjectionPattern[],
): InjectionPattern[] {
  const seenIds = new Set<string>();
  const seenPatterns = new Set<string>();
  const merged: InjectionPattern[] = [];

  const push = (list: InjectionPattern[]) => {
    for (const p of list) {
      if (seenIds.has(p.id)) continue;
      if (seenPatterns.has(p.pattern)) continue;
      seenIds.add(p.id);
      seenPatterns.add(p.pattern);
      merged.push(p);
    }
  };

  push(manual);
  push(nova);
  push(odin);
  return merged;
}

/**
 * Load and merge injection patterns from three sources:
 *   1. injection/patterns.json   (manual, highest priority)
 *   2. injection/nova-translated.json (NOVA framework, auto-translated)
 *   3. injection/0din-translated.json (0din disclosures, auto-translated)
 *
 * Precedence on ID collision: manual > NOVA > 0din (first-wins).
 * Each source is independently validated; invalid patterns are dropped.
 * Falls back to DEFAULT_INJECTION_PATTERNS when all sources are empty.
 *
 * Mirrors PAI's config-loader.ts:335-399 algorithm.
 */
export function loadInjectionPatterns(): InjectionPattern[] {
  // Manual patterns (may not exist — default to bundled 8)
  const manualConfig = loadConfig<{ patterns: InjectionPattern[] }>(
    'injection/patterns.json',
    { patterns: DEFAULT_INJECTION_PATTERNS }
  );
  const manualPatterns = validatePatterns(
    manualConfig.patterns || DEFAULT_INJECTION_PATTERNS,
    'injection/patterns.json'
  );

  // NOVA-translated patterns (auto-translated from NOVA Framework rules)
  const novaConfig = loadConfig<{ patterns: InjectionPattern[] }>(
    'injection/nova-translated.json',
    { patterns: [] }
  );
  const novaValidated = validatePatterns(
    novaConfig.patterns || [],
    'injection/nova-translated.json'
  );

  // 0din-translated patterns (auto-translated from 0din.ai disclosures)
  const odinConfig = loadConfig<{ patterns: InjectionPattern[] }>(
    'injection/0din-translated.json',
    { patterns: [] }
  );
  const odinValidated = validatePatterns(
    odinConfig.patterns || [],
    'injection/0din-translated.json'
  );

  // Tier filter BEFORE merge — reduces dedup work and keeps contract clear:
  // plugin tier = ~200 curated patterns out-of-box (blog claim)
  // full tier = ~450 with experimental NOVA/0din broad patterns
  const activeTier = getActivePatternTier();
  const novaTiered = filterByTier(novaValidated, activeTier);
  const odinTiered = filterByTier(odinValidated, activeTier);

  // Exposed as a pure function so tests can verify the collision
  // precedence invariant with synthetic inputs.
  const merged = mergeInjectionPatterns(manualPatterns, novaTiered, odinTiered);
  const novaPatterns = novaTiered.filter(
    (p) => !manualPatterns.some(m => m.id === p.id || m.pattern === p.pattern),
  );
  const odinPatterns = odinTiered.filter(
    (p) =>
      !manualPatterns.some(m => m.id === p.id || m.pattern === p.pattern) &&
      !novaPatterns.some(n => n.id === p.id || n.pattern === p.pattern),
  );

  // Fallback to bundled defaults only if ALL sources are empty
  if (merged.length === 0) {
    return DEFAULT_INJECTION_PATTERNS;
  }

  // One-time info log when external sources contributed patterns.
  // Counts reflect after-dedup contribution (fewer than raw file count
  // when JSON had ID or pattern-string duplicates).
  if (novaPatterns.length > 0 || odinPatterns.length > 0) {
    const stats = [
      `${manualPatterns.length} manual`,
      novaPatterns.length > 0 ? `${novaPatterns.length} NOVA` : null,
      odinPatterns.length > 0 ? `${odinPatterns.length} 0din` : null,
    ]
      .filter(Boolean)
      .join(' + ');
    console.error(
      `[ConfigLoader] Loaded ${stats} = ${merged.length} total injection patterns`
    );
  }

  return merged;
}

export function loadCodeEnforcerPatterns(): typeof DEFAULT_CODE_PATTERNS {
  const config = loadConfig<{ patterns: typeof DEFAULT_CODE_PATTERNS }>(
    'code-enforcer/patterns.json',
    { patterns: DEFAULT_CODE_PATTERNS }
  );
  const raw = config.patterns || DEFAULT_CODE_PATTERNS;
  // Validate each category's patterns
  for (const key of Object.keys(raw) as (keyof typeof raw)[]) {
    const patterns = raw[key];
    if (Array.isArray(patterns)) {
      const validated = validatePatterns(patterns as { pattern: string; severity?: string }[], `code-enforcer/${key}`);
      if (validated.length === 0 && DEFAULT_CODE_PATTERNS[key]) {
        (raw as any)[key] = DEFAULT_CODE_PATTERNS[key];
      } else {
        (raw as any)[key] = validated;
      }
    }
  }
  return raw;
}

export function loadEgressConfig(): {
  secretPatterns: SecretPattern[];
  blockedDestinations: BlockedDestination[];
} {
  const config = loadConfig<{
    patterns: {
      secretPatterns: SecretPattern[];
      blockedDestinations: BlockedDestination[];
    };
  }>('egress/config.json', {
    patterns: {
      secretPatterns: DEFAULT_SECRET_PATTERNS,
      blockedDestinations: DEFAULT_BLOCKED_DESTINATIONS,
    },
  });
  return config.patterns || {
    secretPatterns: DEFAULT_SECRET_PATTERNS,
    blockedDestinations: DEFAULT_BLOCKED_DESTINATIONS,
  };
}

export function loadSupplyChainConfig(): {
  maliciousPackages: MaliciousPackage[];
} {
  const config = loadConfig<{ patterns: { maliciousPackages: MaliciousPackage[] } }>(
    'supply-chain/config.json',
    { patterns: { maliciousPackages: DEFAULT_MALICIOUS_PACKAGES } }
  );
  return config.patterns || { maliciousPackages: DEFAULT_MALICIOUS_PACKAGES };
}
