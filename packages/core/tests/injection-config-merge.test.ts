/**
 * Injection Config Merge Tests (Phase 1 of PAI parity port).
 *
 * Verifies that loadInjectionPatterns() merges three sources:
 *   1. injection/patterns.json   (manual, optional)
 *   2. injection/nova-translated.json (auto-translated from NOVA rules)
 *   3. injection/0din-translated.json (auto-translated from 0din disclosures)
 *
 * Precedence on ID collision: manual > NOVA > 0din (first-wins).
 *
 * Mirrors PAI's config-loader.ts:335-399 algorithm.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { loadInjectionPatterns, clearConfigCache } from '../src/hooks/lib/config-loader';

describe('loadInjectionPatterns — merged config (Phase 1)', () => {
  afterEach(() => {
    clearConfigCache();
  });

  it('loads the bundled NOVA patterns (>= 300)', () => {
    const patterns = loadInjectionPatterns();
    const novaPatterns = patterns.filter((p) => p.id.startsWith('nova-'));
    expect(novaPatterns.length).toBeGreaterThanOrEqual(300);
  });

  it('loads the bundled 0din patterns (>= 40)', () => {
    const patterns = loadInjectionPatterns();
    const odinPatterns = patterns.filter((p) => p.id.startsWith('0din-'));
    expect(odinPatterns.length).toBeGreaterThanOrEqual(40);
  });

  it('returns at least ~400 total patterns after merge', () => {
    const patterns = loadInjectionPatterns();
    // Pre-port: 8 bundled defaults. Post-port: 8 manual + 389 NOVA + 57 0din − collisions
    expect(patterns.length).toBeGreaterThanOrEqual(400);
  });

  it('has no duplicate pattern IDs after merge', () => {
    const patterns = loadInjectionPatterns();
    const ids = patterns.map((p) => p.id);
    const uniqueIds = new Set(ids);
    expect(ids.length).toBe(uniqueIds.size);
  });

  it('every pattern compiles as a valid regex', () => {
    const patterns = loadInjectionPatterns();
    for (const p of patterns) {
      expect(() => new RegExp(p.pattern, 'gi')).not.toThrow();
    }
  });

  it('every pattern has a valid severity', () => {
    const patterns = loadInjectionPatterns();
    const valid = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
    for (const p of patterns) {
      expect(valid.has(p.severity)).toBe(true);
    }
  });

  it('every pattern has a valid category', () => {
    const patterns = loadInjectionPatterns();
    const valid = new Set([
      'instruction_override',
      'jailbreak',
      'encoding',
      'context_manipulation',
    ]);
    for (const p of patterns) {
      expect(valid.has(p.category)).toBe(true);
    }
  });

  it('bundled INJ-001 (manual) survives the merge', () => {
    // manual/default pattern that should have precedence on any NOVA/0din collision
    const patterns = loadInjectionPatterns();
    const inj001 = patterns.find((p) => p.id === 'INJ-001');
    expect(inj001).toBeDefined();
    expect(inj001?.description).toBe('Instruction override attempt');
  });

  it('all NOVA patterns have nova- prefix', () => {
    const patterns = loadInjectionPatterns();
    const novaPatterns = patterns.filter((p) => p.id.startsWith('nova-'));
    for (const p of novaPatterns) {
      expect(p.id).toMatch(/^nova-/);
    }
  });

  it('all 0din patterns have 0din- prefix', () => {
    const patterns = loadInjectionPatterns();
    const odinPatterns = patterns.filter((p) => p.id.startsWith('0din-'));
    for (const p of odinPatterns) {
      expect(p.id).toMatch(/^0din-/);
    }
  });

  it('dedupes duplicate pattern strings across sources', () => {
    // 0din has multiple IDs sharing the same regex (e.g. encode|cipher
    // duplicated 5 times). Loader must dedup by pattern string, not ID.
    const patterns = loadInjectionPatterns();
    const patternStrings = patterns.map((p) => p.pattern);
    const unique = new Set(patternStrings);
    expect(patternStrings.length).toBe(unique.size);
  });
});

describe('L4 hook wire-up — getActivePatterns()', () => {
  it('L4 hook uses merged loader output at runtime (not stale inline array)', () => {
    const {
      getActivePatterns,
      clearPatternCache,
    } = require('../src/hooks/L4-injection-scanner');
    clearPatternCache();
    const active = getActivePatterns();
    // Must include NOVA + 0din + bundled (22 inline) = well above 400
    expect(active.length).toBeGreaterThanOrEqual(400);
    // Bundled inline IDs must survive the merge
    const ids = new Set(active.map((p: any) => p.id));
    expect(ids.has('override-ignore')).toBe(true);
    expect(ids.has('override-forget')).toBe(true);
  });

  it('L4 active patterns are compiled RegExp objects (not strings)', () => {
    const {
      getActivePatterns,
      clearPatternCache,
    } = require('../src/hooks/L4-injection-scanner');
    clearPatternCache();
    const active = getActivePatterns();
    for (const p of active) {
      expect(p.pattern instanceof RegExp).toBe(true);
    }
  });
});

describe('validatePatterns — category enum check', () => {
  it('drops pattern with invalid category', () => {
    const { validatePatterns } = require('../src/hooks/lib/config-loader');
    const patterns = [
      { id: 'A', pattern: 'foo', severity: 'HIGH', category: 'jailbreak' },
      { id: 'B', pattern: 'bar', severity: 'HIGH', category: 'jailbreaks' }, // typo
      { id: 'C', pattern: 'baz', severity: 'HIGH', category: 'encoding' },
    ];
    const valid = validatePatterns(patterns, 'test');
    expect(valid.length).toBe(2);
    expect(valid.map((p: any) => p.id)).toEqual(['A', 'C']);
  });
});
