/**
 * Regression: the ConfigLoader ReDoS guard (rejects the nested-quantifier shape
 * `+)*` / `+){`) was silently dropping two real detection patterns:
 *   - `0din-ascii-decimal`      — `(?:\d{2,3}\s+){5,}`      (ascii-decimal encoding)
 *   - `0din-memory-execution-cmd` — `(?:[A-Z]+\s+)*`        (`[EXECUTE MEMORY]` style)
 * Both are rewritten with bounded, non-nested quantifiers: detection preserved,
 * ReDoS removed, and they now pass the guard instead of being disabled.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { getActivePatterns, clearPatternCache } from '../src/hooks/L4-injection-scanner';

const CONFIG = fileURLToPath(
  new URL('../src/hooks/config/injection/patterns.json', import.meta.url)
);
const rawPatterns: Array<{ id: string; pattern: string }> =
  JSON.parse(readFileSync(CONFIG, 'utf-8')).patterns;
// The loader's own ReDoS heuristic — no shipped pattern should match it.
const REDOS_SHAPE = /(\+|\*|\{)\)(\+|\*|\{)/;
const src = (id: string) => rawPatterns.find((p) => p.id === id)!.pattern;
const fresh = (id: string) => new RegExp(src(id), 'gi');

describe('ReDoS guard — no shipped pattern is silently dropped', () => {
  it('zero patterns match the nested-quantifier heuristic', () => {
    const flagged = rawPatterns.filter((p) => REDOS_SHAPE.test(p.pattern)).map((p) => p.id);
    expect(flagged).toEqual([]);
  });
  it('both previously-dropped patterns are active in the scanner', () => {
    clearPatternCache();
    const active = new Set(getActivePatterns().map((p) => p.id));
    expect(active.has('0din-ascii-decimal')).toBe(true);
    expect(active.has('0din-memory-execution-cmd')).toBe(true);
  });
});

describe('0din-ascii-decimal — detection preserved + ReDoS-safe', () => {
  it('detects ascii-decimal payloads', () => {
    expect(fresh('0din-ascii-decimal').test('decode: 104 101 108 108 111 32 119 111 114 108 100')).toBe(true);
    expect(fresh('0din-ascii-decimal').test('comma: 104,101,108,108,111,32,119')).toBe(true);
    expect(fresh('0din-ascii-decimal').test('chr(104)chr(105)')).toBe(true);
  });
  it('no catastrophic backtracking', () => {
    const re = fresh('0din-ascii-decimal');
    const evil = '12 '.repeat(400) + '9'.repeat(6000);
    const t = performance.now(); re.test(evil);
    expect(performance.now() - t).toBeLessThan(50);
  });
});

describe('0din-memory-execution-cmd — detection preserved + ReDoS-safe', () => {
  it('detects memory-execution commands (with and without intervening words)', () => {
    expect(fresh('0din-memory-execution-cmd').test('[EXECUTE MEMORY]')).toBe(true);
    expect(fresh('0din-memory-execution-cmd').test('[CLEAR ALL CONTEXT]')).toBe(true);
    expect(fresh('0din-memory-execution-cmd').test('[WIPE THE ENTIRE HISTORY]')).toBe(true);
  });
  it('no catastrophic backtracking', () => {
    const re = fresh('0din-memory-execution-cmd');
    const evil = '[EXECUTE ' + 'A'.repeat(9000);
    const t = performance.now(); re.test(evil);
    expect(performance.now() - t).toBeLessThan(50);
  });
});
