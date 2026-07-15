/**
 * Enforcement Canary — COVERAGE GUARD (drift-prevention keystone).
 *
 * Makes it structurally impossible for the canary corpus to fall behind the
 * policy set: every Cedar `forbid` control MUST be declared in the coverage map
 * as either a Tier-1 `corpus` probe (that proves it fires) or an `exempt` reason.
 * Add a new forbid without a coverage decision and THIS TEST FAILS in CI.
 *
 * It also keeps the map honest: no stale entries, no mapping to a missing or
 * exempt corpus entry, no reasonless exemptions.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { fileURLToPath } from 'node:url';
import { join } from 'path';

const SRC = fileURLToPath(new URL('../src', import.meta.url));
const CEDAR_DIR = join(SRC, 'security', 'cedar', 'policies');
const CONFIG_DIR = join(SRC, 'hooks', 'config', 'enforcement');
const COVERAGE_MAP = join(CONFIG_DIR, 'enforcement-coverage-map.json');
const CORPUS = join(CONFIG_DIR, 'enforcement-corpus.json');

/** Every `@id("...")` declared across the Cedar forbid policies. */
function cedarForbidIds(): string[] {
  const ids = new Set<string>();
  for (const f of readdirSync(CEDAR_DIR).filter((n) => n.endsWith('.cedar'))) {
    const text = readFileSync(join(CEDAR_DIR, f), 'utf-8');
    for (const m of text.matchAll(/@id\("([^"]+)"\)/g)) ids.add(m[1]);
  }
  return [...ids].sort();
}

interface Coverage {
  corpus?: string;
  exempt?: string;
}
const map = JSON.parse(readFileSync(COVERAGE_MAP, 'utf-8'));
const controls: Record<string, Coverage> = map.controls;
const exemptReasons: Record<string, string> = map.exemptReasons;
const corpus = JSON.parse(readFileSync(CORPUS, 'utf-8'));
const corpusByName = new Map<string, { name: string; canary_exempt?: boolean }>(
  corpus.entries.map((e: { name: string }) => [e.name, e])
);
const forbidIds = cedarForbidIds();

describe('Enforcement coverage guard — Cedar forbid surface', () => {
  it('finds the Cedar policy set (guard is not vacuously passing)', () => {
    expect(forbidIds.length).toBeGreaterThan(0);
  });

  it('every Cedar forbid @id has a coverage decision (add a forbid -> declare it here)', () => {
    const undeclared = forbidIds.filter((id) => !(id in controls));
    expect(
      undeclared,
      `Undeclared Cedar forbid(s) — add to enforcement-coverage-map.json:\n${undeclared.join('\n')}`
    ).toEqual([]);
  });

  it('no stale coverage-map entries (every mapped id is a real Cedar forbid)', () => {
    const stale = Object.keys(controls).filter((id) => !forbidIds.includes(id));
    expect(stale, `Stale coverage-map entries — remove:\n${stale.join('\n')}`).toEqual([]);
  });

  it('every control declares exactly one of corpus | exempt', () => {
    const bad = Object.entries(controls)
      .filter(([, c]) => Boolean(c.corpus) === Boolean(c.exempt))
      .map(([id]) => id);
    expect(bad, `Must declare exactly one of corpus|exempt:\n${bad.join('\n')}`).toEqual([]);
  });

  it('every corpus mapping points at a real, non-exempt corpus entry', () => {
    const broken = Object.entries(controls)
      .filter(([, c]) => c.corpus)
      .filter(([, c]) => {
        const e = corpusByName.get(c.corpus as string);
        return !e || e.canary_exempt === true;
      })
      .map(([id, c]) => `${id} -> ${c.corpus}`);
    expect(broken, `Mapping points at a missing/exempt corpus entry:\n${broken.join('\n')}`).toEqual([]);
  });

  it('every exemption cites a defined reason (no silent exemptions)', () => {
    const bad = Object.entries(controls)
      .filter(([, c]) => c.exempt && !(c.exempt in exemptReasons))
      .map(([id, c]) => `${id} -> "${c.exempt}"`);
    expect(bad, `Exemption reason not defined in exemptReasons:\n${bad.join('\n')}`).toEqual([]);
  });

  it('known gaps are recorded as gaps, not disguised as exemptions', () => {
    // Missing controls must never be laundered into exemptReasons — an exemption
    // says "proven elsewhere", a gap says "not built yet". Conflating them is how
    // a hole starts reading as covered. Assert each gap BY NAME: a count would
    // pass on `description` alone, so deleting a real gap would go unnoticed.
    expect(map.knownGaps).toHaveProperty('control-plane-self-protection');
    expect(map.knownGaps).toHaveProperty('fail-closed-degraded-mode');
    for (const [k, v] of Object.entries(map.knownGaps ?? {})) {
      expect(String(v).length, `knownGaps.${k} needs a real description`).toBeGreaterThan(20);
    }
  });
});
