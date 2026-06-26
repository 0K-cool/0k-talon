/**
 * Tests for the L2 Secure Code Linter smart tier:
 *
 *   - decideRevert()            — pure confidence-aware revert decision (core)
 *   - parseLLMResponse()        — verdict extraction from LLM output
 *   - isWarnOnlyPath()          — scan-but-never-revert path list
 *   - resolveL2Backend()        — symmetric to L3/L4 backend resolution
 *   - isL2SmartTier()           — tier toggle (default OFF)
 *   - isL2ClassifierEnabled()   — tier + backend gate
 *
 * NO real LLM calls — decideRevert is tested directly with structural
 * inputs, so every revert branch is covered deterministically.
 *
 * Run: pnpm test packages/core/tests/l2-confidence-revert.test.ts
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import {
  decideRevert,
  parseLLMResponse,
  isWarnOnlyPath,
  type RevertDecisionInput,
} from '../src/hooks/lib/l2-security-review';

import {
  resolveL2Backend,
  isL2SmartTier,
  isL2ClassifierEnabled,
  type Backend,
} from '../src/hooks/lib/classifier';

// ===========================================================================
// decideRevert — the core confidence-aware revert decision
// ===========================================================================

describe('decideRevert', () => {
  // Convenience builder with safe defaults (smart on, nothing flagged).
  const base = (overrides: Partial<RevertDecisionInput> = {}): RevertDecisionInput => ({
    smartMode: true,
    staticErrors: 0,
    llmVerdict: null,
    llmConfidence: null,
    llmFailed: false,
    isWarnOnlyPath: false,
    ...overrides,
  });

  it('off-mode → no revert (current behavior, the no-regression contract)', () => {
    const d = decideRevert(base({ smartMode: false, staticErrors: 3, llmVerdict: 'UNSAFE', llmConfidence: 'HIGH' }));
    expect(d.revert).toBe(false);
    expect(d.reason).toMatch(/off|static-only/i);
  });

  it('static CRITICAL finding → revert (Tier 1)', () => {
    const d = decideRevert(base({ staticErrors: 2 }));
    expect(d.revert).toBe(true);
    expect(d.reason).toMatch(/static CRITICAL/i);
  });

  it('LLM UNSAFE + HIGH confidence → revert', () => {
    const d = decideRevert(base({ llmVerdict: 'UNSAFE', llmConfidence: 'HIGH' }));
    expect(d.revert).toBe(true);
    expect(d.reason).toMatch(/UNSAFE.*HIGH/i);
  });

  it('LLM UNSAFE + MEDIUM confidence → revert', () => {
    const d = decideRevert(base({ llmVerdict: 'UNSAFE', llmConfidence: 'MEDIUM' }));
    expect(d.revert).toBe(true);
    expect(d.reason).toMatch(/UNSAFE.*MEDIUM/i);
  });

  it('LLM UNSAFE + LOW confidence → warn only (no revert, likely FP)', () => {
    const d = decideRevert(base({ llmVerdict: 'UNSAFE', llmConfidence: 'LOW' }));
    expect(d.revert).toBe(false);
    expect(d.reason).toMatch(/LOW confidence|false positive/i);
  });

  it('LLM failed/timeout → revert (fail-closed)', () => {
    const d = decideRevert(base({ llmFailed: true }));
    expect(d.revert).toBe(true);
    expect(d.reason).toMatch(/fail-closed|failed|timeout/i);
  });

  it('LLM SAFE → no revert', () => {
    const d = decideRevert(base({ llmVerdict: 'SAFE', llmConfidence: 'HIGH' }));
    expect(d.revert).toBe(false);
    expect(d.reason).toMatch(/no revert/i);
  });

  it('LLM SAFE_WITH_CONCERNS → no revert', () => {
    const d = decideRevert(base({ llmVerdict: 'SAFE_WITH_CONCERNS', llmConfidence: 'MEDIUM' }));
    expect(d.revert).toBe(false);
  });

  it('LLM NEEDS_REVIEW → no revert (human review, file kept)', () => {
    const d = decideRevert(base({ llmVerdict: 'NEEDS_REVIEW', llmConfidence: 'MEDIUM' }));
    expect(d.revert).toBe(false);
  });

  it('warn-only path + static CRITICAL → no revert (warn instead)', () => {
    const d = decideRevert(base({ staticErrors: 5, isWarnOnlyPath: true }));
    expect(d.revert).toBe(false);
    expect(d.reason).toMatch(/warn-only/i);
  });

  it('warn-only path + LLM UNSAFE + HIGH → no revert (warn instead)', () => {
    const d = decideRevert(base({ llmVerdict: 'UNSAFE', llmConfidence: 'HIGH', isWarnOnlyPath: true }));
    expect(d.revert).toBe(false);
    expect(d.reason).toMatch(/warn-only/i);
  });

  it('warn-only path + LLM failed → no revert (path beats fail-closed)', () => {
    const d = decideRevert(base({ llmFailed: true, isWarnOnlyPath: true }));
    expect(d.revert).toBe(false);
    expect(d.reason).toMatch(/warn-only/i);
  });

  it('no signal at all (smart on, clean) → no revert', () => {
    const d = decideRevert(base());
    expect(d.revert).toBe(false);
  });

  it('static CRITICAL takes precedence over an UNSAFE-LOW verdict (Tier 1 wins)', () => {
    const d = decideRevert(base({ staticErrors: 1, llmVerdict: 'UNSAFE', llmConfidence: 'LOW' }));
    expect(d.revert).toBe(true);
    expect(d.reason).toMatch(/static CRITICAL/i);
  });
});

// ===========================================================================
// isWarnOnlyPath — generic infra/tooling paths
// ===========================================================================

describe('isWarnOnlyPath', () => {
  it.each([
    '/home/u/project/.claude/hooks/my-hook.ts',
    '/home/u/project/.claude/scripts/run.sh',
    '/home/u/project/.claude/skills/render.ts',
    '/home/u/.0k-talon/state/x.ts',
    '/home/u/project/node_modules/pkg/index.js',
  ])('flags %s as warn-only', (p) => {
    expect(isWarnOnlyPath(p)).toBe(true);
  });

  it.each([
    '/home/u/project/src/server.ts',
    '/home/u/project/lib/auth.py',
  ])('does NOT flag ordinary source %s', (p) => {
    expect(isWarnOnlyPath(p)).toBe(false);
  });

  it('normalizes backslashes (windows-style paths)', () => {
    expect(isWarnOnlyPath('C:\\proj\\node_modules\\x.js')).toBe(true);
  });
});

// ===========================================================================
// parseLLMResponse — verdict extraction (no network)
// ===========================================================================

describe('parseLLMResponse', () => {
  it('parses a clean JSON verdict', () => {
    const v = parseLLMResponse('{"verdict":"UNSAFE","confidence":"HIGH","vulnerabilities":["sqli"],"summary":"bad"}');
    expect(v).not.toBeNull();
    expect(v!.verdict).toBe('UNSAFE');
    expect(v!.confidence).toBe('HIGH');
    expect(v!.vulnerabilities).toEqual(['sqli']);
  });

  it('tolerates surrounding prose', () => {
    const v = parseLLMResponse('Here is the result:\n{"verdict":"SAFE","confidence":"HIGH","vulnerabilities":[],"summary":"ok"}\nThanks');
    expect(v!.verdict).toBe('SAFE');
  });

  it('normalizes object-array vulnerabilities to strings', () => {
    const v = parseLLMResponse('{"verdict":"UNSAFE","confidence":"MEDIUM","vulnerabilities":[{"type":"XSS","description":"d"}],"summary":"s"}');
    expect(v!.vulnerabilities).toEqual(['XSS']);
  });

  it('defaults confidence to MEDIUM when missing/invalid', () => {
    const v = parseLLMResponse('{"verdict":"NEEDS_REVIEW","vulnerabilities":[],"summary":"s"}');
    expect(v!.confidence).toBe('MEDIUM');
  });

  it('returns null for an invalid verdict label', () => {
    expect(parseLLMResponse('{"verdict":"MAYBE","confidence":"HIGH"}')).toBeNull();
  });

  it('returns null for non-JSON garbage', () => {
    expect(parseLLMResponse('the model refused to answer')).toBeNull();
  });
});

// ===========================================================================
// Env gating — default OFF (no behavior change for existing installs)
// ===========================================================================

function makeFakeClaudeBinDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'fake-claude-bin-l2-'));
  const shim = join(dir, 'claude');
  writeFileSync(shim, '#!/bin/sh\nexit 0\n');
  chmodSync(shim, 0o755);
  return dir;
}

describe('L2 env gating (default OFF)', () => {
  const orig = {
    tier: process.env.OK_TALON_L2_CLASSIFIER,
    tierLegacy: process.env.VEX_L2_CLASSIFIER,
    backend: process.env.OK_TALON_L2_CLASSIFIER_BACKEND,
    key: process.env.ANTHROPIC_API_KEY,
    path: process.env.PATH,
  };

  beforeEach(() => {
    delete process.env.OK_TALON_L2_CLASSIFIER;
    delete process.env.VEX_L2_CLASSIFIER;
    delete process.env.OK_TALON_L2_CLASSIFIER_BACKEND;
    delete process.env.ANTHROPIC_API_KEY;
    process.env.PATH = orig.path;
  });

  afterEach(() => {
    const restore = (k: string, v: string | undefined) => {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    };
    restore('OK_TALON_L2_CLASSIFIER', orig.tier);
    restore('VEX_L2_CLASSIFIER', orig.tierLegacy);
    restore('OK_TALON_L2_CLASSIFIER_BACKEND', orig.backend);
    restore('ANTHROPIC_API_KEY', orig.key);
    process.env.PATH = orig.path;
  });

  it('isL2SmartTier() is false when unset (default off)', () => {
    expect(isL2SmartTier()).toBe(false);
  });

  it('isL2SmartTier() is true when OK_TALON_L2_CLASSIFIER=smart (no backend needed)', () => {
    process.env.OK_TALON_L2_CLASSIFIER = 'smart';
    process.env.PATH = '/nonexistent';
    expect(isL2SmartTier()).toBe(true);
  });

  it('isL2ClassifierEnabled() is false when tier off even with backend', () => {
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isL2ClassifierEnabled()).toBe(false);
  });

  it('isL2ClassifierEnabled() is true when smart + API backend available', () => {
    process.env.OK_TALON_L2_CLASSIFIER = 'smart';
    process.env.PATH = '/nonexistent';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isL2ClassifierEnabled()).toBe(true);
  });

  it('isL2ClassifierEnabled() is false when smart but no backend', () => {
    process.env.OK_TALON_L2_CLASSIFIER = 'smart';
    process.env.PATH = '/nonexistent';
    expect(isL2ClassifierEnabled()).toBe(false);
  });

  it('resolveL2Backend() returns "api" when explicit=api + key set', () => {
    process.env.OK_TALON_L2_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(resolveL2Backend()).toBe<Backend>('api');
  });

  it('resolveL2Backend() auto-prefers cli when claude on PATH', () => {
    const dir = makeFakeClaudeBinDir();
    try {
      process.env.PATH = `${dir}:${orig.path ?? ''}`;
      expect(resolveL2Backend()).toBe<Backend>('cli');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('resolveL2Backend() returns null when no backend available', () => {
    process.env.PATH = '/nonexistent';
    expect(resolveL2Backend()).toBeNull();
  });
});
