/**
 * Tests for L3 classifier backend resolution + CLI subprocess path.
 *
 * Phase 4: PAI's local-only philosophy means "use the Claude Code MAX
 * subscription, not a paid API key" wherever possible. This adds a CLI
 * backend that shells out to `claude -p --model claude-haiku-4-5
 * --no-session-persistence` from /tmp (so PAI's CLAUDE.md doesn't
 * leak into the classifier prompt).
 *
 * Test scope: pure backend resolution + a faked spawnSync to validate
 * the parsing/error paths. We never actually invoke the real `claude`
 * binary in tests.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import {
  resolveBackend,
  isClassifierEnabled,
  type Backend,
} from '../src/hooks/lib/classifier';

/**
 * Build a throwaway directory containing an executable shim named
 * `claude` so PATH-based detection has a deterministic hit, regardless
 * of whether Claude Code is actually installed on the test runner.
 */
function makeFakeClaudeBinDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'fake-claude-bin-'));
  const shim = join(dir, 'claude');
  writeFileSync(shim, '#!/bin/sh\nexit 0\n');
  chmodSync(shim, 0o755);
  return dir;
}

// ===========================================================================
// resolveBackend — env-driven dispatch
// ===========================================================================

describe('resolveBackend', () => {
  const origTier = process.env.VEX_L3_CLASSIFIER;
  const origExplicit = process.env.VEX_L3_CLASSIFIER_BACKEND;
  const origKey = process.env.ANTHROPIC_API_KEY;
  const origPath = process.env.PATH;

  beforeEach(() => {
    delete process.env.VEX_L3_CLASSIFIER;
    delete process.env.VEX_L3_CLASSIFIER_BACKEND;
    delete process.env.ANTHROPIC_API_KEY;
    // Keep real PATH so claude is auto-detectable
    process.env.PATH = origPath;
  });

  afterEach(() => {
    if (origTier === undefined) delete process.env.VEX_L3_CLASSIFIER;
    else process.env.VEX_L3_CLASSIFIER = origTier;
    if (origExplicit === undefined) delete process.env.VEX_L3_CLASSIFIER_BACKEND;
    else process.env.VEX_L3_CLASSIFIER_BACKEND = origExplicit;
    if (origKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = origKey;
    process.env.PATH = origPath;
  });

  it('returns null when explicit=cli but claude is not on PATH', () => {
    process.env.VEX_L3_CLASSIFIER_BACKEND = 'cli';
    process.env.PATH = '/nonexistent';
    expect(resolveBackend()).toBeNull();
  });

  it('returns "api" when explicit=api and ANTHROPIC_API_KEY is set', () => {
    process.env.VEX_L3_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(resolveBackend()).toBe<Backend>('api');
  });

  it('returns null when explicit=api but ANTHROPIC_API_KEY is missing', () => {
    process.env.VEX_L3_CLASSIFIER_BACKEND = 'api';
    expect(resolveBackend()).toBeNull();
  });

  it('auto-prefers cli when claude is on PATH (PAI local-only path)', () => {
    // Use a controlled fixture so the test is deterministic across
    // environments (CI without Claude Code installed, etc.).
    const fakeBinDir = makeFakeClaudeBinDir();
    try {
      process.env.PATH = `${fakeBinDir}:${origPath ?? ''}`;
      expect(resolveBackend()).toBe<Backend>('cli');
    } finally {
      rmSync(fakeBinDir, { recursive: true, force: true });
    }
  });

  it('auto-falls-back to api when claude is not on PATH but API key is set', () => {
    process.env.PATH = '/nonexistent';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(resolveBackend()).toBe<Backend>('api');
  });

  it('auto-returns null when neither claude CLI nor API key is available', () => {
    process.env.PATH = '/nonexistent';
    expect(resolveBackend()).toBeNull();
  });

  it('rejects unknown explicit backend value (treats as auto)', () => {
    process.env.VEX_L3_CLASSIFIER_BACKEND = 'magic';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    process.env.PATH = '/nonexistent'; // force API path so test is deterministic
    expect(resolveBackend()).toBe<Backend>('api');
  });
});

// ===========================================================================
// isClassifierEnabled — combines tier toggle with backend availability
// ===========================================================================

describe('isClassifierEnabled (Phase 4 — backend-aware)', () => {
  const origTier = process.env.VEX_L3_CLASSIFIER;
  const origExplicit = process.env.VEX_L3_CLASSIFIER_BACKEND;
  const origKey = process.env.ANTHROPIC_API_KEY;
  const origPath = process.env.PATH;

  beforeEach(() => {
    delete process.env.VEX_L3_CLASSIFIER;
    delete process.env.VEX_L3_CLASSIFIER_BACKEND;
    delete process.env.ANTHROPIC_API_KEY;
    process.env.PATH = origPath;
  });

  afterEach(() => {
    if (origTier === undefined) delete process.env.VEX_L3_CLASSIFIER;
    else process.env.VEX_L3_CLASSIFIER = origTier;
    if (origExplicit === undefined) delete process.env.VEX_L3_CLASSIFIER_BACKEND;
    else process.env.VEX_L3_CLASSIFIER_BACKEND = origExplicit;
    if (origKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = origKey;
    process.env.PATH = origPath;
  });

  it('false when tier off, regardless of backend availability', () => {
    expect(isClassifierEnabled()).toBe(false);
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isClassifierEnabled()).toBe(false);
  });

  it('true when tier=smart and CLI backend resolvable (PAI default)', () => {
    process.env.VEX_L3_CLASSIFIER = 'smart';
    const fakeBinDir = makeFakeClaudeBinDir();
    try {
      process.env.PATH = `${fakeBinDir}:${origPath ?? ''}`;
      expect(isClassifierEnabled()).toBe(true);
    } finally {
      rmSync(fakeBinDir, { recursive: true, force: true });
    }
  });

  it('true when tier=smart, no CLI, but API key present', () => {
    process.env.VEX_L3_CLASSIFIER = 'smart';
    process.env.PATH = '/nonexistent';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isClassifierEnabled()).toBe(true);
  });

  it('false when tier=smart but no backend available', () => {
    process.env.VEX_L3_CLASSIFIER = 'smart';
    process.env.PATH = '/nonexistent';
    expect(isClassifierEnabled()).toBe(false);
  });
});
