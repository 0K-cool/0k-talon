/**
 * Enforcement Canary — pure-logic unit tests (Tier 1).
 *
 * Encodes the spec's acceptance criteria that can be proven WITHOUT the live
 * hooks (criteria 1, 2, 4, 5). The full-harness integration test (criterion 3,
 * and criterion 1 against real hooks) lives in ../enforcement-canary.test.ts and
 * only runs once the files are applied into .claude/.
 *
 * Spec: output/product-ip/security-review-2026-07-13/enforcement-canary-spec.md
 */

import { describe, expect, test } from 'vitest';
import {
  validateDecision,
  evaluateEntry,
  runCanary,
  deepSubstitute,
  materializeEntry,
  formatStatusline,
  type HookContract,
  type Corpus,
  type CorpusEntry,
  type HookRunResult,
} from '../src/hooks/lib/enforcement-canary-lib';

const CONTRACT: HookContract = {
  version: '1.0.0',
  PreToolUse: {
    decisionEnvelope: 'hookSpecificOutput',
    requiredFields: { 'hookSpecificOutput.hookEventName': 'PreToolUse' },
    permissionDecisionField: 'hookSpecificOutput.permissionDecision',
    permissionDecisionEnum: ['allow', 'deny', 'ask'],
    denyValue: 'deny',
    exitCodeDeny: 2,
    deadFormatSignals: { topLevelKeys: ['permissionDecision', 'decision', 'tool_input', 'updatedInput'] },
  },
};

// Golden good output — the CURRENT, honored contract shape.
const GOOD_DENY = JSON.stringify({
  hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'blocked' },
});
// Golden BAD output — the C-1 shape: a decision at the TOP LEVEL that CC ignores.
const DEAD_DENY = JSON.stringify({ decision: 'block', tool_input: { file_path: 'x' } });

const ENTRY: CorpusEntry = {
  name: 'control-plane-policy-write',
  layer: 'L1',
  hook: 'governor-pre-tool-use.ts',
  tool_name: 'Write',
  tool_input: { file_path: '{{PAI_ROOT}}/.claude/policies/x.yml', content: 'c' },
  expected: 'deny',
};
const ok = (stdout: string): HookRunResult => ({ status: 0, stdout });

describe('validateDecision — contract check (the C-1 catcher)', () => {
  test('VALID: nested hookSpecificOutput deny is honored', () => {
    const c = validateDecision(GOOD_DENY, CONTRACT);
    expect(c.valid).toBe(true);
    expect(c.decision).toBe('deny');
    expect(c.deadFormat).toBe(false);
  });

  test('DEAD (criterion 2): top-level decision is flagged, not accepted', () => {
    const c = validateDecision(DEAD_DENY, CONTRACT);
    expect(c.valid).toBe(false);
    expect(c.deadFormat).toBe(true);
    expect(c.reason).toContain('DEAD');
  });

  test('NEITHER: no decision emitted', () => {
    const c = validateDecision('some log line\n', CONTRACT);
    expect(c.valid).toBe(false);
    expect(c.deadFormat).toBe(false);
    expect(c.reason).toContain('no decision');
  });

  test('wrong hookEventName does not satisfy the envelope', () => {
    const bad = JSON.stringify({ hookSpecificOutput: { hookEventName: 'PostToolUse', permissionDecision: 'deny' } });
    expect(validateDecision(bad, CONTRACT).valid).toBe(false);
  });

  test('out-of-enum permissionDecision is rejected', () => {
    const bad = JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'block' } });
    expect(validateDecision(bad, CONTRACT).valid).toBe(false);
  });
});

describe('evaluateEntry', () => {
  test('PASS when expected deny matches a valid deny', () => {
    expect(evaluateEntry(ENTRY, ok(GOOD_DENY), CONTRACT).status).toBe('PASS');
  });

  test('FAIL (C-1 class) when the deny is in dead format', () => {
    const r = evaluateEntry(ENTRY, ok(DEAD_DENY), CONTRACT);
    expect(r.status).toBe('FAIL');
    expect(r.reason).toContain('DEAD');
  });

  test('FAIL when the control allows what it should deny', () => {
    const allow = JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } });
    const r = evaluateEntry(ENTRY, ok(allow), CONTRACT);
    expect(r.status).toBe('FAIL');
    expect(r.reason).toContain('got "allow"');
  });

  test('ERROR (criterion 5) when the probe could not run', () => {
    const r = evaluateEntry(ENTRY, { status: null, stdout: '', spawnError: 'hook not found' }, CONTRACT);
    expect(r.status).toBe('ERROR');
    expect(r.reason).toContain('did not run');
  });

  test('PASS via exit code 2 — the legacy PreToolUse block contract (no JSON at all)', () => {
    // gh Tier-1 / L0 / egress all block this way. Exit 2 alone = honored deny.
    const r = evaluateEntry(ENTRY, { status: 2, stdout: '' }, CONTRACT);
    expect(r.status).toBe('PASS');
    expect(r.reason).toContain('exit code 2');
  });

  test('PASS via exit 2 even when the hook ALSO emits a legacy top-level {decision:block}', () => {
    // L0 secure-code-enforcer emits both. Exit-2 wins over the dead-format flag.
    const r = evaluateEntry(ENTRY, { status: 2, stdout: DEAD_DENY }, CONTRACT);
    expect(r.status).toBe('PASS');
  });

  test('ERROR when the hook CRASHED (non-zero exit that is NOT 2, no decision)', () => {
    const r = evaluateEntry(ENTRY, { status: 1, stdout: '' }, CONTRACT);
    expect(r.status).toBe('ERROR');
    expect(r.reason).toContain('did not run');
    expect(r.reason).toContain('exited 1');
  });

  test('FAIL (C-1 class) when a top-level decision is emitted at exit 0 (no exit-2 either)', () => {
    // The true C-1 signature: intended block, but neither exit-2 nor hookSpecificOutput.
    const r = evaluateEntry(ENTRY, { status: 0, stdout: DEAD_DENY }, CONTRACT);
    expect(r.status).toBe('FAIL');
    expect(r.reason).toContain('DEAD');
  });

  test('FAIL (not ERROR) when the hook ran cleanly (exit 0) but silently allowed', () => {
    const r = evaluateEntry(ENTRY, { status: 0, stdout: 'just a log line\n' }, CONTRACT);
    expect(r.status).toBe('FAIL');
    expect(r.reason).toContain('did not fire');
  });
});

describe('runCanary', () => {
  const corpus: Corpus = {
    version: '1',
    entries: [
      { ...ENTRY, name: 'a' },
      { ...ENTRY, name: 'b' },
      { ...ENTRY, name: 'exempt-one', canary_exempt: true, exempt_reason: 'tier-2 scope' },
    ],
  };

  test('criterion 1: all healthy → pass == total, exempt excluded', () => {
    const s = runCanary(corpus, CONTRACT, () => ok(GOOD_DENY), () => 'T');
    expect(s.ran).toBe(true);
    expect(s.total).toBe(2); // exempt not counted
    expect(s.pass).toBe(2);
    expect(s.failures).toHaveLength(0);
    expect(s.results.find((r) => r.name === 'exempt-one')?.status).toBe('EXEMPT');
  });

  test('criterion 2 at runner level: one control reverts to dead format → FAIL surfaces', () => {
    const s = runCanary(
      corpus,
      CONTRACT,
      (e) => (e.name === 'b' ? ok(DEAD_DENY) : ok(GOOD_DENY)),
      () => 'T',
    );
    expect(s.pass).toBe(1);
    expect(s.failures.map((f) => f.name)).toContain('b');
  });

  test('exempt-only corpus never silently reports all-pass on nothing', () => {
    const s = runCanary({ version: '1', entries: [corpus.entries[2]] }, CONTRACT, () => ok(GOOD_DENY), () => 'T');
    expect(s.total).toBe(0);
    expect(s.pass).toBe(0);
  });
});

describe('materializeEntry / deepSubstitute', () => {
  test('substitutes {{PAI_ROOT}} in nested strings', () => {
    const m = materializeEntry(ENTRY, { PAI_ROOT: '/repo', CANARY_SECRET: 'S' });
    expect(m.tool_input.file_path).toBe('/repo/.claude/policies/x.yml');
  });

  test('injects {{CANARY_SECRET}} so the corpus file needs no literal', () => {
    const e: CorpusEntry = { ...ENTRY, tool_input: { content: 'k = "{{CANARY_SECRET}}"' } };
    expect(materializeEntry(e, { PAI_ROOT: '/r', CANARY_SECRET: 'SEKRIT' }).tool_input.content).toBe('k = "SEKRIT"');
  });

  test('deepSubstitute leaves non-strings untouched', () => {
    expect(deepSubstitute({ a: 1, b: true, c: null }, { X: 'y' })).toEqual({ a: 1, b: true, c: null });
  });
});

describe('formatStatusline', () => {
  test('all pass', () => {
    expect(formatStatusline({ ts: 'T', ran: true, pass: 5, total: 5, results: [], failures: [] })).toBe('ENFORCEMENT ✅ 5/5');
  });
  test('with failures names the first + count', () => {
    const s = formatStatusline({
      ts: 'T', ran: true, pass: 3, total: 5, results: [],
      failures: [
        { name: 'env-read', layer: 'L1', status: 'FAIL', reason: 'x' },
        { name: 'gh', layer: 'L1', status: 'FAIL', reason: 'y' },
      ],
    });
    expect(s).toBe('ENFORCEMENT ❌ 3/5 (L1 env-read +1)');
  });
  test('did-not-run', () => {
    expect(formatStatusline({ ts: 'T', ran: false, pass: 0, total: 0, results: [], failures: [] })).toContain('DID NOT RUN');
  });
});
