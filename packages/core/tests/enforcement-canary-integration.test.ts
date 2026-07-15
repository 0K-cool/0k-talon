/**
 * Enforcement Canary — integration (the canary's own effect test).
 *
 * A canary you cannot prove goes RED is just a green light. These tests run the
 * real entrypoint as a subprocess against synthetic hooks and assert it actually
 * distinguishes an enforcing control from a silent no-op.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'node:url';

const CANARY = fileURLToPath(new URL('../src/hooks/enforcement-canary.ts', import.meta.url));
const CONTRACT = fileURLToPath(
  new URL('../src/hooks/config/enforcement/hook-contract.json', import.meta.url)
);

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'talon-canary-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

/** A fake hook with the given body, referenced by an absolute path in the corpus. */
function fakeHook(name: string, body: string): string {
  const p = join(dir, name);
  writeFileSync(p, body);
  return p;
}

function corpusWith(hookPath: string): string {
  const p = join(dir, 'corpus.json');
  writeFileSync(
    p,
    JSON.stringify({
      version: 'test',
      entries: [
        {
          name: 'probe',
          layer: 'L1',
          hook: hookPath,
          tool_name: 'Bash',
          tool_input: { command: 'rm -rf .git' },
          expected: 'deny',
        },
      ],
    })
  );
  return p;
}

function runCanaryProc(corpusPath: string, extraEnv: Record<string, string> = {}) {
  const statePath = join(dir, 'state.json');
  const res = spawnSync('bun', ['run', CANARY], {
    encoding: 'utf-8',
    timeout: 30_000,
    env: {
      ...process.env,
      OK_TALON_CANARY_STATE_FILE: statePath,
      OK_TALON_CANARY_CORPUS: corpusPath,
      OK_TALON_CANARY_CONTRACT: CONTRACT,
      OK_TALON_CANARY_THROTTLE_HOURS: '0',
      ...extraEnv,
    },
  });
  const state = JSON.parse(readFileSync(statePath, 'utf-8'));
  return { status: res.status, stderr: res.stderr ?? '', state };
}

describe('Enforcement canary — detects the silent no-op class', () => {
  it('goes RED when a control emits a dead-format decision and exits 0', () => {
    const hook = fakeHook(
      'noop.ts',
      `console.log(JSON.stringify({ tool_input: { command: 'echo blocked' } })); process.exit(0);`
    );
    const { state, stderr } = runCanaryProc(corpusWith(hook));
    expect(state.pass).toBe(0);
    expect(state.failures[0].reason).toMatch(/DEAD top-level format/);
    expect(stderr).toMatch(/CONTROLS NOT ENFORCING/);
  });

  it('goes RED when a control silently allows (exit 0, no decision)', () => {
    const hook = fakeHook('silent.ts', `process.exit(0);`);
    const { state } = runCanaryProc(corpusWith(hook));
    expect(state.pass).toBe(0);
    expect(state.failures[0].reason).toMatch(/control did not fire/);
  });

  it('goes GREEN on a real exit-2 block (Talon L0/gh contract)', () => {
    const hook = fakeHook('exit2.ts', `console.error('blocked'); process.exit(2);`);
    const { state } = runCanaryProc(corpusWith(hook));
    expect(state.pass).toBe(1);
    expect(state.failures).toEqual([]);
  });

  it('goes GREEN on a hookSpecificOutput deny', () => {
    const hook = fakeHook(
      'deny.ts',
      `console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'no' } })); process.exit(0);`
    );
    const { state } = runCanaryProc(corpusWith(hook));
    expect(state.pass).toBe(1);
  });

  it('ERRORs (never silently passes) when the target hook is missing', () => {
    const { state } = runCanaryProc(corpusWith(join(dir, 'does-not-exist.ts')));
    expect(state.failures[0].status).toBe('ERROR');
    expect(state.failures[0].reason).toMatch(/did not run/);
  });

  it('never blocks the session, even when every probe fails', () => {
    const hook = fakeHook('silent.ts', `process.exit(0);`);
    const { status } = runCanaryProc(corpusWith(hook));
    expect(status).toBe(0); // fail-loud, not fail-shut
  });
});

describe('Enforcement canary — throttle (distributed-plugin cost guard)', () => {
  it('skips a re-run inside the throttle window after a clean pass', () => {
    const hook = fakeHook('exit2.ts', `console.error('blocked'); process.exit(2);`);
    const corpus = corpusWith(hook);
    const statePath = join(dir, 'state.json');

    const env = {
      ...process.env,
      OK_TALON_CANARY_STATE_FILE: statePath,
      OK_TALON_CANARY_CORPUS: corpus,
      OK_TALON_CANARY_CONTRACT: CONTRACT,
      OK_TALON_CANARY_THROTTLE_HOURS: '24',
    };
    spawnSync('bun', ['run', CANARY], { encoding: 'utf-8', timeout: 30_000, env });
    const firstTs = JSON.parse(readFileSync(statePath, 'utf-8')).ts;

    spawnSync('bun', ['run', CANARY], { encoding: 'utf-8', timeout: 30_000, env });
    const secondTs = JSON.parse(readFileSync(statePath, 'utf-8')).ts;

    expect(secondTs).toBe(firstTs); // not re-run → state untouched
  });

  it('does NOT throttle after a failure (re-checks until proven enforcing)', () => {
    const hook = fakeHook('silent.ts', `process.exit(0);`);
    const corpus = corpusWith(hook);
    const statePath = join(dir, 'state.json');
    const env = {
      ...process.env,
      OK_TALON_CANARY_STATE_FILE: statePath,
      OK_TALON_CANARY_CORPUS: corpus,
      OK_TALON_CANARY_CONTRACT: CONTRACT,
      OK_TALON_CANARY_THROTTLE_HOURS: '24',
    };
    spawnSync('bun', ['run', CANARY], { encoding: 'utf-8', timeout: 30_000, env });
    const firstTs = JSON.parse(readFileSync(statePath, 'utf-8')).ts;

    const res = spawnSync('bun', ['run', CANARY], { encoding: 'utf-8', timeout: 30_000, env });
    const secondTs = JSON.parse(readFileSync(statePath, 'utf-8')).ts;

    expect(res.stderr).toMatch(/CONTROLS NOT ENFORCING/);
    expect(secondTs).not.toBe(firstTs); // re-ran
  });
});
