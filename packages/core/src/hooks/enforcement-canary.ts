#!/usr/bin/env bun
/**
 * Enforcement Canary — SessionStart Hook (Tier 1: session self-test)
 *
 * Proves the security controls actually STOP what they claim to stop, and alarms
 * the moment one stops enforcing. For each MUST-BLOCK corpus entry it spawns the
 * live target hook exactly as Claude Code does and checks the emitted decision
 * against the PINNED hook-output contract (hook-contract.json) — which catches
 * the class where a control "blocks" in a format Claude Code silently ignores.
 *
 * Fail-LOUD, never fail-shut: a failure (or the canary being unable to run) emits
 * a banner and records state, but NEVER blocks the session. Always exits 0.
 *
 * Distributed-plugin constraints (0K-Talon runs on other people's machines):
 *   - Throttled to once per THROTTLE_HOURS. Probes spawn one process each; running
 *     them on every SessionStart would tax every user's session forever.
 *   - Only deterministic probes may go RED (see corpusRule in the corpus). A red
 *     banner a user cannot act on trains them to ignore the banner — which is
 *     worse than no canary, since it yields false assurance AND noise.
 *
 * @version 1.0.0
 * @layer Enforcement Canary (continuous control validation)
 */

import { spawnSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname, isAbsolute, join } from 'path';
import { STATE_DIR } from './lib/talon-paths';
import {
  loadContract,
  loadCorpus,
  materializeEntry,
  runCanary,
  formatStatusline,
  type CorpusEntry,
  type CanarySummary,
  type HookRunResult,
} from './lib/enforcement-canary-lib';

const HOOK_NAME = 'enforcement-canary';

// This file lives in <pluginRoot>/packages/core/src/hooks/, so the hooks dir is
// its own directory. CLAUDE_PLUGIN_ROOT is what Claude Code sets when invoking
// plugin hooks; fall back to this file's location so the hook also runs from a
// source checkout (and under the test harness).
const HOOKS_DIR = process.env.CLAUDE_PLUGIN_ROOT
  ? join(process.env.CLAUDE_PLUGIN_ROOT, 'packages', 'core', 'src', 'hooks')
  : __dirname;

const CONFIG_DIR = join(HOOKS_DIR, 'config', 'enforcement');

// Env-overridable so the integration test runs in isolation without touching real state.
const STATE_FILE = process.env.OK_TALON_CANARY_STATE_FILE || join(STATE_DIR, 'enforcement-canary.json');
const CORPUS_FILE = process.env.OK_TALON_CANARY_CORPUS || join(CONFIG_DIR, 'enforcement-corpus.json');
const CONTRACT_FILE = process.env.OK_TALON_CANARY_CONTRACT || join(CONFIG_DIR, 'hook-contract.json');

const THROTTLE_HOURS = Number(process.env.OK_TALON_CANARY_THROTTLE_HOURS ?? 24);

/**
 * Synthetic test secret, assembled from fragments at runtime. The canonical AWS
 * documentation EXAMPLE key — real-shaped so L0 must catch it, but NEVER written
 * as a literal to any file (that would trip the credential-leak guard / git
 * pre-commit). It exists only here and on the spawned hook's stdin.
 */
function canarySecret(): string {
  return ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
}

function substitutions(): Record<string, string> {
  return { CANARY_SECRET: canarySecret() };
}

function resolveHookPath(hook: string): string {
  return isAbsolute(hook) ? hook : join(HOOKS_DIR, hook);
}

/**
 * True when a successful run happened within the throttle window. The canary is
 * drift detection, not an intrusion detector — daily is enough, and a per-session
 * process fan-out is a cost every user would pay forever.
 *
 * A previous run that FAILED or errored is never throttled: we re-check until the
 * control is proven enforcing again.
 */
function recentlyRan(now: Date): boolean {
  if (THROTTLE_HOURS <= 0) return false;
  try {
    const prev = JSON.parse(readFileSync(STATE_FILE, 'utf-8')) as CanarySummary;
    if (!prev?.ts || !prev.ran) return false;
    if (prev.failures?.length) return false;
    const ageH = (now.getTime() - new Date(prev.ts).getTime()) / 3_600_000;
    return ageH >= 0 && ageH < THROTTLE_HOURS;
  } catch {
    return false; // no state / unreadable → run
  }
}

/** Spawn a target hook with the entry's payload, exactly as Claude Code would. */
function runHook(entry: CorpusEntry): HookRunResult {
  const hookPath = resolveHookPath(entry.hook);
  if (!existsSync(hookPath)) {
    return { status: null, stdout: '', spawnError: `hook not found: ${hookPath}` };
  }
  // Tag probe-origin calls so a control can tell a canary probe from real traffic.
  const env = { ...process.env, OK_TALON_ENFORCEMENT_CANARY: '1' };

  const res = spawnSync('bun', ['run', hookPath], {
    input: JSON.stringify({ tool_name: entry.tool_name, tool_input: entry.tool_input }),
    encoding: 'utf-8',
    timeout: 15_000,
    env,
  });
  if (res.error) {
    return { status: res.status ?? null, stdout: res.stdout ?? '', spawnError: String(res.error) };
  }
  return { status: res.status ?? null, stdout: res.stdout ?? '' };
}

function writeState(summary: CanarySummary): void {
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify({ ...summary, statusline: formatStatusline(summary) }, null, 2));
}

function main(): void {
  try {
    if (recentlyRan(new Date())) {
      process.exit(0);
    }

    const contract = loadContract(CONTRACT_FILE);
    const corpus = loadCorpus(CORPUS_FILE);
    const subs = substitutions();

    const summary = runCanary(
      corpus,
      contract,
      (entry) => runHook(materializeEntry(entry, subs)),
      () => new Date().toISOString(),
    );

    writeState(summary);

    if (summary.failures.length > 0) {
      const list = summary.failures.map((f) => `  • ${f.layer} ${f.name}: ${f.reason}`).join('\n');
      const banner = `🚨 [EnforcementCanary] ${summary.failures.length}/${summary.total} CONTROLS NOT ENFORCING:\n${list}`;
      console.error(banner);
      console.log(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: 'SessionStart',
            additionalContext: `🚨 ENFORCEMENT CANARY FAILURE — a 0K-Talon control that should BLOCK is not blocking:\n${list}\n\nDo NOT trust the affected layer until fixed. State: ${STATE_FILE}`,
          },
        }),
      );
    } else {
      console.error(`🐦 [EnforcementCanary] ${formatStatusline(summary)}`);
    }
  } catch (err) {
    // The canary being unable to run is ITSELF an alarm — a silent canary gives
    // false assurance too. Record ran:false and shout; never a silent pass.
    const msg = `⚠️  [EnforcementCanary] CANARY DID NOT RUN: ${err}`;
    try {
      mkdirSync(dirname(STATE_FILE), { recursive: true });
      writeFileSync(
        STATE_FILE,
        JSON.stringify(
          {
            ts: new Date().toISOString(),
            ran: false,
            pass: 0,
            total: 0,
            error: String(err),
            results: [],
            failures: [],
            statusline: 'ENFORCEMENT ⚠ CANARY DID NOT RUN',
          },
          null,
          2,
        ),
      );
    } catch {
      /* state dir unwritable — the stderr banner below is still emitted */
    }
    console.error(msg);
  }
  // NEVER block the session: always exit 0 (fail-loud, not fail-shut).
  process.exit(0);
}

// Only auto-run as a hook, not when imported by tests.
if (process.env.OK_TALON_CANARY_NO_AUTORUN !== '1') {
  main();
}

export { HOOK_NAME, canarySecret, recentlyRan, resolveHookPath, runHook };
