/**
 * Enforcement Canary — pure logic (Tier 1: session self-test)
 *
 * Continuous control validation. For each MUST-BLOCK corpus entry, the canary
 * spawns the live target hook exactly as Claude Code does and checks TWO things:
 *   1. Decision  — the hook emits the expected decision (e.g. `deny`), AND
 *   2. Contract  — the emitted output validates against the PINNED current
 *                  Claude-Code hook-output schema (hook-contract.json).
 *
 * (2) catches the class where a hook emits a deny-ish object in a DEAD top-level
 * format that Claude Code silently ignores — the control believes it blocked, the
 * tool call proceeds anyway. A decision not nested under `hookSpecificOutput`
 * fails RED here.
 *
 * Most 0K-Talon controls (L0, L1 Governor, gh-policy, L9) block via exit code 2
 * rather than a JSON envelope; the contract honors BOTH shapes, so a control
 * passes if either says deny. What is never a pass: exit 0 plus a decision in a
 * shape Claude Code ignores.
 *
 * Alert-class controls (PostToolUse, e.g. L4) cannot deny by design — they are
 * marked `canary_exempt` rather than expected to block.
 *
 * This module is intentionally side-effect-free (no path/logger imports) so it is
 * unit-testable standalone. The thin entrypoint (enforcement-canary.ts) supplies
 * the spawn function and the clock.
 */

import { readFileSync } from 'fs';

// ── Types ───────────────────────────────────────────────────────────────────

export interface HookContract {
  version: string;
  pinnedForClaudeCodeVersion?: string;
  PreToolUse: {
    decisionEnvelope: string; // "hookSpecificOutput"
    requiredFields: Record<string, string>; // e.g. { "hookSpecificOutput.hookEventName": "PreToolUse" }
    permissionDecisionField: string; // "hookSpecificOutput.permissionDecision"
    permissionDecisionEnum: string[];
    denyValue: string;
    /** Exit code Claude Code honors as a PreToolUse block (legacy "blocking error" contract). */
    exitCodeDeny: number;
    deadFormatSignals: { description?: string; topLevelKeys: string[] };
  };
}

/** One MUST-BLOCK probe. Decoys only — never touches real assets. */
export interface CorpusEntry {
  name: string;
  layer: string;
  hook: string; // hooks-dir-relative or absolute path to the target hook
  tool_name: string;
  tool_input: Record<string, unknown>;
  /** Currently supported: 'deny' | 'ask'. Alert-class controls are Tier-2 scope. */
  expected: 'deny' | 'ask';
  /** If true, the entry is recorded but NOT executed and does NOT count toward pass/total. */
  canary_exempt?: boolean;
  exempt_reason?: string;
  note?: string;
}

export interface Corpus {
  version: string;
  entries: CorpusEntry[];
}

export type EntryStatus = 'PASS' | 'FAIL' | 'ERROR' | 'EXEMPT';

export interface EntryResult {
  name: string;
  layer: string;
  status: EntryStatus;
  reason: string;
}

export interface CanarySummary {
  ts: string;
  ran: boolean; // false only when the whole canary aborts before evaluating anything
  pass: number; // PASS count among non-exempt entries
  total: number; // non-exempt entries evaluated
  results: EntryResult[]; // every entry, including exempt
  failures: EntryResult[]; // FAIL + ERROR only
}

/** Raw result of spawning a target hook. spawnError set when it could not run. */
export interface HookRunResult {
  status: number | null;
  stdout: string;
  spawnError?: string;
}

export type RunHookFn = (entry: CorpusEntry) => HookRunResult;

// ── Output parsing + contract validation ─────────────────────────────────────

/** Every JSON object emitted on its own line of a hook's stdout. */
export function parseHookOutputs(stdout: string): Record<string, unknown>[] {
  const objs: Record<string, unknown>[] = [];
  for (const line of stdout.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    try {
      const o = JSON.parse(t);
      if (o && typeof o === 'object') objs.push(o as Record<string, unknown>);
    } catch {
      /* not a JSON decision line */
    }
  }
  return objs;
}

export interface DecisionCheck {
  /** True only when a decision is emitted in the CURRENT, honored contract shape. */
  valid: boolean;
  decision?: string; // the permissionDecision value, when valid
  deadFormat: boolean; // a decision was emitted but in an IGNORED top-level shape (C-1 class)
  reason: string;
}

/**
 * Validate a hook's stdout against the pinned PreToolUse contract.
 *
 * VALID   → a well-formed `hookSpecificOutput` envelope with hookEventName
 *           "PreToolUse" and an in-enum permissionDecision.
 * DEAD    → no valid envelope, but a top-level decision-ish key is present
 *           (permissionDecision/decision/tool_input/updatedInput). This is the
 *           C-1 signature: the hook "decided" but Claude Code ignores it.
 * NEITHER → no decision emitted at all.
 */
export function validateDecision(stdout: string, contract: HookContract): DecisionCheck {
  const spec = contract.PreToolUse;
  const outputs = parseHookOutputs(stdout);
  const envelopeKey = spec.decisionEnvelope;
  const decisionLeaf = spec.permissionDecisionField.split('.').pop() as string;

  for (const o of outputs) {
    const env = o[envelopeKey];
    if (env && typeof env === 'object') {
      const envObj = env as Record<string, unknown>;
      // All required fields under the envelope must match.
      let requiredOk = true;
      for (const [path, expected] of Object.entries(spec.requiredFields)) {
        const leaf = path.split('.').pop() as string;
        if (envObj[leaf] !== expected) {
          requiredOk = false;
          break;
        }
      }
      const decision = envObj[decisionLeaf];
      if (
        requiredOk &&
        typeof decision === 'string' &&
        spec.permissionDecisionEnum.includes(decision)
      ) {
        return { valid: true, decision, deadFormat: false, reason: `valid ${envelopeKey}.${decisionLeaf}=${decision}` };
      }
    }
  }

  // No valid envelope. Is a decision leaking at the top level (dead format)?
  for (const o of outputs) {
    for (const key of spec.deadFormatSignals.topLevelKeys) {
      if (key in o) {
        return {
          valid: false,
          deadFormat: true,
          reason: `decision emitted in DEAD top-level format ("${key}") — not nested under ${envelopeKey}; Claude Code ignores it (C-1 class)`,
        };
      }
    }
  }

  return { valid: false, deadFormat: false, reason: 'no decision emitted' };
}

// ── Payload materialization ───────────────────────────────────────────────────
//
// Corpus payloads use {{PLACEHOLDER}} tokens instead of literals for two reasons:
//   1. {{PAI_ROOT}}      — the real repo root isn't known until runtime.
//   2. {{CANARY_SECRET}} — a secret-shaped literal in the corpus file would trip
//      the credential-leak guard / L0 / git pre-commit every time the file is read
//      or committed. The synthetic test key is assembled by the ENTRYPOINT (from
//      fragments) and injected here, so it exists only on the spawned hook's stdin.

/** Recursively replace {{TOKEN}} occurrences in any string value of an object. */
export function deepSubstitute<T>(value: T, subs: Record<string, string>): T {
  if (typeof value === 'string') {
    let out: string = value;
    for (const [k, v] of Object.entries(subs)) out = out.split(`{{${k}}}`).join(v);
    return out as unknown as T;
  }
  if (Array.isArray(value)) return value.map((v) => deepSubstitute(v, subs)) as unknown as T;
  if (value && typeof value === 'object') {
    const o: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) o[k] = deepSubstitute(v, subs);
    return o as unknown as T;
  }
  return value;
}

/** A copy of the entry with all placeholder tokens in tool_input resolved. */
export function materializeEntry(entry: CorpusEntry, subs: Record<string, string>): CorpusEntry {
  return { ...entry, tool_input: deepSubstitute(entry.tool_input, subs) };
}

// ── Per-entry evaluation ──────────────────────────────────────────────────────

export function evaluateEntry(
  entry: CorpusEntry,
  run: HookRunResult,
  contract: HookContract,
): EntryResult {
  const base = { name: entry.name, layer: entry.layer };

  if (run.spawnError) {
    // Could not run the probe at all → LOUD alarm, never a silent pass.
    return { ...base, status: 'ERROR', reason: `canary did not run: ${run.spawnError}` };
  }

  const spec = contract.PreToolUse;
  const check = validateDecision(run.stdout, contract);

  // 1) A well-formed hookSpecificOutput decision was emitted.
  if (check.valid) {
    if (check.decision === entry.expected) {
      return { ...base, status: 'PASS', reason: check.reason };
    }
    return { ...base, status: 'FAIL', reason: `expected "${entry.expected}" but got "${check.decision}"` };
  }

  // 2) No JSON decision — but exit code 2 IS an honored PreToolUse block (the
  //    legacy "blocking error" contract most PAI hooks use: L0, gh, egress...).
  if (entry.expected === spec.denyValue && run.status === spec.exitCodeDeny) {
    return {
      ...base,
      status: 'PASS',
      reason: `honored block via exit code ${spec.exitCodeDeny} (legacy PreToolUse blocking-error contract)`,
    };
  }

  // 3) A decision was emitted in an IGNORED top-level shape AND the hook did not
  //    exit-2 either → the block is a silent no-op. This is the C-1 class.
  if (check.deadFormat) {
    return { ...base, status: 'FAIL', reason: check.reason };
  }

  // 4) No decision and a non-zero, non-block exit → the hook crashed. It cannot
  //    enforce → LOUD alarm, never a silent pass.
  if (run.status !== 0) {
    return {
      ...base,
      status: 'ERROR',
      reason: `canary did not run: target hook exited ${run.status ?? 'null'} without a valid decision (likely crashed) — enforcement UNVERIFIED`,
    };
  }

  // 5) Clean exit 0, no decision → the control silently allowed what it should
  //    have blocked → FAIL (it did not fire).
  return { ...base, status: 'FAIL', reason: `expected "${entry.expected}" but ${check.reason} (control did not fire)` };
}

// ── Runner ────────────────────────────────────────────────────────────────────

export function runCanary(
  corpus: Corpus,
  contract: HookContract,
  runHook: RunHookFn,
  now: () => string,
): CanarySummary {
  const results: EntryResult[] = [];

  for (const entry of corpus.entries) {
    if (entry.canary_exempt) {
      results.push({
        name: entry.name,
        layer: entry.layer,
        status: 'EXEMPT',
        reason: entry.exempt_reason || 'canary_exempt (no reason given)',
      });
      continue;
    }
    const run = runHook(entry);
    results.push(evaluateEntry(entry, run, contract));
  }

  const evaluated = results.filter((r) => r.status !== 'EXEMPT');
  const failures = results.filter((r) => r.status === 'FAIL' || r.status === 'ERROR');
  const pass = evaluated.filter((r) => r.status === 'PASS').length;

  return {
    ts: now(),
    ran: true,
    pass,
    total: evaluated.length,
    results,
    failures,
  };
}

// ── Loaders (fail loud on malformed config) ──────────────────────────────────

export function loadContract(path: string): HookContract {
  const c = JSON.parse(readFileSync(path, 'utf-8')) as HookContract;
  if (!c.PreToolUse?.decisionEnvelope || !Array.isArray(c.PreToolUse?.permissionDecisionEnum)) {
    throw new Error(`malformed hook-contract at ${path}: missing PreToolUse.decisionEnvelope/permissionDecisionEnum`);
  }
  return c;
}

export function loadCorpus(path: string): Corpus {
  const c = JSON.parse(readFileSync(path, 'utf-8')) as Corpus;
  if (!Array.isArray(c.entries)) {
    throw new Error(`malformed enforcement-corpus at ${path}: entries[] missing`);
  }
  for (const e of c.entries) {
    if (!e.name || !e.hook || !e.tool_name) {
      throw new Error(`malformed corpus entry (needs name/hook/tool_name): ${JSON.stringify(e)}`);
    }
    // An exemption must be argued, not asserted. Without this, one
    // `canary_exempt: true` silently drops a probe out of enforcement scoring
    // and the canary still reports green.
    if (e.canary_exempt && !e.exempt_reason?.trim()) {
      throw new Error(`corpus entry "${e.name}" is canary_exempt with no exempt_reason — exemptions must be justified`);
    }
  }
  // A corpus of nothing-but-exemptions has no failures and would report a
  // healthy `0/0`. Zero evaluated controls is never health.
  if (!c.entries.some((e) => !e.canary_exempt)) {
    throw new Error(`enforcement-corpus at ${path} has no active probes (all entries exempt) — that is not a healthy canary`);
  }
  return c;
}

// ── Presentation ──────────────────────────────────────────────────────────────

/** One-line statusline segment. `ENFORCEMENT ✅ 5/5` or `ENFORCEMENT ❌ 4/5 (L1 env-read)`. */
export function formatStatusline(summary: CanarySummary): string {
  if (!summary.ran) return 'ENFORCEMENT ⚠ CANARY DID NOT RUN';
  // Zero evaluated controls proves nothing — never render it as a green check.
  if (summary.total === 0) return 'ENFORCEMENT ⚠ NO ACTIVE PROBES (0 controls verified)';
  const first = summary.failures[0];
  if (!first) return `ENFORCEMENT ✅ ${summary.pass}/${summary.total}`;
  const extra = summary.failures.length > 1 ? ` +${summary.failures.length - 1}` : '';
  return `ENFORCEMENT ❌ ${summary.pass}/${summary.total} (${first.layer} ${first.name}${extra})`;
}
