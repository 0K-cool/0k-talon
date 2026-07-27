/**
 * additionalContext must nest under hookSpecificOutput — for EVERY event.
 *
 * Sibling of governor-block-enforcement.test.ts. That test covers the BLOCK
 * DECISION channel; this covers the CONTEXT channel, which had the identical
 * defect and no coverage.
 *
 * CONTRACT, read out of the installed Claude Code binary rather than the docs
 * (v2.1.220, ~/.local/share/claude/versions/2.1.220). The top-level hook-output
 * schema has NO `additionalContext` key for any event — its keys are `continue`,
 * `suppressOutput`, `stopReason`, `decision`, `reason`, `systemMessage`,
 * `terminalSequence`, `hookSpecificOutput`. Each event instead has its own
 * hookSpecificOutput variant, e.g.
 *
 *   E.object({ hookEventName: E.literal("SessionStart"), additionalContext: ... })
 *
 * The binary special-cases the mistake by name:
 *
 *   "Hook JSON output had unrecognized keys (ignored): ...
 *    Did you mean hookSpecificOutput.additionalContext (with a hookEventName)?"
 *
 * An earlier revision of this file claimed top-level was valid for SessionStart /
 * Setup / SubagentStart. That was taken from published docs and is WRONG for this
 * runtime. The false premise exempted five hooks from the fix — including
 * enforcement-canary, whose "a control that should BLOCK is not blocking" alert
 * was itself being written to a channel nothing reads. Trust the binary over the
 * docs: the runtime is the authority.
 *
 * A wrong hookEventName is NOT a soft failure. The response handler does:
 *   if (i && e.hookSpecificOutput.hookEventName !== i)
 *     throw Error("Hook returned incorrect event name: expected ... but got ...")
 * which discards the WHOLE payload — including a sibling `continue: true` or
 * `permissionDecision: 'deny'`. Hence the event-match test below.
 *
 * KNOWN GAPS (static analysis; stated so nobody rediscovers them by archaeology):
 *   FALSE NEGATIVES — these slip past and fail SILENT, the wrong direction:
 *     - single-line emission: `JSON.stringify({ continue: true, additionalContext: m })`
 *       (the ^\s* anchor requires the key to start its own line)
 *     - a `hookSpecificOutput` mention in a COMMENT within the lookback window
 *     - additionalContext as a SIBLING of a real hookSpecificOutput literal —
 *       exactly the shape a partially-applied fix produces
 *     - bracket notation / computed / spread keys
 *   FALSE POSITIVE — fails LOUD, which is the acceptable direction:
 *     - `out.hookSpecificOutput.additionalContext = m` is correct nesting but is
 *       flagged by the assignment rule
 *     - a hookSpecificOutput literal with >LOOKBACK preceding keys
 *   Closing these properly means structural (AST) matching over ~22 files.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'node:url';
import { join } from 'path';

const SRC = fileURLToPath(new URL('../src', import.meta.url));
const HOOKS_DIR = join(SRC, 'hooks');
const HOOKS_MANIFEST = fileURLToPath(new URL('../../../hooks/hooks.json', import.meta.url));

/**
 * Events whose hookSpecificOutput variant carries `additionalContext`.
 * Top-level is invalid for ALL of them — this is not a "which events must nest"
 * list, it is "which events can deliver context at all".
 */
const CONTEXT_CAPABLE = new Set([
  'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PostToolBatch',
  'UserPromptSubmit', 'SessionStart', 'Setup', 'SubagentStart',
  'Stop', 'SubagentStop', 'Notification',
]);

/**
 * Registered events with NO hookSpecificOutput variant in v2.1.220. A hook on
 * one of these cannot deliver model-facing context in ANY shape — nesting does
 * not help, because the hookEventName literal would not match a known variant.
 * Their available channels are top-level `systemMessage` (user-visible) and
 * stderr. Listed rather than silently skipped: this is a real delivery gap.
 */
const NO_CONTEXT_CHANNEL = new Set(['ConfigChange', 'TaskCreated', 'PostCompact', 'SessionEnd']);

const LOOKBACK = 8;

/** The single implementation both the real scan and the self-test exercise. */
export function findViolations(file: string, lines: string[], events: string[]): string[] {
  const out: string[] = [];
  lines.forEach((line, i) => {
    if (/\.additionalContext\s*=/.test(line)) {
      out.push(`${file}:${i + 1} assigns .additionalContext [${events.join(',')}]`);
      return;
    }
    if (/^\s*additionalContext\s*:/.test(line)) {
      const ctx = lines.slice(Math.max(0, i - LOOKBACK), i).join('\n');
      if (!ctx.includes('hookSpecificOutput')) {
        out.push(`${file}:${i + 1} top-level additionalContext [${events.join(',')}]`);
      }
    }
  });
  return out;
}

/** hook source filename -> events it is registered under in hooks.json */
function registeredEvents(): Map<string, Set<string>> {
  const manifest = JSON.parse(readFileSync(HOOKS_MANIFEST, 'utf8'));
  const events: Record<string, unknown> = manifest.hooks ?? manifest;
  const map = new Map<string, Set<string>>();

  for (const [event, entries] of Object.entries(events)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      for (const hook of entry?.hooks ?? []) {
        for (const match of String(hook?.command ?? '').match(/[\w.-]+\.(?:ts|js)/g) ?? []) {
          const file = match.replace(/\.js$/, '.ts');
          if (!map.has(file)) map.set(file, new Set());
          map.get(file)!.add(event);
        }
      }
    }
  }
  return map;
}

describe('additionalContext nesting contract', () => {
  it('no hook emits a top-level additionalContext, on any event', () => {
    const violations: string[] = [];
    let scanned = 0;

    for (const [file, events] of registeredEvents()) {
      const path = join(HOOKS_DIR, file);
      if (!existsSync(path)) continue;

      // Hooks whose every event lacks a hookSpecificOutput variant cannot
      // deliver context in ANY shape, so "nest it" is not the remedy and
      // flagging them here would be noise. The dedicated test below asserts
      // that set explicitly, so they are covered, not skipped.
      if ([...events].every(e => NO_CONTEXT_CHANNEL.has(e))) continue;

      scanned++;
      const lines = readFileSync(path, 'utf8').split('\n');
      violations.push(...findViolations(file, lines, [...events]));
    }

    // Anti-vacuity. Without this, a hooks.json restructure (per-package
    // manifests, a renamed `hooks` key, dist basenames) empties the map and the
    // suite goes green having checked nothing. "Not vacuous today" is weaker
    // than "cannot become vacuous".
    expect(scanned, 'scanned too few hooks — the manifest mapping is broken')
      .toBeGreaterThanOrEqual(13);

    expect(
      violations,
      'additionalContext must nest under hookSpecificOutput — a top-level key is ' +
        'ignored for EVERY event and the message never reaches the model:\n  ' +
        violations.join('\n  '),
    ).toEqual([]);
  });

  it('every emitted hookEventName matches the hook’s registered event', () => {
    // A mismatch throws in the harness and discards the ENTIRE payload,
    // including permissionDecision. Hardcoding the literal is only safe while a
    // hook has exactly one registration.
    const problems: string[] = [];

    for (const [file, events] of registeredEvents()) {
      const path = join(HOOKS_DIR, file);
      if (!existsSync(path)) continue;

      const emitted = [...readFileSync(path, 'utf8').matchAll(/hookEventName:\s*'([A-Za-z]+)'/g)]
        .map(m => m[1]!);
      if (emitted.length === 0) continue;

      if (events.size > 1) {
        problems.push(
          `${file} is registered under ${[...events].join(',')} but hardcodes ` +
            `hookEventName — unsatisfiable; pass through data.hook_event_name instead`,
        );
        continue;
      }
      const registered = [...events][0]!;
      for (const name of new Set(emitted)) {
        if (name !== registered) {
          problems.push(`${file} emits hookEventName '${name}' but is registered as '${registered}'`);
        }
      }
    }

    expect(problems, problems.join('\n  ')).toEqual([]);
  });

  it('flags hooks whose event cannot deliver context at all', () => {
    // Not a failure — a documented delivery gap. These hooks emit context that
    // no event variant accepts, so it is dropped regardless of nesting.
    const undeliverable: string[] = [];

    for (const [file, events] of registeredEvents()) {
      const path = join(HOOKS_DIR, file);
      if (!existsSync(path)) continue;
      const src = readFileSync(path, 'utf8');
      if (!/additionalContext/.test(src)) continue;

      for (const ev of events) {
        if (NO_CONTEXT_CHANNEL.has(ev)) undeliverable.push(`${file} [${ev}]`);
        else if (!CONTEXT_CAPABLE.has(ev)) undeliverable.push(`${file} [${ev} — unknown event]`);
      }
    }

    // Known and accepted today; assert the set does not GROW silently.
    expect(undeliverable.sort()).toEqual([
      'L18-mcp-audit-config-change.ts [ConfigChange]',
      'subagent-audit.ts [TaskCreated]',
    ]);
  });

  it('detects both known-bad shapes (guards the guard)', () => {
    // Feeds the REAL findViolations, not a re-typed copy of its regexes — an
    // inline duplicate would keep passing while the real check drifted.
    const objectKey = ['{', "  additionalContext: 'x',", '}'];
    const assignment = ['const o = { continue: true };', "o.additionalContext = 'x';"];
    const nested = ['hookSpecificOutput: {', "  additionalContext: 'x',", '},'];

    expect(findViolations('f.ts', objectKey, ['PreToolUse']), 'missed object-key shape').toHaveLength(1);
    expect(findViolations('f.ts', assignment, ['PreToolUse']), 'missed assignment shape').toHaveLength(1);
    expect(findViolations('f.ts', nested, ['PreToolUse']), 'false-positive on correct nesting').toHaveLength(0);
  });
});
