/**
 * gh-policy — three-tier classifier for `gh` (GitHub CLI) operations.
 *
 * Tier 1 BLOCK  — destructive / irreversible (repo delete, secret remove,
 *                 api -X DELETE, etc.). Hard block. No token bypasses it.
 * Tier 2 CONFIRM — state-mutating but recoverable (repo edit, pr merge,
 *                 release create/publish, secret set, etc.). Blocked unless a
 *                 valid confirm token exists in state.
 * Tier 3 ALLOW   — routine ops (view/list/search/api GET, pr create, etc.).
 *                 Audit log only.
 *
 * Threat model — be honest about what each tier buys:
 *  - Tier 1 is the real boundary against an irreversible mistake or a malicious
 *    agent: a hard block no token can lift. The OS sandbox (L10/L11) backs it.
 *  - Tier 2's confirm token is an INTENT GATE for an HONEST agent — it prevents
 *    accidental / over-eager recoverable mutations by requiring an out-of-band
 *    operator action. It is NOT a guarantee against a malicious/injected agent:
 *    the token is a local file, and an agent with filesystem write could forge
 *    it. Against that threat, rely on Tier 1 + the sandbox, not the token.
 *
 * Pure functions — no I/O for classification. Token I/O is split into
 * a separate set of helpers below so the classifier itself stays unit-
 * testable in isolation.
 */

import { existsSync, readFileSync, unlinkSync } from 'fs';
import { atomicWriteFileSync } from './atomic-file';

export enum GhTier {
  ALLOW = 'allow',
  CONFIRM = 'confirm',
  BLOCK = 'block',
  NOT_GH = 'not_gh',
}

export interface GhClassification {
  tier: GhTier;
  reason: string;
  matched_pattern: string;
  operation: string;
}

interface PatternRule {
  pattern: RegExp;
  operation: string;
  reason: string;
}

/**
 * Tier 1 — HARD BLOCK. Order matters: most specific first.
 * Agent cannot do these even with a confirm token. Operator-only.
 */
const TIER_1_BLOCK: PatternRule[] = [
  {
    pattern: /\bgh\s+repo\s+delete\b/,
    operation: 'repo delete',
    reason: 'Repository deletion is irreversible and operator-only',
  },
  {
    pattern: /\bgh\s+release\s+delete\b/,
    operation: 'release delete',
    reason: 'Release deletion is irreversible and operator-only',
  },
  {
    pattern: /\bgh\s+repo\s+transfer\b/,
    operation: 'repo transfer',
    reason: 'Repository ownership transfer is operator-only',
  },
  {
    pattern: /\bgh\s+secret\s+(?:remove|delete)\b/,
    operation: 'secret remove',
    reason: 'Secret removal is operator-only',
  },
  {
    pattern: /\bgh\s+variable\s+(?:remove|delete)\b/,
    operation: 'variable remove',
    reason: 'Variable removal is operator-only',
  },
  {
    pattern: /\bgh\s+auth\s+(?:refresh|logout)\b/,
    operation: 'auth mutation',
    reason: 'Auth state changes are operator-only',
  },
  {
    pattern: /\bgh\s+ssh-key\s+(?:add|delete)\b/,
    operation: 'ssh-key mutation',
    reason: 'SSH key changes are operator-only',
  },
  {
    pattern: /\bgh\s+gpg-key\s+(?:add|delete)\b/,
    operation: 'gpg-key mutation',
    reason: 'GPG key changes are operator-only',
  },
  // gh api with a DELETE method. `[\s=]*` (not `+`) also catches the glued
  // `-XDELETE` form (which gh/curl accept), not just `-X DELETE` / `--method=DELETE`.
  {
    pattern: /\bgh\s+api\b[^|;&]*?(?:-X|--method)[\s=]*DELETE\b/i,
    operation: 'api DELETE',
    reason: 'Raw DELETE API calls are operator-only',
  },
];

/**
 * Tier 2 — CONFIRM TOKEN REQUIRED.
 * State-mutating but recoverable. Allowed if a talon-gh-confirm token is valid.
 */
const TIER_2_CONFIRM: PatternRule[] = [
  {
    pattern: /\bgh\s+repo\s+edit\b/,
    operation: 'repo edit',
    reason: 'Repository settings changes require explicit operator confirmation',
  },
  {
    pattern: /\bgh\s+repo\s+(?:archive|unarchive)\b/,
    operation: 'repo archive',
    reason: 'Repository archive state changes require operator confirmation',
  },
  {
    pattern: /\bgh\s+release\s+edit\b/,
    operation: 'release edit',
    reason: 'Release edits require operator confirmation',
  },
  {
    // `gh release create` publishes by default (tag pushed, notifications sent) unless
    // `--draft`/`--draft=true` is given — so gate ALL release create; a true-draft create
    // getting a confirm prompt is acceptable fail-safe friction.
    pattern: /\bgh\s+release\s+create\b/,
    operation: 'release create/publish',
    reason: 'Creating/publishing a release requires operator confirmation',
  },
  {
    pattern: /\bgh\s+pr\s+merge\b/,
    operation: 'pr merge',
    reason: 'PR merges require operator confirmation',
  },
  {
    pattern: /\bgh\s+secret\s+set\b/,
    operation: 'secret set',
    reason: 'Setting secrets requires operator confirmation',
  },
  {
    pattern: /\bgh\s+variable\s+set\b/,
    operation: 'variable set',
    reason: 'Setting variables requires operator confirmation',
  },
  // gh api write methods (`[\s=]*` also catches the glued `-XPOST` form).
  {
    pattern: /\bgh\s+api\b[^|;&]*?(?:-X|--method)[\s=]*(?:PUT|POST|PATCH)\b/i,
    operation: 'api write',
    reason: 'Raw write API calls require operator confirmation',
  },
  // gh api graphql with a mutation — a GraphQL mutation is a write (and can be
  // destructive, e.g. deleteRepository). Reads (query only, no "mutation") stay ALLOW.
  {
    pattern: /\bgh\s+api\s+graphql\b[^|;&]*mutation/i,
    operation: 'api graphql mutation',
    reason: 'GraphQL mutations are writes and require operator confirmation',
  },
];

/**
 * Neutralize backslash escapes (bash treats `\X` as a literal X).
 * Two cases, handled in order:
 *  - Escaped QUOTES (`\"` `\'`) are removed entirely so they cannot form false
 *    quote pairs (the escaped-quote bypass: `echo \" ; gh pr merge ; echo \"`).
 *  - Any OTHER escaped char (`\h`, `\;`) collapses to its literal (`\h`→`h`), so
 *    an escaped command fragment like `g\h pr merge` still reads as `gh pr merge`
 *    — bash runs it as `gh`. (The old `\\.`→space turned `g\h` into `g h` and
 *    broke the match, which was itself a bypass.)
 */
function neutralizeEscapes(cmd: string): string {
  return cmd.replace(/\\(['"])/g, '').replace(/\\(.)/g, '$1');
}

/**
 * De-obfuscate a command's TOKEN structure before classification. Undoes the
 * command-name/whitespace obfuscations that hid a gh op from the regex classifier:
 *
 *   "gh" repo delete           quote-spliced command name
 *   g"h" repo delete           split-quote command name
 *   gh repo "delete"           quoted verb
 *   gh${IFS}repo${IFS}delete   $IFS word-splitting
 *
 * Both moves are SAFE — they cannot fabricate a multi-word gh-op phrase, because a
 * phrase's internal spaces must be REAL separators:
 *  1. `$IFS` / `${IFS…}` → a real space (bash word-splits on it).
 *  2. Unquote whitespace-FREE quoted spans only. A multi-word quoted span (a commit
 *     message / echo arg) keeps its quotes and is removed later as DATA by
 *     stripBalancedQuotes — so this never re-exposes quoted data as a command.
 */
function defuseObfuscation(cmd: string): string {
  let s = neutralizeEscapes(cmd);
  s = s.replace(/\$\{IFS[^}]*\}/g, ' ').replace(/\$IFS(?![A-Za-z0-9_])/g, ' ');
  s = s.replace(/"([^"\s]*)"/g, '$1').replace(/'([^'\s]*)'/g, '$1');
  return s;
}

/** Sentinel marking a collapsed dynamic span (no internal whitespace). */
const DYN = '\x00DYN\x00';

/**
 * Collapse `$( … )`, backtick, and `${ … }` spans to a whitespace-free sentinel,
 * so a dynamically-assembled command name (`g$(echo h)`) becomes a single token.
 * Innermost `$( )` first, to handle nesting.
 */
function collapseDynamic(s: string): string {
  let out = s;
  let prev: string;
  do { prev = out; out = out.replace(/\$\([^()]*\)/g, DYN); } while (out !== prev);
  out = out.replace(/`[^`]*`/g, DYN).replace(/\$\{[^}]*\}/g, DYN);
  return out;
}

/**
 * Catch a gh op whose command NAME is dynamically assembled and thus invisible to
 * the literal `\bgh\b` patterns — `g$(echo h) repo delete`, `$(printf gh) pr merge`.
 * The substitution can't be resolved statically, so for any command-position token
 * that contains a dynamic span we assume the worst (it could assemble to `gh`),
 * substitute `gh`, and classify. Over-flags a dynamic command that is *followed by
 * a gated gh verb-phrase*; a dynamic command with no such phrase is untouched.
 */
function matchAssembledGhOp(esc: string): GhClassification | null {
  const collapsed = collapseDynamic(esc);
  let worst: GhClassification | null = null;
  for (const seg of collapsed.split(/\|\||&&|[;|&\n()]/)) {
    const trimmed = seg.trim();
    if (!trimmed) continue;
    const firstTok = trimmed.split(/\s+/)[0] ?? '';
    if (!firstTok.includes(DYN)) continue;
    const candidate = 'gh' + trimmed.slice(firstTok.length);
    const m = matchTierPatterns(candidate);
    if (m) worst = moreSevere(worst, m);
  }
  return worst;
}

/**
 * Remove BALANCED quoted spans — text inside quotes is DATA (commit messages,
 * echo args, `--title` values), not an executable command. This is what keeps a
 * message like `git commit -m "... gh pr merge ..."` from being gated. An
 * unbalanced quote is ambiguous, so it's left intact (the op stays visible to
 * the fail-safe sweep — over-flag, never under-block).
 */
function stripBalancedQuotes(s: string): string {
  let out = s;
  if ((s.match(/"/g) || []).length % 2 === 0) out = out.replace(/"[^"]*"/g, ' ');
  if ((s.match(/'/g) || []).length % 2 === 0) out = out.replace(/'[^']*'/g, ' ');
  return out;
}

/**
 * Interpreters/shells that execute a quoted `-c`/`-e` payload we cannot tokenize
 * (sh/bash/zsh/dash/ash/ksh/csh/tcsh/fish — all end in `sh` — plus python/perl/
 * ruby/node/php/pwsh and `eval`). Their presence (or unbalanced quotes) means an
 * op could be hiding inside the quoted payload, so classifyGhCommand runs a
 * fail-safe CONTAINS sweep over the full (incl. quoted) command in that case.
 */
// `\b` lead-in (not `[\s/]`): a shell metacharacter (`;` `|` `&` `(`) is a word
// boundary, so `;sh -c "…"` / `|bash -c "…"` must still trip Stage 2. `\b` also
// matches after `/`, so `/bin/sh -c` is covered.
// `-[a-z]*[ce]` (not `-[ce]`) so clustered flag bundles like `bash -lc` / `-ec`
// are caught, not just a bare `-c`/`-e`.
const INTERPRETER_EXEC =
  /\b(?:[a-z]*sh|python\d?|perl|ruby|node|php|pwsh)\s+-[a-z]*[ce]\b|\beval\b/i;

/**
 * Match the tier pattern tables against a string. Returns the most-severe match
 * (Tier 1 block over Tier 2 confirm), or null if no state-mutating gh op is
 * present. Unlike classifyGhSegment this does NOT fall back to ALLOW, so it can
 * be used for a CONTAINS sweep without mislabeling non-gh text.
 */
function matchTierPatterns(text: string): GhClassification | null {
  for (const rule of TIER_1_BLOCK) {
    if (rule.pattern.test(text)) {
      return { tier: GhTier.BLOCK, reason: rule.reason, matched_pattern: rule.pattern.source, operation: rule.operation };
    }
  }
  for (const rule of TIER_2_CONFIRM) {
    if (rule.pattern.test(text)) {
      return { tier: GhTier.CONFIRM, reason: rule.reason, matched_pattern: rule.pattern.source, operation: rule.operation };
    }
  }
  return null;
}

const TIER_SEVERITY: Record<GhTier, number> = {
  [GhTier.BLOCK]: 3,
  [GhTier.CONFIRM]: 2,
  [GhTier.ALLOW]: 1,
  [GhTier.NOT_GH]: 0,
};

/** Pick the more severe of two classifications (null = nothing yet). */
function moreSevere(a: GhClassification | null, b: GhClassification): GhClassification {
  return a === null || TIER_SEVERITY[b.tier] > TIER_SEVERITY[a.tier] ? b : a;
}

/**
 * Classify a (possibly compound) command into one of three gh tiers.
 *
 * The tier patterns are anchored (`\bgh\s+...`), so a CONTAINS sweep over the
 * command catches a state-mutating op no matter how it's chained or wrapped —
 * `cd && gh pr merge`, pipes, `$( )` / `<( )` / `` `…` ``, escaped quotes, and
 * command-runner prefixes (`xargs -I{}`, `nice -n5`) all included. No segment
 * enumeration, so there's no runner/operator list to keep complete.
 *
 * Stage 1 sweeps the QUOTE-STRIPPED command: quoted text is data, so a commit
 * message or `echo` arg that merely mentions a gh op doesn't false-positive.
 * Stage 2 (fail-safe) handles ops hidden inside an EXECUTED quoted payload
 * (`sh -c "…"`, `fish -c "…"`, `python -c "…"`, `eval "…"`) or behind unbalanced
 * quotes: when the command looks like it executes a quoted payload, sweep the
 * FULL escape-neutralized command incl. quoted content. Over-flags, never under.
 *
 * @param normalizedCmd Command string AFTER Governor's normalizeCommand()
 *                      (comments stripped, evasion decoded).
 */
export function classifyGhCommand(normalizedCmd: string): GhClassification {
  // defuseObfuscation folds in neutralizeEscapes AND undoes command-token
  // obfuscation ($IFS, quote-splice) so the tier patterns see the real op.
  const esc = defuseObfuscation(normalizedCmd);
  const codeOnly = stripBalancedQuotes(esc);

  // Stage 1 — unquoted ops (the common case; covers every chaining/wrapping form).
  let worst = matchTierPatterns(codeOnly);
  if (worst?.tier === GhTier.BLOCK) return worst;

  // Stage 2 — op possibly hidden in an executed quoted payload or behind an
  // unbalanced quote. Sweep the full command (incl. quotes), fail-safe.
  const ambiguous =
    INTERPRETER_EXEC.test(esc) ||
    (esc.match(/"/g) || []).length % 2 !== 0 ||
    (esc.match(/'/g) || []).length % 2 !== 0;
  if (ambiguous) {
    const swept = matchTierPatterns(esc);
    if (swept) worst = moreSevere(worst, swept);
  }

  // Stage 3 — command NAME dynamically assembled via `$( )` / backtick / `${ }`.
  const assembled = matchAssembledGhOp(esc);
  if (assembled) worst = moreSevere(worst, assembled);

  if (worst) return worst;

  // No state-mutating op. Distinguish a routine gh command (ALLOW) from non-gh.
  if (/\bgh\s+\S/.test(codeOnly)) {
    return {
      tier: GhTier.ALLOW,
      reason: 'Routine gh operation (read or non-destructive write)',
      matched_pattern: '',
      operation: 'gh routine',
    };
  }
  return { tier: GhTier.NOT_GH, reason: 'Not a gh command', matched_pattern: '', operation: '' };
}

// ============================================================================
// Confirm-token helpers (I/O — kept separate from classifier for testability)
// ============================================================================

export interface ConfirmToken {
  intent: string;
  issued_at: string;
  expires_at: string;
  uses_remaining: number;
  issuer_pid?: number;
  issuer_ppid?: number;
}

export interface TokenValidation {
  valid: boolean;
  token?: ConfirmToken;
  reason?: string;
}

/**
 * Check whether a confirm token at the given path is valid.
 * Valid = exists, parses as JSON, not expired, uses_remaining > 0.
 *
 * Returns { valid, token?, reason? } — does NOT mutate the file.
 */
export function checkConfirmToken(tokenPath: string): TokenValidation {
  if (!existsSync(tokenPath)) {
    return { valid: false, reason: 'no confirm token present' };
  }

  let raw: string;
  try {
    raw = readFileSync(tokenPath, 'utf8');
  } catch (e) {
    return { valid: false, reason: `failed to read token: ${(e as Error).message}` };
  }

  let token: ConfirmToken;
  try {
    token = JSON.parse(raw);
  } catch (e) {
    return { valid: false, reason: 'token file is not valid JSON' };
  }

  if (typeof token.uses_remaining !== 'number' || token.uses_remaining <= 0) {
    return { valid: false, token, reason: 'token has no uses remaining' };
  }

  const expiresAt = Date.parse(token.expires_at);
  if (Number.isNaN(expiresAt)) {
    return { valid: false, token, reason: 'token expires_at is malformed' };
  }
  if (expiresAt <= Date.now()) {
    return { valid: false, token, reason: 'token has expired' };
  }

  return { valid: true, token };
}

/**
 * Consume one use of the confirm token. If uses_remaining hits 0, delete
 * the file. Atomic write so a crash mid-decrement does not leave a
 * partially-corrupt token on disk.
 */
export function consumeConfirmToken(tokenPath: string): void {
  if (!existsSync(tokenPath)) return;

  const validation = checkConfirmToken(tokenPath);
  if (!validation.valid || !validation.token) {
    // Already invalid — nothing to consume
    return;
  }

  const remaining = validation.token.uses_remaining - 1;
  if (remaining <= 0) {
    try {
      unlinkSync(tokenPath);
    } catch (e) {
      // Best-effort delete; not a security issue if file lingers (next check will see uses=0)
    }
    return;
  }

  const updated: ConfirmToken = { ...validation.token, uses_remaining: remaining };
  atomicWriteFileSync(tokenPath, JSON.stringify(updated, null, 2));
}
