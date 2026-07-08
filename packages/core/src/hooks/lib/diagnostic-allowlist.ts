/**
 * Diagnostic-command allowlist for the L4 injection scanner.
 *
 * NOVA / L4 injection patterns are designed to detect prompt-injection
 * attempts in content that flows into an LLM (files read, web fetches, Bash
 * output from untrusted sources). Running them on the output of pure
 * diagnostic commands — `git status`, `ls`, `ps`, `stat`, `wc`, etc. —
 * produces false positives because the threat model doesn't apply:
 * structural system state is not attacker-controlled content.
 *
 * This allowlist skips scanning when the Bash command's leading verb is a
 * well-known diagnostic / inspection tool that emits structural metadata
 * only.
 *
 * DELIBERATELY EXCLUDED from the allowlist:
 *   - File-content readers (`cat`, `head`, `tail`, `less`, `more`) — they
 *     can reveal arbitrary file content, so scanning their output is still
 *     useful.
 *   - Network fetchers (`curl`, `wget`, `nc`, `dig`) — they introduce
 *     external content and are exactly what L4 exists to scan.
 *   - Text searchers (`grep`, `rg`, `ag`) as the HEAD of a pipeline —
 *     matched lines can contain attacker content from any file. Allowed
 *     as pipe STAGES (e.g. `ls | grep foo`) because they're filtering
 *     already-diagnostic output.
 *   - Structured-file parsers (`jq`, `yq`, `xmllint`) — same reason.
 *
 * The list is conservative by design: metadata-only tools whose output is
 * system state, not content.
 */

const DIAGNOSTIC_COMMANDS = new Set<string>([
  // VCS / platform metadata
  'git', 'gh', 'jj',
  // Filesystem listing / metadata (no file contents)
  'ls', 'find', 'tree', 'stat', 'file', 'du', 'df', 'pwd',
  // Size counting
  'wc',
  // Process / system inspection
  'ps', 'top', 'htop', 'pgrep',
  // System info (read-only introspection)
  'uname', 'hostname', 'uptime', 'whoami', 'id', 'groups',
  'env', 'printenv', 'history', 'which', 'whereis', 'type', 'command',
  // Diff structural output
  'diff',
]);

// Tools that are safe as PIPE STAGES (not as the head): text processors
// that only reshape already-diagnostic output. A pipeline like
// `ls | grep foo | wc -l` is fine because grep/wc are acting on
// structural `ls` output. A pipeline whose HEAD is cat/grep/etc. is NOT
// allowlisted by isDiagnosticBashCommand().
const PIPE_STAGE_EXTRA = new Set<string>([
  'grep', 'rg', 'ag', 'head', 'tail', 'sort', 'uniq',
  'awk', 'sed', 'cut', 'tr', 'xargs', 'tee', 'cat',
]);

const WRAPPER_COMMANDS = new Set<string>(['sudo', 'time', 'nice', 'nohup']);

/**
 * Extract the leading (primary) command from a Bash string.
 *
 * Handles common prefixes:
 *   - `cd <dir> && <cmd>` / `cd <dir>; <cmd>`
 *   - `FOO=bar BAZ=qux <cmd>` env-var assignments
 *   - `sudo <cmd>` / `time <cmd>` / `nice <cmd>` / `nohup <cmd>`
 *   - Absolute paths → basename (`/usr/bin/git` → `git`)
 *
 * Returns the first real command token, or null if the command can't be
 * parsed cleanly. Conservative: unknown input returns null → falls through
 * to normal scanning.
 */
export function extractLeadingCommand(command: string): string | null {
  if (!command) return null;

  let remaining = command.trim();

  // Strip `cd <dir> && ` / `cd <dir>; ` prefix (one level).
  const cdPrefix = /^cd\s+(?:'[^']*'|"[^"]*"|\S+)\s*(?:&&|;)\s+/;
  const cdMatch = remaining.match(cdPrefix);
  if (cdMatch) {
    remaining = remaining.slice(cdMatch[0].length);
  }

  // Strip env-var assignments: `FOO=bar BAZ=qux cmd ...`
  const envPrefix = /^(?:[A-Z_][A-Z0-9_]*=(?:'[^']*'|"[^"]*"|\S*)\s+)+/;
  const envMatch = remaining.match(envPrefix);
  if (envMatch) {
    remaining = remaining.slice(envMatch[0].length);
  }

  // Strip harmless wrappers.
  const firstSpace = remaining.search(/\s/);
  const firstToken = firstSpace === -1 ? remaining : remaining.slice(0, firstSpace);
  if (WRAPPER_COMMANDS.has(firstToken)) {
    remaining = remaining.slice(firstToken.length).trimStart();
  }

  const match = remaining.match(/^([A-Za-z0-9_./-]+)/);
  if (!match || !match[1]) return null;

  const raw: string = match[1];
  const basename = raw.includes('/') ? raw.slice(raw.lastIndexOf('/') + 1) : raw;
  return basename || null;
}

/**
 * True iff the Bash command is a pure diagnostic call whose output is
 * structural system state (safe to skip L4 scanning).
 *
 * Rules:
 *   - The HEAD of the pipeline must be in DIAGNOSTIC_COMMANDS.
 *   - Every pipe STAGE may be either a DIAGNOSTIC_COMMAND or a
 *     structural processor (grep, sort, wc, etc.).
 *   - `cd <dir> && <cmd>` wrapper is transparent to chain detection.
 *   - Any other boolean chain (&&, ||, ;) disables the allowlist.
 */
export function isDiagnosticBashCommand(command: string | undefined): boolean {
  if (!command) return false;

  // Strip the single allowed `cd <dir> && ` wrapper — transparent for
  // chain-detection purposes.
  let effective = command.trim();
  const cdPrefix = /^cd\s+(?:'[^']*'|"[^"]*"|\S+)\s*(?:&&|;)\s+/;
  const cdMatch = effective.match(cdPrefix);
  if (cdMatch) {
    effective = effective.slice(cdMatch[0].length);
  }

  // Any OTHER chain-to-another-command disables the allowlist.
  const chainRe = /(?:&&|\|\||;(?!\s*$))/;
  if (chainRe.test(effective)) return false;

  // Split on pipes; every segment's leading verb must be in the combined
  // allowlist (diagnostics ∪ pipe-stage processors).
  const pipeStageOk = new Set<string>([
    ...DIAGNOSTIC_COMMANDS,
    ...PIPE_STAGE_EXTRA,
  ]);

  const segments = effective.split('|');
  for (const seg of segments) {
    const verb = extractLeadingCommand(seg);
    if (!verb) return false;
    if (!pipeStageOk.has(verb)) return false;
  }

  // Head of the pipeline must be a strict diagnostic command.
  // Otherwise `cat untrusted.md | wc -l` would pass.
  const head = extractLeadingCommand(segments[0]!);
  if (!head || !DIAGNOSTIC_COMMANDS.has(head)) return false;

  return true;
}

// ---------------------------------------------------------------------------
// L4 provenance gate — local trusted RAG retrieval
// ---------------------------------------------------------------------------
// Output of the local 0k-rag CLI is RETRIEVAL from the user's OWN indexed
// knowledge base — content the user curated, already gated at index time by
// the RAG security scanner (L15). Injection patterns surfacing in that output
// are self-originated, not an untrusted inbound channel. The smart L4
// classifier can still keep the alert here because a retrieved chunk (e.g. a
// CISO-book line "Implement tiered admin model") reads as imperative in
// isolation and the classifier window carries no provenance signal. Treating
// these commands as a provenance signal DOWNGRADES the alert to LOG (still
// scanned + audited) rather than firing a CRITICAL human-in-the-loop
// interruption on the user's own KB.
const LOCAL_RAG_RETRIEVAL_COMMANDS = new Set<string>([
  '0k-search', '0k-index', '0k-rag', '0k-vacuum',
]);

// Structural pipe-stage processors permitted downstream of a RAG command
// (`0k-search "x" | grep foo | head`). Never grants trust as a pipeline HEAD.
const RAG_PIPE_STAGE_OK = new Set<string>([
  'grep', 'rg', 'ag', 'head', 'tail', 'sort', 'uniq',
  'awk', 'sed', 'cut', 'tr', 'wc', 'tee', 'cat',
]);

/**
 * Split on top-level pipes only — a `|` inside single/double quotes (e.g. a
 * grep alternation `grep -E "ddos|score"`) is NOT a pipeline separator. A
 * naive String.split('|') would mis-segment such commands and reject a
 * legitimate RAG-retrieval pipeline. Chain operators (`||`) are already
 * rejected upstream, so every unquoted `|` here is a genuine pipe.
 */
export function splitTopLevelPipes(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: '"' | "'" | null = null;
  for (const c of s) {
    if (quote) {
      if (c === quote) quote = null;
      cur += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      cur += c;
    } else if (c === '|') {
      out.push(cur);
      cur = '';
    } else {
      cur += c;
    }
  }
  out.push(cur);
  return out;
}

/**
 * True iff `command` is a read-only local RAG-retrieval invocation whose
 * output is the user's own indexed KB. Mirrors isDiagnosticBashCommand's
 * safety: strips the single allowed `cd … &&` wrapper, rejects boolean
 * chains / command substitution that could append arbitrary commands, and
 * requires the pipeline HEAD to be a known 0k-rag command with only
 * structural processors downstream.
 */
export function isTrustedLocalRagRetrieval(command: string | undefined): boolean {
  if (!command) return false;

  let effective = command.trim();
  const cdPrefix = /^cd\s+(?:'[^']*'|"[^"]*"|\S+)\s*(?:&&|;)\s+/;
  const cdMatch = effective.match(cdPrefix);
  if (cdMatch) effective = effective.slice(cdMatch[0].length);

  // Reject boolean chains / statement separators that introduce new commands.
  if (/(?:&&|\|\||;(?!\s*$))/.test(effective)) return false;
  // Reject command substitution outright — no `$(…)` / backticks.
  if (/\$\(|`/.test(effective)) return false;

  const segments = splitTopLevelPipes(effective);
  const head = extractLeadingCommand(segments[0]!);
  if (!head || !LOCAL_RAG_RETRIEVAL_COMMANDS.has(head)) return false;
  for (let i = 1; i < segments.length; i++) {
    const verb = extractLeadingCommand(segments[i]!);
    if (!verb || !RAG_PIPE_STAGE_OK.has(verb)) return false;
  }
  return true;
}

// Exposed for tests / auditing.
export const _internals = {
  DIAGNOSTIC_COMMANDS,
  PIPE_STAGE_EXTRA,
  WRAPPER_COMMANDS,
  LOCAL_RAG_RETRIEVAL_COMMANDS,
  RAG_PIPE_STAGE_OK,
};
