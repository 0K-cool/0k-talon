/**
 * Memory Guardian — Pure Functions
 *
 * Extracted from L3-auto-memory-guardian.ts for testability and reuse.
 *
 * No I/O here. The hook composes these helpers and handles file reads,
 * writes, audit logging, and process exit.
 *
 * @version 0.2.0 (0k-talon, Smart-L3 Phase 1)
 */

// ===========================================================================
// Types
// ===========================================================================

export interface Finding {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  detail: string;
  patternId?: string;
  file?: string;
  line?: number;
}

export interface PatternDef {
  id: string;
  pattern: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  flags?: string;
}

export interface CompiledPattern extends PatternDef {
  regex: RegExp;
}

export interface Section {
  /** Section title from `## ` header, or `__preamble__` for content before the first header. */
  title: string;
  /** Full section body, including the `## Title` header line if present. */
  body: string;
  /** 1-indexed start line of this section in the original file. */
  startLine: number;
}

/** Map of section title → findings detected in that section. */
export type SectionFindings = Map<string, Finding[]>;

export interface FrontmatterResult {
  /** The `source:` field from the frontmatter, or undefined if absent / no frontmatter. */
  source?: string;
  /** The file body after the frontmatter fence (or the full content if no frontmatter). */
  body: string;
}

export interface SurgicalResult {
  /** The MEMORY.md body with poisoned sections replaced by quarantine stubs. */
  cleanedBody: string;
  /** Sections that were extracted (original content) — caller writes these to quarantine. */
  extracted: Section[];
}

// ===========================================================================
// Frontmatter parsing
// ===========================================================================

/**
 * Parse YAML frontmatter at the top of a markdown file.
 *
 * Recognises the standard `---\n...\n---\n` fence at offset 0. Anything
 * else is treated as no frontmatter (fail safe — never raises on bad YAML).
 *
 * Only the `source:` field is extracted. The full body (everything after
 * the closing fence) is returned for downstream scanning.
 */
export function parseFrontmatter(content: string): FrontmatterResult {
  // Frontmatter must start at the very beginning with `---\n`.
  if (!content.startsWith('---\n')) {
    return { source: undefined, body: content };
  }

  // Find the closing `\n---\n` fence.
  const closeIdx = content.indexOf('\n---\n', 4);
  if (closeIdx === -1) {
    // Unterminated — treat as no frontmatter so we don't accidentally swallow content.
    return { source: undefined, body: content };
  }

  const fmText = content.slice(4, closeIdx);
  const body = content.slice(closeIdx + 5);

  // Extract `source:` field. Strip optional surrounding quotes from value.
  let source: string | undefined;
  for (const line of fmText.split('\n')) {
    const m = line.match(/^source\s*:\s*(.+?)\s*$/);
    if (m) {
      source = m[1]?.replace(/^["'](.*)["']$/, '$1');
      break;
    }
  }

  return { source, body };
}

// ===========================================================================
// trustedSources gate
// ===========================================================================

/**
 * Check whether a source identifier is in the trusted-writers allowlist.
 *
 * Case-sensitive exact match — sources are stable identifiers, not free
 * text. Returns false for undefined sources or empty allowlists.
 */
export function isTrustedSource(
  source: string | undefined,
  trustedSources: readonly string[],
): boolean {
  if (!source || trustedSources.length === 0) return false;
  return trustedSources.includes(source);
}

// ===========================================================================
// Section parsing (MEMORY.md splitter)
// ===========================================================================

const PREAMBLE_TITLE = '__preamble__';

/**
 * Split a markdown file into top-level `## ` sections.
 *
 * Content before the first `## ` becomes a section titled `__preamble__`.
 * `###` and deeper headers are part of their parent section's body.
 *
 * Each returned section's `body` is verbatim — joining all bodies in
 * order reproduces the original content exactly. We slice by byte
 * offset to preserve every blank line and trailing newline.
 */
export function parseSections(content: string): Section[] {
  const matches: Array<{ title: string; offset: number; lineNum: number }> = [];
  for (const m of content.matchAll(/^## (.+)$/gm)) {
    const titleRaw = m[1];
    if (!titleRaw || m.index === undefined) continue;
    matches.push({
      title: titleRaw.trim(),
      offset: m.index,
      // 1-indexed line number derived from byte offset.
      lineNum: content.slice(0, m.index).split('\n').length,
    });
  }

  if (matches.length === 0) {
    return [{ title: PREAMBLE_TITLE, body: content, startLine: 1 }];
  }

  const sections: Section[] = [];

  // Preamble — only emit if there is content before the first header.
  const firstOffset = matches[0]!.offset;
  if (firstOffset > 0) {
    sections.push({
      title: PREAMBLE_TITLE,
      body: content.slice(0, firstOffset),
      startLine: 1,
    });
  }

  // Each section runs from its header offset to the next header (or EOF).
  for (let i = 0; i < matches.length; i++) {
    const start = matches[i]!.offset;
    const end = i + 1 < matches.length ? matches[i + 1]!.offset : content.length;
    sections.push({
      title: matches[i]!.title,
      body: content.slice(start, end),
      startLine: matches[i]!.lineNum,
    });
  }

  return sections;
}

// ===========================================================================
// Pattern compilation
// ===========================================================================

/**
 * Compile pattern defs into RegExp objects. Always case-insensitive.
 * Strips the `g` flag to avoid `lastIndex` statefulness bugs when
 * patterns are reused across multiple inputs.
 *
 * Pattern source is the local memory config file (under
 * `~/.0k-talon/config/memory/`) plus hardcoded fallbacks in the hook —
 * never PR input or untrusted network data. Local-config trust boundary
 * is the same surface that already gates filesystem write access; if
 * an attacker can write that file, ReDoS via crafted patterns is the
 * least of the user's problems. Bad regex syntax is caught and skipped
 * by the try/catch below.
 */
// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
export function compilePatterns(defs: readonly PatternDef[]): CompiledPattern[] {
  const compiled: CompiledPattern[] = [];
  for (const def of defs) {
    try {
      const rawFlags = (def.flags || '') + 'i';
      const flags = rawFlags.replace(/g/gi, '');
      // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
      compiled.push({ ...def, regex: new RegExp(def.pattern, flags) });
    } catch {
      // Skip invalid regex
    }
  }
  return compiled;
}

// ===========================================================================
// Surgical quarantine
// ===========================================================================

/**
 * Stub written into MEMORY.md in place of an extracted section.
 * Documents which pattern triggered the extraction so the user can decide
 * whether to mark the entity as a trusted source on next session.
 */
function buildQuarantineStub(title: string, findings: readonly Finding[]): string {
  const patternIds = Array.from(
    new Set(findings.map((f) => f.patternId).filter(Boolean)),
  ).join(',');
  const ts = new Date().toISOString();
  return (
    `## ${title}\n\n` +
    `<!-- L3-QUARANTINED: pattern=${patternIds || 'unknown'} ts=${ts} -->\n` +
    `<!-- Original content extracted to quarantine. If this is a false positive, -->\n` +
    `<!-- restore the entity and add YAML frontmatter \`source: <trusted-id>\` -->\n` +
    `<!-- where the id is listed in your memory config trustedSources allowlist. -->\n\n`
  );
}

/**
 * Given parsed sections and a per-section findings map, return a cleaned
 * body (poisoned sections replaced with stubs) plus the list of extracted
 * sections for the caller to persist to the quarantine directory.
 *
 * Only CRITICAL findings trigger extraction. HIGH/MEDIUM are left in place
 * (alert-only behaviour, matching the existing hook semantics).
 */
export function surgicalQuarantineSections(
  sections: readonly Section[],
  findings: SectionFindings,
): SurgicalResult {
  const extracted: Section[] = [];
  const outBodies: string[] = [];

  for (const section of sections) {
    const sectionFindings = findings.get(section.title) ?? [];
    const hasCritical = sectionFindings.some((f) => f.severity === 'CRITICAL');

    if (hasCritical) {
      extracted.push(section);
      outBodies.push(buildQuarantineStub(section.title, sectionFindings));
    } else {
      outBodies.push(section.body);
    }
  }

  return {
    cleanedBody: outBodies.join(''),
    extracted,
  };
}

// ===========================================================================
// Exposed for tests — fallback patterns mirror the production set
// ===========================================================================

/**
 * Subset of fallback patterns exposed for the golden-FP regression test.
 * Mirror of the FALLBACK_INJECTION/SENSITIVE/PERSISTENT lists in the hook.
 * Kept in sync intentionally — drift here means the test corpus is wrong,
 * not the production code.
 */
export const FALLBACKS_FOR_TEST: PatternDef[] = [
  // Instruction injection
  { id: 'fb-inj-ignore', pattern: 'ignore\\s+(all\\s+)?(previous|prior)', severity: 'CRITICAL', description: 'Instruction override' },
  // Persistent poisoning
  { id: 'persist-secretly', pattern: '(secretly|covertly|silently|without\\s+informing)', severity: 'CRITICAL', description: 'Covert action' },
  // Sensitive (close mirror of memory/config patterns)
  { id: 'fb-sens-static-cred', pattern: '(api[_\\s-]?key|token|secret|password)[\\s\\w]{0,30}(static|hardcoded|plaintext|embedded)', severity: 'CRITICAL', description: 'Static credential' },
  // Persistent exfil
  { id: 'persist-exfil', pattern: '(exfiltrate|steal|copy|send|upload)\\s+.{0,20}(env|secret|key|token|credential|password)', severity: 'CRITICAL', description: 'Exfil instruction' },
];
