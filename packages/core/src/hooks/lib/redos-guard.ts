/**
 * ReDoS static guard for externally-loaded detection patterns.
 *
 * Catastrophic backtracking comes from a group quantified by an UNBOUNDED
 * quantifier (`+`, `*`, `{n,}`) whose interior ALSO carries an unbounded
 * quantifier — `(a+)+`, `(.*)*`, `(\d+)*`, `(x{2,})+`.
 *
 * BOUNDED quantifiers (`{n,m}`, `?`) are polynomial-at-worst and MUST NOT be
 * flagged: dropping them costs real detection coverage. The predecessor
 * heuristic (`/(\+|\*|\{)\)(\+|\*|\{)/`) failed in both directions — it missed
 * the `{n,}` shape and disabled two live patterns that were merely bounded.
 *
 * This static drop is the ONLY defense against the exponential class — measured
 * on V8, `(a+)+$` needs ~28s on a 30-byte input, so the scanners' 8KB input cap
 * is no help there, and their wall-clock budget is checked BETWEEN patterns and
 * cannot interrupt a single uninterruptible match. The cap and budget bound the
 * polynomial/accumulation cases; this check bounds the exponential one.
 *
 * It is a shape check, so the alternation-overlap class (`(a|a)+`) stays
 * invisible to it. A linear-time engine (re2) is the follow-up for full
 * hard guarantees.
 */

/** Unbounded quantifier: `+`, `*`, or `{n,}` (note the required trailing comma). */
const UNBOUNDED = String.raw`(?:[+*]|\{\d+,\})`;

const NESTED_UNBOUNDED = new RegExp(
  String.raw`\([^()]*${UNBOUNDED}[^()]*\)${UNBOUNDED}`
);

/**
 * True when `source` contains a group under an unbounded quantifier whose
 * interior is also unbounded — the catastrophic-backtracking shape.
 */
export function isRedosVulnerable(source: string): boolean {
  return NESTED_UNBOUNDED.test(source);
}
