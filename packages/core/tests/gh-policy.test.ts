/**
 * gh-policy classifier — compound-command decomposition.
 *
 * Regression coverage for the bypass where a Tier-2 gh op embedded in a
 * compound command (`cd … && gh pr merge`) evaded classification because
 * the classifier gated on the WHOLE command starting with `gh`. The merge
 * ran without consuming a confirm token. classifyGhCommand must decompose
 * shell segments (&&, ||, ;, |, &, newline, $( ), backticks) and classify
 * each — returning the most-severe tier — without false-positiving on `gh`
 * appearing inside a quoted string.
 */

import { describe, it, expect } from 'vitest';
import { classifyGhCommand, GhTier } from '../src/hooks/lib/gh-policy';

describe('classifyGhCommand — bare commands (existing behavior preserved)', () => {
  it('classifies a bare Tier-2 pr merge as CONFIRM', () => {
    expect(classifyGhCommand('gh pr merge 5 --squash --delete-branch').tier).toBe(GhTier.CONFIRM);
  });
  it('classifies a bare Tier-1 repo delete as BLOCK', () => {
    expect(classifyGhCommand('gh repo delete 0K-cool/x --yes').tier).toBe(GhTier.BLOCK);
  });
  it('classifies a routine read as ALLOW', () => {
    expect(classifyGhCommand('gh pr view 5').tier).toBe(GhTier.ALLOW);
  });
  it('classifies a non-gh command as NOT_GH', () => {
    expect(classifyGhCommand('ls -la && cat file.txt').tier).toBe(GhTier.NOT_GH);
  });
});

describe('classifyGhCommand — compound-command decomposition (the bypass)', () => {
  it('catches a Tier-2 pr merge buried after && (the exact bypass)', () => {
    const cmd = 'cd /repo && echo "merging" && gh pr merge 77 --squash --delete-branch';
    expect(classifyGhCommand(cmd).tier).toBe(GhTier.CONFIRM);
  });
  it('catches a Tier-1 repo delete buried after &&', () => {
    expect(classifyGhCommand('echo hi && gh repo delete foo --yes').tier).toBe(GhTier.BLOCK);
  });
  it('catches a Tier-2 op after a semicolon', () => {
    expect(classifyGhCommand('cd /x; gh secret set FOO --body bar').tier).toBe(GhTier.CONFIRM);
  });
  it('catches a Tier-2 op on the right side of a pipe', () => {
    expect(classifyGhCommand('cat body.txt | gh secret set FOO').tier).toBe(GhTier.CONFIRM);
  });
  it('catches a gh op inside command substitution', () => {
    // gh repo view is routine → ALLOW, but it must be detected as gh (not NOT_GH)
    expect(classifyGhCommand('cat $(gh repo view --json name) && echo done').tier).toBe(GhTier.ALLOW);
  });
  it('returns the MOST SEVERE tier across multiple gh segments', () => {
    expect(classifyGhCommand('gh pr merge 5 && gh repo delete x --yes').tier).toBe(GhTier.BLOCK);
  });
});

describe('classifyGhCommand — no false positives on gh-in-string', () => {
  it('does NOT classify gh mentioned inside an echo string as a gh op', () => {
    expect(classifyGhCommand('echo "to merge, run gh pr merge 5 later"').tier).toBe(GhTier.NOT_GH);
  });
  it('does NOT classify a filename containing gh as a gh op', () => {
    expect(classifyGhCommand('cat high-gh-notes.txt').tier).toBe(GhTier.NOT_GH);
  });
  it('does NOT flag a commit message that mentions a gh op with shell operators', () => {
    // The self-referential case: committing this very fix tripped the gate.
    const cmd = 'git commit -m "fix: a compound cmd like cd && gh pr merge bypassed the gate"';
    expect(classifyGhCommand(cmd).tier).toBe(GhTier.NOT_GH);
  });
  it('does NOT flag gh op text inside single-quoted strings', () => {
    expect(classifyGhCommand("echo 'gh secret set FOO' >> notes.md").tier).toBe(GhTier.NOT_GH);
  });
  it('classifies a real gh command with a gh-op phrase in its quoted args by the COMMAND, not the quote', () => {
    // `gh pr create` is routine ALLOW; the quoted title mentioning "gh pr merge" must not upgrade it to CONFIRM.
    expect(classifyGhCommand('gh pr create --title "automate gh pr merge later"').tier).toBe(GhTier.ALLOW);
  });
});

describe('classifyGhCommand — shell-aware hardening (post-merge HIGH findings)', () => {
  // Finding 1: escaped quotes must not let a real op be swallowed by quote-stripping.
  it('catches a Tier-2 op wrapped in escaped quotes (escaped-quote bypass)', () => {
    expect(classifyGhCommand('echo \\" ; gh pr merge 5 --squash ; echo \\"').tier).toBe(GhTier.CONFIRM);
  });
  it('catches a Tier-1 op wrapped in escaped quotes', () => {
    expect(classifyGhCommand('echo \\" ; gh repo delete 0K-cool/x --yes ; echo \\"').tier).toBe(GhTier.BLOCK);
  });

  // Finding 2: process substitution executes its inner command.
  it('catches a Tier-1 op inside process substitution <( )', () => {
    expect(classifyGhCommand('cat <(gh repo delete 0K-cool/x --yes)').tier).toBe(GhTier.BLOCK);
  });
  it('catches a Tier-2 op inside process substitution >( )', () => {
    expect(classifyGhCommand('tee >(gh secret set FOO) < in.txt').tier).toBe(GhTier.CONFIRM);
  });

  // Shell-wrapper payloads (sh -c / bash -c / eval) execute a quoted command string.
  it('catches a Tier-1 op inside sh -c "..."', () => {
    expect(classifyGhCommand('sh -c "gh repo delete 0K-cool/x --yes"').tier).toBe(GhTier.BLOCK);
  });
  it('catches a Tier-2 op inside bash -c "..."', () => {
    expect(classifyGhCommand('bash -c "gh pr merge 5 --squash"').tier).toBe(GhTier.CONFIRM);
  });
  it('catches a Tier-2 op inside eval "..."', () => {
    expect(classifyGhCommand('eval "gh secret set DEPLOY_KEY --body x"').tier).toBe(GhTier.CONFIRM);
  });

  // xargs runs its args as a command with stdin appended.
  it('catches a Tier-2 op invoked via xargs', () => {
    expect(classifyGhCommand('echo 5 | xargs gh pr merge').tier).toBe(GhTier.CONFIRM);
  });

  // Unbalanced quotes are ambiguous → must not hide a real op (fail closed).
  it('does not let an unbalanced quote hide a Tier-2 op', () => {
    expect(classifyGhCommand('gh pr merge 5 ; echo "oops').tier).toBe(GhTier.CONFIRM);
  });

  // A shell wrapper with NO gh op must stay NOT_GH (no false block).
  it('does not flag a shell wrapper that contains no gh op', () => {
    expect(classifyGhCommand('sh -c "ls -la && cat file.txt"').tier).toBe(GhTier.NOT_GH);
  });
});

describe('classifyGhCommand — CONTAINS classifier (runner options + interpreters)', () => {
  // HIGH: command-runner with options between runner and gh.
  it('catches a Tier-1 op via xargs with options (xargs -I{})', () => {
    expect(classifyGhCommand('echo 0K-cool/x | xargs -I{} gh repo delete {} --yes').tier).toBe(GhTier.BLOCK);
  });
  it('catches a Tier-1 op behind nice with options', () => {
    expect(classifyGhCommand('nice -n5 gh repo delete 0K-cool/x --yes').tier).toBe(GhTier.BLOCK);
  });

  // MEDIUM: interpreters beyond the sh/bash/zsh/dash/ash + eval allowlist.
  it('catches a Tier-1 op inside a fish -c payload', () => {
    expect(classifyGhCommand('fish -c "gh repo delete 0K-cool/x --yes"').tier).toBe(GhTier.BLOCK);
  });
  it('catches a Tier-1 op inside a ksh -c payload', () => {
    expect(classifyGhCommand('ksh -c "gh secret remove DEPLOY_KEY"').tier).toBe(GhTier.BLOCK);
  });
  it('catches a Tier-1 op inside a python -c payload', () => {
    expect(classifyGhCommand('python -c "import os; os.system(\'gh repo delete 0K-cool/x --yes\')"').tier).toBe(GhTier.BLOCK);
  });
  it('does not flag an interpreter payload that contains no gh op', () => {
    expect(classifyGhCommand('python -c "print(1+1)"').tier).toBe(GhTier.NOT_GH);
  });

  // Regression: interpreter wrapper placed immediately after a shell metacharacter
  // (no whitespace) must still trigger the Stage-2 fail-safe sweep.
  it('catches a Tier-1 op in a wrapper directly after a semicolon (;sh -c)', () => {
    expect(classifyGhCommand(':;sh -c "gh repo delete 0K-cool/vex --yes"').tier).toBe(GhTier.BLOCK);
  });
  it('catches a Tier-1 op in a wrapper directly after a pipe (|bash -c)', () => {
    expect(classifyGhCommand('true|bash -c "gh secret remove DEPLOY_KEY"').tier).toBe(GhTier.BLOCK);
  });
  it('catches a Tier-1 op in a wrapper directly after a paren ((zsh -c)', () => {
    expect(classifyGhCommand('(zsh -c "gh repo delete 0K-cool/x --yes")').tier).toBe(GhTier.BLOCK);
  });
  it('catches a wrapper invoked by absolute path (/bin/sh -c)', () => {
    expect(classifyGhCommand('/bin/sh -c "gh secret remove K"').tier).toBe(GhTier.BLOCK);
  });
});

describe('classifyGhCommand — review-round hardening (CodeRabbit findings)', () => {
  // #1 release create publishes by default; not only --draft=false.
  it('gates a plain release create (publishes by default)', () => {
    expect(classifyGhCommand('gh release create v1.2.3 --notes x').tier).toBe(GhTier.CONFIRM);
  });

  // #2 escaped command fragment: bash runs g\h as gh.
  it('catches an escaped command fragment (g\\h pr merge)', () => {
    expect(classifyGhCommand('g\\h pr merge 5 --squash').tier).toBe(GhTier.CONFIRM);
  });
  it('still catches the escaped-quote wrapping after the escape fix', () => {
    expect(classifyGhCommand('echo \\" ; gh repo delete o/r --yes ; echo \\"').tier).toBe(GhTier.BLOCK);
  });

  // #3 clustered interpreter flags (bash -lc).
  it('catches a Tier-1 op inside bash -lc (clustered flags)', () => {
    expect(classifyGhCommand('bash -lc "gh repo delete 0K-cool/x --yes"').tier).toBe(GhTier.BLOCK);
  });

  // #94 --method=VERB form (with =, not just space).
  it('catches gh api --method=DELETE (= form)', () => {
    expect(classifyGhCommand('gh api --method=DELETE /repos/o/r').tier).toBe(GhTier.BLOCK);
  });
  it('catches gh api --method=POST (= form) as Tier 2', () => {
    expect(classifyGhCommand('gh api --method=POST /repos/o/r/issues').tier).toBe(GhTier.CONFIRM);
  });
});
