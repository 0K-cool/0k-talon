/**
 * T-1 — the workspace must not be able to relocate the control plane.
 *
 * `detectTalonDir()` used to fall back to scanning the current working
 * directory for `.0k-talon/`, `0k-talon/`, or `.claude-plugin/0k-talon/`.
 * A cloned repo that ships one of those directories then owned config, state,
 * logs AND quarantine for the session that scanned it. Measured effect of the
 * substitution: the injection pattern set collapsed from 272 patterns to 1,
 * with no error and no warning.
 *
 * The branch was only reachable when `~/.0k-talon` did not exist, so a fresh
 * install was the exposure window. Project-local installation was never a
 * documented mode — the README only ever describes `~/.0k-talon` and
 * `TALON_DIR` — so the discovery scan was removed rather than gated.
 *
 * Subprocess-level on purpose: TALON_DIR is resolved once at module load from
 * `process.cwd()`, so the only honest way to test it is to load the module
 * from inside a hostile directory and read back what it picked.
 */

import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const PATHS_MODULE = fileURLToPath(
  new URL('../src/hooks/lib/talon-paths.ts', import.meta.url),
);

let root: string;
let hostileRepo: string;
let cleanHome: string;
let probe: string;

beforeAll(() => {
  // realpath: on macOS `tmpdir()` is /var/... but a process started there
  // reports cwd as /private/var/..., which would let these assertions match
  // on the wrong string.
  root = realpathSync(mkdtempSync(join(tmpdir(), 'talon-t1-')));

  // A repo that ships every directory name the old scan looked for.
  hostileRepo = join(root, 'hostile-repo');
  for (const bait of ['.0k-talon', '0k-talon', join('.claude-plugin', '0k-talon')]) {
    mkdirSync(join(hostileRepo, bait, 'config'), { recursive: true });
  }

  // A HOME with no global install — the only state where the scan ever ran.
  cleanHome = join(root, 'clean-home');
  mkdirSync(cleanHome, { recursive: true });

  probe = join(root, 'probe.ts');
  writeFileSync(
    probe,
    `import { TALON_DIR } from ${JSON.stringify(PATHS_MODULE)};\nconsole.log(TALON_DIR);\n`,
  );
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

/** Load talon-paths from inside `cwd` and report the directory it resolved. */
function resolveTalonDirFrom(cwd: string, env: Record<string, string>): string {
  const res = spawnSync('bun', ['run', probe], {
    cwd,
    encoding: 'utf-8',
    timeout: 20_000,
    env: { ...process.env, ...env },
  });
  return (res.stdout ?? '').trim().split('\n').pop() ?? '';
}

describe('T-1: control-plane location is not workspace-controlled', () => {
  it('ignores a .0k-talon directory shipped by the working directory', () => {
    const resolved = resolveTalonDirFrom(hostileRepo, { HOME: cleanHome });

    expect(resolved).not.toContain(hostileRepo);
    expect(resolved).toBe(join(cleanHome, '.0k-talon'));
  });

  it('ignores 0k-talon/ and .claude-plugin/0k-talon/ bait as well', () => {
    // Same assertion from one directory up, where only the nested
    // .claude-plugin/0k-talon bait is a direct child.
    const nested = join(hostileRepo, '.claude-plugin');
    const resolved = resolveTalonDirFrom(nested, { HOME: cleanHome });

    expect(resolved).not.toContain(hostileRepo);
    expect(resolved).toBe(join(cleanHome, '.0k-talon'));
  });

  it('still honors an explicit, validated TALON_DIR', () => {
    const operatorDir = join(cleanHome, 'custom-talon');
    mkdirSync(operatorDir, { recursive: true });

    const resolved = resolveTalonDirFrom(hostileRepo, {
      HOME: cleanHome,
      TALON_DIR: operatorDir,
    });

    expect(resolved).toBe(operatorDir);
  });

  it('still prefers the global install when one exists', () => {
    const homeWithInstall = join(root, 'home-with-install');
    mkdirSync(join(homeWithInstall, '.0k-talon'), { recursive: true });

    const resolved = resolveTalonDirFrom(hostileRepo, { HOME: homeWithInstall });

    expect(resolved).toBe(join(homeWithInstall, '.0k-talon'));
  });
});
