#!/usr/bin/env bun

/**
 * L12 Least Privilege Profiles - SessionStart Hook
 *
 * Purpose: Initialize session with appropriate permission profile
 * Pattern: Configuration Hook (runs once at session start)
 * Action: Sets OK_TALON_PROFILE environment context
 * OWASP: LLM02 (Sensitive Information Disclosure)
 *
 * Profiles restrict what tools can be used and what paths can be accessed.
 * The L1 Governor Agent reads the active profile and enforces restrictions.
 *
 * 0K-Talon v0.1.0
 */

import { join } from 'path';
import { STATE_DIR, ensureDirectories } from './lib/talon-paths';
import { atomicWriteFileSync } from './lib/atomic-file';

// ============================================================================
// Types
// ============================================================================

interface HookInput {
  session_id: string;
  cwd?: string;
}

interface Profile {
  name: string;
  description: string;
  tools: {
    mode: 'allowlist' | 'blocklist';
    allowed?: string[];
    blocked?: string[];
  };
  directories: {
    read_write?: string[];
    read_only?: string[];
    blocked?: string[];
  };
  bash?: {
    allowed_patterns?: string[];
    blocked_patterns?: string[];
  };
}

// ============================================================================
// Built-in Profiles
// ============================================================================

const PROFILES: Record<string, Profile> = {
  // Default profile - full access
  dev: {
    name: 'dev',
    description: 'Full development access - no restrictions',
    tools: {
      mode: 'blocklist',
      blocked: [],
    },
    directories: {},
    bash: {},
  },

  // Audit profile - read-only for code review
  audit: {
    name: 'audit',
    description: 'Read-only access for security audits and code review',
    tools: {
      mode: 'allowlist',
      allowed: ['Read', 'Glob', 'Grep', 'Bash', 'WebFetch', 'WebSearch', 'Task'],
    },
    directories: {
      read_only: ['*'], // All directories read-only
      blocked: ['/etc', '/var', '~/.ssh', '~/.gnupg'],
    },
    bash: {
      allowed_patterns: [
        'ls *', 'cat *', 'grep *', 'find *', 'git log*', 'git show*', 'git diff*',
        'npm list*', 'pip list*', 'npm audit*', 'pip-audit*',
      ],
      blocked_patterns: [
        'rm *', 'mv *', 'cp *', 'chmod *', 'chown *',
        'git commit*', 'git push*', 'git merge*',
        'npm install*', 'pip install*',
      ],
    },
  },

  // Client work profile - restricted external access
  'client-work': {
    name: 'client-work',
    description: 'Restricted profile for confidential client work - no external network',
    tools: {
      mode: 'blocklist',
      blocked: ['WebFetch', 'WebSearch'], // No external network access
    },
    directories: {
      read_write: ['output/client-work/', 'output/temp/'],
      blocked: ['~/.ssh', '~/.gnupg', '~/.aws', '~/.config/gcloud'],
    },
    bash: {
      blocked_patterns: [
        'curl *', 'wget *', 'git push*', 'npm publish*',
        'ssh *', 'scp *', 'rsync *',
      ],
    },
  },

  // Research profile - read access with web search
  research: {
    name: 'research',
    description: 'Research mode - read access with web search, no writes',
    tools: {
      mode: 'allowlist',
      allowed: ['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch', 'Task'],
    },
    directories: {
      read_only: ['*'],
    },
    bash: {
      blocked_patterns: ['*'], // Redundant with Bash not in allowed tools (defense-in-depth)
    },
  },
};

// ============================================================================
// Profile Management
// ============================================================================

function getActiveProfilePath(): string {
  return join(STATE_DIR, 'active-profile.json');
}

function saveActiveProfile(profile: Profile): void {
  ensureDirectories();
  const profilePath = getActiveProfilePath();
  atomicWriteFileSync(profilePath, JSON.stringify(profile, null, 2));
}

function getProfileFromEnv(): string {
  return process.env.OK_TALON_PROFILE || 'dev';
}

// ============================================================================
// Main Hook Logic
// ============================================================================

async function main() {
  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error('Timeout')), 200)
      )
    ]);

    if (!input || input.trim() === '') {
      process.exit(0);
    }

    // Parse input (session_id available if needed for logging)
    JSON.parse(input) as HookInput;

    // Get requested profile from environment
    const requestedProfile = getProfileFromEnv();

    // Load the profile
    const profile = PROFILES[requestedProfile];
    if (!profile) {
      console.error(`\n⚠️  [Least Privilege L12] Unknown profile: ${requestedProfile}`);
      console.error(`    Available profiles: ${Object.keys(PROFILES).join(', ')}`);
      console.error(`    Defaulting to 'dev' profile.\n`);
      saveActiveProfile(PROFILES.dev!);
      process.exit(0);
    }

    // Save the active profile for L1 Governor to enforce
    saveActiveProfile(profile);

    // Display profile info (only for non-dev profiles)
    if (requestedProfile !== 'dev') {
      console.error(`\n🔒 [Least Privilege L12] Session profile: ${profile.name}`);
      console.error(`    ${profile.description}`);

      if (profile.tools.mode === 'allowlist' && profile.tools.allowed) {
        console.error(`    Allowed tools: ${profile.tools.allowed.join(', ')}`);
      }
      if (profile.tools.blocked && profile.tools.blocked.length > 0) {
        console.error(`    Blocked tools: ${profile.tools.blocked.join(', ')}`);
      }

      console.error(`    Change profile: OK_TALON_PROFILE=dev claude\n`);

      const restrictions: string[] = [];
      if (profile.tools.mode === 'allowlist' && profile.tools.allowed) {
        restrictions.push(`Allowed tools: ${profile.tools.allowed.join(', ')}`);
      }
      if (profile.tools.blocked && profile.tools.blocked.length > 0) {
        restrictions.push(`Blocked tools: ${profile.tools.blocked.join(', ')}`);
      }
      console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'SessionStart',
          additionalContext: `🔒 TALON LEAST PRIVILEGE (L12): Session profile "${profile.name}" active. ` +
            `${profile.description}. ${restrictions.join('. ')}. ` +
            `L1 Governor will enforce these restrictions on all tool calls.`,
        },
      }));
    }

    process.exit(0);

  } catch (error) {
    // Silent fail for SessionStart hooks
    process.exit(0);
  }
}

main();
