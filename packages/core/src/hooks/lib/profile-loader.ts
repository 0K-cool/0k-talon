/**
 * Profile Loader - Shared utility for L12 and L1
 *
 * Provides profile type definitions and loading functions
 * for the Least Privilege system.
 */

import { existsSync, openSync, fstatSync, readFileSync, closeSync } from 'fs';
import { join } from 'path';
import { STATE_DIR } from './talon-paths';

// ============================================================================
// Types (exported for L1 Governor)
// ============================================================================

export interface Profile {
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

export interface ProfileEnforcementResult {
  allowed: boolean;
  reason: string;
  profile: string;
}

// ============================================================================
// Profile Loading
// ============================================================================

function getActiveProfilePath(): string {
  return join(STATE_DIR, 'active-profile.json');
}

/**
 * Load the active profile set by L12 SessionStart hook.
 * Validates file ownership to prevent profile injection attacks.
 *
 * Security: Uses fd-based operations (openSync → fstatSync → readFileSync)
 * on the same file descriptor to eliminate TOCTOU race between stat and read.
 *
 * Windows: process.getuid is undefined on Windows. The optional chain (?.)
 * returns undefined, which never equals stat.uid, so ALL profiles are
 * rejected on Windows. This is fail-safe (returns null = no restrictions).
 */
export function loadActiveProfile(): Profile | null {
  let fd: number | null = null;
  try {
    const profilePath = getActiveProfilePath();
    if (!existsSync(profilePath)) return null;

    // Open fd, then stat+read on same fd to eliminate TOCTOU
    fd = openSync(profilePath, 'r');
    const stat = fstatSync(fd);
    if (stat.uid !== process.getuid?.()) {
      console.error(`[profile-loader] WARNING: ${profilePath} not owned by current user. Ignoring.`);
      return null;
    }
    const content = readFileSync(fd, 'utf-8');
    return JSON.parse(content) as Profile;
  } catch {
    // Fall through - profile not set or invalid
    return null;
  } finally {
    if (fd !== null) try { closeSync(fd); } catch { /* best effort */ }
  }
}

// ============================================================================
// Profile Enforcement
// ============================================================================

/**
 * Check if a tool is allowed by the active profile
 */
export function isToolAllowed(tool: string, profile: Profile): ProfileEnforcementResult {
  // Default dev profile allows everything
  if (profile.name === 'dev') {
    return { allowed: true, reason: 'dev profile - no restrictions', profile: 'dev' };
  }

  const { mode, allowed, blocked } = profile.tools;

  if (mode === 'allowlist') {
    // Allowlist mode: only tools in 'allowed' array are permitted
    if (allowed && allowed.includes(tool)) {
      return { allowed: true, reason: `Tool in allowlist`, profile: profile.name };
    }
    return {
      allowed: false,
      reason: `Tool '${tool}' not in allowlist for '${profile.name}' profile. Allowed: ${allowed?.join(', ') || 'none'}`,
      profile: profile.name,
    };
  }

  if (mode === 'blocklist') {
    // Blocklist mode: all tools allowed except those in 'blocked' array
    if (blocked && blocked.includes(tool)) {
      return {
        allowed: false,
        reason: `Tool '${tool}' blocked by '${profile.name}' profile`,
        profile: profile.name,
      };
    }
    return { allowed: true, reason: `Tool not in blocklist`, profile: profile.name };
  }

  return { allowed: true, reason: 'Unknown mode - allowing', profile: profile.name };
}

/**
 * Check if a path is allowed by the active profile
 */
export function isPathAllowed(
  path: string,
  operation: 'read' | 'write',
  profile: Profile
): ProfileEnforcementResult {
  // Default dev profile allows everything
  if (profile.name === 'dev') {
    return { allowed: true, reason: 'dev profile - no restrictions', profile: 'dev' };
  }

  const { read_write, read_only, blocked } = profile.directories;

  // Check blocked paths first
  if (blocked) {
    for (const blockedPath of blocked) {
      const expandedPath = blockedPath.replace('~', process.env.HOME || '');
      if (path.includes(expandedPath) || path.startsWith(expandedPath)) {
        return {
          allowed: false,
          reason: `Path '${path}' is blocked by '${profile.name}' profile`,
          profile: profile.name,
        };
      }
    }
  }

  // For write operations, check if path is read-only
  if (operation === 'write' && read_only) {
    // If read_only is ['*'], all paths are read-only
    if (read_only.includes('*')) {
      // Unless in read_write list
      if (read_write) {
        for (const rwPath of read_write) {
          if (path.includes(rwPath) || path.startsWith(rwPath)) {
            return { allowed: true, reason: `Path in read_write allowlist`, profile: profile.name };
          }
        }
      }
      return {
        allowed: false,
        reason: `Write operation blocked - '${profile.name}' profile is read-only`,
        profile: profile.name,
      };
    }
  }

  return { allowed: true, reason: 'Path not restricted', profile: profile.name };
}

/**
 * Check if a bash command is allowed by the active profile
 */
export function isBashCommandAllowed(command: string, profile: Profile): ProfileEnforcementResult {
  // Default dev profile allows everything
  if (profile.name === 'dev') {
    return { allowed: true, reason: 'dev profile - no restrictions', profile: 'dev' };
  }

  const { allowed_patterns, blocked_patterns } = profile.bash || {};

  // Check blocked patterns first
  if (blocked_patterns) {
    for (const pattern of blocked_patterns) {
      // Convert glob pattern to regex
      const regex = new RegExp('^' + pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*?') + '$', 'i');
      if (regex.test(command) || command.startsWith(pattern.replace(/\*/g, ''))) {
        return {
          allowed: false,
          reason: `Bash command blocked by '${profile.name}' profile: matches '${pattern}'`,
          profile: profile.name,
        };
      }
    }
  }

  // If allowed_patterns is set and not matching, block
  if (allowed_patterns && allowed_patterns.length > 0) {
    for (const pattern of allowed_patterns) {
      const regex = new RegExp('^' + pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*?') + '$', 'i');
      if (regex.test(command) || command.startsWith(pattern.replace(/\*/g, ''))) {
        return { allowed: true, reason: `Bash command in allowlist`, profile: profile.name };
      }
    }
    return {
      allowed: false,
      reason: `Bash command not in allowlist for '${profile.name}' profile`,
      profile: profile.name,
    };
  }

  return { allowed: true, reason: 'No bash restrictions', profile: profile.name };
}
