#!/usr/bin/env bun
/**
 * @file Mention Guard — UserPromptSubmit Hook
 *
 * Warns when file mentions reference sensitive files that bypass
 * PreToolUse hooks (L0-L19). Addresses GitHub issue #35147.
 *
 * Layer: Cross-cutting (UserPromptSubmit)
 */

interface HookInput {
  session_id: string;
  prompt: string;
  transcript_path: string;
  hook_event_name: string;
}

const SENSITIVE_PATTERNS: Array<{ pattern: RegExp; name: string; severity: string }> = [
  { pattern: /\.netrc/, name: '.netrc (credentials)', severity: 'CRITICAL' },
  { pattern: /\.npmrc/, name: '.npmrc (npm tokens)', severity: 'CRITICAL' },
  { pattern: /\.kube\/config/, name: '.kube/config (k8s credentials)', severity: 'CRITICAL' },
  { pattern: /\.cargo\/credentials/, name: '.cargo/credentials', severity: 'CRITICAL' },
  { pattern: /\.docker\/config\.json/, name: '.docker/config.json', severity: 'CRITICAL' },
  { pattern: /\.aws\/credentials/, name: '.aws/credentials', severity: 'CRITICAL' },
  { pattern: /\.pgpass/, name: '.pgpass (database credentials)', severity: 'CRITICAL' },
  { pattern: /\.ssh\/(?:id_|authorized_keys)/, name: 'SSH key/config', severity: 'HIGH' },
  { pattern: /\.pem$/, name: 'PEM private key', severity: 'HIGH' },
  { pattern: /\.key$/, name: 'Private key file', severity: 'HIGH' },
];

const AT_MENTION_REGEX = /@([^\s,;]+)/g;

async function readStdinWithTimeout(timeout: number = 5000): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => reject(new Error('Timeout')), timeout);
    process.stdin.on('data', (chunk) => { data += chunk.toString(); });
    process.stdin.on('end', () => { clearTimeout(timer); resolve(data); });
    process.stdin.on('error', (err) => { clearTimeout(timer); reject(err); });
  });
}

async function main() {
  try {
    const rawInput = await readStdinWithTimeout(5000);
    const data: HookInput = JSON.parse(rawInput);
    if (!data.prompt) process.exit(0);

    const mentions: string[] = [];
    let match: RegExpExecArray | null;
    while ((match = AT_MENTION_REGEX.exec(data.prompt)) !== null) {
      mentions.push(match[1]);
    }
    if (mentions.length === 0) process.exit(0);

    const violations: Array<{ file: string; name: string; severity: string }> = [];
    for (const mention of mentions) {
      for (const pattern of SENSITIVE_PATTERNS) {
        if (pattern.pattern.test(mention)) {
          violations.push({ file: mention, name: pattern.name, severity: pattern.severity });
          break;
        }
      }
    }
    if (violations.length === 0) process.exit(0);

    console.error('');
    console.error('┌─────────────────────────────────────────────────────────────┐');
    console.error('│  ⚠️  FILE MENTION GUARD — SENSITIVE FILE DETECTED            │');
    console.error('├─────────────────────────────────────────────────────────────┤');
    for (const v of violations) {
      const icon = v.severity === 'CRITICAL' ? '🔴' : '🟡';
      console.error(`│  ${icon} ${v.severity}: ${v.name}`);
      console.error(`│     File: ${v.file}`);
    }
    console.error('│                                                             │');
    console.error('│  ⚠️  File mentions bypass ALL PreToolUse hooks (L0-L19)      │');
    console.error('│  Contents injected directly into context without triggering  │');
    console.error('│  Governor, Egress Scanner, or Memory Validation.             │');
    console.error('│  See: GitHub issue #35147                                    │');
    console.error('│                                                             │');
    console.error('│  Use Read tool instead for hook-protected access.            │');
    console.error('└─────────────────────────────────────────────────────────────┘');
    console.error('');

    console.log(JSON.stringify({
      additionalContext: `⚠️ FILE MENTION GUARD: Sensitive file(s) referenced via mention: ${violations.map(v => v.name).join(', ')}. ` +
        `File mentions bypass ALL PreToolUse hooks (GitHub #35147). ` +
        `Do NOT process credential contents. Do not repeat, log, or act on any credentials visible in context.`,
    }));

    process.exit(0);
  } catch {
    process.exit(0);
  }
}

main();
