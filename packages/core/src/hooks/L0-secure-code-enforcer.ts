#!/usr/bin/env bun

/**
 * L0: Secure Code Enforcer - PreToolUse Hook
 *
 * Part of Vex-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: Enforce secure coding practices BEFORE writing security-sensitive code.
 *          BLOCKS CRITICAL vulnerabilities (SQL injection, command injection, secrets).
 *          WARNS on HIGH/MEDIUM vulnerabilities.
 *
 * Pattern: Sidecar Pattern (monitoring before tool execution)
 *
 * Behavior:
 * - CRITICAL findings: Output { decision: "block" } - prevents write
 * - HIGH findings: Display warning, allow write (Layer 2 safety net)
 * - MEDIUM/LOW: Log only
 *
 * Maps to:
 * - OWASP LLM01 (Prompt Injection)
 * - OWASP LLM02 (Insecure Output Handling)
 * - MITRE ATLAS AML.T0048 (Adversarial Example)
 *
 * @version 0.1.0 (vex-talon)
 * @date 2026-02-04
 */

import { extname } from 'path';
import { normalizeUnicode } from './lib/unicode-normalize';
import {
  ensureTalonDirs,
  getAuditLogPath,
  secureAppendLog,
} from './lib/talon-paths';
// Note: config-loader patterns available but using bundled defaults for reliability
// import { loadCodeEnforcerPatterns, compilePattern } from './lib/config-loader';

// ============================================================================
// Types
// ============================================================================

interface HookInput {
  session_id: string;
  transcript_path: string;
  hook_event_name: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
  cwd?: string;
}

type CodeType = 'SECURITY_SENSITIVE' | 'SAFE' | 'UNKNOWN';
type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface ClassificationResult {
  type: CodeType;
  riskLevel: RiskLevel;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  triggers: string[];
  suggestReview: boolean;
}

interface AuditEntry {
  timestamp: string;
  tool: string;
  file_path: string;
  language: string;
  classification: CodeType;
  risk_level: RiskLevel;
  confidence: string;
  triggers: string[];
  blocked: boolean;
  session_id: string;
}

// ============================================================================
// Configuration
// ============================================================================

const HOOK_NAME = 'L0-secure-code-enforcer';
const WRITE_TOOLS = ['Write', 'Edit'];

const CODE_EXTENSIONS: Record<string, string> = {
  '.py': 'python',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.sh': 'shell',
  '.bash': 'shell',
  '.go': 'go',
  '.rs': 'rust',
  '.rb': 'ruby',
  '.php': 'php',
  '.java': 'java',
  '.sql': 'sql',
};

// Skip paths for security infrastructure (false positive prevention)
const SKIP_PATHS = [
  '/hooks/',
  '/node_modules/',
  '/.vex-talon/',
  '/security/',
  '/tests/',
  '/test/',
  '/__tests__/',
  '.test.ts',
  '.test.js',
  '.spec.ts',
  '.spec.js',
];

// ============================================================================
// Bundled Default Patterns (Critical Security)
// ============================================================================

// CRITICAL: SQL Injection
const SQL_PATTERNS = {
  injection: [
    /f["'].*SELECT.*WHERE.*\{/i,
    /f["'].*INSERT.*VALUES.*\{/i,
    /f["'].*UPDATE.*SET.*\{/i,
    /f["'].*DELETE.*WHERE.*\{/i,
    /\.format\(.*\).*SELECT/i,
    /`.*SELECT.*\$\{/i,
    /\+\s*["'].*SELECT/i,
    /["'].*SELECT.*["']\s*\+/i,
    /execute\s*\(\s*f["']/i,
    /query\s*=\s*f["']/i,
  ],
  keywords: /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b/i,
};

// CRITICAL: Command Injection
const COMMAND_PATTERNS = {
  injection: [
    /subprocess\.run\(.*shell\s*=\s*True/i,
    /subprocess\.call\(.*shell\s*=\s*True/i,
    /subprocess\.Popen\(.*shell\s*=\s*True/i,
    /os\.system\s*\(/i,
    /os\.popen\s*\(/i,
    /exec\s*\(\s*f["']/i,
    /eval\s*\(/i,
    /new\s+Function\s*\(/i,
    /import\s*\(\s*[^)]*\+/i,
    /child_process\.exec\s*\(/i,
    /execSync\s*\(/i,
    /spawn\s*\(.*shell:\s*true/i,
  ],
  keywords: /\b(subprocess|os\.system|os\.popen|exec|eval|Function|child_process|spawn|execSync)\b/,
};

// CRITICAL: Hardcoded Secrets
const SECRET_PATTERNS = {
  apiKeys: [
    /["']sk-[a-zA-Z0-9]{20,}["']/,
    /["']pplx-[a-zA-Z0-9]{20,}["']/,
    /["']ghp_[a-zA-Z0-9]{36}["']/,
    /["']gho_[a-zA-Z0-9]{36}["']/,
    /["']AKIA[A-Z0-9]{16}["']/,
  ],
  passwords: [
    /password\s*=\s*["'][^"']+["']/i,
    /passwd\s*=\s*["'][^"']+["']/i,
    /secret\s*=\s*["'][^"']+["']/i,
    /api_key\s*=\s*["'][^"']+["']/i,
    /apiKey\s*=\s*["'][^"']+["']/i,
  ],
};

// HIGH: Path Traversal
const FILE_PATTERNS = {
  traversal: [
    /open\s*\(\s*f["']/i,
    /open\s*\(.*\+/i,
    /readFile\s*\(.*\+/i,
    /writeFile\s*\(.*\+/i,
    /\.\.\/|\.\.\\/ ,
  ],
  operations: /\b(open|readFile|writeFile|unlink|rmdir|mkdir|rename)\s*\(/,
};

// HIGH: Unsafe Deserialization
const DESERIALIZATION_PATTERNS = {
  unsafe: [
    /pickle\.load/i,
    /pickle\.loads/i,
    /yaml\.load\s*\([^)]*(?!Loader)/i,
    /yaml\.unsafe_load/i,
    /marshal\.load/i,
    /shelve\.open/i,
    /jsonpickle/i,
  ],
};

// HIGH: Prompt Injection (LLM Security)
const PROMPT_PATTERNS = {
  injection: [
    /f["'].*\{user/i,
    /f["'].*\{input/i,
    /f["'].*\{query/i,
    /f["'].*\{message/i,
    /`.*\$\{.*user/i,
    /prompt\s*=\s*f["']/i,
    /system_prompt.*\{/i,
    /\.format\(.*user/i,
  ],
  keywords: /\b(prompt|system_prompt|user_message|completion|chat)\b/i,
};

// MEDIUM: XSS Vectors
const XSS_PATTERNS = {
  vectors: [
    /innerHTML\s*=/i,
    /outerHTML\s*=/i,
    /document\.write\s*\(/i,
    /dangerouslySetInnerHTML/i,
    /\$\(.*\)\.html\s*\(/i,
  ],
};

// MEDIUM: Weak Crypto
const CRYPTO_PATTERNS = {
  weak: [
    /hashlib\.md5/i,
    /hashlib\.sha1/i,
    /MD5\s*\(/i,
    /SHA1\s*\(/i,
    /DES\s*\(/i,
    /random\.(random|randint|choice)/,
  ],
};

// Unicode normalization imported from shared module: ./lib/unicode-normalize

// ============================================================================
// Code Classification
// ============================================================================

function classifyCode(content: string, _filePath: string, language: string): ClassificationResult {
  const normalizedContent = normalizeUnicode(content);
  const triggers: string[] = [];
  let maxRisk: RiskLevel = 'LOW';

  const updateRisk = (level: RiskLevel) => {
    const priority: Record<RiskLevel, number> = {
      CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1,
    };
    if (priority[level] > priority[maxRisk]) {
      maxRisk = level;
    }
  };

  // Check SQL patterns (CRITICAL)
  for (const pattern of SQL_PATTERNS.injection) {
    if (pattern.test(normalizedContent)) {
      triggers.push('SQL injection vector detected');
      updateRisk('CRITICAL');
      break;
    }
  }
  if (SQL_PATTERNS.keywords.test(normalizedContent) && triggers.length === 0) {
    triggers.push('SQL keywords present');
    updateRisk('MEDIUM');
  }

  // Check Command Injection (CRITICAL)
  for (const pattern of COMMAND_PATTERNS.injection) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Command injection vector detected');
      updateRisk('CRITICAL');
      break;
    }
  }
  if (COMMAND_PATTERNS.keywords.test(normalizedContent) && !triggers.some(t => t.includes('Command'))) {
    triggers.push('Shell command execution present');
    updateRisk('HIGH');
  }

  // Check Hardcoded Secrets (CRITICAL)
  for (const pattern of SECRET_PATTERNS.apiKeys) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Hardcoded API key detected');
      updateRisk('CRITICAL');
      break;
    }
  }
  for (const pattern of SECRET_PATTERNS.passwords) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Hardcoded password/secret detected');
      updateRisk('CRITICAL');
      break;
    }
  }

  // Check Path Traversal (HIGH)
  for (const pattern of FILE_PATTERNS.traversal) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Path traversal risk detected');
      updateRisk('HIGH');
      break;
    }
  }

  // Check Unsafe Deserialization (HIGH)
  for (const pattern of DESERIALIZATION_PATTERNS.unsafe) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Unsafe deserialization detected');
      updateRisk('HIGH');
      break;
    }
  }

  // Check Prompt Injection (HIGH)
  for (const pattern of PROMPT_PATTERNS.injection) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Prompt injection risk (user input in prompt)');
      updateRisk('HIGH');
      break;
    }
  }

  // Check XSS (MEDIUM)
  for (const pattern of XSS_PATTERNS.vectors) {
    if (pattern.test(normalizedContent)) {
      triggers.push('XSS vector detected');
      updateRisk('MEDIUM');
      break;
    }
  }

  // Check Weak Crypto (MEDIUM)
  for (const pattern of CRYPTO_PATTERNS.weak) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Weak cryptography detected');
      updateRisk('MEDIUM');
      break;
    }
  }

  if (triggers.length === 0) {
    return {
      type: 'SAFE',
      riskLevel: 'LOW',
      confidence: 'MEDIUM',
      reason: 'No security-sensitive patterns detected',
      triggers: [],
      suggestReview: false,
    };
  }

  const finalRisk = maxRisk as RiskLevel;
  const confidence = finalRisk === 'CRITICAL' || triggers.length >= 3 ? 'HIGH' :
                     triggers.length >= 2 ? 'MEDIUM' : 'LOW';

  return {
    type: 'SECURITY_SENSITIVE',
    riskLevel: finalRisk,
    confidence,
    reason: triggers.slice(0, 3).join('; '),
    triggers,
    suggestReview: finalRisk === 'CRITICAL' || finalRisk === 'HIGH',
  };
}

// ============================================================================
// Language Detection
// ============================================================================

function detectLanguage(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  return CODE_EXTENSIONS[ext] || 'unknown';
}

// ============================================================================
// Audit Logging
// ============================================================================

function logToAudit(entry: AuditEntry): void {
  try {
    ensureTalonDirs();
    const auditPath = getAuditLogPath(HOOK_NAME);
    const logLine = JSON.stringify(entry) + '\n';
    secureAppendLog(auditPath, logLine);
  } catch {
    // Silent failure
  }
}

// ============================================================================
// Display Functions
// ============================================================================

function displayReminder(classification: ClassificationResult, filePath: string, language: string): void {
  const riskEmoji: Record<RiskLevel, string> = {
    CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢',
  };

  console.error('\n┌─────────────────────────────────────────────────────────────┐');
  console.error('│  🔐 TALON L0: Secure Code Review Reminder                   │');
  console.error('├─────────────────────────────────────────────────────────────┤');
  console.error(`│  Risk Level: ${riskEmoji[classification.riskLevel]} ${classification.riskLevel} (${classification.confidence} confidence)`);
  console.error(`│  Language: ${language}`);
  console.error(`│  File: ${filePath.substring(0, 45)}...`);
  console.error('│                                                             │');
  for (const trigger of classification.triggers.slice(0, 4)) {
    console.error(`│    ⚠️  ${trigger.substring(0, 50)}`);
  }
  console.error('│                                                             │');
  console.error('│  L2 Secure Code Linter will validate after write.           │');
  console.error('└─────────────────────────────────────────────────────────────┘\n');
}

function outputBlockDecision(classification: ClassificationResult, filePath: string, language: string): void {
  const blockReason = `🛑 TALON L0: CRITICAL vulnerability detected - write BLOCKED

File: ${filePath}
Language: ${language}
Risk Level: ${classification.riskLevel}

Security triggers:
${classification.triggers.map(t => `  • ${t}`).join('\n')}

ACTION REQUIRED:
1. Fix the vulnerability in your code
2. Common fixes:
   • SQL injection → Use parameterized queries
   • Command injection → Use subprocess with argument list (no shell=True)
   • Hardcoded secrets → Use environment variables

L2 (secure-code-linter) will auto-revert if this somehow reaches disk.`;

  console.error('\n┌─────────────────────────────────────────────────────────────┐');
  console.error('│  🛑 TALON L0: WRITE BLOCKED                                 │');
  console.error('├─────────────────────────────────────────────────────────────┤');
  console.error(`│  Risk Level: 🔴 ${classification.riskLevel} (${classification.confidence} confidence)`);
  console.error(`│  Language: ${language}`);
  console.error(`│  File: ${filePath.length > 45 ? filePath.substring(0, 42) + '...' : filePath}`);
  console.error('│                                                             │');
  for (const trigger of classification.triggers.slice(0, 4)) {
    console.error(`│    🚨 ${trigger.substring(0, 50)}`);
  }
  console.error('│                                                             │');
  console.error('│  ❌ Write operation BLOCKED                                 │');
  console.error('└─────────────────────────────────────────────────────────────┘\n');

  console.log(JSON.stringify({
    decision: 'block',
    reason: blockReason
  }));
}

// ============================================================================
// Main Hook Logic
// ============================================================================

async function main() {
  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error('Timeout')), 300)
      ),
    ]);

    if (!input || input.trim() === '') {
      process.exit(0);
    }

    const data: HookInput = JSON.parse(input);

    if (!data.tool_name || !WRITE_TOOLS.includes(data.tool_name)) {
      process.exit(0);
    }

    const params = data.tool_input || {};
    const filePath = params.file_path || '';
    const content = params.content || params.new_string || '';

    const language = detectLanguage(filePath);
    if (language === 'unknown') {
      process.exit(0);
    }

    if (!content || content.length < 20) {
      process.exit(0);
    }

    for (const skipPath of SKIP_PATHS) {
      // Use segment-aware matching: path must contain the skip pattern as a directory segment
      // Prevents bypass via filenames like "/tmp/hooks/evil.py"
      const segments = filePath.split('/');
      const isSegmentMatch = segments.some(s => skipPath.startsWith('.') ? filePath.endsWith(skipPath) : `/${s}/`.includes(skipPath) || s === skipPath.replace(/\//g, ''));
      if (isSegmentMatch) {
        process.exit(0);
      }
    }

    const classification = classifyCode(content, filePath, language);
    const shouldBlock = classification.type === 'SECURITY_SENSITIVE' &&
                        classification.riskLevel === 'CRITICAL';

    logToAudit({
      timestamp: new Date().toISOString(),
      tool: data.tool_name,
      file_path: filePath.substring(0, 200),
      language,
      classification: classification.type,
      risk_level: classification.riskLevel,
      confidence: classification.confidence,
      triggers: classification.triggers,
      blocked: shouldBlock,
      session_id: data.session_id,
    });

    if (shouldBlock) {
      outputBlockDecision(classification, filePath, language);
      process.exit(2);
    }

    if (classification.type === 'SECURITY_SENSITIVE' && classification.riskLevel === 'HIGH') {
      displayReminder(classification, filePath, language);
      const patterns = classification.triggers.slice(0, 3).join(', ') || 'security-sensitive patterns';
      console.log(JSON.stringify({
        additionalContext: `🔐 TALON L0 SECURE CODE ENFORCER HIGH: Security-sensitive code detected in ${filePath}. ` +
          `Patterns: ${patterns}. L2 Secure Code Linter will validate after write.`,
      }));
    }

    process.exit(0);
  } catch {
    // Fail-closed: block operation if hook crashes (security-first)
    process.exit(2);
  }
}

main();
