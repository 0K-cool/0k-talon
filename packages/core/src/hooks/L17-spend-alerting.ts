#!/usr/bin/env bun

/**
 * L17: Spend Alerting - PostToolUse Hook
 *
 * Part of 0K-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: Track session costs and alert at thresholds.
 * Pattern: Sidecar Pattern (monitoring after tool execution)
 *
 * Thresholds: WARNING $5, ALERT $10, CRITICAL $20
 *
 * Maps to:
 * - OWASP LLM10 (Unbounded Consumption)
 *
 * @version 0.2.0 (0k-talon)
 * @date 2026-02-06
 */

import { getStateFilePath } from './lib/talon-paths';
import { atomicUpdateJsonFile, readJsonFileSync } from './lib/atomic-file';

const HOOK_NAME = 'L17-spend-alerting';

const THRESHOLDS = { WARNING: 5.0, ALERT: 10.0, CRITICAL: 20.0 };
// Opus 4.6 pricing (Feb 2026): $5/$25 base, $10/$37.50 for >200K context
const PRICING = { INPUT_PER_MILLION: 5.0, OUTPUT_PER_MILLION: 25.0 };
const CHARS_PER_TOKEN = 4;

interface HookInput {
  session_id: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response?: { output?: string; content?: string };
}

interface SessionState {
  session_id: string;
  total_cost_usd: number;
  tool_calls: number;
  last_threshold: 'NONE' | 'WARNING' | 'ALERT' | 'CRITICAL';
}

function estimateTokens(content: unknown): number {
  if (!content) return 0;
  const str = typeof content === 'string' ? content : JSON.stringify(content);
  return Math.ceil(str.length / CHARS_PER_TOKEN);
}

function calculateCost(inputTokens: number, outputTokens: number): number {
  return (inputTokens / 1_000_000) * PRICING.INPUT_PER_MILLION +
         (outputTokens / 1_000_000) * PRICING.OUTPUT_PER_MILLION;
}

function loadState(sessionId: string): SessionState {
  const path = getStateFilePath(HOOK_NAME, 'session.json');
  const all = readJsonFileSync<Record<string, SessionState>>(path, {});
  return all[sessionId] || { session_id: sessionId, total_cost_usd: 0, tool_calls: 0, last_threshold: 'NONE' };
}

const MAX_SESSIONS = 50;

function saveState(state: SessionState): void {
  const path = getStateFilePath(HOOK_NAME, 'session.json');
  // Use atomicUpdateJsonFile to prevent TOCTOU race conditions
  atomicUpdateJsonFile<Record<string, SessionState>>(
    path,
    (current) => {
      current[state.session_id] = state;
      // Evict oldest sessions if over limit to prevent unbounded growth
      const keys = Object.keys(current);
      if (keys.length > MAX_SESSIONS) {
        // Sort by total_cost_usd ascending (cheapest/oldest first) as proxy for age
        const sorted = keys.sort((a, b) => (current[a]?.total_cost_usd || 0) - (current[b]?.total_cost_usd || 0));
        for (const key of sorted.slice(0, keys.length - MAX_SESSIONS)) {
          delete current[key];
        }
      }
      return current;
    },
    { [state.session_id]: state }
  );
}

function displayAlert(threshold: string, cost: number): void {
  const emoji = threshold === 'CRITICAL' ? '🔴' : threshold === 'ALERT' ? '🟠' : '⚠️';
  console.error(`\n${emoji} TALON L17: SPEND ${threshold} - $${cost.toFixed(4)}\n`);
}

async function main() {
  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 300)),
    ]);
    if (!input?.trim()) process.exit(0);

    const data: HookInput = JSON.parse(input);
    if (!data.tool_response) process.exit(0);

    const inputTokens = estimateTokens(data.tool_input);
    const outputTokens = estimateTokens(data.tool_response.output || data.tool_response.content);
    const callCost = calculateCost(inputTokens, outputTokens);

    const state = loadState(data.session_id);
    state.total_cost_usd += callCost;
    state.tool_calls++;

    // Check thresholds
    const thresholdKeys = ['WARNING', 'ALERT', 'CRITICAL'] as const;
    type ThresholdKey = typeof thresholdKeys[number];
    const lastIdx = state.last_threshold === 'NONE' ? -1 : thresholdKeys.indexOf(state.last_threshold as ThresholdKey);

    let triggeredThreshold: string | null = null;
    for (let i = lastIdx + 1; i < thresholdKeys.length; i++) {
      const threshold = thresholdKeys[i];
      if (threshold && state.total_cost_usd >= THRESHOLDS[threshold]) {
        state.last_threshold = threshold;
        triggeredThreshold = threshold;
        displayAlert(threshold, state.total_cost_usd);
        break;
      }
    }

    saveState(state);

    // Output JSON with additionalContext so the AI is aware of spend threshold
    if (triggeredThreshold) {
      console.log(JSON.stringify({
        continue: true,
        hookSpecificOutput: {
          hookEventName: 'PostToolUse',
          additionalContext: `💰 TALON L17 SPEND ${triggeredThreshold}: Session cost is $${state.total_cost_usd.toFixed(4)} (${state.tool_calls} tool calls). ` +
            `Thresholds: WARNING=$${THRESHOLDS.WARNING}, ALERT=$${THRESHOLDS.ALERT}, CRITICAL=$${THRESHOLDS.CRITICAL}. ` +
            `Consider more efficient approaches or inform user about costs.`,
        },
      }));
    } else {
      console.log(JSON.stringify({ continue: true }));
    }

    process.exit(0);
  } catch {
    process.exit(0);
  }
}

main();
