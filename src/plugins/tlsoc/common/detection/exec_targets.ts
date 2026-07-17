/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { deriveAliasName } from './alias';

/**
 * Compute the desired set of per-index execution-target aliases for a stateless (doc-level) rule
 * whose index PATTERN currently resolves to `concreteIndices` — one dot-free alias per concrete
 * index (see {@link deriveAliasName}), deduped and SORTED for a stable, comparable result.
 *
 * WHY per-index, not one pattern-level alias (the pre-hotfix approach): OpenSearch 3.7's doc-level
 * monitor runner only persists scan-checkpoint context for an alias's WRITE index
 * (source-confirmed: `MonitorMetadataService.createFullRunContext` → `IndexUtils.getWriteIndex`
 * returns `null` for a multi-backed alias with no write index → the run context resets to `{}`
 * every run → a zero-width scan window → the monitor silently finds nothing, forever, with NO
 * error — upstream alerting issue #1290). A single-backed alias (exactly one concrete index) always
 * has an implicit write index, so its run context persists correctly. Hence: one alias PER concrete
 * index, never one alias for the whole pattern.
 */
export function desiredExecutionTargets(concreteIndices: string[]): string[] {
  const set = new Set(concreteIndices.map((idx) => deriveAliasName(idx)));
  return Array.from(set).sort();
}

/**
 * Do two execution-target lists differ, as SETS (order-insensitive, dedupe-insensitive)? Drives the
 * drift-repair decision in `syncStatelessMonitorTargets` (server/routes/monitors.ts) — only touch
 * the live monitor + saved object when something has actually changed (a new daily index rolled in,
 * an old one aged out of an ISM policy, etc.), so a no-drift sweep is a cheap read-only no-op.
 */
export function executionTargetsDiffer(current: string[], desired: string[]): boolean {
  const a = Array.from(new Set(current)).sort();
  const b = Array.from(new Set(desired)).sort();
  if (a.length !== b.length) return true;
  return a.some((v, i) => v !== b[i]);
}
