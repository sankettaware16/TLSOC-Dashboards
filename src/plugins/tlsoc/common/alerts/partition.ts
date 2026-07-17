/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Partition raw Alerting-plugin-API alert objects against a wanted-id list (Task 5a.1d).
 *
 * Used by the case linked-alert hydration route: under OpenSearch Security the
 * `.opendistro-alerting-*` system indices are protected (direct `_search` returns silently
 * empty), so alerts are fetched through the Alerting PLUGIN API and filtered here by the
 * case's `linkedAlertIds`. An id with no matching alert is a genuine miss (purged from the
 * alert/history indices) and is reported in `missingIds`.
 */
export interface AlertIdPartition {
  /** Raw alert objects whose `id` is in `wantedIds`, deduped, in wantedIds order. */
  found: any[];
  /** Ids from `wantedIds` (order preserved, deduped) with no matching alert. */
  missingIds: string[];
}

/**
 * Pure: select from `rawAlerts` the ones whose `id` is in `wantedIds`.
 * - `found` follows `wantedIds` order (stable for the UI table), one entry per unique id.
 * - `missingIds` preserves `wantedIds` order and is deduped.
 * - Alerts without an `id`, duplicate alert entries, and duplicate wanted ids are tolerated.
 */
export function partitionByIds(rawAlerts: any[], wantedIds: string[]): AlertIdPartition {
  const byId = new Map<string, any>();
  for (const a of rawAlerts ?? []) {
    const id = a?.id;
    if (typeof id === 'string' && id.length > 0 && !byId.has(id)) {
      byId.set(id, a);
    }
  }
  const found: any[] = [];
  const missingIds: string[] = [];
  const seen = new Set<string>();
  for (const id of wantedIds ?? []) {
    if (seen.has(id)) continue;
    seen.add(id);
    const hit = byId.get(id);
    if (hit !== undefined) {
      found.push(hit);
    } else {
      missingIds.push(id);
    }
  }
  return { found, missingIds };
}
