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
/** One per-monitor acknowledge batch (the Alerting acknowledge API is per-monitor). */
export interface AckTarget {
  monitorId: string;
  alertIds: string[];
}

/** The minimal alert shape {@link groupAckTargets} reads (normalized camelCase fields). */
interface AckableAlert {
  id?: string;
  monitorId?: string;
  state?: string;
}

/**
 * Pure: group a selection of alerts into per-monitor acknowledge batches (PROB-24/25).
 *
 * Only ACTIVE alerts are acknowledgeable (ACKNOWLEDGED is already done; COMPLETED/ERROR/DELETED
 * are engine-managed states the acknowledge API rejects) — everything else is filtered out, as are
 * entries missing an id or monitorId. Ids are deduped; group order follows first appearance, id
 * order within a group follows the input (stable for tests and for audit summaries).
 */
export function groupAckTargets(alerts: AckableAlert[]): AckTarget[] {
  const byMonitor = new Map<string, string[]>();
  const seenIds = new Set<string>();
  for (const a of alerts ?? []) {
    if (a?.state !== 'ACTIVE') continue;
    const id = a?.id;
    const monitorId = a?.monitorId;
    if (!id || !monitorId || seenIds.has(id)) continue;
    seenIds.add(id);
    const list = byMonitor.get(monitorId) ?? [];
    list.push(id);
    byMonitor.set(monitorId, list);
  }
  return Array.from(byMonitor.entries()).map(([monitorId, alertIds]) => ({ monitorId, alertIds }));
}

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
