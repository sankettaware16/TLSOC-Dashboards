/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TlsocAlert } from '../alerts';

/** The index + absolute time window a case's investigation surface (Task 4.5) is scoped to. */
export interface InvestigationScope {
  /** User-facing index to investigate (most-common non-null rule.index); undefined when unknown. */
  index?: string;
  /** Absolute time window as ISO strings (consumed by getTime + the SearchBar). */
  timeRange: { from: string; to: string };
}

/** The minimal shape of an alert this derivation reads (a subset of {@link TlsocAlert}). */
type ScopeAlert = Pick<TlsocAlert, 'rule' | 'startTime' | 'endTime' | 'lastNotificationTime'>;

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

/**
 * Pure: derive the investigation scope (index + time window) for a case from its linked alerts.
 * `nowMs` is passed in (no `Date.now()` inside) so the function is deterministic + unit-testable.
 *
 * INDEX RULE (decision — pinned by scope.test.ts): the MOST COMMON non-null `rule.index` across the
 * alerts; ties break to the FIRST occurrence; `undefined` when no alert carries a known index.
 *
 * TIME RULE (decision — pinned by scope.test.ts):
 *  - per-alert upper bound = `endTime ?? lastNotificationTime ?? nowMs`.
 *  - `from` = min(startTime) over alerts that have one; if none have a startTime, the earliest upper bound.
 *  - `to`   = max(upper bound) over all alerts.
 *  - if NO alert has ANY of startTime/endTime/lastNotificationTime (or there are no alerts) → last-24h
 *    window `[nowMs - 24h, nowMs]`.
 *  - guard: a non-positive span widens `to` to `from + 1h` so the window is never degenerate.
 */
export function deriveInvestigationScope(alerts: ScopeAlert[], nowMs: number): InvestigationScope {
  const index = mostCommonIndex(alerts);

  const anyTime = alerts.some(
    (a) => a.startTime != null || a.endTime != null || a.lastNotificationTime != null
  );
  if (alerts.length === 0 || !anyTime) {
    return { index, timeRange: { from: iso(nowMs - DAY_MS), to: iso(nowMs) } };
  }

  const starts = alerts.map((a) => a.startTime).filter((t): t is number => t != null);
  const uppers = alerts.map((a) => a.endTime ?? a.lastNotificationTime ?? nowMs);
  let from = starts.length ? Math.min(...starts) : Math.min(...uppers);
  let to = Math.max(...uppers);
  if (to <= from) {
    to = from + HOUR_MS; // guard a degenerate (point-in-time) window
  }
  return { index, timeRange: { from: iso(from), to: iso(to) } };
}

/** Most-common non-null rule.index; ties resolve to the first-seen index; undefined if none. */
function mostCommonIndex(alerts: Array<Pick<TlsocAlert, 'rule'>>): string | undefined {
  const counts = new Map<string, number>();
  const firstSeen: string[] = [];
  for (const a of alerts) {
    const idx = a.rule?.index;
    if (!idx) continue;
    if (!counts.has(idx)) firstSeen.push(idx);
    counts.set(idx, (counts.get(idx) ?? 0) + 1);
  }
  let best: string | undefined;
  let bestCount = 0;
  for (const idx of firstSeen) {
    const c = counts.get(idx)!;
    if (c > bestCount) {
      best = idx;
      bestCount = c;
    }
  }
  return best;
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}
