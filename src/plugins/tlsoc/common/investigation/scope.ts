/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

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

/** The minimal shape of an alert {@link deriveEvidence} reads (a subset of {@link TlsocAlert}). */
type EvidenceAlert = Pick<TlsocAlert, 'relatedDocIds' | 'bucketKeys' | 'rule'>;

/**
 * The concrete evidence (documents + bucket group-scopes) a case's linked alerts point at —
 * used to scope the Investigate tab's query to what actually triggered the alerts, instead of
 * the whole time window (PROB-17).
 */
export interface InvestigationEvidence {
  /** Deduped union of (id, index) pairs from doc-level alerts' relatedDocIds. */
  docRefs: Array<{ id: string; index: string }>;
  /** One AND-set of exact field=value pairs per bucket (threshold) alert; deduped. */
  groupScopes: Array<Array<{ field: string; value: string }>>;
}

/**
 * Pure: derive {@link InvestigationEvidence} from a case's linked alerts.
 *
 * DOC REFS (decision — pinned by scope.test.ts): each alert's `relatedDocIds` entries are
 * "docId|index" strings; the index is everything AFTER the LAST '|' (docId itself may contain
 * '|'). Entries with no parseable index (no '|', or an empty index) are skipped. The result is
 * deduped by (id, index) across ALL alerts.
 *
 * GROUP SCOPES (decision — pinned by scope.test.ts): bucket (threshold) alerts carry
 * `bucketKeys` (values) and `rule.groupBy` (field names) — a positional zip in ONE AND-set per
 * alert. An alert is skipped for group-scope purposes unless it has BOTH a non-empty
 * `bucketKeys` AND a non-empty `rule.groupBy`. Pairs are zipped index-by-index; a pair where
 * either side is missing (arrays of different length) is skipped, not the whole alert. Identical
 * (fully matching) AND-sets are deduped.
 */
export function deriveEvidence(alerts: EvidenceAlert[]): InvestigationEvidence {
  const docRefs: Array<{ id: string; index: string }> = [];
  const seenDocRefs = new Set<string>();
  for (const a of alerts) {
    for (const raw of a.relatedDocIds ?? []) {
      const sep = raw.lastIndexOf('|');
      if (sep < 0) continue; // no parseable index
      const id = raw.slice(0, sep);
      const index = raw.slice(sep + 1);
      if (!index) continue;
      const key = `${id}|${index}`;
      if (seenDocRefs.has(key)) continue;
      seenDocRefs.add(key);
      docRefs.push({ id, index });
    }
  }

  const groupScopes: Array<Array<{ field: string; value: string }>> = [];
  const seenGroupScopes = new Set<string>();
  for (const a of alerts) {
    const keys = a.bucketKeys;
    const fields = a.rule?.groupBy;
    if (!keys || keys.length === 0 || !fields || fields.length === 0) continue;
    const pairs: Array<{ field: string; value: string }> = [];
    const len = Math.min(keys.length, fields.length);
    for (let i = 0; i < len; i++) {
      const field = fields[i];
      const value = keys[i];
      if (field == null || value == null) continue; // either side missing — skip this pair only
      pairs.push({ field, value });
    }
    if (pairs.length === 0) continue;
    // Order-sensitive dedupe key — groupBy/bucketKeys are already positionally aligned.
    const dedupeKey = pairs.map((p) => `${p.field}=${p.value}`).join('&');
    if (seenGroupScopes.has(dedupeKey)) continue;
    seenGroupScopes.add(dedupeKey);
    groupScopes.push(pairs);
  }

  return { docRefs, groupScopes };
}

/**
 * Pure: build a SearchSource-compatible custom filter that scopes a query to exactly the
 * evidence behind a case's linked alerts, or `null` when there is no evidence to scope to.
 *
 * SHAPE (verified against this repo — see from_filters.ts:58-66 + search_source.ts:696): a
 * filter carrying a raw `query` is passed through `buildQueryFromFilters` unmodified and merged
 * with the SearchBar query into one bool by `buildOpenSearchQuery`. One `should` clause per
 * INDEX (binds doc ids to their own index — a flat multi-index `ids` query would return
 * colliding `_id`s from other indices), plus one `should` clause per bucket group-scope (an AND
 * of exact `term` matches).
 */
export function buildEvidenceFilter(
  evidence: InvestigationEvidence
): { meta: any; query: any } | null {
  if (evidence.docRefs.length === 0 && evidence.groupScopes.length === 0) return null;

  const byIndex = new Map<string, string[]>();
  for (const { id, index } of evidence.docRefs) {
    const list = byIndex.get(index);
    if (list) list.push(id);
    else byIndex.set(index, [id]);
  }

  const should: any[] = [];
  for (const [index, ids] of byIndex) {
    should.push({
      bool: { filter: [{ term: { _index: index } }, { ids: { values: ids } }] },
    });
  }
  for (const pairs of evidence.groupScopes) {
    should.push({
      bool: { filter: pairs.map((p) => ({ term: { [p.field]: p.value } })) },
    });
  }

  return {
    meta: { alias: 'Linked alert evidence', disabled: false, negate: false, type: 'custom' },
    query: { bool: { should, minimum_should_match: 1 } },
  };
}
