/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Bulk rule actions (v1.2.3 D8) — the PROB-25 idiom applied to the rules list: PURE
 * partition/merge/summarize helpers plus sequential client loops over the EXISTING per-rule
 * routes (`_toggle`, `_tags`, DELETE). There are deliberately NO bulk server routes: no
 * transaction exists across monitors anyway, and the loop preserves each route's own
 * rollback/consistency guarantees (research_r6 A4). Per-item failures never abort the rest;
 * the caller shows ONE summary toast and does ONE reload.
 */

import { CoreStart } from 'opensearch-dashboards/public';

/** The row slice the bulk loops need. */
export interface BulkRuleRow {
  soId: string;
  name: string;
  enabled: boolean;
  tags?: string[];
}

export interface BulkFailure {
  name: string;
  message: string;
}

/** Outcome of one bulk run: per-item successes/skips/failures, for the single summary toast. */
export interface BulkRunResult {
  succeeded: number;
  /** Rows that needed no call at all (e.g. "enable" on an already-enabled rule). */
  skipped: number;
  failures: BulkFailure[];
}

/**
 * Pure: which selected rows actually need a toggle call? Rows already in the target state are
 * skipped (no pointless GET+PUT round-trips against the cluster).
 */
export function partitionToggleTargets<T extends { enabled: boolean }>(
  rows: T[],
  enable: boolean
): { targets: T[]; skipped: number } {
  const targets = (rows ?? []).filter((r) => r.enabled !== enable);
  return { targets, skipped: (rows ?? []).length - targets.length };
}

/**
 * Pure: merge tags to ADD into a row's existing tags — trim, drop empties, dedupe, existing
 * order first. The `_tags` route REPLACES the rule's tag list, so "add" is client-side merge of
 * the row's tags (the LIST returns them) + the new ones. The server re-validates (caps, length)
 * and 400s by name — this merge is presentation-level hygiene, not the authority.
 */
export function mergeTags(existing: string[] | undefined, added: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of [...(existing ?? []), ...(added ?? [])]) {
    if (typeof raw !== 'string') continue;
    const tag = raw.trim();
    if (tag === '' || seen.has(tag)) continue;
    seen.add(tag);
    out.push(tag);
  }
  return out;
}

/** Pure: one summary toast per bulk run (never a toast storm). */
export function summarizeBulk(
  pastTenseVerb: string,
  result: BulkRunResult
): { color: 'success' | 'warning' | 'danger'; title: string; text?: string } {
  const parts: string[] = [];
  if (result.succeeded > 0) {
    parts.push(`${pastTenseVerb} ${result.succeeded} rule${result.succeeded === 1 ? '' : 's'}`);
  }
  if (result.skipped > 0) {
    parts.push(`${result.skipped} already ${result.skipped === 1 ? 'was' : 'were'} — skipped`);
  }
  if (result.failures.length > 0) {
    parts.push(`${result.failures.length} failed`);
  }
  const title = parts.length > 0 ? parts.join('; ') : 'Nothing to do';
  const text =
    result.failures.length > 0
      ? `${result.failures[0].name}: ${result.failures[0].message}`
      : undefined;
  const color =
    result.failures.length === 0 ? 'success' : result.succeeded > 0 ? 'warning' : 'danger';
  return { color, title, text };
}

function errMessage(e: unknown): string {
  const err = e as any;
  return err?.body?.message ?? err?.message ?? 'Failed';
}

/** Sequential loop over `POST .../{soId}/_toggle` for the rows that need it. */
export async function runBulkToggle(
  http: CoreStart['http'],
  rows: BulkRuleRow[],
  enable: boolean
): Promise<BulkRunResult> {
  const { targets, skipped } = partitionToggleTargets(rows, enable);
  const result: BulkRunResult = { succeeded: 0, skipped, failures: [] };
  for (const row of targets) {
    try {
      await http.post(`/api/tlsoc/detection/monitors/${row.soId}/_toggle`, {
        body: JSON.stringify({ enabled: enable }),
      });
      result.succeeded++;
    } catch (e) {
      result.failures.push({ name: row.name, message: errMessage(e) });
    }
  }
  return result;
}

/** Sequential loop over `DELETE .../{soId}` (idempotent per route; 404s count as failures here). */
export async function runBulkDelete(
  http: CoreStart['http'],
  rows: BulkRuleRow[]
): Promise<BulkRunResult> {
  const result: BulkRunResult = { succeeded: 0, skipped: 0, failures: [] };
  for (const row of rows ?? []) {
    try {
      await http.delete(`/api/tlsoc/detection/monitors/${row.soId}`);
      result.succeeded++;
    } catch (e) {
      result.failures.push({ name: row.name, message: errMessage(e) });
    }
  }
  return result;
}

/**
 * Sequential loop over `POST .../{soId}/_tags`, each row REPLACING its tags with
 * {@link mergeTags}(row.tags, tagsToAdd). Rows the merge leaves unchanged are skipped.
 */
export async function runBulkAddTags(
  http: CoreStart['http'],
  rows: BulkRuleRow[],
  tagsToAdd: string[]
): Promise<BulkRunResult> {
  const result: BulkRunResult = { succeeded: 0, skipped: 0, failures: [] };
  for (const row of rows ?? []) {
    const merged = mergeTags(row.tags, tagsToAdd);
    if (merged.length === (row.tags ?? []).length) {
      result.skipped++;
      continue;
    }
    try {
      await http.post(`/api/tlsoc/detection/monitors/${row.soId}/_tags`, {
        body: JSON.stringify({ tags: merged }),
      });
      result.succeeded++;
    } catch (e) {
      result.failures.push({ name: row.name, message: errMessage(e) });
    }
  }
  return result;
}
