/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Logger, SavedObjectsClientContract } from '../../../../core/server';
import {
  DETECTION_STATE_INDEX,
  NEW_TERMS_MODE,
  NewTermsRuleDefinition,
  SEEN_VALUES_CAP,
  assertValidNewTermsRule,
  newTermsStateDocId,
} from '../../common/detection/new_terms';
import { conditionGroupToLucene } from '../../common/detection/lucene';
import { DetectionRuleAttributes } from '../../common/detection/save';
import { TimeWindow } from '../../common/detection/types';
import { DETECTION_RULE_SO_TYPE } from '../saved_objects';

/**
 * Seen-values state for 'new_terms' rules (v1.2.3 D5): one doc per (rule × term field) in the
 * TLSOC-owned cluster index {@link DETECTION_STATE_INDEX}, consumed by the compiled monitor's
 * `bool.must_not` terms-LOOKUP (research_r5 §3 — live-proven). Two writers, both here:
 *
 * - {@link bootstrapSeenValues}: called SYNCHRONOUSLY by the save route BEFORE the monitor is
 *   created — kills "first run = everything is new" (research_r5 §3.4). Because it aggregates on
 *   the term field with the CALLER's credentials, it doubles as the save gate: an unaggregatable
 *   field or unreadable index fails the save loudly, before any monitor exists.
 * - {@link refreshSeenValuesSweep}: the periodic refresh, piggybacked fire-and-forget on the
 *   alerts poll with the CALLER's credentials (a background job would have none) — the
 *   syncStatelessMonitorTargets idioms exactly (monitors.ts:169-245): module-level 60s debounce
 *   BEFORE the SO scan, per-rule try/catch so one rule's failure never skips the rest, and it
 *   NEVER throws into the caller's request.
 *
 * The race between a monitor run and the sweep is benign by construction: a value arriving
 * between sweeps IS new and fires; bucket-key dedup keeps it one alert until the sweep marks it
 * seen, then the alert auto-COMPLETEs (research_r5 §3.4).
 *
 * Every client is INJECTED — no module state beyond the debounce timestamp, so tests drive these
 * with plain mocks.
 */

type EsClient = any;

/** The terms-agg name the bootstrap/sweep reads back. Internal, but pinned by tests. */
export const SEEN_AGG = 'tlsoc_seen_values';

/**
 * Date-math abbreviations for the HISTORY-window query only. The MONITOR's window still comes
 * exclusively from buildWindow (window.ts) inside the compiler — this never feeds a monitor.
 */
const UNIT_ABBREV: Record<TimeWindow['unit'], string> = {
  MINUTES: 'm',
  HOURS: 'h',
  DAYS: 'd',
};

/**
 * Mappings/settings for the state index. Kept deliberately minimal: the terms-lookup reads the
 * doc's _source (not the mapping), so these exist only so `rule_id`/`updated_at` stay queryable
 * for operators.
 */
const STATE_INDEX_BODY = {
  settings: { index: { number_of_shards: 1, auto_expand_replicas: '0-1' } },
  mappings: {
    properties: {
      rule_id: { type: 'keyword' },
      values: { type: 'keyword' },
      truncated: { type: 'boolean' },
      updated_at: { type: 'date' },
    },
  },
};

/**
 * Create {@link DETECTION_STATE_INDEX} if absent. Idempotent AND race-safe: a concurrent create
 * losing the race surfaces resource_already_exists_exception, which is success here.
 */
export async function ensureStateIndex(esClient: EsClient): Promise<void> {
  const exists = await esClient.indices.exists({ index: DETECTION_STATE_INDEX });
  if ((exists as any).body === true) return;
  try {
    await esClient.indices.create({ index: DETECTION_STATE_INDEX, body: STATE_INDEX_BODY });
  } catch (err: any) {
    const type = err?.meta?.body?.error?.type ?? err?.body?.error?.type;
    if (type === 'resource_already_exists_exception') return;
    throw err;
  }
}

export interface SeenValuesResult {
  values: string[];
  /**
   * True when the history window held MORE distinct values than {@link SEEN_VALUES_CAP} (or
   * exactly the cap — the set can no longer grow): the rule is DEGRADED — values beyond the cap
   * are treated as new even though they were seen. Persisted on the state doc so the list UI can
   * badge it.
   */
  truncated: boolean;
}

/**
 * The history-window terms aggregation both writers share: distinct values of the term field
 * among events matching the (optional) pre-filter within the last historyWindow. Missing indices
 * degrade to an empty result — an empty history window means "everything is new", which is the
 * CORRECT semantics (the UI warns about it; research_r5 §3.4).
 */
async function aggregateSeenValues(
  esClient: EsClient,
  rule: NewTermsRuleDefinition
): Promise<SeenValuesResult> {
  const filter: any[] = [
    {
      range: {
        '@timestamp': {
          gte: `now-${rule.historyWindow.value}${UNIT_ABBREV[rule.historyWindow.unit]}`,
          lte: 'now',
        },
      },
    },
  ];
  if (rule.filter) {
    filter.push({
      query_string: { query: conditionGroupToLucene(rule.filter), analyze_wildcard: true },
    });
  }
  const resp = await esClient.search({
    index: rule.index,
    allow_no_indices: true,
    ignore_unavailable: true,
    body: {
      size: 0,
      query: { bool: { filter } },
      aggregations: {
        [SEEN_AGG]: { terms: { field: rule.termField, size: SEEN_VALUES_CAP } },
      },
    },
  });
  const agg = (resp as any).body?.aggregations?.[SEEN_AGG];
  const buckets: any[] = agg?.buckets ?? [];
  const values = buckets.map((bucket) => String(bucket.key));
  const truncated = (agg?.sum_other_doc_count ?? 0) > 0 || values.length >= SEEN_VALUES_CAP;
  return { values, truncated };
}

async function putStateDoc(
  esClient: EsClient,
  docId: string,
  ruleSoId: string,
  seen: SeenValuesResult,
  refresh: 'wait_for' | false
): Promise<void> {
  await esClient.index({
    index: DETECTION_STATE_INDEX,
    id: docId,
    ...(refresh ? { refresh } : {}),
    body: {
      rule_id: ruleSoId,
      values: seen.values,
      truncated: seen.truncated,
      updated_at: new Date().toISOString(),
    },
  });
}

/**
 * Snapshot the currently-seen values and write the state doc — the save route calls this AFTER
 * compiling (so shape errors keep their richer 400s) and BEFORE creating/updating the monitor
 * (the lookup target must exist before the first run). `refresh: wait_for` so the monitor's
 * first scheduled run is guaranteed to see the doc. Returns the snapshot so the route can
 * surface `truncated` to the caller.
 */
export async function bootstrapSeenValues(
  esClient: EsClient,
  rule: NewTermsRuleDefinition,
  docId: string,
  ruleSoId: string
): Promise<SeenValuesResult> {
  assertValidNewTermsRule(rule);
  await ensureStateIndex(esClient);
  const seen = await aggregateSeenValues(esClient, rule);
  await putStateDoc(esClient, docId, ruleSoId, seen, 'wait_for');
  return seen;
}

/**
 * Best-effort removal of a rule's state doc (DELETE-route cleanup, and UPDATE cleanup when an
 * edit changes the term field and therefore the doc id). Missing doc/index are success — the
 * goal state is "gone".
 */
export async function deleteSeenValuesDoc(esClient: EsClient, docId: string): Promise<void> {
  try {
    await esClient.delete({ index: DETECTION_STATE_INDEX, id: docId });
  } catch (err: any) {
    if ((err?.meta?.statusCode ?? err?.statusCode) === 404) return;
    throw err;
  }
}

/** One sweep target: the rule SO id + its (unmapped) rule attribute, as scanned from the SO index. */
export interface NewTermsSweepTarget {
  soId: string;
  rule: NewTermsRuleDefinition;
}

/** The rule's state doc id: the persisted one when present, else re-derived (always recomputable). */
function stateDocIdOf(target: NewTermsSweepTarget): string {
  const persisted = target.rule.stateDocId;
  return typeof persisted === 'string' && persisted !== ''
    ? persisted
    : newTermsStateDocId(target.soId, target.rule.termField);
}

/**
 * Refresh the seen doc of every target: re-run the history aggregation and overwrite the state
 * doc. Per-rule try/catch — one rule's failure (bad field, deleted index, mangled rule attr) is
 * logged and skipped, never propagated (a later sweep retries). Exported separately from the
 * debounced entry so tests (and any future explicit-refresh route) can drive it directly.
 */
export async function refreshSeenValuesForRules(
  esClient: EsClient,
  targets: NewTermsSweepTarget[],
  logger: Logger
): Promise<void> {
  for (const target of targets) {
    try {
      const seen = await aggregateSeenValues(esClient, target.rule);
      await putStateDoc(esClient, stateDocIdOf(target), target.soId, seen, false);
    } catch (err: any) {
      logger.warn(
        `tlsoc refreshSeenValues: sweep failed for "${target.rule?.name}" (${target.soId}), skipping: ${err.message}`
      );
    }
  }
}

/**
 * Module-level debounce, BEFORE the SO scan (same placement as monitors.ts:313): the alerts poll
 * fires this on every request (~30s per open tab); at most one full sweep per minute runs no
 * matter how many pollers there are.
 */
let lastNewTermsSweepAt = 0;
const NEW_TERMS_SWEEP_DEBOUNCE_MS = 60000;

/** Test hook ONLY — module-level state would otherwise leak the debounce across test cases. */
export function __resetNewTermsSweepDebounceForTests(): void {
  lastNewTermsSweepAt = 0;
}

/**
 * The fire-and-forget sweep entry the alerts poll calls (next to syncStatelessMonitorTargets):
 * debounce → scan the rule SOs (perPage 1000, the plugin-wide honesty cap) → refresh every
 * 'new_terms' rule's seen doc. NEVER throws — any failure is logged and this sweep round is
 * abandoned (the next poll retries).
 */
export async function refreshSeenValuesSweep(
  esClient: EsClient,
  soClient: SavedObjectsClientContract,
  logger: Logger
): Promise<void> {
  const now = Date.now();
  if (now - lastNewTermsSweepAt < NEW_TERMS_SWEEP_DEBOUNCE_MS) return;
  lastNewTermsSweepAt = now;

  let targets: NewTermsSweepTarget[];
  try {
    const found = await soClient.find<DetectionRuleAttributes>({
      type: DETECTION_RULE_SO_TYPE,
      perPage: 1000,
    });
    targets = found.saved_objects
      .filter((so) => so.attributes.mode === NEW_TERMS_MODE)
      .map((so) => ({
        soId: so.id,
        rule: (so.attributes.rule as unknown) as NewTermsRuleDefinition,
      }));
  } catch (err: any) {
    logger.warn(
      `tlsoc refreshSeenValues: could not list rules, skipping this sweep: ${err.message}`
    );
    return;
  }
  if (targets.length === 0) return;

  try {
    // Self-heals an admin-deleted state index: without this, the per-rule doc writes would
    // auto-create it with dynamic mappings.
    await ensureStateIndex(esClient);
  } catch (err: any) {
    logger.warn(
      `tlsoc refreshSeenValues: state index unavailable, skipping this sweep: ${err.message}`
    );
    return;
  }

  await refreshSeenValuesForRules(esClient, targets, logger);
}
