/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { AggregationCompileInput } from './agg_types';
import { compileAggregationRule } from './agg_compile';
import { BucketLevelMonitor } from './bucket_monitor';
import { SEVERITY_TO_MONITOR_SEVERITY, assertValidTimeWindowUnit } from './internal';
import { conditionGroupToLucene } from './lucene';
import { exceptionsToFilterClause, validateExceptions } from './exceptions';
import {
  Condition,
  ConditionGroup,
  LIST_OPERATORS,
  RuleMetadataFields,
  Severity,
  TimeWindow,
  VALUELESS_OPERATORS,
} from './types';

/**
 * The 'new_terms' detection rule (v1.2.3 D5) — first-seen detection: fire once per value of ONE
 * field that was never seen in the rule's history window. Compiles to a BUCKET-level Alerting
 * monitor (live-proven, research_r5 §3): a `bool.must_not` terms-LOOKUP against the TLSOC-owned
 * seen-state index excludes known values, a composite terms agg on the term field buckets the
 * survivors, and a `params._count > 0` trigger fires one alert PER new value (the value itself is
 * carried in `agg_alert_content.bucket_keys`). Bucket-key dedup keeps it ONE alert while the value
 * keeps appearing, and the alert auto-COMPLETEs once the seen-values sweep
 * (server/lib/new_terms_state.ts) marks the value seen — the exact Elastic-shaped lifecycle with
 * zero parallel execution path.
 *
 * DECISIONS (binding, each live-evidence-backed):
 * - ONE term field in v1: composite aggs + per-field seen-sets cannot express Elastic's
 *   "the COMBINATION is new" semantics (no clean OpenSearch primitive without an ingest-side
 *   concat field — research_r5 §3.4). N-field any/all variants are expressible but semantically
 *   different; deliberately not offered.
 * - The monitor's DETECTION window is the scan cadence (runEvery, default 1 minute), NOT the
 *   history window: each run scans only the arrivals of the last runEvery period, so consecutive
 *   runs tile the timeline exactly ({@link buildWindow} consumed verbatim via the shared
 *   aggregation compiler — schedule and range derive from the SAME TimeWindow and cannot drift).
 *   `historyWindow` feeds ONLY the seen-state bootstrap/sweep query — it never appears in the
 *   monitor. A @timestamp range (unlike the doc-level seq-no checkpoint) also means replayed/
 *   backfilled OLD events do NOT fire as "new" (research_r5 §5 risk note). Accepted tradeoff:
 *   events indexed with more lag than the tiling allows are never scanned — the same
 *   characteristic every TLSOC bucket rule has.
 * - Emission goes through {@link compileAggregationRule} (the ONE bucket compiler), not a
 *   parallel emission: the must_not lookup rides as a `dsl` filter clause, so the composite
 *   shape, `missing_bucket:false`, GROUPS_AGG naming, buckets_path consistency, and the window
 *   idiom are all inherited — a second bucket emitter would be exactly the drift the v1.2.3
 *   architecture bans. (ONE acknowledged exception stands in v1.2.3: indicator_match.ts's
 *   LOOKUP compiler hand-emits its golden-pinned bucket shape; consolidating it into
 *   compileAggregationRule is deliberate v1.3 debt — see its docblock.) The ONLY post-compile
 *   override is the trigger's display NAME (the
 *   compiler's "threshold breached" copy would mislead analysts on a first-seen alert); the
 *   trigger CONDITION stays compiler-emitted, untouched.
 * - The seen-state doc id is OWNED BY THE SAVE ROUTE (it owns rule identity): compile takes it
 *   as an explicit parameter and throws by name when it is missing, so an unsaved rule can never
 *   silently compile a lookup at a nonexistent doc.
 * - Composite page size is the shared compiler's 100: more than 100 NEW values in one scan
 *   window alert only for the first composite page; the rest are marked seen by the next sweep
 *   without ever alerting (documented cap, same class as the R1 group-by truncation risk).
 */

/**
 * The persisted mode string for this type. Typed `string` (not DetectionMode) so modules that
 * must not depend on the registry edit landing (the server sweep) can compare against SO `mode`
 * values without a cast.
 */
export const NEW_TERMS_MODE: string = 'new_terms';

/**
 * The TLSOC-owned cluster index holding one seen-values doc per (rule × term field). Verified
 * collision-free against every shipped template pattern (fosstlsoc-logs-*, all-logs-*, soc-*) and
 * the ISM delete policy scope (research_r5 §2) — never renamed without re-running that check.
 */
export const DETECTION_STATE_INDEX = 'tlsoc-detection-state';

/**
 * The field of the state doc the terms-lookup reads. Changing it orphans every existing monitor's
 * lookup `path` — frozen.
 */
export const SEEN_VALUES_PATH = 'values';

/**
 * Hard cap on stored seen values = the engine's `index.max_terms_count` default, enforced on the
 * DATA index at query time: a lookup doc with more values fails the monitor run LOUDLY with
 * query_shard_exception (live-proven, research_r5 §3.1). The bootstrap/sweep never writes more;
 * hitting the cap marks the state doc `truncated` (the rule is degraded: values beyond the cap
 * are MISSING from the seen set, so they keep alerting as new even after they have been seen).
 */
export const SEEN_VALUES_CAP = 65536;

/** Default history window: how far back "already seen" reaches when the rule is saved. */
export const DEFAULT_NEW_TERMS_HISTORY_WINDOW: TimeWindow = { value: 30, unit: 'DAYS' };

/**
 * Default scan cadence when the rule carries no `runEvery` — matches the doc-level types'
 * 1-minute default (and the ScheduleSection's "1-minute default" helper copy), so the shared
 * schedule UI needs no per-type branch.
 */
export const DEFAULT_NEW_TERMS_RUN_EVERY: TimeWindow = { value: 1, unit: 'MINUTES' };

/** A complete new-terms detection rule — the builder's output and this compiler's input. */
export interface NewTermsRuleDefinition extends RuleMetadataFields {
  /** Stable rule id (UUID). Optional; callers may supply one for deterministic output. */
  id?: string;
  name: string;
  description?: string;
  severity: Severity;
  /** The index / data-view pattern the rule runs against, e.g. 'fosstlsoc-logs-*'. */
  index: string;
  /**
   * THE one field whose never-seen values fire (v1 scope — see the file docblock). Arrives
   * PRE-RESOLVED: the editor offers aggregatable fields only (text fields via their `.keyword`
   * subfield) — a terms agg/composite on analyzed text fails at monitor runtime with NO alert
   * written (silent-failure class, research_r2 §a). The bootstrap agg doubles as the server-side
   * gate: an unaggregatable field fails the save LOUDLY before any monitor exists.
   */
  termField: string;
  /**
   * How far back a value must have been absent to count as new. Feeds ONLY the seen-state
   * bootstrap/sweep aggregation — never the monitor query. Default {@link DEFAULT_NEW_TERMS_HISTORY_WINDOW}.
   */
  historyWindow: TimeWindow;
  /** Optional pre-filter: only matching events are scanned for new values (and bootstrapped from). */
  filter?: ConditionGroup;
  /** Scan cadence R = the per-run detection range. Default {@link DEFAULT_NEW_TERMS_RUN_EVERY}. */
  runEvery?: TimeWindow;
  /**
   * MUST be exactly [termField]: the alert flyout labels bucket keys from rule.groupBy (the R1
   * risk), and this rule's buckets are keyed by the term field alone. Enforced by
   * {@link assertValidNewTermsRule}; the editor mirrors it automatically.
   */
  groupBy: string[];
  /**
   * The seen-state doc id, INJECTED BY THE SAVE ROUTE (never authored client-side): deterministic
   * {@link newTermsStateDocId} of the rule's SO id + termField. Persisted for delete cleanup and
   * degraded-state lookups; always recomputable, so a client dropping it on edit is harmless —
   * the update route re-injects it.
   */
  stateDocId?: string;
}

/**
 * The deterministic seen-state doc id for a saved rule. The SO id comes first so the whole
 * (rule × field) identity is recomputable from the saved object alone — the route, the sweep,
 * and delete cleanup must all derive the id HERE, never inline.
 */
export function newTermsStateDocId(ruleSoId: string, termField: string): string {
  return `seen-${ruleSoId}-${termField}`;
}

function assertValidTimeWindow(window: TimeWindow, what: string, ruleName: string): void {
  if (!window || !(window.value > 0) || !Number.isInteger(window.value)) {
    throw new Error(`New-terms rule "${ruleName}" must have a positive integer ${what}.`);
  }
  // Unit membership via the ONE shared reject-by-name helper (v1.2.3 W3 review: this file's
  // original idiom, hoisted to internal.ts so every TimeWindow-accepting validator shares it).
  assertValidTimeWindowUnit(window, what, `New-terms rule "${ruleName}"`);
}

/**
 * Mirrors the per-condition checks of internal.ts's (private) assertValidCondition for the
 * pre-filter: a degenerate condition would compile into a broken Lucene clause that the bucket
 * monitor swallows silently at runtime (no alert, no error — research_r2 §a).
 */
function assertValidFilterCondition(condition: Condition, index: number, ruleName: string): void {
  const where = `pre-filter condition ${index} ("${condition?.field}") in new-terms rule "${ruleName}"`;
  if (!condition || typeof condition.field !== 'string' || condition.field.trim() === '') {
    throw new Error(`${where}: a field is required.`);
  }
  if (LIST_OPERATORS.has(condition.operator)) {
    if (!Array.isArray(condition.values) || condition.values.length === 0) {
      throw new Error(
        `${where}: operator "${condition.operator}" requires a non-empty values list.`
      );
    }
  } else if (!VALUELESS_OPERATORS.has(condition.operator)) {
    if (condition.value === undefined || condition.value === null || condition.value === '') {
      throw new Error(`${where}: operator "${condition.operator}" requires a value.`);
    }
  }
}

/** Validate a new-terms rule before compiling; throws with a clear, user-facing message. */
export function assertValidNewTermsRule(rule: NewTermsRuleDefinition): void {
  if (!rule || typeof rule.name !== 'string' || rule.name.trim() === '') {
    throw new Error('New-terms rule must have a non-empty name.');
  }
  if (typeof rule.index !== 'string' || rule.index.trim() === '') {
    throw new Error(`New-terms rule "${rule.name}" must specify a data view.`);
  }
  if (typeof rule.termField !== 'string' || rule.termField.trim() === '') {
    throw new Error(
      `New-terms rule "${rule.name}" must specify the term field whose new values fire.`
    );
  }
  // A rule can arrive via the API with any severity string; an unknown one would emit
  // `severity: undefined` into the trigger — the silent-failure class this release bans.
  if (!Object.prototype.hasOwnProperty.call(SEVERITY_TO_MONITOR_SEVERITY, rule.severity)) {
    throw new Error(
      `New-terms rule "${rule.name}" has an unknown severity "${String(rule.severity)}".`
    );
  }
  assertValidTimeWindow(rule.historyWindow, 'history window', rule.name);
  if (rule.runEvery !== undefined) {
    assertValidTimeWindow(rule.runEvery, 'run-every cadence', rule.name);
  }
  if (
    !Array.isArray(rule.groupBy) ||
    rule.groupBy.length !== 1 ||
    rule.groupBy[0] !== rule.termField
  ) {
    throw new Error(
      `New-terms rule "${rule.name}": groupBy must be exactly [termField] ` +
        `(["${rule.termField}"]) — the alert flyout labels bucket keys from it.`
    );
  }
  if (rule.filter !== undefined) {
    if (
      !rule.filter ||
      !Array.isArray(rule.filter.conditions) ||
      rule.filter.conditions.length === 0
    ) {
      throw new Error(
        `New-terms rule "${rule.name}": a pre-filter must contain at least one condition ` +
          '(omit the filter entirely to scan all events).'
      );
    }
    rule.filter.conditions.forEach((condition, index) =>
      assertValidFilterCondition(condition, index, rule.name)
    );
  }
  // v1.2.3 D9: exceptions are additive — a rule WITHOUT them validates exactly as before.
  if (rule.exceptions !== undefined) {
    validateExceptions(rule.exceptions, `New-terms rule "${rule.name}"`);
  }
}

/** The effective scan cadence: `runEvery`, defaulted. The single place the default applies. */
export function newTermsScanWindow(rule: NewTermsRuleDefinition): TimeWindow {
  return rule.runEvery ?? DEFAULT_NEW_TERMS_RUN_EVERY;
}

/**
 * Compile a new-terms rule to the bucket-level Alerting monitor that executes it. `stateDocId`
 * is the route-owned seen-state doc id ({@link newTermsStateDocId}) — required: the terms-lookup
 * MUST point at a doc the route bootstrapped BEFORE this monitor is created (a missing lookup
 * doc's behavior is unverified on the engine and must never be relied on).
 */
export function compileNewTermsToMonitor(
  rule: NewTermsRuleDefinition,
  stateDocId: string
): BucketLevelMonitor {
  assertValidNewTermsRule(rule);
  if (typeof stateDocId !== 'string' || stateDocId.trim() === '') {
    throw new Error(
      `New-terms rule "${rule.name}" has no seen-state document id — the save route owns rule ` +
        'identity and must supply it (bootstrap the seen values, then compile).'
    );
  }

  // Clause order is pinned by the goldens: optional pre-filter first, then the seen-exclusion.
  const clauses: object[] = [];
  if (rule.filter) {
    clauses.push({
      query_string: { query: conditionGroupToLucene(rule.filter), analyze_wildcard: true },
    });
  }
  clauses.push({
    bool: {
      must_not: [
        {
          terms: {
            [rule.termField]: {
              index: DETECTION_STATE_INDEX,
              id: stateDocId,
              path: SEEN_VALUES_PATH,
            },
          },
        },
      ],
    },
  });
  const exceptionClause = exceptionsToFilterClause(rule.exceptions);
  if (exceptionClause) {
    clauses.push(exceptionClause);
  }

  const input: AggregationCompileInput = {
    name: rule.name,
    severity: rule.severity,
    index: rule.index,
    filter: { kind: 'dsl', clauses },
    // The scan cadence IS the window: schedule and @timestamp range both derive from it inside
    // compileAggregationRule (buildWindow verbatim), so runs tile the timeline exactly.
    window: newTermsScanWindow(rule),
    spec: {
      by: [rule.termField],
      metrics: [],
      // Any surviving (never-seen) value = one bucket = one alert.
      having: { kind: 'cmp', alias: '_count', op: 'gt', value: 0 },
    },
  };

  const monitor = compileAggregationRule(input);
  // Cosmetic override ONLY (see file docblock): the shared compiler's "threshold breached" copy
  // would mislead analysts on a first-seen alert. The condition is untouched.
  monitor.triggers[0].bucket_level_trigger.name = `${rule.name} new value seen`;
  return monitor;
}
