/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { ConditionGroup, Severity, TimeWindow } from './types';
import type { RuleMetadataFields } from './types';
import {
  SEVERITY_TO_MONITOR_SEVERITY,
  assertValidTimeWindowUnit,
  compositeSourceName,
  slugify,
} from './internal';
import { conditionGroupToLucene } from './lucene';
import {
  applyExceptionsToLucene,
  exceptionsToFilterClause,
  validateExceptions,
} from './exceptions';
import { buildWindow } from './window';
import { DocLevelMonitor } from './monitor';
import { BucketLevelMonitor, GROUPS_AGG } from './bucket_monitor';
import {
  VALUE_LISTS_INDEX,
  VALUE_LIST_INLINE_MAX_VALUES,
  VALUE_LIST_MAX_VALUES,
} from '../value_lists';

/**
 * The D6 indicator-match rule (v1.2.3): fire when an EVENT field's value appears in a value list
 * (IOC list). ONE rule type, TWO compile shapes — a size-based hybrid, every leg live-proven on
 * OpenSearch 3.7 (research_r5 §4):
 *
 * - INLINE (list ≤ {@link VALUE_LIST_INLINE_MAX_VALUES} values): a doc-level monitor whose query
 *   is `field:("v1" OR "v2" …)` — the best alert quality (one alert per matching EVENT, with
 *   `related_doc_ids` feeding the existing flyout enrichment). The ceiling exists because the
 *   engine's 1024-clause cap fails SILENTLY (1024 matches, 1025 matches NOTHING with no error) —
 *   the compiler REFUSES over-cap input by name and never truncates. When the list changes, the
 *   monitor's query string must be rewritten (the sweep in server/routes/value_lists.ts; observed
 *   one-run percolation staleness accepted + documented there).
 *
 * - LOOKUP (larger lists, up to {@link VALUE_LIST_MAX_VALUES}): a bucket-level monitor whose
 *   filter is a terms-LOOKUP `{index: 'tlsoc-value-lists', id: <listId>, path: 'values'}` + a
 *   composite terms agg on the event field + trigger `params._count > 0` — one alert per MATCHED
 *   INDICATOR VALUE per window, the value itself carried in `agg_alert_content.bucket_keys`,
 *   dedup while it keeps matching, auto-COMPLETED when it stops. List edits apply on the next
 *   run with NO monitor rewrite. (A doc-level terms-lookup is IMPOSSIBLE: the lookup JSON passed
 *   as a query string silently matches nothing — research_r2 §d — which is exactly why the
 *   hybrid exists.)
 *
 * Which shape executes is picked AT SAVE TIME from the list's current size (the save route's
 * job — {@link pickIndicatorListMode}); `listMode` is persisted on the rule so the UI can show
 * which shape a saved rule runs as, and every re-save re-picks it.
 */

/** The registry type id — the persisted `mode` string (new id, zero-migration discipline). */
export const INDICATOR_MATCH_MODE = 'indicator_match';

export type IndicatorListMode = 'inline' | 'lookup';

/** A complete indicator-match rule — the builder's output and both compilers' input. */
export interface IndicatorMatchRuleDefinition extends RuleMetadataFields {
  /** Stable rule id (UUID). Optional; callers may supply one for deterministic output. */
  id?: string;
  name: string;
  description?: string;
  severity: Severity;
  /** The index / data-view pattern the rule runs against, e.g. 'fosstlsoc-logs-*'. */
  index: string;
  /**
   * The field in EVENTS whose value is matched against the list. Must be keyword-family for
   * 'keyword' lists and ip-mapped for 'ip' lists (CIDR blocks only match against `ip` fields —
   * the save route verifies via field_caps; research_r5 §4.3).
   */
  eventField: string;
  /** The value list's id — the `_id` of its doc in {@link VALUE_LISTS_INDEX}. */
  listId: string;
  /**
   * Which compile shape this rule currently executes as. PERSISTED so the rules list / Threat
   * Intel UI can show it honestly; RE-PICKED from the list's size on every save (create AND
   * update) by the save route — a client cannot pin a list over the inline cliff to inline mode.
   */
  listMode: IndicatorListMode;
  /** Optional pre-filter: only events matching it are checked against the list. */
  filter?: ConditionGroup;
  /**
   * MUST be exactly [eventField]: in lookup (bucket) mode the composite groups by the event
   * field, and the alert flyout labels bucket keys from RuleRef.groupBy — an out-of-sync value
   * would mislabel the matched indicator, so the validator enforces the equality.
   */
  groupBy: string[];
  /**
   * Optional cadence R. Inline (doc-level) mode: the monitor schedule only (default 1 minute —
   * the doc-level legacy default; doc-level monitors have no window). Lookup (bucket) mode: the
   * schedule AND the evaluated window are BOTH this value (default 1 minute) — window == period
   * means contiguous coverage with each event evaluated exactly once, the same decision class as
   * the D5 new-terms monitor (design §W3b; the range comes from buildWindow VERBATIM).
   */
  runEvery?: TimeWindow;
}

/** The lookup-mode window/schedule when `runEvery` is absent (mirrors the doc-level default). */
const DEFAULT_INDICATOR_WINDOW: TimeWindow = { value: 1, unit: 'MINUTES' };

const LIST_MODES: readonly IndicatorListMode[] = ['inline', 'lookup'];

/**
 * Pick the compile shape for a list of `valueCount` values — the save route calls this with the
 * list's CURRENT size on every create/update. Throws (refuses, never truncates) for empty and
 * over-cap lists: an empty inline query is invalid Lucene, and an over-cap lookup fails every
 * monitor run loudly (research_r5 §3.1) — both are authoring errors to surface at save.
 */
export function pickIndicatorListMode(valueCount: number): IndicatorListMode {
  if (!Number.isInteger(valueCount) || valueCount <= 0) {
    throw new Error(
      'The value list has no values — an indicator-match rule on it could never fire. Add ' +
        'values to the list first.'
    );
  }
  if (valueCount > VALUE_LIST_MAX_VALUES) {
    throw new Error(
      `The value list has ${valueCount} values — over the ${VALUE_LIST_MAX_VALUES} ceiling ` +
        '(index.max_terms_count): every run of a rule on it would fail. Split the list.'
    );
  }
  return valueCount <= VALUE_LIST_INLINE_MAX_VALUES ? 'inline' : 'lookup';
}

/** Validate an indicator-match rule before compiling; throws with a user-facing message. */
export function assertValidIndicatorMatchRule(rule: IndicatorMatchRuleDefinition): void {
  if (!rule || typeof rule.name !== 'string' || rule.name.trim() === '') {
    throw new Error('Indicator-match rule must have a non-empty name.');
  }
  if (typeof rule.index !== 'string' || rule.index.trim() === '') {
    throw new Error(`Indicator-match rule "${rule.name}" must specify a data view.`);
  }
  // A bad severity would silently emit `severity: undefined` — the banned silent-failure class.
  if (!Object.prototype.hasOwnProperty.call(SEVERITY_TO_MONITOR_SEVERITY, rule.severity)) {
    throw new Error(
      `Indicator-match rule "${rule.name}" has an unknown severity "${String(rule.severity)}".`
    );
  }
  if (typeof rule.eventField !== 'string' || rule.eventField.trim() === '') {
    throw new Error(
      `Indicator-match rule "${rule.name}" must specify the event field to match against the list.`
    );
  }
  if (typeof rule.listId !== 'string' || rule.listId.trim() === '' || /\s/.test(rule.listId)) {
    throw new Error(`Indicator-match rule "${rule.name}" must reference a value list.`);
  }
  if (!LIST_MODES.includes(rule.listMode)) {
    throw new Error(
      `Indicator-match rule "${rule.name}" has an unknown list mode ` +
        `"${String(rule.listMode)}". Supported: ${LIST_MODES.join(', ')}.`
    );
  }
  // groupBy labels the bucket keys in the alert flyout — it must be exactly the event field.
  if (
    !Array.isArray(rule.groupBy) ||
    rule.groupBy.length !== 1 ||
    rule.groupBy[0] !== rule.eventField
  ) {
    throw new Error(
      `Indicator-match rule "${rule.name}" must group by exactly its event field ` +
        `("${rule.eventField}") — the alert flyout labels matched values from it.`
    );
  }
  if (rule.filter !== undefined) {
    if (
      !rule.filter ||
      !Array.isArray(rule.filter.conditions) ||
      rule.filter.conditions.length === 0
    ) {
      throw new Error(
        `Indicator-match rule "${rule.name}": the pre-filter must contain at least one ` +
          'condition — omit it entirely to check every event.'
      );
    }
    // Per-condition validation: compile each condition — conditionGroupToLucene throws the
    // operator-level rejections, and an incomplete condition (empty field) is caught below.
    rule.filter.conditions.forEach((condition, index) => {
      if (!condition || typeof condition.field !== 'string' || condition.field.trim() === '') {
        throw new Error(
          `Indicator-match rule "${rule.name}": pre-filter condition ${index + 1} needs a field.`
        );
      }
    });
    conditionGroupToLucene(rule.filter);
  }
  if (rule.runEvery) {
    if (!(rule.runEvery.value > 0 && Number.isInteger(rule.runEvery.value))) {
      throw new Error(
        `Indicator-match rule "${rule.name}" must have a positive run-every value.`
      );
    }
    // A non-member unit compiles into broken schedule/date math the engine swallows silently
    // (the W3 review fix-the-class sweep) — reject it by name like every other validator.
    assertValidTimeWindowUnit(rule.runEvery, 'run-every', `Indicator-match rule "${rule.name}"`);
  }
  // v1.2.3 D9: exceptions are additive — a rule WITHOUT them validates exactly as before.
  if (rule.exceptions !== undefined) {
    validateExceptions(rule.exceptions, `Indicator-match rule "${rule.name}"`);
  }
}

/**
 * Quote one indicator value as a Lucene phrase — backslashes and quotes escaped (the quoted-
 * phrase escaping of lucene.ts's escapePhrase, mirrored here). CIDR blocks MUST ride quoted:
 * `src:"10.0.0.0/8"` matches correctly against an ip field in a real doc-level monitor run
 * (research_r5 §4.3); unquoted, the '/' would start a Lucene regex literal.
 */
function quoteIndicatorValue(value: string): string {
  return `"${value.replace(/([\\"])/g, '\\$1')}"`;
}

/**
 * The exact Lucene `query_string` an INLINE indicator rule executes: the field-grouped OR of
 * every list value, AND-composed with the optional pre-filter. Exported separately from the
 * monitor compiler because the list-change sweep (server/routes/value_lists.ts) rebuilds JUST
 * this string to compare against / rewrite into the live monitor.
 *
 * REFUSES (never truncates) lists over {@link VALUE_LIST_INLINE_MAX_VALUES}: past the engine's
 * 1024-clause cap the query matches NOTHING silently (research_r5 §4.2) — a truncated list would
 * be the same lie with extra steps.
 */
export function buildInlineIndicatorQuery(
  rule: Pick<IndicatorMatchRuleDefinition, 'eventField' | 'filter' | 'name' | 'exceptions'>,
  values: string[]
): string {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error(
      `Indicator-match rule "${rule.name}": the value list has no values — an inline query ` +
        'over an empty list is invalid.'
    );
  }
  if (values.length > VALUE_LIST_INLINE_MAX_VALUES) {
    throw new Error(
      `Indicator-match rule "${rule.name}": the value list has ${values.length} values — over ` +
        `the ${VALUE_LIST_INLINE_MAX_VALUES}-value inline limit. The list is NEVER truncated ` +
        '(past 1024 clauses the query silently matches nothing) — save the rule again so it ' +
        'switches to lookup mode.'
    );
  }
  values.forEach((value, index) => {
    if (typeof value !== 'string' || value.trim() === '') {
      throw new Error(
        `Indicator-match rule "${rule.name}": list value ${index + 1} is empty — an empty ` +
          'indicator can never be intended.'
      );
    }
  });
  const listClause = `${rule.eventField}:(${values.map(quoteIndicatorValue).join(' OR ')})`;
  // v1.2.3 D9: exceptions append the shared ` AND NOT (…)` fragment LAST (wrapping the base
  // query first — Lucene precedence safety). A rule without exceptions builds the exact pre-D9
  // string, byte for byte — the list-change sweep compares/rewrites THIS string, so both sides
  // (create route + sweep) must flow the same rule object through here.
  const base =
    rule.filter && rule.filter.conditions.length > 0
      ? `${listClause} AND (${conditionGroupToLucene(rule.filter)})`
      : listClause;
  return applyExceptionsToLucene(base, rule.exceptions);
}

/**
 * Compile an indicator-match rule + its list's CURRENT values to a doc-level Alerting monitor —
 * the INLINE shape. Emission mirrors compileToDocLevelMonitor (monitor.ts) byte-for-byte: same
 * schedule default, same queries[] shape, same `query[name=<slug>]` trigger condition (the
 * OpenSearch 3.7 hard requirement — a bare painless boolean errors at execution).
 *
 * Callers (the save route, the sweep) own fetching `values` from the list doc; this compiler is
 * pure. The registry's own `compile` uses the LOOKUP shape (values-free) — the route upgrades to
 * this shape when the list is small.
 */
export function compileIndicatorInlineToDocMonitor(
  rule: IndicatorMatchRuleDefinition,
  values: string[]
): DocLevelMonitor {
  assertValidIndicatorMatchRule(rule);
  const slug = slugify(rule.name);
  const query = buildInlineIndicatorQuery(rule, values);

  return {
    type: 'monitor',
    name: rule.name,
    monitor_type: 'doc_level_monitor',
    enabled: true,
    schedule: rule.runEvery
      ? { period: { interval: rule.runEvery.value, unit: rule.runEvery.unit } }
      : { period: { interval: 1, unit: 'MINUTES' } },
    inputs: [
      {
        doc_level_input: {
          description: rule.description ?? '',
          indices: [rule.index],
          queries: [
            {
              id: slug,
              name: slug,
              query,
              tags: ['tlsoc', rule.severity],
            },
          ],
        },
      },
    ],
    triggers: [
      {
        document_level_trigger: {
          name: `${rule.name} matched`,
          severity: SEVERITY_TO_MONITOR_SEVERITY[rule.severity],
          condition: { script: { source: `query[name=${slug}]`, lang: 'painless' } },
        },
      },
    ],
  };
}

/**
 * Compile an indicator-match rule to a bucket-level Alerting monitor — the LOOKUP shape, and the
 * registry's `compile` (it needs no list values: the engine resolves the lookup doc at run time,
 * so list edits go live on the next run with no rewrite). Shape per the live probes
 * (research_r5 §3.1/§4.2): window range + terms-LOOKUP filter (+ optional pre-filter) feeding a
 * composite terms agg on the event field, trigger `params._count > 0` — one alert per matched
 * indicator value, the value in `bucket_keys`.
 *
 * Window discipline: schedule AND range both come from ONE buildWindow(runEvery-or-default) call
 * — window == period (contiguous, each event evaluated once). The `{{period_end}}` range is
 * buildWindow's output VERBATIM (the window-sync invariant).
 *
 * SECOND-EMITTER ACKNOWLEDGMENT (v1.2.3 W3 review, D6): this function HAND-EMITS the bucket
 * monitor shape instead of routing through compileAggregationRule — the ONE bucket compiler that
 * new_terms.ts's docblock ban points every other emission at (its must_not lookup rides as a
 * `dsl` filter clause into the shared compiler; this one's terms-lookup could ride the same
 * way). It stands only because the emitted JSON is pinned golden to the live probes
 * (research_r5 §3.1/§4.2 — indicator_match.test.ts pins it byte-for-byte). Consolidating this
 * emission into compileAggregationRule is DELIBERATE v1.3 debt — do NOT copy this pattern; any
 * NEW bucket shape goes through the shared compiler.
 */
export function compileIndicatorLookupToBucketMonitor(
  rule: IndicatorMatchRuleDefinition
): BucketLevelMonitor {
  assertValidIndicatorMatchRule(rule);
  const window = buildWindow(rule.runEvery ?? DEFAULT_INDICATOR_WINDOW);

  const filterClauses: Array<Record<string, unknown>> = [
    {
      range: {
        '@timestamp': {
          from: window.rangeFrom,
          to: '{{period_end}}',
          include_lower: true,
          include_upper: true,
          format: 'epoch_millis',
        },
      },
    },
    {
      // The live-proven terms-lookup clause: the list DOC is the lookup target. Works in
      // query/bucket monitors; silently impossible in doc-level ones (research_r2 §d).
      terms: {
        [rule.eventField]: {
          index: VALUE_LISTS_INDEX,
          id: rule.listId,
          path: 'values',
        },
      },
    },
  ];
  if (rule.filter && rule.filter.conditions.length > 0) {
    filterClauses.push({
      query_string: { query: conditionGroupToLucene(rule.filter), analyze_wildcard: true },
    });
  }
  // v1.2.3 D9: exceptions append the shared {bool: {must_not}} clause LAST — a rule without
  // them emits the exact pre-D9 clause list (the golden-pinned probe shape stays untouched).
  const exceptionClause = exceptionsToFilterClause(rule.exceptions);
  if (exceptionClause) {
    filterClauses.push(exceptionClause);
  }

  return {
    type: 'monitor',
    name: rule.name,
    monitor_type: 'bucket_level_monitor',
    enabled: true,
    schedule: window.schedule,
    inputs: [
      {
        search: {
          indices: [rule.index],
          query: {
            size: 0,
            query: { bool: { filter: filterClauses } },
            aggregations: {
              [GROUPS_AGG]: {
                composite: {
                  size: 100,
                  sources: [
                    {
                      // missing_bucket EXPLICIT (the agg_compile idiom): events without the field
                      // can never match an indicator, so dropping them is the correct semantics.
                      [compositeSourceName(rule.eventField)]: {
                        terms: { field: rule.eventField, missing_bucket: false },
                      },
                    },
                  ],
                },
              },
            },
          },
        },
      },
    ],
    triggers: [
      {
        bucket_level_trigger: {
          name: `${rule.name} matched`,
          severity: SEVERITY_TO_MONITOR_SEVERITY[rule.severity],
          condition: {
            parent_bucket_path: GROUPS_AGG,
            buckets_path: { _count: '_count' },
            script: { source: 'params._count > 0', lang: 'painless' },
          },
        },
      },
    ],
  };
}
