/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  Condition,
  CountThreshold,
  LIST_OPERATORS,
  RuleDefinition,
  Severity,
  SuppressionConfig,
  ThresholdRuleDefinition,
  TimeWindow,
  VALUELESS_OPERATORS,
} from './types';
import { validateExceptions } from './exceptions';
// Type-only import (agg_types has no runtime exports), so no runtime cycle exists even though
// agg_types.ts itself imports types from './types'.
import type { AggregationSpec, HavingExpr } from './agg_types';

/**
 * Shared, side-effect-free helpers used by BOTH compile targets, so the Sigma and doc-level
 * monitor outputs derive severity, validation, and naming identically (decision D-008).
 */

/** TLSOC severity → Sigma `level`. */
export const SEVERITY_TO_SIGMA_LEVEL: Record<Severity, string> = {
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'critical',
};

/**
 * TLSOC severity → OpenSearch Alerting trigger severity ("1".."5", where 1 is most severe).
 * See the Alerting monitor API: triggers[].*.severity.
 */
export const SEVERITY_TO_MONITOR_SEVERITY: Record<Severity, string> = {
  critical: '1',
  high: '2',
  medium: '3',
  low: '4',
};

/** Minutes per {@link TimeWindow} unit, for comparing two windows expressed in different units. */
const MINUTES_PER_UNIT: Record<TimeWindow['unit'], number> = {
  MINUTES: 1,
  HOURS: 60,
  DAYS: 60 * 24,
};

/** Express a {@link TimeWindow} in minutes, so windows in different units can be compared. */
export function windowMinutes(window: TimeWindow): number {
  return window.value * MINUTES_PER_UNIT[window.unit];
}

/** Runtime mirror of the {@link TimeWindow} unit union, for reject-by-name validation. */
const TIME_WINDOW_UNITS: ReadonlySet<string> = new Set(['MINUTES', 'HOURS', 'DAYS']);

/**
 * Reject a {@link TimeWindow} whose unit is outside the union, BY NAME (v1.2.3 W3 review, the
 * fix-the-class sweep of new_terms.ts's original idiom). TypeScript's union only protects typed
 * callers — a rule arriving over the API can carry any unit string, and a non-member unit
 * compiles into a broken schedule/date-math expression the engine swallows silently (bucket
 * monitors write NO alert on runtime failure — research_r2 §a), or NaNs out of
 * {@link windowMinutes} so the R ≤ T comparison silently passes. EVERY validator that accepts a
 * TimeWindow must call this for each window it takes; `ruleLabel` is the validator's own rule
 * prefix (e.g. `Threshold rule "X"`) and `what` names the window (e.g. 'time window',
 * 'run-every').
 */
export function assertValidTimeWindowUnit(
  window: TimeWindow,
  what: string,
  ruleLabel: string
): void {
  if (!window || !TIME_WINDOW_UNITS.has(window.unit)) {
    throw new Error(
      `${ruleLabel} has an unknown ${what} unit "${String(window?.unit)}". ` +
        'Supported: MINUTES, HOURS, DAYS.'
    );
  }
}

/** Validate a rule before compiling; throws an Error with a clear, user-facing message. */
export function assertValidRule(rule: RuleDefinition): void {
  if (!rule || typeof rule.name !== 'string' || rule.name.trim() === '') {
    throw new Error('Detection rule must have a non-empty name.');
  }
  if (typeof rule.index !== 'string' || rule.index.trim() === '') {
    throw new Error(`Detection rule "${rule.name}" must specify a data view.`);
  }
  if (!rule.group || !Array.isArray(rule.group.conditions) || rule.group.conditions.length === 0) {
    throw new Error(`Detection rule "${rule.name}" must have at least one condition.`);
  }
  rule.group.conditions.forEach((condition, index) =>
    assertValidCondition(condition, index, rule.name)
  );
  if (rule.runEvery) {
    if (!(rule.runEvery.value > 0 && Number.isInteger(rule.runEvery.value))) {
      throw new Error(`Detection rule "${rule.name}" must have a positive run-every value.`);
    }
    assertValidTimeWindowUnit(rule.runEvery, 'run-every', `Detection rule "${rule.name}"`);
  }
  // v1.2.3 D9 (both additive — a rule WITHOUT them validates exactly as before):
  if (rule.exceptions !== undefined) {
    validateExceptions(rule.exceptions, `Detection rule "${rule.name}"`);
  }
  if (rule.suppression !== undefined) {
    assertValidSuppression(rule.suppression, `Detection rule "${rule.name}"`);
    // The alerts join labels bucket keys from rule.groupBy — a stale mirror would mislabel the
    // suppressed alert's group keys (the same R1 risk new_terms/indicator_match enforce).
    if (
      rule.groupBy !== undefined &&
      (rule.groupBy.length !== rule.suppression.groupBy.length ||
        rule.groupBy.some((f, i) => f !== rule.suppression!.groupBy[i]))
    ) {
      throw new Error(
        `Detection rule "${rule.name}": groupBy must mirror suppression.groupBy ` +
          `(${rule.suppression.groupBy.join(', ')}) — the alert flyout labels group keys from it.`
      );
    }
  }
}

/**
 * Validate a doc-kind rule's suppression config (v1.2.3 D9); throws with a user-facing message.
 * Field aggregatability cannot be checked here (pure module, no cluster) — the builder offers
 * aggregatable fields only, and the compiled monitor's composite validation is the engine gate.
 */
export function assertValidSuppression(suppression: SuppressionConfig, ruleLabel: string): void {
  if (!suppression || typeof suppression !== 'object' || Array.isArray(suppression)) {
    throw new Error(`${ruleLabel}: suppression is malformed.`);
  }
  if (!Array.isArray(suppression.groupBy) || suppression.groupBy.length === 0) {
    throw new Error(`${ruleLabel}: suppression must group by at least one field.`);
  }
  suppression.groupBy.forEach((field) => {
    if (typeof field !== 'string' || field.trim() === '') {
      throw new Error(`${ruleLabel}: suppression group-by entries must be non-empty field names.`);
    }
  });
  if (
    !suppression.window ||
    !(suppression.window.value > 0) ||
    !Number.isInteger(suppression.window.value)
  ) {
    throw new Error(`${ruleLabel} must have a positive integer suppression window.`);
  }
  assertValidTimeWindowUnit(suppression.window, 'suppression window', ruleLabel);
}

function assertValidCondition(condition: Condition, index: number, ruleName: string): void {
  const where = `condition ${index} ("${condition?.field}") in rule "${ruleName}"`;
  if (!condition || typeof condition.field !== 'string' || condition.field.trim() === '') {
    throw new Error(`${where}: a field is required.`);
  }
  if (LIST_OPERATORS.has(condition.operator)) {
    if (!Array.isArray(condition.values) || condition.values.length === 0) {
      throw new Error(`${where}: operator "${condition.operator}" requires a non-empty values list.`);
    }
  } else if (!VALUELESS_OPERATORS.has(condition.operator)) {
    if (condition.value === undefined || condition.value === null || condition.value === '') {
      throw new Error(`${where}: operator "${condition.operator}" requires a value.`);
    }
  }
}

/** Produce a slug usable as an OpenSearch doc-level monitor query id/name ([a-z0-9_]). */
export function slugify(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return slug || 'tlsoc_rule';
}

/** Threshold comparison operator → Painless comparator for the bucket-level trigger condition. */
export const PAINLESS_OP: Record<CountThreshold['operator'], string> = {
  gt: '>',
  gte: '>=',
  lt: '<',
  lte: '<=',
};

/** A composite-aggregation source name must not contain dots; derive a safe key from a field. */
export function compositeSourceName(field: string): string {
  return field.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'group';
}

/** Validate a stateful threshold rule before compiling; throws with a clear, user-facing message. */
export function assertValidThresholdRule(rule: ThresholdRuleDefinition): void {
  if (!rule || typeof rule.name !== 'string' || rule.name.trim() === '') {
    throw new Error('Threshold rule must have a non-empty name.');
  }
  if (typeof rule.index !== 'string' || rule.index.trim() === '') {
    throw new Error(`Threshold rule "${rule.name}" must specify a data view.`);
  }
  if (!rule.filter || !Array.isArray(rule.filter.conditions) || rule.filter.conditions.length === 0) {
    throw new Error(`Threshold rule "${rule.name}" must have at least one filter condition.`);
  }
  rule.filter.conditions.forEach((condition, index) =>
    assertValidCondition(condition, index, rule.name)
  );
  if (!Array.isArray(rule.groupBy) || rule.groupBy.length === 0) {
    throw new Error(`Threshold rule "${rule.name}" must group by at least one field.`);
  }
  if (!rule.window || !(rule.window.value > 0)) {
    throw new Error(`Threshold rule "${rule.name}" must have a positive time window.`);
  }
  assertValidTimeWindowUnit(rule.window, 'time window', `Threshold rule "${rule.name}"`);
  if (!rule.threshold || !Number.isInteger(rule.threshold.value) || rule.threshold.value < 0) {
    throw new Error(`Threshold rule "${rule.name}" must have a non-negative integer threshold.`);
  }
  if (rule.runEvery) {
    if (!(rule.runEvery.value > 0 && Number.isInteger(rule.runEvery.value))) {
      throw new Error(`Threshold rule "${rule.name}" must have a positive run-every value.`);
    }
    // Unit membership BEFORE the R ≤ T comparison — windowMinutes NaNs on a bad unit, and
    // NaN > x is false, so the comparison alone would silently accept it.
    assertValidTimeWindowUnit(rule.runEvery, 'run-every', `Threshold rule "${rule.name}"`);
    if (windowMinutes(rule.runEvery) > windowMinutes(rule.window)) {
      throw new Error(
        `Threshold rule "${rule.name}": run-every must not exceed the threshold window — a longer ` +
          'cadence would leave time the rule never evaluates.'
      );
    }
  }
  // v1.2.3 D9: exceptions are additive — a rule WITHOUT them validates exactly as before.
  if (rule.exceptions !== undefined) {
    validateExceptions(rule.exceptions, `Threshold rule "${rule.name}"`);
  }
  // v1.2.3 D4: OPTIONAL enhanced metrics. When present, the advanced spec is validated with
  // rule.groupBy as its group-by — rule.groupBy is authoritative (advanced.by is ignored at
  // compile; see ThresholdRuleDefinition.advanced). Behavior when `advanced` is ABSENT is
  // UNCHANGED — the legacy count-only path validates and compiles byte-identically.
  if (rule.advanced) {
    validateAggregationSpec({
      by: rule.groupBy,
      metrics: rule.advanced.metrics,
      having: rule.advanced.having,
    });
  }
}

/*
 * ————————————————————————————————————————————————————————————————————————————————————————————
 * v1.2.3 aggregation-spec validation (D4 enhanced threshold / D3 PPL — the shared IR of
 * common/detection/agg_types.ts). Lives here (not in agg_compile.ts) so assertValidThresholdRule
 * can reuse it without an internal ⇄ agg_compile import cycle; agg_compile.ts re-exports it as
 * its public validation entry point.
 * ————————————————————————————————————————————————————————————————————————————————————————————
 */

/**
 * The reserved buckets_path key/alias for the composite bucket's own document count. A having
 * comparison may reference it directly; a metric alias may never claim it.
 */
export const RESERVED_COUNT_ALIAS = '_count';

/**
 * Metric alias shape: lowercase letters/digits/underscores, no leading digit. The alias doubles as
 * the buckets_path key AND the `params.<alias>` reference in the trigger's painless script — a
 * leading digit makes `params.9x` a painless syntax error at monitor runtime, which (for bucket
 * monitors) fails SILENTLY with no alert written (research_r2 §a). So the shape is enforced here,
 * at authoring/compile time.
 */
export const AGG_ALIAS_PATTERN = /^[a-z_][a-z0-9_]*$/;

/**
 * Aliases that may never name a metric: '_count' is the reserved doc-count reference, and
 * 'key'/'doc_count' would collide with the composite bucket's own response keys the Alerting
 * trigger reads (`agg_alert_content.bucket.key` / `.doc_count`).
 */
const RESERVED_ALIASES: ReadonlySet<string> = new Set([RESERVED_COUNT_ALIAS, 'key', 'doc_count']);

/** Runtime mirror of the (type-only) agg_types MetricFn union, for reject-by-name validation. */
const METRIC_FNS: ReadonlySet<string> = new Set([
  'count',
  'value_count',
  'cardinality',
  'sum',
  'avg',
  'min',
  'max',
]);

/** Runtime mirror of the HavingExpr cmp op union. */
const HAVING_OPS: ReadonlySet<string> = new Set(['gt', 'gte', 'lt', 'lte', 'eq', 'neq']);

/**
 * Validate an {@link AggregationSpec} before compiling; throws with a clear, user-facing message.
 * Every rejection here guards a live-verified engine trap (research_r2 §a): a buckets_path alias
 * that doesn't match an emitted agg name fails at runtime with the useless "Empty list doesn't
 * contain element at index 0.", and bucket-monitor runtime failures write NO alert at all — so
 * alias shape, alias↔metric consistency, and having-reference resolution are all enforced HERE.
 */
export function validateAggregationSpec(spec: AggregationSpec): void {
  if (!spec || typeof spec !== 'object') {
    throw new Error('Aggregation spec is missing.');
  }
  if (!Array.isArray(spec.by) || spec.by.length === 0) {
    throw new Error('Aggregation rule must group by at least one field.');
  }
  const sourceNames = new Map<string, string>();
  spec.by.forEach((field) => {
    if (typeof field !== 'string' || field.trim() === '') {
      throw new Error('Aggregation rule group-by entries must be non-empty field names.');
    }
    const sourceName = compositeSourceName(field);
    const priorField = sourceNames.get(sourceName);
    if (priorField === field) {
      throw new Error(`Group-by field "${field}" is listed more than once.`);
    }
    if (priorField !== undefined) {
      throw new Error(
        `Group-by fields "${priorField}" and "${field}" both map to composite source name ` +
          `"${sourceName}" — the aggregation would be invalid. Remove one of them.`
      );
    }
    sourceNames.set(sourceName, field);
  });
  if (!Array.isArray(spec.metrics)) {
    throw new Error('Aggregation spec metrics must be a list (it may be empty).');
  }
  const aliases = new Set<string>();
  spec.metrics.forEach((metric, i) => {
    if (!metric || typeof metric.alias !== 'string' || metric.alias.trim() === '') {
      throw new Error(
        `Metric ${i + 1}: an alias is required — it names the value in the threshold condition.`
      );
    }
    const label = `Metric "${metric.alias}"`;
    if (RESERVED_ALIASES.has(metric.alias)) {
      throw new Error(
        `${label}: this alias is reserved ("_count" is the per-group event count; "key" and ` +
          '"doc_count" collide with the bucket response). Pick another name.'
      );
    }
    if (!AGG_ALIAS_PATTERN.test(metric.alias)) {
      throw new Error(
        `${label}: aliases must use lowercase letters, digits, and underscores only, and must ` +
          'not start with a digit.'
      );
    }
    if (aliases.has(metric.alias)) {
      throw new Error(`${label}: duplicate alias — each metric alias must be unique.`);
    }
    aliases.add(metric.alias);
    if (!METRIC_FNS.has(metric.fn)) {
      throw new Error(
        `${label}: unknown aggregation function "${metric.fn}". Supported: count, value_count, ` +
          'cardinality, sum, avg, min, max.'
      );
    }
    if (metric.fn === 'count') {
      if (metric.field !== undefined && String(metric.field).trim() !== '') {
        throw new Error(
          `${label}: count() takes no field — use value_count to count non-null values of a field.`
        );
      }
    } else if (typeof metric.field !== 'string' || metric.field.trim() === '') {
      throw new Error(`${label}: ${metric.fn} requires a field.`);
    }
    if (metric.filter !== undefined) {
      if (
        !metric.filter ||
        !Array.isArray(metric.filter.conditions) ||
        metric.filter.conditions.length === 0
      ) {
        throw new Error(`${label}: a sub-filter must contain at least one condition.`);
      }
      metric.filter.conditions.forEach((condition, ci) =>
        assertValidCondition(condition, ci, `${metric.alias} metric sub-filter`)
      );
    }
  });
  if (!spec.having) {
    throw new Error(
      'Aggregation rule has no threshold condition — add at least one comparison ' +
        '(e.g. distinct_urls >= 40).'
    );
  }
  assertValidHavingExpr(spec.having, aliases);
}

/** Walk a HavingExpr tree, rejecting unknown kinds/ops and unresolvable alias references by name. */
function assertValidHavingExpr(expr: HavingExpr, knownAliases: ReadonlySet<string>): void {
  if (!expr || typeof expr !== 'object' || !('kind' in expr)) {
    throw new Error('The threshold condition is malformed (an entry has no kind).');
  }
  if (expr.kind === 'cmp') {
    if (typeof expr.alias !== 'string' || expr.alias.trim() === '') {
      throw new Error('A threshold comparison must reference a metric alias (or "_count").');
    }
    if (expr.alias !== RESERVED_COUNT_ALIAS && !knownAliases.has(expr.alias)) {
      const known = ['_count', ...knownAliases].join(', ');
      throw new Error(
        `The threshold condition references "${expr.alias}", which is not a defined metric ` +
          `alias. Known: ${known}. (An unmatched alias fails at monitor runtime with an ` +
          'unusable engine error, so it is rejected here.)'
      );
    }
    if (!HAVING_OPS.has(expr.op)) {
      throw new Error(
        `The threshold condition on "${expr.alias}" uses unknown operator "${expr.op}". ` +
          'Supported: gt, gte, lt, lte, eq, neq.'
      );
    }
    if (typeof expr.value !== 'number' || !Number.isFinite(expr.value)) {
      throw new Error(
        `The threshold condition on "${expr.alias}" needs a finite numeric value to compare to.`
      );
    }
    return;
  }
  if (expr.kind === 'and' || expr.kind === 'or') {
    if (!Array.isArray(expr.operands) || expr.operands.length === 0) {
      throw new Error('The threshold condition must contain at least one comparison.');
    }
    expr.operands.forEach((operand) => assertValidHavingExpr(operand, knownAliases));
    return;
  }
  throw new Error(
    `Unknown threshold-condition kind "${(expr as { kind: string }).kind}". ` +
      'Supported: cmp, and, or.'
  );
}
