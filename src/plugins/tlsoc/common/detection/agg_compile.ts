/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { AggFilter, AggregationCompileInput, HavingExpr, MetricDef } from './agg_types';
import { ConditionGroup, ThresholdRuleDefinition } from './types';
import { BucketLevelMonitor, GROUPS_AGG } from './bucket_monitor';
import {
  RESERVED_COUNT_ALIAS,
  SEVERITY_TO_MONITOR_SEVERITY,
  assertValidThresholdRule,
  compositeSourceName,
  validateAggregationSpec,
  windowMinutes,
} from './internal';
import { buildWindow } from './window';
import { conditionGroupToLucene } from './lucene';

/**
 * THE v1.2.3 aggregation compiler — the ONE compiler both new bucket-shaped front-ends lower to:
 * the D4 enhanced-threshold no-code form and the D3 PPL editor. It turns the shared IR
 * ({@link AggregationCompileInput}, agg_types.ts — the frozen contract) into a bucket-level
 * Alerting monitor shaped like the LIVE-PROVEN scanner monitor of research_r2 §a: a composite
 * aggregation per group-by field, metric sub-aggs (cardinality / value_count / sum / avg / min /
 * max, and `filter`-wrapped conditional counts), and a per-bucket painless trigger referencing
 * `params.<alias>` with `&&` / `||`.
 *
 * Deliberate house-idiom divergences from the §a probe JSON (semantically identical, byte-shape
 * aligned with compileToBucketLevelMonitor instead):
 * - The window range + filter sit inside `bool.filter` (the probe had a bare range query), and
 *   the range clause uses buildWindow's from/to + include_lower/include_upper form — the
 *   window-sync invariant (window.ts) consumed VERBATIM, never recomputed.
 * - The group agg is named {@link GROUPS_AGG} ('tlsoc_groups', same as the legacy bucket
 *   compiler), sources are named via {@link compositeSourceName}, and `missing_bucket: false` is
 *   EXPLICIT on every source: composite aggs DROP missing-key buckets, PPL groups them under
 *   null — the divergence is pinned explicitly so previews can explain it (research_r2 §c).
 * - Metric sub-filters compile through the battle-tested Lucene compiler into a `query_string`
 *   inside the `filter` agg (the probe hand-wrote range DSL) — same matching semantics, and the
 *   full 15-operator vocabulary (incl. analyzed-text handling) comes for free.
 *
 * Engine traps enforced at compile time (all live-verified, research_r2 §a):
 * - buckets_path aliases are GUARANTEED to match emitted agg names (a mismatch fails at monitor
 *   runtime with "Empty list doesn't contain element at index 0." and NO alert written).
 * - A bare doc-count metric (fn 'count', no filter) emits NO sub-agg — the trigger reads the
 *   bucket's own doc count via the reserved `_count` path, and having references to that
 *   metric's alias are rewritten to `params._count`.
 * - Field names arrive PRE-RESOLVED (text → `.keyword`) per the agg_types contract; the
 *   compiler never sees a data view, so producers own that resolution.
 */

/**
 * The composite page size — at most this many groups are evaluated per run (the legacy bucket
 * compiler's cap, kept identical; documented risk R1: high-cardinality group-bys are truncated).
 */
const COMPOSITE_SIZE = 100;

/**
 * The fixed name of the metric agg nested INSIDE a filter agg when a non-count metric carries a
 * sub-filter — addressed in buckets_path as `<alias>.<FILTERED_METRIC_AGG>`. Exported so tests
 * (and any future reader of compiled monitors) pin the exact path shape.
 */
export const FILTERED_METRIC_AGG = 'metric';

/** Re-exported here as the compiler's public validation entry point (defined in internal.ts so
 * assertValidThresholdRule can share it without an import cycle). */
export { validateAggregationSpec } from './internal';

/** HavingExpr comparison op → painless comparator. */
const HAVING_PAINLESS_OP: Record<'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq', string> = {
  gt: '>',
  gte: '>=',
  lt: '<',
  lte: '<=',
  eq: '==',
  neq: '!=',
};

/** Validate everything about a compile input; throws with a clear, user-facing message. */
export function validateAggregationInput(input: AggregationCompileInput): void {
  if (!input || typeof input.name !== 'string' || input.name.trim() === '') {
    throw new Error('Aggregation rule must have a non-empty name.');
  }
  if (typeof input.index !== 'string' || input.index.trim() === '') {
    throw new Error(`Aggregation rule "${input.name}" must specify an index or pattern.`);
  }
  if (!SEVERITY_TO_MONITOR_SEVERITY[input.severity]) {
    throw new Error(`Aggregation rule "${input.name}" has unknown severity "${input.severity}".`);
  }
  if (input.filter !== null && input.filter !== undefined) {
    if (input.filter.kind === 'lucene') {
      if (typeof input.filter.query !== 'string' || input.filter.query.trim() === '') {
        throw new Error(
          `Aggregation rule "${input.name}": a lucene filter must carry a non-empty query.`
        );
      }
    } else if (input.filter.kind === 'dsl') {
      if (!Array.isArray(input.filter.clauses)) {
        throw new Error(
          `Aggregation rule "${input.name}": a dsl filter must carry a clauses array.`
        );
      }
      input.filter.clauses.forEach((clause) => {
        if (!clause || typeof clause !== 'object' || Array.isArray(clause)) {
          throw new Error(
            `Aggregation rule "${input.name}": every dsl filter clause must be an object.`
          );
        }
      });
    } else {
      throw new Error(
        `Aggregation rule "${input.name}": unknown filter kind ` +
          `"${(input.filter as AggFilter).kind}". Supported: lucene, dsl.`
      );
    }
  }
  if (!input.window || !(input.window.value > 0)) {
    throw new Error(`Aggregation rule "${input.name}" must have a positive time window.`);
  }
  if (input.runEvery) {
    if (!(input.runEvery.value > 0 && Number.isInteger(input.runEvery.value))) {
      throw new Error(`Aggregation rule "${input.name}" must have a positive run-every value.`);
    }
    if (windowMinutes(input.runEvery) > windowMinutes(input.window)) {
      throw new Error(
        `Aggregation rule "${input.name}": run-every must not exceed the window — a longer ` +
          'cadence would leave time the rule never evaluates.'
      );
    }
  }
  validateAggregationSpec(input.spec);
}

/** A metric that emits NO sub-agg: the bare per-group doc count (fn 'count', no sub-filter). */
function isBareCount(metric: MetricDef): boolean {
  return metric.fn === 'count' && !metric.filter;
}

/** The `filter` agg body for a metric sub-filter: the proven query_string idiom. */
function filterAggQuery(filter: ConditionGroup): Record<string, unknown> {
  return { query_string: { query: conditionGroupToLucene(filter), analyze_wildcard: true } };
}

/**
 * Lower a HavingExpr tree to the trigger's painless source. `resolve` maps a having alias to its
 * `params.` key ('_count' for bare-count metrics and the reserved alias itself; otherwise the
 * alias verbatim). Compound operands are parenthesized; comparisons are not; the top level is
 * bare — the scanner golden reads `params.a >= 40 && params.b >= 50`.
 */
function havingToPainless(expr: HavingExpr, resolve: (alias: string) => string): string {
  if (expr.kind === 'cmp') {
    return `params.${resolve(expr.alias)} ${HAVING_PAINLESS_OP[expr.op]} ${expr.value}`;
  }
  const joiner = expr.kind === 'and' ? ' && ' : ' || ';
  return expr.operands
    .map((operand) =>
      operand.kind === 'cmp'
        ? havingToPainless(operand, resolve)
        : `(${havingToPainless(operand, resolve)})`
    )
    .join(joiner);
}

/**
 * Compile the shared aggregation IR into a bucket-level Alerting monitor (research_r2 §a shape).
 * Validates first — throws with a user-facing message; a bad spec never reaches the engine
 * (bucket-monitor runtime failures are SILENT: no alert is ever written).
 */
export function compileAggregationRule(input: AggregationCompileInput): BucketLevelMonitor {
  validateAggregationInput(input);
  const window = buildWindow(input.window, input.runEvery);

  // Metric sub-aggs + the buckets_path that provably matches them (the "Empty list" trap).
  // `_count` is ALWAYS present (the bucket's own doc count), exactly like the legacy compiler.
  const metricAggs: Record<string, unknown> = {};
  const bucketsPath: Record<string, string> = { [RESERVED_COUNT_ALIAS]: RESERVED_COUNT_ALIAS };
  for (const metric of input.spec.metrics) {
    if (isBareCount(metric)) {
      // No sub-agg: the trigger reads the composite bucket's own doc_count via `_count`.
      continue;
    }
    if (metric.fn === 'count') {
      // Filtered count: the filter agg's own doc_count IS the metric.
      metricAggs[metric.alias] = { filter: filterAggQuery(metric.filter!) };
      bucketsPath[metric.alias] = `${metric.alias}._count`;
    } else if (metric.filter) {
      // Filtered non-count metric: filter agg wrapping the metric agg, addressed two levels deep.
      metricAggs[metric.alias] = {
        filter: filterAggQuery(metric.filter),
        aggregations: { [FILTERED_METRIC_AGG]: { [metric.fn]: { field: metric.field } } },
      };
      bucketsPath[metric.alias] = `${metric.alias}.${FILTERED_METRIC_AGG}`;
    } else {
      metricAggs[metric.alias] = { [metric.fn]: { field: metric.field } };
      bucketsPath[metric.alias] = metric.alias;
    }
  }

  // Having references to a bare-count metric's alias resolve to the reserved `_count` path;
  // everything else references its own alias (already guaranteed present in bucketsPath).
  const bareCountAliases = new Set(
    input.spec.metrics.filter(isBareCount).map((metric) => metric.alias)
  );
  const resolve = (alias: string) =>
    alias === RESERVED_COUNT_ALIAS || bareCountAliases.has(alias) ? RESERVED_COUNT_ALIAS : alias;
  const painless = havingToPainless(input.spec.having, resolve);

  // The event filter ahead of aggregation: lucene → ONE query_string clause (same shape as the
  // legacy bucket compiler); dsl → ready bool-filter clauses spread verbatim; null → range only.
  const eventFilterClauses: Array<Record<string, unknown>> = [];
  if (input.filter) {
    if (input.filter.kind === 'lucene') {
      eventFilterClauses.push({
        query_string: { query: input.filter.query, analyze_wildcard: true },
      });
    } else {
      eventFilterClauses.push(...(input.filter.clauses as Array<Record<string, unknown>>));
    }
  }

  return {
    type: 'monitor',
    name: input.name,
    monitor_type: 'bucket_level_monitor',
    enabled: true,
    schedule: window.schedule,
    inputs: [
      {
        search: {
          indices: [input.index],
          query: {
            size: 0,
            query: {
              bool: {
                filter: [
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
                  ...eventFilterClauses,
                ],
              },
            },
            aggregations: {
              [GROUPS_AGG]: {
                composite: {
                  size: COMPOSITE_SIZE,
                  sources: input.spec.by.map((field) => ({
                    [compositeSourceName(field)]: {
                      terms: { field, missing_bucket: false },
                    },
                  })),
                },
                ...(Object.keys(metricAggs).length > 0 ? { aggregations: metricAggs } : {}),
              },
            },
          },
        },
      },
    ],
    triggers: [
      {
        bucket_level_trigger: {
          name: `${input.name} threshold breached`,
          severity: SEVERITY_TO_MONITOR_SEVERITY[input.severity],
          condition: {
            parent_bucket_path: GROUPS_AGG,
            buckets_path: bucketsPath,
            script: { source: painless, lang: 'painless' },
          },
        },
      },
    ],
  };
}

/**
 * Build the compiler input for a STATEFUL rule carrying `advanced` metrics — the registry's D4
 * routing helper. The rule's own no-code `filter` becomes the lucene event filter (via the same
 * conditionGroupToLucene the legacy compiler uses), `rule.groupBy` is the AUTHORITATIVE group-by
 * (advanced.by is deliberately ignored — see ThresholdRuleDefinition.advanced), and window /
 * runEvery pass through untouched so buildWindow stays the single window source.
 */
export function thresholdRuleToAggregationInput(
  rule: ThresholdRuleDefinition
): AggregationCompileInput {
  assertValidThresholdRule(rule);
  if (!rule.advanced) {
    throw new Error(
      `Threshold rule "${rule.name}" has no advanced metrics — compile it through ` +
        'compileToBucketLevelMonitor (the legacy count-only path).'
    );
  }
  return {
    name: rule.name,
    severity: rule.severity,
    index: rule.index,
    filter: { kind: 'lucene', query: conditionGroupToLucene(rule.filter) },
    spec: { by: rule.groupBy, metrics: rule.advanced.metrics, having: rule.advanced.having },
    window: rule.window,
    ...(rule.runEvery ? { runEvery: rule.runEvery } : {}),
  };
}
