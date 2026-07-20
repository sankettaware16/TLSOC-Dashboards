/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The shared aggregation-rule IR — the single contract both v1.2.3 front-ends lower to:
 * the no-code enhanced-threshold form (D4) and the PPL text editor (D3). One compiler
 * (`compileAggregationRule` in agg_compile.ts) turns this into a bucket-level Alerting
 * monitor shaped exactly like the live-proven scanner monitor
 * (research_r2 §a, validated against a live engine): composite sources per group-by field,
 * cardinality/value_count/sum/avg/min/max (+ filter-wrapped count) sub-aggs, and a
 * bucket_selector-style trigger whose painless script references `params.<alias>`.
 *
 * CONTRACT NOTES (binding on every producer and the compiler):
 * - Field names in `by`, `MetricDef.field`, and DSL filter clauses arrive PRE-RESOLVED:
 *   the front-end maps analyzed text fields to their `.keyword` subfield via the data
 *   view's field caps before building this IR (cardinality/terms on a text field fails at
 *   monitor runtime with NO alert written — silent-failure class, research_r2 §a).
 * - `alias` doubles as the buckets_path key and the painless `params.<alias>` reference:
 *   lowercase [a-z0-9_], must not collide with the reserved `_count`.
 * - A bare doc-count metric (fn 'count', no field, no filter) is NOT emitted as a sub-agg:
 *   the trigger reads the composite bucket's own doc_count via buckets_path `_count`.
 * - A `filter`-wrapped metric is addressed as `<alias>._count` in buckets_path.
 * - The compiler consumes buildWindow() output verbatim (window-sync invariant, window.ts).
 */

import { ConditionGroup, TimeWindow } from './types';

/** Aggregation functions the v1.2.3 subset supports (PPL: count/c, dc/distinct_count, sum, avg, min, max). */
export type MetricFn = 'count' | 'value_count' | 'cardinality' | 'sum' | 'avg' | 'min' | 'max';

export interface MetricDef {
  /** buckets_path key + `params.<alias>` in the trigger script; lowercase [a-z0-9_]; never '_count'. */
  alias: string;
  fn: MetricFn;
  /** Required for every fn except 'count'. Pre-resolved (see contract notes). */
  field?: string;
  /**
   * Optional sub-filter: the metric counts/aggregates only docs matching it (compiled as a
   * `filter` agg wrapping the metric — the scanner's "errors where status>=400" leg).
   * For fn 'count' with a filter, the filter agg's own doc_count IS the metric.
   */
  filter?: ConditionGroup;
}

/** Threshold condition tree evaluated in the bucket trigger's painless script. */
export type HavingExpr =
  | { kind: 'and' | 'or'; operands: HavingExpr[] }
  | { kind: 'cmp'; alias: string; op: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq'; value: number };

/** The aggregation body shared by every bucket-shaped v1.2.3 rule. */
export interface AggregationSpec {
  /** Group-by fields → composite sources, in order. Pre-resolved. May not be empty in v1.2.3. */
  by: string[];
  /** Extra metrics beyond the bucket doc count. May be empty (plain count-threshold rules). */
  metrics: MetricDef[];
  /** The trigger condition. `alias` references a MetricDef.alias or the reserved '_count'. */
  having: HavingExpr;
}

/**
 * The event filter applied before aggregation. Two shapes because the two front-ends
 * produce different filter languages natively:
 * - 'lucene': a query_string (the no-code ConditionGroup path via conditionGroupToLucene).
 * - 'dsl': ready bool-filter clauses (the PPL where-expression mapping — term/range/
 *   wildcard/terms/bool per research_r4 §3.4, null-guards included by the producer).
 */
export type AggFilter =
  | { kind: 'lucene'; query: string }
  | { kind: 'dsl'; clauses: object[] };

/** Everything compileAggregationRule needs. Producers fill it; the compiler adds nothing. */
export interface AggregationCompileInput {
  name: string;
  severity: import('./types').Severity;
  /** Index/pattern string exactly as the monitor input expects it (bucket monitors accept patterns). */
  index: string;
  /** null = no event filter (window range only). */
  filter: AggFilter | null;
  spec: AggregationSpec;
  window: TimeWindow;
  runEvery?: TimeWindow;
}
