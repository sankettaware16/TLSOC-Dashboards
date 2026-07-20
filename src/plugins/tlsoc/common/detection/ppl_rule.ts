/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  AggFilter,
  AggregationCompileInput,
  HavingExpr,
  MetricDef,
  MetricFn,
} from './agg_types';
import { assertValidTimeWindowUnit, windowMinutes } from './internal';
import { RuleMetadataFields, Severity, TimeWindow } from './types';
import { MetricAgg, parsePpl, PplHavingExpr, PplRuleAst, WhereExpr } from './ppl_parse';

/**
 * The 'ppl' detection rule IR (v1.2.3 D3) + its lowering into the SHARED aggregation-rule IR
 * (agg_types.ts — the frozen contract both the PPL and the D4 no-code front-ends feed into ONE
 * compiler, compileAggregationRule). `pplText` is stored verbatim: the rule round-trips through
 * edit losslessly, and every compile re-parses it (parse → lower → compile), so a saved rule can
 * never drift from its query.
 *
 * The where→DSL / metric / having mapping below is research_r4.md §3.4 VERBATIM — it reproduces
 * what the 3.7 Calcite engine itself pushes down (explain-verified), including the exists
 * null-guard on `!=`/not-of-a-leaf, ILIKE case-insensitivity for like(), and count() reading the
 * composite bucket's own doc_count via the reserved `_count` buckets_path.
 */

/**
 * Resolves a raw PPL field name to the field the compiled monitor must address — text fields map
 * to their `.keyword` subfield (exactly what Calcite does internally; a monitor compiled without
 * the resolution aggregates on a text field and fails at runtime with NO alert — silent-failure
 * class). Must THROW a user-facing error for fields that cannot be aggregated on.
 */
export type ResolveField = (field: string) => string;

/** A complete PPL detection rule — what the builder saves inside the SO's unmapped `rule` attr. */
export interface PplRuleDefinition extends RuleMetadataFields {
  /** Stable rule id (UUID). Optional; callers may supply one for deterministic output. */
  id?: string;
  name: string;
  description?: string;
  severity: Severity;
  /** The index/pattern the rule runs against — MUST equal the query's `source =` list (joined by ','). */
  index: string;
  /** The PPL query, verbatim — the lossless editing source of truth. Re-parsed at every compile. */
  pplText: string;
  /** The time window T — feeds schedule + the {{period_end}} range filter (window.ts contract). */
  window: TimeWindow;
  /** Optional cadence R; must be <= T (same invariant as threshold rules). */
  runEvery?: TimeWindow;
  /**
   * MUST mirror the query's `by` fields (raw, unresolved, in order) — the alert flyout labels
   * bucket keys from rule.groupBy (R1 risk). The PPL editor keeps this in sync automatically;
   * {@link assertValidPplRule} enforces the invariant.
   */
  groupBy: string[];
  /**
   * Raw-field → monitor-field resolution map captured by the builder from the data view's field
   * caps at save time (e.g. `{"url.path": "url.path.keyword"}`). Only text fields with a keyword
   * subfield need entries; absent fields pass through unchanged. Lets the server re-compile the
   * rule without a data-view lookup.
   */
  fieldMap?: Record<string, string>;
}

/** The default {@link ResolveField} for a saved rule: look up `fieldMap`, else pass through. */
export function makeFieldResolver(rule: PplRuleDefinition): ResolveField {
  const map = rule.fieldMap ?? {};
  return (field: string) =>
    Object.prototype.hasOwnProperty.call(map, field) ? map[field] : field;
}

/**
 * The raw field names a parsed PPL rule uses in STRING-CONTEXT positions — exactly the positions
 * {@link lowerPplToCompileInput} resolves through the fieldMap: `by` group-bys, `dc()` metric
 * arguments, `=`/`!=` term matches, `like` wildcards, and `in` term lists. Ranges, exists-guards,
 * and numeric metric arguments address the raw field and are excluded.
 *
 * This is the ONE enumerator both fieldMap gates share (v1.2.3 W2 review, BLOCKING-1): the
 * builder resolves these fields against the data view's field caps at edit time, and the save
 * route re-derives the same set and verifies the fieldMap against the CLUSTER's field caps —
 * keeping the two layers in lock-step so neither can silently miss a position the other checks.
 */
export function collectPplStringContextFields(ast: PplRuleAst): string[] {
  const raw = new Set<string>();
  ast.by.forEach((f) => raw.add(f.name));
  ast.metrics.forEach((m) => {
    if (m.fn === 'dc' && m.field) raw.add(m.field);
  });
  const walk = (e: WhereExpr): void => {
    switch (e.kind) {
      case 'and':
      case 'or':
        e.operands.forEach(walk);
        return;
      case 'not':
        walk(e.operand);
        return;
      case 'cmp':
        // Only '='/'!=' are string-context (term match); ranges address the raw field.
        if (e.op === '=' || e.op === '!=') raw.add(e.field.name);
        return;
      case 'like':
      case 'in':
        raw.add(e.field.name);
    }
  };
  if (ast.where) walk(ast.where);
  return [...raw];
}

/** Validate a PPL rule before compiling; throws an Error with a clear, user-facing message. */
export function assertValidPplRule(rule: PplRuleDefinition): void {
  if (!rule || typeof rule.name !== 'string' || rule.name.trim() === '') {
    throw new Error('PPL rule must have a non-empty name.');
  }
  if (typeof rule.index !== 'string' || rule.index.trim() === '') {
    throw new Error(`PPL rule "${rule.name}" must specify a data view.`);
  }
  if (typeof rule.pplText !== 'string' || rule.pplText.trim() === '') {
    throw new Error(`PPL rule "${rule.name}" must have a PPL query.`);
  }
  const parsed = parsePpl(rule.pplText);
  if (!parsed.ok) {
    const first = parsed.errors[0];
    throw new Error(
      `PPL rule "${rule.name}" query is invalid — ${first.construct}: ${first.reason}`
    );
  }
  const sourceIndex = parsed.rule.indices.join(',');
  if (sourceIndex !== rule.index) {
    throw new Error(
      `PPL rule "${rule.name}": the rule index ("${rule.index}") must match the query's ` +
        `source ("${sourceIndex}").`
    );
  }
  const by = parsed.rule.by.map((f) => f.name);
  if (by.length === 0) {
    throw new Error(
      `PPL rule "${rule.name}" must group by at least one field — add "by <field>" to the stats command.`
    );
  }
  const groupBy = Array.isArray(rule.groupBy) ? rule.groupBy : [];
  if (by.length !== groupBy.length || by.some((b, i) => b !== groupBy[i])) {
    throw new Error(
      `PPL rule "${rule.name}": groupBy must mirror the query's "by" fields (${by.join(', ')}) — ` +
        'the alert flyout labels group keys from it.'
    );
  }
  if (!rule.window || !(rule.window.value > 0)) {
    throw new Error(`PPL rule "${rule.name}" must have a positive time window.`);
  }
  assertValidTimeWindowUnit(rule.window, 'time window', `PPL rule "${rule.name}"`);
  if (rule.runEvery) {
    if (!(rule.runEvery.value > 0 && Number.isInteger(rule.runEvery.value))) {
      throw new Error(`PPL rule "${rule.name}" must have a positive run-every value.`);
    }
    // Unit membership BEFORE the R ≤ T comparison — windowMinutes NaNs on a bad unit, and
    // NaN > x is false, so the comparison alone would silently accept it.
    assertValidTimeWindowUnit(rule.runEvery, 'run-every', `PPL rule "${rule.name}"`);
    if (windowMinutes(rule.runEvery) > windowMinutes(rule.window)) {
      throw new Error(
        `PPL rule "${rule.name}": run-every must not exceed the rule window — a longer cadence ` +
          'would leave time the rule never evaluates.'
      );
    }
  }
}

/**
 * Parse + validate + lower in one step — the registry `compile` entry point composes this with
 * compileAggregationRule. `resolveField` defaults to the rule's own saved {@link fieldMap}.
 */
export function pplRuleToCompileInput(
  rule: PplRuleDefinition,
  resolveField?: ResolveField
): AggregationCompileInput {
  assertValidPplRule(rule);
  const parsed = parsePpl(rule.pplText);
  if (!parsed.ok) {
    // Unreachable after assertValidPplRule — kept for type narrowing and defense in depth.
    throw new Error(`PPL rule "${rule.name}" query is invalid.`);
  }
  return lowerPplToCompileInput(parsed.rule, rule, resolveField ?? makeFieldResolver(rule));
}

/** research_r4.md §3.4 having op → agg_types HavingExpr op (painless emission happens in the compiler). */
const HAVING_OP_MAP: Record<
  '>' | '>=' | '<' | '<=' | '=' | '!=',
  'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq'
> = {
  '>': 'gt',
  '>=': 'gte',
  '<': 'lt',
  '<=': 'lte',
  '=': 'eq',
  '!=': 'neq',
};

const RANGE_OP_MAP: Record<'>' | '>=' | '<' | '<=', 'gt' | 'gte' | 'lt' | 'lte'> = {
  '>': 'gt',
  '>=': 'gte',
  '<': 'lt',
  '<=': 'lte',
};

/** PPL `like` pattern → OpenSearch wildcard pattern: `%` → `*`, `_` → `?`, all else literal. */
export function likePatternToWildcard(pattern: string): string {
  return pattern
    .split('')
    .map((ch) => (ch === '%' ? '*' : ch === '_' ? '?' : ch))
    .join('');
}

/**
 * Lower a parsed PPL AST + its rule envelope into the frozen {@link AggregationCompileInput}.
 *
 * Field-resolution positions (R4 §3.4 — only string-context positions resolve; ranges and
 * numeric metric args address the raw field, and the `!=`/not exists-guard uses the RAW field
 * exactly as Calcite pushes it down):
 * - resolved: `=` / `!=` term, like wildcard, in terms, `by` sources, dc (cardinality)
 * - raw: range fields, exists guards, count(field) (value_count), sum/avg/min/max
 */
export function lowerPplToCompileInput(
  ast: PplRuleAst,
  rule: PplRuleDefinition,
  resolveField: ResolveField
): AggregationCompileInput {
  if (ast.by.length === 0) {
    throw new Error(
      `PPL rule "${rule.name}" must group by at least one field — add "by <field>" to the stats command.`
    );
  }
  const by = ast.by.map((f) => resolveField(f.name));

  // Metrics: bare count() is NOT a sub-agg (the trigger reads the composite bucket's own
  // doc_count via the reserved '_count' buckets_path key — agg_types contract note).
  const userAliases = new Set<string>();
  ast.metrics.forEach((m) => {
    if (m.alias !== null) {
      userAliases.add(m.alias);
    }
  });
  const metrics: MetricDef[] = [];
  const aliasToBucketsKey = new Map<string, string>();
  ast.metrics.forEach((m, i) => {
    if (m.fn === 'count' && m.field === null) {
      if (m.alias !== null) {
        aliasToBucketsKey.set(m.alias, '_count');
      }
      return;
    }
    let alias = m.alias;
    if (alias === null) {
      // Unaliased metrics cannot be referenced in the threshold (parse-enforced) but still need
      // a deterministic agg name. Positional, de-collided against user aliases.
      alias = `m${i}`;
      while (userAliases.has(alias) || metrics.some((d) => d.alias === alias)) {
        alias += '_';
      }
    }
    metrics.push({ alias, fn: metricFn(m), field: metricField(m, resolveField) });
    if (m.alias !== null) {
      aliasToBucketsKey.set(m.alias, alias);
    }
  });

  const having: HavingExpr = ast.having
    ? lowerHaving(ast.having, aliasToBucketsKey, rule.name)
    : // No post-stats where: fire for every group with >= 1 matching event (parse warns).
      { kind: 'cmp', alias: '_count', op: 'gt', value: 0 };

  let filter: AggFilter | null = null;
  if (ast.where !== null) {
    const clauses =
      ast.where.kind === 'and'
        ? ast.where.operands.map((e) => compileWhereExpr(e, resolveField))
        : [compileWhereExpr(ast.where, resolveField)];
    filter = { kind: 'dsl', clauses };
  }

  const out: AggregationCompileInput = {
    name: rule.name,
    severity: rule.severity,
    index: rule.index,
    filter,
    spec: { by, metrics, having },
    window: rule.window,
  };
  if (rule.runEvery) {
    out.runEvery = rule.runEvery;
  }
  return out;
}

function metricFn(m: MetricAgg): MetricFn {
  if (m.fn === 'count') {
    return 'value_count'; // count(field) — bare count() never reaches here
  }
  if (m.fn === 'dc') {
    return 'cardinality';
  }
  return m.fn;
}

function metricField(m: MetricAgg, resolveField: ResolveField): string {
  const field = m.field as string; // non-null for every non-bare-count metric (parse-enforced)
  // Only cardinality is a string-context agg (keyword resolution); value_count/sum/avg/min/max
  // address the raw field (numeric validation is the resolver/producer's concern).
  return m.fn === 'dc' ? resolveField(field) : field;
}

function lowerHaving(
  expr: PplHavingExpr,
  aliasToBucketsKey: Map<string, string>,
  ruleName: string
): HavingExpr {
  if (expr.kind === 'cmp') {
    const key = aliasToBucketsKey.get(expr.metricAlias);
    if (key === undefined) {
      // Parse guarantees membership; defensive for hand-built ASTs.
      throw new Error(
        `PPL rule "${ruleName}": threshold references unknown metric alias "${expr.metricAlias}".`
      );
    }
    return { kind: 'cmp', alias: key, op: HAVING_OP_MAP[expr.op], value: expr.value };
  }
  return {
    kind: expr.kind,
    operands: expr.operands.map((o) => lowerHaving(o, aliasToBucketsKey, ruleName)),
  };
}

/**
 * One where-expression → one bool-filter clause (research_r4.md §3.4, explain-verified shapes).
 */
function compileWhereExpr(
  expr: WhereExpr,
  resolveField: ResolveField
): Record<string, unknown> {
  switch (expr.kind) {
    case 'and':
      return { bool: { filter: expr.operands.map((e) => compileWhereExpr(e, resolveField)) } };
    case 'or':
      return {
        bool: {
          should: expr.operands.map((e) => compileWhereExpr(e, resolveField)),
          minimum_should_match: 1,
        },
      };
    case 'not': {
      const leafField = leafFieldOf(expr.operand);
      const inner = compileWhereExpr(expr.operand, resolveField);
      if (leafField !== null) {
        // not-of-a-leaf carries the exists null-guard (Calcite parity — R4 §2): docs missing
        // the field are EXCLUDED, matching what the preview shows on sparse fields.
        return { bool: { must: [{ exists: { field: leafField } }], must_not: [inner] } };
      }
      // Compound not: plain must_not (compound-not null semantics unverified on engine — R4 risk).
      return { bool: { must_not: [inner] } };
    }
    case 'cmp': {
      if (expr.op === '=') {
        return { term: { [resolveField(expr.field.name)]: expr.value } };
      }
      if (expr.op === '!=') {
        return {
          bool: {
            must: [{ exists: { field: expr.field.name } }],
            must_not: [{ term: { [resolveField(expr.field.name)]: expr.value } }],
          },
        };
      }
      return { range: { [expr.field.name]: { [RANGE_OP_MAP[expr.op]]: expr.value } } };
    }
    case 'like':
      return {
        wildcard: {
          [resolveField(expr.field.name)]: {
            wildcard: likePatternToWildcard(expr.pattern),
            case_insensitive: true, // PPL like() is ILIKE in 3.7 (live-verified)
          },
        },
      };
    case 'in':
      return { terms: { [resolveField(expr.field.name)]: expr.values } };
  }
}

function leafFieldOf(expr: WhereExpr): string | null {
  if (expr.kind === 'cmp' || expr.kind === 'like' || expr.kind === 'in') {
    return expr.field.name;
  }
  return null;
}
