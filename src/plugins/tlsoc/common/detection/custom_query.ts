/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { RuleMetadataFields, Severity, SuppressionConfig, TimeWindow } from './types';
import {
  SEVERITY_TO_MONITOR_SEVERITY,
  assertValidSuppression,
  assertValidTimeWindowUnit,
  slugify,
} from './internal';
import { DocLevelMonitor } from './monitor';
import { BucketLevelMonitor } from './bucket_monitor';
import { compileAggregationRule } from './agg_compile';
import {
  applyExceptionsToLucene,
  exceptionsToFilterClause,
  validateExceptions,
} from './exceptions';
import { formatDqlTranslationErrors, translateDqlToLucene } from './dql_to_lucene';

/**
 * The D2 custom-query rule (v1.2.3): the analyst writes the match as a QUERY — Lucene or DQL —
 * instead of no-code condition rows. It executes EXACTLY like a stateless rule: a doc-level
 * Alerting monitor (findings + related_doc_ids + per-event alerts — the enrichment lifecycle a
 * query-level monitor would forfeit, research_r3 §2). Lucene rides as a validated passthrough
 * (the fork's own `luceneStringToDsl` precedent); DQL goes through the clean-room subset
 * translator in dql_to_lucene.ts, whose rejections this compiler re-throws VERBATIM.
 *
 * The rule IR stores `{ language, queryText }` — the ORIGINAL text, never the translation — so
 * edit round-trips are lossless (OpenSearch Alerting strips ui_metadata on persist; the
 * tlsoc-detection-rule saved object is the source of truth, research_r3 RISKS).
 *
 * Monitor emission mirrors compileToDocLevelMonitor byte-for-byte (same schedule default, same
 * queries[] shape, same `query[name=<slug>]` trigger — the OpenSearch 3.7 hard requirement);
 * custom_query.test.ts pins the two outputs against each other so they can never drift.
 */

export type CustomQueryLanguage = 'lucene' | 'kuery';

/** A complete custom-query detection rule — the builder's output and this compiler's input. */
export interface CustomQueryRuleDefinition extends RuleMetadataFields {
  /** Stable rule id (UUID). Optional; callers may supply one for deterministic output. */
  id?: string;
  name: string;
  description?: string;
  severity: Severity;
  /** The index / data-view pattern the rule runs against, e.g. 'fosstlsoc-logs-*'. */
  index: string;
  /** The query language `queryText` is written in. 'kuery' is DQL. */
  language: CustomQueryLanguage;
  /** The original query text, verbatim — stored for lossless edit; compiled only at save. */
  queryText: string;
  /** Optional schedule cadence R. Absent = the legacy 1-minute doc-level default. */
  runEvery?: TimeWindow;
  /**
   * OPTIONAL alert suppression (v1.2.3 D9). ABSENT = the legacy doc-level compile path —
   * byte-identical output. PRESENT = the rule compiles through
   * {@link compileSuppressedCustomQueryToBucketMonitor} to a bucket-level monitor instead
   * (see SuppressionConfig in types.ts for semantics and the enrichment trade-off).
   */
  suppression?: SuppressionConfig;
  /**
   * Suppressed rules only: MUST mirror `suppression.groupBy` (validated when both are present).
   * The alerts join reads `rule.groupBy` to label bucket keys in the flyout — the builder
   * stamps it automatically alongside `suppression`.
   */
  groupBy?: string[];
}

/**
 * The Lucene `query_string` this rule executes as: trimmed passthrough for 'lucene', the subset
 * translation for 'kuery'. Throws the translator's rejection message VERBATIM (one line per
 * rejected construct) so the builder, the save route, and the compile goldens all surface the
 * exact same words.
 */
export function compileCustomQueryText(rule: CustomQueryRuleDefinition): string {
  if (rule.language === 'lucene') {
    // Passthrough (doc-level queries accept full Lucene, live-verified research_r3 §2) — trimmed
    // only, never rewritten. Validation against the cluster is the _validate route's job: the
    // engine itself NEVER validates doc-level queries (silent-failure class, research_r2 §b).
    return rule.queryText.trim();
  }
  const translated = translateDqlToLucene(rule.queryText);
  if (!translated.ok) {
    throw new Error(formatDqlTranslationErrors(translated.errors));
  }
  return translated.lucene;
}

/** Validate a custom-query rule before compiling; throws with a clear, user-facing message. */
export function assertValidCustomQueryRule(rule: CustomQueryRuleDefinition): void {
  if (!rule || typeof rule.name !== 'string' || rule.name.trim() === '') {
    throw new Error('Custom-query rule must have a non-empty name.');
  }
  if (typeof rule.index !== 'string' || rule.index.trim() === '') {
    throw new Error(`Custom-query rule "${rule.name}" must specify a data view.`);
  }
  if (rule.language !== 'lucene' && rule.language !== 'kuery') {
    throw new Error(
      `Custom-query rule "${rule.name}" has an unsupported query language "${String(
        (rule as { language?: unknown }).language
      )}". Supported: lucene, kuery.`
    );
  }
  if (typeof rule.queryText !== 'string' || rule.queryText.trim() === '') {
    throw new Error(`Custom-query rule "${rule.name}" must have a non-empty query.`);
  }
  // A bad severity would silently emit `severity: undefined` + a broken tag — the silent-failure
  // class this release bans. (The no-code builders constrain severity in the UI; a custom-query
  // rule can arrive via the API, so the compiler checks.)
  if (!Object.prototype.hasOwnProperty.call(SEVERITY_TO_MONITOR_SEVERITY, rule.severity)) {
    throw new Error(
      `Custom-query rule "${rule.name}" has an unknown severity "${String(rule.severity)}".`
    );
  }
  if (rule.runEvery) {
    if (!(rule.runEvery.value > 0 && Number.isInteger(rule.runEvery.value))) {
      throw new Error(`Custom-query rule "${rule.name}" must have a positive run-every value.`);
    }
    assertValidTimeWindowUnit(rule.runEvery, 'run-every', `Custom-query rule "${rule.name}"`);
  }
  // v1.2.3 D9 (both additive — a rule WITHOUT them validates exactly as before):
  if (rule.exceptions !== undefined) {
    validateExceptions(rule.exceptions, `Custom-query rule "${rule.name}"`);
  }
  if (rule.suppression !== undefined) {
    assertValidSuppression(rule.suppression, `Custom-query rule "${rule.name}"`);
    if (
      rule.groupBy !== undefined &&
      (rule.groupBy.length !== rule.suppression.groupBy.length ||
        rule.groupBy.some((f, i) => f !== rule.suppression!.groupBy[i]))
    ) {
      throw new Error(
        `Custom-query rule "${rule.name}": groupBy must mirror suppression.groupBy ` +
          `(${rule.suppression.groupBy.join(', ')}) — the alert flyout labels group keys from it.`
      );
    }
  }
  // For DQL, a rule that cannot translate must never validate: surface the translator's
  // rejection here so the registry's validate() catches everything compile would throw.
  if (rule.language === 'kuery') {
    compileCustomQueryText(rule);
  }
}

/** Compile a custom-query rule to an OpenSearch doc-level Alerting monitor definition.
 * v1.2.3 D9: a rule WITH `suppression` is REFUSED by name (it compiles through
 * {@link compileSuppressedCustomQueryToBucketMonitor} instead — the monitor.ts twin's idiom);
 * exceptions append the ` AND NOT (…)` fragment to the executed query. The save route
 * (assertCustomQueryValidates) validates the FULL executed string — compileCustomQueryText's
 * output WITH the exceptions fragment applied — against the cluster before any monitor exists. */
export function compileCustomQueryToMonitor(rule: CustomQueryRuleDefinition): DocLevelMonitor {
  assertValidCustomQueryRule(rule);
  if (rule.suppression) {
    throw new Error(
      `Custom-query rule "${rule.name}" carries suppression — it compiles to a grouped ` +
        '(bucket-level) monitor via compileSuppressedCustomQueryToBucketMonitor, never to a ' +
        'doc-level monitor (doc-level monitors have no per-field suppression primitive).'
    );
  }
  const slug = slugify(rule.name);
  const query = applyExceptionsToLucene(compileCustomQueryText(rule), rule.exceptions);

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
          // Doc-level trigger conditions reference the matching query by name — `query[name=<slug>]`
          // fires the trigger for every doc the query matched. (The OpenSearch 3.7 hard requirement;
          // see compileToDocLevelMonitor in monitor.ts, the emission twin this mirrors.)
          condition: { script: { source: `query[name=${slug}]`, lang: 'painless' } },
        },
      },
    ],
  };
}

/**
 * v1.2.3 D9: compile a SUPPRESSED custom-query rule to the bucket-level monitor that executes
 * it — the monitor.ts conversion's exact twin: the rule's query (for 'kuery', the TRANSLATED
 * Lucene — compileCustomQueryText) becomes the aggregation filter's query_string, exceptions
 * ride as the shared `{bool: {must_not}}` clause (structured — never folded into the Lucene, so
 * CIDR exceptions stay in engine-proven term form on the bucket side), `suppression.groupBy` /
 * `suppression.window` shape the composite + window, trigger `_count >= 1`. One alert per group
 * per window; the alert loses per-doc findings/related docs — it carries the group keys instead.
 */
export function compileSuppressedCustomQueryToBucketMonitor(
  rule: CustomQueryRuleDefinition
): BucketLevelMonitor {
  assertValidCustomQueryRule(rule);
  if (!rule.suppression) {
    throw new Error(
      `Custom-query rule "${rule.name}" has no suppression — compile it through ` +
        'compileCustomQueryToMonitor (the doc-level path).'
    );
  }
  const clauses: Array<Record<string, unknown>> = [
    { query_string: { query: compileCustomQueryText(rule), analyze_wildcard: true } },
  ];
  const exceptionClause = exceptionsToFilterClause(rule.exceptions);
  if (exceptionClause) {
    clauses.push(exceptionClause);
  }
  const monitor = compileAggregationRule({
    name: rule.name,
    severity: rule.severity,
    index: rule.index,
    filter: { kind: 'dsl', clauses },
    spec: {
      by: rule.suppression.groupBy,
      metrics: [],
      having: { kind: 'cmp', alias: '_count', op: 'gte', value: 1 },
    },
    window: rule.suppression.window,
    ...(rule.runEvery ? { runEvery: rule.runEvery } : {}),
  });
  // Cosmetic override ONLY (the new_terms precedent) — the condition is untouched.
  monitor.triggers[0].bucket_level_trigger.name = `${rule.name} matched`;
  return monitor;
}
