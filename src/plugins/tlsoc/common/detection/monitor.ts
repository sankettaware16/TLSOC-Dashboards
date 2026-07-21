/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { RuleDefinition } from './types';
import { SEVERITY_TO_MONITOR_SEVERITY, assertValidRule, slugify } from './internal';
import { conditionGroupToLucene } from './lucene';
import { applyExceptionsToLucene, exceptionsToFilterClause } from './exceptions';
import { compileAggregationRule } from './agg_compile';
import { BucketLevelMonitor } from './bucket_monitor';

/**
 * Compile the detection IR to an OpenSearch doc-level Alerting monitor — the artifact that actually
 * runs the stateless rule (decision D-008). A doc-level monitor matches each newly indexed document
 * against a `query_string` and produces a finding per match. The "> N within T" stateful case is a
 * bucket-level monitor (a separate compiler, Task 3.2) and is intentionally out of scope here.
 */

export interface DocLevelQuery {
  id: string;
  name: string;
  query: string;
  tags: string[];
}

export interface DocLevelMonitor {
  type: 'monitor';
  name: string;
  monitor_type: 'doc_level_monitor';
  enabled: boolean;
  schedule: { period: { interval: number; unit: string } };
  inputs: Array<{
    doc_level_input: {
      description: string;
      indices: string[];
      queries: DocLevelQuery[];
    };
  }>;
  triggers: Array<{
    document_level_trigger: {
      name: string;
      severity: string;
      condition: { script: { source: string; lang: 'painless' } };
    };
  }>;
}

/** Compile a stateless rule to an OpenSearch doc-level Alerting monitor definition.
 * v1.2.3 D9: a rule WITH `suppression` never compiles doc-level — it is REFUSED by name here
 * (the thresholdRuleToAggregationInput idiom) and compiles through
 * {@link compileSuppressedStatelessToBucketMonitor} instead; silently ignoring the field would
 * be the banned silent-failure class. Exceptions append the ` AND NOT (…)` fragment to the
 * query; a rule without them compiles byte-identically (golden-pinned). */
export function compileToDocLevelMonitor(rule: RuleDefinition): DocLevelMonitor {
  assertValidRule(rule);
  if (rule.suppression) {
    throw new Error(
      `Detection rule "${rule.name}" carries suppression — it compiles to a grouped ` +
        '(bucket-level) monitor via compileSuppressedStatelessToBucketMonitor, never to a ' +
        'doc-level monitor (doc-level monitors have no per-field suppression primitive).'
    );
  }
  const slug = slugify(rule.name);
  const query = applyExceptionsToLucene(conditionGroupToLucene(rule.group), rule.exceptions);

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
          // Doc-level trigger conditions reference the matching query by name (NOT a bare painless
          // boolean — `source:'true'` errors at execution: "Error while processing the trigger
          // expression 'true'", producing zero triggered docs). `query[name=<slug>]` fires the
          // trigger for every doc the query matched. (Verified live against OpenSearch 3.7 Alerting.)
          condition: { script: { source: `query[name=${slug}]`, lang: 'painless' } },
        },
      },
    ],
  };
}

/**
 * v1.2.3 D9: compile a SUPPRESSED stateless rule to the bucket-level monitor that executes it —
 * the honest doc→bucket conversion (research_r2 §e): the rule's match becomes the aggregation
 * filter, `suppression.groupBy` the composite group-by, `suppression.window` the window, trigger
 * `_count >= 1` — ONE alert per group per window, deduplicated by the engine's per-bucket-key
 * alert lifecycle. TRADE-OFF (stated verbatim in the builder): the alert loses per-doc
 * findings/related docs — it carries the group keys instead.
 *
 * Emission goes through {@link compileAggregationRule} (the ONE bucket compiler — the new_terms
 * discipline): the match rides as a `dsl` query_string clause, exceptions as the shared
 * `{bool: {must_not}}` clause, so composite shape / GROUPS_AGG naming / window idiom are all
 * inherited. The ONLY post-compile override is the trigger's display NAME ("threshold breached"
 * would mislead on a single-event rule); the condition stays compiler-emitted, untouched.
 */
export function compileSuppressedStatelessToBucketMonitor(
  rule: RuleDefinition
): BucketLevelMonitor {
  assertValidRule(rule);
  if (!rule.suppression) {
    throw new Error(
      `Detection rule "${rule.name}" has no suppression — compile it through ` +
        'compileToDocLevelMonitor (the doc-level path).'
    );
  }
  const clauses: Array<Record<string, unknown>> = [
    { query_string: { query: conditionGroupToLucene(rule.group), analyze_wildcard: true } },
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
      // Any group with at least one matching event in the window = one alert.
      having: { kind: 'cmp', alias: '_count', op: 'gte', value: 1 },
    },
    window: rule.suppression.window,
    ...(rule.runEvery ? { runEvery: rule.runEvery } : {}),
  });
  // Cosmetic override ONLY (the new_terms precedent): keep the doc-level trigger copy so the
  // alert reads as a match, not a threshold breach. The condition is untouched.
  monitor.triggers[0].bucket_level_trigger.name = `${rule.name} matched`;
  return monitor;
}
