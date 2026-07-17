/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { RuleDefinition } from './types';
import { SEVERITY_TO_MONITOR_SEVERITY, assertValidRule, slugify } from './internal';
import { conditionGroupToLucene } from './lucene';

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

/** Compile a stateless rule to an OpenSearch doc-level Alerting monitor definition. */
export function compileToDocLevelMonitor(rule: RuleDefinition): DocLevelMonitor {
  assertValidRule(rule);
  const slug = slugify(rule.name);
  const query = conditionGroupToLucene(rule.group);

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
