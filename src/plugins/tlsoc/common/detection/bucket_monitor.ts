/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { ThresholdRuleDefinition } from './types';
import {
  PAINLESS_OP,
  SEVERITY_TO_MONITOR_SEVERITY,
  assertValidThresholdRule,
  compositeSourceName,
} from './internal';
import { buildWindow } from './window';
import { conditionGroupToLucene } from './lucene';

/**
 * Compile a stateful "> N within T" rule to an OpenSearch bucket-level Alerting monitor — the
 * execution path for the stateful differentiator (decision D-008). A composite `terms` aggregation
 * groups events by the rule's group-by field(s) over the time window, and a per-bucket Painless
 * trigger fires for each group whose document count breaches the threshold (`params._count <op> N`).
 *
 * The time window T is taken verbatim from {@link buildWindow}, which is the SINGLE place that derives
 * both the schedule interval and the `@timestamp` range filter — they cannot drift (the window-sync
 * gotcha). The WHERE filter reuses the stateless Lucene compiler ({@link conditionGroupToLucene}).
 */

/** The fixed name of the composite aggregation that the trigger reads buckets from. */
const GROUPS_AGG = 'tlsoc_groups';

export interface BucketLevelMonitor {
  type: 'monitor';
  name: string;
  monitor_type: 'bucket_level_monitor';
  enabled: boolean;
  schedule: { period: { interval: number; unit: string } };
  inputs: Array<{
    search: {
      indices: string[];
      query: {
        size: 0;
        query: { bool: { filter: Array<Record<string, unknown>> } };
        aggregations: Record<string, unknown>;
      };
    };
  }>;
  triggers: Array<{
    bucket_level_trigger: {
      name: string;
      severity: string;
      condition: {
        parent_bucket_path: string;
        buckets_path: Record<string, string>;
        script: { source: string; lang: 'painless' };
      };
    };
  }>;
}

export function compileToBucketLevelMonitor(rule: ThresholdRuleDefinition): BucketLevelMonitor {
  assertValidThresholdRule(rule);
  const window = buildWindow(rule.window, rule.runEvery);
  const filterQuery = conditionGroupToLucene(rule.filter);
  const painless = `params._count ${PAINLESS_OP[rule.threshold.operator]} ${rule.threshold.value}`;

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
                  {
                    query_string: {
                      query: filterQuery,
                      analyze_wildcard: true,
                    },
                  },
                ],
              },
            },
            aggregations: {
              [GROUPS_AGG]: {
                composite: {
                  size: 100,
                  sources: rule.groupBy.map((field) => ({
                    [compositeSourceName(field)]: { terms: { field } },
                  })),
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
          name: `${rule.name} threshold breached`,
          severity: SEVERITY_TO_MONITOR_SEVERITY[rule.severity],
          condition: {
            parent_bucket_path: GROUPS_AGG,
            buckets_path: { _count: '_count' },
            script: { source: painless, lang: 'painless' },
          },
        },
      },
    ],
  };
}
