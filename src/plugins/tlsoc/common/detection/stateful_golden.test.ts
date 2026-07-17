/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { compileToBucketLevelMonitor } from './index';
import { ThresholdRuleDefinition } from './types';

/**
 * Golden, realistic stateful detections. Each asserts the FULL compiled bucket-level monitor for a
 * real "> N within T grouped by …" rule, and that the schedule and @timestamp range encode the same T.
 */
describe('golden: realistic stateful "> N within T" detections compile to bucket-level monitors', () => {
  it('1. > 10 failed SSH logins from one source IP within 5 minutes (single group-by)', () => {
    const rule: ThresholdRuleDefinition = {
      name: 'Brute force: over 10 failed SSH logins from one source IP in 5 minutes',
      description: 'A single source IP failing SSH authentication more than 10 times in 5 minutes.',
      severity: 'high',
      index: 'fosstlsoc-logs-*',
      filter: {
        logic: 'AND',
        conditions: [
          { field: 'event.outcome', operator: 'equals', value: 'failure' },
          { field: 'event.module', operator: 'equals', value: 'ssh' },
        ],
      },
      groupBy: ['source.ip'],
      window: { value: 5, unit: 'MINUTES' },
      threshold: { operator: 'gt', value: 10 },
    };

    expect(compileToBucketLevelMonitor(rule)).toEqual({
      type: 'monitor',
      name: 'Brute force: over 10 failed SSH logins from one source IP in 5 minutes',
      monitor_type: 'bucket_level_monitor',
      enabled: true,
      schedule: { period: { interval: 5, unit: 'MINUTES' } },
      inputs: [
        {
          search: {
            indices: ['fosstlsoc-logs-*'],
            query: {
              size: 0,
              query: {
                bool: {
                  filter: [
                    {
                      range: {
                        '@timestamp': {
                          from: '{{period_end}}||-5m',
                          to: '{{period_end}}',
                          include_lower: true,
                          include_upper: true,
                          format: 'epoch_millis',
                        },
                      },
                    },
                    {
                      query_string: {
                        query: '(event.outcome:"failure") AND (event.module:"ssh")',
                        analyze_wildcard: true,
                      },
                    },
                  ],
                },
              },
              aggregations: {
                tlsoc_groups: {
                  composite: {
                    size: 100,
                    sources: [{ source_ip: { terms: { field: 'source.ip' } } }],
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
            name: 'Brute force: over 10 failed SSH logins from one source IP in 5 minutes threshold breached',
            severity: '2',
            condition: {
              parent_bucket_path: 'tlsoc_groups',
              buckets_path: { _count: '_count' },
              script: { source: 'params._count > 10', lang: 'painless' },
            },
          },
        },
      ],
    });
  });

  it('2. > 100 requests from one source IP to one URL path within 1 minute (multi group-by, exists filter)', () => {
    const rule: ThresholdRuleDefinition = {
      name: 'Request flood: over 100 requests from one IP to one path in 1 minute',
      severity: 'medium',
      index: 'fosstlsoc-logs-reverse-proxy-*',
      filter: {
        logic: 'AND',
        conditions: [{ field: 'http.request.method', operator: 'exists' }],
      },
      groupBy: ['source.ip', 'url.path'],
      window: { value: 1, unit: 'MINUTES' },
      threshold: { operator: 'gt', value: 100 },
    };

    const monitor = compileToBucketLevelMonitor(rule);

    // schedule ⇄ range window-sync
    expect(monitor.schedule.period).toEqual({ interval: 1, unit: 'MINUTES' });
    expect(
      (monitor.inputs[0].search.query.query.bool.filter[0] as any).range['@timestamp'].from
    ).toBe('{{period_end}}||-1m');

    // multi group-by composite sources
    expect((monitor.inputs[0].search.query.aggregations as any).tlsoc_groups.composite.sources).toEqual([
      { source_ip: { terms: { field: 'source.ip' } } },
      { url_path: { terms: { field: 'url.path' } } },
    ]);

    // exists filter → _exists_ query_string; threshold + severity
    expect((monitor.inputs[0].search.query.query.bool.filter[1] as any).query_string.query).toBe(
      '_exists_:http.request.method'
    );
    expect(monitor.triggers[0].bucket_level_trigger.condition.script.source).toBe(
      'params._count > 100'
    );
    expect(monitor.triggers[0].bucket_level_trigger.severity).toBe('3');
  });

  it('3. > 5 web attack signature hits in a request URL from one source IP within 5 minutes (contains on an analyzed text field, PROB-4)', () => {
    // The bucket path funnels through the SAME conditionGroupToLucene as the doc-level path
    // (lucene.ts), but had no golden coverage for `contains` on an analyzed text field — this closes
    // that gap. url.query carries fieldType 'match_only_text' (as it would in a real web-log data
    // view), so `contains` must compile to a quoted phrase, not the substring wildcard that silently
    // matches nothing for multi-word values on an analyzed field.
    const rule: ThresholdRuleDefinition = {
      name: 'Repeated web attack signature hits from one source IP in 5 minutes',
      description: 'A single source IP repeatedly sending a SQL-injection-style query string.',
      severity: 'critical',
      index: 'fosstlsoc-logs-reverse-proxy-*',
      filter: {
        logic: 'AND',
        conditions: [
          {
            field: 'url.query',
            operator: 'contains',
            value: 'union select',
            fieldType: 'match_only_text',
          },
        ],
      },
      groupBy: ['source.ip'],
      window: { value: 5, unit: 'MINUTES' },
      threshold: { operator: 'gt', value: 5 },
    };

    expect(compileToBucketLevelMonitor(rule)).toEqual({
      type: 'monitor',
      name: 'Repeated web attack signature hits from one source IP in 5 minutes',
      monitor_type: 'bucket_level_monitor',
      enabled: true,
      schedule: { period: { interval: 5, unit: 'MINUTES' } },
      inputs: [
        {
          search: {
            indices: ['fosstlsoc-logs-reverse-proxy-*'],
            query: {
              size: 0,
              query: {
                bool: {
                  filter: [
                    {
                      range: {
                        '@timestamp': {
                          from: '{{period_end}}||-5m',
                          to: '{{period_end}}',
                          include_lower: true,
                          include_upper: true,
                          format: 'epoch_millis',
                        },
                      },
                    },
                    {
                      query_string: {
                        query: 'url.query:"union select"',
                        analyze_wildcard: true,
                      },
                    },
                  ],
                },
              },
              aggregations: {
                tlsoc_groups: {
                  composite: {
                    size: 100,
                    sources: [{ source_ip: { terms: { field: 'source.ip' } } }],
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
            name: 'Repeated web attack signature hits from one source IP in 5 minutes threshold breached',
            severity: '1',
            condition: {
              parent_bucket_path: 'tlsoc_groups',
              buckets_path: { _count: '_count' },
              script: { source: 'params._count > 5', lang: 'painless' },
            },
          },
        },
      ],
    });
  });
});
