/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  FILTERED_METRIC_AGG,
  compileAggregationRule,
  thresholdRuleToAggregationInput,
  validateAggregationSpec,
} from './agg_compile';
import { AggregationCompileInput, AggregationSpec, HavingExpr, MetricFn } from './agg_types';
import { compileToBucketLevelMonitor } from './bucket_monitor';
import { assertValidThresholdRule } from './internal';
import { conditionGroupToLucene } from './lucene';
import { getType } from './registry';
import { ThresholdRuleDefinition } from './types';

/** A minimal valid input; tests override the parts they exercise. */
function baseInput(overrides: Partial<AggregationCompileInput> = {}): AggregationCompileInput {
  return {
    name: 'agg rule',
    severity: 'high',
    index: 'logs-*',
    filter: null,
    spec: {
      by: ['source.ip'],
      metrics: [],
      having: { kind: 'cmp', alias: '_count', op: 'gt', value: 10 },
    },
    window: { value: 5, unit: 'MINUTES' },
    ...overrides,
  };
}

function spec(overrides: Partial<AggregationSpec> = {}): AggregationSpec {
  return {
    by: ['source.ip'],
    metrics: [],
    having: { kind: 'cmp', alias: '_count', op: 'gt', value: 10 },
    ...overrides,
  };
}

/** Reach into a compiled monitor: the composite group agg. */

function groupsAgg(monitor: any): any {
  return monitor.inputs[0].search.query.aggregations.tlsoc_groups;
}

function trigger(monitor: any): any {
  return monitor.triggers[0].bucket_level_trigger;
}

function boolFilter(monitor: any): any[] {
  return monitor.inputs[0].search.query.query.bool.filter;
}

describe('GOLDEN: the research_r2 §a scanner monitor (the live-proven compile target)', () => {
  // The exact rule proven live on the engine: group by src_ip + ua over 1h, alert when
  // dc(url) >= 10 AND count(status >= 400) >= 5, checked every 5 minutes.
  const scannerInput: AggregationCompileInput = {
    name: 'tlsoc123probe-scanner',
    severity: 'critical',
    index: 'tlsoc123probe1',
    filter: null,
    spec: {
      by: ['src_ip', 'ua'],
      metrics: [
        { alias: 'distinct_urls', fn: 'cardinality', field: 'url' },
        {
          alias: 'error_count',
          fn: 'count',
          filter: {
            logic: 'AND',
            conditions: [{ field: 'status', operator: 'gte', value: 400 }],
          },
        },
      ],
      having: {
        kind: 'and',
        operands: [
          { kind: 'cmp', alias: 'distinct_urls', op: 'gte', value: 10 },
          { kind: 'cmp', alias: 'error_count', op: 'gte', value: 5 },
        ],
      },
    },
    window: { value: 1, unit: 'HOURS' },
    runEvery: { value: 5, unit: 'MINUTES' },
  };

  it('compiles to the full pinned monitor JSON', () => {
    expect(compileAggregationRule(scannerInput)).toEqual({
      type: 'monitor',
      name: 'tlsoc123probe-scanner',
      monitor_type: 'bucket_level_monitor',
      enabled: true,
      schedule: { period: { interval: 5, unit: 'MINUTES' } },
      inputs: [
        {
          search: {
            indices: ['tlsoc123probe1'],
            query: {
              size: 0,
              query: {
                bool: {
                  filter: [
                    {
                      range: {
                        '@timestamp': {
                          from: '{{period_end}}||-1h',
                          to: '{{period_end}}',
                          include_lower: true,
                          include_upper: true,
                          format: 'epoch_millis',
                        },
                      },
                    },
                  ],
                },
              },
              aggregations: {
                tlsoc_groups: {
                  composite: {
                    size: 100,
                    sources: [
                      { src_ip: { terms: { field: 'src_ip', missing_bucket: false } } },
                      { ua: { terms: { field: 'ua', missing_bucket: false } } },
                    ],
                  },
                  aggregations: {
                    distinct_urls: { cardinality: { field: 'url' } },
                    error_count: {
                      filter: {
                        query_string: { query: 'status:>=400', analyze_wildcard: true },
                      },
                    },
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
            name: 'tlsoc123probe-scanner threshold breached',
            severity: '1',
            condition: {
              parent_bucket_path: 'tlsoc_groups',
              buckets_path: {
                _count: '_count',
                distinct_urls: 'distinct_urls',
                error_count: 'error_count._count',
              },
              script: {
                source: 'params.distinct_urls >= 10 && params.error_count >= 5',
                lang: 'painless',
              },
            },
          },
        },
      ],
    });
  });

  it('is deterministic (same input → identical JSON)', () => {
    expect(JSON.stringify(compileAggregationRule(scannerInput))).toBe(
      JSON.stringify(compileAggregationRule(scannerInput))
    );
  });
});

describe('metric functions — every fn of the agg_types contract', () => {
  it.each<[MetricFn]>([['value_count'], ['cardinality'], ['sum'], ['avg'], ['min'], ['max']])(
    '%s(field) → its own sub-agg, addressed by bare alias',
    (fn) => {
      const monitor = compileAggregationRule(
        baseInput({
          spec: spec({
            metrics: [{ alias: 'm1', fn, field: 'f1' }],
            having: { kind: 'cmp', alias: 'm1', op: 'gt', value: 0 },
          }),
        })
      );
      expect(groupsAgg(monitor).aggregations).toEqual({ m1: { [fn]: { field: 'f1' } } });
      expect(trigger(monitor).condition.buckets_path).toEqual({ _count: '_count', m1: 'm1' });
      expect(trigger(monitor).condition.script.source).toBe('params.m1 > 0');
    }
  );

  it('bare count() → NO sub-agg at all; the trigger reads the bucket doc count via _count', () => {
    const monitor = compileAggregationRule(
      baseInput({
        spec: spec({
          metrics: [{ alias: 'total', fn: 'count' }],
          having: { kind: 'cmp', alias: 'total', op: 'gte', value: 100 },
        }),
      })
    );
    // No aggregations key on the composite: nothing to emit.
    expect(groupsAgg(monitor).aggregations).toBeUndefined();
    // The alias got NO buckets_path entry — it resolves to the reserved _count path.
    expect(trigger(monitor).condition.buckets_path).toEqual({ _count: '_count' });
    expect(trigger(monitor).condition.script.source).toBe('params._count >= 100');
  });

  it('count(filter) → a filter agg whose own doc_count is the metric: buckets_path <alias>._count', () => {
    const monitor = compileAggregationRule(
      baseInput({
        spec: spec({
          metrics: [
            {
              alias: 'errors',
              fn: 'count',
              filter: {
                logic: 'OR',
                conditions: [
                  { field: 'status', operator: 'gte', value: 500 },
                  { field: 'status', operator: 'equals', value: 403 },
                ],
              },
            },
          ],
          having: { kind: 'cmp', alias: 'errors', op: 'gt', value: 3 },
        }),
      })
    );
    expect(groupsAgg(monitor).aggregations).toEqual({
      errors: {
        filter: {
          query_string: { query: '(status:>=500) OR (status:403)', analyze_wildcard: true },
        },
      },
    });
    expect(trigger(monitor).condition.buckets_path).toEqual({
      _count: '_count',
      errors: 'errors._count',
    });
    expect(trigger(monitor).condition.script.source).toBe('params.errors > 3');
  });

  it('THE PIN: a filtered NON-count metric nests under a filter agg named by FILTERED_METRIC_AGG', () => {
    // The compiler's chosen shape for "dc(url.path) among error events": a filter agg named by
    // the alias, wrapping the metric agg under the fixed name 'metric', addressed two levels
    // deep as '<alias>.metric'. Pinned so the buckets_path shape can never silently drift from
    // the emitted agg names (the "Empty list doesn't contain element at index 0." engine trap).
    expect(FILTERED_METRIC_AGG).toBe('metric');
    const monitor = compileAggregationRule(
      baseInput({
        spec: spec({
          metrics: [
            {
              alias: 'error_urls',
              fn: 'cardinality',
              field: 'url.path.keyword',
              filter: {
                logic: 'AND',
                conditions: [{ field: 'status', operator: 'gte', value: 400 }],
              },
            },
          ],
          having: { kind: 'cmp', alias: 'error_urls', op: 'gte', value: 7 },
        }),
      })
    );
    expect(groupsAgg(monitor).aggregations).toEqual({
      error_urls: {
        filter: { query_string: { query: 'status:>=400', analyze_wildcard: true } },
        aggregations: { metric: { cardinality: { field: 'url.path.keyword' } } },
      },
    });
    expect(trigger(monitor).condition.buckets_path).toEqual({
      _count: '_count',
      error_urls: 'error_urls.metric',
    });
    expect(trigger(monitor).condition.script.source).toBe('params.error_urls >= 7');
  });

  it('filtered sum follows the same nested shape', () => {
    const monitor = compileAggregationRule(
      baseInput({
        spec: spec({
          metrics: [
            {
              alias: 'bytes_up',
              fn: 'sum',
              field: 'network.bytes',
              filter: {
                logic: 'AND',
                conditions: [{ field: 'network.direction', operator: 'equals', value: 'outbound' }],
              },
            },
          ],
          having: { kind: 'cmp', alias: 'bytes_up', op: 'gt', value: 1000000 },
        }),
      })
    );
    expect(groupsAgg(monitor).aggregations).toEqual({
      bytes_up: {
        filter: {
          query_string: { query: 'network.direction:"outbound"', analyze_wildcard: true },
        },
        aggregations: { metric: { sum: { field: 'network.bytes' } } },
      },
    });
    expect(trigger(monitor).condition.buckets_path.bytes_up).toBe('bytes_up.metric');
  });

  it('a metric defined but not referenced in having still emits (it enriches the alert content)', () => {
    const monitor = compileAggregationRule(
      baseInput({
        spec: spec({
          metrics: [{ alias: 'dc_paths', fn: 'cardinality', field: 'url.path' }],
          having: { kind: 'cmp', alias: '_count', op: 'gt', value: 100 },
        }),
      })
    );
    expect(groupsAgg(monitor).aggregations).toEqual({
      dc_paths: { cardinality: { field: 'url.path' } },
    });
    expect(trigger(monitor).condition.buckets_path).toEqual({
      _count: '_count',
      dc_paths: 'dc_paths',
    });
  });
});

describe('painless lowering of HavingExpr', () => {
  const compileHaving = (having: HavingExpr, metrics: AggregationSpec['metrics'] = []) =>
    trigger(compileAggregationRule(baseInput({ spec: spec({ metrics, having }) }))).condition.script
      .source;

  it.each<['gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq', string]>([
    ['gt', '>'],
    ['gte', '>='],
    ['lt', '<'],
    ['lte', '<='],
    ['eq', '=='],
    ['neq', '!='],
  ])('cmp op %s → painless %s', (op, painless) => {
    expect(compileHaving({ kind: 'cmp', alias: '_count', op, value: 5 })).toBe(
      `params._count ${painless} 5`
    );
  });

  it('a flat AND joins with && (no parens around comparisons)', () => {
    const metrics: AggregationSpec['metrics'] = [
      { alias: 'a', fn: 'cardinality', field: 'f1' },
      { alias: 'b', fn: 'sum', field: 'f2' },
    ];
    expect(
      compileHaving(
        {
          kind: 'and',
          operands: [
            { kind: 'cmp', alias: 'a', op: 'gte', value: 40 },
            { kind: 'cmp', alias: 'b', op: 'gt', value: 9.5 },
            { kind: 'cmp', alias: '_count', op: 'lt', value: 10000 },
          ],
        },
        metrics
      )
    ).toBe('params.a >= 40 && params.b > 9.5 && params._count < 10000');
  });

  it('a flat OR joins with ||', () => {
    const metrics: AggregationSpec['metrics'] = [{ alias: 'a', fn: 'avg', field: 'f1' }];
    expect(
      compileHaving(
        {
          kind: 'or',
          operands: [
            { kind: 'cmp', alias: 'a', op: 'eq', value: 0 },
            { kind: 'cmp', alias: '_count', op: 'gte', value: 3 },
          ],
        },
        metrics
      )
    ).toBe('params.a == 0 || params._count >= 3');
  });

  it('nested compounds are parenthesized: and(cmp, or(cmp, cmp))', () => {
    const metrics: AggregationSpec['metrics'] = [
      { alias: 'a', fn: 'cardinality', field: 'f1' },
      { alias: 'b', fn: 'min', field: 'f2' },
      { alias: 'c', fn: 'max', field: 'f3' },
    ];
    expect(
      compileHaving(
        {
          kind: 'and',
          operands: [
            { kind: 'cmp', alias: 'a', op: 'gt', value: 1 },
            {
              kind: 'or',
              operands: [
                { kind: 'cmp', alias: 'b', op: 'gt', value: 2 },
                { kind: 'cmp', alias: 'c', op: 'gt', value: 3 },
              ],
            },
          ],
        },
        metrics
      )
    ).toBe('params.a > 1 && (params.b > 2 || params.c > 3)');
  });

  it('nested compounds are parenthesized: or(and(cmp, cmp), cmp)', () => {
    const metrics: AggregationSpec['metrics'] = [
      { alias: 'a', fn: 'cardinality', field: 'f1' },
      { alias: 'b', fn: 'value_count', field: 'f2' },
    ];
    expect(
      compileHaving(
        {
          kind: 'or',
          operands: [
            {
              kind: 'and',
              operands: [
                { kind: 'cmp', alias: 'a', op: 'gte', value: 4 },
                { kind: 'cmp', alias: 'b', op: 'lte', value: 8 },
              ],
            },
            { kind: 'cmp', alias: '_count', op: 'gt', value: 500 },
          ],
        },
        metrics
      )
    ).toBe('(params.a >= 4 && params.b <= 8) || params._count > 500');
  });

  it('a single-operand compound lowers to the bare comparison', () => {
    expect(
      compileHaving({
        kind: 'and',
        operands: [{ kind: 'cmp', alias: '_count', op: 'gt', value: 7 }],
      })
    ).toBe('params._count > 7');
  });

  it("a bare-count metric's ALIAS is rewritten to params._count (no buckets_path entry exists for it)", () => {
    const monitor = compileAggregationRule(
      baseInput({
        spec: spec({
          metrics: [
            { alias: 'hits', fn: 'count' },
            { alias: 'dc_ua', fn: 'cardinality', field: 'user_agent.original.keyword' },
          ],
          having: {
            kind: 'and',
            operands: [
              { kind: 'cmp', alias: 'hits', op: 'gte', value: 50 },
              { kind: 'cmp', alias: 'dc_ua', op: 'gte', value: 5 },
            ],
          },
        }),
      })
    );
    expect(trigger(monitor).condition.script.source).toBe(
      'params._count >= 50 && params.dc_ua >= 5'
    );
    expect(trigger(monitor).condition.buckets_path).toEqual({
      _count: '_count',
      dc_ua: 'dc_ua',
    });
  });
});

describe('window invariant — buildWindow consumed VERBATIM', () => {
  it('without runEvery, the schedule AND the range both encode T', () => {
    const monitor = compileAggregationRule(baseInput({ window: { value: 10, unit: 'MINUTES' } }));
    expect(monitor.schedule).toEqual({ period: { interval: 10, unit: 'MINUTES' } });
    expect(boolFilter(monitor)[0].range['@timestamp'].from).toBe('{{period_end}}||-10m');
    expect(boolFilter(monitor)[0].range['@timestamp'].to).toBe('{{period_end}}');
  });

  it('runEvery (R) drives ONLY the schedule; the range still encodes T', () => {
    const monitor = compileAggregationRule(
      baseInput({
        window: { value: 10, unit: 'MINUTES' },
        runEvery: { value: 5, unit: 'MINUTES' },
      })
    );
    expect(monitor.schedule).toEqual({ period: { interval: 5, unit: 'MINUTES' } });
    expect(boolFilter(monitor)[0].range['@timestamp'].from).toBe('{{period_end}}||-10m');
  });

  it('unit abbreviations: hours → h, days → d', () => {
    expect(
      boolFilter(compileAggregationRule(baseInput({ window: { value: 2, unit: 'HOURS' } })))[0]
        .range['@timestamp'].from
    ).toBe('{{period_end}}||-2h');
    expect(
      boolFilter(compileAggregationRule(baseInput({ window: { value: 1, unit: 'DAYS' } })))[0]
        .range['@timestamp'].from
    ).toBe('{{period_end}}||-1d');
  });

  it('rejects runEvery exceeding the window (the no-look-back rule)', () => {
    expect(() =>
      compileAggregationRule(
        baseInput({
          window: { value: 5, unit: 'MINUTES' },
          runEvery: { value: 1, unit: 'HOURS' },
        })
      )
    ).toThrow(/run-every must not exceed the window/i);
  });

  it('rejects a non-integer or non-positive runEvery and a non-positive window', () => {
    expect(() =>
      compileAggregationRule(baseInput({ runEvery: { value: 2.5, unit: 'MINUTES' } }))
    ).toThrow(/positive run-every/i);
    expect(() =>
      compileAggregationRule(baseInput({ runEvery: { value: 0, unit: 'MINUTES' } }))
    ).toThrow(/positive run-every/i);
    expect(() =>
      compileAggregationRule(baseInput({ window: { value: 0, unit: 'MINUTES' } }))
    ).toThrow(/positive time window/i);
  });

  it('rejects non-member window/runEvery units BY NAME (W3 review: the NaN-comparison bypass)', () => {
    expect(() =>
      compileAggregationRule(
        baseInput({ window: { value: 5, unit: 'FORTNIGHTS' as never } })
      )
    ).toThrow(/unknown time window unit "FORTNIGHTS"/);
    // A bad runEvery unit NaNs windowMinutes, and NaN > T is false — without the membership
    // check the R ≤ T guard would silently pass a unit the engine cannot schedule.
    expect(() =>
      compileAggregationRule(
        baseInput({
          window: { value: 5, unit: 'MINUTES' },
          runEvery: { value: 1, unit: 'weeks' as never },
        })
      )
    ).toThrow(/unknown run-every unit "weeks"/);
  });
});

describe('event filter — the three AggFilter shapes', () => {
  it("kind 'lucene' → ONE query_string clause with analyze_wildcard, after the range", () => {
    const monitor = compileAggregationRule(
      baseInput({ filter: { kind: 'lucene', query: 'event.module:"nginx"' } })
    );
    const filter = boolFilter(monitor);
    expect(filter).toHaveLength(2);
    expect(filter[1]).toEqual({
      query_string: { query: 'event.module:"nginx"', analyze_wildcard: true },
    });
  });

  it("kind 'dsl' → clauses spread into bool.filter verbatim, in order", () => {
    const clauses = [{ term: { 'event.module': 'nginx' } }, { range: { status: { gte: 400 } } }];
    const monitor = compileAggregationRule(baseInput({ filter: { kind: 'dsl', clauses } }));
    const filter = boolFilter(monitor);
    expect(filter).toHaveLength(3);
    expect(filter[1]).toEqual({ term: { 'event.module': 'nginx' } });
    expect(filter[2]).toEqual({ range: { status: { gte: 400 } } });
  });

  it("kind 'dsl' with an empty clauses list → range only", () => {
    const monitor = compileAggregationRule(baseInput({ filter: { kind: 'dsl', clauses: [] } }));
    expect(boolFilter(monitor)).toHaveLength(1);
  });

  it('null → range only', () => {
    expect(boolFilter(compileAggregationRule(baseInput({ filter: null })))).toHaveLength(1);
  });
});

describe('validation — every rejection is by name, at compile time (the silent-failure guard)', () => {
  const compileSpec = (s: AggregationSpec) => () => compileAggregationRule(baseInput({ spec: s }));

  it('rejects an empty name, empty index, unknown severity', () => {
    expect(() => compileAggregationRule(baseInput({ name: '  ' }))).toThrow(/non-empty name/i);
    expect(() => compileAggregationRule(baseInput({ index: '' }))).toThrow(/index or pattern/i);
    expect(() => compileAggregationRule(baseInput({ severity: 'urgent' as 'high' }))).toThrow(
      /unknown severity "urgent"/i
    );
  });

  it('rejects a lucene filter without a query and an unknown filter kind', () => {
    expect(() =>
      compileAggregationRule(baseInput({ filter: { kind: 'lucene', query: ' ' } }))
    ).toThrow(/non-empty query/i);
    expect(() =>
      compileAggregationRule(baseInput({ filter: { kind: 'ppl', query: 'x' } as any }))
    ).toThrow(/unknown filter kind "ppl"/i);
  });

  it('rejects dsl clauses that are not objects', () => {
    expect(() =>
      compileAggregationRule(baseInput({ filter: { kind: 'dsl', clauses: ['nope'] as any } }))
    ).toThrow(/must be an object/i);
  });

  it('rejects an empty group-by (the v1.2.3 contract: at least one field)', () => {
    expect(compileSpec(spec({ by: [] }))).toThrow(/group by at least one field/i);
    expect(compileSpec(spec({ by: [' '] }))).toThrow(/non-empty field names/i);
  });

  it('rejects duplicate group-by fields and composite source-name collisions', () => {
    expect(compileSpec(spec({ by: ['source.ip', 'source.ip'] }))).toThrow(/listed more than once/i);
    // 'a.b' and 'a_b' both slug to composite source name 'a_b' — an invalid aggregation.
    expect(compileSpec(spec({ by: ['a.b', 'a_b'] }))).toThrow(/composite source name "a_b"/i);
  });

  it('rejects a missing/blank alias, naming the metric position', () => {
    expect(
      compileSpec(
        spec({
          metrics: [{ alias: '', fn: 'cardinality', field: 'f' }],
        })
      )
    ).toThrow(/Metric 1: an alias is required/i);
  });

  it('rejects bad alias shapes: uppercase, dashes, leading digit', () => {
    for (const alias of ['Bad', 'a-b', '9lives', 'has space']) {
      expect(compileSpec(spec({ metrics: [{ alias, fn: 'cardinality', field: 'f' }] }))).toThrow(
        /lowercase letters, digits, and underscores/i
      );
    }
  });

  it('rejects the reserved aliases _count, key, doc_count by name', () => {
    for (const alias of ['_count', 'key', 'doc_count']) {
      expect(compileSpec(spec({ metrics: [{ alias, fn: 'cardinality', field: 'f' }] }))).toThrow(
        /reserved/i
      );
    }
  });

  it('rejects duplicate aliases (each names a buckets_path entry)', () => {
    expect(
      compileSpec(
        spec({
          metrics: [
            { alias: 'm1', fn: 'cardinality', field: 'f1' },
            { alias: 'm1', fn: 'sum', field: 'f2' },
          ],
        })
      )
    ).toThrow(/duplicate alias/i);
  });

  it('rejects an unknown aggregation function by name', () => {
    expect(
      compileSpec(spec({ metrics: [{ alias: 'm1', fn: 'median' as any, field: 'f1' }] }))
    ).toThrow(/unknown aggregation function "median"/i);
  });

  it('rejects count() WITH a field (value_count is the field-counting fn) and non-count WITHOUT one', () => {
    expect(compileSpec(spec({ metrics: [{ alias: 'm1', fn: 'count', field: 'f1' }] }))).toThrow(
      /count\(\) takes no field/i
    );
    expect(compileSpec(spec({ metrics: [{ alias: 'm1', fn: 'cardinality' }] }))).toThrow(
      /cardinality requires a field/i
    );
    expect(compileSpec(spec({ metrics: [{ alias: 'm1', fn: 'sum', field: ' ' }] }))).toThrow(
      /sum requires a field/i
    );
  });

  it('rejects an empty metric sub-filter and an incomplete sub-filter condition', () => {
    expect(
      compileSpec(
        spec({
          metrics: [{ alias: 'm1', fn: 'count', filter: { logic: 'AND', conditions: [] } }],
        })
      )
    ).toThrow(/sub-filter must contain at least one condition/i);
    expect(
      compileSpec(
        spec({
          metrics: [
            {
              alias: 'm1',
              fn: 'count',
              filter: {
                logic: 'AND',
                conditions: [{ field: 'status', operator: 'gte' }],
              },
            },
          ],
        })
      )
    ).toThrow(/requires a value/i);
  });

  it("rejects a having reference to an alias that isn't a metric (the 'Empty list' engine trap)", () => {
    expect(
      compileSpec(
        spec({
          metrics: [{ alias: 'm1', fn: 'cardinality', field: 'f1' }],
          having: { kind: 'cmp', alias: 'nope', op: 'gt', value: 1 },
        })
      )
    ).toThrow(/references "nope".*not a defined metric alias/i);
  });

  it('rejects a missing having and empty and/or operands with an actionable message', () => {
    expect(compileSpec(({ by: ['f'], metrics: [] } as unknown) as AggregationSpec)).toThrow(
      /no threshold condition/i
    );
    expect(compileSpec(spec({ having: { kind: 'and', operands: [] } }))).toThrow(
      /at least one comparison/i
    );
  });

  it('rejects unknown having kinds/ops and non-finite values by name', () => {
    expect(compileSpec(spec({ having: { kind: 'xor', operands: [] } as any }))).toThrow(
      /unknown threshold-condition kind "xor"/i
    );
    expect(
      compileSpec(spec({ having: { kind: 'cmp', alias: '_count', op: 'like', value: 1 } as any }))
    ).toThrow(/unknown operator "like"/i);
    expect(
      compileSpec(spec({ having: { kind: 'cmp', alias: '_count', op: 'gt', value: NaN } }))
    ).toThrow(/finite numeric value/i);
    expect(
      compileSpec(spec({ having: { kind: 'cmp', alias: '', op: 'gt', value: 1 } as any }))
    ).toThrow(/must reference a metric alias/i);
  });

  it('validateAggregationSpec is exported standalone and passes a valid spec', () => {
    expect(() =>
      validateAggregationSpec(
        spec({
          metrics: [{ alias: 'dc_x', fn: 'cardinality', field: 'x' }],
          having: { kind: 'cmp', alias: 'dc_x', op: 'gte', value: 2 },
        })
      )
    ).not.toThrow();
  });
});

describe("stateful + advanced — the registry's D4 routing (and the D4 acceptance rule)", () => {
  /** The D4 ACCEPTANCE RULE: the scanner, authored as a no-code stateful rule with advanced
   * metrics — group by source.ip + user_agent.original, dc(url.path) >= 40 AND
   * count(status >= 400) >= 50 in a 10-minute window. */
  const scannerRule: ThresholdRuleDefinition = {
    name: 'Web scanner: many distinct paths and many errors from one client',
    severity: 'high',
    index: 'fosstlsoc-logs-*',
    filter: {
      logic: 'AND',
      conditions: [{ field: 'http.request.method', operator: 'exists' }],
    },
    groupBy: ['source.ip', 'user_agent.original'],
    window: { value: 10, unit: 'MINUTES' },
    // Superseded by advanced.having (documented on ThresholdRuleDefinition.advanced).
    threshold: { operator: 'gt', value: 1000 },
    advanced: {
      by: ['source.ip', 'user_agent.original'],
      metrics: [
        { alias: 'dc_url_path', fn: 'cardinality', field: 'url.path.keyword' },
        {
          alias: 'error_count',
          fn: 'count',
          filter: {
            logic: 'AND',
            conditions: [{ field: 'http.response.status_code', operator: 'gte', value: 400 }],
          },
        },
      ],
      having: {
        kind: 'and',
        operands: [
          { kind: 'cmp', alias: 'dc_url_path', op: 'gte', value: 40 },
          { kind: 'cmp', alias: 'error_count', op: 'gte', value: 50 },
        ],
      },
    },
  };

  it('GOLDEN: the scanner rule compiles end-to-end through getType("stateful").compile', () => {
    expect(getType('stateful').compile(scannerRule)).toEqual({
      type: 'monitor',
      name: 'Web scanner: many distinct paths and many errors from one client',
      monitor_type: 'bucket_level_monitor',
      enabled: true,
      schedule: { period: { interval: 10, unit: 'MINUTES' } },
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
                          from: '{{period_end}}||-10m',
                          to: '{{period_end}}',
                          include_lower: true,
                          include_upper: true,
                          format: 'epoch_millis',
                        },
                      },
                    },
                    {
                      query_string: {
                        query: '_exists_:http.request.method',
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
                    sources: [
                      {
                        source_ip: { terms: { field: 'source.ip', missing_bucket: false } },
                      },
                      {
                        user_agent_original: {
                          terms: { field: 'user_agent.original', missing_bucket: false },
                        },
                      },
                    ],
                  },
                  aggregations: {
                    dc_url_path: { cardinality: { field: 'url.path.keyword' } },
                    error_count: {
                      filter: {
                        query_string: {
                          query: 'http.response.status_code:>=400',
                          analyze_wildcard: true,
                        },
                      },
                    },
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
            name:
              'Web scanner: many distinct paths and many errors from one client threshold breached',
            severity: '2',
            condition: {
              parent_bucket_path: 'tlsoc_groups',
              buckets_path: {
                _count: '_count',
                dc_url_path: 'dc_url_path',
                error_count: 'error_count._count',
              },
              script: {
                source: 'params.dc_url_path >= 40 && params.error_count >= 50',
                lang: 'painless',
              },
            },
          },
        },
      ],
    });
  });

  it('the legacy threshold is SUPERSEDED by advanced.having (never applied)', () => {
    const monitor = getType('stateful').compile(scannerRule);
    expect(trigger(monitor).condition.script.source).not.toContain('1000');
  });

  it('registry compile === compileAggregationRule(thresholdRuleToAggregationInput(rule))', () => {
    expect(getType('stateful').compile(scannerRule)).toEqual(
      compileAggregationRule(thresholdRuleToAggregationInput(scannerRule))
    );
  });

  it("the input's lucene filter is EXACTLY conditionGroupToLucene(rule.filter)", () => {
    const input = thresholdRuleToAggregationInput(scannerRule);
    expect(input.filter).toEqual({
      kind: 'lucene',
      query: conditionGroupToLucene(scannerRule.filter),
    });
  });

  it('rule.groupBy is AUTHORITATIVE — a divergent advanced.by is ignored at compile', () => {
    const divergent: ThresholdRuleDefinition = {
      ...scannerRule,
      advanced: { ...scannerRule.advanced!, by: ['totally.different'] },
    };
    const monitor = getType('stateful').compile(divergent);

    expect(groupsAgg(monitor).composite.sources).toEqual(
      groupsAgg(getType('stateful').compile(scannerRule)).composite.sources
    );
  });

  it('runEvery on the rule propagates: R drives the schedule, the range still encodes T', () => {
    const withCadence: ThresholdRuleDefinition = {
      ...scannerRule,
      runEvery: { value: 5, unit: 'MINUTES' },
    };
    const monitor = getType('stateful').compile(withCadence);

    expect((monitor as any).schedule).toEqual({ period: { interval: 5, unit: 'MINUTES' } });
    expect(boolFilter(monitor)[0].range['@timestamp'].from).toBe('{{period_end}}||-10m');
  });

  it('BYTE IDENTITY: a stateful rule WITHOUT advanced still compiles through the legacy path', () => {
    const legacy: ThresholdRuleDefinition = {
      name: 'DDoS: single-source request flood',
      severity: 'high',
      index: 'fosstlsoc-logs-*',
      filter: {
        logic: 'AND',
        conditions: [{ field: 'http.request.method', operator: 'exists' }],
      },
      groupBy: ['source.ip'],
      window: { value: 5, unit: 'MINUTES' },
      threshold: { operator: 'gt', value: 1000 },
    };
    expect(JSON.stringify(getType('stateful').compile(legacy))).toBe(
      JSON.stringify(compileToBucketLevelMonitor(legacy))
    );
    // And the legacy shape has NO advanced artifacts: no missing_bucket, only _count in the path.
    const monitor = getType('stateful').compile(legacy);
    expect(groupsAgg(monitor).composite.sources).toEqual([
      { source_ip: { terms: { field: 'source.ip' } } },
    ]);
    expect(trigger(monitor).condition.buckets_path).toEqual({ _count: '_count' });
  });

  it('thresholdRuleToAggregationInput refuses a rule without advanced', () => {
    const { advanced, ...rest } = scannerRule;
    expect(() => thresholdRuleToAggregationInput(rest as ThresholdRuleDefinition)).toThrow(
      /has no advanced metrics/i
    );
  });

  it('assertValidThresholdRule accepts a valid advanced rule and is UNCHANGED without one', () => {
    expect(() => assertValidThresholdRule(scannerRule)).not.toThrow();
    const { advanced, ...legacy } = scannerRule;
    expect(() => assertValidThresholdRule(legacy as ThresholdRuleDefinition)).not.toThrow();
    expect(() =>
      assertValidThresholdRule({ ...legacy, groupBy: [] } as ThresholdRuleDefinition)
    ).toThrow(/group by at least one field/i);
  });

  it('assertValidThresholdRule validates the advanced spec (duplicate alias, unknown having ref)', () => {
    expect(() =>
      assertValidThresholdRule({
        ...scannerRule,
        advanced: {
          ...scannerRule.advanced!,
          metrics: [
            { alias: 'm1', fn: 'cardinality', field: 'f1' },
            { alias: 'm1', fn: 'sum', field: 'f2' },
          ],
          having: { kind: 'cmp', alias: 'm1', op: 'gt', value: 1 },
        },
      })
    ).toThrow(/duplicate alias/i);
    expect(() =>
      assertValidThresholdRule({
        ...scannerRule,
        advanced: {
          ...scannerRule.advanced!,
          having: { kind: 'cmp', alias: 'ghost', op: 'gt', value: 1 },
        },
      })
    ).toThrow(/references "ghost"/i);
  });

  it("assertValidThresholdRule validates advanced against rule.groupBy (advanced.by isn't trusted)", () => {
    // advanced.by is empty — invalid on its own — but rule.groupBy is what gets validated.
    expect(() =>
      assertValidThresholdRule({
        ...scannerRule,
        advanced: { ...scannerRule.advanced!, by: [] },
      })
    ).not.toThrow();
    // Conversely an empty rule.groupBy fails even if advanced.by is populated.
    expect(() => assertValidThresholdRule({ ...scannerRule, groupBy: [] })).toThrow(
      /group by at least one field/i
    );
  });

  it('the compiled advanced monitor keeps the ENABLED-trap contract: compiler emits enabled:true', () => {
    expect((getType('stateful').compile(scannerRule) as any).enabled).toBe(true);
  });
});

/*
 * ————————————————————————————————————————————————————————————————————————————————————————————
 * v1.2.3 W4b (D9) — ADDITIVE tests: exceptions on the D4 advanced-threshold routing helper.
 * ————————————————————————————————————————————————————————————————————————————————————————————
 */
describe('v1.2.3 D9 — thresholdRuleToAggregationInput exceptions', () => {
  const advancedRule = (overrides: Partial<ThresholdRuleDefinition> = {}): ThresholdRuleDefinition => ({
    name: 'adv',
    severity: 'high',
    index: 'fosstlsoc-logs-*',
    filter: {
      logic: 'AND',
      conditions: [{ field: 'event.category', operator: 'equals', value: 'web' }],
    },
    groupBy: ['source.ip'],
    window: { value: 10, unit: 'MINUTES' },
    threshold: { operator: 'gt', value: 0 },
    advanced: {
      by: ['source.ip'],
      metrics: [{ alias: 'dc_paths', fn: 'cardinality', field: 'url.path' }],
      having: { kind: 'cmp', alias: 'dc_paths', op: 'gte', value: 40 },
    },
    ...overrides,
  });

  it('byte identity: exceptions absent and [] produce the identical lucene-kind input', () => {
    const withAbsent = thresholdRuleToAggregationInput(advancedRule());
    const withEmpty = thresholdRuleToAggregationInput(advancedRule({ exceptions: [] }));
    expect(JSON.stringify(withEmpty)).toBe(JSON.stringify(withAbsent));
    expect(withAbsent.filter).toEqual({
      kind: 'lucene',
      query: 'event.category:"web"',
    });
  });

  it('with exceptions: the filter becomes dsl [query_string, {bool: {must_not}}]', () => {
    const input = thresholdRuleToAggregationInput(
      advancedRule({ exceptions: [{ field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] }] })
    );
    expect(input.filter).toEqual({
      kind: 'dsl',
      clauses: [
        { query_string: { query: 'event.category:"web"', analyze_wildcard: true } },
        { bool: { must_not: [{ term: { 'source.ip': '10.0.0.0/8' } }] } },
      ],
    });
    // The compiled monitor carries both clauses verbatim in bool.filter (after the range).
    const monitor = compileAggregationRule(input);
    const filter = monitor.inputs[0].search.query.query.bool.filter;
    expect(filter).toHaveLength(3);
    expect(filter[2]).toEqual({
      bool: { must_not: [{ term: { 'source.ip': '10.0.0.0/8' } }] },
    });
  });

  it('the dsl query_string clause equals what the lucene kind would emit (shape parity)', () => {
    const withExc = compileAggregationRule(
      thresholdRuleToAggregationInput(
        advancedRule({ exceptions: [{ field: 'u', op: 'equals', values: ['svc'] }] })
      )
    );
    const withoutExc = compileAggregationRule(thresholdRuleToAggregationInput(advancedRule()));
    expect(withExc.inputs[0].search.query.query.bool.filter[1]).toEqual(
      withoutExc.inputs[0].search.query.query.bool.filter[1]
    );
  });
});
