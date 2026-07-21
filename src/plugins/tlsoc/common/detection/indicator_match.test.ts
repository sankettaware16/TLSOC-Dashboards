/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  IndicatorMatchRuleDefinition,
  assertValidIndicatorMatchRule,
  buildInlineIndicatorQuery,
  compileIndicatorInlineToDocMonitor,
  compileIndicatorLookupToBucketMonitor,
  pickIndicatorListMode,
} from './indicator_match';
import { VALUE_LIST_INLINE_MAX_VALUES, VALUE_LIST_MAX_VALUES } from '../value_lists';

const baseRule = (): IndicatorMatchRuleDefinition => ({
  name: 'IOC hits — known bad IPs',
  severity: 'high',
  index: 'fosstlsoc-logs-*',
  eventField: 'source.ip',
  listId: 'known_bad_ips',
  listMode: 'inline',
  groupBy: ['source.ip'],
});

describe('pickIndicatorListMode — the size-based hybrid decision', () => {
  it('picks inline at and under the cap, lookup above it', () => {
    expect(pickIndicatorListMode(1)).toBe('inline');
    expect(pickIndicatorListMode(VALUE_LIST_INLINE_MAX_VALUES)).toBe('inline');
    expect(pickIndicatorListMode(VALUE_LIST_INLINE_MAX_VALUES + 1)).toBe('lookup');
    expect(pickIndicatorListMode(VALUE_LIST_MAX_VALUES)).toBe('lookup');
  });

  it('refuses an empty list by name', () => {
    expect(() => pickIndicatorListMode(0)).toThrow(/has no values/);
  });

  it('refuses an over-ceiling list by name (max_terms_count fails every run)', () => {
    expect(() => pickIndicatorListMode(VALUE_LIST_MAX_VALUES + 1)).toThrow(/65536/);
  });
});

describe('compileIndicatorInlineToDocMonitor — the inline (doc-level) golden', () => {
  it('compiles the exact doc-level monitor (emission mirrors monitor.ts byte-for-byte)', () => {
    const monitor = compileIndicatorInlineToDocMonitor(baseRule(), [
      '10.0.0.66',
      '192.168.0.0/16',
    ]);
    expect(monitor).toEqual({
      type: 'monitor',
      name: 'IOC hits — known bad IPs',
      monitor_type: 'doc_level_monitor',
      enabled: true,
      schedule: { period: { interval: 1, unit: 'MINUTES' } },
      inputs: [
        {
          doc_level_input: {
            description: '',
            indices: ['fosstlsoc-logs-*'],
            queries: [
              {
                id: 'ioc_hits_known_bad_ips',
                name: 'ioc_hits_known_bad_ips',
                // CIDR blocks ride QUOTED — live-verified to match against ip fields
                // (research_r5 §4.3); unquoted the '/' would open a Lucene regex literal.
                query: 'source.ip:("10.0.0.66" OR "192.168.0.0/16")',
                tags: ['tlsoc', 'high'],
              },
            ],
          },
        },
      ],
      triggers: [
        {
          document_level_trigger: {
            name: 'IOC hits — known bad IPs matched',
            severity: '2',
            condition: {
              script: { source: 'query[name=ioc_hits_known_bad_ips]', lang: 'painless' },
            },
          },
        },
      ],
    });
  });

  it('escapes quotes and backslashes inside values; spaces ride inside the phrase', () => {
    const rule = { ...baseRule(), eventField: 'user.name', groupBy: ['user.name'] };
    const query = buildInlineIndicatorQuery(rule, ['bad "guy"', 'C:\\evil.exe', 'two words']);
    expect(query).toBe('user.name:("bad \\"guy\\"" OR "C:\\\\evil.exe" OR "two words")');
  });

  it('AND-composes the optional pre-filter after the list clause', () => {
    const rule: IndicatorMatchRuleDefinition = {
      ...baseRule(),
      filter: {
        logic: 'AND',
        conditions: [{ field: 'event.category', operator: 'equals', value: 'network' }],
      },
    };
    const monitor = compileIndicatorInlineToDocMonitor(rule, ['10.0.0.66']);
    expect(monitor.inputs[0].doc_level_input.queries[0].query).toBe(
      'source.ip:("10.0.0.66") AND (event.category:"network")'
    );
  });

  it('honors runEvery as the doc-level schedule', () => {
    const monitor = compileIndicatorInlineToDocMonitor(
      { ...baseRule(), runEvery: { value: 5, unit: 'MINUTES' } },
      ['10.0.0.66']
    );
    expect(monitor.schedule).toEqual({ period: { interval: 5, unit: 'MINUTES' } });
  });

  it(`REFUSES ${VALUE_LIST_INLINE_MAX_VALUES + 1} values BY NAME — never truncates (the silent 1024 cliff)`, () => {
    const values = Array.from({ length: VALUE_LIST_INLINE_MAX_VALUES + 1 }, (_, i) => `ioc-${i}`);
    expect(() => compileIndicatorInlineToDocMonitor(baseRule(), values)).toThrow(
      /901 values.*900-value inline limit.*NEVER truncated.*silently matches nothing/s
    );
  });

  it(`accepts exactly ${VALUE_LIST_INLINE_MAX_VALUES} values (the cap is inclusive)`, () => {
    const values = Array.from({ length: VALUE_LIST_INLINE_MAX_VALUES }, (_, i) => `ioc-${i}`);
    const monitor = compileIndicatorInlineToDocMonitor(baseRule(), values);
    expect(monitor.inputs[0].doc_level_input.queries[0].query).toContain('"ioc-899"');
  });

  it('refuses an empty values array and empty entries by position', () => {
    expect(() => compileIndicatorInlineToDocMonitor(baseRule(), [])).toThrow(/has no values/);
    expect(() => compileIndicatorInlineToDocMonitor(baseRule(), ['ok', ''])).toThrow(
      /value 2 is empty/
    );
  });
});

describe('compileIndicatorLookupToBucketMonitor — the lookup (bucket) golden', () => {
  it('compiles the exact bucket monitor with the terms-lookup clause pinned', () => {
    const monitor = compileIndicatorLookupToBucketMonitor({ ...baseRule(), listMode: 'lookup' });
    expect(monitor).toEqual({
      type: 'monitor',
      name: 'IOC hits — known bad IPs',
      monitor_type: 'bucket_level_monitor',
      enabled: true,
      schedule: { period: { interval: 1, unit: 'MINUTES' } },
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
                          from: '{{period_end}}||-1m',
                          to: '{{period_end}}',
                          include_lower: true,
                          include_upper: true,
                          format: 'epoch_millis',
                        },
                      },
                    },
                    {
                      terms: {
                        'source.ip': {
                          index: 'tlsoc-value-lists',
                          id: 'known_bad_ips',
                          path: 'values',
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
                      { source_ip: { terms: { field: 'source.ip', missing_bucket: false } } },
                    ],
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
            name: 'IOC hits — known bad IPs matched',
            severity: '2',
            condition: {
              parent_bucket_path: 'tlsoc_groups',
              buckets_path: { _count: '_count' },
              script: { source: 'params._count > 0', lang: 'painless' },
            },
          },
        },
      ],
    });
  });

  it('runEvery drives BOTH the schedule and the window range (window == period)', () => {
    const monitor = compileIndicatorLookupToBucketMonitor({
      ...baseRule(),
      listMode: 'lookup',
      runEvery: { value: 15, unit: 'MINUTES' },
    });
    expect(monitor.schedule).toEqual({ period: { interval: 15, unit: 'MINUTES' } });
    const range = monitor.inputs[0].search.query.query.bool.filter[0] as {
      range: Record<string, { from: string }>;
    };
    expect(range.range['@timestamp'].from).toBe('{{period_end}}||-15m');
  });

  it('appends the optional pre-filter as a query_string clause after the lookup', () => {
    const monitor = compileIndicatorLookupToBucketMonitor({
      ...baseRule(),
      listMode: 'lookup',
      filter: {
        logic: 'OR',
        conditions: [
          { field: 'event.category', operator: 'equals', value: 'network' },
          { field: 'destination.port', operator: 'gt', value: 1024 },
        ],
      },
    });
    const clauses = monitor.inputs[0].search.query.query.bool.filter;
    expect(clauses).toHaveLength(3);
    expect(clauses[2]).toEqual({
      query_string: {
        query: '(event.category:"network") OR (destination.port:>1024)',
        analyze_wildcard: true,
      },
    });
  });
});

describe('assertValidIndicatorMatchRule — reject-by-name battery', () => {
  it('accepts the base rule (both modes)', () => {
    expect(() => assertValidIndicatorMatchRule(baseRule())).not.toThrow();
    expect(() =>
      assertValidIndicatorMatchRule({ ...baseRule(), listMode: 'lookup' })
    ).not.toThrow();
  });

  it.each([
    [{ ...baseRule(), name: '  ' }, /non-empty name/],
    [{ ...baseRule(), index: '' }, /must specify a data view/],
    [
      ({ ...baseRule(), severity: 'urgent' } as unknown) as IndicatorMatchRuleDefinition,
      /unknown severity "urgent"/,
    ],
    [{ ...baseRule(), eventField: '' }, /must specify the event field/],
    [{ ...baseRule(), listId: '' }, /must reference a value list/],
    [{ ...baseRule(), listId: 'has space' }, /must reference a value list/],
    [
      ({ ...baseRule(), listMode: 'both' } as unknown) as IndicatorMatchRuleDefinition,
      /unknown list mode "both". Supported: inline, lookup/,
    ],
    [{ ...baseRule(), groupBy: [] }, /group by exactly its event field/],
    [{ ...baseRule(), groupBy: ['user.name'] }, /group by exactly its event field/],
    [
      { ...baseRule(), groupBy: ['source.ip', 'user.name'] },
      /group by exactly its event field/,
    ],
    [
      { ...baseRule(), filter: { logic: 'AND' as const, conditions: [] } },
      /pre-filter must contain at least one condition/,
    ],
    [
      {
        ...baseRule(),
        filter: {
          logic: 'AND' as const,
          conditions: [{ field: '', operator: 'exists' as const }],
        },
      },
      /pre-filter condition 1 needs a field/,
    ],
    [{ ...baseRule(), runEvery: { value: 0, unit: 'MINUTES' as const } }, /positive run-every/],
    [{ ...baseRule(), runEvery: { value: 1.5, unit: 'MINUTES' as const } }, /positive run-every/],
    [
      ({ ...baseRule(), runEvery: { value: 5, unit: 'weeks' } } as unknown) as IndicatorMatchRuleDefinition,
      /unknown run-every unit "weeks"/,
    ],
  ])('rejects %#', (rule, message) => {
    expect(() => assertValidIndicatorMatchRule(rule as IndicatorMatchRuleDefinition)).toThrow(
      message
    );
  });

  it('both compilers validate first — an invalid rule never compiles', () => {
    const bad = ({ ...baseRule(), listMode: 'both' } as unknown) as IndicatorMatchRuleDefinition;
    expect(() => compileIndicatorInlineToDocMonitor(bad, ['x'])).toThrow(/unknown list mode/);
    expect(() => compileIndicatorLookupToBucketMonitor(bad)).toThrow(/unknown list mode/);
  });
});

/*
 * ————————————————————————————————————————————————————————————————————————————————————————————
 * v1.2.3 W4b (D9) — ADDITIVE tests: exceptions on both indicator-match compile shapes.
 * ————————————————————————————————————————————————————————————————————————————————————————————
 */
describe('v1.2.3 D9 — indicator-match exceptions', () => {
  const d9Rule = (overrides: Partial<IndicatorMatchRuleDefinition> = {}): IndicatorMatchRuleDefinition => ({
    name: 'ioc rule',
    severity: 'high',
    index: 'fosstlsoc-logs-*',
    eventField: 'source.ip',
    listId: 'list-1',
    listMode: 'lookup',
    groupBy: ['source.ip'],
    ...overrides,
  });

  it('inline query — byte identity without exceptions; fragment appended with them', () => {
    const bare = buildInlineIndicatorQuery(d9Rule(), ['1.2.3.4']);
    expect(bare).toBe('source.ip:("1.2.3.4")');
    expect(buildInlineIndicatorQuery(d9Rule({ exceptions: [] }), ['1.2.3.4'])).toBe(bare);
    expect(
      buildInlineIndicatorQuery(
        d9Rule({ exceptions: [{ field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] }] }),
        ['1.2.3.4']
      )
    ).toBe('(source.ip:("1.2.3.4")) AND NOT (source.ip:"10.0.0.0/8")');
  });

  it('inline query — pre-filter and exceptions compose (filter inside, NOT appended last)', () => {
    expect(
      buildInlineIndicatorQuery(
        d9Rule({
          filter: {
            logic: 'AND',
            conditions: [{ field: 'event.category', operator: 'equals', value: 'network' }],
          },
          exceptions: [{ field: 'user.name', op: 'equals', values: ['svc'] }],
        }),
        ['1.2.3.4']
      )
    ).toBe(
      '(source.ip:("1.2.3.4") AND (event.category:"network")) AND NOT (user.name:"svc")'
    );
  });

  it('lookup monitor — byte identity without exceptions; must_not clause appended with them', () => {
    const withAbsent = compileIndicatorLookupToBucketMonitor(d9Rule());
    const withEmpty = compileIndicatorLookupToBucketMonitor(d9Rule({ exceptions: [] }));
    expect(JSON.stringify(withEmpty)).toBe(JSON.stringify(withAbsent));

    const monitor = compileIndicatorLookupToBucketMonitor(
      d9Rule({ exceptions: [{ field: 'user.name', op: 'is_one_of', values: ['a', 'b'] }] })
    );
    const filter = monitor.inputs[0].search.query.query.bool.filter as Array<
      Record<string, unknown>
    >;
    // [range, terms-lookup, exceptions] — appended LAST.
    expect(filter).toHaveLength(3);
    expect(filter[2]).toEqual({
      bool: { must_not: [{ terms: { 'user.name': ['a', 'b'] } }] },
    });
  });

  it('invalid exceptions are rejected with the Indicator-match label', () => {
    expect(() =>
      assertValidIndicatorMatchRule(
        d9Rule({ exceptions: [{ field: 's', op: 'cidr', values: ['999.0.0.0/8'] }] })
      )
    ).toThrow('Indicator-match rule "ioc rule": exception 1 ("s"): "999.0.0.0/8" is not a valid CIDR');
  });
});
