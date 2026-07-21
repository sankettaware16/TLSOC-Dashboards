/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  DEFAULT_NEW_TERMS_HISTORY_WINDOW,
  DEFAULT_NEW_TERMS_RUN_EVERY,
  DETECTION_STATE_INDEX,
  NewTermsRuleDefinition,
  SEEN_VALUES_CAP,
  SEEN_VALUES_PATH,
  assertValidNewTermsRule,
  compileNewTermsToMonitor,
  newTermsScanWindow,
  newTermsStateDocId,
} from './new_terms';

/** A minimal valid rule; tests override the parts they exercise. */
function baseRule(overrides: Partial<NewTermsRuleDefinition> = {}): NewTermsRuleDefinition {
  return {
    name: 'New country seen',
    severity: 'high',
    index: 'fosstlsoc-logs-*',
    termField: 'source.geo.country_iso_code',
    historyWindow: { value: 30, unit: 'DAYS' },
    groupBy: ['source.geo.country_iso_code'],
    ...overrides,
  };
}

const DOC_ID = newTermsStateDocId('abc123', 'source.geo.country_iso_code');

describe('newTermsStateDocId', () => {
  it('is deterministic: seen-<soId>-<termField>', () => {
    expect(newTermsStateDocId('abc123', 'user.name')).toBe('seen-abc123-user.name');
    expect(newTermsStateDocId('abc123', 'user.name')).toBe(
      newTermsStateDocId('abc123', 'user.name')
    );
  });
});

describe('constants frozen by the live probes (research_r5)', () => {
  it('pins the state-index name, lookup path, and the max_terms_count cap', () => {
    expect(DETECTION_STATE_INDEX).toBe('tlsoc-detection-state');
    expect(SEEN_VALUES_PATH).toBe('values');
    expect(SEEN_VALUES_CAP).toBe(65536);
    expect(DEFAULT_NEW_TERMS_HISTORY_WINDOW).toEqual({ value: 30, unit: 'DAYS' });
    expect(DEFAULT_NEW_TERMS_RUN_EVERY).toEqual({ value: 1, unit: 'MINUTES' });
  });
});

describe('newTermsScanWindow', () => {
  it('defaults to the 1-minute cadence and honors an explicit runEvery', () => {
    expect(newTermsScanWindow(baseRule())).toEqual({ value: 1, unit: 'MINUTES' });
    expect(newTermsScanWindow(baseRule({ runEvery: { value: 10, unit: 'MINUTES' } }))).toEqual({
      value: 10,
      unit: 'MINUTES',
    });
  });
});

describe('GOLDEN: full compiled monitor (pre-filter + explicit cadence)', () => {
  it('pins the entire monitor JSON, including the terms-lookup, composite, and trigger', () => {
    const rule = baseRule({
      filter: {
        logic: 'AND',
        conditions: [{ field: 'event.category', operator: 'equals', value: 'authentication' }],
      },
      runEvery: { value: 10, unit: 'MINUTES' },
    });

    expect(compileNewTermsToMonitor(rule, DOC_ID)).toEqual({
      type: 'monitor',
      name: 'New country seen',
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
                        query: 'event.category:"authentication"',
                        analyze_wildcard: true,
                      },
                    },
                    {
                      bool: {
                        must_not: [
                          {
                            terms: {
                              'source.geo.country_iso_code': {
                                index: 'tlsoc-detection-state',
                                id: 'seen-abc123-source.geo.country_iso_code',
                                path: 'values',
                              },
                            },
                          },
                        ],
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
                        source_geo_country_iso_code: {
                          terms: {
                            field: 'source.geo.country_iso_code',
                            missing_bucket: false,
                          },
                        },
                      },
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
            name: 'New country seen new value seen',
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
});

describe('GOLDEN: minimal rule (no pre-filter, default cadence)', () => {
  it('scans the last 1 minute each run; the seen-exclusion is the only event filter', () => {
    const monitor = compileNewTermsToMonitor(baseRule(), DOC_ID);

    expect(monitor.schedule).toEqual({ period: { interval: 1, unit: 'MINUTES' } });
    expect(monitor.inputs[0].search.query.query.bool.filter).toEqual([
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
        bool: {
          must_not: [
            {
              terms: {
                'source.geo.country_iso_code': {
                  index: 'tlsoc-detection-state',
                  id: 'seen-abc123-source.geo.country_iso_code',
                  path: 'values',
                },
              },
            },
          ],
        },
      },
    ]);
    // No metrics → no sub-aggs under the composite group agg.
    expect(
      (monitor.inputs[0].search.query.aggregations.tlsoc_groups as Record<string, unknown>)
        .aggregations
    ).toBeUndefined();
  });
});

describe('assertValidNewTermsRule — reject-by-name', () => {
  it('rejects a missing/empty term field', () => {
    expect(() => assertValidNewTermsRule(baseRule({ termField: '' }))).toThrow(
      /must specify the term field/
    );
    expect(() =>
      assertValidNewTermsRule(baseRule({ termField: (undefined as unknown) as string }))
    ).toThrow(/must specify the term field/);
  });

  it('rejects a missing name and a missing index', () => {
    expect(() => assertValidNewTermsRule(baseRule({ name: ' ' }))).toThrow(/non-empty name/);
    expect(() => assertValidNewTermsRule(baseRule({ index: '' }))).toThrow(
      /must specify a data view/
    );
  });

  it('rejects groupBy that is not exactly [termField]', () => {
    expect(() => assertValidNewTermsRule(baseRule({ groupBy: [] }))).toThrow(
      /groupBy must be exactly \[termField\]/
    );
    expect(() => assertValidNewTermsRule(baseRule({ groupBy: ['user.name'] }))).toThrow(
      /groupBy must be exactly \[termField\]/
    );
    expect(() =>
      assertValidNewTermsRule(baseRule({ groupBy: ['source.geo.country_iso_code', 'user.name'] }))
    ).toThrow(/groupBy must be exactly \[termField\]/);
  });

  it('rejects a bad history window: missing, non-positive, fractional, unknown unit', () => {
    expect(() =>
      assertValidNewTermsRule(baseRule({ historyWindow: (undefined as unknown) as never }))
    ).toThrow(/positive integer history window/);
    expect(() =>
      assertValidNewTermsRule(baseRule({ historyWindow: { value: 0, unit: 'DAYS' } }))
    ).toThrow(/positive integer history window/);
    expect(() =>
      assertValidNewTermsRule(baseRule({ historyWindow: { value: 2.5, unit: 'DAYS' } }))
    ).toThrow(/positive integer history window/);
    expect(() =>
      assertValidNewTermsRule(
        baseRule({ historyWindow: { value: 30, unit: 'FORTNIGHTS' as never } })
      )
    ).toThrow(/unknown history window unit "FORTNIGHTS"/);
  });

  it('rejects a bad run-every cadence by name', () => {
    expect(() =>
      assertValidNewTermsRule(baseRule({ runEvery: { value: -1, unit: 'MINUTES' } }))
    ).toThrow(/positive integer run-every cadence/);
    expect(() =>
      assertValidNewTermsRule(baseRule({ runEvery: { value: 5, unit: 'weeks' as never } }))
    ).toThrow(/unknown run-every cadence unit "weeks"/);
  });

  it('rejects an unknown severity by name', () => {
    expect(() => assertValidNewTermsRule(baseRule({ severity: 'urgent' as never }))).toThrow(
      /unknown severity "urgent"/
    );
  });

  it('rejects a degenerate pre-filter (empty group, missing field, empty values list)', () => {
    expect(() =>
      assertValidNewTermsRule(baseRule({ filter: { logic: 'AND', conditions: [] } }))
    ).toThrow(/pre-filter must contain at least one condition/);
    expect(() =>
      assertValidNewTermsRule(
        baseRule({
          filter: { logic: 'AND', conditions: [{ field: '', operator: 'equals', value: 'x' }] },
        })
      )
    ).toThrow(/a field is required/);
    expect(() =>
      assertValidNewTermsRule(
        baseRule({
          filter: {
            logic: 'AND',
            conditions: [{ field: 'user.name', operator: 'is_one_of', values: [] }],
          },
        })
      )
    ).toThrow(/requires a non-empty values list/);
    expect(() =>
      assertValidNewTermsRule(
        baseRule({
          filter: { logic: 'AND', conditions: [{ field: 'user.name', operator: 'equals' }] },
        })
      )
    ).toThrow(/requires a value/);
  });

  it('accepts a valueless-operator pre-filter condition (exists)', () => {
    expect(() =>
      assertValidNewTermsRule(
        baseRule({
          filter: { logic: 'AND', conditions: [{ field: 'user.name', operator: 'exists' }] },
        })
      )
    ).not.toThrow();
  });
});

describe('compileNewTermsToMonitor — the state-doc-id contract', () => {
  it('throws by name when the seen-state doc id is missing or blank', () => {
    expect(() => compileNewTermsToMonitor(baseRule(), '')).toThrow(/no seen-state document id/);
    expect(() => compileNewTermsToMonitor(baseRule(), '   ')).toThrow(/no seen-state document id/);
    expect(() => compileNewTermsToMonitor(baseRule(), (undefined as unknown) as string)).toThrow(
      /no seen-state document id/
    );
  });

  it('validates the rule before looking at the doc id (a bad rule never compiles)', () => {
    expect(() => compileNewTermsToMonitor(baseRule({ termField: '' }), DOC_ID)).toThrow(
      /must specify the term field/
    );
  });
});

/*
 * ————————————————————————————————————————————————————————————————————————————————————————————
 * v1.2.3 W4b (D9) — ADDITIVE tests: exceptions on the new-terms compiler.
 * ————————————————————————————————————————————————————————————————————————————————————————————
 */
describe('v1.2.3 D9 — new-terms exceptions (bucket must_not clause)', () => {
  const d9Rule = (overrides: Record<string, unknown> = {}) =>
    (({
      name: 'first-seen country',
      severity: 'medium',
      index: 'fosstlsoc-logs-*',
      termField: 'source.geo.country_iso_code',
      historyWindow: { value: 30, unit: 'DAYS' },
      groupBy: ['source.geo.country_iso_code'],
      ...overrides,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as unknown) as any);

  it('byte identity: exceptions absent and exceptions [] compile identically', () => {
    const withAbsent = compileNewTermsToMonitor(d9Rule(), 'seen-so-1-source.geo.country_iso_code');
    const withEmpty = compileNewTermsToMonitor(
      d9Rule({ exceptions: [] }),
      'seen-so-1-source.geo.country_iso_code'
    );
    expect(JSON.stringify(withEmpty)).toBe(JSON.stringify(withAbsent));
  });

  it('with exceptions: the clause is appended LAST — after the seen-exclusion lookup', () => {
    const monitor = compileNewTermsToMonitor(
      d9Rule({ exceptions: [{ field: 'user.name', op: 'equals', values: ['svc-probe'] }] }),
      'seen-so-1-source.geo.country_iso_code'
    );
    const filter = monitor.inputs[0].search.query.query.bool.filter as Array<
      Record<string, unknown>
    >;
    // [range, seen-exclusion, exceptions] — no pre-filter in this fixture.
    expect(filter).toHaveLength(3);
    expect(filter[1]).toHaveProperty(['bool', 'must_not', 0, 'terms']);
    expect(filter[2]).toEqual({
      bool: { must_not: [{ term: { 'user.name': 'svc-probe' } }] },
    });
  });

  it('invalid exceptions are rejected with the New-terms label', () => {
    expect(() =>
      compileNewTermsToMonitor(
        d9Rule({ exceptions: [{ field: 'f', op: 'nope', values: ['v'] }] }),
        'seen-x'
      )
    ).toThrow('New-terms rule "first-seen country": exception 1 ("f") has unknown operator "nope"');
  });
});
