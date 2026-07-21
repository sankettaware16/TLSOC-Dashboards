/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { compileToDocLevelMonitor } from './monitor';
import { Condition, RuleDefinition, Severity } from './types';

const ruleWith = (
  condition: Condition,
  overrides: Partial<RuleDefinition> = {}
): RuleDefinition => ({
  name: 'r',
  severity: 'medium',
  index: 'fosstlsoc-logs-*',
  group: { logic: 'AND', conditions: [condition] },
  ...overrides,
});

const queryOf = (rule: RuleDefinition) =>
  compileToDocLevelMonitor(rule).inputs[0].doc_level_input.queries[0].query;

describe('compileToDocLevelMonitor — query mirrors the Lucene compiler per operator', () => {
  it('equals', () =>
    expect(queryOf(ruleWith({ field: 'event.module', operator: 'equals', value: 'ssh' }))).toBe(
      'event.module:"ssh"'
    ));
  it('not_equals', () =>
    expect(queryOf(ruleWith({ field: 'event.module', operator: 'not_equals', value: 'ssh' }))).toBe(
      'NOT event.module:"ssh"'
    ));
  it('contains', () =>
    expect(queryOf(ruleWith({ field: 'url.path', operator: 'contains', value: 'admin' }))).toBe(
      'url.path:*admin*'
    ));
  it('is_one_of', () =>
    expect(
      queryOf(ruleWith({ field: 'source.ip', operator: 'is_one_of', values: ['a', 'b'] }))
    ).toBe('(source.ip:"a" OR source.ip:"b")'));
  it('exists', () =>
    expect(queryOf(ruleWith({ field: 'user.name', operator: 'exists' }))).toBe(
      '_exists_:user.name'
    ));
  it('gte', () =>
    expect(
      queryOf(ruleWith({ field: 'http.response.status_code', operator: 'gte', value: 500 }))
    ).toBe('http.response.status_code:>=500'));
});

describe('compileToDocLevelMonitor — monitor envelope', () => {
  it('builds a valid doc-level monitor shell', () => {
    const m = compileToDocLevelMonitor(
      ruleWith(
        { field: 'event.module', operator: 'equals', value: 'ssh' },
        { name: 'My Rule', description: 'desc' }
      )
    );
    expect(m.type).toBe('monitor');
    expect(m.monitor_type).toBe('doc_level_monitor');
    expect(m.enabled).toBe(true);
    expect(m.schedule).toEqual({ period: { interval: 1, unit: 'MINUTES' } });
    expect(m.inputs[0].doc_level_input.indices).toEqual(['fosstlsoc-logs-*']);
    expect(m.inputs[0].doc_level_input.description).toBe('desc');
    expect(m.inputs[0].doc_level_input.queries[0]).toEqual({
      id: 'my_rule',
      name: 'my_rule',
      query: 'event.module:"ssh"',
      tags: ['tlsoc', 'medium'],
    });
    expect(m.triggers[0].document_level_trigger.name).toBe('My Rule matched');
    expect(m.triggers[0].document_level_trigger.condition.script).toEqual({
      source: 'query[name=my_rule]',
      lang: 'painless',
    });
  });
  it('maps severity → trigger severity (1 = critical … 4 = low)', () => {
    const sev = (s: Severity) =>
      compileToDocLevelMonitor(ruleWith({ field: 'a', operator: 'equals', value: 'b' }, { severity: s }))
        .triggers[0].document_level_trigger.severity;
    expect(sev('critical')).toBe('1');
    expect(sev('high')).toBe('2');
    expect(sev('medium')).toBe('3');
    expect(sev('low')).toBe('4');
  });
});

describe('compileToDocLevelMonitor — configurable run-every schedule (WS-20)', () => {
  it('runEvery present → schedule period matches it', () => {
    const m = compileToDocLevelMonitor(
      ruleWith(
        { field: 'event.module', operator: 'equals', value: 'ssh' },
        { runEvery: { value: 10, unit: 'MINUTES' } }
      )
    );
    expect(m.schedule).toEqual({ period: { interval: 10, unit: 'MINUTES' } });
  });

  it('runEvery absent → legacy default of 1 MINUTE', () => {
    const m = compileToDocLevelMonitor(ruleWith({ field: 'event.module', operator: 'equals', value: 'ssh' }));
    expect(m.schedule).toEqual({ period: { interval: 1, unit: 'MINUTES' } });
  });

  it('rejects a non-positive runEvery value', () => {
    expect(() =>
      compileToDocLevelMonitor(
        ruleWith(
          { field: 'event.module', operator: 'equals', value: 'ssh' },
          { runEvery: { value: 0, unit: 'MINUTES' } }
        )
      )
    ).toThrow(/positive run-every value/);
  });

  it('rejects a non-member runEvery unit BY NAME (W3 review fix-the-class)', () => {
    expect(() =>
      compileToDocLevelMonitor(
        ruleWith(
          { field: 'event.module', operator: 'equals', value: 'ssh' },
          { runEvery: { value: 5, unit: 'weeks' as never } }
        )
      )
    ).toThrow(/unknown run-every unit "weeks"/);
  });
});

/*
 * ————————————————————————————————————————————————————————————————————————————————————————————
 * v1.2.3 W4b (D9) — ADDITIVE tests: exceptions + the suppression conversion. Byte identity for
 * rules WITHOUT the new fields is pinned here per compiler (the goldens stay untouched).
 * ————————————————————————————————————————————————————————————————————————————————————————————
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { compileSuppressedStatelessToBucketMonitor } = require('./monitor');

describe('v1.2.3 D9 — stateless exceptions (doc-level fragment)', () => {
  const baseRule = (): RuleDefinition => ({
    name: 'Failed logins',
    severity: 'high',
    index: 'fosstlsoc-logs-*',
    group: {
      logic: 'AND',
      conditions: [
        { field: 'event.category', operator: 'equals', value: 'authentication' },
        { field: 'event.outcome', operator: 'equals', value: 'failure' },
      ],
    },
  });

  it('byte identity: exceptions absent and exceptions [] compile identically', () => {
    const withAbsent = compileToDocLevelMonitor(baseRule());
    const withEmpty = compileToDocLevelMonitor({ ...baseRule(), exceptions: [] });
    expect(JSON.stringify(withEmpty)).toBe(JSON.stringify(withAbsent));
    expect(withAbsent.inputs[0].doc_level_input.queries[0].query).toBe(
      '(event.category:"authentication") AND (event.outcome:"failure")'
    );
  });

  it('with exceptions: the base query is parenthesized and the AND NOT fragment appended', () => {
    const monitor = compileToDocLevelMonitor({
      ...baseRule(),
      exceptions: [
        { field: 'user.name', op: 'equals', values: ['svc-backup'] },
        { field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] },
      ],
    });
    expect(monitor.inputs[0].doc_level_input.queries[0].query).toBe(
      '((event.category:"authentication") AND (event.outcome:"failure"))' +
        ' AND NOT (user.name:"svc-backup" OR source.ip:"10.0.0.0/8")'
    );
    // Everything else stays the doc-level shape.
    expect(monitor.monitor_type).toBe('doc_level_monitor');
  });

  it('rejects invalid exceptions at validate time, by name', () => {
    expect(() =>
      compileToDocLevelMonitor({
        ...baseRule(),
        exceptions: [{ field: 'user.name', op: 'equals', values: [] }],
      })
    ).toThrow('must list at least one value');
  });
});

describe('v1.2.3 D9 — stateless suppression (the doc→bucket conversion)', () => {
  const suppressedRule = (): RuleDefinition => ({
    name: 'Failed logins',
    severity: 'high',
    index: 'fosstlsoc-logs-*',
    group: {
      logic: 'AND',
      conditions: [{ field: 'event.outcome', operator: 'equals', value: 'failure' }],
    },
    suppression: { groupBy: ['source.ip'], window: { value: 5, unit: 'MINUTES' } },
  });

  it('compileToDocLevelMonitor REFUSES a suppressed rule by name (never silently ignores)', () => {
    expect(() => compileToDocLevelMonitor(suppressedRule())).toThrow(
      'carries suppression — it compiles to a grouped (bucket-level) monitor via ' +
        'compileSuppressedStatelessToBucketMonitor'
    );
  });

  it('compileSuppressedStatelessToBucketMonitor refuses a rule WITHOUT suppression by name', () => {
    const rule = suppressedRule();
    delete rule.suppression;
    expect(() => compileSuppressedStatelessToBucketMonitor(rule)).toThrow(
      'has no suppression — compile it through compileToDocLevelMonitor'
    );
  });

  it('golden: the full suppressed bucket monitor (grouped, _count >= 1, trigger renamed)', () => {
    expect(compileSuppressedStatelessToBucketMonitor(suppressedRule())).toEqual({
      type: 'monitor',
      name: 'Failed logins',
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
                        query: 'event.outcome:"failure"',
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
            name: 'Failed logins matched',
            severity: '2',
            condition: {
              parent_bucket_path: 'tlsoc_groups',
              buckets_path: { _count: '_count' },
              script: { source: 'params._count >= 1', lang: 'painless' },
            },
          },
        },
      ],
    });
  });

  it('exceptions ride as the shared {bool: {must_not}} clause on the bucket side', () => {
    const monitor = compileSuppressedStatelessToBucketMonitor({
      ...suppressedRule(),
      exceptions: [{ field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] }],
    });
    const filter = (monitor.inputs[0].search.query.query.bool.filter as unknown) as Array<
      Record<string, unknown>
    >;
    expect(filter[2]).toEqual({
      bool: { must_not: [{ term: { 'source.ip': '10.0.0.0/8' } }] },
    });
  });

  it('runEvery passes through as the schedule cadence (R <= T enforced by the shared compiler)', () => {
    const monitor = compileSuppressedStatelessToBucketMonitor({
      ...suppressedRule(),
      runEvery: { value: 1, unit: 'MINUTES' },
    });
    expect(monitor.schedule).toEqual({ period: { interval: 1, unit: 'MINUTES' } });
    expect(() =>
      compileSuppressedStatelessToBucketMonitor({
        ...suppressedRule(),
        runEvery: { value: 10, unit: 'MINUTES' },
      })
    ).toThrow('run-every must not exceed the window');
  });

  it('a stale groupBy mirror is rejected by name (the flyout-label invariant)', () => {
    expect(() =>
      compileSuppressedStatelessToBucketMonitor({
        ...suppressedRule(),
        groupBy: ['user.name'],
      })
    ).toThrow('groupBy must mirror suppression.groupBy (source.ip)');
  });

  it('suppression window unit outside the union is rejected by name', () => {
    expect(() =>
      compileSuppressedStatelessToBucketMonitor({
        ...suppressedRule(),
        suppression: { groupBy: ['source.ip'], window: { value: 5, unit: 'SECONDS' as never } },
      })
    ).toThrow('unknown suppression window unit "SECONDS"');
  });
});
