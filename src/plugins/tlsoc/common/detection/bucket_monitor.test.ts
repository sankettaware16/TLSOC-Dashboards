/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { compileToBucketLevelMonitor } from './bucket_monitor';
import { CountThreshold, ThresholdRuleDefinition, TimeWindow } from './types';

const baseRule = (
  overrides: Partial<ThresholdRuleDefinition> = {}
): ThresholdRuleDefinition => ({
  name: 'r',
  severity: 'high',
  index: 'fosstlsoc-logs-*',
  filter: { logic: 'AND', conditions: [{ field: 'event.outcome', operator: 'equals', value: 'failure' }] },
  groupBy: ['source.ip'],
  window: { value: 5, unit: 'MINUTES' },
  threshold: { operator: 'gt', value: 10 },
  ...overrides,
});

/* eslint-disable @typescript-eslint/no-explicit-any */
const aggOf = (m: ReturnType<typeof compileToBucketLevelMonitor>) =>
  (m.inputs[0].search.query.aggregations as any).tlsoc_groups.composite;
const filtersOf = (m: ReturnType<typeof compileToBucketLevelMonitor>) =>
  m.inputs[0].search.query.query.bool.filter as any[];

describe('compileToBucketLevelMonitor — envelope', () => {
  it('emits a bucket_level_monitor with a composite agg + a threshold trigger', () => {
    const m = compileToBucketLevelMonitor(baseRule());
    expect(m.type).toBe('monitor');
    expect(m.monitor_type).toBe('bucket_level_monitor');
    expect(m.enabled).toBe(true);
    expect(m.schedule.period).toEqual({ interval: 5, unit: 'MINUTES' });
    expect(m.inputs[0].search.indices).toEqual(['fosstlsoc-logs-*']);
    expect(m.inputs[0].search.query.size).toBe(0);
    expect(aggOf(m).sources).toEqual([{ source_ip: { terms: { field: 'source.ip' } } }]);

    const trigger = m.triggers[0].bucket_level_trigger;
    expect(trigger.name).toBe('r threshold breached');
    expect(trigger.severity).toBe('2'); // high
    expect(trigger.condition.parent_bucket_path).toBe('tlsoc_groups');
    expect(trigger.condition.buckets_path).toEqual({ _count: '_count' });
    expect(trigger.condition.script).toEqual({ source: 'params._count > 10', lang: 'painless' });
  });

  it('puts the WHERE filter into a query_string clause beside the @timestamp range filter', () => {
    const m = compileToBucketLevelMonitor(
      baseRule({
        filter: {
          logic: 'AND',
          conditions: [
            { field: 'event.outcome', operator: 'equals', value: 'failure' },
            { field: 'event.module', operator: 'equals', value: 'ssh' },
          ],
        },
      })
    );
    const filters = filtersOf(m);
    expect(filters[0].range['@timestamp'].from).toBe('{{period_end}}||-5m');
    expect(filters[0].range['@timestamp'].to).toBe('{{period_end}}');
    expect(filters[1].query_string).toEqual({
      query: '(event.outcome:"failure") AND (event.module:"ssh")',
      analyze_wildcard: true,
    });
  });

  it('maps the threshold operator → Painless comparator', () => {
    const sourceFor = (operator: CountThreshold['operator']) =>
      compileToBucketLevelMonitor(baseRule({ threshold: { operator, value: 3 } })).triggers[0]
        .bucket_level_trigger.condition.script.source;
    expect(sourceFor('gt')).toBe('params._count > 3');
    expect(sourceFor('gte')).toBe('params._count >= 3');
    expect(sourceFor('lt')).toBe('params._count < 3');
    expect(sourceFor('lte')).toBe('params._count <= 3');
  });

  it('supports multiple group-by fields as composite sources (dots → safe agg keys)', () => {
    const m = compileToBucketLevelMonitor(baseRule({ groupBy: ['source.ip', 'url.path'] }));
    expect(aggOf(m).sources).toEqual([
      { source_ip: { terms: { field: 'source.ip' } } },
      { url_path: { terms: { field: 'url.path' } } },
    ]);
  });
});

describe('compileToBucketLevelMonitor — the window stays in lockstep in the compiled monitor', () => {
  const ABBREV: Record<TimeWindow['unit'], string> = { MINUTES: 'm', HOURS: 'h', DAYS: 'd' };
  const cases: TimeWindow[] = [
    { value: 1, unit: 'MINUTES' },
    { value: 5, unit: 'MINUTES' },
    { value: 15, unit: 'MINUTES' },
    { value: 1, unit: 'HOURS' },
    { value: 24, unit: 'HOURS' },
    { value: 7, unit: 'DAYS' },
  ];
  it.each(cases)('T=%o: schedule period and @timestamp range encode the same window', (window) => {
    const m = compileToBucketLevelMonitor(baseRule({ window }));
    expect(m.schedule.period).toEqual({ interval: window.value, unit: window.unit });
    const from = filtersOf(m)[0].range['@timestamp'].from;
    expect(from).toBe(`{{period_end}}||-${window.value}${ABBREV[window.unit]}`);
    // cross-check the integer parsed from the range filter against the schedule interval
    const parsed = from.match(/-(\d+)([mhd])$/);
    expect(Number(parsed[1])).toBe(m.schedule.period.interval);
  });
});

describe('compileToBucketLevelMonitor — configurable run-every schedule (WS-20)', () => {
  it('runEvery flows to schedule.period; the @timestamp range stays derived from window (T)', () => {
    const m = compileToBucketLevelMonitor(
      baseRule({ window: { value: 15, unit: 'MINUTES' }, runEvery: { value: 5, unit: 'MINUTES' } })
    );
    expect(m.schedule.period).toEqual({ interval: 5, unit: 'MINUTES' });
    expect(filtersOf(m)[0].range['@timestamp'].from).toBe('{{period_end}}||-15m');
    expect(filtersOf(m)[0].range['@timestamp'].to).toBe('{{period_end}}');
  });

  it('runEvery absent → legacy default of schedule = window (T)', () => {
    const m = compileToBucketLevelMonitor(baseRule({ window: { value: 5, unit: 'MINUTES' } }));
    expect(m.schedule.period).toEqual({ interval: 5, unit: 'MINUTES' });
  });
});

describe('assertValidThresholdRule — run-every guards (via compile, WS-20)', () => {
  it('R > T throws (a longer cadence would leave an uncovered gap)', () => {
    expect(() =>
      compileToBucketLevelMonitor(
        baseRule({ window: { value: 5, unit: 'MINUTES' }, runEvery: { value: 10, unit: 'MINUTES' } })
      )
    ).toThrow(/run-every must not exceed the threshold window/);
  });

  it('R == T passes', () => {
    expect(() =>
      compileToBucketLevelMonitor(
        baseRule({ window: { value: 5, unit: 'MINUTES' }, runEvery: { value: 5, unit: 'MINUTES' } })
      )
    ).not.toThrow();
  });

  it('R < T across units passes (R in MINUTES, T in HOURS)', () => {
    expect(() =>
      compileToBucketLevelMonitor(
        baseRule({ window: { value: 1, unit: 'HOURS' }, runEvery: { value: 30, unit: 'MINUTES' } })
      )
    ).not.toThrow();
  });

  it('runEvery 0 throws', () => {
    expect(() =>
      compileToBucketLevelMonitor(baseRule({ runEvery: { value: 0, unit: 'MINUTES' } }))
    ).toThrow(/positive run-every value/);
  });

  it('runEvery negative throws', () => {
    expect(() =>
      compileToBucketLevelMonitor(baseRule({ runEvery: { value: -5, unit: 'MINUTES' } }))
    ).toThrow(/positive run-every value/);
  });

  it('non-member window/runEvery units throw BY NAME (W3 review fix-the-class)', () => {
    expect(() =>
      compileToBucketLevelMonitor(baseRule({ window: { value: 5, unit: 'FORTNIGHTS' as never } }))
    ).toThrow(/unknown time window unit "FORTNIGHTS"/);
    // Without the membership check, windowMinutes NaNs and the R ≤ T guard silently passes.
    expect(() =>
      compileToBucketLevelMonitor(
        baseRule({
          window: { value: 5, unit: 'MINUTES' },
          runEvery: { value: 1, unit: 'weeks' as never },
        })
      )
    ).toThrow(/unknown run-every unit "weeks"/);
  });
});

describe('assertValidThresholdRule — guards (via compile)', () => {
  it('requires at least one filter condition', () => {
    expect(() =>
      compileToBucketLevelMonitor(baseRule({ filter: { logic: 'AND', conditions: [] } }))
    ).toThrow(/at least one filter condition/);
  });
  it('requires at least one group-by field', () => {
    expect(() => compileToBucketLevelMonitor(baseRule({ groupBy: [] }))).toThrow(
      /group by at least one field/
    );
  });
  it('requires a positive time window', () => {
    expect(() =>
      compileToBucketLevelMonitor(baseRule({ window: { value: 0, unit: 'MINUTES' } }))
    ).toThrow(/positive time window/);
  });
  it('requires a non-negative integer threshold', () => {
    expect(() =>
      compileToBucketLevelMonitor(baseRule({ threshold: { operator: 'gt', value: -1 } }))
    ).toThrow(/non-negative integer threshold/);
  });
});

/*
 * ————————————————————————————————————————————————————————————————————————————————————————————
 * v1.2.3 W4b (D9) — ADDITIVE tests: exceptions on the legacy stateful compiler.
 * ————————————————————————————————————————————————————————————————————————————————————————————
 */
describe('v1.2.3 D9 — threshold exceptions (bucket must_not clause)', () => {
  it('byte identity: exceptions absent and exceptions [] compile identically', () => {
    const withAbsent = compileToBucketLevelMonitor(baseRule());
    const withEmpty = compileToBucketLevelMonitor(baseRule({ exceptions: [] }));
    expect(JSON.stringify(withEmpty)).toBe(JSON.stringify(withAbsent));
    // The filter list stays exactly [range, query_string].
    expect(withAbsent.inputs[0].search.query.query.bool.filter).toHaveLength(2);
  });

  it('with exceptions: ONE {bool: {must_not}} clause is appended LAST to the filter list', () => {
    const monitor = compileToBucketLevelMonitor(
      baseRule({
        exceptions: [
          { field: 'user.name', op: 'is_one_of', values: ['svc-a', 'svc-b'] },
          { field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] },
        ],
      })
    );
    const filter = monitor.inputs[0].search.query.query.bool.filter;
    expect(filter).toHaveLength(3);
    expect(filter[2]).toEqual({
      bool: {
        must_not: [
          { terms: { 'user.name': ['svc-a', 'svc-b'] } },
          { term: { 'source.ip': '10.0.0.0/8' } },
        ],
      },
    });
    // The first two clauses are untouched.
    expect(Object.keys(filter[0])).toEqual(['range']);
    expect(Object.keys(filter[1])).toEqual(['query_string']);
  });

  it('invalid exceptions are rejected at validate time with the Threshold-rule label', () => {
    expect(() =>
      compileToBucketLevelMonitor(
        baseRule({ exceptions: [{ field: '', op: 'equals', values: ['v'] }] })
      )
    ).toThrow('Threshold rule "r": exception 1: a field is required.');
  });
});
