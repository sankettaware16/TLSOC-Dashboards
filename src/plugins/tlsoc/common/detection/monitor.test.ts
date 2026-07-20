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
