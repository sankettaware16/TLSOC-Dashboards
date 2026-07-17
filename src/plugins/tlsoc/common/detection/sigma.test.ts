/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { load } from 'js-yaml';
import { buildSigmaRule, compileToSigma } from './sigma';
import { Condition, RuleDefinition } from './types';

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

const detectionOf = (condition: Condition, overrides?: Partial<RuleDefinition>) =>
  buildSigmaRule(ruleWith(condition, overrides)).detection as Record<string, any>;

describe('buildSigmaRule — per-operator selection blocks', () => {
  it('equals → positive block', () => {
    const d = detectionOf({ field: 'event.module', operator: 'equals', value: 'ssh' });
    expect(d.sel0).toEqual({ 'event.module': 'ssh' });
    expect(d.condition).toBe('sel0');
  });
  it('not_equals → negated in the condition', () => {
    const d = detectionOf({ field: 'event.module', operator: 'not_equals', value: 'ssh' });
    expect(d.sel0).toEqual({ 'event.module': 'ssh' });
    expect(d.condition).toBe('not sel0');
  });
  it('contains → |contains modifier', () => {
    expect(detectionOf({ field: 'url.path', operator: 'contains', value: 'admin' }).sel0).toEqual({
      'url.path|contains': 'admin',
    });
  });
  it('not_contains → |contains modifier, negated in the condition', () => {
    const d = detectionOf({ field: 'url.path', operator: 'not_contains', value: 'health' });
    expect(d.sel0).toEqual({ 'url.path|contains': 'health' });
    expect(d.condition).toBe('not sel0');
  });
  it('starts_with / ends_with modifiers', () => {
    expect(
      detectionOf({ field: 'url.path', operator: 'starts_with', value: '/admin' }).sel0
    ).toEqual({ 'url.path|startswith': '/admin' });
    expect(
      detectionOf({ field: 'process.name', operator: 'ends_with', value: '.exe' }).sel0
    ).toEqual({ 'process.name|endswith': '.exe' });
  });
  it('is_one_of → list value; is_not_one_of → list value negated', () => {
    const one = detectionOf({ field: 'source.ip', operator: 'is_one_of', values: ['a', 'b'] });
    expect(one.sel0).toEqual({ 'source.ip': ['a', 'b'] });
    expect(one.condition).toBe('sel0');
    expect(
      detectionOf({ field: 'source.ip', operator: 'is_not_one_of', values: ['a', 'b'] }).condition
    ).toBe('not sel0');
  });
  it('exists / not_exists via the |exists modifier value', () => {
    expect(detectionOf({ field: 'user.name', operator: 'exists' }).sel0).toEqual({
      'user.name|exists': true,
    });
    expect(detectionOf({ field: 'user.name', operator: 'not_exists' }).sel0).toEqual({
      'user.name|exists': false,
    });
  });
  it('numeric range modifiers gt / gte / lt / lte', () => {
    expect(
      detectionOf({ field: 'http.response.status_code', operator: 'gte', value: 500 }).sel0
    ).toEqual({ 'http.response.status_code|gte': 500 });
    expect(detectionOf({ field: 'x', operator: 'gt', value: 1 }).sel0).toEqual({ 'x|gt': 1 });
    expect(detectionOf({ field: 'x', operator: 'lt', value: 1 }).sel0).toEqual({ 'x|lt': 1 });
    expect(detectionOf({ field: 'x', operator: 'lte', value: 1 }).sel0).toEqual({ 'x|lte': 1 });
  });
  it('matches_regex keeps the raw pattern (no slash escaping in Sigma)', () => {
    expect(
      detectionOf({ field: 'url.original', operator: 'matches_regex', value: '(?i)etc/passwd' }).sel0
    ).toEqual({ 'url.original|re': '(?i)etc/passwd' });
  });
});

describe('buildSigmaRule — rule envelope', () => {
  it('maps severity → level, sets status, defaults logsource to the index', () => {
    const r = buildSigmaRule(
      ruleWith({ field: 'a', operator: 'equals', value: 'b' }, { severity: 'critical' })
    );
    expect(r.level).toBe('critical');
    expect(r.status).toBe('experimental');
    expect(r.logsource).toEqual({ product: 'fosstlsoc-logs-*' });
    expect(r.id).toBeUndefined();
  });
  it('includes optional metadata only when provided', () => {
    const r = buildSigmaRule(
      ruleWith(
        { field: 'a', operator: 'equals', value: 'b' },
        {
          id: 'abc',
          author: 'TLSOC',
          date: '2026/06/22',
          references: ['https://example.test'],
          logSource: { category: 'authentication', product: 'linux', service: 'auth' },
        }
      )
    );
    expect(r.id).toBe('abc');
    expect(r.author).toBe('TLSOC');
    expect(r.date).toBe('2026/06/22');
    expect(r.references).toEqual(['https://example.test']);
    expect(r.logsource).toEqual({ category: 'authentication', product: 'linux', service: 'auth' });
  });
});

describe('buildSigmaRule — MITRE threat → tags, falsePositives → falsepositives', () => {
  it('tactic only → one attack.<tactic_snake> tag', () => {
    const r = buildSigmaRule(
      ruleWith(
        { field: 'a', operator: 'equals', value: 'b' },
        {
          threat: [
            {
              framework: 'MITRE ATT&CK',
              tactic: {
                id: 'TA0006',
                name: 'Credential Access',
                reference: 'https://attack.mitre.org/tactics/TA0006/',
              },
            },
          ],
        }
      )
    );
    expect(r.tags).toEqual(['attack.credential_access']);
  });

  it('technique + subtechnique → lowercased id tags, alongside the tactic tag', () => {
    const r = buildSigmaRule(
      ruleWith(
        { field: 'a', operator: 'equals', value: 'b' },
        {
          threat: [
            {
              framework: 'MITRE ATT&CK',
              tactic: {
                id: 'TA0006',
                name: 'Credential Access',
                reference: 'https://attack.mitre.org/tactics/TA0006/',
              },
              technique: [
                {
                  id: 'T1110',
                  name: 'Brute Force',
                  reference: 'https://attack.mitre.org/techniques/T1110/',
                  subtechnique: [
                    {
                      id: 'T1110.001',
                      name: 'Password Guessing',
                      reference: 'https://attack.mitre.org/techniques/T1110/001/',
                    },
                  ],
                },
              ],
            },
          ],
        }
      )
    );
    expect(r.tags).toEqual(['attack.credential_access', 'attack.t1110', 'attack.t1110.001']);
  });

  it('technique with no tactic → just the technique tag', () => {
    const r = buildSigmaRule(
      ruleWith(
        { field: 'a', operator: 'equals', value: 'b' },
        {
          threat: [
            {
              framework: 'MITRE ATT&CK',
              technique: [
                { id: 'T1059', name: 'Command and Scripting Interpreter', reference: 'https://attack.mitre.org/techniques/T1059/' },
              ],
            },
          ],
        }
      )
    );
    expect(r.tags).toEqual(['attack.t1059']);
  });

  it('empty threat array → no tags key at all', () => {
    const r = buildSigmaRule(
      ruleWith({ field: 'a', operator: 'equals', value: 'b' }, { threat: [] })
    );
    expect(r.tags).toBeUndefined();
  });

  it('threat absent → no tags key', () => {
    const r = buildSigmaRule(ruleWith({ field: 'a', operator: 'equals', value: 'b' }));
    expect(r.tags).toBeUndefined();
  });

  it('falsePositives maps to falsepositives verbatim', () => {
    const r = buildSigmaRule(
      ruleWith(
        { field: 'a', operator: 'equals', value: 'b' },
        { falsePositives: ['Scheduled maintenance window', 'Known scanner IP'] }
      )
    );
    expect(r.falsepositives).toEqual(['Scheduled maintenance window', 'Known scanner IP']);
  });

  it('falsePositives absent → no falsepositives key', () => {
    const r = buildSigmaRule(ruleWith({ field: 'a', operator: 'equals', value: 'b' }));
    expect(r.falsepositives).toBeUndefined();
  });
});

describe('compileToSigma — YAML serialisation', () => {
  it('dumps valid YAML that loads back equal to the built object', () => {
    const rule = ruleWith({ field: 'event.module', operator: 'equals', value: 'ssh' });
    expect(load(compileToSigma(rule))).toEqual(buildSigmaRule(rule));
  });
});

describe('assertValidRule — guards (via compile)', () => {
  it('throws on an empty condition list', () => {
    expect(() =>
      buildSigmaRule({
        name: 'r',
        severity: 'low',
        index: 'i',
        group: { logic: 'AND', conditions: [] },
      })
    ).toThrow(/at least one condition/);
  });
  it('throws when a value operator has no value', () => {
    expect(() =>
      buildSigmaRule(ruleWith({ field: 'a', operator: 'equals' } as Condition))
    ).toThrow(/requires a value/);
  });
  it('throws when a list operator has an empty values list', () => {
    expect(() =>
      buildSigmaRule(ruleWith({ field: 'a', operator: 'is_one_of', values: [] }))
    ).toThrow(/non-empty values list/);
  });
});
