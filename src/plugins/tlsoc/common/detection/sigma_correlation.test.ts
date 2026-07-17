/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { loadAll } from 'js-yaml';
import { buildWindow, compileToBucketLevelMonitor, compileToSigmaCorrelation } from './index';
import { CountThreshold, ThresholdRuleDefinition } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */
const parse = (yaml: string): any[] => loadAll(yaml) as any[];

const rule: ThresholdRuleDefinition = {
  id: 'corr-001',
  name: 'Brute force: over 10 failed SSH logins from one source IP in 5 minutes',
  description: 'A single source IP failing SSH authentication more than 10 times in 5 minutes.',
  severity: 'high',
  index: 'fosstlsoc-logs-*',
  logSource: { category: 'authentication', product: 'linux', service: 'auth' },
  author: 'TLSOC',
  date: '2026/06/22',
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

const BASE_NAME =
  'brute_force_over_10_failed_ssh_logins_from_one_source_ip_in_5_minutes_base';

describe('compileToSigmaCorrelation — event_count correlation (export artifact, spec v2.1.0)', () => {
  it('emits a two-document YAML: the correlation rule then the base rule', () => {
    const docs = parse(compileToSigmaCorrelation(rule));
    expect(docs).toHaveLength(2);
    const [corr, base] = docs;

    // Correlation rule — exact field names per the SigmaHQ correlation-rules spec.
    expect(corr.title).toBe(rule.name);
    expect(corr.correlation).toEqual({
      type: 'event_count',
      rules: [BASE_NAME],
      'group-by': ['source.ip'],
      timespan: '5m',
      condition: { gt: 10 },
    });
    expect(corr.level).toBe('high');

    // Base rule carries the top-level `name:` the correlation references, plus the compiled detection.
    expect(base.name).toBe(BASE_NAME);
    expect(base.detection).toEqual({
      sel0: { 'event.outcome': 'failure' },
      sel1: { 'event.module': 'ssh' },
      condition: 'sel0 and sel1',
    });
    expect(base.logsource).toEqual({ category: 'authentication', product: 'linux', service: 'auth' });
  });

  it('the correlation timespan shares the monitor window single-source (cannot drift)', () => {
    const [corr] = parse(compileToSigmaCorrelation(rule));
    const monitor = compileToBucketLevelMonitor(rule);
    expect(corr.correlation.timespan).toBe(buildWindow(rule.window).timespan);
    expect(corr.correlation.timespan).toBe('5m');
    expect(monitor.schedule.period).toEqual({ interval: 5, unit: 'MINUTES' });
  });

  it('maps the threshold operator → the Sigma condition key', () => {
    const conditionFor = (operator: CountThreshold['operator'], value: number) =>
      parse(compileToSigmaCorrelation({ ...rule, threshold: { operator, value } }))[0].correlation
        .condition;
    expect(conditionFor('gt', 10)).toEqual({ gt: 10 });
    expect(conditionFor('gte', 5)).toEqual({ gte: 5 });
    expect(conditionFor('lt', 2)).toEqual({ lt: 2 });
    expect(conditionFor('lte', 1)).toEqual({ lte: 1 });
  });

  it('group-by is hyphenated and renders multiple fields', () => {
    const [corr] = parse(compileToSigmaCorrelation({ ...rule, groupBy: ['source.ip', 'url.path'] }));
    expect(corr.correlation['group-by']).toEqual(['source.ip', 'url.path']);
    expect(corr.correlation.group_by).toBeUndefined();
  });
});
