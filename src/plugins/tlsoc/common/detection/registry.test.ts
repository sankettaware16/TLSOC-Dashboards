/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { compileToBucketLevelMonitor } from './bucket_monitor';
import { compileToDocLevelMonitor } from './monitor';
import { getType, isValidMode, listTypes, unknownTypeMessage } from './registry';
import { compileToSigma } from './sigma';
import { compileToSigmaCorrelation } from './sigma_correlation';
import { RuleDefinition, ThresholdRuleDefinition } from './types';

const stateless: RuleDefinition = {
  name: 'Web attack signature in URL',
  severity: 'high',
  index: 'fosstlsoc-logs-moodle-2026.05.16',
  group: {
    logic: 'OR',
    conditions: [
      { field: 'url.path', operator: 'contains', value: '../' },
      { field: 'url.path', operator: 'matches_regex', value: 'union.*select' },
    ],
  },
};

const stateful: ThresholdRuleDefinition = {
  name: 'DDoS: single-source request flood',
  severity: 'high',
  index: 'fosstlsoc-logs-moodle-2026.05.16',
  filter: { logic: 'AND', conditions: [{ field: 'http.request.method', operator: 'exists' }] },
  groupBy: ['source.ip'],
  window: { value: 5, unit: 'MINUTES' },
  threshold: { operator: 'gt', value: 1000 },
};

describe('rule-type registry — the two existing types wrap their compilers verbatim', () => {
  it('registers exactly the two existing type ids', () => {
    expect(new Set(listTypes().map((t) => t.id))).toEqual(new Set(['stateful', 'stateless']));
  });

  it('monitorKind: stateless is doc-level, stateful is bucket-level', () => {
    expect(getType('stateless').monitorKind).toBe('doc');
    expect(getType('stateful').monitorKind).toBe('bucket');
  });

  it("compile dispatches to the existing compilers verbatim (the goldens' guarantee holds)", () => {
    expect(getType('stateless').compile(stateless)).toEqual(compileToDocLevelMonitor(stateless));
    expect(getType('stateful').compile(stateful)).toEqual(compileToBucketLevelMonitor(stateful));
  });

  it('toSigma dispatches to the existing Sigma exporters verbatim', () => {
    expect(getType('stateless').toSigma!(stateless)).toEqual(compileToSigma(stateless));
    expect(getType('stateful').toSigma!(stateful)).toEqual(compileToSigmaCorrelation(stateful));
  });

  it('validate dispatches to the existing validators (throws on an invalid rule, passes a valid one)', () => {
    expect(() => getType('stateless').validate(stateless)).not.toThrow();
    expect(() => getType('stateful').validate(stateful)).not.toThrow();
    expect(() => getType('stateless').validate({ ...stateless, index: '' })).toThrow(/data view/i);
    expect(() => getType('stateful').validate({ ...stateful, groupBy: [] })).toThrow(
      /group by at least one field/i
    );
  });
});

describe('rule-type registry — unknown ids are rejected BY NAME', () => {
  it('getType throws naming the unknown id and listing the registered ones', () => {
    expect(() => getType('sequence')).toThrow(/"sequence"/);
    expect(() => getType('sequence')).toThrow(/stateful, stateless/);
  });

  it('isValidMode is the runtime membership check', () => {
    expect(isValidMode('stateful')).toBe(true);
    expect(isValidMode('stateless')).toBe(true);
    expect(isValidMode('sequence')).toBe(false);
    expect(isValidMode('')).toBe(false);
  });

  it('unknownTypeMessage names the id (the routes reuse it for their 400s)', () => {
    expect(unknownTypeMessage('ppl')).toContain('"ppl"');
    expect(unknownTypeMessage('ppl')).toContain('stateful, stateless');
  });
});
