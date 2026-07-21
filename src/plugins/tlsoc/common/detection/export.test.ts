/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  NATIVE_EXPORT_KIND,
  NATIVE_EXPORT_VERSION,
  buildNativeBulkExport,
  buildNativeEnvelope,
  canExportSigma,
  parseNativeImport,
  sigmaExportUnavailableReason,
} from './export';

/* eslint-disable @typescript-eslint/no-explicit-any */

const statelessRule = () => ({
  name: 'Admin probe',
  severity: 'high',
  index: 'security-logs',
  group: {
    logic: 'AND',
    conditions: [{ field: 'url.path', operator: 'contains', value: 'admin' }],
  },
});

const statefulRule = () => ({
  name: 'Brute force',
  severity: 'high',
  index: 'security-logs',
  filter: {
    logic: 'AND',
    conditions: [{ field: 'event.outcome', operator: 'equals', value: 'failure' }],
  },
  groupBy: ['user.name'],
  window: { value: 5, unit: 'MINUTES' },
  threshold: { operator: 'gt', value: 5 },
});

describe('buildNativeEnvelope / buildNativeBulkExport', () => {
  it('the single envelope is self-identifying and carries {mode, rule} — the create-route SaveBody', () => {
    const rule = statelessRule();
    expect(buildNativeEnvelope('stateless', rule)).toEqual({
      version: '1',
      kind: 'tlsoc-detection-rule',
      mode: 'stateless',
      rule,
    });
  });

  it('bulk export is a plain array of envelopes, in input order', () => {
    const out = buildNativeBulkExport([
      { mode: 'stateless', rule: statelessRule() },
      { mode: 'stateful', rule: statefulRule() },
    ]);
    expect(out).toHaveLength(2);
    expect(out[0].mode).toBe('stateless');
    expect(out[1].mode).toBe('stateful');
    out.forEach((e) => {
      expect(e.kind).toBe(NATIVE_EXPORT_KIND);
      expect(e.version).toBe(NATIVE_EXPORT_VERSION);
    });
  });
});

describe('sigmaExportUnavailableReason / canExportSigma', () => {
  it('stateless and plain stateful rules are Sigma-exportable', () => {
    expect(sigmaExportUnavailableReason('stateless', statelessRule())).toBeNull();
    expect(sigmaExportUnavailableReason('stateful', statefulRule())).toBeNull();
    expect(canExportSigma('stateless', statelessRule())).toBe(true);
    expect(canExportSigma('stateful', statefulRule())).toBe(true);
  });

  it('types without a toSigma compiler refuse BY NAME', () => {
    for (const mode of ['ppl', 'custom_query', 'new_terms', 'indicator_match']) {
      const reason = sigmaExportUnavailableReason(mode, {});
      expect(reason).toContain(`"${mode}"`);
      expect(reason).toContain('native JSON');
      expect(canExportSigma(mode, {})).toBe(false);
    }
  });

  it('a stateful rule WITH advanced metrics is native-only (Sigma event_count cannot express it)', () => {
    const rule = { ...statefulRule(), advanced: { metrics: [], having: {} } };
    const reason = sigmaExportUnavailableReason('stateful', rule);
    expect(reason).toContain('advanced metrics');
    expect(canExportSigma('stateful', rule)).toBe(false);
  });

  it('a rule WITH exceptions is native-only (Sigma export would silently drop them)', () => {
    const rule = {
      ...statelessRule(),
      exceptions: [{ field: 'source.ip', op: 'equals', values: ['10.0.0.1'] }],
    };
    const reason = sigmaExportUnavailableReason('stateless', rule);
    expect(reason).toContain('exceptions');
    expect(canExportSigma('stateless', rule)).toBe(false);
    // An EMPTY exceptions array is no caveat at all.
    expect(canExportSigma('stateless', { ...statelessRule(), exceptions: [] })).toBe(true);
  });

  it('a rule WITH suppression is native-only (the Sigma form would silently lose the grouping)', () => {
    const rule = {
      ...statelessRule(),
      suppression: { groupBy: ['source.ip'], window: { value: 5, unit: 'MINUTES' } },
    };
    const reason = sigmaExportUnavailableReason('stateless', rule);
    expect(reason).toContain('suppression');
    expect(canExportSigma('stateless', rule)).toBe(false);
    // custom_query rules refuse on suppression the same way.
    expect(
      canExportSigma('custom_query', {
        name: 'cq',
        severity: 'low',
        index: 'idx',
        language: 'lucene',
        queryText: 'a:1',
        suppression: { groupBy: ['source.ip'], window: { value: 5, unit: 'MINUTES' } },
      })
    ).toBe(false);
  });

  it('an unregistered mode refuses with the registry message', () => {
    expect(sigmaExportUnavailableReason('sequence', {})).toContain('"sequence"');
    expect(canExportSigma('sequence', {})).toBe(false);
  });
});

describe('parseNativeImport', () => {
  it('round-trips a single exported envelope', () => {
    const text = JSON.stringify(buildNativeEnvelope('stateless', statelessRule()));
    const result = parseNativeImport(text);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.envelopes).toHaveLength(1);
      expect(result.envelopes[0].mode).toBe('stateless');
      expect((result.envelopes[0].rule as any).name).toBe('Admin probe');
    }
  });

  it('round-trips a bulk export array', () => {
    const text = JSON.stringify(
      buildNativeBulkExport([
        { mode: 'stateless', rule: statelessRule() },
        { mode: 'stateful', rule: statefulRule() },
      ])
    );
    const result = parseNativeImport(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.envelopes.map((e) => e.mode)).toEqual(['stateless', 'stateful']);
  });

  it('tolerates a numeric version 1 (hand-edited files)', () => {
    const text = JSON.stringify({
      version: 1,
      kind: 'tlsoc-detection-rule',
      mode: 'stateless',
      rule: statelessRule(),
    });
    expect(parseNativeImport(text).ok).toBe(true);
  });

  it('rejects non-JSON by name', () => {
    const result = parseNativeImport('title: not json');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]).toContain('Not valid JSON');
  });

  it('rejects a FOREIGN kind by name (never silently reinterpreted)', () => {
    const result = parseNativeImport(
      JSON.stringify({ version: '1', kind: 'elastic-security-rule', mode: 'stateless', rule: {} })
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors[0]).toContain('"elastic-security-rule"');
      expect(result.errors[0]).toContain('tlsoc-detection-rule');
    }
  });

  it('rejects an unknown export version by name', () => {
    const result = parseNativeImport(
      JSON.stringify({ version: '2', kind: 'tlsoc-detection-rule', mode: 'stateless', rule: {} })
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]).toContain('version "2"');
  });

  it('rejects an unregistered mode with the registry message naming the id', () => {
    const result = parseNativeImport(
      JSON.stringify({ version: '1', kind: 'tlsoc-detection-rule', mode: 'sequence', rule: {} })
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors[0]).toContain('"sequence"');
      expect(result.errors[0]).toContain('Registered types');
    }
  });

  it('a rule that fails the registry validator surfaces the validator message, named per entry', () => {
    const bad = { ...statelessRule(), group: { logic: 'AND', conditions: [] } };
    const result = parseNativeImport(
      JSON.stringify([
        buildNativeEnvelope('stateless', statelessRule()),
        { version: '1', kind: 'tlsoc-detection-rule', mode: 'stateless', rule: bad },
      ])
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('"Admin probe"'); // the entry's own name
      expect(result.errors[0]).toContain('at least one condition');
    }
  });

  it('rejects an envelope with no rule object, an empty array, and non-object entries', () => {
    const noRule = parseNativeImport(
      JSON.stringify({ version: '1', kind: 'tlsoc-detection-rule', mode: 'stateless' })
    );
    expect(noRule.ok).toBe(false);
    if (!noRule.ok) expect(noRule.errors[0]).toContain('no rule object');

    const empty = parseNativeImport('[]');
    expect(empty.ok).toBe(false);
    if (!empty.ok) expect(empty.errors[0]).toContain('empty array');

    const nonObject = parseNativeImport('[42]');
    expect(nonObject.ok).toBe(false);
    if (!nonObject.ok) expect(nonObject.errors[0]).toContain('not an object');
  });
});
