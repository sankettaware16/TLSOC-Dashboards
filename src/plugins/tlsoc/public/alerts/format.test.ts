/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { entityOf, riskScoreColor } from './format';
import { TlsocAlert } from '../../common/alerts';

describe('riskScoreColor', () => {
  it('>=75 → danger', () => {
    expect(riskScoreColor(75)).toBe('danger');
    expect(riskScoreColor(100)).toBe('danger');
  });
  it('50-74 → warning', () => {
    expect(riskScoreColor(50)).toBe('warning');
    expect(riskScoreColor(74)).toBe('warning');
  });
  it('25-49 → default', () => {
    expect(riskScoreColor(25)).toBe('default');
    expect(riskScoreColor(49)).toBe('default');
  });
  it('<25 → hollow', () => {
    expect(riskScoreColor(0)).toBe('hollow');
    expect(riskScoreColor(24)).toBe('hollow');
  });
});

function baseAlert(overrides: Partial<TlsocAlert> = {}): TlsocAlert {
  return {
    id: 'a1',
    monitorId: 'm1',
    monitorName: 'monitor-name',
    triggerName: 'trigger',
    state: 'ACTIVE',
    severity: '2',
    severityLabel: 'high',
    findingIds: [],
    relatedDocIds: [],
    startTime: null,
    lastNotificationTime: null,
    acknowledgedTime: null,
    endTime: null,
    errorMessage: null,
    rule: null,
    ruleKnown: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// WS-18 (PROB-18): entityOf — bucket-level alerts.
// ---------------------------------------------------------------------------
describe('entityOf — bucket-level alerts', () => {
  it('groupBy known → "field · value" pairs, comma-joined', () => {
    const alert = baseAlert({
      bucketKeys: ['10.8.0.10'],
      rule: { soId: 'so1', name: 'r', mode: 'stateful', index: 'i-*', groupBy: ['source.ip'] },
    });
    expect(entityOf(alert)).toBe('source.ip · 10.8.0.10');
  });

  it('multi-field groupBy → all pairs comma-joined', () => {
    const alert = baseAlert({
      bucketKeys: ['10.8.0.10', 'jdoe'],
      rule: {
        soId: 'so1',
        name: 'r',
        mode: 'stateful',
        index: 'i-*',
        groupBy: ['source.ip', 'user.name'],
      },
    });
    expect(entityOf(alert)).toBe('source.ip · 10.8.0.10, user.name · jdoe');
  });

  it('rule/groupBy absent → falls back to bare comma-joined keys', () => {
    const alert = baseAlert({ bucketKeys: ['10.8.0.10', '20.20.20.20'] });
    expect(entityOf(alert)).toBe('10.8.0.10, 20.20.20.20');
  });

  it('bucketKeys takes priority over relatedDocIds when both are present', () => {
    const alert = baseAlert({
      bucketKeys: ['10.8.0.10'],
      relatedDocIds: ['doc1|idx'],
      rule: { soId: 'so1', name: 'r', mode: 'stateful', index: 'i-*', groupBy: ['source.ip'] },
    });
    expect(entityOf(alert)).toBe('source.ip · 10.8.0.10');
  });
});

// ---------------------------------------------------------------------------
// entityOf — doc-level alerts (byte-identical to pre-WS-18 behavior).
// ---------------------------------------------------------------------------
describe('entityOf — doc-level alerts (unchanged)', () => {
  it('relatedDocIds "docId|index" → "index · docId"', () => {
    const alert = baseAlert({ relatedDocIds: ['abc123|logs-*'] });
    expect(entityOf(alert)).toBe('logs-* · abc123');
  });

  it('relatedDocIds with no "|" separator → the bare id', () => {
    const alert = baseAlert({ relatedDocIds: ['abc123'] });
    expect(entityOf(alert)).toBe('abc123');
  });

  it('no bucketKeys, no relatedDocIds → em dash', () => {
    const alert = baseAlert();
    expect(entityOf(alert)).toBe('—');
  });
});
