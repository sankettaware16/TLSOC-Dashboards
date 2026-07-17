/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TlsocAlert } from '../alerts';
import { buildCaseFromAlert } from './seed';

/** Build a realistic TlsocAlert for test fixtures. */
function makeAlert(overrides: Partial<TlsocAlert> = {}): TlsocAlert {
  return {
    id: 'a1',
    monitorId: 'mon1',
    monitorName: 'iptrigger',
    triggerName: 'iptrigger matched',
    state: 'ACTIVE',
    severity: '2',
    severityLabel: 'high',
    findingIds: ['f1', 'f2'],
    relatedDocIds: ['doc1|idx'],
    startTime: 1000,
    lastNotificationTime: 2000,
    acknowledgedTime: null,
    endTime: null,
    errorMessage: null,
    rule: {
      soId: 'so1',
      name: 'iptrigger',
      mode: 'stateless',
      index: 'foo-*',
    },
    ruleKnown: true,
    ...overrides,
  };
}

describe('buildCaseFromAlert — baseline alert', () => {
  const alert = makeAlert();
  const result = buildCaseFromAlert(alert);

  it('title contains the rule name "iptrigger"', () => {
    expect(result.title).toContain('iptrigger');
  });

  it('title contains the entity from relatedDocIds[0]', () => {
    expect(result.title).toContain('doc1|idx');
  });

  it('severity is "high" (from severityLabel)', () => {
    expect(result.severity).toBe('high');
  });

  it('status is "New"', () => {
    expect(result.status).toBe('New');
  });

  it('linkedAlertIds contains the alert id', () => {
    expect(result.linkedAlertIds).toEqual(['a1']);
  });

  it('linkedFindingIds matches findingIds', () => {
    expect(result.linkedFindingIds).toEqual(['f1', 'f2']);
  });

  it('createdFromAlertId is the alert id', () => {
    expect(result.createdFromAlertId).toBe('a1');
  });

  it('description is a non-empty string mentioning the rule name', () => {
    expect(typeof result.description).toBe('string');
    expect(result.description!.length).toBeGreaterThan(0);
    expect(result.description).toContain('iptrigger');
  });
});

describe('buildCaseFromAlert — severity fallback', () => {
  it('severityLabel "unknown" falls back to severity "medium"', () => {
    const result = buildCaseFromAlert(makeAlert({ severityLabel: 'unknown' }));
    expect(result.severity).toBe('medium');
  });

  it('severityLabel "low" maps through correctly', () => {
    const result = buildCaseFromAlert(makeAlert({ severityLabel: 'low' }));
    expect(result.severity).toBe('low');
  });

  it('severityLabel "critical" maps through correctly', () => {
    const result = buildCaseFromAlert(makeAlert({ severityLabel: 'critical' }));
    expect(result.severity).toBe('critical');
  });
});

describe('buildCaseFromAlert — rule null falls back to monitorName', () => {
  it('title uses monitorName when rule is null', () => {
    const result = buildCaseFromAlert(makeAlert({ rule: null, ruleKnown: false }));
    expect(result.title).toContain('iptrigger');
  });
});

describe('buildCaseFromAlert — missing findingIds', () => {
  it('linkedFindingIds is [] when findingIds is undefined', () => {
    // Cast to bypass TS to simulate a partial/malformed alert at runtime
    const result = buildCaseFromAlert(makeAlert({ findingIds: undefined as any }));
    expect(result.linkedFindingIds).toEqual([]);
  });
});

describe('buildCaseFromAlert — empty relatedDocIds falls back to triggerName', () => {
  it('title uses triggerName as entity when relatedDocIds is empty', () => {
    const result = buildCaseFromAlert(makeAlert({ relatedDocIds: [] }));
    expect(result.title).toContain('iptrigger matched');
  });
});
