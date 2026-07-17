/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TlsocAlert } from '../../common/alerts';
import { sortAlerts } from './sort';

/** Build a minimal TlsocAlert fixture — only the fields compareAlerts uses plus required stubs. */
function makeAlert(
  id: string,
  state: TlsocAlert['state'],
  severityLabel: TlsocAlert['severityLabel'],
  startTime: number | null
): TlsocAlert {
  return {
    id,
    monitorId: 'mon-1',
    monitorName: 'Test Monitor',
    triggerName: 'Test Trigger',
    state,
    severity: '1',
    severityLabel,
    findingIds: [],
    relatedDocIds: [],
    startTime,
    lastNotificationTime: null,
    acknowledgedTime: null,
    endTime: null,
    errorMessage: null,
    rule: null,
    ruleKnown: false,
  } as TlsocAlert;
}

describe('sortAlerts', () => {
  it('places all ACTIVE alerts before all ACKNOWLEDGED alerts', () => {
    const ack1 = makeAlert('ack1', 'ACKNOWLEDGED', 'critical', 3000);
    const active1 = makeAlert('active1', 'ACTIVE', 'low', 1000);
    const ack2 = makeAlert('ack2', 'ACKNOWLEDGED', 'high', 2000);
    const active2 = makeAlert('active2', 'ACTIVE', 'medium', 500);

    const result = sortAlerts([ack1, active1, ack2, active2]);

    const states = result.map((a) => a.state);
    const lastActiveIdx = states.lastIndexOf('ACTIVE');
    const firstAckIdx = states.indexOf('ACKNOWLEDGED');
    expect(lastActiveIdx).toBeLessThan(firstAckIdx);
  });

  it('within the same state, orders critical before high before low', () => {
    const low = makeAlert('low', 'ACTIVE', 'low', 1000);
    const critical = makeAlert('critical', 'ACTIVE', 'critical', 1000);
    const high = makeAlert('high', 'ACTIVE', 'high', 1000);

    const result = sortAlerts([low, critical, high]);

    expect(result.map((a) => a.severityLabel)).toEqual(['critical', 'high', 'low']);
  });

  it('within the same state and severity, orders larger startTime first (newest)', () => {
    const older = makeAlert('older', 'ACTIVE', 'high', 1000);
    const newer = makeAlert('newer', 'ACTIVE', 'high', 5000);
    const mid = makeAlert('mid', 'ACTIVE', 'high', 3000);

    const result = sortAlerts([older, newer, mid]);

    expect(result.map((a) => a.id)).toEqual(['newer', 'mid', 'older']);
  });

  it('handles null startTime (sorts to the back within same state+severity)', () => {
    const withTime = makeAlert('withTime', 'ACTIVE', 'medium', 9999);
    const nullTime = makeAlert('nullTime', 'ACTIVE', 'medium', null);

    const result = sortAlerts([nullTime, withTime]);

    expect(result[0].id).toBe('withTime');
    expect(result[1].id).toBe('nullTime');
  });

  it('orders full state rank: ACTIVE < ERROR < ACKNOWLEDGED < COMPLETED < DELETED', () => {
    const deleted = makeAlert('deleted', 'DELETED', 'high', 1000);
    const completed = makeAlert('completed', 'COMPLETED', 'high', 1000);
    const acked = makeAlert('acked', 'ACKNOWLEDGED', 'high', 1000);
    const error = makeAlert('error', 'ERROR', 'high', 1000);
    const active = makeAlert('active', 'ACTIVE', 'high', 1000);

    const result = sortAlerts([deleted, completed, acked, error, active]);

    expect(result.map((a) => a.state)).toEqual([
      'ACTIVE',
      'ERROR',
      'ACKNOWLEDGED',
      'COMPLETED',
      'DELETED',
    ]);
  });
});
