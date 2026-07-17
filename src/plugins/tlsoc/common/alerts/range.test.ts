/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { filterAlertsByRange } from './range';
import { TlsocAlert } from './types';

function alertAt(id: string, startTime: number | null): TlsocAlert {
  return {
    id,
    monitorId: 'm1',
    monitorName: 'monitor',
    triggerName: 'trigger',
    state: 'ACTIVE',
    severity: '2',
    severityLabel: 'high',
    findingIds: [],
    relatedDocIds: [],
    startTime,
    lastNotificationTime: null,
    acknowledgedTime: null,
    endTime: null,
    errorMessage: null,
    rule: null,
    ruleKnown: false,
  };
}

describe('filterAlertsByRange', () => {
  const alerts = [alertAt('a', 100), alertAt('b', 200), alertAt('c', 300), alertAt('d', null)];

  it('neither bound given → returns the SAME array unchanged (byte-identical pass-through)', () => {
    expect(filterAlertsByRange(alerts)).toBe(alerts);
    expect(filterAlertsByRange(alerts, undefined, undefined)).toBe(alerts);
  });

  it('from only → keeps startTime >= from, drops earlier and null', () => {
    const result = filterAlertsByRange(alerts, 200);
    expect(result.map((a) => a.id)).toEqual(['b', 'c']);
  });

  it('to only → keeps startTime <= to, drops later and null', () => {
    const result = filterAlertsByRange(alerts, undefined, 200);
    expect(result.map((a) => a.id)).toEqual(['a', 'b']);
  });

  it('both bounds → keeps startTime in [from, to] inclusive, drops null', () => {
    const result = filterAlertsByRange(alerts, 100, 200);
    expect(result.map((a) => a.id)).toEqual(['a', 'b']);
  });

  it('boundaries are INCLUSIVE on both ends', () => {
    expect(filterAlertsByRange(alerts, 100, 100).map((a) => a.id)).toEqual(['a']);
    expect(filterAlertsByRange(alerts, 300, 300).map((a) => a.id)).toEqual(['c']);
  });

  it('null startTime is EXCLUDED whenever a range is active', () => {
    expect(filterAlertsByRange(alerts, 0).some((a) => a.id === 'd')).toBe(false);
    expect(filterAlertsByRange(alerts, undefined, 1000).some((a) => a.id === 'd')).toBe(false);
  });

  it('a range matching nothing → empty array', () => {
    expect(filterAlertsByRange(alerts, 1000, 2000)).toEqual([]);
  });

  it('empty input array → empty output, regardless of range', () => {
    expect(filterAlertsByRange([], 0, 100)).toEqual([]);
    expect(filterAlertsByRange([])).toEqual([]);
  });
});
