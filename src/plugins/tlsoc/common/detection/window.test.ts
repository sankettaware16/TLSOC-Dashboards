/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { buildWindow } from './window';
import { TimeWindow } from './types';

const ABBREV: Record<TimeWindow['unit'], string> = { MINUTES: 'm', HOURS: 'h', DAYS: 'd' };
const FROM_ABBREV: Record<string, TimeWindow['unit']> = { m: 'MINUTES', h: 'HOURS', d: 'DAYS' };

const cases: TimeWindow[] = [
  { value: 1, unit: 'MINUTES' },
  { value: 5, unit: 'MINUTES' },
  { value: 15, unit: 'MINUTES' },
  { value: 1, unit: 'HOURS' },
  { value: 24, unit: 'HOURS' },
  { value: 1, unit: 'DAYS' },
  { value: 7, unit: 'DAYS' },
];

describe('buildWindow — single source of truth for T', () => {
  it('derives schedule, range-from and timespan from one window', () => {
    const w = buildWindow({ value: 5, unit: 'MINUTES' });
    expect(w.schedule).toEqual({ period: { interval: 5, unit: 'MINUTES' } });
    expect(w.rangeFrom).toBe('{{period_end}}||-5m');
    expect(w.timespan).toBe('5m');
  });

  // The window-sync guarantee: across many T, the schedule period and the range-filter date-math must
  // always encode the SAME window — parse the integer + unit out of BOTH and assert they agree.
  it.each(cases)('schedule and range-from stay in lockstep for %o', (window) => {
    const w = buildWindow(window);
    expect(w.rangeFrom).toBe(`{{period_end}}||-${window.value}${ABBREV[window.unit]}`);
    expect(w.timespan).toBe(`${window.value}${ABBREV[window.unit]}`);

    const match = w.rangeFrom.match(/-(\d+)([mhd])$/);
    expect(match).not.toBeNull();
    const [, amount, abbrev] = match!;
    expect(Number(amount)).toBe(w.schedule.period.interval);
    expect(FROM_ABBREV[abbrev]).toBe(w.schedule.period.unit);
  });
});

describe('buildWindow(window, runEvery) — R drives the schedule ONLY, T still drives rangeFrom/timespan', () => {
  it('single-arg call equals passing runEvery as undefined (legacy default is byte-identical)', () => {
    for (const window of cases) {
      expect(buildWindow(window)).toEqual(buildWindow(window, undefined));
    }
  });

  it('R < T (both MINUTES): schedule takes R, rangeFrom/timespan stay on T', () => {
    const window: TimeWindow = { value: 15, unit: 'MINUTES' };
    const runEvery: TimeWindow = { value: 5, unit: 'MINUTES' };
    const w = buildWindow(window, runEvery);
    expect(w.schedule).toEqual({ period: { interval: 5, unit: 'MINUTES' } });
    expect(w.rangeFrom).toBe('{{period_end}}||-15m');
    expect(w.timespan).toBe('15m');
  });

  it('R in HOURS, T in DAYS: schedule takes R (in its own unit), rangeFrom/timespan stay on T', () => {
    const window: TimeWindow = { value: 1, unit: 'DAYS' };
    const runEvery: TimeWindow = { value: 6, unit: 'HOURS' };
    const w = buildWindow(window, runEvery);
    expect(w.schedule).toEqual({ period: { interval: 6, unit: 'HOURS' } });
    expect(w.rangeFrom).toBe('{{period_end}}||-1d');
    expect(w.timespan).toBe('1d');
  });
});
