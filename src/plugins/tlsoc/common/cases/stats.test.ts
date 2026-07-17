/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { summarizeCases, formatDuration, caseOpenDurationMs } from './stats';

describe('summarizeCases', () => {
  it('returns all zeros for an empty array', () => {
    expect(summarizeCases([])).toEqual({
      open: 0,
      inProgress: 0,
      closed: 0,
      avgTimeToCloseMs: null,
    });
  });

  it('correctly buckets a mixed set of statuses', () => {
    // New, Assigned, In Progress (open=3, inProgress=1), Contained (open=4),
    // Closed with valid closedAt (closed=1, duration=10000ms),
    // Closed without closedAt (closed=2, excluded from avg)
    const rows = [
      { status: 'New' as const, createdAt: '2026-01-01T00:00:00.000Z' },
      { status: 'Assigned' as const, createdAt: '2026-01-01T00:00:00.000Z' },
      { status: 'In Progress' as const, createdAt: '2026-01-01T00:00:00.000Z' },
      { status: 'Contained' as const, createdAt: '2026-01-01T00:00:00.000Z' },
      {
        status: 'Closed' as const,
        createdAt: '2026-01-01T00:00:00.000Z',
        closedAt: '2026-01-01T00:00:10.000Z', // +10000ms
      },
      {
        status: 'Closed' as const,
        createdAt: '2026-01-01T00:00:00.000Z',
        // no closedAt — excluded from avg
      },
    ];

    const result = summarizeCases(rows);
    expect(result.open).toBe(4); // New + Assigned + In Progress + Contained
    expect(result.inProgress).toBe(1);
    expect(result.closed).toBe(2);
    expect(result.avgTimeToCloseMs).toBe(10000); // only the one valid duration
  });

  it('returns avgTimeToCloseMs null when all Closed cases lack closedAt', () => {
    const rows = [
      { status: 'Closed' as const, createdAt: '2026-01-01T00:00:00.000Z' },
      { status: 'Closed' as const, createdAt: '2026-01-01T00:00:00.000Z' },
    ];
    const result = summarizeCases(rows);
    expect(result.closed).toBe(2);
    expect(result.avgTimeToCloseMs).toBeNull();
  });

  it('ignores a Closed case whose closedAt < createdAt in the average', () => {
    const rows = [
      {
        status: 'Closed' as const,
        createdAt: '2026-01-01T01:00:00.000Z',
        closedAt: '2026-01-01T00:00:00.000Z', // closedAt BEFORE createdAt — invalid
      },
      {
        status: 'Closed' as const,
        createdAt: '2026-01-01T00:00:00.000Z',
        closedAt: '2026-01-01T00:05:00.000Z', // +300000ms
      },
    ];
    const result = summarizeCases(rows);
    expect(result.closed).toBe(2);
    expect(result.avgTimeToCloseMs).toBe(300000);
  });

  it('averages multiple valid durations', () => {
    const rows = [
      {
        status: 'Closed' as const,
        createdAt: '2026-01-01T00:00:00.000Z',
        closedAt: '2026-01-01T00:00:02.000Z', // 2000ms
      },
      {
        status: 'Closed' as const,
        createdAt: '2026-01-01T00:00:00.000Z',
        closedAt: '2026-01-01T00:00:04.000Z', // 4000ms
      },
    ];
    const result = summarizeCases(rows);
    expect(result.avgTimeToCloseMs).toBe(3000); // avg of 2000 and 4000
  });
});

describe('formatDuration', () => {
  it('formats days and hours: 2d 3h', () => {
    expect(formatDuration(2 * 86400e3 + 3 * 3600e3)).toBe('2d 3h');
  });

  it('formats hours only: 21h', () => {
    expect(formatDuration(21 * 3600e3)).toBe('21h');
  });

  it('formats minutes only: 5m', () => {
    expect(formatDuration(5 * 60e3)).toBe('5m');
  });

  it('formats seconds when less than a minute', () => {
    expect(formatDuration(30000)).toBe('30s');
  });

  it('returns — for null', () => {
    expect(formatDuration(null)).toBe('—');
  });

  it('returns — for negative values', () => {
    expect(formatDuration(-5)).toBe('—');
  });

  it('formats days without hours when h=0: 2d', () => {
    expect(formatDuration(2 * 86400e3)).toBe('2d');
  });

  it('formats hours with minutes: 2h 30m', () => {
    expect(formatDuration(2 * 3600e3 + 30 * 60e3)).toBe('2h 30m');
  });
});

describe('caseOpenDurationMs', () => {
  const created = '2026-06-25T00:00:00.000Z';

  it('open case (no closedAt): createdAt → now', () => {
    const now = new Date('2026-06-25T00:05:00.000Z').getTime();
    expect(caseOpenDurationMs(created, undefined, now)).toBe(5 * 60e3);
  });

  it('treats null closedAt as open (createdAt → now)', () => {
    const now = new Date('2026-06-25T00:05:00.000Z').getTime();
    expect(caseOpenDurationMs(created, null, now)).toBe(5 * 60e3);
  });

  it('closed case: createdAt → closedAt, ignoring now', () => {
    const closed = '2026-06-25T02:00:00.000Z';
    const now = new Date('2026-06-25T10:00:00.000Z').getTime(); // far later — must be ignored
    expect(caseOpenDurationMs(created, closed, now)).toBe(2 * 3600e3);
  });

  it('clamps a negative span (createdAt in the future) to 0', () => {
    const now = new Date('2026-06-24T23:00:00.000Z').getTime(); // before created
    expect(caseOpenDurationMs(created, undefined, now)).toBe(0);
  });

  it('returns 0 for an invalid createdAt', () => {
    expect(caseOpenDurationMs('not-a-date', undefined, 1000)).toBe(0);
  });
});
