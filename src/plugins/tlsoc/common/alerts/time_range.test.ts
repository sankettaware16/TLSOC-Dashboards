/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import moment from 'moment';
import { resolveDateMathRange } from './time_range';

const NOW = new Date('2026-07-17T12:00:00.000Z');

describe('resolveDateMathRange', () => {
  it('resolves a relative range against a fixed forceNow instant', () => {
    const { from, to } = resolveDateMathRange('now-24h', 'now', NOW);
    expect(from).toBe(new Date('2026-07-16T12:00:00.000Z').valueOf());
    expect(to).toBe(NOW.valueOf());
  });

  it('resolves an absolute ISO start/end', () => {
    const { from, to } = resolveDateMathRange(
      '2026-01-01T00:00:00.000Z',
      '2026-01-02T00:00:00.000Z',
      NOW
    );
    expect(from).toBe(new Date('2026-01-01T00:00:00.000Z').valueOf());
    expect(to).toBe(new Date('2026-01-02T00:00:00.000Z').valueOf());
  });

  it('rounds "now/d" style end strings UP (roundUp:true) to the end of the (local) day', () => {
    const { to } = resolveDateMathRange(undefined, 'now/d', NOW);
    // datemath rounds in LOCAL time (no momentInstance override) — compute the expectation the
    // same way rather than hardcoding a UTC literal, so this test is timezone-independent.
    expect(to).toBe(moment(NOW).endOf('day').valueOf());
  });

  it('undefined start/end → undefined bounds (no throw)', () => {
    expect(resolveDateMathRange(undefined, undefined, NOW)).toEqual({
      from: undefined,
      to: undefined,
    });
  });

  it('empty-string start/end → undefined bounds', () => {
    expect(resolveDateMathRange('', '', NOW)).toEqual({ from: undefined, to: undefined });
  });

  it('an unparseable string resolves to undefined for that bound (never throws)', () => {
    expect(() => resolveDateMathRange('not-a-date', 'now', NOW)).not.toThrow();
    const { from, to } = resolveDateMathRange('not-a-date', 'now', NOW);
    expect(from).toBeUndefined();
    expect(to).toBe(NOW.valueOf());
  });

  it('resolves against the REAL current instant when no forceNow is given', () => {
    const before = Date.now();
    const { to } = resolveDateMathRange(undefined, 'now');
    const after = Date.now();
    expect(to).toBeGreaterThanOrEqual(before);
    expect(to).toBeLessThanOrEqual(after);
  });

  it('a longer relative window (30 days) resolves correctly', () => {
    const { from } = resolveDateMathRange('now-30d', 'now', NOW);
    expect(from).toBe(NOW.valueOf() - 30 * 24 * 60 * 60 * 1000);
  });
});
