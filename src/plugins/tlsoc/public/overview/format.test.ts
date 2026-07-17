/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { compactNumber, timeAgo, freshnessColor } from './format';

describe('compactNumber', () => {
  it('formats across magnitudes', () => {
    expect(compactNumber(42)).toBe('42');
    expect(compactNumber(1500)).toBe('1.5k');
    expect(compactNumber(217022)).toBe('217k');
    expect(compactNumber(2_100_000)).toBe('2.1M');
  });
});

describe('timeAgo', () => {
  const now = Date.parse('2026-07-16T12:00:00Z');
  it('renders relative buckets', () => {
    expect(timeAgo('2026-07-16T11:59:30Z', now)).toBe('30s ago');
    expect(timeAgo('2026-07-16T11:45:00Z', now)).toBe('15m ago');
    expect(timeAgo('2026-07-16T09:00:00Z', now)).toBe('3h ago');
    expect(timeAgo('2026-05-16T12:00:00Z', now)).toBe('61d ago');
  });
  it('handles null/garbage', () => {
    expect(timeAgo(null, now)).toBe('—');
    expect(timeAgo('not-a-date', now)).toBe('—');
  });
});

describe('freshnessColor', () => {
  const now = Date.parse('2026-07-16T12:00:00Z');
  it('grades by staleness', () => {
    expect(freshnessColor('2026-07-16T11:58:00Z', now)).toBe('success'); // 2m
    expect(freshnessColor('2026-07-16T11:30:00Z', now)).toBe('subdued'); // 30m
    expect(freshnessColor('2026-05-16T12:00:00Z', now)).toBe('warning'); // months
    expect(freshnessColor(null, now)).toBe('subdued');
  });
});
