/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** Compact number: 1234 -> "1.2k", 2_100_000 -> "2.1M". */
export function compactNumber(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

/**
 * Relative "time ago" from an ISO string, e.g. "3m ago", "2d ago". `nowMs` is injectable so
 * this stays pure/testable. Returns "—" for null/unparseable input.
 */
export function timeAgo(iso: string | null | undefined, nowMs: number): string {
  if (!iso) return '—';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '—';
  const diff = Math.max(0, nowMs - then);
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

/** Freshness color: fresh (<5m) success, <1h default, older warning. */
export function freshnessColor(iso: string | null | undefined, nowMs: number): 'success' | 'subdued' | 'warning' {
  if (!iso) return 'subdued';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return 'subdued';
  const min = (nowMs - then) / 60000;
  if (min < 5) return 'success';
  if (min < 60) return 'subdued';
  return 'warning';
}
