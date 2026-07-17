/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { CaseStatus } from './types';

export interface CaseSummaryInput {
  status: CaseStatus;
  createdAt: string;
  closedAt?: string;
}

export interface CaseSummary {
  open: number;
  inProgress: number;
  closed: number;
  avgTimeToCloseMs: number | null;
}

/**
 * Bucket counts for the list stat-cards.
 * open = all non-Closed; inProgress = status 'In Progress'; closed = Closed.
 * avgTimeToCloseMs = mean(closedAt - createdAt) over Closed cases that HAVE a closedAt, else null.
 */
export function summarizeCases(rows: CaseSummaryInput[]): CaseSummary {
  let open = 0;
  let inProgress = 0;
  let closed = 0;
  const durations: number[] = [];

  for (const r of rows) {
    if (r.status === 'Closed') {
      closed++;
      if (r.closedAt && r.createdAt) {
        const d = new Date(r.closedAt).getTime() - new Date(r.createdAt).getTime();
        if (!Number.isNaN(d) && d >= 0) durations.push(d);
      }
    } else {
      open++;
      if (r.status === 'In Progress') inProgress++;
    }
  }

  const avgTimeToCloseMs = durations.length
    ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length)
    : null;

  return { open, inProgress, closed, avgTimeToCloseMs };
}

/**
 * How long a case has been open, in ms: createdAt → closedAt if the case is closed,
 * else createdAt → now. `nowMs` is passed in (Date.now() at the call site) so this stays
 * pure and unit-testable. Clamps invalid/negative spans to 0 so formatDuration renders cleanly.
 */
export function caseOpenDurationMs(
  createdAt: string,
  closedAt: string | null | undefined,
  nowMs: number
): number {
  const start = new Date(createdAt).getTime();
  if (Number.isNaN(start)) return 0;
  const end = closedAt ? new Date(closedAt).getTime() : nowMs;
  if (Number.isNaN(end)) return 0;
  const ms = end - start;
  return ms > 0 ? ms : 0;
}

/** Human duration: "2d 3h" / "21h" / "5m" / "—" for null/invalid. */
export function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined || Number.isNaN(ms) || ms < 0) return '—';
  const sec = Math.floor(ms / 1000);
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  if (m > 0) return `${m}m`;
  return `${sec}s`;
}
