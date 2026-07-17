/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TlsocAlert } from '../../common/alerts';

// Lower rank = shown first. Unacknowledged (ACTIVE) first; ERROR next; then ACKNOWLEDGED/COMPLETED/DELETED.
const STATE_RANK: Record<string, number> = {
  ACTIVE: 0,
  ERROR: 1,
  ACKNOWLEDGED: 2,
  COMPLETED: 3,
  DELETED: 4,
};

const SEV_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

export function compareAlerts(a: TlsocAlert, b: TlsocAlert): number {
  const s = (STATE_RANK[a.state] ?? 9) - (STATE_RANK[b.state] ?? 9);
  if (s !== 0) return s;
  const sev = (SEV_RANK[a.severityLabel] ?? 9) - (SEV_RANK[b.severityLabel] ?? 9);
  if (sev !== 0) return sev;
  return (b.startTime ?? 0) - (a.startTime ?? 0); // newest first
}

export function sortAlerts(alerts: TlsocAlert[]): TlsocAlert[] {
  return [...alerts].sort(compareAlerts);
}
