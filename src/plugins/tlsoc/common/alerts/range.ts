/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TlsocAlert } from './types';

/**
 * Filter alerts to those whose `startTime` falls within `[from, to]` (both bounds inclusive).
 * WS-3 (PROB-3): the upstream OpenSearch Alerting get-alerts API has no time parameter at all
 * (verified) — so TLSOC's own `GET /api/tlsoc/alerts` route pages the engine API itself
 * (see `fetchAlertsInRange` in server/routes/alerts.ts) and applies this pure filter server-side.
 *
 * When NEITHER bound is given, no range is active — `alerts` is returned UNCHANGED (this is the
 * "from/to absent → existing behavior byte-identical" contract). When a range IS active (either
 * bound given), alerts with a null `startTime` are EXCLUDED — an alert with no known start time
 * can't be said to fall inside any time window.
 */
export function filterAlertsByRange(
  alerts: TlsocAlert[],
  from?: number,
  to?: number
): TlsocAlert[] {
  if (from === undefined && to === undefined) return alerts;
  const lo = from ?? -Infinity;
  const hi = to ?? Infinity;
  return alerts.filter((a) => a.startTime !== null && a.startTime >= lo && a.startTime <= hi);
}
