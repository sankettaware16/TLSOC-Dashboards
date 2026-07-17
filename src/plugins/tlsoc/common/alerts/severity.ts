/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Severity } from '../detection/types';

/**
 * Inverse of `SEVERITY_TO_MONITOR_SEVERITY` (from `common/detection/internal`):
 * OpenSearch Alerting numeric severity string → TLSOC human-readable label.
 *
 * The exact inverse relationship is enforced by `severity.test.ts` — both maps are
 * checked in both directions so they cannot silently drift apart.
 */
export const MONITOR_SEVERITY_TO_SEVERITY: Record<string, Severity> = {
  '1': 'critical',
  '2': 'high',
  '3': 'medium',
  '4': 'low',
};

/**
 * Map a raw Alerting severity string (e.g. "1") to a TLSOC severity label.
 * Returns 'unknown' when the value is absent or unrecognised.
 */
export function severityLabel(raw: string | undefined | null): Severity | 'unknown' {
  return (raw != null && MONITOR_SEVERITY_TO_SEVERITY[raw]) || 'unknown';
}
