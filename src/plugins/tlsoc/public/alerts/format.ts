/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TlsocAlert } from '../../common/alerts';

export function sevColor(label: string): string {
  switch (label) {
    case 'critical':
      return 'danger';
    case 'high':
      return 'warning';
    case 'medium':
      return 'default';
    case 'low':
      return 'hollow';
    default:
      return 'hollow';
  }
}

export function stateColor(state: string): string {
  switch (state) {
    case 'ACTIVE':
      return 'accent';
    case 'ACKNOWLEDGED':
      return 'hollow';
    default:
      return 'default';
  }
}

/** Badge color for a 0-100 rule risk score (WS-1) — same bucket idiom as {@link sevColor}. */
export function riskScoreColor(score: number): string {
  if (score >= 75) return 'danger';
  if (score >= 50) return 'warning';
  if (score >= 25) return 'default';
  return 'hollow';
}

/**
 * WS-18 (PROB-18): bucket-level alerts have no `relatedDocIds` — the "entity" the alert is about
 * is the group-by key(s) that crossed the threshold. Named via `rule.groupBy` when known (e.g.
 * "source.ip · 10.8.0.10"), else the bare bucket key values, comma-joined for multi-field groups.
 */
function bucketEntityOf(a: TlsocAlert): string {
  const keys = a.bucketKeys ?? [];
  const groupBy = a.rule?.groupBy;
  if (!groupBy || groupBy.length === 0) {
    return keys.join(', ');
  }
  return keys.map((value, i) => `${groupBy[i] ?? `group key ${i + 1}`} · ${value}`).join(', ');
}

export function entityOf(a: TlsocAlert): string {
  if (a.bucketKeys?.length) {
    return bucketEntityOf(a);
  }
  if (a.relatedDocIds?.length) {
    const parts = a.relatedDocIds[0].split('|');
    // relatedDocIds look like "docId|index"; show "index · docId"
    if (parts.length >= 2) {
      return `${parts[1]} · ${parts[0]}`;
    }
    return parts[0];
  }
  return '—';
}
