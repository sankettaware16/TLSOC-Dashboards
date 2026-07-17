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

export function entityOf(a: TlsocAlert): string {
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
