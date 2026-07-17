/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { CaseStatus } from './types';

export const CASE_STATUSES: CaseStatus[] = ['New', 'Assigned', 'In Progress', 'Contained', 'Closed'];

export const ALLOWED_TRANSITIONS: Record<CaseStatus, CaseStatus[]> = {
  New: ['Assigned', 'In Progress', 'Closed'],
  Assigned: ['In Progress', 'New', 'Closed'],
  'In Progress': ['Contained', 'Assigned', 'Closed'],
  Contained: ['Closed', 'In Progress'],
  Closed: ['In Progress'],
};

export function canTransition(from: CaseStatus, to: CaseStatus): boolean {
  if (from === to) return true; // same-status no-op always allowed
  return (ALLOWED_TRANSITIONS[from] ?? []).includes(to);
}

export function assertTransition(from: CaseStatus, to: CaseStatus): void {
  if (!CASE_STATUSES.includes(to)) {
    throw new Error(`"${to}" is not a valid case status. Valid: ${CASE_STATUSES.join(', ')}.`);
  }
  if (!canTransition(from, to)) {
    const allowed = [from, ...(ALLOWED_TRANSITIONS[from] ?? [])];
    throw new Error(
      `Cannot move a case from "${from}" to "${to}". Allowed next states: ${allowed.join(', ')}.`
    );
  }
}

/**
 * Returns the current status (first element) followed by all valid next statuses.
 * Used in the UI to populate a status-change select that only shows legal transitions.
 */
export function nextStatuses(current: CaseStatus): CaseStatus[] {
  return [current, ...(ALLOWED_TRANSITIONS[current] ?? [])];
}
