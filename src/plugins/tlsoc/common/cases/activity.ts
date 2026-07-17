/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { CaseActivity, CaseActivityType, CaseStatus } from './types';

export const ACTIVITY_TYPES: CaseActivityType[] = [
  'created',
  'status_changed',
  'edited',
  'commented',
  'alerts_linked',
];

/** Human-readable summary builders (pure — the testable core). */
export function describeCreated(opts?: { fromAlert?: boolean }): string {
  return opts?.fromAlert ? 'Created the case from an alert' : 'Created the case';
}

export function describeStatusChange(from: CaseStatus, to: CaseStatus): string {
  return `Status changed from ${from} to ${to}`;
}

export function describeEdit(changedFields: string[]): string {
  if (!changedFields || changedFields.length === 0) return 'Updated the case';
  return `Updated ${changedFields.join(', ')}`;
}

export function describeComment(): string {
  return 'Added a comment';
}

export function describeAlertsLinked(count: number): string {
  return count === 1 ? 'Linked 1 alert' : `Linked ${count} alerts`;
}

/** Pure entry builder; id + createdAt supplied by the caller (route) so this stays pure. */
export function buildActivity(
  type: CaseActivityType,
  summary: string,
  actor: string,
  id: string,
  createdAt: string
): CaseActivity {
  return { id, type, actor, summary, createdAt };
}

/** Immutable append of one entry. */
export function appendActivity(
  existing: CaseActivity[] | undefined,
  entry: CaseActivity
): CaseActivity[] {
  return [...(existing ?? []), entry];
}
