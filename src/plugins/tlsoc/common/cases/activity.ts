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
  'alerts_acknowledged',
  'alerts_reopened',
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

/**
 * Close-time acknowledge summary (PROB-24). Reports what actually happened — including the
 * partial-failure case — so the audit trail never overstates ("acknowledged all") what a flaky
 * Alerting call may have only partly done.
 */
export function describeAlertsAcknowledged(acked: number, failed: number): string {
  const ackedPart = acked === 1 ? 'Acknowledged 1 linked alert' : `Acknowledged ${acked} linked alerts`;
  if (failed <= 0) return `${ackedPart} on close`;
  return `${ackedPart} on close (${failed} could not be acknowledged)`;
}

/**
 * Reopen-time reactivation summary (PROB-29). Mirrors {@link describeAlertsAcknowledged}: reports
 * exactly what happened — including the partial-failure case — so the trail never overstates how
 * many linked alerts a reopen actually reactivated via the TLSOC display override.
 */
export function describeAlertsReopened(reopened: number, failed = 0): string {
  const part =
    reopened === 1 ? 'Reactivated 1 linked alert' : `Reactivated ${reopened} linked alerts`;
  if (failed <= 0) return `${part} on reopen`;
  return `${part} on reopen (${failed} could not be reactivated)`;
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
