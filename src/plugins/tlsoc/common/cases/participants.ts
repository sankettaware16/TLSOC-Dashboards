/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { CaseActivity, CaseComment } from './types';

/** The minimal shape needed to derive a case's people (a subset of CaseAttributes). */
export interface ParticipantsInput {
  createdBy?: string;
  assignee?: string | null;
  comments?: CaseComment[];
  activity?: CaseActivity[];
}

/**
 * The "Reporter" = the case creator (`createdBy`, server-set since 5a.3). Undefined for
 * pre-5a.3 cases that were created before identity flowed (their creator is genuinely unknown).
 */
export function caseReporter(c: Pick<ParticipantsInput, 'createdBy'>): string | undefined {
  return c.createdBy && c.createdBy.trim() ? c.createdBy : undefined;
}

/**
 * Every distinct person who touched the case — creator + assignee + comment authors +
 * activity actors — deduped and sorted (Task 5a.5). Empty/blank values are dropped. Records
 * exactly what is stored (including the legacy 'analyst' placeholder on pre-5a.3 activity),
 * so the view is honest about what identity was captured.
 */
export function deriveParticipants(c: ParticipantsInput): string[] {
  const set = new Set<string>();
  const add = (v?: string | null) => {
    if (v && v.trim()) set.add(v);
  };
  add(c.createdBy);
  add(c.assignee ?? undefined);
  for (const cm of c.comments ?? []) add(cm.author);
  for (const a of c.activity ?? []) add(a.actor);
  return Array.from(set).sort((x, y) => x.localeCompare(y));
}
