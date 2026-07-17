/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Severity } from '../detection/types';

export type CaseStatus = 'New' | 'Assigned' | 'In Progress' | 'Contained' | 'Closed';

export interface CaseComment {
  id: string;
  author: string;
  text: string;
  createdAt: string;
}

export type CaseActivityType =
  | 'created'
  | 'status_changed'
  | 'edited'
  | 'commented'
  | 'alerts_linked';

export interface CaseActivity {
  id: string;
  type: CaseActivityType;
  actor: string;
  summary: string;
  createdAt: string;
}

export interface CaseAttributes {
  title: string;
  description: string;
  status: CaseStatus;
  severity: Severity;
  assignee: string | null;
  tags: string[];
  linkedAlertIds: string[];
  linkedFindingIds: string[];
  createdFromAlertId?: string;
  comments: CaseComment[];
  activity?: CaseActivity[];
  createdAt: string;
  updatedAt: string;
  category?: string;
  closedAt?: string;
  /** The authenticated user who created the case (the "Reporter"). Server-set (Task 5a.3);
   * absent on pre-5a.3 cases → treated as unknown. */
  createdBy?: string;
}

export interface CaseCreateInput {
  title: string;
  description?: string;
  status?: CaseStatus;
  severity: Severity;
  assignee?: string | null;
  tags?: string[];
  linkedAlertIds?: string[];
  linkedFindingIds?: string[];
  createdFromAlertId?: string;
  category?: string;
}

export type CaseCategory =
  | 'Intrusion'
  | 'Malware'
  | 'Phishing'
  | 'Policy Violation'
  | 'Reconnaissance'
  | 'Other';

export const CASE_CATEGORIES: CaseCategory[] = [
  'Intrusion',
  'Malware',
  'Phishing',
  'Policy Violation',
  'Reconnaissance',
  'Other',
];
