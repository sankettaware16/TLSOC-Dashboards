/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TlsocAlert } from '../alerts';
import { Severity } from '../detection/types';
import { CaseCreateInput } from './types';

const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];

/** Seed a new case from a triaged alert (the alert→case loop-closer). Pure; 4.4 wires the button. */
export function buildCaseFromAlert(alert: TlsocAlert): CaseCreateInput {
  const ruleName = alert?.rule?.name || alert?.monitorName || 'Detection';
  const entity = (alert?.relatedDocIds && alert.relatedDocIds[0]) || alert?.triggerName || '';
  const title = entity ? `${ruleName} — ${entity}` : ruleName;
  const severity: Severity = SEVERITIES.includes(alert?.severityLabel as Severity)
    ? (alert.severityLabel as Severity)
    : 'medium';
  const description = [
    `Auto-seeded from alert ${alert?.id ?? ''}.`,
    `Rule: ${ruleName}${alert?.rule?.mode ? ` (${alert.rule.mode})` : ''}.`,
    alert?.monitorName ? `Monitor: ${alert.monitorName}.` : '',
    alert?.triggerName ? `Trigger: ${alert.triggerName}.` : '',
    entity ? `Entity/doc: ${entity}.` : '',
  ]
    .filter(Boolean)
    .join(' ');
  return {
    title,
    description,
    status: 'New',
    severity,
    linkedAlertIds: alert?.id ? [alert.id] : [],
    linkedFindingIds: Array.isArray(alert?.findingIds) ? alert.findingIds : [],
    createdFromAlertId: alert?.id,
  };
}
