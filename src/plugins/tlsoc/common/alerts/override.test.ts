/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { applyAlertOverride, effectiveAlertState } from './override';
import { AlertOverrideAttributes, AlertState, TlsocAlert } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const baseAlert = (state: AlertState): TlsocAlert => ({
  id: 'alert-1',
  monitorId: 'm1',
  monitorName: 'Brute force',
  triggerName: 'threshold',
  state,
  severity: '2',
  severityLabel: 'high',
  findingIds: [],
  relatedDocIds: [],
  startTime: 1,
  lastNotificationTime: null,
  acknowledgedTime: null,
  endTime: null,
  errorMessage: null,
  rule: null,
  ruleKnown: false,
});

const override: AlertOverrideAttributes = {
  alertId: 'alert-1',
  caseId: 'c-1',
  caseName: 'Brute force from 10.8.0.10',
  monitorId: 'm1',
  reopenedAt: '2026-07-21T00:00:00.000Z',
  reopenedBy: 'analyst',
};

describe('applyAlertOverride (PROB-29)', () => {
  it('attaches reopenedFromCase to an ACKNOWLEDGED alert with a live override (not stale)', () => {
    const { alert, stale } = applyAlertOverride(baseAlert('ACKNOWLEDGED'), override);
    expect(stale).toBe(false);
    expect(alert.reopenedFromCase).toEqual({
      caseId: 'c-1',
      caseName: 'Brute force from 10.8.0.10',
      reopenedAt: '2026-07-21T00:00:00.000Z',
    });
    // The real engine state is NEVER mutated — honesty invariant.
    expect(alert.state).toBe('ACKNOWLEDGED');
  });

  it('does NOT carry the actor/monitorId into the client-facing projection', () => {
    const { alert } = applyAlertOverride(baseAlert('ACKNOWLEDGED'), override);
    expect(alert.reopenedFromCase).not.toHaveProperty('reopenedBy');
    expect(alert.reopenedFromCase).not.toHaveProperty('monitorId');
  });

  it('engine-COMPLETE wins: a COMPLETED alert keeps its state, gets NO badge, override flagged stale', () => {
    const { alert, stale } = applyAlertOverride(baseAlert('COMPLETED'), override);
    expect(stale).toBe(true);
    expect(alert.reopenedFromCase).toBeUndefined();
    expect(alert.state).toBe('COMPLETED');
  });

  it('engine-ACTIVE wins: an ACTIVE alert is never overridden, override flagged stale', () => {
    const { alert, stale } = applyAlertOverride(baseAlert('ACTIVE'), override);
    expect(stale).toBe(true);
    expect(alert.reopenedFromCase).toBeUndefined();
    expect(alert.state).toBe('ACTIVE');
  });

  it('DELETED engine state also wins and flags the override stale', () => {
    const { alert, stale } = applyAlertOverride(baseAlert('DELETED'), override);
    expect(stale).toBe(true);
    expect(alert.reopenedFromCase).toBeUndefined();
  });

  it('no override → pass-through, never stale', () => {
    const input = baseAlert('ACKNOWLEDGED');
    const { alert, stale } = applyAlertOverride(input, null);
    expect(stale).toBe(false);
    expect(alert).toBe(input);
    const undef = applyAlertOverride(input, undefined);
    expect(undef.stale).toBe(false);
    expect(undef.alert).toBe(input);
  });
});

describe('effectiveAlertState (PROB-29)', () => {
  it('reads a reopened ACKNOWLEDGED alert as ACTIVE', () => {
    const { alert } = applyAlertOverride(baseAlert('ACKNOWLEDGED'), override);
    expect(effectiveAlertState(alert)).toBe('ACTIVE');
  });

  it('leaves a plain ACKNOWLEDGED alert (no override) as ACKNOWLEDGED', () => {
    expect(effectiveAlertState(baseAlert('ACKNOWLEDGED'))).toBe('ACKNOWLEDGED');
  });

  it('leaves a plain ACTIVE alert as ACTIVE', () => {
    expect(effectiveAlertState(baseAlert('ACTIVE'))).toBe('ACTIVE');
  });

  it('never promotes a non-ACKNOWLEDGED alert even if a reopenedFromCase somehow rode along', () => {
    const weird = { ...baseAlert('COMPLETED'), reopenedFromCase: override } as any;
    expect(effectiveAlertState(weird)).toBe('COMPLETED');
  });
});
