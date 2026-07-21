/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { computeRuleHealth, foldErrorAlerts, foldJobsInfo } from './health';

/* eslint-disable @typescript-eslint/no-explicit-any */

/** A raw get-alerts-API ERROR alert as the engine really emits it (research_r2 §f evidence). */
const errorAlert = (overrides: Record<string, any> = {}) => ({
  id: 'error-alert-7Uq5ZZ8B5XwSW2UmUkhT', // the real 'error-alert-' id prefix — must be tolerated
  monitor_id: 'm1',
  state: 'ERROR',
  severity: '', // ERROR alerts carry an EMPTY severity — must never be parsed
  error_message: 'IndexNotFoundException[no such index [opensearch_dashboards_sample_data_logs]]',
  start_time: 1784129651894,
  last_notification_time: 1784549651894,
  end_time: null,
  ...overrides,
});

describe('foldErrorAlerts', () => {
  it('folds an UN-ENDED ERROR alert into lastError {message, at=start_time}', () => {
    const out = foldErrorAlerts([errorAlert()]);
    expect(out.m1).toEqual({
      message:
        'IndexNotFoundException[no such index [opensearch_dashboards_sample_data_logs]]',
      at: 1784129651894,
    });
  });

  it('an ENDED ERROR alert means "recovered" — it produces NO entry', () => {
    const out = foldErrorAlerts([errorAlert({ end_time: 1784129531908 })]);
    expect(out.m1).toBeUndefined();
  });

  it('un-ended wins over ended for the same monitor, and the NEWEST un-ended streak wins', () => {
    const out = foldErrorAlerts([
      errorAlert({ start_time: 100, end_time: 200 }), // old, recovered
      errorAlert({ start_time: 300, error_message: 'older live failure' }),
      errorAlert({ start_time: 500, error_message: 'newest live failure' }),
      errorAlert({ start_time: 400, error_message: 'not the newest' }),
    ]);
    expect(out.m1).toEqual({ message: 'newest live failure', at: 500 });
  });

  it('folds per monitor id', () => {
    const out = foldErrorAlerts([
      errorAlert(),
      errorAlert({ monitor_id: 'm2', error_message: 'other monitor broke', start_time: 7 }),
    ]);
    expect(Object.keys(out).sort()).toEqual(['m1', 'm2']);
    expect(out.m2).toEqual({ message: 'other monitor broke', at: 7 });
  });

  it('ignores non-ERROR states even if passed un-filtered', () => {
    const out = foldErrorAlerts([
      errorAlert({ state: 'ACTIVE' }),
      errorAlert({ state: 'COMPLETED' }),
      errorAlert({ state: 'DELETED' }),
    ]);
    expect(out).toEqual({});
  });

  it('tolerates garbage: non-objects, missing monitor_id, missing message/start_time', () => {
    const out = foldErrorAlerts([
      null,
      42,
      'nope',
      errorAlert({ monitor_id: undefined }),
      errorAlert({ monitor_id: '' }),
      errorAlert({ monitor_id: 'm3', error_message: undefined, start_time: undefined }),
    ] as any[]);
    expect(out.m3).toEqual({
      message: 'The monitor run failed (no error message was recorded).',
    });
    expect(Object.keys(out)).toEqual(['m3']);
  });

  it('empty / nullish input folds to {}', () => {
    expect(foldErrorAlerts([])).toEqual({});
    expect(foldErrorAlerts(undefined as any)).toEqual({});
  });
});

describe('foldJobsInfo', () => {
  it('folds nodes.*.jobs_info into monitorId → last_execution_time', () => {
    const out = foldJobsInfo({
      nodes: {
        nodeA: {
          jobs_info: {
            m1: { last_execution_time: 1784550011887, running_on_time: true },
            m2: { last_execution_time: 42 },
          },
        },
      },
    });
    expect(out).toEqual({ m1: 1784550011887, m2: 42 });
  });

  it('the NEWEST timestamp wins when a monitor appears on several nodes', () => {
    const out = foldJobsInfo({
      nodes: {
        nodeA: { jobs_info: { m1: { last_execution_time: 100 } } },
        nodeB: { jobs_info: { m1: { last_execution_time: 300 } } },
        nodeC: { jobs_info: { m1: { last_execution_time: 200 } } },
      },
    });
    expect(out).toEqual({ m1: 300 });
  });

  it('malformed shapes fold to {} (never throw)', () => {
    expect(foldJobsInfo(undefined)).toEqual({});
    expect(foldJobsInfo(null)).toEqual({});
    expect(foldJobsInfo({})).toEqual({});
    expect(foldJobsInfo({ nodes: 'nope' })).toEqual({});
    expect(foldJobsInfo({ nodes: { a: { jobs_info: { m1: { last_execution_time: 'x' } } } } })).toEqual(
      {}
    );
  });
});

describe('computeRuleHealth — the honest tri-state', () => {
  it('disabled → off, even with a lingering un-ended error (off beats failing)', () => {
    const health = computeRuleHealth({
      enabled: false,
      lastError: { message: 'boom', at: 5 },
    });
    expect(health.status).toBe('off');
    expect(health.enabled).toBe(false);
  });

  it('enabled + live error → failing, carrying the error through', () => {
    const health = computeRuleHealth({
      enabled: true,
      lastRun: 10,
      lastError: { message: 'boom', at: 5 },
    });
    expect(health.status).toBe('failing');
    expect(health.lastError).toEqual({ message: 'boom', at: 5 });
    expect(health.lastRun).toBe(10);
  });

  it('enabled + no error → ok-unverified (NEVER a "succeeded" claim)', () => {
    const health = computeRuleHealth({ enabled: true });
    expect(health.status).toBe('ok-unverified');
    // The whole model has no 'succeeded' member — pin the honesty contract.
    expect(['failing', 'ok-unverified', 'off']).toContain(health.status);
  });

  it('passes enabledTime/lastUpdateTime through and omits absent optionals', () => {
    const health = computeRuleHealth({
      enabled: true,
      enabledTime: 1,
      lastUpdateTime: 2,
    });
    expect(health).toEqual({
      status: 'ok-unverified',
      enabled: true,
      enabledTime: 1,
      lastUpdateTime: 2,
    });
    expect('lastRun' in health).toBe(false);
    expect('lastError' in health).toBe(false);
  });
});
