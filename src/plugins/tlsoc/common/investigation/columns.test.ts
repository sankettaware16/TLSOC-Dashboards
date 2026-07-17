/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { planColumns, PREFERRED_COLUMN_FIELDS } from './columns';

describe('planColumns — investigation grid column selection (decision pinned here)', () => {
  it('all preferred fields present → all, in preferred order, no fallback', () => {
    // input order intentionally shuffled to prove output follows PREFERRED order, not input order
    const plan = planColumns([
      'http.response.status_code',
      'source.ip',
      '@timestamp',
      'http.request.method',
    ]);
    expect(plan.fields).toEqual([
      'source.ip',
      'http.request.method',
      'http.response.status_code',
    ]);
    expect(plan.fallbackSummary).toBe(false);
  });

  it('only a subset present → just those (absent ones skipped, not blank)', () => {
    const plan = planColumns(['@timestamp', 'source.ip', 'message']);
    expect(plan.fields).toEqual(['source.ip']);
    expect(plan.fallbackSummary).toBe(false);
  });

  it('NONE of the preferred fields present (different-shaped index) → empty + fallbackSummary', () => {
    const plan = planColumns(['@timestamp', 'message', 'host.name', 'log.level']);
    expect(plan.fields).toEqual([]);
    expect(plan.fallbackSummary).toBe(true);
  });

  it('empty field list → fallbackSummary', () => {
    const plan = planColumns([]);
    expect(plan.fields).toEqual([]);
    expect(plan.fallbackSummary).toBe(true);
  });

  it('honors a custom preferred list', () => {
    const plan = planColumns(['a', 'b', 'c'], ['c', 'x', 'a']);
    expect(plan.fields).toEqual(['c', 'a']); // preferred order, only present
    expect(plan.fallbackSummary).toBe(false);
  });

  it('default preferred set is the documented SOC field list', () => {
    expect(PREFERRED_COLUMN_FIELDS).toEqual([
      'source.ip',
      'http.request.method',
      'http.response.status_code',
    ]);
  });
});
