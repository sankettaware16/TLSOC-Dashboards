/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { buildEvidenceFilter, deriveEvidence, deriveInvestigationScope } from './scope';

// Fixed instants so the tests are deterministic (nowMs is passed in, never read from the clock).
const T_1000 = Date.UTC(2026, 4, 16, 10, 0, 0); // 2026-05-16T10:00:00Z
const T_1002 = Date.UTC(2026, 4, 16, 10, 2, 0);
const T_1005 = Date.UTC(2026, 4, 16, 10, 5, 0);
const NOW = Date.UTC(2026, 4, 16, 12, 0, 0);
const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

const ruleFor = (index: string) => ({ soId: `so-${index}`, name: `${index} rule`, mode: 'stateful', index });
const mk = (over: Record<string, unknown>) => ({
  rule: null,
  startTime: null,
  endTime: null,
  lastNotificationTime: null,
  ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const derive = (alerts: any[], now = NOW) => deriveInvestigationScope(alerts as any, now);

describe('deriveInvestigationScope — time window', () => {
  it('happy path: from = min(startTime), to = max(endTime)', () => {
    const s = derive([
      mk({ rule: ruleFor('idx'), startTime: T_1000, endTime: T_1002 }),
      mk({ rule: ruleFor('idx'), startTime: T_1002, endTime: T_1005 }),
    ]);
    expect(s.timeRange.from).toBe(new Date(T_1000).toISOString());
    expect(s.timeRange.to).toBe(new Date(T_1005).toISOString());
  });

  it('null endTime falls back to lastNotificationTime for the upper bound', () => {
    const s = derive([
      mk({ rule: ruleFor('idx'), startTime: T_1000, endTime: null, lastNotificationTime: T_1005 }),
    ]);
    expect(s.timeRange.from).toBe(new Date(T_1000).toISOString());
    expect(s.timeRange.to).toBe(new Date(T_1005).toISOString());
  });

  it('null endTime AND null lastNotificationTime falls back to nowMs for the upper bound', () => {
    const s = derive([
      mk({ rule: ruleFor('idx'), startTime: T_1000, endTime: null, lastNotificationTime: null }),
    ]);
    expect(s.timeRange.from).toBe(new Date(T_1000).toISOString());
    expect(s.timeRange.to).toBe(new Date(NOW).toISOString());
  });

  it('no times on ANY alert → last-24h fallback [now-24h, now]', () => {
    const s = derive([mk({ rule: ruleFor('idx') }), mk({ rule: ruleFor('idx') })]);
    expect(s.timeRange.from).toBe(new Date(NOW - DAY_MS).toISOString());
    expect(s.timeRange.to).toBe(new Date(NOW).toISOString());
    expect(s.index).toBe('idx'); // index still derived even when times are absent
  });

  it('empty alerts array → last-24h fallback + undefined index', () => {
    const s = derive([]);
    expect(s.timeRange.from).toBe(new Date(NOW - DAY_MS).toISOString());
    expect(s.timeRange.to).toBe(new Date(NOW).toISOString());
    expect(s.index).toBeUndefined();
  });

  it('degenerate (point-in-time) window is widened to from + 1h', () => {
    const s = derive([mk({ rule: ruleFor('idx'), startTime: T_1000, endTime: T_1000 })]);
    expect(s.timeRange.from).toBe(new Date(T_1000).toISOString());
    expect(s.timeRange.to).toBe(new Date(T_1000 + HOUR_MS).toISOString());
  });

  it('no startTime anywhere → from = earliest upper bound', () => {
    const s = derive([
      mk({ rule: ruleFor('idx'), endTime: T_1005 }),
      mk({ rule: ruleFor('idx'), endTime: T_1002 }),
    ]);
    expect(s.timeRange.from).toBe(new Date(T_1002).toISOString());
    expect(s.timeRange.to).toBe(new Date(T_1005).toISOString());
  });
});

describe('deriveInvestigationScope — index selection (decision pinned here)', () => {
  it('picks the MOST COMMON non-null rule.index', () => {
    const s = derive([
      mk({ rule: ruleFor('A'), startTime: T_1000 }),
      mk({ rule: ruleFor('A'), startTime: T_1000 }),
      mk({ rule: ruleFor('B'), startTime: T_1000 }),
    ]);
    expect(s.index).toBe('A');
  });

  it('on a tie, the FIRST-occurring index wins', () => {
    expect(
      derive([mk({ rule: ruleFor('A'), startTime: T_1000 }), mk({ rule: ruleFor('B'), startTime: T_1000 })]).index
    ).toBe('A');
    expect(
      derive([mk({ rule: ruleFor('B'), startTime: T_1000 }), mk({ rule: ruleFor('A'), startTime: T_1000 })]).index
    ).toBe('B');
  });

  it('ignores null rules; a less-frequent-overall but only-known index still wins', () => {
    const s = derive([
      mk({ rule: null, startTime: T_1000 }),
      mk({ rule: null, startTime: T_1000 }),
      mk({ rule: ruleFor('only'), startTime: T_1000 }),
    ]);
    expect(s.index).toBe('only');
  });

  it('all rules null → index undefined (window still derived from times)', () => {
    const s = derive([mk({ rule: null, startTime: T_1000, endTime: T_1002 })]);
    expect(s.index).toBeUndefined();
    expect(s.timeRange.from).toBe(new Date(T_1000).toISOString());
    expect(s.timeRange.to).toBe(new Date(T_1002).toISOString());
  });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const evAlert = (over: Record<string, unknown>): any => ({
  relatedDocIds: [],
  bucketKeys: undefined,
  rule: null,
  ...over,
});

describe('deriveEvidence — docRefs', () => {
  it('unions + dedupes doc refs across alerts', () => {
    const e = deriveEvidence([
      evAlert({ relatedDocIds: ['a1|idx-a', 'a2|idx-a'] }),
      evAlert({ relatedDocIds: ['a2|idx-a', 'a3|idx-b'] }),
    ]);
    expect(e.docRefs).toEqual([
      { id: 'a1', index: 'idx-a' },
      { id: 'a2', index: 'idx-a' },
      { id: 'a3', index: 'idx-b' },
    ]);
  });

  it('splits on the LAST pipe — a docId containing "|" is preserved intact', () => {
    const e = deriveEvidence([evAlert({ relatedDocIds: ['weird|doc|id|idx-a'] })]);
    expect(e.docRefs).toEqual([{ id: 'weird|doc|id', index: 'idx-a' }]);
  });

  it('entries with no parseable index (no pipe, or empty index) are skipped', () => {
    const e = deriveEvidence([evAlert({ relatedDocIds: ['no-pipe-here', 'bare-id|'] })]);
    expect(e.docRefs).toEqual([]);
  });

  it('empty input → empty docRefs', () => {
    expect(deriveEvidence([]).docRefs).toEqual([]);
  });
});

describe('deriveEvidence — groupScopes', () => {
  it('bucket alert with bucketKeys + rule.groupBy zips into one AND-set', () => {
    const e = deriveEvidence([
      evAlert({
        relatedDocIds: [],
        bucketKeys: ['host-1', 'admin'],
        rule: { ...ruleFor('idx'), groupBy: ['host.name', 'user.name'] },
      }),
    ]);
    expect(e.groupScopes).toEqual([
      [
        { field: 'host.name', value: 'host-1' },
        { field: 'user.name', value: 'admin' },
      ],
    ]);
  });

  it('alert with bucketKeys but no rule.groupBy is skipped', () => {
    const e = deriveEvidence([evAlert({ bucketKeys: ['host-1'], rule: { ...ruleFor('idx'), groupBy: undefined } })]);
    expect(e.groupScopes).toEqual([]);
  });

  it('alert with rule.groupBy but no bucketKeys is skipped', () => {
    const e = deriveEvidence([evAlert({ bucketKeys: undefined, rule: { ...ruleFor('idx'), groupBy: ['host.name'] } })]);
    expect(e.groupScopes).toEqual([]);
  });

  it('dedupes identical group-scope sets across alerts', () => {
    const rule = { ...ruleFor('idx'), groupBy: ['host.name'] };
    const e = deriveEvidence([
      evAlert({ bucketKeys: ['host-1'], rule }),
      evAlert({ bucketKeys: ['host-1'], rule }),
    ]);
    expect(e.groupScopes).toEqual([[{ field: 'host.name', value: 'host-1' }]]);
  });

  it('empty input → empty groupScopes', () => {
    expect(deriveEvidence([]).groupScopes).toEqual([]);
  });
});

describe('buildEvidenceFilter', () => {
  it('returns null when both docRefs and groupScopes are empty', () => {
    expect(buildEvidenceFilter({ docRefs: [], groupScopes: [] })).toBeNull();
  });

  it('golden shape: 2 indices + 1 bucket group-scope', () => {
    const evidence = {
      docRefs: [
        { id: 'a1', index: 'idx-a' },
        { id: 'a2', index: 'idx-a' },
        { id: 'b1', index: 'idx-b' },
      ],
      groupScopes: [
        [
          { field: 'host.name', value: 'host-1' },
          { field: 'user.name', value: 'admin' },
        ],
      ],
    };
    expect(buildEvidenceFilter(evidence)).toEqual({
      meta: { alias: 'Linked alert evidence', disabled: false, negate: false, type: 'custom' },
      query: {
        bool: {
          should: [
            { bool: { filter: [{ term: { _index: 'idx-a' } }, { ids: { values: ['a1', 'a2'] } }] } },
            { bool: { filter: [{ term: { _index: 'idx-b' } }, { ids: { values: ['b1'] } }] } },
            {
              bool: {
                filter: [
                  { term: { 'host.name': 'host-1' } },
                  { term: { 'user.name': 'admin' } },
                ],
              },
            },
          ],
          minimum_should_match: 1,
        },
      },
    });
  });

  it('includes minimum_should_match when only docRefs are present', () => {
    const result = buildEvidenceFilter({ docRefs: [{ id: 'a1', index: 'idx-a' }], groupScopes: [] });
    expect(result?.query.bool.minimum_should_match).toBe(1);
  });
});
