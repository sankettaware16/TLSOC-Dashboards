/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { groupAckTargets, partitionByIds } from './partition';

const alert = (id: string, extra: Record<string, unknown> = {}) => ({ id, ...extra });

describe('partitionByIds — case-hydration id filter (decision pinned here)', () => {
  test('found subset: returns only wanted alerts, missing collects the rest', () => {
    const raw = [alert('a'), alert('b'), alert('c')];
    const { found, missingIds } = partitionByIds(raw, ['a', 'c', 'zz']);
    expect(found.map((f) => f.id)).toEqual(['a', 'c']);
    expect(missingIds).toEqual(['zz']);
  });

  test('found follows wantedIds order, not rawAlerts order', () => {
    const raw = [alert('b'), alert('a')];
    const { found } = partitionByIds(raw, ['a', 'b']);
    expect(found.map((f) => f.id)).toEqual(['a', 'b']);
  });

  test('all missing: empty found, missingIds preserves wanted order', () => {
    const { found, missingIds } = partitionByIds([alert('x')], ['q', 'p']);
    expect(found).toEqual([]);
    expect(missingIds).toEqual(['q', 'p']);
  });

  test('empty wanted list → empty both (the 0-linked-ids case)', () => {
    const { found, missingIds } = partitionByIds([alert('a')], []);
    expect(found).toEqual([]);
    expect(missingIds).toEqual([]);
  });

  test('duplicate wanted ids and duplicate raw alerts are deduped', () => {
    const raw = [alert('a', { v: 1 }), alert('a', { v: 2 }), alert('b')];
    const { found, missingIds } = partitionByIds(raw, ['a', 'a', 'gone', 'gone']);
    expect(found).toHaveLength(1);
    expect(found[0].v).toBe(1); // first occurrence wins
    expect(missingIds).toEqual(['gone']);
  });

  test('tolerates malformed alerts (no id / null) and null-ish inputs', () => {
    const raw = [{ notId: true }, null, alert('a')] as any[];
    const { found, missingIds } = partitionByIds(raw, ['a']);
    expect(found.map((f) => f.id)).toEqual(['a']);
    expect(missingIds).toEqual([]);
    expect(partitionByIds(undefined as any, undefined as any)).toEqual({
      found: [],
      missingIds: [],
    });
  });
});

describe('groupAckTargets', () => {
  const a = (id: string, monitorId: string, state = 'ACTIVE') => ({ id, monitorId, state });

  test('groups ACTIVE alerts per monitor, preserving first-appearance order', () => {
    const targets = groupAckTargets([a('1', 'm1'), a('2', 'm2'), a('3', 'm1')]);
    expect(targets).toEqual([
      { monitorId: 'm1', alertIds: ['1', '3'] },
      { monitorId: 'm2', alertIds: ['2'] },
    ]);
  });

  test('filters out non-ACTIVE states (acknowledged/completed/error are not ack-able)', () => {
    const targets = groupAckTargets([
      a('1', 'm1'),
      a('2', 'm1', 'ACKNOWLEDGED'),
      a('3', 'm1', 'COMPLETED'),
      a('4', 'm1', 'ERROR'),
    ]);
    expect(targets).toEqual([{ monitorId: 'm1', alertIds: ['1'] }]);
  });

  test('drops entries missing id or monitorId, dedupes ids, tolerates null-ish input', () => {
    const targets = groupAckTargets([
      a('1', 'm1'),
      a('1', 'm1'), // duplicate id
      { id: '', monitorId: 'm1', state: 'ACTIVE' },
      { id: 'x', monitorId: undefined, state: 'ACTIVE' } as any,
      null as any,
    ]);
    expect(targets).toEqual([{ monitorId: 'm1', alertIds: ['1'] }]);
    expect(groupAckTargets(undefined as any)).toEqual([]);
    expect(groupAckTargets([])).toEqual([]);
  });
});
