/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { mergeTags, partitionToggleTargets, summarizeBulk } from './bulk_actions';

describe('partitionToggleTargets — skip rows already in the target state', () => {
  const rows = [
    { soId: 'a', enabled: true },
    { soId: 'b', enabled: false },
    { soId: 'c', enabled: true },
  ];

  it('enable: targets only the disabled rows, counts the rest as skipped', () => {
    const { targets, skipped } = partitionToggleTargets(rows, true);
    expect(targets.map((r) => r.soId)).toEqual(['b']);
    expect(skipped).toBe(2);
  });

  it('disable: targets only the enabled rows', () => {
    const { targets, skipped } = partitionToggleTargets(rows, false);
    expect(targets.map((r) => r.soId)).toEqual(['a', 'c']);
    expect(skipped).toBe(1);
  });

  it('all rows already in the target state → zero targets, all skipped', () => {
    const { targets, skipped } = partitionToggleTargets(
      rows.filter((r) => r.enabled),
      true
    );
    expect(targets).toEqual([]);
    expect(skipped).toBe(2);
  });

  it('tolerates an empty/undefined row list', () => {
    expect(partitionToggleTargets([], true)).toEqual({ targets: [], skipped: 0 });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(partitionToggleTargets(undefined as any, true)).toEqual({ targets: [], skipped: 0 });
  });
});

describe('mergeTags — presentation-level add-merge (the server stays the authority)', () => {
  it('appends new tags after the existing ones, preserving order', () => {
    expect(mergeTags(['auth', 'web'], ['brute-force'])).toEqual(['auth', 'web', 'brute-force']);
  });

  it('trims and drops empties/whitespace-only entries', () => {
    expect(mergeTags(['auth'], [' web ', '', '   '])).toEqual(['auth', 'web']);
  });

  it('dedupes across existing and added (first occurrence wins)', () => {
    expect(mergeTags(['auth', 'web'], ['web', ' auth ', 'new'])).toEqual(['auth', 'web', 'new']);
  });

  it('handles absent existing tags', () => {
    expect(mergeTags(undefined, ['a', 'b'])).toEqual(['a', 'b']);
  });

  it('skips non-string junk instead of crashing', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(mergeTags(['ok'], [42, null, 'fine'] as any)).toEqual(['ok', 'fine']);
  });

  it('an unchanged merge returns the same list content (the loop skips such rows)', () => {
    expect(mergeTags(['a', 'b'], ['a'])).toEqual(['a', 'b']);
  });
});

describe('summarizeBulk — ONE summary toast per bulk run', () => {
  it('all succeeded → success color, verb + count', () => {
    const s = summarizeBulk('Enabled', { succeeded: 3, skipped: 0, failures: [] });
    expect(s.color).toBe('success');
    expect(s.title).toBe('Enabled 3 rules');
    expect(s.text).toBeUndefined();
  });

  it('singular count reads grammatically', () => {
    expect(summarizeBulk('Deleted', { succeeded: 1, skipped: 0, failures: [] }).title).toBe(
      'Deleted 1 rule'
    );
  });

  it('skips are reported alongside successes (still success color)', () => {
    const s = summarizeBulk('Enabled', { succeeded: 2, skipped: 1, failures: [] });
    expect(s.color).toBe('success');
    expect(s.title).toContain('Enabled 2 rules');
    expect(s.title).toContain('1 already was — skipped');
  });

  it('a partial failure is a warning carrying the FIRST failure detail', () => {
    const s = summarizeBulk('Disabled', {
      succeeded: 1,
      skipped: 0,
      failures: [
        { name: 'Rule A', message: 'boom' },
        { name: 'Rule B', message: 'later' },
      ],
    });
    expect(s.color).toBe('warning');
    expect(s.title).toContain('Disabled 1 rule');
    expect(s.title).toContain('2 failed');
    expect(s.text).toBe('Rule A: boom');
  });

  it('total failure (nothing succeeded) is danger', () => {
    const s = summarizeBulk('Tagged', {
      succeeded: 0,
      skipped: 0,
      failures: [{ name: 'Rule A', message: 'nope' }],
    });
    expect(s.color).toBe('danger');
    expect(s.title).toBe('1 failed');
    expect(s.text).toBe('Rule A: nope');
  });

  it('nothing at all to do → "Nothing to do" (success color, no detail)', () => {
    const s = summarizeBulk('Enabled', { succeeded: 0, skipped: 0, failures: [] });
    expect(s.color).toBe('success');
    expect(s.title).toBe('Nothing to do');
  });
});
