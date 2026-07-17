/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { deriveAliasName } from './alias';
import { desiredExecutionTargets, executionTargetsDiffer } from './exec_targets';

describe('desiredExecutionTargets', () => {
  it('maps each concrete index to its deriveAliasName, one alias per index', () => {
    const result = desiredExecutionTargets([
      'fosstlsoc-logs-moodle-2026.05.16',
      'fosstlsoc-logs-moodle-2026.05.17',
    ]);
    expect(result).toEqual(
      [
        deriveAliasName('fosstlsoc-logs-moodle-2026.05.16'),
        deriveAliasName('fosstlsoc-logs-moodle-2026.05.17'),
      ].sort()
    );
  });

  it('is sorted, for a stable/comparable result regardless of input order', () => {
    const a = desiredExecutionTargets(['z-index-2026.01.02', 'a-index-2026.01.01']);
    const b = desiredExecutionTargets(['a-index-2026.01.01', 'z-index-2026.01.02']);
    expect(a).toEqual(b);
    expect(a).toEqual([...a].sort());
  });

  it('dedupes when two concrete indices collide onto the same alias', () => {
    // deriveAliasName lowercases + collapses non-alphanumerics, so these two collide.
    const result = desiredExecutionTargets(['Index-A', 'index_a']);
    expect(result).toHaveLength(1);
  });

  it('empty input → empty output', () => {
    expect(desiredExecutionTargets([])).toEqual([]);
  });
});

describe('executionTargetsDiffer', () => {
  it('identical lists (same order) → false', () => {
    expect(executionTargetsDiffer(['a', 'b'], ['a', 'b'])).toBe(false);
  });

  it('same SET, different order → false (order-insensitive)', () => {
    expect(executionTargetsDiffer(['b', 'a'], ['a', 'b'])).toBe(false);
  });

  it('different length → true', () => {
    expect(executionTargetsDiffer(['a'], ['a', 'b'])).toBe(true);
    expect(executionTargetsDiffer(['a', 'b'], ['a'])).toBe(true);
  });

  it('same length, different content → true', () => {
    expect(executionTargetsDiffer(['a', 'b'], ['a', 'c'])).toBe(true);
  });

  it('both empty → false', () => {
    expect(executionTargetsDiffer([], [])).toBe(false);
  });

  it('duplicate-insensitive: [a,a,b] vs [a,b] → false', () => {
    expect(executionTargetsDiffer(['a', 'a', 'b'], ['a', 'b'])).toBe(false);
  });

  it('a real drift scenario: a new daily index rolled in', () => {
    const current = [deriveAliasName('logs-2026.05.16')];
    const desired = [deriveAliasName('logs-2026.05.16'), deriveAliasName('logs-2026.05.17')];
    expect(executionTargetsDiffer(current, desired)).toBe(true);
  });
});
