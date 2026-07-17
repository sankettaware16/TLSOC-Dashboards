/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { findDataViewForIndex, DataViewIdTitle } from './dv_match';

const view = (id: string, title: string): DataViewIdTitle => ({ id, title });

describe('findDataViewForIndex', () => {
  it('exact match wins over subsumption', () => {
    const views = [
      view('all', 'fosstlsoc-logs-*'),
      view('exact', 'fosstlsoc-logs-mailnile-*'),
    ];
    const match = findDataViewForIndex(views, 'fosstlsoc-logs-mailnile-*');
    expect(match?.id).toBe('exact');
  });

  it('fosstlsoc-logs-* matches the index string fosstlsoc-logs-mailnile-*', () => {
    const views = [view('all', 'fosstlsoc-logs-*')];
    const match = findDataViewForIndex(views, 'fosstlsoc-logs-mailnile-*');
    expect(match?.id).toBe('all');
  });

  it('specificity: fosstlsoc-logs-mailnile-* beats fosstlsoc-logs-* when both subsume', () => {
    const views = [
      view('all', 'fosstlsoc-logs-*'),
      view('endpoint', 'fosstlsoc-logs-mailnile-*'),
    ];
    // Neither title equals this literal index string, so this exercises the subsumption branch —
    // both globs match it, and the longer (more specific) title must win.
    const match = findDataViewForIndex(views, 'fosstlsoc-logs-mailnile-2026.07.17');
    expect(match?.id).toBe('endpoint');
  });

  it('order independence: the more specific view still wins regardless of list order', () => {
    const views = [
      view('endpoint', 'fosstlsoc-logs-mailnile-*'),
      view('all', 'fosstlsoc-logs-*'),
    ];
    const match = findDataViewForIndex(views, 'fosstlsoc-logs-mailnile-2026.07.17');
    expect(match?.id).toBe('endpoint');
  });

  it('no match returns undefined', () => {
    const views = [view('other', 'some-other-index-*')];
    expect(findDataViewForIndex(views, 'fosstlsoc-logs-mailnile-2026.07.17')).toBeUndefined();
  });

  it('empty views list returns undefined', () => {
    expect(findDataViewForIndex([], 'fosstlsoc-logs-*')).toBeUndefined();
  });

  it('regex metacharacters in titles do not break matching or throw', () => {
    const views = [
      view('dotted', 'fosstlsoc.logs-*'), // literal dot must NOT act as "any char"
      view('plain', 'fosstlsoc-logs-*'),
    ];
    // The dotted title must not spuriously match an index with a hyphen where the dot is.
    expect(() => findDataViewForIndex(views, 'fosstlsoc-logs-mailnile-2026.07.17')).not.toThrow();
    const match = findDataViewForIndex(views, 'fosstlsoc-logs-mailnile-2026.07.17');
    expect(match?.id).toBe('plain');
  });

  it('regex metacharacters in the literal (non-wildcard) part of a title match literally', () => {
    const views = [view('bracketed', 'fosstlsoc[prod]-logs-*')];
    // Exact literal string (with the brackets) must match via subsumption.
    expect(findDataViewForIndex(views, 'fosstlsoc[prod]-logs-2026.07.17')?.id).toBe('bracketed');
    // A different literal string that merely LOOKS like it could match a naive regex must not.
    expect(findDataViewForIndex(views, 'fosstlsocXprodX-logs-2026.07.17')).toBeUndefined();
  });
});
