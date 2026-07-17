/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { caseReporter, deriveParticipants } from './participants';

const comment = (author: string) => ({ id: 'x', author, text: 't', createdAt: 'now' });
const act = (actor: string) => ({ id: 'x', type: 'edited' as const, actor, summary: 's', createdAt: 'now' });

describe('caseReporter', () => {
  test('returns createdBy when present', () => {
    expect(caseReporter({ createdBy: 'tlsoc-l1' })).toBe('tlsoc-l1');
  });
  test('undefined for pre-5a.3 cases (no createdBy) or blank', () => {
    expect(caseReporter({})).toBeUndefined();
    expect(caseReporter({ createdBy: '  ' })).toBeUndefined();
  });
});

describe('deriveParticipants (decision pinned here)', () => {
  test('unions createdBy + assignee + comment authors + activity actors, deduped + sorted', () => {
    const result = deriveParticipants({
      createdBy: 'tlsoc-l1',
      assignee: 'tlsoc-manager',
      comments: [comment('tlsoc-engineer'), comment('tlsoc-l1')],
      activity: [act('tlsoc-l1'), act('tlsoc-manager')],
    });
    expect(result).toEqual(['tlsoc-engineer', 'tlsoc-l1', 'tlsoc-manager']);
  });

  test('null/blank assignee and empty collections are skipped', () => {
    expect(deriveParticipants({ createdBy: 'tlsoc-l1', assignee: null })).toEqual(['tlsoc-l1']);
    expect(deriveParticipants({})).toEqual([]);
  });

  test('keeps the legacy analyst placeholder (honest about what was recorded)', () => {
    expect(deriveParticipants({ activity: [act('analyst')], comments: [comment('admin')] })).toEqual(
      ['admin', 'analyst']
    );
  });
});
