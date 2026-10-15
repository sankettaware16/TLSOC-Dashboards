/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { CaseEditForm, diffCaseEdit } from './edit';

const original = {
  title: 'Brute force from 10.8.0.10',
  description: 'ssh failures',
  severity: 'high' as const,
  assignee: null,
  tags: ['ssh', 'vpn'],
  category: undefined,
};

const formFrom = (o: typeof original): CaseEditForm => ({
  title: o.title,
  description: o.description,
  severity: o.severity,
  assignee: o.assignee ?? '',
  tags: o.tags,
  category: o.category ?? '',
});

describe('diffCaseEdit', () => {
  it('an untouched form produces an empty patch (nothing to save, nothing reverted)', () => {
    expect(diffCaseEdit(original, formFrom(original))).toEqual({});
  });

  it('sends only the changed field', () => {
    expect(diffCaseEdit(original, { ...formFrom(original), title: 'SSH brute force' })).toEqual({
      title: 'SSH brute force',
    });
  });

  it('an unchanged empty assignee is NOT sent (it would 403 for non-managers)', () => {
    const patch = diffCaseEdit(original, { ...formFrom(original), severity: 'critical' });
    expect(patch).toEqual({ severity: 'critical' });
    expect('assignee' in patch).toBe(false);
  });

  it('assigning and unassigning map "" to null', () => {
    expect(diffCaseEdit(original, { ...formFrom(original), assignee: 'alice' })).toEqual({
      assignee: 'alice',
    });
    expect(
      diffCaseEdit({ ...original, assignee: 'alice' } as any, {
        ...formFrom(original),
        assignee: '',
      })
    ).toEqual({ assignee: null });
  });

  it('tag order alone is not a change', () => {
    expect(diffCaseEdit(original, { ...formFrom(original), tags: ['vpn', 'ssh'] })).toEqual({});
    expect(diffCaseEdit(original, { ...formFrom(original), tags: ['ssh'] })).toEqual({
      tags: ['ssh'],
    });
  });

  it('a missing category/description reads as "" (legacy cases)', () => {
    expect(
      diffCaseEdit({ ...original, description: undefined } as any, {
        ...formFrom(original),
        description: '',
      })
    ).toEqual({});
    expect(diffCaseEdit(original, { ...formFrom(original), category: 'Intrusion' })).toEqual({
      category: 'Intrusion',
    });
  });
});
