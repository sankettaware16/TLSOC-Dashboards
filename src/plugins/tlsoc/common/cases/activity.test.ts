/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  ACTIVITY_TYPES,
  appendActivity,
  buildActivity,
  describeAlertsLinked,
  describeComment,
  describeCreated,
  describeEdit,
  describeStatusChange,
} from './activity';
import { CaseActivity, CaseActivityType } from './types';

describe('ACTIVITY_TYPES', () => {
  it('contains exactly the five expected types', () => {
    expect(ACTIVITY_TYPES).toEqual([
      'created',
      'status_changed',
      'edited',
      'commented',
      'alerts_linked',
    ]);
  });
});

describe('describeCreated', () => {
  it('returns "Created the case" when fromAlert is false', () => {
    expect(describeCreated({ fromAlert: false })).toBe('Created the case');
  });

  it('returns "Created the case" when called with no args', () => {
    expect(describeCreated()).toBe('Created the case');
  });

  it('returns "Created the case from an alert" when fromAlert is true', () => {
    expect(describeCreated({ fromAlert: true })).toBe('Created the case from an alert');
  });
});

describe('describeStatusChange', () => {
  it('returns the exact status-change string', () => {
    expect(describeStatusChange('New', 'Assigned')).toBe('Status changed from New to Assigned');
  });

  it('handles In Progress as from status', () => {
    expect(describeStatusChange('In Progress', 'Closed')).toBe(
      'Status changed from In Progress to Closed'
    );
  });

  it('handles Closed → In Progress (reopen)', () => {
    expect(describeStatusChange('Closed', 'In Progress')).toBe(
      'Status changed from Closed to In Progress'
    );
  });
});

describe('describeEdit', () => {
  it('returns "Updated the case" for empty changedFields', () => {
    expect(describeEdit([])).toBe('Updated the case');
  });

  it('returns a joined list for non-empty changedFields', () => {
    expect(describeEdit(['title', 'description'])).toBe('Updated title, description');
  });

  it('returns single field update string', () => {
    expect(describeEdit(['severity'])).toBe('Updated severity');
  });
});

describe('describeComment', () => {
  it('returns "Added a comment"', () => {
    expect(describeComment()).toBe('Added a comment');
  });
});

describe('describeAlertsLinked', () => {
  it('returns singular "Linked 1 alert" for count=1', () => {
    expect(describeAlertsLinked(1)).toBe('Linked 1 alert');
  });

  it('returns plural "Linked N alerts" for count>1', () => {
    expect(describeAlertsLinked(3)).toBe('Linked 3 alerts');
  });

  it('returns plural for count=0', () => {
    expect(describeAlertsLinked(0)).toBe('Linked 0 alerts');
  });
});

describe('buildActivity', () => {
  it('returns the exact object with all fields', () => {
    const result = buildActivity('created', 'Created the case', 'analyst', 'id-001', '2024-01-01T00:00:00.000Z');
    expect(result).toEqual({
      id: 'id-001',
      type: 'created',
      actor: 'analyst',
      summary: 'Created the case',
      createdAt: '2024-01-01T00:00:00.000Z',
    } as CaseActivity);
  });

  it('preserves the type field correctly for each activity type', () => {
    const types: CaseActivityType[] = ['created', 'status_changed', 'edited', 'commented', 'alerts_linked'];
    types.forEach((t) => {
      const result = buildActivity(t, 'summary', 'actor', 'id', 'ts');
      expect(result.type).toBe(t);
    });
  });
});

describe('appendActivity', () => {
  it('appends to an existing array immutably', () => {
    const existing: CaseActivity[] = [
      { id: 'a1', type: 'created', actor: 'analyst', summary: 'Created the case', createdAt: 't1' },
    ];
    const entry: CaseActivity = {
      id: 'a2',
      type: 'commented',
      actor: 'analyst',
      summary: 'Added a comment',
      createdAt: 't2',
    };
    const result = appendActivity(existing, entry);
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual(existing[0]);
    expect(result[1]).toEqual(entry);
    // original not mutated
    expect(existing).toHaveLength(1);
  });

  it('treats undefined existing as empty array', () => {
    const entry: CaseActivity = {
      id: 'a1',
      type: 'created',
      actor: 'analyst',
      summary: 'Created the case',
      createdAt: 't1',
    };
    const result = appendActivity(undefined, entry);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual(entry);
  });
});
