/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { ALLOWED_TRANSITIONS, CASE_STATUSES, assertTransition, canTransition, nextStatuses } from './state';
import { CaseStatus } from './types';

describe('CASE_STATUSES', () => {
  it('contains exactly the five expected statuses', () => {
    expect(CASE_STATUSES).toEqual(['New', 'Assigned', 'In Progress', 'Contained', 'Closed']);
  });
});

describe('canTransition — allowed transitions', () => {
  // Enumerate every entry in ALLOWED_TRANSITIONS and assert canTransition returns true
  (Object.entries(ALLOWED_TRANSITIONS) as [CaseStatus, CaseStatus[]][]).forEach(([from, tos]) => {
    tos.forEach((to) => {
      it(`allows ${from} → ${to}`, () => {
        expect(canTransition(from, to)).toBe(true);
      });
    });
  });
});

describe('canTransition — same-status no-op', () => {
  CASE_STATUSES.forEach((status) => {
    it(`allows ${status} → ${status} (same-status no-op)`, () => {
      expect(canTransition(status, status)).toBe(true);
    });
  });
});

describe('canTransition — illegal transitions', () => {
  it('blocks New → Contained', () => {
    expect(canTransition('New', 'Contained')).toBe(false);
  });

  it('blocks Assigned → Contained', () => {
    expect(canTransition('Assigned', 'Contained')).toBe(false);
  });

  it('blocks Contained → New', () => {
    expect(canTransition('Contained', 'New')).toBe(false);
  });

  it('blocks Closed → New', () => {
    expect(canTransition('Closed', 'New')).toBe(false);
  });

  it('blocks Closed → Assigned', () => {
    expect(canTransition('Closed', 'Assigned')).toBe(false);
  });
});

describe('canTransition — reopen', () => {
  it('allows Closed → In Progress (reopen)', () => {
    expect(canTransition('Closed', 'In Progress')).toBe(true);
  });
});

describe('assertTransition — allowed transitions do not throw', () => {
  (Object.entries(ALLOWED_TRANSITIONS) as [CaseStatus, CaseStatus[]][]).forEach(([from, tos]) => {
    tos.forEach((to) => {
      it(`does not throw for ${from} → ${to}`, () => {
        expect(() => assertTransition(from, to)).not.toThrow();
      });
    });
  });
});

describe('assertTransition — same-status does not throw', () => {
  it('allows In Progress → In Progress', () => {
    expect(() => assertTransition('In Progress', 'In Progress')).not.toThrow();
  });
});

describe('assertTransition — illegal transitions throw with allowed-states message', () => {
  it('throws for New → Contained with allowed next states in message', () => {
    expect(() => assertTransition('New', 'Contained')).toThrow(
      /Allowed next states: New, Assigned, In Progress, Closed/
    );
  });

  it('throws for Closed → New', () => {
    const err = (() => {
      try {
        assertTransition('Closed', 'New');
      } catch (e) {
        return e as Error;
      }
    })();
    expect(err).toBeDefined();
    expect(err!.message).toMatch(/Cannot move a case from "Closed" to "New"/);
    expect(err!.message).toMatch(/Allowed next states:/);
    expect(err!.message).toMatch(/In Progress/);
  });

  it('throws for Closed → Assigned', () => {
    expect(() => assertTransition('Closed', 'Assigned')).toThrow(/Cannot move a case/);
  });

  it('throws for Contained → New', () => {
    expect(() => assertTransition('Contained', 'New')).toThrow(/Cannot move a case/);
  });
});

describe('assertTransition — invalid status value throws', () => {
  it('throws "not a valid case status" for a garbage status', () => {
    // Cast to bypass TS so we can test the runtime guard
    expect(() => assertTransition('New', 'Gibberish' as CaseStatus)).toThrow(
      /is not a valid case status/
    );
  });

  it('error message for invalid status lists the valid statuses', () => {
    expect(() => assertTransition('New', 'INVALID' as CaseStatus)).toThrow(
      /Valid: New, Assigned, In Progress, Contained, Closed/
    );
  });
});

describe('nextStatuses', () => {
  it('nextStatuses("New") deep-equals [New, Assigned, In Progress, Closed]', () => {
    expect(nextStatuses('New')).toEqual(['New', 'Assigned', 'In Progress', 'Closed']);
  });

  it('nextStatuses("Closed") deep-equals [Closed, In Progress]', () => {
    expect(nextStatuses('Closed')).toEqual(['Closed', 'In Progress']);
  });

  it('first element is always the current status', () => {
    CASE_STATUSES.forEach((status) => {
      const result = nextStatuses(status);
      expect(result[0]).toBe(status);
    });
  });
});
