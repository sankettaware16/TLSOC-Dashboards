/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { SEVERITY_TO_MONITOR_SEVERITY } from '../detection/internal';
import { MONITOR_SEVERITY_TO_SEVERITY, severityLabel } from './severity';

describe('severity maps — drift guard', () => {
  it('MONITOR_SEVERITY_TO_SEVERITY is the exact inverse of SEVERITY_TO_MONITOR_SEVERITY (forward direction)', () => {
    // For every (sev, num) entry in the detection map, the alerts map must round-trip back.
    for (const [sev, num] of Object.entries(SEVERITY_TO_MONITOR_SEVERITY)) {
      expect(MONITOR_SEVERITY_TO_SEVERITY[num]).toBe(sev);
    }
  });

  it('SEVERITY_TO_MONITOR_SEVERITY is the exact inverse of MONITOR_SEVERITY_TO_SEVERITY (reverse direction)', () => {
    // For every (num, sev) entry in the alerts map, the detection map must round-trip back.
    for (const [num, sev] of Object.entries(MONITOR_SEVERITY_TO_SEVERITY)) {
      expect(SEVERITY_TO_MONITOR_SEVERITY[sev]).toBe(num);
    }
  });
});

describe('severityLabel', () => {
  it('maps "2" → "high"', () => {
    expect(severityLabel('2')).toBe('high');
  });

  it('maps "1" → "critical"', () => {
    expect(severityLabel('1')).toBe('critical');
  });

  it('maps "3" → "medium"', () => {
    expect(severityLabel('3')).toBe('medium');
  });

  it('maps "4" → "low"', () => {
    expect(severityLabel('4')).toBe('low');
  });

  it('returns "unknown" for an unrecognised value like "9"', () => {
    expect(severityLabel('9')).toBe('unknown');
  });

  it('returns "unknown" for undefined', () => {
    expect(severityLabel(undefined)).toBe('unknown');
  });

  it('returns "unknown" for null', () => {
    expect(severityLabel(null)).toBe('unknown');
  });
});
