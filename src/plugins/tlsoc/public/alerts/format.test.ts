/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { riskScoreColor } from './format';

describe('riskScoreColor', () => {
  it('>=75 → danger', () => {
    expect(riskScoreColor(75)).toBe('danger');
    expect(riskScoreColor(100)).toBe('danger');
  });
  it('50-74 → warning', () => {
    expect(riskScoreColor(50)).toBe('warning');
    expect(riskScoreColor(74)).toBe('warning');
  });
  it('25-49 → default', () => {
    expect(riskScoreColor(25)).toBe('default');
    expect(riskScoreColor(49)).toBe('default');
  });
  it('<25 → hollow', () => {
    expect(riskScoreColor(0)).toBe('hollow');
    expect(riskScoreColor(24)).toBe('hollow');
  });
});
