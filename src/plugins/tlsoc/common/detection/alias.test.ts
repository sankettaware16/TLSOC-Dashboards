/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { deriveAliasName } from './alias';

describe('deriveAliasName — dot-free alias for doc-level (stateless) monitors', () => {
  it('sanitizes a wildcard daily-index pattern', () => {
    expect(deriveAliasName('fosstlsoc-logs-moodle-*')).toBe('tlsoc_alias_fosstlsoc_logs_moodle');
  });

  it('sanitizes a concrete dotted daily index', () => {
    expect(deriveAliasName('fosstlsoc-logs-moodle-2026.05.16')).toBe(
      'tlsoc_alias_fosstlsoc_logs_moodle_2026_05_16'
    );
  });

  it('output never contains "." or "*" (the chars the doc-level validator rejects)', () => {
    for (const p of ['a.b.c', 'logs-*', 'x.*.y', '.kibana_1', 'UPPER.Case-2026.01.01']) {
      const a = deriveAliasName(p);
      expect(a.includes('.')).toBe(false);
      expect(a.includes('*')).toBe(false);
    }
  });

  it('is deterministic and shared across rules on the same pattern', () => {
    expect(deriveAliasName('fosstlsoc-logs-moodle-*')).toBe(
      deriveAliasName('fosstlsoc-logs-moodle-*')
    );
  });

  it('falls back for an empty pattern', () => {
    expect(deriveAliasName('')).toBe('tlsoc_alias_index');
  });
});
