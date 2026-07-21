/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { CoverageRuleLike, foldCoverage } from './coverage_matrix';
import type { AttackCatalog } from '../../common/mitre/catalog';
import type { ThreatEntry } from '../../common/detection';

/** Small stub catalog — the fold is pure and catalog-injected, so the 200 KB real one stays out. */
const CATALOG: AttackCatalog = {
  version: 'test',
  tactics: [
    { id: 'TA0006', name: 'Credential Access', shortname: 'credential-access' },
    { id: 'TA0043', name: 'Reconnaissance', shortname: 'reconnaissance' },
  ],
  techniques: [
    {
      id: 'T1110',
      name: 'Brute Force',
      tactics: ['credential-access'],
      sub: [{ id: 'T1110.001', name: 'Password Guessing' }],
    },
    {
      id: 'T1595',
      name: 'Active Scanning',
      tactics: ['reconnaissance'],
      sub: [{ id: 'T1595.003', name: 'Wordlist Scanning' }],
    },
  ],
};

const threatWith = (techniqueId: string, subId?: string): ThreatEntry[] => [
  {
    framework: 'MITRE ATT&CK',
    technique: [
      {
        id: techniqueId,
        name: techniqueId,
        reference: `https://attack.mitre.org/techniques/${techniqueId}/`,
        ...(subId
          ? {
              subtechnique: [
                {
                  id: subId,
                  name: subId,
                  reference: `https://attack.mitre.org/techniques/${subId.replace('.', '/')}/`,
                },
              ],
            }
          : {}),
      },
    ],
  },
];

describe('foldCoverage', () => {
  it('counts one rule per top-level technique', () => {
    const rules: CoverageRuleLike[] = [
      { threat: threatWith('T1110') },
      { threat: threatWith('T1110') },
      { threat: threatWith('T1595') },
    ];
    const counts = foldCoverage(rules, CATALOG);
    expect(counts.get('T1110')).toBe(2);
    expect(counts.get('T1595')).toBe(1);
  });

  it('rolls sub-technique ids up to the parent technique cell', () => {
    // Sub id in the nested subtechnique array…
    const nested: CoverageRuleLike = { threat: threatWith('T1595', 'T1595.003') };
    // …and a sub id used directly as the technique id (imported-rule tolerance).
    const direct: CoverageRuleLike = { threat: threatWith('T1110.001') };
    const counts = foldCoverage([nested, direct], CATALOG);
    expect(counts.get('T1595')).toBe(1);
    expect(counts.get('T1110')).toBe(1);
    // No sub-technique rows exist in the matrix — subs never appear as their own key.
    expect(counts.has('T1595.003')).toBe(false);
    expect(counts.has('T1110.001')).toBe(false);
  });

  it('a rule tagging both parent and its sub counts ONCE in the parent cell', () => {
    const rule: CoverageRuleLike = { threat: threatWith('T1595', 'T1595.003') };
    const counts = foldCoverage([rule], CATALOG);
    expect(counts.get('T1595')).toBe(1);
  });

  it('tolerates unknown ids, missing threat, and malformed entries without throwing', () => {
    const rules: CoverageRuleLike[] = [
      { threat: threatWith('T9999') }, // unknown technique
      { threat: threatWith('T9999.001') }, // unknown sub
      {}, // no threat at all
      { threat: [] },
      // Structurally broken entries an imported rule could carry.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      { threat: [{ framework: 'MITRE ATT&CK', technique: 'not-an-array' } as any] },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      { threat: [{ framework: 'MITRE ATT&CK', technique: [{ id: 42 }] } as any] },
      { threat: threatWith('T1110') },
    ];
    const counts = foldCoverage(rules, CATALOG);
    expect(counts.get('T1110')).toBe(1);
    expect(counts.size).toBe(1);
  });

  it('returns an empty map for no rules', () => {
    expect(foldCoverage([], CATALOG).size).toBe(0);
  });
});
