/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { ATTACK_CATALOG } from './attack_catalog';
import {
  findTactic,
  findTacticBySlug,
  findTechnique,
  tacticReference,
  techniqueReference,
  techniquesForTactic,
} from './catalog';

const TACTIC_ID_RE = /^TA\d{4}$/;
const TECHNIQUE_ID_RE = /^T\d{4}$/;
const SUB_ID_RE = /^T\d{4}\.\d{3}$/;

describe('ATTACK_CATALOG — v19.1 shape', () => {
  it('is pinned to version 19.1', () => {
    expect(ATTACK_CATALOG.version).toBe('19.1');
  });

  it('has exactly 15 tactics, including TA0112 and TA0005', () => {
    expect(ATTACK_CATALOG.tactics).toHaveLength(15);
    const ids = ATTACK_CATALOG.tactics.map((t) => t.id);
    expect(ids).toContain('TA0112');
    expect(ids).toContain('TA0005');
    const ta0112 = ATTACK_CATALOG.tactics.find((t) => t.id === 'TA0112');
    const ta0005 = ATTACK_CATALOG.tactics.find((t) => t.id === 'TA0005');
    expect(ta0112?.name).toBe('Defense Impairment');
    expect(ta0005?.name).toBe('Stealth');
  });

  it('has at least 200 techniques', () => {
    expect(ATTACK_CATALOG.techniques.length).toBeGreaterThanOrEqual(200);
  });

  it('has at least 400 sub-techniques in total', () => {
    const subCount = ATTACK_CATALOG.techniques.reduce((n, t) => n + t.sub.length, 0);
    expect(subCount).toBeGreaterThanOrEqual(400);
  });

  it('every tactic id matches TA\\d{4} — garbage ids are structurally impossible', () => {
    for (const tactic of ATTACK_CATALOG.tactics) {
      expect(tactic.id).toMatch(TACTIC_ID_RE);
    }
  });

  it('every technique id matches T\\d{4}, every sub-technique id matches T\\d{4}.\\d{3}', () => {
    for (const technique of ATTACK_CATALOG.techniques) {
      expect(technique.id).toMatch(TECHNIQUE_ID_RE);
      for (const sub of technique.sub) {
        expect(sub.id).toMatch(SUB_ID_RE);
      }
    }
  });

  it('every technique tactics[] shortname resolves to a bundled tactic', () => {
    const shortnames = new Set(ATTACK_CATALOG.tactics.map((t) => t.shortname));
    for (const technique of ATTACK_CATALOG.techniques) {
      for (const shortname of technique.tactics) {
        expect(shortnames.has(shortname)).toBe(true);
      }
    }
  });
});

describe('findTechnique', () => {
  it("T1110 resolves to 'Brute Force' with sub-techniques attached", () => {
    const result = findTechnique('T1110');
    expect(result).toBeDefined();
    expect(result?.node.id).toBe('T1110');
    expect(result?.node.name).toBe('Brute Force');
    expect(result?.parentId).toBeUndefined();
    expect((result?.node as { sub: unknown[] }).sub.length).toBeGreaterThan(0);
  });

  it('resolves a sub-technique with its parent id attached', () => {
    const parent = ATTACK_CATALOG.techniques.find((t) => t.id === 'T1110');
    const subId = parent!.sub[0].id;
    const result = findTechnique(subId);
    expect(result).toBeDefined();
    expect(result?.node.id).toBe(subId);
    expect(result?.parentId).toBe('T1110');
  });

  it('returns undefined for an id not in the catalog', () => {
    expect(findTechnique('Brutforce')).toBeUndefined();
  });
});

describe('techniquesForTactic', () => {
  it('TA0006 (Credential Access) contains T1110', () => {
    const techniques = techniquesForTactic('TA0006');
    expect(techniques.map((t) => t.id)).toContain('T1110');
  });

  it('returns [] for an unknown tactic id', () => {
    expect(techniquesForTactic('TA9999')).toEqual([]);
  });
});

describe('findTactic / findTacticBySlug round-trip', () => {
  it('every tactic slug round-trips through findTacticBySlug', () => {
    for (const tactic of ATTACK_CATALOG.tactics) {
      const slug = tactic.name.toLowerCase().replace(/\s+/g, '_');
      const found = findTacticBySlug(slug);
      expect(found?.id).toBe(tactic.id);
    }
  });

  it('findTactic resolves a known id and returns undefined for an unknown one', () => {
    expect(findTactic('TA0006')?.name).toBe('Credential Access');
    expect(findTactic('TA9999')).toBeUndefined();
  });
});

describe('reference URL builders', () => {
  it('tacticReference derives the attack.mitre.org tactic URL', () => {
    expect(tacticReference('TA0006')).toBe('https://attack.mitre.org/tactics/TA0006/');
  });

  it('techniqueReference derives the attack.mitre.org technique URL', () => {
    expect(techniqueReference('T1110')).toBe('https://attack.mitre.org/techniques/T1110/');
  });

  it('techniqueReference derives the attack.mitre.org sub-technique URL (dot -> slash)', () => {
    expect(techniqueReference('T1110.001')).toBe('https://attack.mitre.org/techniques/T1110/001/');
  });
});
