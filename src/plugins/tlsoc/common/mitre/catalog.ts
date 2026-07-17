/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Types + pure lookup helpers over the offline MITRE ATT&CK® catalog (WS-21 / PROB-21).
 *
 * IMPORTANT: this module statically imports {@link ATTACK_CATALOG} from `./attack_catalog`, which
 * is a ~200 KB generated data module. Consumers must NEVER import this module (or `./index`)
 * statically from an eagerly-loaded bundle entry point — always reach it via
 * `await import('../../common/mitre')` (see public/detection/mitre_ttp_picker.tsx) so the data
 * lands in an async chunk, not the initial bundle.
 */

import { ATTACK_CATALOG } from './attack_catalog';

// Re-exported so consumers (e.g. the picker's tactic/technique lists) can enumerate the full
// catalog without a bespoke "list all" helper — every lookup function below defaults to it too.
export { ATTACK_CATALOG };

/** One MITRE ATT&CK Enterprise tactic (kill-chain phase), e.g. TA0006 "Credential Access". */
export interface AttackTactic {
  id: string;
  name: string;
  /** The STIX `x_mitre_shortname`, e.g. 'credential-access' — used to join techniques to tactics. */
  shortname: string;
}

/** One MITRE ATT&CK sub-technique, e.g. T1110.001 under T1110. */
export interface AttackSubtechnique {
  id: string;
  name: string;
}

/** One MITRE ATT&CK (top-level) technique, e.g. T1110 "Brute Force". */
export interface AttackTechnique {
  id: string;
  name: string;
  /** Tactic shortnames this technique belongs to (a technique may span multiple tactics). */
  tactics: string[];
  sub: AttackSubtechnique[];
}

/** The full offline catalog shipped in the bundle. */
export interface AttackCatalog {
  version: string;
  tactics: AttackTactic[];
  techniques: AttackTechnique[];
}

/** Result of {@link findTechnique}: the matched node plus its parent technique id when it's a sub. */
export interface TechniqueLookupResult {
  node: AttackTechnique | AttackSubtechnique;
  /** Set when `node` is a sub-technique — the id of its parent technique. */
  parentId?: string;
}

export function findTactic(
  id: string,
  catalog: AttackCatalog = ATTACK_CATALOG
): AttackTactic | undefined {
  return catalog.tactics.find((t) => t.id === id);
}

/**
 * Slug MUST mirror sigma.ts's `tagsFromThreat` slugification exactly
 * (`name.toLowerCase().replace(/\s+/g, '_')`) so tag round-tripping stays in sync.
 */
export function findTacticBySlug(
  slug: string,
  catalog: AttackCatalog = ATTACK_CATALOG
): AttackTactic | undefined {
  return catalog.tactics.find((t) => t.name.toLowerCase().replace(/\s+/g, '_') === slug);
}

export function techniquesForTactic(
  tacticId: string,
  catalog: AttackCatalog = ATTACK_CATALOG
): AttackTechnique[] {
  const tactic = findTactic(tacticId, catalog);
  if (!tactic) return [];
  return catalog.techniques.filter((t) => t.tactics.includes(tactic.shortname));
}

/** Search techniques AND their sub arrays for `id`; returns the node plus parent id when it's a sub. */
export function findTechnique(
  id: string,
  catalog: AttackCatalog = ATTACK_CATALOG
): TechniqueLookupResult | undefined {
  for (const technique of catalog.techniques) {
    if (technique.id === id) return { node: technique };
    const sub = technique.sub.find((s) => s.id === id);
    if (sub) return { node: sub, parentId: technique.id };
  }
  return undefined;
}

export function tacticReference(id: string): string {
  return `https://attack.mitre.org/tactics/${id}/`;
}

/** e.g. techniqueReference('T1110.001') === 'https://attack.mitre.org/techniques/T1110/001/'. */
export function techniqueReference(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}
