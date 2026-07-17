/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Generator for `attack_catalog.ts` (WS-21 / PROB-21).
 *
 * Produces a compact, offline MITRE ATT&CK® Enterprise catalog from the pinned STIX bundle at
 * https://github.com/mitre-attack/attack-stix-data, tag v19.1. Run this ONCE at build/authoring
 * time — it is NOT part of the runtime, and it is NOT run in CI. The runtime never touches the
 * network; only the committed output of this script (`attack_catalog.ts`) ships.
 *
 * SOURCE (pinned):
 *   https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/enterprise-attack/enterprise-attack-19.1.json
 *   (fallback: the unversioned `enterprise-attack.json` at the same tag)
 *
 * EXTRACTION RECIPE (from the attack-stix-data repo's USAGE.md):
 *   - tactics        = `x-mitre-tactic` objects
 *                       -> { id: external_references[source_name=='mitre-attack'].external_id,
 *                            name, shortname: x_mitre_shortname }
 *   - techniques     = `attack-pattern` objects with x_mitre_is_subtechnique === false
 *                       -> { id (same external_id path), name,
 *                            tactics: kill_chain_phases[].phase_name (the shortname) }
 *   - sub-techniques = `attack-pattern` objects with x_mitre_is_subtechnique === true, joined to
 *                       their parent via `relationship` objects where
 *                       relationship_type === 'subtechnique-of' (source_ref = sub, target_ref =
 *                       parent) — NOT by id-prefix string matching.
 *   - DROP every object with revoked === true or x_mitre_deprecated === true, and drop any
 *     relationship pointing at a dropped object.
 *   - Output is sorted (tactics by id, techniques by id, subs by id) for determinism.
 *
 * HOW TO RE-RUN (e.g. for a future ATT&CK release):
 *   1. Download the pinned bundle to a scratch path (NOT into the repo), e.g.:
 *        curl -sL -o /tmp/enterprise-attack.json \
 *          https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v<TAG>/enterprise-attack/enterprise-attack-<TAG>.json
 *   2. node src/plugins/tlsoc/common/mitre/generate_catalog.js /tmp/enterprise-attack.json <version>
 *   3. Review the diff to `attack_catalog.ts`, update the header comment's version/tag, commit.
 */

/* eslint-disable no-console */
const fs = require('fs');
const path = require('path');

function fail(message) {
  console.error(message);
  process.exit(1);
}

function mitreExternalId(obj) {
  const ref = (obj.external_references || []).find((r) => r.source_name === 'mitre-attack');
  return ref ? ref.external_id : undefined;
}

function isLive(obj) {
  return obj.revoked !== true && obj.x_mitre_deprecated !== true;
}

function generate(bundlePath, version) {
  const raw = fs.readFileSync(bundlePath, 'utf8');
  const bundle = JSON.parse(raw);
  const objects = bundle.objects || [];

  const liveIds = new Set(objects.filter(isLive).map((o) => o.id));

  // --- tactics ---
  const tactics = objects
    .filter((o) => o.type === 'x-mitre-tactic' && isLive(o))
    .map((o) => ({
      id: mitreExternalId(o),
      name: o.name,
      shortname: o.x_mitre_shortname,
    }))
    .filter((t) => t.id)
    .sort((a, b) => a.id.localeCompare(b.id));

  // --- attack-pattern split into techniques / sub-techniques ---
  const attackPatterns = objects.filter((o) => o.type === 'attack-pattern' && isLive(o));
  const techniqueObjs = attackPatterns.filter((o) => o.x_mitre_is_subtechnique === false);
  const subObjs = attackPatterns.filter((o) => o.x_mitre_is_subtechnique === true);

  // sub-technique -> parent technique, via subtechnique-of relationships (not id-prefix matching)
  const subToParentStixId = new Map();
  for (const rel of objects) {
    if (rel.type !== 'relationship') continue;
    if (rel.relationship_type !== 'subtechnique-of') continue;
    if (!isLive(rel)) continue;
    if (!liveIds.has(rel.source_ref) || !liveIds.has(rel.target_ref)) continue;
    subToParentStixId.set(rel.source_ref, rel.target_ref);
  }

  const techniqueByStixId = new Map(techniqueObjs.map((o) => [o.id, o]));

  const subsByParentExternalId = new Map();
  for (const subObj of subObjs) {
    const parentStixId = subToParentStixId.get(subObj.id);
    if (!parentStixId) continue; // orphaned sub-technique (no live parent) — skip
    const parentObj = techniqueByStixId.get(parentStixId);
    if (!parentObj) continue;
    const parentExternalId = mitreExternalId(parentObj);
    const subExternalId = mitreExternalId(subObj);
    if (!parentExternalId || !subExternalId) continue;
    if (!subsByParentExternalId.has(parentExternalId))
      subsByParentExternalId.set(parentExternalId, []);
    subsByParentExternalId.get(parentExternalId).push({ id: subExternalId, name: subObj.name });
  }
  for (const subs of subsByParentExternalId.values()) {
    subs.sort((a, b) => a.id.localeCompare(b.id));
  }

  const techniques = techniqueObjs
    .map((o) => {
      const id = mitreExternalId(o);
      const tacticShortnames = (o.kill_chain_phases || [])
        .filter((k) => k.kill_chain_name === 'mitre-attack')
        .map((k) => k.phase_name);
      return {
        id,
        name: o.name,
        tactics: tacticShortnames,
        sub: subsByParentExternalId.get(id) || [],
      };
    })
    .filter((t) => t.id)
    .sort((a, b) => a.id.localeCompare(b.id));

  const subCount = techniques.reduce((n, t) => n + t.sub.length, 0);

  console.log(`tactics: ${tactics.length}`);
  console.log(`techniques: ${techniques.length}`);
  console.log(`sub-techniques: ${subCount}`);

  const header = `/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * GENERATED by generate_catalog.js from MITRE ATT&CK v${version} — do not hand-edit.
 *
 * MITRE ATT&CK® is a registered trademark of The MITRE Corporation. © ${new Date().getFullYear()}
 * The MITRE Corporation. This work is reproduced and distributed with the permission of The
 * MITRE Corporation. See NOTICE.txt for the full attribution.
 */

import { AttackCatalog } from './catalog';

export const ATTACK_CATALOG: AttackCatalog = `;

  const body = JSON.stringify({ version, tactics, techniques }, null, 2);
  const footer = ';\n';

  const outPath = path.join(__dirname, 'attack_catalog.ts');
  fs.writeFileSync(outPath, header + body + footer);

  const bytes = fs.statSync(outPath).size;
  console.log(`wrote ${outPath} (${bytes} bytes, ${(bytes / 1024).toFixed(1)} KB)`);
}

const [, , bundlePathArg, versionArg] = process.argv;
if (!bundlePathArg || !versionArg) {
  fail('Usage: node generate_catalog.js <path-to-stix-bundle.json> <version e.g. 19.1>');
}
generate(bundlePathArg, versionArg);
