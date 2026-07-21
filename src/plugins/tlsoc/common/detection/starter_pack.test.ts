/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { MitreCatalogLookup, parseSigmaImport, SigmaImportSuccess } from './sigma_import';
import { getType } from './registry';
import { compileNewTermsToMonitor, NewTermsRuleDefinition } from './new_terms';
import { ThreatEntry, ThresholdRuleDefinition } from './types';
import { PACK_DEFAULT_INDEX, PackRule, STARTER_PACK } from './starter_pack';

/**
 * THE PACK INVARIANT TEST (v1.2.3 D10, research_r6 §C3 test plan): every bundled Sigma rule must
 * parse through the REAL importer with the REAL MITRE catalog — ok:true, the expected mode, zero
 * errors, and no unresolved-tag warnings. This pins the pack inside the `parseSigmaImport`
 * supported subset forever: if either the pack or the importer drifts, this suite fails by name
 * instead of the pack silently rotting. Native rules are pinned against their registry validators
 * and compilers the same way.
 */

// The real catalog, async-imported exactly like production consumers do (never static in
// bundles — catalog.ts docblock; in jest the async import is simply awaited).
let catalog: MitreCatalogLookup;
beforeAll(async () => {
  const mitre = await import('../mitre');
  catalog = (mitre.ATTACK_CATALOG as unknown) as MitreCatalogLookup;
});

/** Collect every tactic / technique / sub-technique id present in a rule's threat[]. */
function threatIds(threat: ThreatEntry[] | undefined): Set<string> {
  const ids = new Set<string>();
  (threat ?? []).forEach((entry) => {
    if (entry.tactic) ids.add(entry.tactic.id);
    (entry.technique ?? []).forEach((tech) => {
      ids.add(tech.id);
      (tech.subtechnique ?? []).forEach((sub) => ids.add(sub.id));
    });
  });
  return ids;
}

const sigmaRules = STARTER_PACK.filter((r): r is PackRule & { yaml: string } => r.kind === 'sigma');
const nativeRules = STARTER_PACK.filter((r) => r.kind === 'native');

describe('starter pack — shape', () => {
  it('bundles exactly 10 rules: 8 Sigma + 2 native (research_r6 §C3)', () => {
    expect(STARTER_PACK).toHaveLength(10);
    expect(sigmaRules).toHaveLength(8);
    expect(nativeRules).toHaveLength(2);
  });

  it('pack ids and titles are unique (titles drive the 409-skip idempotency)', () => {
    const ids = STARTER_PACK.map((r) => r.id);
    const titles = STARTER_PACK.map((r) => r.title);
    expect(new Set(ids).size).toBe(STARTER_PACK.length);
    expect(new Set(titles).size).toBe(STARTER_PACK.length);
  });

  it('every rule carries at least one MITRE id for the preview/coverage surfaces', () => {
    STARTER_PACK.forEach((r) => expect(r.mitre.length).toBeGreaterThan(0));
  });
});

describe('starter pack — THE INVARIANT: every Sigma rule parses inside the importer subset', () => {
  sigmaRules.forEach((pack) => {
    describe(pack.title, () => {
      it('parses ok with the real catalog, in the expected mode, with zero errors', () => {
        const result = parseSigmaImport(pack.yaml, { catalog });
        // On failure, surface the importer's named rejections in the test output.
        if (!result.ok) {
          throw new Error(
            `pack rule "${pack.id}" fell out of the importer subset: ` +
              result.errors.map((e) => `${e.construct}: ${e.reason}`).join('; ')
          );
        }
        expect(result.mode).toBe(pack.expectedMode);
        expect((result as { errors?: unknown }).errors).toBeUndefined();
      });

      it('warns ONLY about the data-view rebind (no unresolved tags, no lossy heuristics)', () => {
        const result = parseSigmaImport(pack.yaml, { catalog }) as SigmaImportSuccess;
        expect(result.ok).toBe(true);
        result.warnings.forEach((w) => expect(w).toMatch(/choose a data view/));
      });

      it('round-trips the bundled index hint and the pack title as the rule name', () => {
        const result = parseSigmaImport(pack.yaml, { catalog }) as SigmaImportSuccess;
        expect(result.rule.index).toBe(PACK_DEFAULT_INDEX);
        // The create route dedups by rule NAME — the modal's 409-skip idempotency depends on
        // the parsed name matching the pack title exactly.
        expect(result.rule.name).toBe(pack.title);
      });

      it('resolves every declared MITRE id into rule.threat via the real catalog', () => {
        const result = parseSigmaImport(pack.yaml, { catalog }) as SigmaImportSuccess;
        const ids = threatIds(result.rule.threat);
        pack.mitre.forEach((id) => expect(Array.from(ids)).toContain(id));
      });
    });
  });
});

describe('starter pack — native rules pass their registry contracts', () => {
  const scanner = STARTER_PACK.find((r) => r.id === 'web-scanner')!;
  const firstSeen = STARTER_PACK.find((r) => r.id === 'first-seen-country')!;

  it('#9 web scanner: validates and compiles through the stateful (D4 advanced) type', () => {
    const { mode, rule } = scanner.native!;
    expect(mode).toBe(scanner.expectedMode);
    expect(() => getType(mode).validate(rule)).not.toThrow();
    const monitor = getType(mode).compile(rule) as { monitor_type?: string; triggers?: unknown[] };
    expect(monitor.monitor_type).toBe('bucket_level_monitor');
    expect(monitor.triggers).toHaveLength(1);
  });

  it('#9 web scanner: group-by ships PRE-RESOLVED (.keyword for the text-mapped user agent)', () => {
    const rule = scanner.native!.rule as ThresholdRuleDefinition;
    // user_agent.original is text+keyword in the sample dataset (field_mappings.ts) — a terms
    // agg on the analyzed text field fails at monitor runtime with NO alert (research_r2 §a).
    expect(rule.groupBy).toEqual(['source.ip', 'user_agent.original.keyword']);
    expect(rule.advanced!.by).toEqual(rule.groupBy);
  });

  it('#9 web scanner: the advanced having encodes dc(url.path)>=40 AND errors>=50 over 10m', () => {
    const rule = scanner.native!.rule as ThresholdRuleDefinition;
    expect(rule.window).toEqual({ value: 10, unit: 'MINUTES' });
    expect(rule.advanced!.having).toEqual({
      kind: 'and',
      operands: [
        { kind: 'cmp', alias: 'unique_paths', op: 'gte', value: 40 },
        { kind: 'cmp', alias: 'error_hits', op: 'gte', value: 50 },
      ],
    });
  });

  it('#10 first-seen country: validates as a new_terms rule and compiles with a state doc id', () => {
    const { mode, rule } = firstSeen.native!;
    expect(mode).toBe(firstSeen.expectedMode);
    expect(() => getType(mode).validate(rule)).not.toThrow();
    // The save route owns the state-doc id; compile with a representative one.
    const monitor = compileNewTermsToMonitor(
      rule as NewTermsRuleDefinition,
      'seen-test-source.geo.country_iso_code'
    );
    expect(monitor.monitor_type).toBe('bucket_level_monitor');
  });

  it('#10 first-seen country: single term field, honestly adapted (not per-user)', () => {
    const rule = firstSeen.native!.rule as NewTermsRuleDefinition;
    expect(rule.termField).toBe('source.geo.country_iso_code');
    expect(rule.groupBy).toEqual([rule.termField]);
    expect(rule.historyWindow).toEqual({ value: 30, unit: 'DAYS' });
    // The adaptation from R6's "new country per user" must stay documented in the rule itself.
    expect(rule.description).toMatch(/not per user/);
  });

  it('native rules carry literal threat[] whose ids match the declared MITRE ids', () => {
    nativeRules.forEach((pack) => {
      const ids = threatIds((pack.native!.rule as ThresholdRuleDefinition).threat);
      pack.mitre.forEach((id) => expect(Array.from(ids)).toContain(id));
    });
  });

  it('native rules ship the default index the modal rebinds', () => {
    nativeRules.forEach((pack) => {
      expect((pack.native!.rule as { index: string }).index).toBe(PACK_DEFAULT_INDEX);
    });
  });
});
