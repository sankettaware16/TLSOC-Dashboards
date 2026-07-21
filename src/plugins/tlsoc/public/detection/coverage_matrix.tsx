/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { CSSProperties, useEffect, useState } from 'react';
import {
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import type { ThreatEntry } from '../../common/detection';
// Type-only imports are erased at runtime — the ~200 KB catalog DATA module is only ever loaded
// via `await import('../../common/mitre')` below (the HARD RULE in common/mitre/catalog.ts), and
// only once this component mounts, i.e. only when the coverage tab is actually opened.
import type { AttackCatalog, AttackTechnique } from '../../common/mitre/catalog';

/** The slice of a rules-LIST row this matrix needs. `threat` is the W4a LIST extension —
 * ABSENT on older payloads, and the fold degrades to zero counts instead of crashing. */
export interface CoverageRuleLike {
  threat?: ThreatEntry[];
}

/**
 * Fold installed rules into per-technique rule counts (v1.2.3 D10 coverage matrix).
 *
 * - Sub-technique ids ROLL UP to their parent technique's cell (research_r6 §C4: attribute via
 *   the catalog's sub→parent relation — the matrix has no sub-technique rows).
 * - Counting is per RULE per technique (a rule tagging both T1595 and T1595.003 counts once in
 *   the T1595 cell).
 * - Unknown ids (a typo, a future ATT&CK version, junk from an imported rule) are silently
 *   SKIPPED — tolerated, never crashed on: coverage is triage metadata, not detection logic.
 */
export function foldCoverage(
  rules: CoverageRuleLike[],
  catalog: AttackCatalog
): Map<string, number> {
  const topLevel = new Set<string>();
  const parentOf = new Map<string, string>();
  catalog.techniques.forEach((tech) => {
    topLevel.add(tech.id);
    tech.sub.forEach((sub) => parentOf.set(sub.id, tech.id));
  });

  const counts = new Map<string, number>();
  for (const rule of rules) {
    const perRule = new Set<string>();
    const addId = (id: unknown) => {
      if (typeof id !== 'string') return;
      const parent = parentOf.get(id);
      if (parent !== undefined) perRule.add(parent);
      else if (topLevel.has(id)) perRule.add(id);
      // else: unknown id — tolerated, skipped.
    };
    const threat = Array.isArray(rule?.threat) ? rule.threat : [];
    for (const entry of threat) {
      const techniques = Array.isArray(entry?.technique) ? entry.technique : [];
      for (const tech of techniques) {
        addId(tech?.id);
        const subs = Array.isArray(tech?.subtechnique) ? tech.subtechnique : [];
        for (const sub of subs) addId(sub?.id);
      }
    }
    perRule.forEach((id) => counts.set(id, (counts.get(id) ?? 0) + 1));
  }
  return counts;
}

/** Count-tinted cell background — deeper tint = more rules cover the technique. */
function cellStyle(count: number, clickable: boolean): CSSProperties {
  const base: CSSProperties = {
    display: 'block',
    width: '100%',
    textAlign: 'left',
    border: '1px solid rgba(128, 128, 128, 0.25)',
    borderRadius: 4,
    padding: '4px 6px',
    marginBottom: 4,
    background: 'transparent',
    cursor: clickable ? 'pointer' : 'default',
    font: 'inherit',
    color: 'inherit',
  };
  if (count >= 4) return { ...base, background: 'rgba(0, 119, 204, 0.55)' };
  if (count >= 2) return { ...base, background: 'rgba(0, 119, 204, 0.34)' };
  if (count >= 1) return { ...base, background: 'rgba(0, 119, 204, 0.18)' };
  return { ...base, opacity: 0.65 };
}

interface Props {
  core: CoreStart;
  /** Click a covered cell → the caller filters the Rules tab by this technique id. */
  onSelectTechnique?: (techniqueId: string) => void;
}

/**
 * The MITRE ATT&CK coverage matrix (v1.2.3 D10): tactic columns × technique cells, count-colored
 * by the installed rules' `threat[]` tags. RENDERED FROM THE CATALOG — all 15 v19.1 tactics in
 * catalog order (incl. the renamed TA0005 "Stealth", TA0042/TA0043), never a hardcoded list
 * (research_r6 §C4). Data = the rules LIST response; the catalog loads lazily on mount (i.e. on
 * tab open), never in the initial bundle.
 */
export function CoverageMatrix({ core, onSelectTechnique }: Props) {
  const [catalog, setCatalog] = useState<AttackCatalog | null>(null);
  const [rules, setRules] = useState<CoverageRuleLike[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [mitre, resp] = await Promise.all([
          import('../../common/mitre'),
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          core.http.get('/api/tlsoc/detection/monitors') as Promise<any>,
        ]);
        if (cancelled) return;
        setCatalog(mitre.ATTACK_CATALOG);
        setRules(resp?.rules ?? []);
      } catch (e) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const err = e as any;
        if (!cancelled) {
          setError(err?.body?.message ?? err?.message ?? 'Could not load coverage data');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [core]);

  if (loading) {
    return (
      <EuiPage paddingSize="l">
        <EuiPageBody>
          <EuiFlexGroup justifyContent="center" alignItems="center" gutterSize="s">
            <EuiFlexItem grow={false}>
              <EuiLoadingSpinner size="m" />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="s">Loading ATT&CK coverage…</EuiText>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPageBody>
      </EuiPage>
    );
  }

  if (error || !catalog) {
    return (
      <EuiPage paddingSize="l">
        <EuiPageBody>
          <EuiCallOut color="danger" iconType="alert" title="Something went wrong">
            <p>{error ?? 'The MITRE ATT&CK catalog could not be loaded.'}</p>
          </EuiCallOut>
        </EuiPageBody>
      </EuiPage>
    );
  }

  const counts = foldCoverage(rules, catalog);
  const coveredTechniques = counts.size;
  const taggedRules = rules.filter(
    (r) => Array.isArray(r.threat) && r.threat.length > 0
  ).length;

  return (
    <EuiPage paddingSize="l">
      <EuiPageBody>
        <EuiTitle size="l">
          <h1>ATT&amp;CK coverage</h1>
        </EuiTitle>
        <EuiText color="subdued" size="s">
          <p>
            MITRE ATT&amp;CK® Enterprise v{catalog.version} — {coveredTechniques} of{' '}
            {catalog.techniques.length} techniques covered by {taggedRules} tagged rule
            {taggedRules === 1 ? '' : 's'} ({rules.length} installed). Sub-technique tags count
            toward their parent technique.
          </p>
        </EuiText>
        <EuiSpacer size="m" />
        {rules.length > 0 && taggedRules === 0 ? (
          <>
            <EuiCallOut
              size="s"
              color="primary"
              iconType="iInCircle"
              title="No MITRE ATT&CK tags found on the installed rules"
            >
              <p>
                Tag rules with ATT&amp;CK techniques in the builder (or install the starter
                pack) to light this matrix up.
              </p>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        ) : null}
        <EuiPanel hasShadow={false} hasBorder style={{ overflowX: 'auto' }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
            {catalog.tactics.map((tactic) => {
              const techniques: AttackTechnique[] = catalog.techniques.filter((t) =>
                t.tactics.includes(tactic.shortname)
              );
              return (
                <div key={tactic.id} style={{ minWidth: 168, maxWidth: 168, flex: '0 0 auto' }}>
                  <EuiText size="xs">
                    <strong>{tactic.name}</strong>
                    <br />
                    <span style={{ opacity: 0.7 }}>
                      {tactic.id} · {techniques.length}
                    </span>
                  </EuiText>
                  <EuiSpacer size="xs" />
                  {techniques.map((tech) => {
                    const count = counts.get(tech.id) ?? 0;
                    const clickable = count > 0 && !!onSelectTechnique;
                    return (
                      <EuiToolTip
                        key={`${tactic.id}-${tech.id}`}
                        position="top"
                        content={`${tech.id} ${tech.name} — ${count} rule${count === 1 ? '' : 's'}${
                          clickable ? ' (click to view them)' : ''
                        }`}
                      >
                        <button
                          type="button"
                          style={cellStyle(count, clickable)}
                          disabled={!clickable}
                          onClick={() => clickable && onSelectTechnique!(tech.id)}
                          data-test-subj={`tlsocCoverageCell-${tech.id}`}
                        >
                          <EuiText size="xs" style={{ lineHeight: 1.2 }}>
                            <span>{tech.name}</span>
                            {count > 0 ? <strong> · {count}</strong> : null}
                          </EuiText>
                        </button>
                      </EuiToolTip>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </EuiPanel>
      </EuiPageBody>
    </EuiPage>
  );
}
