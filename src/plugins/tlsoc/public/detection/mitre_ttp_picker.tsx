/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * MITRE ATT&CK TTP picker (WS-21 / PROB-21) — replaces free-text tactic/technique entry (which
 * produced real broken ids like "Brutforce") with a cascading tactic → technique → sub-technique
 * picker backed by the offline v19.1 catalog ({@link ../../common/mitre}). NOT wired into the
 * detection builder by this task — standalone component, ready for a follow-up wiring task.
 *
 * The catalog (~200 KB generated data module) is lazy-loaded via a dynamic import so it never
 * lands in the initial bundle — mirrors the route-level code-splitting idiom already used in
 * public/plugin.ts (`await import('./application')`).
 */

import { useEffect, useState } from 'react';
import {
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiComboBox,
  EuiComboBoxOptionOption,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiIconTip,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import { ThreatEntry, ThreatTechnique } from '../../common/detection';
// Type-only import: never pulls the ~200 KB data module into this (or any) bundle — the runtime
// value only ever arrives via the dynamic import in the effect below.
import type * as MitreCatalogModule from '../../common/mitre';

type CatalogModule = typeof MitreCatalogModule;

interface Props {
  value: ThreatEntry[];
  onChange: (threat: ThreatEntry[]) => void;
}

const EMPTY_ENTRY: ThreatEntry = { framework: 'MITRE ATT&CK' };

/** Drop rows with neither a tactic nor a technique — the shape the legacy builder's helper produced. */
function cleanThreatEntry(entry: ThreatEntry): ThreatEntry | undefined {
  const techniques = (entry.technique ?? []).filter((t) => t.id);
  if (!entry.tactic?.id && techniques.length === 0) return undefined;
  return {
    framework: 'MITRE ATT&CK',
    ...(entry.tactic?.id ? { tactic: entry.tactic } : {}),
    ...(techniques.length ? { technique: techniques } : {}),
  };
}

function cleanAll(rows: ThreatEntry[]): ThreatEntry[] {
  const cleaned: ThreatEntry[] = [];
  for (const row of rows) {
    const c = cleanThreatEntry(row);
    if (c) cleaned.push(c);
  }
  return cleaned;
}

function tacticOptionLabel(id: string, name: string): string {
  return `${id} — ${name}`;
}

/** One ThreatEntry row: cascading tactic → technique → sub-technique selectors. */
function TtpRow({
  entry,
  catalog,
  showRemove,
  onChange,
  onRemove,
}: {
  entry: ThreatEntry;
  catalog: CatalogModule;
  showRemove: boolean;
  onChange: (next: ThreatEntry) => void;
  onRemove: () => void;
}) {
  const {
    ATTACK_CATALOG,
    findTactic,
    techniquesForTactic,
    tacticReference,
    techniqueReference,
  } = catalog;

  const selectedTacticId = entry.tactic?.id;
  const knownTactic = selectedTacticId ? findTactic(selectedTacticId) : undefined;
  const tacticIsUnknown = !!selectedTacticId && !knownTactic;

  const knownTechniqueIds = new Set(ATTACK_CATALOG.techniques.map((t) => t.id));
  const allTechniqueEntries = entry.technique ?? [];
  const knownTechniqueEntries = allTechniqueEntries.filter((t) => knownTechniqueIds.has(t.id));
  const unknownTechniqueEntries = allTechniqueEntries.filter((t) => !knownTechniqueIds.has(t.id));

  const availableTechniques = knownTactic
    ? techniquesForTactic(knownTactic.id)
    : ATTACK_CATALOG.techniques;

  // Sub-technique options: grouped by parent technique id, built ONLY from the currently selected
  // known techniques (never the whole catalog) so the dropdown stays scoped to this row's picks.
  const subGroups: Array<EuiComboBoxOptionOption<string>> = knownTechniqueEntries
    .map((techniqueEntry): EuiComboBoxOptionOption<string> | undefined => {
      const catalogTechnique = ATTACK_CATALOG.techniques.find((t) => t.id === techniqueEntry.id);
      if (!catalogTechnique || catalogTechnique.sub.length === 0) return undefined;
      return {
        label: catalogTechnique.id,
        options: catalogTechnique.sub.map((s) => ({
          label: `${s.id} — ${s.name}`,
          value: s.id,
        })),
      };
    })
    .filter((g): g is EuiComboBoxOptionOption<string> => g !== undefined);

  // Reverse map: sub id -> its parent's catalog technique id, derived from the SAME scoped groups
  // above (a real lookup, not id-prefix string matching).
  const subParent = new Map<string, string>();
  for (const group of subGroups) {
    for (const opt of group.options ?? []) {
      if (opt.value) subParent.set(opt.value, group.label);
    }
  }

  const selectedSubOptions: Array<EuiComboBoxOptionOption<string>> = [];
  const unknownSubs: Array<{ parentId: string; sub: ThreatTechnique }> = [];
  for (const techniqueEntry of knownTechniqueEntries) {
    for (const sub of techniqueEntry.subtechnique ?? []) {
      if (subParent.get(sub.id) === techniqueEntry.id) {
        selectedSubOptions.push({ label: `${sub.id} — ${sub.name}`, value: sub.id });
      } else {
        unknownSubs.push({ parentId: techniqueEntry.id, sub });
      }
    }
  }

  function updateTactic(selected: Array<EuiComboBoxOptionOption<string>>) {
    const id = selected[0]?.value;
    if (!id) {
      const { tactic, ...rest } = entry;
      onChange(rest);
      return;
    }
    const tactic = findTactic(id);
    onChange({
      ...entry,
      tactic: tactic
        ? { id: tactic.id, name: tactic.name, reference: tacticReference(tactic.id) }
        : { id, name: id, reference: tacticReference(id) },
    });
  }

  function removeUnknownTactic() {
    const { tactic, ...rest } = entry;
    onChange(rest);
  }

  function updateTechniques(selected: Array<EuiComboBoxOptionOption<string>>) {
    const nextKnown: ThreatTechnique[] = selected
      .map((opt) => opt.value)
      .filter((id): id is string => !!id)
      .map((id) => {
        const existing = knownTechniqueEntries.find((t) => t.id === id);
        const catalogTechnique = ATTACK_CATALOG.techniques.find((t) => t.id === id);
        return {
          id,
          name: catalogTechnique?.name ?? id,
          reference: techniqueReference(id),
          // Preserve any previously-chosen sub-techniques for a technique that stays selected.
          ...(existing?.subtechnique?.length ? { subtechnique: existing.subtechnique } : {}),
        };
      });
    onChange({ ...entry, technique: [...nextKnown, ...unknownTechniqueEntries] });
  }

  function removeUnknownTechnique(id: string) {
    onChange({
      ...entry,
      technique: allTechniqueEntries.filter((t) => t.id !== id),
    });
  }

  function updateSubtechniques(selected: Array<EuiComboBoxOptionOption<string>>) {
    const selectedIds = new Set(
      selected.map((opt) => opt.value).filter((id): id is string => !!id)
    );
    const nextKnown = knownTechniqueEntries.map((techniqueEntry) => {
      const catalogTechnique = ATTACK_CATALOG.techniques.find((t) => t.id === techniqueEntry.id);
      const subs = (catalogTechnique?.sub ?? [])
        .filter((s) => selectedIds.has(s.id))
        .map((s) => ({ id: s.id, name: s.name, reference: techniqueReference(s.id) }));
      // Keep any pre-existing unknown subs attached to this technique untouched.
      const preservedUnknown = unknownSubs
        .filter((u) => u.parentId === techniqueEntry.id)
        .map((u) => u.sub);
      const subtechnique = [...subs, ...preservedUnknown];
      return {
        ...techniqueEntry,
        ...(subtechnique.length ? { subtechnique } : { subtechnique: undefined }),
      };
    });
    onChange({ ...entry, technique: [...nextKnown, ...unknownTechniqueEntries] });
  }

  function removeUnknownSub(parentId: string, subId: string) {
    onChange({
      ...entry,
      technique: allTechniqueEntries.map((t) =>
        t.id === parentId
          ? { ...t, subtechnique: (t.subtechnique ?? []).filter((s) => s.id !== subId) }
          : t
      ),
    });
  }

  return (
    <EuiPanel hasBorder paddingSize="m">
      <EuiFlexGroup gutterSize="s" alignItems="flexStart" responsive={false}>
        <EuiFlexItem>
          <EuiFormRow label="Tactic">
            <EuiComboBox
              singleSelection={{ asPlainText: true }}
              placeholder="Select a tactic"
              options={ATTACK_CATALOG.tactics.map((t) => ({
                label: tacticOptionLabel(t.id, t.name),
                value: t.id,
              }))}
              selectedOptions={
                knownTactic
                  ? [
                      {
                        label: tacticOptionLabel(knownTactic.id, knownTactic.name),
                        value: knownTactic.id,
                      },
                    ]
                  : []
              }
              onChange={updateTactic}
              isClearable
            />
          </EuiFormRow>
          {tacticIsUnknown ? (
            <>
              <EuiSpacer size="xs" />
              <EuiFlexGroup gutterSize="xs" alignItems="center" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiText size="xs" color="warning">
                    {entry.tactic?.id} — {entry.tactic?.name} (not in the bundled ATT&CK v19.1
                    catalog)
                  </EuiText>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButtonIcon
                    iconType="cross"
                    color="warning"
                    aria-label="Remove unrecognized tactic"
                    onClick={removeUnknownTactic}
                  />
                </EuiFlexItem>
              </EuiFlexGroup>
            </>
          ) : null}
        </EuiFlexItem>

        <EuiFlexItem>
          <EuiFormRow label="Technique(s)">
            <EuiComboBox
              placeholder="Select technique(s)"
              options={availableTechniques.map((t) => ({
                label: `${t.id} — ${t.name}`,
                value: t.id,
              }))}
              selectedOptions={knownTechniqueEntries.map((t) => ({
                label: `${t.id} — ${t.name}`,
                value: t.id,
              }))}
              onChange={updateTechniques}
            />
          </EuiFormRow>
          {unknownTechniqueEntries.length > 0 ? (
            <>
              <EuiSpacer size="xs" />
              {unknownTechniqueEntries.map((t) => (
                <EuiFlexGroup key={t.id} gutterSize="xs" alignItems="center" responsive={false}>
                  <EuiFlexItem grow={false}>
                    <EuiText size="xs" color="warning">
                      {t.id} — {t.name} (not in the bundled ATT&CK v19.1 catalog)
                    </EuiText>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButtonIcon
                      iconType="cross"
                      color="warning"
                      aria-label={`Remove unrecognized technique ${t.id}`}
                      onClick={() => removeUnknownTechnique(t.id)}
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
              ))}
            </>
          ) : null}
        </EuiFlexItem>

        <EuiFlexItem>
          <EuiFormRow label="Sub-technique(s)">
            <EuiComboBox
              placeholder={
                knownTechniqueEntries.length === 0
                  ? 'Select a technique first'
                  : 'Select sub-technique(s)'
              }
              isDisabled={knownTechniqueEntries.length === 0}
              options={subGroups}
              selectedOptions={selectedSubOptions}
              onChange={updateSubtechniques}
            />
          </EuiFormRow>
          {unknownSubs.length > 0 ? (
            <>
              <EuiSpacer size="xs" />
              {unknownSubs.map(({ parentId, sub }) => (
                <EuiFlexGroup key={sub.id} gutterSize="xs" alignItems="center" responsive={false}>
                  <EuiFlexItem grow={false}>
                    <EuiText size="xs" color="warning">
                      {sub.id} — {sub.name} (not in the bundled ATT&CK v19.1 catalog)
                    </EuiText>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButtonIcon
                      iconType="cross"
                      color="warning"
                      aria-label={`Remove unrecognized sub-technique ${sub.id}`}
                      onClick={() => removeUnknownSub(parentId, sub.id)}
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
              ))}
            </>
          ) : null}
        </EuiFlexItem>

        {showRemove ? (
          <EuiFlexItem grow={false}>
            <EuiFormRow hasEmptyLabelSpace>
              <EuiButtonIcon
                iconType="minusInCircle"
                color="danger"
                aria-label="Remove threat entry"
                onClick={onRemove}
              />
            </EuiFormRow>
          </EuiFlexItem>
        ) : null}
      </EuiFlexGroup>
    </EuiPanel>
  );
}

/**
 * Cascading MITRE ATT&CK tactic → technique → sub-technique picker over the offline v19.1
 * catalog. `value`/`onChange` carry {@link ThreatEntry}[] — the same shape the (stateless)
 * detection IR's `threat` field expects. Not wired into the detection builder by this task.
 */
export function MitreTtpPicker({ value, onChange }: Props) {
  const [catalog, setCatalog] = useState<CatalogModule | undefined>(undefined);
  // Local, uncleaned working copy — seeded once from `value`. Kept separate from what's emitted
  // via onChange (see `emit` below) so an in-progress empty draft row (added via "Add threat
  // entry", not yet given a tactic/technique) stays visible instead of disappearing the instant
  // cleanAll() would drop it from the emitted value.
  const [rows, setRows] = useState<ThreatEntry[]>(value);

  useEffect(() => {
    let cancelled = false;
    import('../../common/mitre').then((mod) => {
      if (!cancelled) setCatalog(mod);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!catalog) {
    return <EuiLoadingSpinner size="m" />;
  }

  function emit(nextRows: ThreatEntry[]) {
    setRows(nextRows);
    onChange(cleanAll(nextRows));
  }

  return (
    <div>
      <EuiFlexGroup gutterSize="xs" alignItems="center" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiText size="xs" color="subdued">
            MITRE ATT&CK classification
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiIconTip
            type="iInCircle"
            content="MITRE ATT&CK® is a registered trademark of The MITRE Corporation. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
            aria-label="MITRE ATT&CK attribution"
          />
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      {rows.map((entry, i) => (
        <div key={i}>
          <TtpRow
            entry={entry}
            catalog={catalog}
            showRemove={rows.length > 0}
            onChange={(next) => {
              const nextRows = [...rows];
              nextRows[i] = next;
              emit(nextRows);
            }}
            onRemove={() => emit(rows.filter((_, ri) => ri !== i))}
          />
          <EuiSpacer size="s" />
        </div>
      ))}
      <EuiButtonEmpty iconType="plusInCircle" onClick={() => emit([...rows, { ...EMPTY_ENTRY }])}>
        Add threat entry
      </EuiButtonEmpty>
    </div>
  );
}
