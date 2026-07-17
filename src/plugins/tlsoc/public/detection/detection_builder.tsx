/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useMemo, useState } from 'react';
import {
  EuiAccordion,
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiButtonIcon,
  EuiCallOut,
  EuiCodeBlock,
  EuiComboBox,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiHorizontalRule,
  EuiMarkdownEditor,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../../data/public';
import {
  Condition,
  ConditionGroup,
  CountThreshold,
  RuleDefinition,
  RuleMetadataFields,
  Severity,
  ThreatEntry,
  ThresholdRuleDefinition,
  TimeWindow,
  compileToDocLevelMonitor,
  compileToSigma,
  compileToSigmaCorrelation,
  deriveAliasName,
} from '../../common/detection';
import { ConditionRow } from './condition_row';
import { useDataViewFields, useDataViews } from './use_data_view_fields';
import {
  DetectionMode,
  MODE_OPTIONS,
  OPERATOR_OPTIONS,
  SEVERITY_OPTIONS,
  THRESHOLD_OP_OPTIONS,
  WINDOW_UNIT_OPTIONS,
} from './ui_options';

interface Props {
  core: CoreStart;
  data: DataPublicPluginStart;
  /** When set, the builder opens in EDIT mode for this saved-object id (PUT instead of POST). */
  editSoId?: string;
  /** Initial mode + rule to hydrate the form from (the lossless edit round-trip). */
  initialMode?: DetectionMode;
  initialRule?: RuleDefinition | ThresholdRuleDefinition;
  /** Called after a successful save/update (and on "Back") so the host can return to the list. */
  onDone?: () => void;
}

const DEFAULT_CONDITION: Condition = { field: '', operator: 'exists' };

/**
 * The 14 MITRE ATT&CK Enterprise tactics (public taxonomy — clean-room, no bundled ATT&CK corpus
 * in v1.1). References are auto-derived from the id, not stored statically here.
 */
const MITRE_TACTICS: Array<{ id: string; name: string }> = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
];

function tacticReference(id: string): string {
  return `https://attack.mitre.org/tactics/${id}/`;
}

/** e.g. 'T1110' → '.../techniques/T1110/'; 'T1110.001' → '.../techniques/T1110/001/'. */
function techniqueReference(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}

interface TechniqueRow {
  id: string;
  name: string;
}

/** v1.1 scope: a single ThreatEntry (one tactic) with a LIST of free-text techniques. */
function buildThreatEntries(tacticId: string, techniques: TechniqueRow[]): ThreatEntry[] | undefined {
  const tactic = MITRE_TACTICS.find((t) => t.id === tacticId);
  const cleanTechniques = techniques
    .filter((t) => t.id.trim() !== '')
    .map((t) => ({
      id: t.id.trim(),
      name: t.name.trim() || t.id.trim(),
      reference: techniqueReference(t.id.trim()),
    }));
  if (!tactic && cleanTechniques.length === 0) return undefined;
  return [
    {
      framework: 'MITRE ATT&CK',
      ...(tactic ? { tactic: { id: tactic.id, name: tactic.name, reference: tacticReference(tactic.id) } } : {}),
      ...(cleanTechniques.length ? { technique: cleanTechniques } : {}),
    },
  ];
}

/** Compute initial form values from a saved rule (edit hydration), or defaults for a new rule. */
function seedFrom(
  initialMode?: DetectionMode,
  initialRule?: RuleDefinition | ThresholdRuleDefinition
) {
  const mode: DetectionMode = initialMode ?? 'stateful';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const r = initialRule as any;
  const grp = mode === 'stateful' ? r?.filter : r?.group;
  const conditions: Condition[] = grp?.conditions?.length
    ? grp.conditions.map((c: Condition) => ({ ...c }))
    : [{ ...DEFAULT_CONDITION }];
  const threatEntry = (r?.threat as ThreatEntry[] | undefined)?.[0];
  return {
    mode,
    name: (r?.name as string) ?? '',
    severity: (r?.severity as Severity) ?? 'high',
    logic: (grp?.logic as ConditionGroup['logic']) ?? 'AND',
    conditions,
    groupBy: (r?.groupBy as string[]) ?? [],
    windowValue: (r?.window?.value as number) ?? 5,
    windowUnit: (r?.window?.unit as TimeWindow['unit']) ?? 'MINUTES',
    thresholdOp: (r?.threshold?.operator as CountThreshold['operator']) ?? 'gt',
    thresholdValue: (r?.threshold?.value as number) ?? 1000,
    // WS-1 (PROB-1): triage/context metadata — round-trips losslessly via seedFrom + currentRule.
    mitreTacticId: threatEntry?.tactic?.id ?? '',
    mitreTechniques: (threatEntry?.technique ?? []).map((t) => ({ id: t.id, name: t.name })) as TechniqueRow[],
    riskScore: (r?.riskScore as number | undefined) ?? undefined,
    note: (r?.note as string) ?? '',
    investigationFields: (r?.investigationFields as string[]) ?? [],
    falsePositives: (r?.falsePositives as string[]) ?? [],
    references: (r?.references as string[]) ?? [],
  };
}

/** Drop empty rows and strip value/values that don't apply to the chosen operator. */
function cleanConditions(conditions: Condition[]): Condition[] {
  return conditions
    .filter((c) => c.field)
    .map((c) => {
      const arity = OPERATOR_OPTIONS.find((o) => o.value === c.operator)?.arity ?? 'value';
      if (arity === 'none') return { field: c.field, operator: c.operator };
      if (arity === 'list') return { field: c.field, operator: c.operator, values: c.values ?? [] };
      return { field: c.field, operator: c.operator, value: c.value };
    });
}

/**
 * The no-code stateful detection builder. The analyst assembles a "> N within T grouped by …" rule
 * and dry-runs it against real data via the proven /api/tlsoc/detection/_execute route (Task 3.3).
 * The builder never compiles client-side — it sends the structured rule; the server compiles + runs.
 */
export function DetectionBuilder({ core, data, editSoId, initialMode, initialRule, onDone }: Props) {
  const seed = useMemo(() => seedFrom(initialMode, initialRule), [initialMode, initialRule]);
  const isEdit = !!editSoId;
  const { views, loadingViews, error: viewsError } = useDataViews(data);
  const [dataViewId, setDataViewId] = useState('');
  const selectedView = views.find((v) => v.id === dataViewId);
  const { fields, loadingFields, error: fieldsError } = useDataViewFields(
    data,
    dataViewId || undefined
  );

  const [mode, setMode] = useState<DetectionMode>(seed.mode);
  const [name, setName] = useState(seed.name);
  const [severity, setSeverity] = useState<Severity>(seed.severity);
  const [logic, setLogic] = useState<ConditionGroup['logic']>(seed.logic);
  const [conditions, setConditions] = useState<Condition[]>(seed.conditions);
  const [groupBy, setGroupBy] = useState<string[]>(seed.groupBy);
  const [windowValue, setWindowValue] = useState<number>(seed.windowValue);
  const [windowUnit, setWindowUnit] = useState<TimeWindow['unit']>(seed.windowUnit);
  const [thresholdOp, setThresholdOp] = useState<CountThreshold['operator']>(seed.thresholdOp);
  const [thresholdValue, setThresholdValue] = useState<number>(seed.thresholdValue);
  const [from, setFrom] = useState('2026-05-16T10:00:00Z');
  const [to, setTo] = useState('2026-05-16T10:02:00Z');

  // Triage & context (optional) — WS-1, PROB-1.
  const [mitreTacticId, setMitreTacticId] = useState<string>(seed.mitreTacticId);
  const [mitreTechniques, setMitreTechniques] = useState<TechniqueRow[]>(seed.mitreTechniques);
  const [riskScore, setRiskScore] = useState<number | undefined>(seed.riskScore);
  const [note, setNote] = useState<string>(seed.note);
  const [investigationFields, setInvestigationFields] = useState<string[]>(seed.investigationFields);
  const [falsePositives, setFalsePositives] = useState<string[]>(seed.falsePositives);
  const [references, setReferences] = useState<string[]>(seed.references);

  const [testing, setTesting] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any>(null);
  const [testError, setTestError] = useState<string | null>(null);

  const [saving, setSaving] = useState(false);
  const [saveResult, setSaveResult] = useState<{ id: string; name: string } | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const aggregatableFields = useMemo(() => fields.filter((f) => f.aggregatable), [fields]);

  // Switching modes clears any stale stateful test result so it can't bleed into the stateless view.
  const onModeChange = (id: string) => {
    setMode(id as DetectionMode);
    setResult(null);
    setTestError(null);
  };

  /**
   * The structured rule the user is currently building, for the active mode. SINGLE source of the
   * rule object — the client-side preview/Sigma compile, the "Test" POST, and the "Save" POST all
   * use this exact value, so what you preview, test, and save can never diverge.
   */
  const currentRule = useMemo<RuleDefinition | ThresholdRuleDefinition>(() => {
    const cleaned = cleanConditions(conditions);
    const index = selectedView?.title ?? '';
    const ruleName = name.trim() || 'Untitled detection';
    const threat = buildThreatEntries(mitreTacticId, mitreTechniques);
    const metadata: RuleMetadataFields = {
      ...(threat ? { threat } : {}),
      ...(note.trim() ? { note: note.trim() } : {}),
      ...(investigationFields.length ? { investigationFields } : {}),
      ...(riskScore !== undefined ? { riskScore } : {}),
      ...(falsePositives.length ? { falsePositives } : {}),
      ...(references.length ? { references } : {}),
    };
    if (mode === 'stateless') {
      return { name: ruleName, severity, index, group: { logic, conditions: cleaned }, ...metadata };
    }
    return {
      name: ruleName,
      severity,
      index,
      filter: { logic, conditions: cleaned },
      groupBy,
      window: { value: windowValue, unit: windowUnit },
      threshold: { operator: thresholdOp, value: thresholdValue },
      ...metadata,
    };
  }, [
    mode,
    name,
    severity,
    selectedView,
    logic,
    conditions,
    groupBy,
    windowValue,
    windowUnit,
    thresholdOp,
    thresholdValue,
    mitreTacticId,
    mitreTechniques,
    note,
    investigationFields,
    riskScore,
    falsePositives,
    references,
  ]);

  /**
   * Compile the in-progress rule CLIENT-SIDE for the preview/export panels (pure TS, decision D-008).
   * The compilers throw on an incomplete rule (empty field/value, no conditions) — we catch that and
   * surface the clear, contained message instead of crashing the form or spewing a stack trace. So a
   * half-built rule simply shows "finish the rule…" until it is valid.
   */
  const preview = useMemo<
    | { ok: true; sigma: string; monitor: Record<string, unknown> | null }
    | { ok: false; error: string }
  >(() => {
    try {
      if (mode === 'stateless') {
        const rule = currentRule as RuleDefinition;
        return {
          ok: true,
          sigma: compileToSigma(rule),
          monitor: (compileToDocLevelMonitor(rule) as unknown) as Record<string, unknown>,
        };
      }
      const rule = currentRule as ThresholdRuleDefinition;
      return { ok: true, sigma: compileToSigmaCorrelation(rule), monitor: null };
    } catch (e) {
      return { ok: false, error: (e as Error)?.message ?? 'The rule is incomplete.' };
    }
  }, [mode, currentRule]);

  // Editing the rule (or switching mode) invalidates a prior "Saved ✓" — clear it so Save re-enables
  // for the now-changed rule. This is half the duplicate-save guard (the server enforces the rest).
  useEffect(() => {
    setSaveResult(null);
    setSaveError(null);
  }, [currentRule]);

  // Edit hydration: once the data views load, select the one matching the saved rule's index so the
  // field dropdowns prefill. (If none matches, the rule is still editable — fields just won't prefill.)
  useEffect(() => {
    if (initialRule && views.length && !dataViewId) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const match = views.find((v) => v.title === (initialRule as any).index);
      if (match) setDataViewId(match.id);
    }
  }, [initialRule, views, dataViewId]);

  const onSave = async () => {
    setSaving(true);
    setSaveError(null);
    setSaveResult(null);
    try {
      const body = JSON.stringify({ mode, rule: currentRule });
      const resp = isEdit
        ? await core.http.put(`/api/tlsoc/detection/monitors/${editSoId}`, { body })
        : await core.http.post('/api/tlsoc/detection/monitors', { body });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const r = resp as any;
      setSaveResult({ id: r?.id, name: r?.name });
      // Return to the list (the new/updated row IS the confirmation).
      if (onDone) onDone();
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const err = e as any;
      setSaveError(err?.body?.message ?? err?.message ?? 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const updateCondition = (index: number, next: Condition) =>
    setConditions((cs) => cs.map((c, i) => (i === index ? next : c)));
  const addCondition = () => setConditions((cs) => [...cs, { ...DEFAULT_CONDITION }]);
  const removeCondition = (index: number) =>
    setConditions((cs) => cs.filter((_, i) => i !== index));

  const canTest =
    !!selectedView && conditions.some((c) => c.field) && groupBy.length > 0 && !testing;

  const onTest = async () => {
    setTesting(true);
    setTestError(null);
    setResult(null);
    try {
      const rule = {
        name: name.trim() || 'Untitled detection',
        severity,
        index: selectedView?.title ?? '',
        filter: { logic, conditions: cleanConditions(conditions) },
        groupBy,
        window: { value: windowValue, unit: windowUnit },
        threshold: { operator: thresholdOp, value: thresholdValue },
      };
      const body = JSON.stringify({
        mode: 'stateful',
        rule,
        ...(from && to ? { timeRange: { from, to } } : {}),
      });
      const resp = await core.http.post('/api/tlsoc/detection/_execute', { body });
      setResult(resp);
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const err = e as any;
      setTestError(err?.body?.message ?? err?.message ?? 'Test request failed');
    } finally {
      setTesting(false);
    }
  };

  const firedGroups: string[][] = (result?.firedGroups as string[][]) ?? [];

  // Stateless (doc-level) monitors are rejected by OpenSearch 3.7 for index names containing "." or
  // "*". Rather than block Save, a stateless rule on such an index runs against a dot-free ALIAS the
  // server links on save (Task 3.5b). When that applies, surface the alias name + the Logstash note.
  const statelessAlias =
    mode === 'stateless' && /[.*]/.test(currentRule.index)
      ? deriveAliasName(currentRule.index)
      : null;

  return (
    <EuiPage paddingSize="l">
      <EuiPageBody>
        {onDone ? (
          <>
            <EuiButtonEmpty iconType="arrowLeft" onClick={onDone} flush="left">
              Back to detections
            </EuiButtonEmpty>
            <EuiSpacer size="s" />
          </>
        ) : null}
        <EuiTitle size="l">
          <h1>{isEdit ? 'Edit detection' : 'New detection'}</h1>
        </EuiTitle>
        <EuiText color="subdued">
          <p>
            Build a detection rule — a single-event match or a “more than N within a time window”
            threshold — then preview or test it before saving. No query language required.
          </p>
        </EuiText>
        <EuiSpacer size="l" />

        {viewsError ? (
          <>
            <EuiCallOut color="danger" title={viewsError} iconType="alert" />
            <EuiSpacer size="m" />
          </>
        ) : null}

        <EuiForm component="form">
          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Detection type</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiButtonGroup
              type="single"
              legend="Detection type"
              idSelected={mode}
              options={MODE_OPTIONS}
              onChange={onModeChange}
            />
            <EuiSpacer size="s" />
            <EuiText size="s" color="subdued">
              <p>
                {mode === 'stateful'
                  ? 'Threshold: fire when more than N matching events occur within a time window, grouped by a field (e.g. a request flood from one source IP). Tested live against your data.'
                  : 'Single-event: fire on any single document that matches the conditions (a Sigma-style rule). Exports to Sigma and compiles to a doc-level monitor; a live single-event preview isn’t available yet — see the note below.'}
              </p>
            </EuiText>
          </EuiPanel>
          <EuiSpacer size="m" />

          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Data source</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiFormRow label="Data view" helpText="The index pattern this rule runs against.">
              <EuiSelect
                options={[
                  { value: '', text: loadingViews ? 'Loading data views…' : 'Select a data view' },
                  ...views.map((v) => ({ value: v.id, text: v.title })),
                ]}
                value={dataViewId}
                onChange={(e) => {
                  setDataViewId(e.target.value);
                  setGroupBy([]);
                }}
              />
            </EuiFormRow>
          </EuiPanel>
          <EuiSpacer size="m" />

          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Match — which events count</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            {conditions.length > 1 ? (
              <>
                <EuiButtonGroup
                  type="single"
                  legend="Combine conditions with AND or OR"
                  idSelected={logic}
                  options={[
                    { id: 'AND', label: 'Match ALL (AND)' },
                    { id: 'OR', label: 'Match ANY (OR)' },
                  ]}
                  onChange={(id) => setLogic(id as ConditionGroup['logic'])}
                />
                <EuiSpacer size="s" />
              </>
            ) : null}
            {fieldsError ? (
              <>
                <EuiCallOut color="danger" title={fieldsError} iconType="alert" />
                <EuiSpacer size="s" />
              </>
            ) : null}
            {conditions.map((condition, index) => (
              <div key={index}>
                <ConditionRow
                  condition={condition}
                  fields={fields}
                  showRemove={conditions.length > 1}
                  onChange={(next) => updateCondition(index, next)}
                  onRemove={() => removeCondition(index)}
                />
                <EuiSpacer size="s" />
              </div>
            ))}
            <EuiButtonEmpty
              iconType="plusInCircle"
              onClick={addCondition}
              isDisabled={!selectedView}
            >
              Add condition
            </EuiButtonEmpty>
          </EuiPanel>
          <EuiSpacer size="m" />

          {mode === 'stateful' ? (
            <>
              <EuiPanel hasShadow={false} hasBorder>
                <EuiTitle size="xs">
                  <h2>Threshold — when to alert</h2>
                </EuiTitle>
            <EuiSpacer size="s" />
            <EuiFormRow
              label="Group by"
              helpText="Only aggregatable fields are listed (e.g. source.ip). Text fields can't be grouped."
            >
              <EuiComboBox
                placeholder="e.g. source.ip"
                isLoading={loadingFields}
                options={aggregatableFields.map((f) => ({ label: f.name }))}
                selectedOptions={groupBy.map((g) => ({ label: g }))}
                onChange={(opts) => setGroupBy(opts.map((o) => o.label))}
              />
            </EuiFormRow>
            <EuiSpacer size="s" />
            <EuiFlexGroup>
              <EuiFlexItem>
                <EuiFormRow label="Count">
                  <EuiSelect
                    options={THRESHOLD_OP_OPTIONS}
                    value={thresholdOp}
                    onChange={(e) => setThresholdOp(e.target.value as CountThreshold['operator'])}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow label="Events">
                  <EuiFieldNumber
                    value={thresholdValue}
                    onChange={(e) => setThresholdValue(Number(e.target.value))}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow label="Within">
                  <EuiFieldNumber
                    value={windowValue}
                    onChange={(e) => setWindowValue(Number(e.target.value))}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow label="Unit">
                  <EuiSelect
                    options={WINDOW_UNIT_OPTIONS}
                    value={windowUnit}
                    onChange={(e) => setWindowUnit(e.target.value as TimeWindow['unit'])}
                  />
                </EuiFormRow>
              </EuiFlexItem>
            </EuiFlexGroup>
              </EuiPanel>
              <EuiSpacer size="m" />
            </>
          ) : null}

          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Rule details</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiFlexGroup>
              <EuiFlexItem>
                <EuiFormRow label="Rule name">
                  <EuiFieldText
                    value={name}
                    placeholder="e.g. Single-source request flood"
                    onChange={(e) => setName(e.target.value)}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem grow={false} style={{ width: 200 }}>
                <EuiFormRow label="Severity">
                  <EuiSelect
                    options={SEVERITY_OPTIONS}
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as Severity)}
                  />
                </EuiFormRow>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="m" />

            <EuiAccordion id="tlsoc-triage-context" buttonContent="Triage & context (optional)">
              <EuiSpacer size="s" />
              <EuiText size="s" color="subdued">
                <p>
                  Everything here is optional — it enriches the alert flyout an analyst sees when
                  this rule fires (MITRE classification, a risk score, a triage runbook, and known
                  false positives) so an L1 can triage without leaving TLSOC.
                </p>
              </EuiText>
              <EuiSpacer size="s" />
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="MITRE ATT&CK tactic">
                    <EuiSelect
                      options={[
                        { value: '', text: '— none —' },
                        ...MITRE_TACTICS.map((t) => ({ value: t.id, text: `${t.id} — ${t.name}` })),
                      ]}
                      value={mitreTacticId}
                      onChange={(e) => setMitreTacticId(e.target.value)}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false} style={{ width: 180 }}>
                  <EuiFormRow label="Risk score (0-100)">
                    <EuiFieldNumber
                      min={0}
                      max={100}
                      value={riskScore ?? ''}
                      onChange={(e) => {
                        const v = e.target.value;
                        if (v === '') {
                          setRiskScore(undefined);
                          return;
                        }
                        const n = Number(v);
                        setRiskScore(Number.isNaN(n) ? undefined : Math.max(0, Math.min(100, n)));
                      }}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="s" />
              <EuiFormRow
                label="MITRE ATT&CK technique(s)"
                helpText="Technique id (e.g. T1110, or a sub-technique T1110.001) + a short name. References to attack.mitre.org are derived automatically."
                fullWidth
              >
                <div>
                  {mitreTechniques.map((t, i) => (
                    <div key={i}>
                      <EuiFlexGroup gutterSize="s" alignItems="center">
                        <EuiFlexItem>
                          <EuiFieldText
                            placeholder="Technique id, e.g. T1110"
                            value={t.id}
                            onChange={(e) =>
                              setMitreTechniques((ts) =>
                                ts.map((row, ri) => (ri === i ? { ...row, id: e.target.value } : row))
                              )
                            }
                          />
                        </EuiFlexItem>
                        <EuiFlexItem>
                          <EuiFieldText
                            placeholder="Technique name, e.g. Brute Force"
                            value={t.name}
                            onChange={(e) =>
                              setMitreTechniques((ts) =>
                                ts.map((row, ri) => (ri === i ? { ...row, name: e.target.value } : row))
                              )
                            }
                          />
                        </EuiFlexItem>
                        <EuiFlexItem grow={false}>
                          <EuiButtonIcon
                            iconType="trash"
                            color="danger"
                            aria-label="Remove technique"
                            onClick={() => setMitreTechniques((ts) => ts.filter((_, ri) => ri !== i))}
                          />
                        </EuiFlexItem>
                      </EuiFlexGroup>
                      <EuiSpacer size="xs" />
                    </div>
                  ))}
                  <EuiButtonEmpty
                    iconType="plusInCircle"
                    onClick={() => setMitreTechniques((ts) => [...ts, { id: '', name: '' }])}
                  >
                    Add technique
                  </EuiButtonEmpty>
                </div>
              </EuiFormRow>
              <EuiSpacer size="s" />
              <EuiFormRow
                label="Investigation fields"
                helpText="Fields to highlight in the alert flyout, in addition to the built-in default set."
                fullWidth
              >
                <EuiComboBox
                  placeholder="e.g. process.name"
                  options={fields.map((f) => ({ label: f.name }))}
                  selectedOptions={investigationFields.map((f) => ({ label: f }))}
                  onChange={(opts) => setInvestigationFields(opts.map((o) => o.label))}
                  onCreateOption={(val) => {
                    const v = val.trim();
                    if (v && !investigationFields.includes(v)) {
                      setInvestigationFields([...investigationFields, v]);
                    }
                  }}
                />
              </EuiFormRow>
              <EuiSpacer size="s" />
              <EuiFormRow
                label="Triage runbook"
                helpText="Markdown. {{field.path}} placeholders (e.g. {{source.ip}}) resolve against the triggering event when an analyst opens the alert."
                fullWidth
              >
                <EuiMarkdownEditor aria-label="Triage runbook" value={note} onChange={setNote} height={200} />
              </EuiFormRow>
              <EuiSpacer size="s" />
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="Known false positives">
                    <EuiComboBox
                      noSuggestions
                      placeholder="Add a false-positive scenario"
                      selectedOptions={falsePositives.map((f) => ({ label: f }))}
                      onCreateOption={(val) => {
                        const v = val.trim();
                        if (v && !falsePositives.includes(v)) setFalsePositives([...falsePositives, v]);
                      }}
                      onChange={(opts) => setFalsePositives(opts.map((o) => o.label))}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow label="References">
                    <EuiComboBox
                      noSuggestions
                      placeholder="Add a reference URL"
                      selectedOptions={references.map((r) => ({ label: r }))}
                      onCreateOption={(val) => {
                        const v = val.trim();
                        if (v && !references.includes(v)) setReferences([...references, v]);
                      }}
                      onChange={(opts) => setReferences(opts.map((o) => o.label))}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiAccordion>
          </EuiPanel>
          <EuiSpacer size="m" />

          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Sigma export</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiText size="s" color="subdued">
              <p>
                A portable Sigma rule you can share or import into other tools.{' '}
                {mode === 'stateful'
                  ? 'Stateful rules export as a Sigma event_count correlation rule.'
                  : 'Single-event rules export as a standard Sigma detection rule.'}{' '}
                Sigma is an export artifact only — TLSOC runs OpenSearch Alerting monitors, not Sigma
                (decision D-008).
              </p>
            </EuiText>
            <EuiSpacer size="s" />
            <EuiAccordion id="tlsoc-sigma-export" buttonContent="View Sigma export (portable YAML)">
              <EuiSpacer size="s" />
              {preview.ok ? (
                <EuiCodeBlock language="yaml" fontSize="s" paddingSize="s" isCopyable>
                  {preview.sigma}
                </EuiCodeBlock>
              ) : (
                <EuiCallOut
                  color="primary"
                  iconType="iInCircle"
                  title="Finish the rule to generate its Sigma export"
                >
                  <p>{preview.error}</p>
                </EuiCallOut>
              )}
            </EuiAccordion>
          </EuiPanel>
          <EuiSpacer size="m" />

          {mode === 'stateful' ? (
          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Test this rule</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiText size="s" color="subdued">
              <p>
                Dry-runs the rule against the data view over the time range below. Nothing is saved.
              </p>
            </EuiText>
            <EuiFlexGroup>
              <EuiFlexItem>
                <EuiFormRow label="From (ISO 8601, UTC)">
                  <EuiFieldText value={from} onChange={(e) => setFrom(e.target.value)} />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow label="To (ISO 8601, UTC)">
                  <EuiFieldText value={to} onChange={(e) => setTo(e.target.value)} />
                </EuiFormRow>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="s" />
            <EuiButton fill iconType="play" onClick={onTest} isLoading={testing} isDisabled={!canTest}>
              Test this rule
            </EuiButton>

            {testError ? (
              <>
                <EuiSpacer size="m" />
                <EuiCallOut color="danger" title="The rule did not run" iconType="alert">
                  <p>{testError}</p>
                </EuiCallOut>
              </>
            ) : null}

            {result ? (
              <>
                <EuiSpacer size="m" />
                <EuiHorizontalRule margin="s" />
                <EuiTitle size="xxs">
                  <h3>Result</h3>
                </EuiTitle>
                <EuiSpacer size="s" />
                {firedGroups.length > 0 ? (
                  <EuiText size="s">
                    <p>This rule would fire for {firedGroups.length} group(s):</p>
                    <p>
                      {firedGroups.map((g, i) => (
                        <EuiBadge key={i} color="danger" style={{ marginRight: 4 }}>
                          {g.join(', ')}
                        </EuiBadge>
                      ))}
                    </p>
                  </EuiText>
                ) : (
                  <EuiCallOut
                    color="primary"
                    iconType="iInCircle"
                    title="No groups crossed the threshold in this window."
                  />
                )}
                <EuiSpacer size="s" />
                <EuiAccordion id="tlsoc-detection-raw" buttonContent="View raw response">
                  <EuiCodeBlock language="json" fontSize="s" paddingSize="s" isCopyable>
                    {JSON.stringify(result, null, 2)}
                  </EuiCodeBlock>
                </EuiAccordion>
              </>
            ) : null}
          </EuiPanel>
          ) : (
          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Test this rule</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiCallOut
              color="warning"
              iconType="iInCircle"
              title="Live single-event preview isn’t available yet"
            >
              <p>
                Single-event (doc-level) rules can’t be dry-run against unsaved data because of an
                upstream OpenSearch Alerting limitation (issue #1295: an unsaved doc-level monitor
                _execute returns “routing is required”). Below is the exact doc-level monitor this
                rule compiles to. Once it is saved as a monitor (a later task) it will evaluate each
                incoming document. Threshold (stateful) rules can be tested live now — switch the
                detection type above.
              </p>
            </EuiCallOut>
            <EuiSpacer size="m" />
            <EuiTitle size="xxs">
              <h3>Compiled doc-level monitor</h3>
            </EuiTitle>
            <EuiSpacer size="s" />
            {preview.ok && preview.monitor ? (
              <EuiCodeBlock language="json" fontSize="s" paddingSize="s" isCopyable>
                {JSON.stringify(preview.monitor, null, 2)}
              </EuiCodeBlock>
            ) : (
              <EuiCallOut
                color="primary"
                iconType="iInCircle"
                title="Finish the rule to see the compiled monitor"
              >
                {preview.ok ? null : <p>{preview.error}</p>}
              </EuiCallOut>
            )}
          </EuiPanel>
          )}
          <EuiSpacer size="m" />

          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Save detection</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiText size="s" color="subdued">
              <p>
                Saves this rule as a real OpenSearch Alerting monitor that runs on its schedule from
                now on — the Test above only dry-runs; saving makes the detection live. The exact rule
                is stored with the monitor so it can be edited later.
              </p>
            </EuiText>
            <EuiSpacer size="s" />
            <EuiButton
              fill
              iconType="save"
              onClick={onSave}
              isLoading={saving}
              isDisabled={!preview.ok || saving || !!saveResult}
            >
              {saveResult ? 'Saved ✓' : isEdit ? 'Update detection' : 'Save detection'}
            </EuiButton>
            {!preview.ok ? (
              <>
                <EuiSpacer size="s" />
                <EuiText size="s" color="subdued">
                  <p>Finish the rule to enable saving.</p>
                </EuiText>
              </>
            ) : null}
            {statelessAlias ? (
              <>
                <EuiSpacer size="m" />
                <EuiCallOut
                  color="primary"
                  iconType="iInCircle"
                  title="Single-event rules run against a dot-free alias"
                >
                  <p>
                    OpenSearch doc-level monitors can’t target index names with “.” or “*”, so this
                    rule will run against the alias <code>{statelessAlias}</code>. On save, TLSOC links
                    your currently-matching indices to it. For new daily indices going forward, add{' '}
                    <code>{statelessAlias}</code> to your Logstash/index template once so they’re
                    covered too.
                  </p>
                </EuiCallOut>
              </>
            ) : null}
            {saveResult ? (
              <>
                <EuiSpacer size="m" />
                <EuiCallOut color="success" iconType="check" title={`Saved “${saveResult.name}”`}>
                  <p>
                    Monitor id <code>{saveResult.id}</code> — it will now run on its schedule.
                    Browsing/editing saved rules arrives next (Task 3.5b).
                  </p>
                </EuiCallOut>
              </>
            ) : null}
            {saveError ? (
              <>
                <EuiSpacer size="m" />
                <EuiCallOut color="danger" iconType="alert" title="Could not save this detection">
                  <p>{saveError}</p>
                </EuiCallOut>
              </>
            ) : null}
          </EuiPanel>
        </EuiForm>
        <EuiSpacer size="l" />
      </EuiPageBody>
    </EuiPage>
  );
}
