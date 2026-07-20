/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Suspense, useEffect, useMemo, useState } from 'react';
import {
  EuiAccordion,
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCard,
  EuiCodeBlock,
  EuiComboBox,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiHorizontalRule,
  EuiIcon,
  EuiLoadingSpinner,
  EuiMarkdownEditor,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../../data/public';
import {
  AggregationSpec,
  ANALYZED_TEXT_TYPES,
  Condition,
  ConditionGroup,
  CountThreshold,
  DEFAULT_NEW_TERMS_HISTORY_WINDOW,
  DetectionMode,
  IndicatorMatchRuleDefinition,
  NewTermsRuleDefinition,
  PplRuleDefinition,
  RuleDefinition,
  RuleMetadataFields,
  Severity,
  ThreatEntry,
  ThresholdRuleDefinition,
  TimeWindow,
  collectPplStringContextFields,
  deriveAliasName,
  getType,
  parsePpl,
} from '../../common/detection';
import type {
  CustomQueryLanguage,
  CustomQueryRuleDefinition,
} from '../../common/detection/custom_query';
import { CustomQueryPreview } from './custom_query_preview';
import type { PplPreviewData } from './ppl_preview_table';
import { MitreTtpPicker } from './mitre_ttp_picker';
import { ScheduleSection } from './schedule_section';
import { getUiType, listUiTypes } from './type_registry';
import { useDataViewFields, useDataViews } from './use_data_view_fields';
import { OPERATOR_OPTIONS, SEVERITY_OPTIONS } from './ui_options';

interface Props {
  core: CoreStart;
  data: DataPublicPluginStart;
  /** When set, the builder opens in EDIT mode for this saved-object id (PUT instead of POST). */
  editSoId?: string;
  /** Initial mode + rule to hydrate the form from (the lossless edit round-trip). */
  initialMode?: DetectionMode;
  initialRule?:
    | RuleDefinition
    | ThresholdRuleDefinition
    | PplRuleDefinition
    | CustomQueryRuleDefinition
    | NewTermsRuleDefinition
    | IndicatorMatchRuleDefinition;
  /** Initial enabled state (edit hydration). Defaults to true for a brand-new detection. */
  initialEnabled?: boolean;
  /** Warnings from a Sigma import that produced this rule — surfaced at the top of the form. */
  importWarnings?: string[];
  /** Called after a successful save/update (and on "Back") so the host can return to the list. */
  onDone?: () => void;
}

const DEFAULT_CONDITION: Condition = { field: '', operator: 'exists' };

/** Compute initial form values from a saved rule (edit hydration), or defaults for a new rule. */
function seedFrom(
  initialMode?: DetectionMode,
  initialRule?:
    | RuleDefinition
    | ThresholdRuleDefinition
    | PplRuleDefinition
    | CustomQueryRuleDefinition
    | NewTermsRuleDefinition
    | IndicatorMatchRuleDefinition
) {
  const mode: DetectionMode = initialMode ?? 'stateful';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const r = initialRule as any;
  const grp = mode === 'stateful' ? r?.filter : r?.group;
  const conditions: Condition[] = grp?.conditions?.length
    ? grp.conditions.map((c: Condition) => ({ ...c }))
    : [{ ...DEFAULT_CONDITION }];
  const savedGroupBy = (r?.groupBy as string[]) ?? [];
  return {
    mode,
    name: (r?.name as string) ?? '',
    severity: (r?.severity as Severity) ?? 'high',
    logic: (grp?.logic as ConditionGroup['logic']) ?? 'AND',
    conditions,
    // The two group-by slices are PER-TYPE (W2 review): the PPL editor force-mirrors its query's
    // by-fields into whatever groupBy state it is handed, so sharing one slice would let a visit
    // to the PPL card clobber an in-progress threshold draft's group-bys (cross-type leak).
    groupBy: mode === 'ppl' ? [] : savedGroupBy,
    pplGroupBy: mode === 'ppl' ? savedGroupBy : [],
    windowValue: (r?.window?.value as number) ?? 5,
    windowUnit: (r?.window?.unit as TimeWindow['unit']) ?? 'MINUTES',
    thresholdOp: (r?.threshold?.operator as CountThreshold['operator']) ?? 'gt',
    thresholdValue: (r?.threshold?.value as number) ?? 1000,
    // WS-1 (PROB-1): triage/context metadata — round-trips losslessly via seedFrom + currentRule.
    threat: (r?.threat as ThreatEntry[] | undefined) ?? [],
    riskScore: (r?.riskScore as number | undefined) ?? undefined,
    note: (r?.note as string) ?? '',
    investigationFields: (r?.investigationFields as string[]) ?? [],
    falsePositives: (r?.falsePositives as string[]) ?? [],
    references: (r?.references as string[]) ?? [],
    // WS-20 (PROB-20): the schedule cadence R — round-trips losslessly, undefined = legacy default.
    runEvery: r?.runEvery as TimeWindow | undefined,
    // v1.2.3 W2a (D4): the stateful rule's optional advanced aggregation spec.
    advanced: r?.advanced as AggregationSpec | undefined,
    // v1.2.3 W2b (D3): the PPL rule's query text (the lossless edit source of truth).
    pplText: (r?.pplText as string) ?? '',
    // W2 review (BLOCKING-1): the SAVED fieldMap — the edit round-trip keeps it until a fresh
    // field-caps resolution SUCCEEDS, so a PUT can never silently strip a correct map.
    fieldMap: (r?.fieldMap as Record<string, string> | undefined) ?? undefined,
    // v1.2.3 W2c (D2): the custom-query rule's text + language (IR field is `language`).
    queryText: (r?.queryText as string) ?? '',
    queryLanguage: (r?.language as CustomQueryLanguage) ?? 'kuery',
    // v1.2.3 W3a (D5): the new-terms rule's term field + history window; stateDocId rides along
    // on edit so the Test panel previews against the LIVE seen set (the save route re-injects it
    // authoritatively on every PUT, so carrying it is harmless).
    termField: (r?.termField as string) ?? '',
    historyWindow: (r?.historyWindow as TimeWindow) ?? DEFAULT_NEW_TERMS_HISTORY_WINDOW,
    stateDocId: (r?.stateDocId as string | undefined) ?? undefined,
    // v1.2.3 W3b (D6): the indicator-match rule's list + event field; listMode is display/
    // lossless-edit only — the server re-picks it from the list's size on every save.
    listId: (r?.listId as string) ?? '',
    eventField: (r?.eventField as string) ?? '',
    listMode: (r?.listMode as 'inline' | 'lookup') ?? 'inline',
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
 * The detection builder — shared chrome (type cards, data source, schedule, rule details, triage,
 * save) around a per-type editor slot resolved from the UI registry (v1.2.3 D1). All form state
 * lives HERE (switching type cards never loses in-progress work); each mode's currentRule branch
 * reads only its own slice, so no type's state leaks into another's save payload. The builder
 * never persists a client-side compile — Save sends the structured rule; the server re-validates,
 * compiles, and creates the monitor.
 */
export function DetectionBuilder({
  core,
  data,
  editSoId,
  initialMode,
  initialRule,
  initialEnabled,
  importWarnings,
  onDone,
}: Props) {
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
  // W2 review: PPL keeps its OWN group-by slice — the PPL editor force-mirrors the query's
  // by-fields into whatever setter it is handed, so handing it the shared `groupBy` would
  // clobber a threshold draft's group-bys the moment the PPL card is visited (cross-type leak).
  const [pplGroupBy, setPplGroupBy] = useState<string[]>(seed.pplGroupBy);
  const [windowValue, setWindowValue] = useState<number>(seed.windowValue);
  const [windowUnit, setWindowUnit] = useState<TimeWindow['unit']>(seed.windowUnit);
  const [thresholdOp, setThresholdOp] = useState<CountThreshold['operator']>(seed.thresholdOp);
  const [thresholdValue, setThresholdValue] = useState<number>(seed.thresholdValue);
  const [from, setFrom] = useState('2026-05-16T10:00:00Z');
  const [to, setTo] = useState('2026-05-16T10:02:00Z');

  // v1.2.3 W2a (D4): the stateful rule's optional advanced metrics spec.
  const [advanced, setAdvanced] = useState<AggregationSpec | undefined>(seed.advanced);
  // v1.2.3 W2b (D3): the PPL rule's query text.
  const [pplText, setPplText] = useState<string>(seed.pplText);
  // v1.2.3 W2c (D2): the custom-query rule's text + language.
  const [queryText, setQueryText] = useState<string>(seed.queryText);
  const [queryLanguage, setQueryLanguage] = useState<CustomQueryLanguage>(seed.queryLanguage);
  // v1.2.3 W3a (D5): the new-terms rule's term field + history window.
  const [termField, setTermField] = useState<string>(seed.termField);
  const [historyWindow, setHistoryWindow] = useState<TimeWindow>(seed.historyWindow);
  // v1.2.3 W3b (D6): the indicator-match rule's value list + event field.
  const [listId, setListId] = useState<string>(seed.listId);
  const [eventField, setEventField] = useState<string>(seed.eventField);

  // Triage & context (optional) — WS-1, PROB-1.
  const [threat, setThreat] = useState<ThreatEntry[]>(seed.threat);
  const [riskScore, setRiskScore] = useState<number | undefined>(seed.riskScore);
  const [note, setNote] = useState<string>(seed.note);
  const [investigationFields, setInvestigationFields] = useState<string[]>(seed.investigationFields);
  const [falsePositives, setFalsePositives] = useState<string[]>(seed.falsePositives);
  const [references, setReferences] = useState<string[]>(seed.references);

  // Schedule cadence R (optional) — WS-20, PROB-20.
  const [runEvery, setRunEvery] = useState<TimeWindow | undefined>(seed.runEvery);

  // Enable/disable on save (WS-19, PROB-19) — defaults to true for a brand-new detection; edit
  // hydration passes the saved object's current value in via `initialEnabled`.
  const [enabled, setEnabled] = useState(initialEnabled ?? true);

  const [testing, setTesting] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any>(null);
  const [testError, setTestError] = useState<string | null>(null);

  const [saving, setSaving] = useState(false);
  const [saveResult, setSaveResult] = useState<{ id: string; name: string } | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  // W2 review (BLOCKING-2): the server-side `_validate` verdict for the CURRENT custom query.
  // The builder owns it because Save is gated on it; the editor only requests runs (blur/submit)
  // and renders the state. `key` records which (language, index, query) triple a verdict is FOR —
  // a verdict for any other triple is stale and treated as 'idle' (never trusted, never shown).
  const [queryCheck, setQueryCheck] = useState<{
    status: 'idle' | 'checking' | 'valid' | 'invalid' | 'error';
    key?: string;
    reason?: string;
  }>({ status: 'idle' });

  // The active type's two registry halves: execution contract (common) + editor/preview UI (public).
  const ruleType = getType(mode);
  const uiType = getUiType(mode);
  const TypeEditor = uiType.editor;

  // Switching modes clears any stale stateful test result so it can't bleed into the stateless view.
  const onModeChange = (id: string) => {
    setMode(id as DetectionMode);
    setResult(null);
    setTestError(null);
  };

  /**
   * v1.2.3 D3: resolve the PPL query's string-context fields against the data view's field caps
   * at BUILD time (the shared enumerator `collectPplStringContextFields` defines the positions;
   * the save route re-checks the same set against the CLUSTER's field caps — the unskippable
   * layer). An analyzed-text field (the ANALYZED_TEXT_TYPES family, not just `text`) WITH an
   * aggregatable `.keyword` sibling maps to it; one WITHOUT blocks the save naming the field
   * (cardinality/terms on text fails at monitor runtime with NO alert — the silent-failure
   * class). Non-text fields need no entry (pass-through).
   *
   * W2 review (BLOCKING-1): the resolution is a three-state VERDICT, never a silent {}. It only
   * reports 'ok' when a data view matching the query's `source` is selected AND its fields have
   * loaded AND every text field resolved; anything less is 'blocked' with the reason (no data
   * view / source mismatch / still loading / unresolvable field) and Save stays disabled. 'idle'
   * = nothing to resolve yet (not a PPL rule, empty query, or a parse error the validator names
   * with a better message).
   */
  const pplFieldResolution = useMemo<
    | { status: 'ok'; fieldMap: Record<string, string> }
    | { status: 'blocked'; reason: string }
    | { status: 'idle' }
  >(() => {
    if (mode !== 'ppl' || pplText.trim() === '') {
      return { status: 'idle' };
    }
    const parsed = parsePpl(pplText);
    if (!parsed.ok) {
      // Parse errors are surfaced (and save is gated) by the preview compile below.
      return { status: 'idle' };
    }
    const source = parsed.rule.indices.join(',');
    if (!selectedView) {
      return {
        status: 'blocked',
        reason:
          `Select the data view matching the query's source ("${source}") — PPL rules resolve ` +
          'text-field mappings from its field caps before they can be saved.',
      };
    }
    if (selectedView.title !== source) {
      return {
        status: 'blocked',
        reason:
          `The selected data view ("${selectedView.title}") does not match the query's ` +
          `source ("${source}") — select the matching data view, or change the query's source.`,
      };
    }
    if (loadingFields || fields.length === 0) {
      return { status: 'blocked', reason: 'Resolving fields from the data view…' };
    }

    const byName = new Map(fields.map((f) => [f.name, f]));
    const fieldMap: Record<string, string> = {};
    for (const f of collectPplStringContextFields(parsed.rule)) {
      const opt = byName.get(f);
      if (!opt || !opt.esTypes.some((t) => ANALYZED_TEXT_TYPES.has(t))) continue;
      const keyword = byName.get(`${f}.keyword`);
      if (keyword && keyword.aggregatable) {
        fieldMap[f] = `${f}.keyword`;
        continue;
      }
      return {
        status: 'blocked',
        reason:
          `Field "${f}" is analyzed text with no ".keyword" subfield, so it cannot be matched ` +
          'or grouped exactly — the saved monitor would fail silently at runtime. Use a keyword ' +
          'field, or add a keyword subfield to the mapping.',
      };
    }
    return { status: 'ok', fieldMap };
  }, [mode, pplText, fields, loadingFields, selectedView]);

  /**
   * The structured rule the user is currently building, for the active mode. SINGLE source of the
   * rule object — the client-side preview/Sigma compile, the "Test" POST, and the "Save" POST all
   * use this exact value, so what you preview, test, and save can never diverge. Each mode's
   * branch reads ONLY its own slice of the form state, so switching type cards never leaks one
   * type's state into another type's save payload.
   */
  const currentRule = useMemo<
    | RuleDefinition
    | ThresholdRuleDefinition
    | PplRuleDefinition
    | CustomQueryRuleDefinition
    | NewTermsRuleDefinition
    | IndicatorMatchRuleDefinition
  >(() => {
    const cleaned = cleanConditions(conditions);
    const index = selectedView?.title ?? '';
    const ruleName = name.trim() || 'Untitled detection';
    const metadata: RuleMetadataFields = {
      ...(threat.length ? { threat } : {}),
      ...(note.trim() ? { note: note.trim() } : {}),
      ...(investigationFields.length ? { investigationFields } : {}),
      ...(riskScore !== undefined ? { riskScore } : {}),
      ...(falsePositives.length ? { falsePositives } : {}),
      ...(references.length ? { references } : {}),
    };
    if (mode === 'stateless') {
      return {
        name: ruleName,
        severity,
        index,
        group: { logic, conditions: cleaned },
        ...(runEvery ? { runEvery } : {}),
        ...metadata,
      };
    }
    if (mode === 'custom_query') {
      return {
        name: ruleName,
        severity,
        index,
        language: queryLanguage,
        queryText,
        ...(runEvery ? { runEvery } : {}),
        ...metadata,
      };
    }
    if (mode === 'ppl') {
      const parsed = parsePpl(pplText);
      // W2 review (BLOCKING-1): a fresh field-caps resolution replaces the fieldMap ONLY when it
      // SUCCEEDS; until then an edit keeps the SAVED rule's map, so a PUT can never silently
      // downgrade a correct map to {} (Save is blocked anyway while the resolution is not 'ok').
      const fieldMap =
        pplFieldResolution.status === 'ok' ? pplFieldResolution.fieldMap : seed.fieldMap ?? {};
      return {
        name: ruleName,
        severity,
        // A PPL rule's index IS the query's `source =` list (assertValidPplRule enforces the
        // equality) — the data view is used for fields/preview, not the rule target.
        index: parsed.ok ? parsed.rule.indices.join(',') : '',
        pplText,
        // Re-stamped from the live parse (the D4 advanced.by idiom below): rule.groupBy MUST
        // mirror the query's by-fields, so derive it from the source of truth instead of racing
        // the editor's debounced mirror (which keeps `pplGroupBy` for hydration/fallback).
        groupBy: parsed.ok ? parsed.rule.by.map((f) => f.name) : pplGroupBy,
        window: { value: windowValue, unit: windowUnit },
        ...(Object.keys(fieldMap).length ? { fieldMap } : {}),
        ...(runEvery ? { runEvery } : {}),
        ...metadata,
      };
    }
    if (mode === 'new_terms') {
      return {
        name: ruleName,
        severity,
        index,
        termField,
        historyWindow,
        ...(cleaned.length ? { filter: { logic, conditions: cleaned } } : {}),
        // Set explicitly — never rely on the editor's mirror effect having run. The validator
        // requires exactly [termField]; its own "term field required" check fires first when empty.
        groupBy: [termField],
        // Edit flow only (seedFrom): lets the Test panel dry-run against the LIVE seen set; the
        // save route re-injects/re-derives it authoritatively on every save.
        ...(seed.stateDocId ? { stateDocId: seed.stateDocId } : {}),
        ...(runEvery ? { runEvery } : {}),
        ...metadata,
      };
    }
    if (mode === 'indicator_match') {
      return {
        name: ruleName,
        severity,
        index,
        eventField,
        listId,
        listMode: seed.listMode, // display/lossless-edit only — the server re-picks on save
        ...(cleaned.length ? { filter: { logic, conditions: cleaned } } : {}),
        groupBy: eventField ? [eventField] : [], // the validator's [eventField] invariant
        ...(runEvery ? { runEvery } : {}),
        ...metadata,
      };
    }
    return {
      name: ruleName,
      severity,
      index,
      filter: { logic, conditions: cleaned },
      groupBy,
      window: { value: windowValue, unit: windowUnit },
      threshold: { operator: thresholdOp, value: thresholdValue },
      // D4: re-stamp advanced.by from the authoritative groupBy so it never goes stale when the
      // group-bys change (the compiler ignores advanced.by anyway — groupBy is authoritative).
      ...(advanced ? { advanced: { ...advanced, by: groupBy } } : {}),
      ...(runEvery ? { runEvery } : {}),
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
    threat,
    note,
    investigationFields,
    riskScore,
    falsePositives,
    references,
    runEvery,
    advanced,
    pplText,
    pplGroupBy,
    pplFieldResolution,
    seed,
    queryText,
    queryLanguage,
    termField,
    historyWindow,
    listId,
    eventField,
  ]);

  /**
   * Compile the in-progress rule CLIENT-SIDE for the preview/export panels (pure TS, decision D-008),
   * dispatched through the type registry. The compilers throw on an incomplete rule (empty
   * field/value, no conditions) — we catch that and surface the clear, contained message instead of
   * crashing the form or spewing a stack trace. So a half-built rule simply shows "finish the
   * rule…" until it is valid. The compiled monitor is shown only for doc-kind types (bucket-kind
   * types get the live dry-run test panel instead).
   */
  const preview = useMemo<
    | { ok: true; sigma: string; monitor: Record<string, unknown> | null }
    | { ok: false; error: string }
  >(() => {
    try {
      // v1.2.3 D3: PPL rules have neither a toSigma nor a doc-kind compile below to gate Save,
      // so gate explicitly: the client-only field-caps resolution verdict first (no data view /
      // source mismatch / fields loading / unresolvable text field — the server re-checks all of
      // it, but only the client can name it before a round-trip), then the FULL compile
      // (parse → validate → lower → compileAggregationRule), so alias shape/duplicate/reserved
      // errors surface pre-save exactly like every other type's compile gate (W2 review).
      if (ruleType.id === 'ppl') {
        if (pplFieldResolution.status === 'blocked') {
          return { ok: false, error: pplFieldResolution.reason };
        }
        ruleType.compile(currentRule);
      }
      // v1.2.3 D6: indicator_match has neither a toSigma nor a doc-kind compile below, so gate
      // Save via the PURE (lookup) compile — it names a missing list/field/groupBy pre-save.
      // (new_terms CANNOT be compile-gated here: its compile requires the route-owned stateDocId,
      // absent on an unsaved rule by design — its Save gate is the explicit termField check below.)
      if (ruleType.id === 'indicator_match') {
        ruleType.compile(currentRule);
      }
      return {
        ok: true,
        sigma: ruleType.toSigma ? ruleType.toSigma(currentRule) : '',
        monitor: ruleType.monitorKind === 'doc' ? ruleType.compile(currentRule) : null,
      };
    } catch (e) {
      return { ok: false, error: (e as Error)?.message ?? 'The rule is incomplete.' };
    }
  }, [ruleType, currentRule, pplFieldResolution]);

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

  // --- W2 review (BLOCKING-2): custom-query save gate ------------------------------------------
  /** The (language, index, query) triple a `_validate` verdict must match to count as fresh. */
  const queryValidationKey = JSON.stringify([queryLanguage, selectedView?.title ?? '', queryText]);
  /** The verdict FOR THE CURRENT triple; anything validated earlier reads as 'idle' (stale). */
  const freshQueryCheck =
    queryCheck.key === queryValidationKey
      ? queryCheck
      : ({ status: 'idle' } as { status: 'idle'; reason?: string });

  /** POST the current triple to `_validate`; records AND returns the verdict (onSave awaits it). */
  const runQueryValidation = async (): Promise<{ valid: boolean; reason?: string }> => {
    const index = selectedView?.title ?? '';
    const key = JSON.stringify([queryLanguage, index, queryText]);
    if (index === '' || queryText.trim() === '') {
      // preview.ok already blocks this state; answered here only for defense in depth.
      return { valid: false, reason: 'Select a data view and write a query first.' };
    }
    setQueryCheck({ status: 'checking', key });
    try {
      const resp = (await core.http.post('/api/tlsoc/detection/_validate', {
        body: JSON.stringify({ index, query: queryText, language: queryLanguage }),
      })) as { valid: boolean; reason?: string };
      if (resp.valid) {
        setQueryCheck({ status: 'valid', key });
        return { valid: true };
      }
      const reason = resp.reason ?? 'The query is invalid.';
      setQueryCheck({ status: 'invalid', key, reason });
      return { valid: false, reason };
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const err = e as any;
      const reason = err?.body?.message ?? err?.message ?? 'Validation request failed';
      setQueryCheck({ status: 'error', key, reason });
      return { valid: false, reason };
    }
  };

  /**
   * The editor's blur/submit hook — skipped when the current triple already has/awaits a REAL
   * verdict. A transient 'error' (network hiccup) is retryable on the next blur, matching the
   * old editor's reset-on-error behavior — otherwise a hiccup would dead-end the save until the
   * query text changed.
   */
  const onQueryValidateRequest = () => {
    if (mode !== 'custom_query') return;
    if (freshQueryCheck.status === 'checking' || freshQueryCheck.status === 'valid') return;
    if (freshQueryCheck.status === 'invalid') return; // a real verdict — only a new query changes it
    if (!selectedView || queryText.trim() === '') return;
    void runQueryValidation();
  };

  /** Why Save is disabled for a custom-query rule right now, or null when it may proceed. */
  const customQueryBlockReason =
    mode !== 'custom_query'
      ? null
      : freshQueryCheck.status === 'checking'
      ? 'Validating the query against your data…'
      : freshQueryCheck.status === 'invalid' || freshQueryCheck.status === 'error'
      ? freshQueryCheck.reason ?? 'The query did not validate.'
      : null;
  // ----------------------------------------------------------------------------------------------

  /**
   * v1.2.3 D5: the new-terms Save gate. Its compile cannot gate Save client-side (the route owns
   * the seen-state doc id it requires), so the one authoring precondition is checked explicitly.
   */
  const newTermsBlockReason =
    mode === 'new_terms' && termField === ''
      ? 'Pick the term field whose first-seen values fire.'
      : null;

  const onSave = async () => {
    setSaving(true);
    setSaveError(null);
    setSaveResult(null);
    try {
      // W2 review (BLOCKING-2): never race the async validation. A custom-query save proceeds
      // only on a verdict for the EXACT current triple — anything stale/absent is re-validated
      // HERE and awaited, and a failure blocks the save with the validator's reason. (The save
      // route re-validates server-side regardless; this keeps the failure interactive.)
      if (mode === 'custom_query' && freshQueryCheck.status !== 'valid') {
        const verdict = await runQueryValidation();
        if (!verdict.valid) {
          setSaveError(verdict.reason ?? 'The query did not validate.');
          return;
        }
      }
      const body = JSON.stringify({ mode, rule: currentRule, enabled });
      const resp = isEdit
        ? await core.http.put(`/api/tlsoc/detection/monitors/${editSoId}`, { body })
        : await core.http.post('/api/tlsoc/detection/monitors', { body });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const r = resp as any;
      setSaveResult({ id: r?.id, name: r?.name });
      // v1.2.3 W3 review (fix 5): the create/update response's ADDITIVE `seenValues` field
      // (new_terms only) surfaces the bootstrap snapshot's honesty flags as toasts — a silent
      // degraded/empty seen set is exactly the class this release bans.
      const seen = r?.seenValues as { count: number; truncated: boolean } | undefined;
      if (seen?.truncated) {
        core.notifications.toasts.addWarning({
          title: 'Seen-value tracking is degraded for this rule',
          text:
            'seen-value tracking truncated at 65,536 — values beyond the cap will alert as new',
        });
      } else if (seen && seen.count === 0) {
        core.notifications.toasts.addInfo({
          title: 'The seen-values snapshot is empty',
          text:
            'Nothing in the history window matched, so EVERY value this rule scans will alert ' +
            'as new until the seen set builds up.',
        });
      }
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

  // v1.2.3 D5: a new-terms rule needs only a data view + term field to dry-run (the pre-filter
  // is optional); the stateful panel keeps its original conditions/group-by gating.
  const canTest =
    mode === 'new_terms'
      ? !!selectedView && termField !== '' && !testing
      : !!selectedView && conditions.some((c) => c.field) && groupBy.length > 0 && !testing;

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
        // D4: same re-stamp as currentRule, so Test exercises the advanced compile path too.
        ...(advanced ? { advanced: { ...advanced, by: groupBy } } : {}),
      };
      // v1.2.3 D5: new_terms posts its REAL mode + currentRule so the _execute route's seen-state
      // branch runs (unsaved rules get an empty preview doc — everything in the window is "new";
      // edits carry stateDocId → a true preview). The stateful body stays byte-identical.
      const body = JSON.stringify(
        mode === 'new_terms'
          ? { mode, rule: currentRule, ...(from && to ? { timeRange: { from, to } } : {}) }
          : { mode: 'stateful', rule, ...(from && to ? { timeRange: { from, to } } : {}) }
      );
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

  /**
   * v1.2.3 D3: run the server-side PPL preview with the CURRENT window. The DataViewRef list
   * carries only id/title, so the full data view is fetched on demand (Preview is an explicit
   * user action) to resolve its time field for the injected window conjunct.
   */
  const onPplPreview = async (text: string): Promise<PplPreviewData> => {
    let timeField = '@timestamp';
    if (dataViewId) {
      try {
        const dv = await data.dataViews.get(dataViewId);
        if (dv?.timeFieldName) timeField = dv.timeFieldName;
      } catch {
        // Fall back to @timestamp — the preview route names a missing time field clearly.
      }
    }
    return (await core.http.post('/api/tlsoc/detection/_ppl_preview', {
      body: JSON.stringify({ pplText: text, timeField, windowValue, windowUnit }),
    })) as PplPreviewData;
  };

  // Doc-level monitors are rejected by OpenSearch 3.7 for index names containing "." or "*".
  // Rather than block Save, a doc-kind rule on such an index runs against a dot-free ALIAS the
  // server links on save (Task 3.5b). When that applies, surface the alias name + the Logstash
  // note. Keyed off the registry's monitorKind PLUS the indicator_match INLINE case (v1.2.3 W3
  // review, fix 8): the hybrid's registry kind is 'bucket' (its pure lookup compile), but an
  // inline-listMode draft compiles to a DOC-level monitor on save and alias-routes exactly like
  // 'stateless' does — same generalization as the server's prepareMonitor, which keys off the
  // COMPILED monitor_type.
  const isInlineIndicatorDraft =
    mode === 'indicator_match' &&
    (currentRule as IndicatorMatchRuleDefinition).listMode === 'inline';
  const statelessAlias =
    (ruleType.monitorKind === 'doc' || isInlineIndicatorDraft) && /[.*]/.test(currentRule.index)
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
            Build a detection rule — a no-code single-event match or threshold, a custom
            DQL/Lucene query, or an advanced PPL aggregation — then preview or test it before
            saving.
          </p>
        </EuiText>
        <EuiSpacer size="l" />

        {importWarnings && importWarnings.length > 0 ? (
          <>
            <EuiCallOut
              color="warning"
              iconType="alert"
              title="Imported from Sigma with warnings"
            >
              <ul>
                {importWarnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        ) : null}

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
            {isEdit ? (
              <>
                {/* v1.2.3 D-A: the type is IMMUTABLE after creation — the server 400s a
                    mode-changing PUT, and the cards below render disabled to say so up front. */}
                <EuiText size="s" color="subdued">
                  <p>The rule type cannot be changed after creation — create a new rule instead.</p>
                </EuiText>
                <EuiSpacer size="s" />
              </>
            ) : null}
            {/* The Elastic-shaped type-chooser card grid, sourced from the UI registry — a new
                type's card appears by registering it, with no edit here (v1.2.3 D1). In EDIT
                sessions the grid is LOCKED (D-A): the saved rule's type stays selected. */}
            <EuiFlexGroup gutterSize="m" wrap>
              {listUiTypes().map((t) => (
                <EuiFlexItem key={t.id} grow={false} style={{ width: 320 }}>
                  <EuiCard
                    titleSize="xs"
                    textAlign="left"
                    icon={<EuiIcon type={t.card.icon} size="xl" />}
                    title={t.card.label}
                    description={t.card.description}
                    selectable={{
                      onClick: () => onModeChange(t.id),
                      isSelected: mode === t.id,
                      isDisabled: isEdit,
                    }}
                  />
                </EuiFlexItem>
              ))}
            </EuiFlexGroup>
          </EuiPanel>
          <EuiSpacer size="m" />

          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Data source</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiFormRow label="Data view" helpText="The data view this rule runs against.">
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

          {/* The per-type editor slot, resolved from the UI registry (lazily loaded). All form
              state stays in this builder, so switching types never loses in-progress conditions. */}
          <Suspense
            fallback={
              <EuiPanel hasShadow={false} hasBorder>
                <EuiLoadingSpinner size="m" />
              </EuiPanel>
            }
          >
            <TypeEditor
              fields={fields}
              loadingFields={loadingFields}
              fieldsError={fieldsError}
              hasDataView={!!selectedView}
              logic={logic}
              conditions={conditions}
              onLogicChange={setLogic}
              onConditionChange={updateCondition}
              onConditionAdd={addCondition}
              onConditionRemove={removeCondition}
              // new_terms gets a DERIVED slice ([termField]) so its editor's groupBy mirror can
              // never clobber the threshold draft's group-bys (the W2 ppl cross-type-leak class);
              // currentRule sets groupBy: [termField] explicitly from the same source.
              groupBy={
                mode === 'ppl'
                  ? pplGroupBy
                  : mode === 'new_terms'
                  ? termField
                    ? [termField]
                    : []
                  : groupBy
              }
              onGroupByChange={
                mode === 'ppl' ? setPplGroupBy : mode === 'new_terms' ? () => {} : setGroupBy
              }
              windowValue={windowValue}
              onWindowValueChange={setWindowValue}
              windowUnit={windowUnit}
              onWindowUnitChange={setWindowUnit}
              thresholdOp={thresholdOp}
              onThresholdOpChange={setThresholdOp}
              thresholdValue={thresholdValue}
              onThresholdValueChange={setThresholdValue}
              advanced={advanced}
              onAdvancedChange={setAdvanced}
              pplText={pplText}
              onPplTextChange={setPplText}
              onPreview={onPplPreview}
              core={core}
              data={data}
              dataViewId={dataViewId || undefined}
              indexPattern={selectedView?.title}
              queryText={queryText}
              queryLanguage={queryLanguage}
              onQueryTextChange={setQueryText}
              onQueryLanguageChange={setQueryLanguage}
              queryCheck={freshQueryCheck}
              onQueryValidate={onQueryValidateRequest}
              termField={termField}
              onTermFieldChange={setTermField}
              historyWindowValue={historyWindow.value}
              historyWindowUnit={historyWindow.unit}
              onHistoryWindowValueChange={(v) => setHistoryWindow((w) => ({ ...w, value: v }))}
              onHistoryWindowUnitChange={(u) => setHistoryWindow((w) => ({ ...w, unit: u }))}
              listId={listId}
              onListIdChange={setListId}
              eventField={eventField}
              onEventFieldChange={setEventField}
            />
          </Suspense>
          <EuiSpacer size="m" />

          {/* Every bucket-kind type with a rule window T gets the R ≤ T cap — keyed off the
              registry's monitorKind, not a mode literal, so 'ppl' gets it too. Two v1.2.3 W3
              exemptions: new_terms has NO separate window (the scan cadence IS the window — the
              doc-kind "1-minute default" copy is exactly true), and indicator_match likewise
              (runEvery IS the lookup window in its bucket shape). */}
          <ScheduleSection
            runEvery={runEvery}
            window={
              ruleType.monitorKind === 'bucket' &&
              ruleType.id !== 'new_terms' &&
              ruleType.id !== 'indicator_match'
                ? { value: windowValue, unit: windowUnit }
                : undefined
            }
            onChange={setRunEvery}
          />
          <EuiSpacer size="m" />

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
              <MitreTtpPicker value={threat} onChange={setThreat} />
              <EuiSpacer size="s" />
              <EuiFlexGroup>
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

          {/* Only Sigma-exportable types get the export panel — ppl/custom_query rules have no
              toSigma (an empty code block would be worse than no panel). A stateful rule WITH
              advanced metrics gets a one-line note instead (W2 review): its toSigma exports only
              the SUPERSEDED simple threshold — Sigma correlation cannot express multi-metric
              having conditions — and offering that export as if it were the rule would mislead. */}
          {mode === 'stateful' && advanced ? (
            <>
              <EuiText size="s" color="subdued">
                <p>
                  Advanced metric rules cannot be expressed in Sigma — the Sigma export is
                  unavailable for this rule.
                </p>
              </EuiText>
              <EuiSpacer size="m" />
            </>
          ) : ruleType.toSigma ? (
            <>
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
                    Sigma is an export artifact only — TLSOC runs OpenSearch Alerting monitors, not
                    Sigma (decision D-008).
                  </p>
                </EuiText>
                <EuiSpacer size="s" />
                <EuiAccordion
                  id="tlsoc-sigma-export"
                  buttonContent="View Sigma export (portable YAML)"
                >
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
            </>
          ) : null}

          {/* Keyed off the registry's previewStrategy: bucket-dryrun types get the proven live
              dry-run; ppl-preview types render NO shared test panel (the PPL editor embeds its
              own Preview); search-sample doc-kind types get a plain-search preview — a live one
              for custom_query, the compiled-monitor fallback for stateless (doc-level monitors
              cannot be dry-run unsaved — upstream alerting #1295/NPE, research_r3 §4). */}
          {uiType.previewStrategy === 'bucket-dryrun' ? (
          <>
          <EuiPanel hasShadow={false} hasBorder>
            <EuiTitle size="xs">
              <h2>Test this rule</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiText size="s" color="subdued">
              <p>
                Dry-runs the rule against the data view over the time range below. Nothing is saved.
                {mode === 'new_terms' && !seed.stateDocId
                  ? ' For an unsaved new-terms rule the preview treats every value in the scan ' +
                    'window as new — the seen-values snapshot is taken when you save.'
                  : ''}
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
          <EuiSpacer size="m" />
          </>
          ) : uiType.previewStrategy === 'ppl-preview' ? null : mode === 'custom_query' ? (
          <>
          {/* D2: a live plain-search preview — the translated Lucene the saved monitor will run. */}
          <CustomQueryPreview
            core={core}
            data={data}
            dataViewId={dataViewId || undefined}
            language={queryLanguage}
            queryText={queryText}
          />
          <EuiSpacer size="m" />
          </>
          ) : (
          <>
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
                Single-event (doc-level) rules can’t be dry-run before saving — on OpenSearch 3.7
                an unsaved doc-level monitor _execute fails outright (upstream alerting issue
                #1295), so TLSOC never fakes a test result here. Below is the exact doc-level
                monitor this rule compiles to; once saved, it evaluates each incoming document on
                its schedule. Threshold rules can be tested live — switch the detection type above.
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
          <EuiSpacer size="m" />
          </>
          )}

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
            <EuiSwitch
              label="Enable this detection (runs on its schedule once saved)"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <EuiSpacer size="m" />
            <EuiButton
              fill
              iconType="save"
              onClick={onSave}
              isLoading={saving}
              isDisabled={
                !preview.ok ||
                !!customQueryBlockReason ||
                !!newTermsBlockReason ||
                saving ||
                !!saveResult
              }
            >
              {saveResult ? 'Saved ✓' : isEdit ? 'Update detection' : 'Save detection'}
            </EuiButton>
            {!preview.ok ? (
              <>
                <EuiSpacer size="s" />
                {/* The reason is named here too — for types without a Sigma/compiled-monitor
                    panel (ppl), this is the ONLY place the blocking message can surface. */}
                <EuiText size="s" color="subdued">
                  <p>Finish the rule to enable saving — {preview.error}</p>
                </EuiText>
              </>
            ) : customQueryBlockReason || newTermsBlockReason ? (
              <>
                <EuiSpacer size="s" />
                {/* W2 review (BLOCKING-2): a failed/pending cluster validation blocks Save with
                    its reason (the editor shows the same verdict next to the query bar).
                    v1.2.3 D5: the new-terms termField gate surfaces here the same way. */}
                <EuiText size="s" color="subdued">
                  <p>Save is blocked — {customQueryBlockReason ?? newTermsBlockReason}</p>
                </EuiText>
              </>
            ) : null}
            {statelessAlias ? (
              <>
                <EuiSpacer size="m" />
                <EuiCallOut
                  color="primary"
                  iconType="iInCircle"
                  title="This rule runs against a dot-free alias"
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
