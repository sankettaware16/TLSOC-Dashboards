/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useMemo, useState } from 'react';
import {
  EuiAccordion,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiButtonIcon,
  EuiCallOut,
  EuiComboBox,
  EuiFieldNumber,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { Condition, ConditionGroup, CountThreshold, TimeWindow } from '../../../common/detection';
import type { AggregationSpec, HavingExpr, MetricDef } from '../../../common/detection/agg_types';
import { OPERATOR_OPTIONS, THRESHOLD_OP_OPTIONS, WINDOW_UNIT_OPTIONS } from '../ui_options';
import type { RuleEditorProps } from '../type_registry';
import { FieldOption } from '../use_data_view_fields';
import { MatchSection } from './match_section';
import { MetricRow, MetricRowState, isInvalidAlias, newMetricRow } from './metric_row';

/**
 * The 'stateful' (threshold) per-type editor: the shared Match panel plus the "> N within T
 * grouped by …" threshold panel — verbatim extraction from detection_builder.tsx (v1.2.3 D1) —
 * and, since v1.2.3 D4, an OPTIONAL "Advanced metrics" accordion that lowers to the shared
 * aggregation IR ({@link AggregationSpec}): metric rows (dc/value_count/sum/avg/min/max, plus
 * count with a sub-filter) and a FLAT one-AND-group-or-one-OR-group condition list over their
 * aliases (nested logic is deliberately the PPL type's job). While the accordion is empty the
 * rule stays legacy — `advanced` is emitted as undefined, NEVER an empty object, so existing
 * rules keep compiling byte-identically.
 *
 * All rule state lives in the builder; this component renders and reports changes. The advanced
 * section keeps LOCAL row state for UI-only ephemera (untouched-alias tracking, incomplete rows —
 * the MitreTtpPicker precedent) and emits the cleaned spec upward on every change.
 */

type HavingCmp = Extract<HavingExpr, { kind: 'cmp' }>;
type HavingOp = HavingCmp['op'];

/** One flat "alert when" row: a metric alias (or the reserved _count), a comparison, a value. */
interface HavingRowState {
  alias: string;
  op: HavingOp;
  value: number | undefined;
}

const HAVING_OP_OPTIONS: Array<{ value: HavingOp; text: string }> = [
  { value: 'gt', text: 'is above (>)' },
  { value: 'gte', text: 'is at least (>=)' },
  { value: 'lt', text: 'is below (<)' },
  { value: 'lte', text: 'is at most (<=)' },
  { value: 'eq', text: 'equals (==)' },
  { value: 'neq', text: 'is not (!=)' },
];

/** Extra props the D4 advanced section needs beyond {@link RuleEditorProps}. The section renders
 * ONLY when `onAdvancedChange` is provided (the builder wiring is a serial integration step). */
export interface StatefulAdvancedProps {
  /** The rule's current advanced spec — undefined for a legacy count-only rule. */
  advanced?: AggregationSpec;
  /** Emits the lowered spec, or undefined when the accordion is empty (the rule stays legacy). */
  onAdvancedChange?: (next: AggregationSpec | undefined) => void;
}

export type StatefulEditorProps = RuleEditorProps & StatefulAdvancedProps;

/** Mirror of the builder's cleanConditions for a metric sub-filter, PRESERVING fieldType (it
 * drives the analyzed-text-aware Lucene compile of the sub-filter's query_string). */
function cleanSubFilter(row: MetricRowState): ConditionGroup | undefined {
  if (!row.subFilter) {
    return undefined;
  }
  const conditions = row.subFilter
    .filter((c) => c.field)
    .map((c) => {
      const arity = OPERATOR_OPTIONS.find((o) => o.value === c.operator)?.arity ?? 'value';
      const base: Condition = {
        field: c.field,
        operator: c.operator,
        ...(c.fieldType !== undefined ? { fieldType: c.fieldType } : {}),
      };
      if (arity === 'none') return base;
      if (arity === 'list') return { ...base, values: c.values ?? [] };
      return { ...base, value: c.value };
    });
  return conditions.length > 0 ? { logic: row.subFilterLogic, conditions } : undefined;
}

/** A metric row that is complete enough to appear in the emitted spec. */
function isCompleteMetricRow(row: MetricRowState): boolean {
  return (
    row.alias.trim() !== '' &&
    !isInvalidAlias(row.alias.trim()) &&
    (row.fn === 'count' || row.field.trim() !== '')
  );
}

function metricRowToDef(row: MetricRowState): MetricDef {
  const filter = cleanSubFilter(row);
  return {
    alias: row.alias.trim(),
    fn: row.fn,
    ...(row.fn !== 'count' ? { field: row.field } : {}),
    ...(filter ? { filter } : {}),
  };
}

/**
 * Lower the UI rows to the shared IR. Returns undefined when there is NOTHING in the accordion
 * (no complete metric, no complete condition) — the legacy-rule contract. Incomplete-but-started
 * states (metrics without a condition) produce a spec that fails validation with a clear message,
 * which the builder surfaces as its usual "finish the rule" gate.
 */
function lowerAdvanced(
  groupBy: string[],
  metricRows: MetricRowState[],
  logic: ConditionGroup['logic'],
  havingRows: HavingRowState[]
): AggregationSpec | undefined {
  const metrics = metricRows.filter(isCompleteMetricRow).map(metricRowToDef);
  const cmps: HavingCmp[] = havingRows
    .filter((r) => r.alias !== '' && r.value !== undefined && Number.isFinite(r.value))
    .map((r) => ({ kind: 'cmp', alias: r.alias, op: r.op, value: r.value as number }));
  if (metrics.length === 0 && cmps.length === 0) {
    return undefined;
  }
  const having: HavingExpr =
    cmps.length === 1 ? cmps[0] : { kind: logic === 'AND' ? 'and' : 'or', operands: cmps };
  return { by: [...groupBy], metrics, having };
}

/** Hydrate metric UI rows from a saved spec (edit round-trip). Stored aliases count as touched. */
function metricRowsFromSpec(spec: AggregationSpec | undefined): MetricRowState[] {
  if (!spec) {
    return [];
  }
  return spec.metrics.map((m) => ({
    alias: m.alias,
    aliasTouched: true,
    fn: m.fn,
    field: m.field ?? '',
    subFilter: m.filter ? m.filter.conditions.map((c) => ({ ...c })) : null,
    subFilterLogic: m.filter?.logic ?? 'AND',
  }));
}

/**
 * Hydrate the flat condition rows from a saved having tree. Only the shapes this editor itself
 * produces are representable (one cmp, or one and/or of cmps); anything nested is flagged so a
 * warning explains that editing will flatten it.
 */
function havingStateFromSpec(
  spec: AggregationSpec | undefined
): { logic: ConditionGroup['logic']; rows: HavingRowState[]; unrepresentable: boolean } {
  if (!spec) {
    return { logic: 'AND', rows: [], unrepresentable: false };
  }
  const having = spec.having;
  const cmpToRow = (cmp: HavingCmp): HavingRowState => ({
    alias: cmp.alias,
    op: cmp.op,
    value: cmp.value,
  });
  if (having.kind === 'cmp') {
    return { logic: 'AND', rows: [cmpToRow(having)], unrepresentable: false };
  }
  if (
    (having.kind === 'and' || having.kind === 'or') &&
    having.operands.every((o) => o.kind === 'cmp')
  ) {
    return {
      logic: having.kind === 'and' ? 'AND' : 'OR',
      rows: (having.operands as HavingCmp[]).map(cmpToRow),
      unrepresentable: false,
    };
  }
  return { logic: 'AND', rows: [], unrepresentable: true };
}

function AdvancedMetricsSection({
  fields,
  groupBy,
  advanced,
  onAdvancedChange,
}: {
  fields: FieldOption[];
  groupBy: string[];
  advanced?: AggregationSpec;
  onAdvancedChange: (next: AggregationSpec | undefined) => void;
}) {
  // Seeded ONCE from the incoming spec (the builder remounts the editor per create/edit/import
  // key, so this is the edit-hydration path); afterwards the local rows are the working copy and
  // every change emits the cleaned spec upward.
  const [seed] = useState(() => ({
    metricRows: metricRowsFromSpec(advanced),
    having: havingStateFromSpec(advanced),
  }));
  const [metricRows, setMetricRows] = useState<MetricRowState[]>(seed.metricRows);
  const [havingLogic, setHavingLogic] = useState<ConditionGroup['logic']>(seed.having.logic);
  const [havingRows, setHavingRows] = useState<HavingRowState[]>(seed.having.rows);

  // `groupBy` is read fresh on every emission; the builder additionally re-stamps `by` from its
  // own groupBy state when assembling the rule, so a later group-by edit can never go stale.
  const emitWith = (
    rows: MetricRowState[],
    logic: ConditionGroup['logic'],
    hrows: HavingRowState[]
  ) => onAdvancedChange(lowerAdvanced(groupBy, rows, logic, hrows));

  const setMetrics = (rows: MetricRowState[]) => {
    setMetricRows(rows);
    emitWith(rows, havingLogic, havingRows);
  };
  const setLogic = (logic: ConditionGroup['logic']) => {
    setHavingLogic(logic);
    emitWith(metricRows, logic, havingRows);
  };
  const setHaving = (rows: HavingRowState[]) => {
    setHavingRows(rows);
    emitWith(metricRows, havingLogic, rows);
  };

  const aliasOptions = [
    { value: '', text: 'Select a metric…' },
    { value: '_count', text: 'event count (_count)' },
    ...metricRows
      .filter(isCompleteMetricRow)
      .map((r) => ({ value: r.alias.trim(), text: r.alias.trim() })),
  ];

  return (
    <>
      <EuiText size="s" color="subdued">
        <p>
          Define per-group metrics (distinct counts, filtered counts, sums…) and combine them into
          one alert condition — e.g. group by source.ip and fire when distinct url.path values reach
          40 AND events with status ≥ 400 reach 50, within the window. When conditions are set here
          they <strong>replace</strong> the simple count threshold above (use the “event count”
          metric to keep a count comparison). Conditions combine with a single AND or a single OR —
          nested logic is available in Advanced (PPL) rules.
        </p>
      </EuiText>
      {seed.having.unrepresentable ? (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut
            color="warning"
            iconType="alert"
            title="This rule's alert condition uses nested logic this editor can't display"
          >
            <p>Editing the conditions below will replace it with a flat AND/OR list.</p>
          </EuiCallOut>
        </>
      ) : null}
      <EuiSpacer size="s" />
      <EuiTitle size="xxs">
        <h3>Metrics</h3>
      </EuiTitle>
      <EuiSpacer size="xs" />
      {metricRows.map((row, i) => (
        <div key={i}>
          <MetricRow
            row={row}
            fields={fields}
            onChange={(next) => setMetrics(metricRows.map((r, j) => (j === i ? next : r)))}
            onRemove={() => setMetrics(metricRows.filter((_, j) => j !== i))}
          />
          <EuiSpacer size="s" />
        </div>
      ))}
      <EuiButtonEmpty
        size="s"
        iconType="plusInCircle"
        onClick={() => setMetrics([...metricRows, newMetricRow()])}
      >
        Add metric
      </EuiButtonEmpty>
      <EuiSpacer size="m" />
      <EuiTitle size="xxs">
        <h3>Alert when</h3>
      </EuiTitle>
      <EuiSpacer size="xs" />
      {havingRows.length > 1 ? (
        <>
          <EuiButtonGroup
            type="single"
            legend="Combine alert conditions with AND or OR"
            buttonSize="compressed"
            idSelected={havingLogic}
            options={[
              { id: 'AND', label: 'Match ALL (AND)' },
              { id: 'OR', label: 'Match ANY (OR)' },
            ]}
            onChange={(id) => setLogic(id as ConditionGroup['logic'])}
          />
          <EuiSpacer size="s" />
        </>
      ) : null}
      {havingRows.map((row, i) => {
        const options = aliasOptions.some((o) => o.value === row.alias)
          ? aliasOptions
          : [...aliasOptions, { value: row.alias, text: `${row.alias} (missing metric)` }];
        return (
          <div key={i}>
            <EuiFlexGroup gutterSize="s" alignItems="flexEnd" responsive={false}>
              <EuiFlexItem>
                <EuiFormRow label="Metric">
                  <EuiSelect
                    options={options}
                    value={row.alias}
                    onChange={(e) =>
                      setHaving(
                        havingRows.map((r, j) => (j === i ? { ...r, alias: e.target.value } : r))
                      )
                    }
                    aria-label="Alert condition metric"
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem grow={false} style={{ width: 200 }}>
                <EuiFormRow label="Comparison">
                  <EuiSelect
                    options={HAVING_OP_OPTIONS}
                    value={row.op}
                    onChange={(e) =>
                      setHaving(
                        havingRows.map((r, j) =>
                          j === i ? { ...r, op: e.target.value as HavingOp } : r
                        )
                      )
                    }
                    aria-label="Alert condition comparison"
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem grow={false} style={{ width: 160 }}>
                <EuiFormRow label="Value">
                  <EuiFieldNumber
                    placeholder="Number"
                    value={row.value === undefined ? '' : row.value}
                    onChange={(e) =>
                      setHaving(
                        havingRows.map((r, j) =>
                          j === i
                            ? {
                                ...r,
                                value: e.target.value === '' ? undefined : Number(e.target.value),
                              }
                            : r
                        )
                      )
                    }
                    aria-label="Alert condition value"
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiFormRow hasEmptyLabelSpace>
                  <EuiButtonIcon
                    iconType="minusInCircle"
                    color="danger"
                    aria-label="Remove alert condition"
                    onClick={() => setHaving(havingRows.filter((_, j) => j !== i))}
                  />
                </EuiFormRow>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="xs" />
          </div>
        );
      })}
      <EuiButtonEmpty
        size="s"
        iconType="plusInCircle"
        onClick={() => setHaving([...havingRows, { alias: '', op: 'gte', value: undefined }])}
      >
        Add condition
      </EuiButtonEmpty>
    </>
  );
}

export function StatefulEditor(props: StatefulEditorProps) {
  const {
    fields,
    loadingFields,
    groupBy,
    onGroupByChange,
    windowValue,
    onWindowValueChange,
    windowUnit,
    onWindowUnitChange,
    thresholdOp,
    onThresholdOpChange,
    thresholdValue,
    onThresholdValueChange,
    advanced,
    onAdvancedChange,
  } = props;
  const aggregatableFields = useMemo(() => fields.filter((f) => f.aggregatable), [fields]);

  return (
    <>
      <MatchSection {...props} />
      <EuiSpacer size="m" />
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
            onChange={(opts) => onGroupByChange(opts.map((o) => o.label))}
          />
        </EuiFormRow>
        <EuiSpacer size="s" />
        <EuiFlexGroup>
          <EuiFlexItem>
            <EuiFormRow label="Count">
              <EuiSelect
                options={THRESHOLD_OP_OPTIONS}
                value={thresholdOp}
                onChange={(e) => onThresholdOpChange(e.target.value as CountThreshold['operator'])}
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiFormRow label="Events">
              <EuiFieldNumber
                value={thresholdValue}
                onChange={(e) => onThresholdValueChange(Number(e.target.value))}
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiFormRow label="Within">
              <EuiFieldNumber
                value={windowValue}
                onChange={(e) => onWindowValueChange(Number(e.target.value))}
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiFormRow label="Unit">
              <EuiSelect
                options={WINDOW_UNIT_OPTIONS}
                value={windowUnit}
                onChange={(e) => onWindowUnitChange(e.target.value as TimeWindow['unit'])}
              />
            </EuiFormRow>
          </EuiFlexItem>
        </EuiFlexGroup>
        {onAdvancedChange ? (
          <>
            <EuiSpacer size="m" />
            <EuiAccordion
              id="tlsoc-advanced-metrics"
              buttonContent="Advanced metrics (optional)"
              initialIsOpen={!!advanced}
            >
              <EuiSpacer size="s" />
              <AdvancedMetricsSection
                fields={fields}
                groupBy={groupBy}
                advanced={advanced}
                onAdvancedChange={onAdvancedChange}
              />
            </EuiAccordion>
          </>
        ) : null}
      </EuiPanel>
    </>
  );
}
