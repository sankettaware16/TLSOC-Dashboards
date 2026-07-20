/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiButtonIcon,
  EuiComboBox,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import { Condition, ConditionGroup } from '../../../common/detection';
import type { MetricFn } from '../../../common/detection/agg_types';
import { AGG_ALIAS_PATTERN } from '../../../common/detection/internal';
import { ConditionRow } from '../condition_row';
import { FieldOption } from '../use_data_view_fields';

/**
 * One "Advanced metrics" row of the enhanced threshold editor (v1.2.3 D4): an aggregation
 * function + field + alias, with an optional sub-filter (the metric then only counts/aggregates
 * events matching it — the scanner's "errors where status >= 400" leg). Reuses ConditionRow for
 * the sub-filter so the condition vocabulary never forks.
 *
 * Field discipline (the agg_types contract): metric fields must be PRE-RESOLVED to aggregatable
 * paths — cardinality/terms on an analyzed text field fails at monitor runtime with NO alert
 * written (research_r2 §a). This row therefore only offers AGGREGATABLE fields (a text field
 * appears via its `.keyword` subfield, which the data view lists as its own aggregatable field),
 * and numeric-only functions (sum/avg/min/max) only offer number fields.
 */

/** UI row state. `aliasTouched` stops fn/field changes from overwriting a hand-edited alias. */
export interface MetricRowState {
  alias: string;
  aliasTouched: boolean;
  fn: MetricFn;
  field: string;
  /** null = no sub-filter section shown; a list = the sub-filter's condition rows. */
  subFilter: Condition[] | null;
  subFilterLogic: ConditionGroup['logic'];
}

/** A fresh, empty metric row (cardinality is the most common non-count metric — the scanner's). */
export function newMetricRow(): MetricRowState {
  return {
    alias: '',
    aliasTouched: false,
    fn: 'cardinality',
    field: '',
    subFilter: null,
    subFilterLogic: 'AND',
  };
}

export const METRIC_FN_OPTIONS: Array<{ value: MetricFn; text: string }> = [
  { value: 'count', text: 'count of events' },
  { value: 'value_count', text: 'count of field values (value_count)' },
  { value: 'cardinality', text: 'distinct values (dc)' },
  { value: 'sum', text: 'sum' },
  { value: 'avg', text: 'average' },
  { value: 'min', text: 'minimum' },
  { value: 'max', text: 'maximum' },
];

/** Functions that only make sense on numeric fields. */
const NUMERIC_METRIC_FNS: ReadonlySet<MetricFn> = new Set(['sum', 'avg', 'min', 'max']);

const FN_ALIAS_PREFIX: Record<MetricFn, string> = {
  count: 'event_count',
  value_count: 'count',
  cardinality: 'dc',
  sum: 'sum',
  avg: 'avg',
  min: 'min',
  max: 'max',
};

/** Aliases the compiler reserves — mirrored from internal.ts's RESERVED_ALIASES for inline UX. */
const RESERVED_UI_ALIASES: ReadonlySet<string> = new Set(['_count', 'key', 'doc_count']);

/**
 * Suggest an alias from the function + field, e.g. cardinality of url.path.keyword → 'dc_url_path'
 * (a trailing '.keyword' is dropped — it's a storage detail, not meaning). Empty until a field is
 * chosen for field-taking functions.
 */
export function suggestAlias(fn: MetricFn, field: string): string {
  if (fn === 'count') {
    return FN_ALIAS_PREFIX.count;
  }
  const slug = field
    .replace(/\.keyword$/, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return slug ? `${FN_ALIAS_PREFIX[fn]}_${slug}` : '';
}

/** True when the alias (as typed) violates the compiler's alias rules — surfaced inline. */
export function isInvalidAlias(alias: string): boolean {
  return alias !== '' && (!AGG_ALIAS_PATTERN.test(alias) || RESERVED_UI_ALIASES.has(alias));
}

const DEFAULT_SUB_FILTER_CONDITION: Condition = { field: '', operator: 'exists' };

interface Props {
  row: MetricRowState;
  fields: FieldOption[];
  onChange: (next: MetricRowState) => void;
  onRemove: () => void;
}

export function MetricRow({ row, fields, onChange, onRemove }: Props) {
  const aggregatable = fields.filter((f) => f.aggregatable);
  const selectable = NUMERIC_METRIC_FNS.has(row.fn)
    ? aggregatable.filter((f) => f.type === 'number')
    : aggregatable;
  const fieldOptions = selectable.map((f) => ({ label: f.name }));

  const withSuggestedAlias = (next: MetricRowState): MetricRowState =>
    next.aliasTouched ? next : { ...next, alias: suggestAlias(next.fn, next.field) };

  const onFnChange = (fn: MetricFn) => {
    let field = fn === 'count' ? '' : row.field;
    // Switching to a numeric-only function drops a now-invalid non-numeric field.
    if (NUMERIC_METRIC_FNS.has(fn) && field && !selectableHasNumeric(aggregatable, field)) {
      field = '';
    }
    onChange(withSuggestedAlias({ ...row, fn, field }));
  };

  const onFieldChange = (field: string) => onChange(withSuggestedAlias({ ...row, field }));

  const onAliasChange = (alias: string) =>
    // Clearing the alias re-enables auto-suggestion on the next fn/field change.
    onChange({ ...row, alias, aliasTouched: alias.trim() !== '' });

  const updateSubCondition = (index: number, next: Condition) =>
    onChange({
      ...row,
      subFilter: (row.subFilter ?? []).map((c, i) => (i === index ? next : c)),
    });

  const aliasInvalid = isInvalidAlias(row.alias);

  return (
    <EuiPanel hasShadow={false} hasBorder paddingSize="s">
      <EuiFlexGroup gutterSize="s" alignItems="flexEnd" responsive={false}>
        <EuiFlexItem grow={false} style={{ width: 240 }}>
          <EuiFormRow label="Metric">
            <EuiSelect
              options={METRIC_FN_OPTIONS}
              value={row.fn}
              onChange={(e) => onFnChange(e.target.value as MetricFn)}
              aria-label="Metric function"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiFormRow
            label="Field"
            helpText={
              row.fn === 'count'
                ? undefined
                : 'Aggregatable fields only — a text field appears as its .keyword subfield.'
            }
          >
            <EuiComboBox
              singleSelection={{ asPlainText: true }}
              placeholder={row.fn === 'count' ? 'All events in the group' : 'Select a field'}
              isDisabled={row.fn === 'count'}
              options={fieldOptions}
              selectedOptions={row.field ? [{ label: row.field }] : []}
              onChange={(selected) => onFieldChange(selected[0]?.label ?? '')}
              isClearable={false}
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false} style={{ width: 200 }}>
          <EuiFormRow
            label="Alias"
            isInvalid={aliasInvalid}
            error={
              aliasInvalid
                ? 'Lowercase letters, digits, underscores; no leading digit; not _count/key/doc_count.'
                : undefined
            }
          >
            <EuiFieldText
              placeholder="e.g. distinct_urls"
              value={row.alias}
              isInvalid={aliasInvalid}
              onChange={(e) => onAliasChange(e.target.value)}
              aria-label="Metric alias"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow hasEmptyLabelSpace>
            <EuiButtonIcon
              iconType="minusInCircle"
              color="danger"
              aria-label="Remove metric"
              onClick={onRemove}
            />
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>

      {row.subFilter === null ? (
        <EuiButtonEmpty
          size="xs"
          iconType="filter"
          onClick={() => onChange({ ...row, subFilter: [{ ...DEFAULT_SUB_FILTER_CONDITION }] })}
        >
          Add sub-filter (only measure matching events)
        </EuiButtonEmpty>
      ) : (
        <>
          <EuiSpacer size="s" />
          <EuiText size="xs" color="subdued">
            <p>
              Sub-filter — this metric only measures events matching{' '}
              {row.subFilterLogic === 'AND' ? 'ALL' : 'ANY'} of:
            </p>
          </EuiText>
          {row.subFilter.length > 1 ? (
            <>
              <EuiButtonGroup
                type="single"
                legend="Combine sub-filter conditions with AND or OR"
                buttonSize="compressed"
                idSelected={row.subFilterLogic}
                options={[
                  { id: 'AND', label: 'ALL (AND)' },
                  { id: 'OR', label: 'ANY (OR)' },
                ]}
                onChange={(id) =>
                  onChange({ ...row, subFilterLogic: id as ConditionGroup['logic'] })
                }
              />
              <EuiSpacer size="s" />
            </>
          ) : null}
          {row.subFilter.map((condition, index) => (
            <div key={index}>
              <ConditionRow
                condition={condition}
                fields={fields}
                showRemove={(row.subFilter ?? []).length > 1}
                onChange={(next) => updateSubCondition(index, next)}
                onRemove={() =>
                  onChange({
                    ...row,
                    subFilter: (row.subFilter ?? []).filter((_, i) => i !== index),
                  })
                }
              />
              <EuiSpacer size="xs" />
            </div>
          ))}
          <EuiFlexGroup gutterSize="s" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                size="xs"
                iconType="plusInCircle"
                onClick={() =>
                  onChange({
                    ...row,
                    subFilter: [...(row.subFilter ?? []), { ...DEFAULT_SUB_FILTER_CONDITION }],
                  })
                }
              >
                Add sub-filter condition
              </EuiButtonEmpty>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                size="xs"
                color="danger"
                iconType="cross"
                onClick={() => onChange({ ...row, subFilter: null })}
              >
                Remove sub-filter
              </EuiButtonEmpty>
            </EuiFlexItem>
          </EuiFlexGroup>
        </>
      )}
    </EuiPanel>
  );
}

/** Does an aggregatable field with this name exist AND have a numeric type? */
function selectableHasNumeric(aggregatable: FieldOption[], name: string): boolean {
  return aggregatable.some((f) => f.name === name && f.type === 'number');
}
