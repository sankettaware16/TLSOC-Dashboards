/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useMemo } from 'react';
import {
  EuiAccordion,
  EuiCallOut,
  EuiComboBox,
  EuiComboBoxOptionOption,
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
import { TimeWindow } from '../../../common/detection';
import {
  DEFAULT_NEW_TERMS_HISTORY_WINDOW,
  SEEN_VALUES_CAP,
} from '../../../common/detection/new_terms';
import { WINDOW_UNIT_OPTIONS } from '../ui_options';
import type { RuleEditorProps } from '../type_registry';
import { MatchSection } from './match_section';

/**
 * The 'new_terms' per-type editor (v1.2.3 D5). Presentational like every editor — all rule state
 * lives in the builder. Three jobs the compile contract forces on this component:
 * - The term-field picker offers AGGREGATABLE fields only: the compiled monitor runs a composite
 *   terms agg on the field, and a terms agg on analyzed text fails at monitor runtime with NO
 *   alert written (research_r2 §a). Text fields appear here via their `.keyword` subfield, which
 *   the data view lists as its own aggregatable entry — so what the analyst picks IS the resolved
 *   field (the ppl fieldMap discipline, collapsed into the picker).
 * - groupBy is mirrored to exactly [termField] (assertValidNewTermsRule enforces it; the alert
 *   flyout labels bucket keys from rule.groupBy).
 * - The lifecycle/empty-history copy: the seen-values snapshot happens AT SAVE, one alert per new
 *   value, auto-resolve once seen — none of which is visible from the form fields alone.
 */

/** Extra props (all optional, so the component stays assignable to the registry's editor slot). */
export interface NewTermsEditorExtraProps {
  /** The picked term field (builder state), already aggregatable/resolved. */
  termField?: string;
  onTermFieldChange?: (field: string) => void;
  historyWindowValue?: number;
  historyWindowUnit?: TimeWindow['unit'];
  onHistoryWindowValueChange?: (value: number) => void;
  onHistoryWindowUnitChange?: (unit: TimeWindow['unit']) => void;
}

export type NewTermsEditorProps = RuleEditorProps & NewTermsEditorExtraProps;

export function NewTermsEditor(props: NewTermsEditorProps) {
  const {
    fields,
    loadingFields,
    hasDataView,
    conditions,
    groupBy,
    onGroupByChange,
    termField = '',
    onTermFieldChange,
    historyWindowValue = DEFAULT_NEW_TERMS_HISTORY_WINDOW.value,
    historyWindowUnit = DEFAULT_NEW_TERMS_HISTORY_WINDOW.unit,
    onHistoryWindowValueChange,
    onHistoryWindowUnitChange,
  } = props;

  // Aggregatable fields only — text fields are represented by their `.keyword` subfield entries.
  const termFieldOptions = useMemo<EuiComboBoxOptionOption[]>(
    () =>
      fields
        .filter((field) => field.aggregatable)
        .map((field) => ({ label: field.name, value: field.name })),
    [fields]
  );

  // Mirror groupBy = [termField] — the validator rejects anything else, so drift here would turn
  // every save into a 400.
  useEffect(() => {
    if (termField !== '' && (groupBy.length !== 1 || groupBy[0] !== termField)) {
      onGroupByChange([termField]);
    }
  }, [termField, groupBy, onGroupByChange]);

  const preFilterActive = conditions.length > 0;

  return (
    <EuiPanel hasShadow={false} hasBorder>
      <EuiTitle size="xs">
        <h2>New terms — first-seen values of one field</h2>
      </EuiTitle>
      <EuiSpacer size="s" />

      <EuiCallOut
        size="s"
        iconType="iInCircle"
        title="How a new-terms rule behaves"
        color="primary"
      >
        <EuiText size="s">
          <ul>
            <li>
              When you save, TLSOC snapshots every value seen in the history window — those are
              &ldquo;known&rdquo; and will not alert.
            </li>
            <li>
              After that: ONE alert per never-before-seen value (the value is the alert&apos;s group
              key). Repeats of the same value update that alert instead of duplicating it.
            </li>
            <li>
              The alert resolves automatically once the value has been marked as seen (a background
              refresh runs about once a minute while TLSOC is in use).
            </li>
            <li>
              If the history window contains no matching events, EVERY value counts as new — the
              first runs can alert heavily.
            </li>
          </ul>
        </EuiText>
      </EuiCallOut>
      <EuiSpacer size="m" />

      <EuiFormRow
        fullWidth
        label="Term field"
        helpText={
          'The field whose first-seen values fire. Only aggregatable fields are listed — pick a ' +
          'text field via its .keyword subfield.'
        }
      >
        <EuiComboBox
          fullWidth
          singleSelection={{ asPlainText: true }}
          placeholder={hasDataView ? 'Pick one field…' : 'Select a data view first'}
          isDisabled={!hasDataView}
          isLoading={loadingFields}
          options={termFieldOptions}
          selectedOptions={termField === '' ? [] : [{ label: termField, value: termField }]}
          onChange={(selected) => onTermFieldChange?.(selected[0]?.label ?? '')}
          aria-label="Term field"
        />
      </EuiFormRow>

      <EuiSpacer size="s" />
      <EuiFlexGroup gutterSize="s">
        <EuiFlexItem grow={false}>
          <EuiFormRow label="History window">
            <EuiFieldNumber
              min={1}
              value={historyWindowValue}
              onChange={(e) => onHistoryWindowValueChange?.(Number(e.target.value))}
              aria-label="History window value"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label="Unit">
            <EuiSelect
              options={WINDOW_UNIT_OPTIONS}
              value={historyWindowUnit}
              onChange={(e) => onHistoryWindowUnitChange?.(e.target.value as TimeWindow['unit'])}
              aria-label="History window unit"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow hasEmptyLabelSpace>
            <EuiText size="xs" color="subdued">
              <p>
                A value is &ldquo;new&rdquo; when it was absent this far back. Up to{' '}
                {SEEN_VALUES_CAP.toLocaleString()} distinct values are tracked; beyond that the rule
                is marked degraded. Each run scans the events since the previous run (the schedule
                cadence below).
              </p>
            </EuiText>
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="m" />
      <EuiAccordion
        id="tlsocNewTermsPreFilter"
        buttonContent="Pre-filter (optional) — only matching events are scanned"
        initialIsOpen={preFilterActive}
        paddingSize="s"
      >
        <EuiText size="xs" color="subdued">
          <p>
            The pre-filter narrows BOTH sides: which events can produce a new value, and which
            historical events count as &ldquo;seen&rdquo;. Leave it empty to scan everything.
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        <MatchSection {...props} />
      </EuiAccordion>
    </EuiPanel>
  );
}
