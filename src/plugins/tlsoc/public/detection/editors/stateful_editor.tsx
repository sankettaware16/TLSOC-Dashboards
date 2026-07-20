/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useMemo } from 'react';
import {
  EuiComboBox,
  EuiFieldNumber,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiTitle,
} from '@elastic/eui';
import { CountThreshold, TimeWindow } from '../../../common/detection';
import { THRESHOLD_OP_OPTIONS, WINDOW_UNIT_OPTIONS } from '../ui_options';
import type { RuleEditorProps } from '../type_registry';
import { MatchSection } from './match_section';

/**
 * The 'stateful' (threshold) per-type editor: the shared Match panel plus the "> N within T
 * grouped by …" threshold panel — verbatim extraction from detection_builder.tsx (v1.2.3 D1).
 * All state lives in the builder; this component only renders and reports changes.
 */
export function StatefulEditor(props: RuleEditorProps) {
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
      </EuiPanel>
    </>
  );
}
