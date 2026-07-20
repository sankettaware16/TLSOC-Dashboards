/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiCallOut,
  EuiPanel,
  EuiSpacer,
  EuiTitle,
} from '@elastic/eui';
import { ConditionGroup } from '../../../common/detection';
import { ConditionRow } from '../condition_row';
import type { RuleEditorProps } from '../type_registry';

/**
 * The "Match — which events count" panel: the flat AND/OR condition-row list BOTH no-code editors
 * are built from (the stateless editor IS this panel; the stateful editor adds a threshold panel
 * below it). Verbatim extraction from detection_builder.tsx (v1.2.3 D1) — shared here so the two
 * editors never fork the condition UI; all state stays in the builder.
 */
export function MatchSection({
  fields,
  fieldsError,
  hasDataView,
  logic,
  conditions,
  onLogicChange,
  onConditionChange,
  onConditionAdd,
  onConditionRemove,
}: RuleEditorProps) {
  return (
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
            onChange={(id) => onLogicChange(id as ConditionGroup['logic'])}
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
            onChange={(next) => onConditionChange(index, next)}
            onRemove={() => onConditionRemove(index)}
          />
          <EuiSpacer size="s" />
        </div>
      ))}
      <EuiButtonEmpty iconType="plusInCircle" onClick={onConditionAdd} isDisabled={!hasDataView}>
        Add condition
      </EuiButtonEmpty>
    </EuiPanel>
  );
}
