/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect } from 'react';
import {
  EuiButtonIcon,
  EuiComboBox,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiSelect,
  EuiText,
} from '@elastic/eui';
import { Condition, DetectionOperator } from '../../common/detection';
import { ANALYZED_TEXT_TYPES } from '../../common/detection/lucene';
import { FieldOption } from './use_data_view_fields';
import { OPERATOR_OPTIONS } from './ui_options';

interface Props {
  condition: Condition;
  fields: FieldOption[];
  showRemove: boolean;
  onChange: (next: Condition) => void;
  onRemove: () => void;
}

/** Operators that can't match reliably (or match only as a whole phrase) on analyzed text fields. */
const TEXT_SENSITIVE_OPERATORS: ReadonlySet<DetectionOperator> = new Set([
  'contains',
  'not_contains',
  'starts_with',
  'ends_with',
  'matches_regex',
]);

/** One match condition: field → operator → value. The value input adapts to the operator. */
export function ConditionRow({ condition, fields, showRemove, onChange, onRemove }: Props) {
  const meta = OPERATOR_OPTIONS.find((o) => o.value === condition.operator);
  const arity = meta?.arity ?? 'value';
  const numeric = !!meta?.numeric;

  const fieldOptions = fields.filter((f) => f.filterable).map((f) => ({ label: f.name }));
  const selectedField = condition.field ? [{ label: condition.field }] : [];

  const selectedFieldOption = fields.find((f) => f.name === condition.field);

  // Legacy rules (saved before Condition.fieldType existed) hydrate a condition with `field` set but
  // `fieldType` undefined. Once the field resolves to a known FieldOption, backfill fieldType so an
  // edit+re-save compiles fieldType-aware (not the stale wildcard) — otherwise the analyzed-text note
  // below would be showing a promise the compiler doesn't keep. Guarded to fire only when fieldType is
  // still undefined AND a real esTypes[0] is resolvable, so it can never loop or set undefined→undefined.
  useEffect(() => {
    if (condition.fieldType === undefined && selectedFieldOption?.esTypes[0] !== undefined) {
      onChange({ ...condition, fieldType: selectedFieldOption.esTypes[0] });
    }
    // `condition` (whole object) and `onChange` are deliberately excluded: both get a new identity on
    // every keystroke edit (e.g. `value`), which would re-run this effect constantly without changing
    // its outcome — the guard only cares about the resolved field and whether fieldType is still unset.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [condition.field, condition.fieldType, selectedFieldOption]);

  const isAnalyzedTextField = !!selectedFieldOption?.esTypes.some((t) =>
    ANALYZED_TEXT_TYPES.has(t)
  );
  const textFieldNote =
    isAnalyzedTextField && TEXT_SENSITIVE_OPERATORS.has(condition.operator) ? (
      condition.operator === 'contains' || condition.operator === 'not_contains' ? (
        <EuiText size="xs" color="subdued">
          Multi-word values match as a phrase on this text field.
        </EuiText>
      ) : (
        <EuiText size="xs" color="warning">
          This operator can&apos;t match reliably on analyzed text fields — prefer contains, equals,
          or a keyword field.
        </EuiText>
      )
    ) : null;

  let valueInput;
  if (arity === 'none') {
    valueInput = (
      <EuiFieldText disabled placeholder="No value needed" value="" onChange={() => undefined} />
    );
  } else if (arity === 'list') {
    valueInput = (
      <EuiComboBox
        noSuggestions
        placeholder="Type a value, press Enter"
        selectedOptions={(condition.values ?? []).map((v) => ({ label: String(v) }))}
        onCreateOption={(v) => onChange({ ...condition, values: [...(condition.values ?? []), v] })}
        onChange={(opts) => onChange({ ...condition, values: opts.map((o) => o.label) })}
      />
    );
  } else if (numeric) {
    valueInput = (
      <EuiFieldNumber
        placeholder="Number"
        value={condition.value === undefined ? '' : Number(condition.value)}
        onChange={(e) =>
          onChange({
            ...condition,
            value: e.target.value === '' ? undefined : Number(e.target.value),
          })
        }
      />
    );
  } else {
    valueInput = (
      <EuiFieldText
        placeholder="Value"
        value={condition.value === undefined ? '' : String(condition.value)}
        onChange={(e) => onChange({ ...condition, value: e.target.value })}
      />
    );
  }

  return (
    <>
      <EuiFlexGroup gutterSize="s" alignItems="flexEnd" responsive={false}>
        <EuiFlexItem>
          <EuiFormRow label="Field">
            <EuiComboBox
              singleSelection={{ asPlainText: true }}
              placeholder="Select a field"
              options={fieldOptions}
              selectedOptions={selectedField}
              onChange={(selected) => {
                const nextName = selected[0]?.label ?? '';
                const nextField = fields.find((f) => f.name === nextName);
                onChange({ ...condition, field: nextName, fieldType: nextField?.esTypes[0] });
              }}
              isClearable={false}
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false} style={{ width: 240 }}>
          <EuiFormRow label="Operator">
            <EuiSelect
              options={OPERATOR_OPTIONS.map((o) => ({ value: o.value, text: o.text }))}
              value={condition.operator}
              onChange={(e) =>
                onChange({
                  ...condition,
                  operator: e.target.value as DetectionOperator,
                  value: undefined,
                  values: undefined,
                })
              }
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiFormRow label="Value">{valueInput}</EuiFormRow>
        </EuiFlexItem>
        {showRemove ? (
          <EuiFlexItem grow={false}>
            <EuiFormRow hasEmptyLabelSpace>
              <EuiButtonIcon
                iconType="minusInCircle"
                color="danger"
                aria-label="Remove condition"
                onClick={onRemove}
              />
            </EuiFormRow>
          </EuiFlexItem>
        ) : null}
      </EuiFlexGroup>
      {textFieldNote}
    </>
  );
}
