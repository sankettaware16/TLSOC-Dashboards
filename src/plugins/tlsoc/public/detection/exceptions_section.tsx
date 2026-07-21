/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiComboBox,
  EuiFieldNumber,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import {
  ExceptionEntry,
  ExceptionOp,
  MAX_EXCEPTION_ENTRIES,
} from '../../common/detection/exceptions';
import { SuppressionConfig, TimeWindow } from '../../common/detection';
import { FieldOption } from './use_data_view_fields';

/**
 * The D9 noise-control sections of the detection builder (v1.2.3 W4b):
 *
 * - {@link ExceptionsSection} — the per-rule exception editor ("never alert when …"), rendered
 *   for EVERY rule type. Rows follow the condition-row idioms (field combo → operator select →
 *   values combo); state lives in the builder (purely presentational, like every type editor).
 *
 * - {@link SuppressionSection} — alert suppression. Doc-kind types (stateless, custom_query) get
 *   the opt-in switch + suppress-by field picker + window, with the compile-target trade-off
 *   stated verbatim. Bucket-kind types get explanatory copy ONLY: group-by dedup is inherent
 *   there, and the knobs the engine cannot deliver (fixed-duration suppression, suppress-by
 *   fields different from the group-by) are deliberately not faked (research_r2 §e).
 */

const EXCEPTION_OP_OPTIONS: Array<{ value: ExceptionOp; text: string }> = [
  { value: 'equals', text: 'equals any of' },
  { value: 'is_one_of', text: 'is one of' },
  { value: 'contains', text: 'contains any of' },
  { value: 'cidr', text: 'is in CIDR block' },
];

const NEW_ENTRY: ExceptionEntry = { field: '', op: 'equals', values: [] };

interface ExceptionsProps {
  entries: ExceptionEntry[];
  onChange: (next: ExceptionEntry[]) => void;
  fields: FieldOption[];
  hasDataView: boolean;
}

/** The per-rule exceptions editor — renders for every detection type (shared builder chrome). */
export function ExceptionsSection({ entries, onChange, fields, hasDataView }: ExceptionsProps) {
  const fieldOptions = fields.filter((f) => f.filterable).map((f) => ({ label: f.name }));
  const update = (index: number, next: ExceptionEntry) =>
    onChange(entries.map((e, i) => (i === index ? next : e)));

  return (
    <>
      <EuiTitle size="xxs">
        <h3>Exceptions — never alert when…</h3>
      </EuiTitle>
      <EuiSpacer size="xs" />
      <EuiText size="s" color="subdued">
        <p>
          Events matching any exception are excluded from this rule — the curated way to kill a
          known false positive without loosening the detection itself. Exceptions are TLSOC-native:
          they are omitted from Sigma exports (with a warning naming them). CIDR exceptions match
          only against IP-mapped fields.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      {entries.map((entry, i) => (
        <div key={i} data-test-subj={`tlsocExceptionRow-${i}`}>
          <EuiFlexGroup gutterSize="s" alignItems="flexEnd" responsive={false}>
            <EuiFlexItem>
              <EuiFormRow label={i === 0 ? 'Field' : undefined}>
                <EuiComboBox
                  singleSelection={{ asPlainText: true }}
                  placeholder="Select a field"
                  options={fieldOptions}
                  selectedOptions={entry.field ? [{ label: entry.field }] : []}
                  onChange={(selected) =>
                    update(i, { ...entry, field: selected[0]?.label ?? '' })
                  }
                  onCreateOption={(val) => update(i, { ...entry, field: val.trim() })}
                  isClearable={false}
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem grow={false} style={{ width: 200 }}>
              <EuiFormRow label={i === 0 ? 'Operator' : undefined}>
                <EuiSelect
                  options={EXCEPTION_OP_OPTIONS}
                  value={entry.op}
                  onChange={(e) => update(i, { ...entry, op: e.target.value as ExceptionOp })}
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow label={i === 0 ? 'Values' : undefined}>
                <EuiComboBox
                  noSuggestions
                  placeholder={
                    entry.op === 'cidr' ? 'e.g. 10.0.0.0/8 — press Enter' : 'Type a value, press Enter'
                  }
                  selectedOptions={entry.values.map((v) => ({ label: v }))}
                  onCreateOption={(v) => {
                    const value = v.trim();
                    if (value) update(i, { ...entry, values: [...entry.values, value] });
                  }}
                  onChange={(opts) => update(i, { ...entry, values: opts.map((o) => o.label) })}
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFormRow hasEmptyLabelSpace={i === 0}>
                <EuiButtonIcon
                  iconType="minusInCircle"
                  color="danger"
                  aria-label="Remove exception"
                  onClick={() => onChange(entries.filter((_, j) => j !== i))}
                />
              </EuiFormRow>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="xs" />
        </div>
      ))}
      <EuiButtonEmpty
        iconType="plusInCircle"
        size="s"
        data-test-subj="tlsocAddException"
        isDisabled={!hasDataView || entries.length >= MAX_EXCEPTION_ENTRIES}
        onClick={() => onChange([...entries, { ...NEW_ENTRY }])}
      >
        Add exception
      </EuiButtonEmpty>
      {entries.length >= MAX_EXCEPTION_ENTRIES ? (
        <EuiText size="xs" color="warning">
          <p>
            {MAX_EXCEPTION_ENTRIES} exceptions is the cap — consolidate values into one
            &quot;is one of&quot; entry, or use an indicator-match value list for large exclusion
            sets.
          </p>
        </EuiText>
      ) : null}
    </>
  );
}

interface SuppressionProps {
  /** 'doc' = stateless/custom_query (opt-in conversion knobs); 'bucket' = explanatory copy only. */
  kind: 'doc' | 'bucket';
  enabled: boolean;
  groupBy: string[];
  window: TimeWindow;
  onToggle: (enabled: boolean) => void;
  onChange: (next: SuppressionConfig) => void;
  fields: FieldOption[];
  hasDataView: boolean;
}

const WINDOW_UNIT_OPTIONS: Array<{ value: TimeWindow['unit']; text: string }> = [
  { value: 'MINUTES', text: 'minutes' },
  { value: 'HOURS', text: 'hours' },
  { value: 'DAYS', text: 'days' },
];

/** The suppression section: knobs for doc-kind types, honest explanatory copy for bucket-kind. */
export function SuppressionSection({
  kind,
  enabled,
  groupBy,
  window,
  onToggle,
  onChange,
  fields,
  hasDataView,
}: SuppressionProps) {
  if (kind === 'bucket') {
    return (
      <>
        <EuiTitle size="xxs">
          <h3>Alert suppression</h3>
        </EuiTitle>
        <EuiSpacer size="xs" />
        <EuiText size="s" color="subdued" data-test-subj="tlsocSuppressionInherent">
          <p>
            Suppression is built in for this rule type: alerts are deduplicated per group key —
            one alert per group stays active while the condition keeps firing and resolves itself
            when it stops. There are no extra knobs: fixed-duration suppression and suppress-by
            fields different from the group-by are not expressible on the OpenSearch Alerting
            engine, and TLSOC does not fake them. Events missing a group-by field are silently
            excluded from counting.
          </p>
        </EuiText>
      </>
    );
  }

  // Aggregatable fields only: a composite terms source on analyzed text fails at monitor
  // runtime with NO alert written (silent-failure class) — the same gating every group-by
  // picker in the builder applies.
  const groupByOptions = fields.filter((f) => f.aggregatable).map((f) => ({ label: f.name }));

  return (
    <>
      <EuiTitle size="xxs">
        <h3>Alert suppression</h3>
      </EuiTitle>
      <EuiSpacer size="xs" />
      <EuiSwitch
        label="Suppress alerts by field (one alert per group per window)"
        checked={enabled}
        data-test-subj="tlsocSuppressionToggle"
        onChange={(e) => onToggle(e.target.checked)}
      />
      {enabled ? (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut
            size="s"
            color="warning"
            iconType="iInCircle"
            title="Suppression changes what the alert carries"
          >
            <p>
              With suppression on, this rule compiles to a grouped (bucket-level) monitor: one
              alert per group per window, deduplicated by the engine while the group keeps
              matching. The alert loses per-doc findings/related docs — it carries the group keys
              instead. Events missing a suppression field are silently excluded from counting.
            </p>
          </EuiCallOut>
          <EuiSpacer size="s" />
          <EuiFormRow
            label="Suppress by field(s)"
            helpText="Aggregatable fields only — one alert per distinct combination of these values."
          >
            <EuiComboBox
              placeholder={hasDataView ? 'Select field(s)' : 'Select a data view first'}
              options={groupByOptions}
              selectedOptions={groupBy.map((f) => ({ label: f }))}
              onChange={(opts) =>
                onChange({ groupBy: opts.map((o) => o.label), window })
              }
              isDisabled={!hasDataView}
              data-test-subj="tlsocSuppressionGroupBy"
            />
          </EuiFormRow>
          <EuiFlexGroup gutterSize="s" style={{ maxWidth: 360 }}>
            <EuiFlexItem>
              <EuiFormRow label="Suppression window">
                <EuiFieldNumber
                  min={1}
                  value={window.value}
                  onChange={(e) => {
                    const v = Number(e.target.value);
                    onChange({
                      groupBy,
                      window: { ...window, value: Number.isNaN(v) ? 1 : v },
                    });
                  }}
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow hasEmptyLabelSpace>
                <EuiSelect
                  options={WINDOW_UNIT_OPTIONS}
                  value={window.unit}
                  onChange={(e) =>
                    onChange({
                      groupBy,
                      window: { ...window, unit: e.target.value as TimeWindow['unit'] },
                    })
                  }
                />
              </EuiFormRow>
            </EuiFlexItem>
          </EuiFlexGroup>
        </>
      ) : null}
    </>
  );
}
