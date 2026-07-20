/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useEffect, useMemo, useState } from 'react';
import {
  EuiAccordion,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiCallOut,
  EuiComboBox,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { ConditionGroup } from '../../../common/detection';
import {
  VALUE_LIST_INLINE_MAX_VALUES,
  ValueListType,
} from '../../../common/value_lists';
import { ConditionRow } from '../condition_row';
import type { RuleEditorProps } from '../type_registry';

/**
 * The 'indicator_match' per-type editor (v1.2.3 D6): pick a value list (managed under Threat
 * Intel), pick the EVENT field to match against it, optionally pre-filter which events are
 * checked. The rule's execution shape is size-based (the save route picks it from the list's
 * CURRENT size): ≤ 900 values compile INLINE into a doc-level monitor (one alert per matching
 * event, with the matching documents attached); larger lists run in LOOKUP mode as a bucket
 * monitor (one alert per matched indicator value per window — the alert carries the VALUE, not
 * the documents). The mode indicator below states which shape THIS rule will get, honestly.
 *
 * PROP THREADING (the custom_query precedent): RuleEditorProps is the D1 v1 contract — the
 * indicator-specific state (listId/eventField) is threaded in via the OPTIONAL props below, so
 * this component remains a valid registry `ComponentType<RuleEditorProps>`. Until the builder
 * threads them (serial integration) the editor renders an explicit "integration pending"
 * callout instead of crashing. The pre-filter reuses the builder's SHARED condition-row state
 * (logic/conditions props) — the same slice the stateless editor uses.
 */
export interface IndicatorMatchEditorProps extends RuleEditorProps {
  /** The selected value list's id (builder state). */
  listId?: string;
  onListIdChange?: (listId: string) => void;
  /** The event field matched against the list (builder state; also mirrored into groupBy). */
  eventField?: string;
  onEventFieldChange?: (field: string) => void;
}

interface ValueListOption {
  id: string;
  name: string;
  type: ValueListType;
  count: number;
}

export function IndicatorMatchEditor(props: IndicatorMatchEditorProps) {
  const {
    core,
    fields,
    hasDataView,
    listId = '',
    onListIdChange,
    eventField = '',
    onEventFieldChange,
    logic,
    conditions,
    onLogicChange,
    onConditionChange,
    onConditionAdd,
    onConditionRemove,
    fieldsError,
  } = props;

  const [lists, setLists] = useState<ValueListOption[] | null>(null);
  const [listsError, setListsError] = useState<string | null>(null);

  useEffect(() => {
    if (!core) return;
    let active = true;
    (async () => {
      try {
        const resp = (await core.http.get('/api/tlsoc/value_lists')) as {
          lists: ValueListOption[];
        };
        if (active) setLists(resp.lists ?? []);
      } catch (e: any) {
        if (active) setListsError(e?.body?.message ?? e?.message ?? 'Could not load value lists');
      }
    })();
    return () => {
      active = false;
    };
  }, [core]);

  const selectedList = lists?.find((l) => l.id === listId);

  // Type-filtered event-field options: ip lists only match ip-mapped fields (CIDR semantics —
  // the save route re-verifies via field_caps); keyword lists match keyword fields.
  const fieldOptions = useMemo(() => {
    const wanted = selectedList?.type === 'ip' ? 'ip' : 'keyword';
    return fields
      .filter((f) => f.aggregatable && f.esTypes.includes(wanted))
      .map((f) => ({ label: f.name }));
  }, [fields, selectedList]);

  if (!core || !onListIdChange || !onEventFieldChange) {
    return (
      <EuiPanel hasShadow={false} hasBorder>
        <EuiTitle size="xs">
          <h2>Indicator match — which list, which field</h2>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiCallOut
          color="warning"
          iconType="iInCircle"
          title="The indicator-match editor is not wired up yet"
        >
          <p>
            The builder must pass its core service and the listId/eventField form state to this
            editor (D6 serial integration) before it can render.
          </p>
        </EuiCallOut>
      </EuiPanel>
    );
  }

  const onListChange = (nextId: string) => {
    onListIdChange(nextId);
    // A list-type switch changes which fields are eligible — drop a now-ineligible field so a
    // keyword field can never ride into an ip rule (the save gate would 400 it anyway).
    const next = lists?.find((l) => l.id === nextId);
    if (next && eventField !== '') {
      const wanted = next.type === 'ip' ? 'ip' : 'keyword';
      const stillValid = fields.some(
        (f) => f.name === eventField && f.aggregatable && f.esTypes.includes(wanted)
      );
      if (!stillValid) onEventFieldChange('');
    }
  };

  return (
    <EuiPanel hasShadow={false} hasBorder>
      <EuiTitle size="xs">
        <h2>Indicator match — which list, which field</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiText size="s" color="subdued">
        <p>
          Fire when the event field's value appears in a value list. Lists are managed under
          Threat Intel; the list's size decides how the rule executes (shown below).
        </p>
      </EuiText>
      <EuiSpacer size="s" />

      {listsError ? (
        <EuiCallOut color="danger" iconType="alert" title="Could not load value lists">
          <p>{listsError}</p>
        </EuiCallOut>
      ) : lists === null ? (
        <EuiLoadingSpinner size="m" />
      ) : lists.length === 0 ? (
        <EuiCallOut color="primary" iconType="iInCircle" title="No value lists yet">
          <p>Create one under Threat Intel first — a rule needs a list to match against.</p>
        </EuiCallOut>
      ) : (
        <>
          <EuiFormRow
            label="Value list"
            helpText="Which indicator list to match events against."
          >
            <EuiSelect
              value={listId}
              onChange={(e) => onListChange(e.target.value)}
              options={[
                { value: '', text: 'Select a value list' },
                ...lists.map((l) => ({
                  value: l.id,
                  text: `${l.name} (${l.type === 'ip' ? 'IP/CIDR' : 'keyword'}, ${l.count} value${
                    l.count === 1 ? '' : 's'
                  })`,
                })),
              ]}
            />
          </EuiFormRow>
          <EuiFormRow
            label="Event field"
            helpText={
              selectedList?.type === 'ip'
                ? 'IP lists only match ip-mapped fields (CIDR blocks need them) — verified against your indices on save.'
                : 'The keyword field whose value is checked against the list.'
            }
          >
            <EuiComboBox
              placeholder={hasDataView ? 'e.g. source.ip' : 'Select a data view first'}
              isDisabled={!hasDataView || !selectedList}
              singleSelection={{ asPlainText: true }}
              options={fieldOptions}
              selectedOptions={eventField ? [{ label: eventField }] : []}
              onChange={(opts) => onEventFieldChange(opts[0]?.label ?? '')}
              onCreateOption={(val) => {
                const v = val.trim();
                if (v) onEventFieldChange(v);
              }}
            />
          </EuiFormRow>
          {fieldsError ? (
            <>
              <EuiSpacer size="s" />
              <EuiCallOut color="danger" title={fieldsError} iconType="alert" />
            </>
          ) : null}

          {selectedList ? (
            <>
              <EuiSpacer size="s" />
              {selectedList.count <= VALUE_LIST_INLINE_MAX_VALUES ? (
                <EuiCallOut
                  color="primary"
                  iconType="iInCircle"
                  title={`Will compile inline (${selectedList.count} value${
                    selectedList.count === 1 ? '' : 's'
                  })`}
                >
                  <p>
                    A per-event (doc-level) rule: one alert per matching event, with the matching
                    documents attached in the alert flyout — the best triage quality. When the
                    list changes, the rule is rewritten in the background (one run of lag). If
                    the list ever grows past {VALUE_LIST_INLINE_MAX_VALUES} values, re-save this
                    rule to switch it to lookup mode — TLSOC refuses to compile larger inline
                    queries because past 1,024 values they silently match nothing.
                  </p>
                </EuiCallOut>
              ) : (
                <EuiCallOut
                  color="primary"
                  iconType="iInCircle"
                  title={`Lookup mode (${selectedList.count} values)`}
                >
                  <p>
                    The list is matched live at every run: one alert per matched indicator value
                    per run window. The alert carries the matched VALUE (not the matching
                    documents — that is the honest tradeoff versus inline mode); list edits apply
                    on the next run without re-saving. Runs on the cadence set under Schedule.
                  </p>
                </EuiCallOut>
              )}
            </>
          ) : null}
        </>
      )}

      <EuiSpacer size="m" />
      <EuiAccordion
        id="tlsoc-indicator-prefilter"
        buttonContent="Pre-filter (optional) — narrow which events are checked"
      >
        <EuiSpacer size="s" />
        <EuiText size="s" color="subdued">
          <p>
            Only events matching these conditions are checked against the list. Leave empty to
            check every event.
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        {conditions.length > 1 ? (
          <>
            <EuiButtonGroup
              type="single"
              legend="Combine pre-filter conditions with AND or OR"
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
      </EuiAccordion>
    </EuiPanel>
  );
}
