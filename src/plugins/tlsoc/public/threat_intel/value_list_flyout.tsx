/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useEffect, useMemo, useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFilePicker,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyoutHeader,
  EuiFormRow,
  EuiFieldText,
  EuiLoadingSpinner,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import {
  VALUE_LIST_INLINE_MAX_VALUES,
  VALUE_LIST_MAX_VALUES,
  ValueListType,
  assertValidValueListName,
  parseValueLines,
  validateValueListValues,
  valueListIdFromName,
} from '../../common/value_lists';

interface Props {
  core: CoreStart;
  /** null = create; otherwise edit (name/type immutable — the id anchors rules' lookups). */
  existing: { id: string; name: string; type: ValueListType } | null;
  onClose: () => void;
  /** Called after a successful save; `warning` carries the server's over-cap honesty note. */
  onSaved: (warning?: string) => void;
}

/** How many per-line validation errors are shown before eliding. */
const SHOWN_ERRORS = 5;

/**
 * Create/edit flyout for one value list: name + type + a one-value-per-line textarea (typed,
 * pasted, or loaded from a text file), with live per-line validation and an honest indicator of
 * which shape rules on this list will compile to (inline ≤ 900 values / lookup above).
 */
export function ValueListFlyout({ core, existing, onClose, onSaved }: Props) {
  const isEdit = !!existing;
  const [name, setName] = useState(existing?.name ?? '');
  const [type, setType] = useState<ValueListType>(existing?.type ?? 'keyword');
  const [rawText, setRawText] = useState('');
  const [hydrating, setHydrating] = useState(isEdit);
  const [hydrateError, setHydrateError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Edit hydration: the LIST route serves summaries only — fetch the full values here.
  useEffect(() => {
    if (!existing) return;
    let active = true;
    (async () => {
      try {
        const resp = (await core.http.get(
          `/api/tlsoc/value_lists/${encodeURIComponent(existing.id)}`
        )) as { values: string[] };
        if (active) setRawText(resp.values.join('\n'));
      } catch (e: any) {
        if (active) setHydrateError(e?.body?.message ?? e?.message ?? 'Could not load the list');
      } finally {
        if (active) setHydrating(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [core, existing]);

  // parseValueLines trims/dedupes, so the remaining live errors are syntax (ip) and length.
  const values = useMemo(() => parseValueLines(rawText), [rawText]);
  const valueErrors = useMemo(() => validateValueListValues(type, values), [type, values]);

  const nameError = useMemo(() => {
    if (name.trim() === '') return null; // untouched — the Save gate handles it
    try {
      assertValidValueListName(name);
      return null;
    } catch (e: any) {
      return e.message as string;
    }
  }, [name]);

  const overHardCap = values.length > VALUE_LIST_MAX_VALUES;
  const canSave =
    !hydrating &&
    !saving &&
    name.trim() !== '' &&
    !nameError &&
    values.length > 0 &&
    valueErrors.length === 0 &&
    !overHardCap;

  const onFiles = (files: FileList | null) => {
    const file = files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      // Append below whatever is already typed; parseValueLines dedupes overlaps.
      setRawText((prev) => (prev.trim() === '' ? text : `${prev}\n${text}`));
    };
    reader.readAsText(file);
  };

  const onSave = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      let warning: string | undefined;
      if (isEdit) {
        const resp = (await core.http.put(
          `/api/tlsoc/value_lists/${encodeURIComponent(existing!.id)}`,
          { body: JSON.stringify({ values }) }
        )) as { warning?: string };
        warning = resp?.warning;
      } else {
        await core.http.post('/api/tlsoc/value_lists', {
          body: JSON.stringify({ name: name.trim(), type, values }),
        });
      }
      onSaved(warning);
    } catch (e: any) {
      setSaveError(e?.body?.message ?? e?.message ?? 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <EuiFlyout onClose={onClose} size="m" aria-labelledby="tlsocValueListFlyoutTitle">
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="m">
          <h2 id="tlsocValueListFlyoutTitle">
            {isEdit ? `Edit "${existing!.name}"` : 'New value list'}
          </h2>
        </EuiTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiFormRow
          label="Name"
          isInvalid={!!nameError}
          error={nameError ?? undefined}
          helpText={
            isEdit
              ? 'The name (and the id derived from it) cannot change — detection rules reference it.'
              : `Rules reference the list by the id derived from this name${
                  name.trim() ? `: "${valueListIdFromName(name)}"` : '.'
                }`
          }
        >
          <EuiFieldText
            value={name}
            disabled={isEdit}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Known bad IPs"
          />
        </EuiFormRow>
        <EuiFormRow
          label="Type"
          helpText={
            isEdit
              ? 'The type cannot change — rules were validated against it.'
              : 'IP lists accept addresses and CIDR blocks (v4/v6) and can only match ip-mapped event fields.'
          }
        >
          <EuiSelect
            value={type}
            disabled={isEdit}
            onChange={(e) => setType(e.target.value as ValueListType)}
            options={[
              { value: 'keyword', text: 'Keyword (exact strings — hashes, domains, users…)' },
              { value: 'ip', text: 'IP (addresses and CIDR blocks)' },
            ]}
          />
        </EuiFormRow>

        {hydrateError ? (
          <>
            <EuiSpacer size="s" />
            <EuiCallOut color="danger" iconType="alert" title="Could not load the list's values">
              <p>{hydrateError}</p>
            </EuiCallOut>
          </>
        ) : null}

        <EuiFormRow
          label={`Values (one per line) — ${values.length} value${values.length === 1 ? '' : 's'}`}
          fullWidth
          helpText="Duplicates and blank lines are dropped automatically."
        >
          {hydrating ? (
            <EuiLoadingSpinner size="m" />
          ) : (
            <EuiTextArea
              fullWidth
              rows={12}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder={type === 'ip' ? '10.0.0.66\n192.168.0.0/16\n2001:db8::1' : 'evil.example.com\nmimikatz.exe'}
              aria-label="Value list values, one per line"
            />
          )}
        </EuiFormRow>
        <EuiFormRow label="…or load values from a text file" fullWidth>
          <EuiFilePicker
            compressed
            initialPromptText="Select or drop a .txt file (one value per line)"
            onChange={onFiles}
            accept=".txt,.csv,text/plain"
            aria-label="Load values from a file"
          />
        </EuiFormRow>

        {valueErrors.length > 0 ? (
          <>
            <EuiSpacer size="s" />
            <EuiCallOut
              color="danger"
              iconType="alert"
              title={`${valueErrors.length} value${valueErrors.length === 1 ? ' is' : 's are'} invalid`}
            >
              <ul>
                {valueErrors.slice(0, SHOWN_ERRORS).map((err) => (
                  <li key={err.index}>
                    “{err.value}” — {err.reason}
                  </li>
                ))}
              </ul>
              {valueErrors.length > SHOWN_ERRORS ? (
                <p>…and {valueErrors.length - SHOWN_ERRORS} more.</p>
              ) : null}
            </EuiCallOut>
          </>
        ) : null}

        {overHardCap ? (
          <>
            <EuiSpacer size="s" />
            <EuiCallOut color="danger" iconType="alert" title="Too many values">
              <p>
                {values.length} values — the maximum is {VALUE_LIST_MAX_VALUES}: the engine
                refuses larger lookups at every monitor run. Split the list.
              </p>
            </EuiCallOut>
          </>
        ) : values.length > 0 ? (
          <>
            <EuiSpacer size="s" />
            <EuiText size="s" color="subdued">
              <p>
                {values.length <= VALUE_LIST_INLINE_MAX_VALUES
                  ? `Rules on this list will compile INLINE (${values.length} values ≤ ${VALUE_LIST_INLINE_MAX_VALUES}): one alert per matching event, with the matching documents attached.`
                  : `Rules on this list will compile in LOOKUP mode (${values.length} values > ${VALUE_LIST_INLINE_MAX_VALUES}): one alert per matched indicator value per run window; list edits apply on the next run.`}
              </p>
            </EuiText>
          </>
        ) : null}

        {saveError ? (
          <>
            <EuiSpacer size="s" />
            <EuiCallOut color="danger" iconType="alert" title="Could not save the list">
              <p>{saveError}</p>
            </EuiCallOut>
          </>
        ) : null}
      </EuiFlyoutBody>
      <EuiFlyoutFooter>
        <EuiFlexGroup justifyContent="spaceBetween">
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton fill onClick={onSave} isLoading={saving} isDisabled={!canSave}>
              {isEdit ? 'Save changes' : 'Create list'}
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
}
