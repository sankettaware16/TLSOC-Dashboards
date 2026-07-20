/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useRef, useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCode,
  EuiCodeBlock,
  EuiFieldNumber,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPanel,
  EuiPopover,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { TimeWindow } from '../../../common/detection';
import { parsePpl, PplParseResult } from '../../../common/detection/ppl_parse';
import { WINDOW_UNIT_OPTIONS } from '../ui_options';
import type { RuleEditorProps } from '../type_registry';
import { PplPreviewData, PplPreviewTable } from '../ppl_preview_table';

/**
 * The 'ppl' per-type editor (v1.2.3 D3): a monospace query textarea with debounced CLIENT-SIDE
 * parsing (our parser owns error positions — the engine's errors have none), a subset
 * cheat-sheet popover, the rule window, and a server-side Preview (the route re-parses; never
 * trusts this client). Like every editor it is presentational: rule state lives in the builder.
 *
 * On every successful parse the editor mirrors the query's `by` fields into the builder's
 * groupBy (rule.groupBy labels alert-flyout bucket keys — the R1 risk this closes by
 * construction).
 */

/** Extra (all-optional, so the component stays assignable to the registry's editor slot). */
export interface PplEditorExtraProps {
  /** The PPL query text (builder state). */
  pplText?: string;
  onPplTextChange?: (text: string) => void;
  /**
   * Runs the server-side preview (POST /api/tlsoc/detection/_ppl_preview) with the builder's
   * data-view time field and current window. Absent → the Preview button is hidden.
   */
  onPreview?: (pplText: string) => Promise<PplPreviewData>;
}

export type PplEditorProps = RuleEditorProps & PplEditorExtraProps;

const PARSE_DEBOUNCE_MS = 300;

const EXAMPLE_QUERY =
  'source = fosstlsoc-logs-* | where http.response.status_code >= 400 | ' +
  'stats dc(url.path) as unique_paths, count() as errors by source.ip | ' +
  'where unique_paths >= 40 and errors >= 50';

/** A windowed excerpt of the query with a caret under the error offset. */
function positionMarker(text: string, offset: number): string {
  const upto = text.slice(0, Math.min(offset, text.length));
  const lineStart = upto.lastIndexOf('\n') + 1;
  const lineEndRaw = text.indexOf('\n', offset);
  const lineEnd = lineEndRaw === -1 ? text.length : lineEndRaw;
  const line = text.slice(lineStart, lineEnd);
  const col = Math.min(offset, text.length) - lineStart;

  const WINDOW = 40;
  const start = Math.max(0, col - WINDOW);
  const end = Math.min(line.length, col + WINDOW);
  const prefix = start > 0 ? '…' : '';
  const suffix = end < line.length ? '…' : '';
  const excerpt = prefix + line.slice(start, end) + suffix;
  const caret = ' '.repeat(prefix.length + (col - start)) + '^';
  return `${excerpt}\n${caret}`;
}

export function PplEditor(props: PplEditorProps) {
  const {
    pplText = '',
    onPplTextChange,
    onPreview,
    groupBy,
    onGroupByChange,
    windowValue,
    onWindowValueChange,
    windowUnit,
    onWindowUnitChange,
    hasDataView,
  } = props;

  const [parsed, setParsed] = useState<PplParseResult | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [preview, setPreview] = useState<PplPreviewData | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Debounced client-side parse.
  useEffect(() => {
    const handle = setTimeout(() => {
      setParsed(pplText.trim() === '' ? null : parsePpl(pplText));
    }, PARSE_DEBOUNCE_MS);
    return () => clearTimeout(handle);
  }, [pplText]);

  // Mirror the parsed by-fields into the builder's groupBy (rule.groupBy labels flyout keys).
  useEffect(() => {
    if (parsed?.ok) {
      const by = parsed.rule.by.map((f) => f.name);
      if (by.length !== groupBy.length || by.some((b, i) => b !== groupBy[i])) {
        onGroupByChange(by);
      }
    }
  }, [parsed, groupBy, onGroupByChange]);

  const parseOk = parsed?.ok === true;

  const runPreview = async () => {
    if (!onPreview) {
      return;
    }
    setPreviewLoading(true);
    setPreviewError(null);
    try {
      const result = await onPreview(pplText);
      if (mounted.current) {
        setPreview(result);
      }
    } catch (e) {
      if (mounted.current) {
        setPreview(null);
        const err = e as { body?: { message?: string }; message?: string };
        setPreviewError(err?.body?.message ?? err?.message ?? String(e));
      }
    } finally {
      if (mounted.current) {
        setPreviewLoading(false);
      }
    }
  };

  return (
    <EuiPanel hasShadow={false} hasBorder>
      <EuiFlexGroup justifyContent="spaceBetween" alignItems="center" gutterSize="s">
        <EuiFlexItem grow={false}>
          <EuiTitle size="xs">
            <h2>PPL query — aggregate and threshold</h2>
          </EuiTitle>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiPopover
            button={
              <EuiButtonEmpty
                iconType="questionInCircle"
                size="xs"
                onClick={() => setHelpOpen((open) => !open)}
              >
                Syntax help
              </EuiButtonEmpty>
            }
            isOpen={helpOpen}
            closePopover={() => setHelpOpen(false)}
            anchorPosition="downRight"
          >
            <EuiText size="s" style={{ maxWidth: 460 }}>
              <p>
                <strong>Supported shape</strong> (nothing else):
              </p>
              <p>
                <EuiCode>
                  source = &lt;index&gt; | where … | stats … by … | where &lt;thresholds&gt;
                </EuiCode>
              </p>
              <ul>
                <li>
                  <EuiCode>=</EuiCode> is an <strong>exact, case-sensitive</strong> match (keyword
                  semantics); field names are case-sensitive, commands are not.
                </li>
                <li>
                  <EuiCode>like(field, &apos;%pat_tern%&apos;)</EuiCode> is case-INsensitive;{' '}
                  <EuiCode>%</EuiCode> = any run, <EuiCode>_</EuiCode> = one character.
                </li>
                <li>
                  Metrics: <EuiCode>count()</EuiCode>, <EuiCode>count(field)</EuiCode>,{' '}
                  <EuiCode>dc(field)</EuiCode> (approximate — HyperLogLog),{' '}
                  <EuiCode>sum/avg/min/max(field)</EuiCode>. Name metrics with{' '}
                  <EuiCode>as</EuiCode> to use them in the threshold.
                </li>
                <li>
                  No <EuiCode>sort</EuiCode>/<EuiCode>head</EuiCode>/<EuiCode>eval</EuiCode>/
                  <EuiCode>span()</EuiCode> — the rule window is the time bucket.
                </li>
                <li>
                  Do not write <EuiCode>.keyword</EuiCode> — TLSOC resolves keyword subfields
                  automatically.
                </li>
              </ul>
              <p>
                <strong>Example</strong>
              </p>
              <EuiCodeBlock language="text" paddingSize="s" fontSize="s" isCopyable>
                {EXAMPLE_QUERY}
              </EuiCodeBlock>
            </EuiText>
          </EuiPopover>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      <EuiFormRow
        fullWidth
        label="Query"
        helpText="The rule fires per group returned by the final threshold. Group-by fields become the alert's group keys."
      >
        <EuiTextArea
          fullWidth
          rows={4}
          placeholder={EXAMPLE_QUERY}
          value={pplText}
          onChange={(e) => onPplTextChange?.(e.target.value)}
          style={{ fontFamily: 'monospace' }}
          aria-label="PPL query"
        />
      </EuiFormRow>

      {parsed && !parsed.ok
        ? parsed.errors.map((err, i) => (
            <div key={`${err.construct}-${i}`}>
              <EuiSpacer size="s" />
              <EuiCallOut color="danger" iconType="alert" title={`${err.construct}: ${err.reason}`}>
                <EuiCodeBlock language="text" paddingSize="s" fontSize="s" transparentBackground>
                  {positionMarker(pplText, err.offset)}
                </EuiCodeBlock>
              </EuiCallOut>
            </div>
          ))
        : null}

      {parsed?.ok ? (
        <>
          {parsed.warnings.map((warning) => (
            <div key={warning}>
              <EuiSpacer size="s" />
              <EuiCallOut color="warning" size="s" title={warning} />
            </div>
          ))}
          <EuiSpacer size="s" />
          <EuiText size="xs" color="subdued">
            <p>
              Groups by:{' '}
              {parsed.rule.by.length > 0
                ? parsed.rule.by.map((f) => f.name).join(', ')
                : 'nothing yet — add "by <field>" (required)'}
            </p>
          </EuiText>
        </>
      ) : null}

      <EuiSpacer size="m" />
      <EuiFlexGroup gutterSize="s">
        <EuiFlexItem grow={false}>
          <EuiFormRow label="Window">
            <EuiFieldNumber
              min={1}
              value={windowValue}
              onChange={(e) => onWindowValueChange(Number(e.target.value))}
              aria-label="Window value"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label="Unit">
            <EuiSelect
              options={WINDOW_UNIT_OPTIONS}
              value={windowUnit}
              onChange={(e) => onWindowUnitChange(e.target.value as TimeWindow['unit'])}
              aria-label="Window unit"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow hasEmptyLabelSpace>
            <EuiText size="xs" color="subdued">
              <p>The window is injected as the monitor&apos;s time-range filter.</p>
            </EuiText>
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>

      {onPreview ? (
        <>
          <EuiSpacer size="m" />
          <EuiButton
            size="s"
            iconType="play"
            onClick={runPreview}
            isLoading={previewLoading}
            isDisabled={!parseOk || !hasDataView}
          >
            Preview
          </EuiButton>
          {previewError ? (
            <>
              <EuiSpacer size="s" />
              <EuiCallOut color="danger" iconType="alert" title="Preview failed">
                <p>{previewError}</p>
              </EuiCallOut>
            </>
          ) : null}
          {preview ? (
            <>
              <EuiSpacer size="s" />
              {preview.query ? (
                <>
                  <EuiText size="xs" color="subdued">
                    <p>Ran (window and row cap injected):</p>
                  </EuiText>
                  <EuiCodeBlock language="text" paddingSize="s" fontSize="s" isCopyable>
                    {preview.query}
                  </EuiCodeBlock>
                  <EuiSpacer size="s" />
                </>
              ) : null}
              <PplPreviewTable preview={preview} />
            </>
          ) : null}
        </>
      ) : null}
    </EuiPanel>
  );
}
