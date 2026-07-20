/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from 'react';
import {
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiCallOut,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart, getTime } from '../../../data/public';
import {
  formatDqlTranslationErrors,
  translateDqlToLucene,
} from '../../common/detection/dql_to_lucene';
import type { CustomQueryLanguage } from '../../common/detection/custom_query';

/**
 * The 'search-sample' preview panel for D2 custom-query rules: From/To window (default: the last
 * hour) + "Test query" → total hit count + the first 10 matching documents.
 *
 * WHY a plain search and not a monitor dry-run: doc-level `_execute?dryrun=true` is broken AND
 * deceptive on OpenSearch 3.7 (usually NPEs; the rare "success" scans nothing because doc-level
 * runs checkpoint from now — research_r3 §4). A plain search over the compiled query IS the
 * honest preview. It reuses `data.search.searchSource`, the exact client-side search primitive
 * the investigation grid uses — no new server route.
 *
 * FAITHFUL-TO-EXECUTION: for DQL rules the preview runs the TRANSLATED Lucene (the very string
 * the saved monitor will run), not native DQL — so what fires here is what fires in production,
 * and a subset-rejected query previews as its rejection instead of silently previewing semantics
 * the doc-level monitor can't have.
 */
export interface CustomQueryPreviewProps {
  core?: CoreStart;
  data?: DataPublicPluginStart;
  /** The selected data view's id (resolved for time field, formatting, and the search). */
  dataViewId?: string;
  language?: CustomQueryLanguage;
  queryText?: string;
}

interface PreviewRow {
  id: string;
  hit: any;
}

const SAMPLE_SIZE = 10;

/** Twin of investigation_tab.tsx `fmt`: format via the SAFE 'text' content type (no markup leak). */
function fmt(dv: any, hit: any, field: string): string {
  try {
    return String(dv.formatField(hit, field, 'text'));
  } catch {
    return String(hit?._source?.[field] ?? '');
  }
}

/** Twin of investigation_tab.tsx `summarize`: compact one-line _source for the Document column. */
function summarize(source: any): string {
  if (!source || typeof source !== 'object') return String(source ?? '');
  const s = JSON.stringify(source);
  return s.length > 200 ? `${s.slice(0, 200)}…` : s;
}

export function CustomQueryPreview({
  core,
  data,
  dataViewId,
  language = 'kuery',
  queryText = '',
}: CustomQueryPreviewProps) {
  const [from, setFrom] = useState('now-1h');
  const [to, setTo] = useState('now');
  const [dv, setDv] = useState<any>(null);
  const [dvError, setDvError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ total: number; rows: PreviewRow[] } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setDv(null);
    setDvError(null);
    if (!data || !dataViewId) return;
    (async () => {
      try {
        const resolved = await data.dataViews.get(dataViewId);
        if (!cancelled) setDv(resolved);
      } catch (e) {
        if (!cancelled) setDvError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [data, dataViewId]);

  // A changed query invalidates a previous sample.
  useEffect(() => {
    setResult(null);
    setError(null);
  }, [queryText, language]);

  const onTest = async () => {
    if (!data || !dv) return;
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      // Compile exactly what the saved monitor will run (see the docblock).
      let lucene = queryText.trim();
      if (language === 'kuery') {
        const translated = translateDqlToLucene(queryText);
        if (!translated.ok) {
          setError(formatDqlTranslationErrors(translated.errors));
          return;
        }
        lucene = translated.lucene;
      }

      const tf = dv.timeFieldName as string | undefined;
      const ss = data.search.searchSource.createEmpty();
      ss.setField('index', dv);
      ss.setField('size', SAMPLE_SIZE);
      ss.setField('query', { query: lucene, language: 'lucene' } as any);
      const timeFilter = tf ? getTime(dv, { from, to }) : undefined;
      ss.setField('filter', timeFilter ? [timeFilter as any] : []);
      if (tf) ss.setField('sort', [{ [tf]: 'desc' }] as any);

      const resp: any = await ss.fetch();
      const hits: any[] = resp?.hits?.hits ?? [];
      const t = resp?.hits?.total;
      const total = typeof t === 'number' ? t : t?.value ?? hits.length;
      setResult({ total, rows: hits.map((h) => ({ id: h._id, hit: h })) });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  };

  const tf = dv?.timeFieldName as string | undefined;
  const columns: Array<EuiBasicTableColumn<PreviewRow>> = [
    ...(tf
      ? [
          {
            name: 'Time',
            width: '210px',
            render: (row: PreviewRow) => fmt(dv, row.hit, tf),
          } as EuiBasicTableColumn<PreviewRow>,
        ]
      : []),
    {
      name: 'Document',
      render: (row: PreviewRow) => (
        <EuiText
          size="xs"
          style={{
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            margin: 0,
            fontFamily: 'monospace',
          }}
        >
          {summarize(row.hit?._source)}
        </EuiText>
      ),
    },
  ];

  const canTest = !!data && !!dv && queryText.trim() !== '' && !running;

  return (
    <EuiPanel hasShadow={false} hasBorder>
      <EuiTitle size="xs">
        <h2>Test this rule</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiText size="s" color="subdued">
        <p>
          Runs the exact compiled query as a plain search over the time window below and shows what
          it matches — doc-level monitors can’t be dry-run unsaved on OpenSearch 3.7, so this search
          IS the honest preview. Nothing is saved. The saved rule evaluates newly indexed documents
          from the moment it is created.
        </p>
      </EuiText>
      <EuiSpacer size="s" />

      {!core || !data ? (
        <EuiCallOut
          color="warning"
          iconType="iInCircle"
          title="The preview panel is not wired up yet"
        >
          <p>
            The builder must pass its core/data services and the query form state to this panel (D2
            serial integration).
          </p>
        </EuiCallOut>
      ) : !dataViewId ? (
        <EuiCallOut color="primary" iconType="iInCircle" title="Select a data view first." />
      ) : dvError ? (
        <EuiCallOut color="danger" iconType="alert" title="Could not load the data view">
          <p>{dvError}</p>
        </EuiCallOut>
      ) : (
        <>
          <EuiFlexGroup>
            <EuiFlexItem>
              <EuiFormRow
                label="From"
                helpText="Date math (now-1h) or ISO 8601. Default: the last hour."
              >
                <EuiFieldText value={from} onChange={(e) => setFrom(e.target.value)} />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow label="To">
                <EuiFieldText value={to} onChange={(e) => setTo(e.target.value)} />
              </EuiFormRow>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="s" />
          <EuiButton
            fill
            iconType="play"
            onClick={onTest}
            isLoading={running}
            isDisabled={!canTest}
          >
            Test query
          </EuiButton>

          {error ? (
            <>
              <EuiSpacer size="m" />
              <EuiCallOut color="danger" iconType="alert" title="The query did not run">
                <EuiText size="s" style={{ whiteSpace: 'pre-wrap' }}>
                  <p>{error}</p>
                </EuiText>
              </EuiCallOut>
            </>
          ) : null}

          {result ? (
            <>
              <EuiSpacer size="m" />
              {result.total > 0 ? (
                <>
                  <EuiText size="s">
                    <p>
                      {result.total.toLocaleString()} matching event(s) in this window
                      {result.total > result.rows.length
                        ? ` — showing the first ${result.rows.length}`
                        : ''}
                      .
                    </p>
                  </EuiText>
                  <EuiSpacer size="s" />
                  <EuiBasicTable
                    items={result.rows}
                    columns={columns}
                    tableLayout="fixed"
                    itemId="id"
                  />
                </>
              ) : (
                <EuiCallOut
                  color="primary"
                  iconType="iInCircle"
                  title="No events match this query in this window."
                />
              )}
            </>
          ) : null}
        </>
      )}
    </EuiPanel>
  );
}
