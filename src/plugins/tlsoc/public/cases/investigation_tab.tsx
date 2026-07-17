/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiCode,
  EuiDescriptionList,
  EuiFieldSearch,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart, getTime } from '../../../data/public';
import {
  buildEvidenceFilter,
  deriveEvidence,
  deriveInvestigationScope,
  planColumns,
} from '../../common/investigation';
import { findDataViewForIndex } from '../../common/investigation/dv_match';
import { HydratedAlert } from './use_cases';

/** PROB-2: request-scoped bootstrap of the agentless pipeline's data view(s) — see server/routes/data_views.ts. */
async function ensureDataViews(core: CoreStart): Promise<void> {
  await core.http.post('/api/tlsoc/data_views/_ensure', {
    body: JSON.stringify({ perEndpoint: true }),
  });
}

interface Props {
  core: CoreStart;
  data: DataPublicPluginStart;
  /** The case's hydrated linked alerts — drive the index + the INITIAL time window the grid is scoped to. */
  alerts: HydratedAlert[];
  alertsLoading: boolean;
}

interface ResultRow {
  id: string;
  summary: string; // used only by the fallback "Document" column (no fields selected)
  hit: any; // raw hit — cells are formatted on the fly so add/remove column needs no re-fetch
}

interface QueryValue {
  query: string;
  language: string;
}

const PAGE_SIZE = 50;
/** index.max_result_window — from+size beyond this errors; deep paging (search_after) is out of scope. */
const MAX_PAGEABLE = 10000;
/** Meta fields excluded from the addable column picker (but KEPT in row expansion — useful there). */
const META_FIELDS = new Set(['_id', '_index', '_score', '_type', '_source']);

/** Compact one-line summary of a hit's _source for the fallback "Document" column (no fields selected). */
function summarize(source: any): string {
  if (!source || typeof source !== 'object') return String(source ?? '');
  const s = JSON.stringify(source);
  return s.length > 200 ? `${s.slice(0, 200)}…` : s;
}

/** Format one field of a hit via the SAFE 'text' content type (never the default 'html' → no markup leak). */
function fmt(dv: any, hit: any, field: string): string {
  try {
    return String(dv.formatField(hit, field, 'text'));
  } catch {
    return String(hit?._source?.[field] ?? '');
  }
}

/** The expanded full document: EVERY flattened field (incl. meta _id/_index) formatted via 'text'. */
function ExpandedDoc({ dv, hit }: { dv: any; hit: any }) {
  const items = useMemo(() => {
    let flat: Record<string, any> = {};
    try {
      flat = dv.flattenHit(hit); // includes meta fields — intentionally kept in expansion
    } catch {
      flat = hit?._source ?? {};
    }
    return Object.keys(flat)
      .sort()
      .map((field) => ({ title: field, description: fmt(dv, hit, field) }));
  }, [dv, hit]);

  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="s" style={{ width: '100%' }}>
      <EuiDescriptionList type="column" compressed textStyle="reverse" listItems={items} style={{ maxWidth: '100%' }} />
    </EuiPanel>
  );
}

export function InvestigationTab({ core, data, alerts, alertsLoading }: Props) {
  const scope = useMemo(() => deriveInvestigationScope(alerts, Date.now()), [alerts]);
  // PROB-17: scope the grid to the ACTUAL evidence behind the case's linked alerts (doc ids +
  // bucket group-scopes), not just the whole derived time window.
  const evidence = useMemo(() => deriveEvidence(alerts), [alerts]);
  const evidenceFilter = useMemo(() => buildEvidenceFilter(evidence), [evidence]);

  const SearchBar = data.ui.SearchBar as any;
  const I18nContext = core.i18n.Context;

  const [dv, setDv] = useState<any>(null);
  const [dvStatus, setDvStatus] = useState<'loading' | 'ready' | 'no-dv'>('loading');
  const [allFields, setAllFields] = useState<string[]>([]); // addable fields (meta excluded), sorted
  const [selectedFields, setSelectedFields] = useState<string[]>([]); // _source columns the analyst shows
  const [fieldFilter, setFieldFilter] = useState('');
  const [query, setQuery] = useState<QueryValue>({ query: '', language: 'kuery' });
  const [timeRange, setTimeRange] = useState<{ from: string; to: string }>(scope.timeRange);
  const [pageIndex, setPageIndex] = useState(0);
  const [rows, setRows] = useState<ResultRow[]>([]);
  const [total, setTotal] = useState(0);
  const [fetchStatus, setFetchStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [errMsg, setErrMsg] = useState('');
  const [queriedWindow, setQueriedWindow] = useState<{ from: string; to: string } | null>(null);
  const [expandedRows, setExpandedRows] = useState<Record<string, ReactNode>>({});
  // Default ON whenever there's evidence to scope to; re-derived once (per mount) after alerts
  // hydrate, mirroring the `seeded` pattern below — afterwards the analyst owns the toggle.
  const [scopedToEvidence, setScopedToEvidence] = useState(true);
  const evidenceSeeded = useRef(false);
  const seeded = useRef(false);
  const colsInitialized = useRef(false);
  // PROB-2 self-heal: try the automatic ensure-and-retry at most ONCE per mount (avoid looping
  // when ensure genuinely can't produce a matching view — e.g. the index truly has no data yet).
  const autoEnsureAttempted = useRef(false);
  const [retryTick, setRetryTick] = useState(0);
  const [manualEnsureLoading, setManualEnsureLoading] = useState(false);
  const [manualEnsureError, setManualEnsureError] = useState<string | null>(null);

  // Seed the time picker to the case window once alerts hydrate; afterwards the analyst owns it.
  useEffect(() => {
    if (!alertsLoading && !seeded.current) {
      setTimeRange(scope.timeRange);
      seeded.current = true;
    }
  }, [alertsLoading, scope]);

  // Seed the evidence-scope toggle once alerts hydrate (ON iff there's evidence); afterwards the
  // analyst owns it via the "Show full window" / "Scope to linked alerts" buttons below.
  useEffect(() => {
    if (!alertsLoading && !evidenceSeeded.current) {
      setScopedToEvidence(evidenceFilter != null);
      evidenceSeeded.current = true;
    }
  }, [alertsLoading, evidenceFilter]);

  // Resolve the case's index → data view; enumerate addable fields; seed the INITIAL columns from planColumns.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (alertsLoading) return;
      if (!scope.index) {
        if (!cancelled) setDvStatus('no-dv');
        return;
      }
      setDvStatus('loading');
      try {
        const ids = await data.dataViews.getIdsWithTitle();
        let match = findDataViewForIndex(ids, scope.index);
        // PROB-2 self-heal: on a miss, try ensuring the data view(s) ONCE, then re-resolve
        // against a force-refreshed id list. Best-effort — a failed ensure just falls through
        // to the existing no-dv callout (which now also offers a manual retry, below).
        if (!match && !autoEnsureAttempted.current) {
          autoEnsureAttempted.current = true;
          try {
            await ensureDataViews(core);
          } catch {
            // best-effort; fall through to the no-match handling below
          }
          if (cancelled) return;
          const refreshedIds = await data.dataViews.getIdsWithTitle(true);
          match = findDataViewForIndex(refreshedIds, scope.index);
        }
        if (!match) {
          if (!cancelled) {
            setDv(null);
            setDvStatus('no-dv');
          }
          return;
        }
        const resolved = await data.dataViews.get(match.id);
        if (cancelled) return;
        // `.getAll()` first — data view `.fields` is an Array subclass (the known gotcha).
        const names: string[] = resolved.fields.getAll().map((f: any) => f.name);
        const addable = names.filter((n) => !META_FIELDS.has(n)).sort();
        setAllFields(addable);
        // planColumns is the sensible INITIAL default; the picker layers on top of it.
        if (!colsInitialized.current) {
          setSelectedFields(planColumns(names).fields);
          colsInitialized.current = true;
        }
        setDv(resolved);
        setDvStatus('ready');
      } catch (e) {
        if (!cancelled) {
          setErrMsg(e instanceof Error ? e.message : String(e));
          setDvStatus('no-dv');
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // retryTick: bumped by the "Create data view" button below to force a re-resolve once its
    // own ensure call has already force-refreshed the data-view cache.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, core, scope.index, alertsLoading, retryTick]);

  // Re-fetch on data view / time / query / page change. NOT on column change — cells format from the cached
  // hit, so adding/removing a column is instant (no re-fetch).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!dv) return;
      setFetchStatus('loading');
      try {
        const tf = dv.timeFieldName;
        const ss = data.search.searchSource.createEmpty();
        ss.setField('index', dv);
        ss.setField('size', PAGE_SIZE);
        ss.setField('from', pageIndex * PAGE_SIZE);
        ss.setField('query', query as any);
        const timeFilter = tf ? getTime(dv, timeRange) : undefined;
        ss.setField('filter', [
          ...(timeFilter ? [timeFilter as any] : []),
          ...(scopedToEvidence && evidenceFilter ? [evidenceFilter as any] : []),
        ]);
        if (tf) ss.setField('sort', [{ [tf]: 'desc' }] as any);

        const resp: any = await ss.fetch();
        if (cancelled) return;

        const hits: any[] = resp?.hits?.hits ?? [];
        const t = resp?.hits?.total;
        const totalVal = typeof t === 'number' ? t : t?.value ?? hits.length;

        setRows(hits.map((h) => ({ id: h._id, summary: summarize(h._source), hit: h })));
        setTotal(totalVal);
        setQueriedWindow({ from: timeRange.from, to: timeRange.to });
        setExpandedRows({});
        // eslint-disable-next-line no-console
        console.log('[investigate] fetched', {
          window: { from: timeRange.from, to: timeRange.to },
          query: query.query,
          page: pageIndex,
          total: totalVal,
        });
        setFetchStatus('ready');
      } catch (e) {
        if (cancelled) return;
        setErrMsg(e instanceof Error ? e.message : String(e));
        setFetchStatus('error');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [dv, timeRange, query, pageIndex, data, scopedToEvidence, evidenceFilter]);

  const onQuerySubmit = (payload: any) => {
    if (payload?.query) setQuery(payload.query);
    if (payload?.dateRange) setTimeRange(payload.dateRange);
    setPageIndex(0);
  };

  // Manual "Create data view" retry (PROB-2): explicit, always attempted on click (not gated by
  // autoEnsureAttempted — that ref only guards the ONE automatic try). Force-refreshes the
  // data-view cache, then bumps retryTick so the resolve effect above re-matches against it.
  const handleCreateDataView = async () => {
    setManualEnsureLoading(true);
    setManualEnsureError(null);
    try {
      await ensureDataViews(core);
      await data.dataViews.getIdsWithTitle(true);
      setRetryTick((t) => t + 1);
    } catch (e) {
      setManualEnsureError(e instanceof Error ? e.message : String(e));
    } finally {
      setManualEnsureLoading(false);
    }
  };

  const addField = (field: string) =>
    setSelectedFields((prev) => (prev.includes(field) ? prev : [...prev, field]));
  const removeField = (field: string) =>
    setSelectedFields((prev) => prev.filter((f) => f !== field));

  const toggleExpand = (row: ResultRow) => {
    setExpandedRows((prev) => {
      const next = { ...prev };
      if (next[row.id]) delete next[row.id];
      else next[row.id] = <ExpandedDoc dv={dv} hit={row.hit} />;
      return next;
    });
  };

  const tf = dv?.timeFieldName as string | undefined;
  const selectedSet = useMemo(() => new Set(selectedFields), [selectedFields]);
  const filteredFields = useMemo(() => {
    const q = fieldFilter.trim().toLowerCase();
    return q ? allFields.filter((f) => f.toLowerCase().includes(q)) : allFields;
  }, [allFields, fieldFilter]);

  const columns: Array<EuiBasicTableColumn<ResultRow>> = useMemo(() => {
    const cols: Array<EuiBasicTableColumn<ResultRow>> = [
      {
        width: '40px',
        isExpander: true,
        render: (row: ResultRow) => (
          <EuiButtonIcon
            onClick={() => toggleExpand(row)}
            aria-label={expandedRows[row.id] ? 'Collapse' : 'Expand'}
            iconType={expandedRows[row.id] ? 'arrowDown' : 'arrowRight'}
          />
        ),
      },
    ];
    if (tf) cols.push({ name: 'Time', width: '210px', render: (row: ResultRow) => (dv ? fmt(dv, row.hit, tf) : '—') });
    for (const f of selectedFields) {
      cols.push({
        name: (
          <EuiFlexGroup gutterSize="xs" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>{f}</EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonIcon
                iconType="cross"
                color="text"
                aria-label={`Remove column ${f}`}
                onClick={() => removeField(f)}
              />
            </EuiFlexItem>
          </EuiFlexGroup>
        ),
        render: (row: ResultRow) => (dv ? fmt(dv, row.hit, f) || '—' : '—'),
      });
    }
    if (selectedFields.length === 0) {
      cols.push({
        name: 'Document',
        render: (row: ResultRow) => (
          <EuiText size="xs" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontFamily: 'monospace' }}>
            {row.summary}
          </EuiText>
        ),
      });
    }
    return cols;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tf, selectedFields, expandedRows, dv]);

  const showLoading = alertsLoading || dvStatus === 'loading';
  const pageStart = pageIndex * PAGE_SIZE;
  const cappedTotal = Math.min(total, MAX_PAGEABLE);

  const fieldsSidebar = (
    <EuiPanel hasBorder hasShadow={false} paddingSize="s" style={{ width: 240 }}>
      <EuiText size="xs"><strong>Fields</strong></EuiText>
      <EuiSpacer size="xs" />
      <EuiFieldSearch
        compressed
        placeholder="Filter fields"
        value={fieldFilter}
        onChange={(e) => setFieldFilter(e.target.value)}
        aria-label="Filter fields"
      />
      <EuiSpacer size="xs" />
      <div style={{ maxHeight: 460, overflowY: 'auto' }}>
        {filteredFields.map((f) => {
          const selected = selectedSet.has(f);
          return (
            <EuiFlexGroup key={f} gutterSize="xs" alignItems="center" responsive={false} style={{ margin: 0 }}>
              <EuiFlexItem grow={false}>
                <EuiButtonIcon
                  iconType={selected ? 'cross' : 'plusInCircle'}
                  color={selected ? 'danger' : 'primary'}
                  aria-label={selected ? `Remove column ${f}` : `Add column ${f}`}
                  onClick={() => (selected ? removeField(f) : addField(f))}
                />
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiText size="xs" style={{ wordBreak: 'break-all', fontWeight: selected ? 600 : 400 }}>
                  {f}
                </EuiText>
              </EuiFlexItem>
            </EuiFlexGroup>
          );
        })}
        {filteredFields.length === 0 ? (
          <EuiText size="xs" color="subdued"><p>No matching fields.</p></EuiText>
        ) : null}
      </div>
    </EuiPanel>
  );

  return (
    <I18nContext>
      <EuiSpacer size="m" />
      <EuiPanel hasBorder hasShadow={false}>
        <EuiFlexGroup alignItems="baseline" gutterSize="s" wrap responsive={false}>
          <EuiFlexItem grow={false}>
            <EuiTitle size="s">
              <h2>Investigate</h2>
            </EuiTitle>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiText size="xs" color="subdued">
              {scope.index ? (
                <span>
                  index <EuiCode>{scope.index}</EuiCode> · scoped from this case&rsquo;s alerts (adjust the
                  time/query/columns freely)
                </span>
              ) : (
                <span>no index resolved from this case&rsquo;s alerts</span>
              )}
            </EuiText>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="m" />

        {dvStatus === 'ready' && dv ? (
          <>
            <SearchBar
              appName="tlsoc-investigate"
              indexPatterns={[dv]}
              query={query}
              dateRangeFrom={timeRange.from}
              dateRangeTo={timeRange.to}
              showQueryInput={true}
              showDatePicker={true}
              showFilterBar={false}
              showSaveQuery={false}
              onQuerySubmit={onQuerySubmit}
            />
            <EuiSpacer size="m" />
          </>
        ) : null}

        {evidenceFilter ? (
          <>
            <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
              <EuiFlexItem grow={false}>
                {scopedToEvidence ? (
                  <EuiBadge color="hollow">
                    Scoped to the evidence behind this case&rsquo;s {alerts.length} linked alert
                    {alerts.length === 1 ? '' : 's'}
                  </EuiBadge>
                ) : (
                  <EuiText size="xs" color="subdued">
                    Showing the full time window
                  </EuiText>
                )}
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                {scopedToEvidence ? (
                  <EuiButtonEmpty
                    size="xs"
                    onClick={() => {
                      setScopedToEvidence(false);
                      setPageIndex(0);
                    }}
                  >
                    Show full window
                  </EuiButtonEmpty>
                ) : (
                  <EuiButtonEmpty
                    size="xs"
                    onClick={() => {
                      setScopedToEvidence(true);
                      setPageIndex(0);
                    }}
                  >
                    Scope to linked alerts
                  </EuiButtonEmpty>
                )}
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="s" />
          </>
        ) : null}

        {showLoading ? (
          <EuiFlexGroup gutterSize="s" alignItems="center">
            <EuiFlexItem grow={false}>
              <EuiLoadingSpinner size="m" />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="s">Loading events…</EuiText>
            </EuiFlexItem>
          </EuiFlexGroup>
        ) : dvStatus === 'no-dv' ? (
          <EuiCallOut color="warning" iconType="help" title="No data view for this case's index — inline investigation unavailable">
            <p>
              {scope.index
                ? `Create a data view for "${scope.index}" to investigate inline, or use "Investigate in Discover" from the alert.`
                : `This case has no linked alert with a known index. Use "Investigate in Discover" from an alert.`}
            </p>
            {scope.index ? (
              <>
                <EuiButton size="s" isLoading={manualEnsureLoading} onClick={handleCreateDataView}>
                  Create data view
                </EuiButton>
                {manualEnsureError ? (
                  <>
                    <EuiSpacer size="s" />
                    <EuiText size="xs" color="danger">
                      <p>Could not create the data view: {manualEnsureError}</p>
                    </EuiText>
                  </>
                ) : null}
              </>
            ) : null}
          </EuiCallOut>
        ) : (
          <EuiFlexGroup gutterSize="m" responsive={false} alignItems="flexStart">
            <EuiFlexItem grow={false}>{fieldsSidebar}</EuiFlexItem>
            <EuiFlexItem>
              {fetchStatus === 'loading' ? (
                <EuiFlexGroup gutterSize="s" alignItems="center">
                  <EuiFlexItem grow={false}>
                    <EuiLoadingSpinner size="m" />
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiText size="s">Searching…</EuiText>
                  </EuiFlexItem>
                </EuiFlexGroup>
              ) : fetchStatus === 'error' ? (
                <EuiCallOut color="danger" iconType="alert" title="Could not load events">
                  <p>{errMsg}</p>
                </EuiCallOut>
              ) : rows.length === 0 ? (
                <EuiText size="s" color="subdued">
                  <p>No events match this query and time window.</p>
                </EuiText>
              ) : (
                <>
                  <EuiText size="xs" color="subdued">
                    <p>
                      Showing {pageStart + 1}–{pageStart + rows.length} of {total.toLocaleString()} event(s).
                      {queriedWindow ? (
                        <>
                          {' '}
                          Queried window: <EuiCode>{queriedWindow.from}</EuiCode> →{' '}
                          <EuiCode>{queriedWindow.to}</EuiCode>.
                        </>
                      ) : null}
                      {total > MAX_PAGEABLE ? (
                        <>
                          {' '}
                          Paging covers the first {MAX_PAGEABLE.toLocaleString()} events — narrow the query or
                          time range to reach the rest.
                        </>
                      ) : null}
                    </p>
                  </EuiText>
                  <EuiSpacer size="s" />
                  <EuiBasicTable
                    items={rows}
                    columns={columns}
                    tableLayout="fixed"
                    itemId="id"
                    itemIdToExpandedRowMap={expandedRows}
                    isExpandable={true}
                    pagination={{
                      pageIndex,
                      pageSize: PAGE_SIZE,
                      totalItemCount: cappedTotal,
                      hidePerPageOptions: true,
                    }}
                    onChange={({ page }: any) => {
                      if (page) setPageIndex(page.index);
                    }}
                  />
                </>
              )}
            </EuiFlexItem>
          </EuiFlexGroup>
        )}
      </EuiPanel>
    </I18nContext>
  );
}
