/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure query helpers for the SIEM-cockpit Overview route: window→duration, mapping-aware keyword
 * resolution (works on templateless text+.keyword AND template-backed keyword indices), the main
 * coverage/health aggregation body, the wide-baseline inventory body (new/silent asset detection),
 * the filter-clause builder, and the response→view-model mappers. No I/O so it is unit-testable.
 */

import {
  AssetRow,
  OverviewKpis,
  RecentEvent,
  SourceTypeBucket,
  TermBucket,
  TypeTimeBucket,
} from '../../common/overview/types';
import { classifySource, foldProgramsToTypes } from '../../common/overview/source_types';

export interface ResolvedWindow {
  from: string;
  to: string;
  interval: string;
  label: string;
}

const WINDOW_TABLE: Record<string, ResolvedWindow> = {
  '24h': { from: 'now-24h', to: 'now', interval: '30m', label: 'Last 24 hours' },
  '7d': { from: 'now-7d', to: 'now', interval: '3h', label: 'Last 7 days' },
  '30d': { from: 'now-30d', to: 'now', interval: '12h', label: 'Last 30 days' },
  '90d': { from: 'now-90d', to: 'now', interval: '1d', label: 'Last 90 days' },
  '1y': { from: 'now-1y', to: 'now', interval: '1w', label: 'Last year' },
};

/** Map a window preset id to a date range + histogram interval. Unknown → 24h. */
export function windowToDuration(window: string | undefined): ResolvedWindow {
  return WINDOW_TABLE[window ?? ''] ?? WINDOW_TABLE['24h'];
}

/**
 * String dimensions resolved to their aggregatable form via _field_caps (keyword directly, or the
 * `.keyword` sub-field of a text field). Numeric/ip/date fields are NOT here.
 */
export const STRING_DIMENSIONS = [
  'observer.source_program',
  'observer.source_host',
  'observer.server',
  'observer.org',
  'observer.dept',
  'observer.env',
  'event.timestamp_source',
  'event.outcome',
  'event.category',
  'event.kind',
  'source.geo.country_name',
  'source.as.organization.name',
  'host.name',
] as const;

export type StringDimension = typeof STRING_DIMENSIONS[number];

/** Date/other fields whose mere presence gates a widget (not aggregated as terms). */
export const PRESENCE_FIELDS = ['event.ingested'] as const;

type FieldCaps = { fields?: Record<string, Record<string, { aggregatable?: boolean }>> } | undefined;

/**
 * Return the aggregatable field name for `base`, or null if neither `base` nor `<base>.keyword` is
 * an aggregatable keyword in the data.
 */
export function resolveKeywordField(fieldCaps: FieldCaps, base: string): string | null {
  const fields = fieldCaps?.fields ?? {};
  const isAggKeyword = (name: string): boolean => {
    const caps = fields[name];
    return !!caps && caps.keyword?.aggregatable === true;
  };
  if (isAggKeyword(base)) return base;
  const dotted = `${base}.keyword`;
  if (isAggKeyword(dotted)) return dotted;
  return null;
}

export function resolveDimensions(fieldCaps: FieldCaps): Record<StringDimension, string | null> {
  const out = {} as Record<StringDimension, string | null>;
  for (const dim of STRING_DIMENSIONS) out[dim] = resolveKeywordField(fieldCaps, dim);
  return out;
}

/** Whether a presence-gated field (e.g. event.ingested) exists at all in the data. */
export function fieldPresent(fieldCaps: FieldCaps, name: string): boolean {
  return !!fieldCaps?.fields?.[name];
}

/** All fields to request from _field_caps (string dims + their .keyword forms + presence fields). */
export function fieldCapsFields(): string[] {
  const out: string[] = [...PRESENCE_FIELDS];
  for (const dim of STRING_DIMENSIONS) out.push(dim, `${dim}.keyword`);
  return out;
}

export interface OverviewFilters {
  org?: string[];
  dept?: string[];
  env?: string[];
  endpoint?: string[];
  logSource?: string[];
}

/** Build bool.filter term clauses from the filter bar, keyed on the resolved dimension fields. */
export function buildFilterClauses(
  filters: OverviewFilters,
  dims: Record<StringDimension, string | null>
): Array<Record<string, unknown>> {
  const clauses: Array<Record<string, unknown>> = [];
  const add = (dim: StringDimension, values?: string[]) => {
    const field = dims[dim];
    if (field && values && values.length) clauses.push({ terms: { [field]: values } });
  };
  add('observer.org', filters.org);
  add('observer.dept', filters.dept);
  add('observer.env', filters.env);
  add('observer.source_host', filters.endpoint);
  add('observer.source_program', filters.logSource);
  return clauses;
}

const INGEST_LAG_SCRIPT =
  "long ing = doc['event.ingested'].value.toInstant().toEpochMilli(); " +
  "long evt = doc['@timestamp'].value.toInstant().toEpochMilli(); " +
  'long d = ing - evt; return d < 0 ? 0 : d;';

/**
 * The main size:0 coverage/health aggregation body. `dims` maps each string dimension to its
 * resolved field (or null → skip). `hasIngested` gates the ingest-lag script agg. `filterClauses`
 * scope every panel. Optional aggs are omitted when their dimension is unresolved so the body
 * adapts to whatever the deployment's data contains.
 */
export function buildOverviewAggs(
  win: ResolvedWindow,
  dims: Record<StringDimension, string | null>,
  hasIngested: boolean,
  filterClauses: Array<Record<string, unknown>>
): Record<string, unknown> {
  const src = dims['observer.source_program'];
  const host = dims['observer.source_host'];
  const aggs: Record<string, unknown> = {
    // ingest-heartbeat sparkline (per-minute, last 60m)
    last_60m: {
      filter: { range: { '@timestamp': { gte: 'now-60m' } } },
      aggs: { per_min: { date_histogram: { field: '@timestamp', fixed_interval: '1m', min_doc_count: 0 } } },
    },
    freshness: { max: { field: '@timestamp' } },
    // coverage cardinalities
    log_sources: src ? { cardinality: { field: src } } : undefined,
    endpoints: host ? { cardinality: { field: host } } : undefined,
    endpoints_hostname: dims['host.name'] ? { cardinality: { field: dims['host.name'] } } : undefined,
    orgs: dims['observer.org'] ? { cardinality: { field: dims['observer.org'] } } : undefined,
    depts: dims['observer.dept'] ? { cardinality: { field: dims['observer.dept'] } } : undefined,
    // top talkers
    top_source_ips: { terms: { field: 'source.ip', size: 10 } },
    top_endpoints: host ? { terms: { field: host, size: 10 } } : undefined,
    top_sources: src ? { terms: { field: src, size: 10 } } : undefined,
    top_depts: dims['observer.dept'] ? { terms: { field: dims['observer.dept'], size: 10 } } : undefined,
    // value lists for the filter bar (small, exhaustive for these low-cardinality dims)
    org_values: dims['observer.org'] ? { terms: { field: dims['observer.org'], size: 50 } } : undefined,
    env_values: dims['observer.env'] ? { terms: { field: dims['observer.env'], size: 20 } } : undefined,
    // source-type breakdown: raw programs (folded to types client-side) + endpoints per program
    programs: src
      ? {
          terms: { field: src, size: 200 },
          ...(host ? { aggs: { endpoints: { cardinality: { field: host } } } } : {}),
        }
      : undefined,
    // events over time with per-program split (folded to type in the mapper)
    events_over_time: {
      date_histogram: { field: '@timestamp', fixed_interval: win.interval, min_doc_count: 0 },
      ...(src ? { aggs: { by_source: { terms: { field: src, size: 40 } } } } : {}),
    },
    // outcome + ECS semantics
    event_outcome: dims['event.outcome'] ? { terms: { field: dims['event.outcome'], size: 6 } } : undefined,
    event_category: dims['event.category'] ? { terms: { field: dims['event.category'], size: 12 } } : undefined,
    event_kind: dims['event.kind'] ? { terms: { field: dims['event.kind'], size: 8 } } : undefined,
    // http status classes (works on web/proxy data)
    http_status_class: {
      range: {
        field: 'http.response.status_code',
        ranges: [
          { key: '2xx', from: 200, to: 300 },
          { key: '3xx', from: 300, to: 400 },
          { key: '4xx', from: 400, to: 500 },
          { key: '5xx', from: 500, to: 600 },
        ],
      },
    },
    // geo + ASN
    top_countries: dims['source.geo.country_name']
      ? { terms: { field: dims['source.geo.country_name'], size: 12 } }
      : undefined,
    top_asns: dims['source.as.organization.name']
      ? { terms: { field: dims['source.as.organization.name'], size: 10 } }
      : undefined,
    // parse health
    parse_fallback: dims['event.timestamp_source']
      ? { filter: { term: { [dims['event.timestamp_source']!]: 'ingest_fallback' } } }
      : undefined,
    // ingest lag percentiles (script) — gated on event.ingested present
    ingest_lag: hasIngested
      ? { percentiles: { percents: [50, 95], script: { lang: 'painless', source: INGEST_LAG_SCRIPT } } }
      : undefined,
    // recent events
    recent_events: {
      top_hits: {
        size: 25,
        sort: [{ '@timestamp': 'desc' }],
        _source: [
          '@timestamp',
          'source.ip',
          'observer.source_program',
          'observer.source_host',
          'event.category',
          'event.kind',
          'event.outcome',
          'event.severity',
          'http.response.status_code',
          'url.path',
          'user.name',
          'rule.name',
          'source.geo.country_name',
        ],
      },
    },
  };
  // strip undefined aggs
  for (const k of Object.keys(aggs)) if (aggs[k] === undefined) delete aggs[k];

  return {
    size: 0,
    track_total_hits: true,
    query: { bool: { filter: [{ range: { '@timestamp': { gte: win.from, lte: win.to } } }, ...filterClauses] } },
    aggs,
  };
}

/**
 * Wide-baseline inventory body for new/silent asset detection. Runs over a fixed 30d range
 * (independent of the dashboard window) but applies the non-time filters. Returns per-endpoint
 * and per-source firstSeen/lastSeen/volume.
 */
export function buildInventoryAggs(
  dims: Record<StringDimension, string | null>,
  filterClauses: Array<Record<string, unknown>>
): Record<string, unknown> {
  const host = dims['observer.source_host'];
  const src = dims['observer.source_program'];
  const perTerm = { firstSeen: { min: { field: '@timestamp' } }, lastSeen: { max: { field: '@timestamp' } } };
  const aggs: Record<string, unknown> = {};
  if (host) aggs.hosts = { terms: { field: host, size: 500 }, aggs: perTerm };
  if (src) aggs.sources = { terms: { field: src, size: 500 }, aggs: perTerm };
  return {
    size: 0,
    query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-30d' } } }, ...filterClauses] } },
    aggs,
  };
}

// ---- response mapping ------------------------------------------------------

interface RawBucket {
  key: string | number;
  key_as_string?: string;
  doc_count: number;
}

function buckets(agg: unknown): RawBucket[] {
  const b = (agg as { buckets?: RawBucket[] } | undefined)?.buckets;
  return Array.isArray(b) ? b : [];
}

function toTermBuckets(agg: unknown): TermBucket[] {
  return buckets(agg).map((b) => ({ key: String(b.key), count: b.doc_count }));
}

function flatSource(source: Record<string, any>, dotted: string): unknown {
  if (source[dotted] !== undefined) return source[dotted];
  return dotted.split('.').reduce<any>((cur, part) => (cur == null ? cur : cur[part]), source);
}

/** Map the main _search response into the cockpit view-model fragment. */
export function toOverviewViewModel(
  body: any,
  total: number
): {
  kpis: OverviewKpis;
  eventsOverTime: TypeTimeBucket[];
  sourceTypes: SourceTypeBucket[];
  otherPrograms: string[];
  topSourceIps: TermBucket[];
  topEndpoints?: TermBucket[];
  topSources?: TermBucket[];
  topDepts?: TermBucket[];
  orgValues?: TermBucket[];
  envValues?: TermBucket[];
  eventOutcome?: TermBucket[];
  eventCategory?: TermBucket[];
  eventKind?: TermBucket[];
  httpStatusClass: TermBucket[];
  topCountries?: TermBucket[];
  topAsns?: TermBucket[];
  recentEvents: RecentEvent[];
} {
  const aggs = body?.aggregations ?? {};

  const perMin = buckets(aggs.last_60m?.per_min).map((b) => b.doc_count);
  const lastFullMinute = perMin.length >= 2 ? perMin[perMin.length - 2] : 0;

  const ingestValues = aggs.ingest_lag?.values;
  const parseFallbackPct =
    aggs.parse_fallback && total > 0 ? (aggs.parse_fallback.doc_count ?? 0) / total : aggs.parse_fallback ? 0 : null;

  const endpointsCard = aggs.endpoints?.value;
  const endpointsFromHostName = endpointsCard === undefined && aggs.endpoints_hostname?.value !== undefined;

  const kpis: OverviewKpis = {
    eventsInWindow: total,
    eventsPerMin: perMin,
    epsNow: Math.round((lastFullMinute / 60) * 100) / 100,
    endpoints: endpointsCard ?? aggs.endpoints_hostname?.value ?? 0,
    endpointsFromHostName,
    logSources: aggs.log_sources?.value ?? 0,
    orgs: aggs.orgs?.value ?? 0,
    depts: aggs.depts?.value ?? 0,
    freshness: aggs.freshness?.value_as_string ?? null,
    ingestLagP50Ms: ingestValues ? Math.round(ingestValues['50.0'] ?? ingestValues['50']) : null,
    ingestLagP95Ms: ingestValues ? Math.round(ingestValues['95.0'] ?? ingestValues['95']) : null,
    parseFallbackPct,
  };

  // fold programs → source types
  const programBuckets = buckets(aggs.programs).map((b) => ({
    program: String(b.key),
    events: b.doc_count,
    endpoints: (b as any).endpoints?.value ?? 0,
  }));
  const { byType, otherPrograms } = foldProgramsToTypes(programBuckets);

  // events over time, folded to type per bucket
  const eventsOverTime: TypeTimeBucket[] = buckets(aggs.events_over_time).map((b) => {
    const byTypeMap = new Map<string, number>();
    for (const s of buckets((b as any).by_source)) {
      const t = classifySource(String(s.key));
      byTypeMap.set(t, (byTypeMap.get(t) ?? 0) + s.doc_count);
    }
    return {
      t: typeof b.key === 'number' ? b.key : Number(b.key),
      total: b.doc_count,
      byType: Array.from(byTypeMap.entries()).map(([key, count]) => ({ key, count })),
    };
  });

  const recentEvents: RecentEvent[] = ((aggs.recent_events?.hits?.hits ?? []) as Array<{ _source: Record<string, any> }>).map(
    (hit) => {
      const s = hit._source ?? {};
      const cat = flatSource(s, 'event.category');
      return {
        timestamp: (flatSource(s, '@timestamp') as string) ?? null,
        sourceIp: (flatSource(s, 'source.ip') as string) ?? null,
        sourceProgram: (flatSource(s, 'observer.source_program') as string) ?? null,
        endpoint: (flatSource(s, 'observer.source_host') as string) ?? null,
        category: Array.isArray(cat) ? cat.join(', ') : ((cat as string) ?? null),
        kind: (flatSource(s, 'event.kind') as string) ?? null,
        outcome: (flatSource(s, 'event.outcome') as string) ?? null,
        severity: (flatSource(s, 'event.severity') as number) ?? null,
        status: (flatSource(s, 'http.response.status_code') as number) ?? null,
        path: (flatSource(s, 'url.path') as string) ?? null,
        user: (flatSource(s, 'user.name') as string) ?? null,
        ruleName: (flatSource(s, 'rule.name') as string) ?? null,
        country: (flatSource(s, 'source.geo.country_name') as string) ?? null,
      };
    }
  );

  return {
    kpis,
    eventsOverTime,
    sourceTypes: byType,
    otherPrograms,
    topSourceIps: toTermBuckets(aggs.top_source_ips),
    topEndpoints: aggs.top_endpoints ? toTermBuckets(aggs.top_endpoints) : undefined,
    topSources: aggs.top_sources ? toTermBuckets(aggs.top_sources) : undefined,
    topDepts: aggs.top_depts ? toTermBuckets(aggs.top_depts) : undefined,
    orgValues: aggs.org_values ? toTermBuckets(aggs.org_values) : undefined,
    envValues: aggs.env_values ? toTermBuckets(aggs.env_values) : undefined,
    eventOutcome: aggs.event_outcome ? toTermBuckets(aggs.event_outcome) : undefined,
    eventCategory: aggs.event_category ? toTermBuckets(aggs.event_category) : undefined,
    eventKind: aggs.event_kind ? toTermBuckets(aggs.event_kind) : undefined,
    httpStatusClass: toTermBuckets(aggs.http_status_class).filter((b) => b.count > 0),
    topCountries: aggs.top_countries ? toTermBuckets(aggs.top_countries) : undefined,
    topAsns: aggs.top_asns ? toTermBuckets(aggs.top_asns) : undefined,
    recentEvents,
  };
}

/**
 * Map the inventory response into new/silent asset lists. `nowMs` is injected for testability.
 * New = firstSeen within 24h; silent = lastSeen older than the per-type threshold.
 */
export function mapInventory(
  body: any,
  nowMs: number
): { newEndpoints: AssetRow[]; newSources: AssetRow[]; silentSources: AssetRow[]; silentEndpoints: AssetRow[] } {
  const aggs = body?.aggregations ?? {};
  const H = 3600 * 1000;
  const NEW_MS = 24 * H;

  // per-type silence threshold (hours) — an IDS silent 30m is an outage; an ERP batch 12h is normal
  const SILENT_H: Record<string, number> = {
    ids: 1,
    firewall: 1,
    auth: 2,
    'web-proxy': 2,
    'web-app': 2,
    webmail: 3,
    mail: 3,
    edr: 2,
    dns: 2,
    erp: 24,
    other: 12,
  };

  const rowsFrom = (agg: unknown, withType: boolean): AssetRow[] =>
    buckets(agg).map((b) => {
      const first = (b as any).firstSeen?.value ?? null;
      const last = (b as any).lastSeen?.value ?? null;
      return {
        name: String(b.key),
        type: withType ? classifySource(String(b.key)) : undefined,
        firstSeen: first ? new Date(first).toISOString() : null,
        lastSeen: last ? new Date(last).toISOString() : null,
        events: b.doc_count,
      };
    });

  const sources = rowsFrom(aggs.sources, true);
  const hosts = rowsFrom(aggs.hosts, false);

  const isNew = (r: AssetRow) => r.firstSeen != null && Date.parse(r.firstSeen) >= nowMs - NEW_MS;
  const silentThreshMs = (r: AssetRow) => (SILENT_H[r.type ?? 'other'] ?? 12) * H;
  const isSilent = (r: AssetRow) =>
    r.lastSeen != null && Date.parse(r.lastSeen) < nowMs - silentThreshMs(r) && !isNew(r);

  return {
    newSources: sources.filter(isNew).sort((a, b) => Date.parse(b.firstSeen!) - Date.parse(a.firstSeen!)),
    newEndpoints: hosts.filter(isNew).sort((a, b) => Date.parse(b.firstSeen!) - Date.parse(a.firstSeen!)),
    silentSources: sources.filter(isSilent).sort((a, b) => Date.parse(a.lastSeen!) - Date.parse(b.lastSeen!)),
    silentEndpoints: hosts.filter((r) => r.lastSeen != null && Date.parse(r.lastSeen) < nowMs - 6 * H && !isNew(r)),
  };
}
