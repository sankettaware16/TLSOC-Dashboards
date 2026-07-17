/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Shared shapes for the TLSOC Overview page. The server route aggregates the agentless
 * log pipeline's output (endpoints -> Kafka -> FOSS SOC Engine -> OpenSearch) into this
 * compact view-model; the client renders it. Kept dependency-free so both sides import it.
 */

/** A single labelled count from a terms/range aggregation. */
export interface TermBucket {
  key: string;
  count: number;
}

/** One time bucket of the events-over-time chart, split by onboarded source. */
export interface TimeBucket {
  /** epoch millis at the bucket start */
  t: number;
  total: number;
  bySource: TermBucket[];
}

export interface OverviewKpis {
  eventsInWindow: number;
  /** doc counts per minute over the last 60 minutes (for the sparkline) */
  eventsPerMin: number[];
  /** events/sec derived from the most recent full minute */
  epsNow: number;
  /** distinct endpoints (observer.source_host, or host.name fallback) reporting */
  endpoints: number;
  /** true when `endpoints` came from the host.name fallback (observer.source_host absent) */
  endpointsFromHostName?: boolean;
  /** distinct log sources (observer.source_program) */
  logSources: number;
  /** distinct observer.org (tenant) values; 0 → single-tenant, tile hidden */
  orgs: number;
  /** distinct observer.dept values; 0 → tile hidden */
  depts: number;
  /** ISO timestamp of the most recent event in the window (freshness), or null */
  freshness: string | null;
  /** ingest lag p50 in ms (event.ingested − @timestamp); null when event.ingested absent */
  ingestLagP50Ms: number | null;
  /** ingest lag p95 in ms; null when event.ingested absent */
  ingestLagP95Ms: number | null;
  /**
   * Fraction (0..1) of events the engine could not time-parse (event.timestamp_source:
   * ingest_fallback). null when the field is absent in this deployment's data.
   */
  parseFallbackPct: number | null;
}

/** An onboarded asset (endpoint or log source) with first/last-seen for new/silent detection. */
export interface AssetRow {
  name: string;
  /** for log sources: the classified SIEM type; for endpoints: undefined */
  type?: string;
  firstSeen: string | null;
  lastSeen: string | null;
  events: number;
}

/** Per-source-type rollup for the breakdown donut + table. */
export interface SourceTypeBucket {
  type: string;
  label: string;
  events: number;
  sources: number;
  endpoints: number;
}

/** One time bucket with per-source-TYPE counts (events-over-time stacked by type). */
export interface TypeTimeBucket {
  t: number;
  total: number;
  byType: TermBucket[];
}

export interface RecentEvent {
  timestamp: string | null;
  sourceIp: string | null;
  sourceProgram: string | null;
  endpoint: string | null;
  category: string | null;
  kind: string | null;
  outcome: string | null;
  severity: number | null;
  status: number | null;
  path: string | null;
  user: string | null;
  ruleName: string | null;
  country: string | null;
}

export type OverviewState = 'pristine' | 'live';

/**
 * The full payload of GET /api/tlsoc/overview.
 * - state 'pristine': the log index pattern holds zero documents (brand-new SOC) -> onboarding UI.
 * - state 'live': the pattern has data. `emptyWindow` true means the selected time range is quiet
 *   (the index has data outside it) -> "widen the range" UI + `latestEventAllTime` to jump to it.
 */
export interface OverviewViewModel {
  state: OverviewState;
  /** the resolved index pattern the route queried (shown in the onboarding/FAQ copy) */
  indexPattern: string;
  window?: { from: string; to: string; interval: string; label: string };
  /** true when state==='live' but no events fell in the selected window */
  emptyWindow?: boolean;
  /** most recent @timestamp across ALL time (for the "your latest events were N ago" jump) */
  latestEventAllTime?: string | null;

  /** the filter selections echoed back (for the client to sync the filter bar) */
  filters?: {
    org?: string[];
    dept?: string[];
    env?: string[];
    endpoint?: string[];
    logSource?: string[];
  };

  kpis?: OverviewKpis;
  /** events over time, stacked by SIEM source type */
  eventsOverTime?: TypeTimeBucket[];
  /** per-source-type rollup for the breakdown donut/table */
  sourceTypes?: SourceTypeBucket[];
  /** raw programs that classified as 'other' (for the "audit other" affordance) */
  otherPrograms?: string[];
  topSourceIps?: TermBucket[];
  topEndpoints?: TermBucket[];
  topSources?: TermBucket[];
  topDepts?: TermBucket[];
  /** value lists for the filter bar */
  orgValues?: TermBucket[];
  envValues?: TermBucket[];
  httpStatusClass?: TermBucket[];
  eventOutcome?: TermBucket[];
  eventCategory?: TermBucket[];
  eventKind?: TermBucket[];
  topCountries?: TermBucket[];
  topAsns?: TermBucket[];
  recentEvents?: RecentEvent[];

  // asset-discovery (from the wide-baseline inventory search)
  newEndpoints?: AssetRow[];
  newSources?: AssetRow[];
  silentSources?: AssetRow[];
  silentEndpoints?: AssetRow[];
}

/** Time-window presets offered by the page. */
export const OVERVIEW_WINDOWS = [
  { id: '24h', label: 'Last 24 hours' },
  { id: '7d', label: 'Last 7 days' },
  { id: '30d', label: 'Last 30 days' },
  { id: '90d', label: 'Last 90 days' },
  { id: '1y', label: 'Last year' },
] as const;

export type OverviewWindowId = typeof OVERVIEW_WINDOWS[number]['id'];
// 30d by default: a SOC posture view is most useful over weeks, and it lets historical/demo data
// render immediately. Operators can narrow to 24h for a "what's happening now" view.
export const DEFAULT_OVERVIEW_WINDOW: OverviewWindowId = '30d';
