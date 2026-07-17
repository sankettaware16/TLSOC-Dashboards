/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  windowToDuration,
  resolveKeywordField,
  resolveDimensions,
  fieldPresent,
  buildFilterClauses,
  buildOverviewAggs,
  buildInventoryAggs,
  toOverviewViewModel,
  mapInventory,
  STRING_DIMENSIONS,
} from './query';

type Dims = Record<(typeof STRING_DIMENSIONS)[number], string | null>;
const allNull = (): Dims =>
  Object.fromEntries(STRING_DIMENSIONS.map((d) => [d, null])) as Dims;

describe('windowToDuration', () => {
  it('maps presets and defaults unknown to 24h', () => {
    expect(windowToDuration('24h')).toMatchObject({ from: 'now-24h', interval: '30m' });
    expect(windowToDuration('90d').interval).toBe('1d');
    expect(windowToDuration('bogus').from).toBe('now-24h');
  });
});

describe('resolveKeywordField / resolveDimensions / fieldPresent', () => {
  it('prefers a bare keyword, then .keyword, else null', () => {
    expect(resolveKeywordField({ fields: { 'observer.org': { keyword: { aggregatable: true } } } }, 'observer.org')).toBe(
      'observer.org'
    );
    expect(
      resolveKeywordField(
        { fields: { 'observer.org': { text: { aggregatable: false } }, 'observer.org.keyword': { keyword: { aggregatable: true } } } },
        'observer.org'
      )
    ).toBe('observer.org.keyword');
    expect(resolveKeywordField({ fields: {} }, 'observer.org')).toBeNull();
  });

  it('fieldPresent detects a non-string presence field', () => {
    expect(fieldPresent({ fields: { 'event.ingested': { date: { aggregatable: true } } } }, 'event.ingested')).toBe(true);
    expect(fieldPresent({ fields: {} }, 'event.ingested')).toBe(false);
  });

  it('resolveDimensions covers every declared dimension', () => {
    const dims = resolveDimensions({ fields: { 'observer.dept.keyword': { keyword: { aggregatable: true } } } });
    expect(dims['observer.dept']).toBe('observer.dept.keyword');
    STRING_DIMENSIONS.forEach((d) => expect(d in dims).toBe(true));
  });
});

describe('buildFilterClauses', () => {
  it('emits terms clauses only for resolved dims with values', () => {
    const dims = { ...allNull(), 'observer.org': 'observer.org', 'observer.dept': 'observer.dept.keyword' };
    const clauses = buildFilterClauses({ org: ['iitb'], dept: ['cse', 'ee'], env: ['prod'] }, dims);
    expect(clauses).toContainEqual({ terms: { 'observer.org': ['iitb'] } });
    expect(clauses).toContainEqual({ terms: { 'observer.dept.keyword': ['cse', 'ee'] } });
    // env has no resolved dim → no clause
    expect(clauses.find((c: any) => JSON.stringify(c).includes('env'))).toBeUndefined();
  });
});

describe('buildOverviewAggs', () => {
  const win = windowToDuration('24h');

  it('gates optional aggs on resolved dims and includes field-agnostic ones', () => {
    const dims = { ...allNull(), 'observer.source_program': 'observer.source_program.keyword', 'observer.source_host': 'observer.source_host.keyword' };
    const body = buildOverviewAggs(win, dims, false, []) as any;
    expect(body.size).toBe(0);
    expect(body.aggs.top_source_ips.terms.field).toBe('source.ip');
    expect(body.aggs.log_sources.cardinality.field).toBe('observer.source_program.keyword');
    expect(body.aggs.endpoints.cardinality.field).toBe('observer.source_host.keyword');
    expect(body.aggs.programs.terms.field).toBe('observer.source_program.keyword');
    expect(body.aggs.programs.aggs.endpoints.cardinality.field).toBe('observer.source_host.keyword');
    // gated off
    expect(body.aggs.top_countries).toBeUndefined();
    expect(body.aggs.event_category).toBeUndefined();
    expect(body.aggs.ingest_lag).toBeUndefined(); // hasIngested false
    expect(body.aggs.parse_fallback).toBeUndefined();
  });

  it('adds the ingest-lag script percentiles when event.ingested present', () => {
    const body = buildOverviewAggs(win, allNull(), true, []) as any;
    expect(body.aggs.ingest_lag.percentiles.percents).toEqual([50, 95]);
    expect(body.aggs.ingest_lag.percentiles.script.lang).toBe('painless');
  });

  it('injects filter clauses into the bool.filter alongside the time range', () => {
    const body = buildOverviewAggs(win, allNull(), false, [{ terms: { 'observer.org': ['iitb'] } }]) as any;
    expect(body.query.bool.filter).toContainEqual({ terms: { 'observer.org': ['iitb'] } });
    expect(body.query.bool.filter[0].range['@timestamp'].gte).toBe('now-24h');
  });
});

describe('buildInventoryAggs', () => {
  it('builds per-host and per-source firstSeen/lastSeen over a 30d baseline', () => {
    const dims = { ...allNull(), 'observer.source_host': 'observer.source_host', 'observer.source_program': 'observer.source_program' };
    const body = buildInventoryAggs(dims, []) as any;
    expect(body.query.bool.filter[0].range['@timestamp'].gte).toBe('now-30d');
    expect(body.aggs.hosts.terms.field).toBe('observer.source_host');
    expect(body.aggs.hosts.aggs.firstSeen.min.field).toBe('@timestamp');
    expect(body.aggs.sources.aggs.lastSeen.max.field).toBe('@timestamp');
  });
});

describe('toOverviewViewModel', () => {
  const fixture = {
    hits: { total: { value: 1000 } },
    aggregations: {
      last_60m: { per_min: { buckets: [{ key: 1, doc_count: 30 }, { key: 2, doc_count: 90 }, { key: 3, doc_count: 5 }] } },
      freshness: { value_as_string: '2026-07-16T12:00:00.000Z' },
      log_sources: { value: 40 },
      endpoints: { value: 34 },
      orgs: { value: 2 },
      depts: { value: 6 },
      ingest_lag: { values: { '50.0': 800, '95.0': 3200 } },
      parse_fallback: { doc_count: 15 },
      top_source_ips: { buckets: [{ key: '49.32.1.1', doc_count: 300 }] },
      top_endpoints: { buckets: [{ key: 'proxy-01', doc_count: 500 }] },
      programs: {
        buckets: [
          { key: 'nginx_app_moodle', doc_count: 400, endpoints: { value: 1 } },
          { key: 'squid', doc_count: 300, endpoints: { value: 3 } },
          { key: 'suricata', doc_count: 50, endpoints: { value: 1 } },
        ],
      },
      event_outcome: { buckets: [{ key: 'success', doc_count: 700 }, { key: 'failure', doc_count: 300 }] },
      event_category: { buckets: [{ key: 'web', doc_count: 700 }, { key: 'authentication', doc_count: 300 }] },
      http_status_class: { buckets: [{ key: '2xx', doc_count: 800 }, { key: '5xx', doc_count: 0 }] },
      top_countries: { buckets: [{ key: 'India', doc_count: 650 }] },
      top_asns: { buckets: [{ key: 'Jio', doc_count: 400 }] },
      events_over_time: {
        buckets: [
          { key: 1000, doc_count: 100, by_source: { buckets: [{ key: 'nginx_app_moodle', doc_count: 60 }, { key: 'squid', doc_count: 40 }] } },
        ],
      },
      recent_events: {
        hits: { hits: [{ _source: { '@timestamp': '2026-07-16T12:00:00Z', source: { ip: '1.2.3.4' }, observer: { source_program: 'suricata', source_host: 'ids-01' }, event: { category: ['network', 'intrusion_detection'], kind: 'alert', severity: 3 }, rule: { name: 'ET SCAN Nmap' } } }] },
      },
    },
  };

  it('computes KPIs, folds programs to types, stacks events-over-time by type', () => {
    const vm = toOverviewViewModel(fixture, 1000);
    expect(vm.kpis.endpoints).toBe(34);
    expect(vm.kpis.logSources).toBe(40);
    expect(vm.kpis.orgs).toBe(2);
    expect(vm.kpis.ingestLagP50Ms).toBe(800);
    expect(vm.kpis.ingestLagP95Ms).toBe(3200);
    expect(vm.kpis.parseFallbackPct).toBeCloseTo(0.015);
    expect(vm.kpis.epsNow).toBe(1.5); // last full minute 90 / 60
    // source types: web-app(400) + web-proxy(300) + ids(50)
    const types = Object.fromEntries(vm.sourceTypes.map((t) => [t.type, t.events]));
    expect(types['web-app']).toBe(400);
    expect(types['web-proxy']).toBe(300);
    expect(types.ids).toBe(50);
    // over-time bucket folded to types
    const byType = Object.fromEntries(vm.eventsOverTime[0].byType.map((b) => [b.key, b.count]));
    expect(byType['web-app']).toBe(60);
    expect(byType['web-proxy']).toBe(40);
    // recent event flattened incl. array category joined
    expect(vm.recentEvents[0]).toMatchObject({ endpoint: 'ids-01', kind: 'alert', severity: 3, ruleName: 'ET SCAN Nmap', category: 'network, intrusion_detection' });
    expect(vm.httpStatusClass.map((b) => b.key)).toEqual(['2xx']); // 0-count 5xx dropped
  });

  it('reports null lag/parse when aggs absent and survives empty aggregations', () => {
    const vm = toOverviewViewModel({ hits: { total: { value: 0 } }, aggregations: {} }, 0);
    expect(vm.kpis.ingestLagP50Ms).toBeNull();
    expect(vm.kpis.parseFallbackPct).toBeNull();
    expect(vm.kpis.endpoints).toBe(0);
    expect(vm.sourceTypes).toEqual([]);
    expect(vm.eventsOverTime).toEqual([]);
    expect(vm.recentEvents).toEqual([]);
  });
});

describe('mapInventory', () => {
  const now = Date.parse('2026-07-16T12:00:00Z');
  const hoursAgo = (h: number) => new Date(now - h * 3600 * 1000).getTime();
  const body = {
    aggregations: {
      hosts: {
        buckets: [
          { key: 'proxy-01', doc_count: 5000, firstSeen: { value: hoursAgo(300) }, lastSeen: { value: hoursAgo(1) } },
          { key: 'edr-mgr-01', doc_count: 40, firstSeen: { value: hoursAgo(18) }, lastSeen: { value: hoursAgo(1) } }, // NEW
          { key: 'proxy-07', doc_count: 2000, firstSeen: { value: hoursAgo(300) }, lastSeen: { value: hoursAgo(96) } }, // SILENT (4d)
        ],
      },
      sources: {
        buckets: [
          { key: 'suricata', doc_count: 100, firstSeen: { value: hoursAgo(300) }, lastSeen: { value: hoursAgo(2) } }, // silent thresh ids=1h → 2h ago = silent
          { key: 'nginx_app_grievance', doc_count: 20, firstSeen: { value: hoursAgo(6) }, lastSeen: { value: hoursAgo(1) } }, // NEW
        ],
      },
    },
  };

  it('flags new (first-seen <24h) and silent (per-type stale) assets', () => {
    const inv = mapInventory(body, now);
    expect(inv.newEndpoints.map((r) => r.name)).toContain('edr-mgr-01');
    expect(inv.newSources.map((r) => r.name)).toContain('nginx_app_grievance');
    expect(inv.silentEndpoints.map((r) => r.name)).toContain('proxy-07');
    // suricata classified ids (1h threshold), last seen 2h ago → silent
    expect(inv.silentSources.map((r) => r.name)).toContain('suricata');
    // a brand-new source is not also flagged silent
    expect(inv.silentSources.map((r) => r.name)).not.toContain('nginx_app_grievance');
  });
});
