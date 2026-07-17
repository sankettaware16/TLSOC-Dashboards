/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TLSOC Security Logs sample dataset — bundled saved objects (structure mirrors the stock
 * home-plugin sample datasets). The index-pattern `fields` string was captured from a live
 * `_fields_for_wildcard` call against an index created with ./field_mappings.ts (38 specs) —
 * NEVER ship an empty fields cache (the 5a.1c empty-field-cache lesson: it kills the Discover
 * histogram and spawns the sticky "index-pattern-field" toast).
 *
 * The overview dashboard is deliberately rich (13 panels, human-directed at the sub-task-B gate:
 * "this dataset and dashboards should actually impress") — intro/story markdown, KPI metrics,
 * attack-story pie, auth + HTTP timelines, top talkers, country heatmap, geo map, and the two
 * seeded-attack tables. It opens time-restored to the last 7 days so the seeded stories are
 * always in view after install.
 */

import { i18n } from '@osd/i18n';
import { SavedObject } from 'opensearch-dashboards/server';

export const PATTERN_ID = 'tlsoc-security-sample-pattern';
export const DASHBOARD_ID = 'tlsoc-security-sample-overview';
const VIS = {
  markdown: 'tlsoc-security-sample-vis-markdown',
  totalEvents: 'tlsoc-security-sample-vis-total-events',
  uniqueIps: 'tlsoc-security-sample-vis-unique-ips',
  authFailures: 'tlsoc-security-sample-vis-auth-failures',
  storyPie: 'tlsoc-security-sample-vis-story-pie',
  authArea: 'tlsoc-security-sample-vis-events',
  httpLine: 'tlsoc-security-sample-vis-http-line',
  topIps: 'tlsoc-security-sample-vis-topips',
  countryHeatmap: 'tlsoc-security-sample-vis-country-heatmap',
  categoryDonut: 'tlsoc-security-sample-vis-category-donut',
  geoMap: 'tlsoc-security-sample-vis-geo-map',
  scannerTable: 'tlsoc-security-sample-vis-scanner-table',
  targetedAccounts: 'tlsoc-security-sample-vis-targeted-accounts',
};

const FIELDS_JSON = '[{"name":"@timestamp","type":"date","esTypes":["date"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"_id","type":"string","esTypes":["_id"],"searchable":true,"aggregatable":true,"readFromDocValues":false},{"name":"_index","type":"string","esTypes":["_index"],"searchable":true,"aggregatable":true,"readFromDocValues":false},{"name":"_score","type":"number","searchable":false,"aggregatable":false,"readFromDocValues":false},{"name":"_source","type":"_source","esTypes":["_source"],"searchable":false,"aggregatable":false,"readFromDocValues":false},{"name":"_type","type":"string","searchable":false,"aggregatable":false,"readFromDocValues":false},{"name":"destination.ip","type":"ip","esTypes":["ip"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"destination.port","type":"number","esTypes":["long"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"event.action","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"event.category","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"event.dataset","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"event.kind","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"event.module","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"event.outcome","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"host.name","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"http.request.method","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"http.request.referrer","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"http.response.body.bytes","type":"number","esTypes":["long"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"http.response.status_code","type":"number","esTypes":["long"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"message","type":"string","esTypes":["text"],"searchable":true,"aggregatable":false,"readFromDocValues":false},{"name":"network.protocol","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"network.transport","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"observer.product","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"observer.vendor","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"process.name","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"source.geo.city_name","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"source.geo.country_iso_code","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"source.geo.country_name","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"source.geo.location","type":"geo_point","esTypes":["geo_point"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"source.ip","type":"ip","esTypes":["ip"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"source.port","type":"number","esTypes":["long"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"tlsoc.story","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"url.original","type":"string","esTypes":["text"],"searchable":true,"aggregatable":false,"readFromDocValues":false},{"name":"url.original.keyword","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true,"subType":{"multi":{"parent":"url.original"}}},{"name":"url.path","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"user.name","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true},{"name":"user_agent.original","type":"string","esTypes":["text"],"searchable":true,"aggregatable":false,"readFromDocValues":false},{"name":"user_agent.original.keyword","type":"string","esTypes":["keyword"],"searchable":true,"aggregatable":true,"readFromDocValues":true,"subType":{"multi":{"parent":"user_agent.original"}}}]';

const searchSource = (query = '') =>
  `{"index":"${PATTERN_ID}","filter":[],"query":{"query":"${query}","language":"kuery"}}`;

const vis = (
  id: string,
  title: string,
  visState: Record<string, unknown>,
  query = '',
  migrationVersion: Record<string, string> = {}
): SavedObject => ({
  id,
  type: 'visualization',
  updated_at: '2026-07-15T00:00:00.000Z',
  version: '1',
  migrationVersion,
  attributes: {
    title,
    visState: JSON.stringify({ title, ...visState }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: { searchSourceJSON: searchSource(query) },
  },
  references: [],
});

const metricVis = (field?: string) => ({
  type: 'metric',
  params: {
    addTooltip: true,
    addLegend: false,
    type: 'metric',
    metric: {
      percentageMode: false,
      useRanges: false,
      colorSchema: 'Green to Red',
      metricColorMode: 'None',
      colorsRange: [{ from: 0, to: 10000 }],
      labels: { show: true },
      invertColors: false,
      style: { bgFill: '#000', bgColor: false, labelColor: false, subText: '', fontSize: 42 },
    },
  },
  aggs: [
    field
      ? { id: '1', enabled: true, type: 'cardinality', schema: 'metric', params: { field } }
      : { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
  ],
});

const MARKDOWN_TEXT = [
  '### TLSOC Security Logs — sample telemetry',
  '',
  'Seven days of ECS-formatted **SSH authentication** and **web proxy** events, with two seeded attacks:',
  '',
  '- **Brute force** — `203.0.113.66` fires ~400 failed SSH logins in 15 minutes against `bastion-01`, then one success.',
  '- **Web scanner** — `198.51.100.23` probes 70 distinct paths (404s) within an hour on `web-01`.',
  '',
  'Try it:',
  '',
  '- Filter `tlsoc.story: brute-force` in **Investigations** to isolate the attack.',
  '- Build a no-code detection in **Detections**: _more than 100 failed logins within 15 minutes grouped by `source.ip`_ — then Test it over the burst window.',
  '- Every aggregation field is properly typed (`ip`, `geo_point`, `keyword`).',
].join('\\n');

export const getSavedObjects = (): SavedObject[] => [
  {
    id: PATTERN_ID,
    type: 'index-pattern',
    updated_at: '2026-07-15T00:00:00.000Z',
    version: '1',
    migrationVersion: {},
    attributes: {
      title: 'opensearch_dashboards_sample_data_tlsoc-security',
      timeFieldName: '@timestamp',
      fields: FIELDS_JSON,
    },
    references: [],
  },

  {
    id: VIS.markdown,
    type: 'visualization',
    updated_at: '2026-07-15T00:00:00.000Z',
    version: '1',
    migrationVersion: {},
    attributes: {
      title: i18n.translate('tlsoc.sampleData.securityLogs.introTitle', {
        defaultMessage: '[TLSOC Sample] About this data',
      }),
      visState: `{"title":"[TLSOC Sample] About this data","type":"markdown","params":{"fontSize":12,"openLinksInNewTab":false,"markdown":"${MARKDOWN_TEXT}"},"aggs":[]}`,
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: '{"query":{"query":"","language":"kuery"},"filter":[]}',
      },
    },
    references: [],
  },

  vis(
    VIS.totalEvents,
    i18n.translate('tlsoc.sampleData.securityLogs.totalEventsTitle', {
      defaultMessage: '[TLSOC Sample] Total Events',
    }),
    metricVis()
  ),
  vis(
    VIS.uniqueIps,
    i18n.translate('tlsoc.sampleData.securityLogs.uniqueIpsTitle', {
      defaultMessage: '[TLSOC Sample] Unique Source IPs',
    }),
    metricVis('source.ip')
  ),
  vis(
    VIS.authFailures,
    i18n.translate('tlsoc.sampleData.securityLogs.authFailuresTitle', {
      defaultMessage: '[TLSOC Sample] Failed Logins',
    }),
    metricVis(),
    'event.category:authentication and event.outcome:failure'
  ),

  vis(
    VIS.storyPie,
    i18n.translate('tlsoc.sampleData.securityLogs.storyPieTitle', {
      defaultMessage: '[TLSOC Sample] Seeded Attack Events',
    }),
    {
      type: 'pie',
      params: {
        type: 'pie',
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        isDonut: true,
        labels: { show: true, values: true, last_level: true, truncate: 100 },
      },
      aggs: [
        { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
        {
          id: '2',
          enabled: true,
          type: 'terms',
          schema: 'segment',
          params: { field: 'tlsoc.story', size: 5, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing' },
        },
      ],
    },
    'not tlsoc.story:background'
  ),

  vis(
    VIS.authArea,
    i18n.translate('tlsoc.sampleData.securityLogs.eventsOverTimeTitle', {
      defaultMessage: '[TLSOC Sample] Authentication Outcomes over Time',
    }),
    {
      type: 'area',
      params: {
        type: 'area',
        grid: { categoryLines: false },
        categoryAxes: [
          { id: 'CategoryAxis-1', type: 'category', position: 'bottom', show: true, style: {}, scale: { type: 'linear' }, labels: { show: true, truncate: 100 }, title: {} },
        ],
        valueAxes: [
          { id: 'ValueAxis-1', name: 'LeftAxis-1', type: 'value', position: 'left', show: true, style: {}, scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 }, title: { text: 'Logins' } },
        ],
        seriesParams: [
          { show: true, type: 'area', mode: 'stacked', data: { label: 'Logins', id: '1' }, drawLinesBetweenPoints: true, showCircles: false, interpolate: 'linear', valueAxis: 'ValueAxis-1' },
        ],
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false,
      },
      aggs: [
        { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
        { id: '2', enabled: true, type: 'date_histogram', schema: 'segment', params: { field: '@timestamp', interval: 'auto', min_doc_count: 1, extended_bounds: {} } },
        { id: '3', enabled: true, type: 'terms', schema: 'group', params: { field: 'event.outcome', size: 5, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing' } },
      ],
    },
    'event.category:authentication'
  ),

  vis(
    VIS.httpLine,
    i18n.translate('tlsoc.sampleData.securityLogs.httpLineTitle', {
      defaultMessage: '[TLSOC Sample] HTTP Responses over Time',
    }),
    {
      type: 'line',
      params: {
        type: 'line',
        grid: { categoryLines: false },
        categoryAxes: [
          { id: 'CategoryAxis-1', type: 'category', position: 'bottom', show: true, style: {}, scale: { type: 'linear' }, labels: { show: true, truncate: 100 }, title: {} },
        ],
        valueAxes: [
          { id: 'ValueAxis-1', name: 'LeftAxis-1', type: 'value', position: 'left', show: true, style: {}, scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 }, title: { text: 'Requests' } },
        ],
        seriesParams: [
          { show: true, type: 'line', mode: 'normal', data: { label: 'Requests', id: '1' }, drawLinesBetweenPoints: true, showCircles: true, interpolate: 'linear', valueAxis: 'ValueAxis-1' },
        ],
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false,
      },
      aggs: [
        { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
        { id: '2', enabled: true, type: 'date_histogram', schema: 'segment', params: { field: '@timestamp', interval: 'auto', min_doc_count: 1, extended_bounds: {} } },
        { id: '3', enabled: true, type: 'terms', schema: 'group', params: { field: 'http.response.status_code', size: 6, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing' } },
      ],
    },
    'event.category:web'
  ),

  vis(
    VIS.topIps,
    i18n.translate('tlsoc.sampleData.securityLogs.topSourceIpsTitle', {
      defaultMessage: '[TLSOC Sample] Top Source IPs',
    }),
    {
      type: 'horizontal_bar',
      params: {
        type: 'histogram',
        grid: { categoryLines: false },
        categoryAxes: [
          { id: 'CategoryAxis-1', type: 'category', position: 'left', show: true, style: {}, scale: { type: 'linear' }, labels: { show: true, rotate: 0, filter: false, truncate: 200 }, title: {} },
        ],
        valueAxes: [
          { id: 'ValueAxis-1', name: 'BottomAxis-1', type: 'value', position: 'bottom', show: true, style: {}, scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 75, filter: true, truncate: 100 }, title: { text: 'Events' } },
        ],
        seriesParams: [
          { show: true, type: 'histogram', mode: 'normal', data: { label: 'Events', id: '1' }, valueAxis: 'ValueAxis-1', drawLinesBetweenPoints: true, showCircles: true },
        ],
        addTooltip: true,
        addLegend: false,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false,
      },
      aggs: [
        { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
        { id: '2', enabled: true, type: 'terms', schema: 'segment', params: { field: 'source.ip', size: 10, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing' } },
      ],
    }
  ),

  vis(
    VIS.countryHeatmap,
    i18n.translate('tlsoc.sampleData.securityLogs.countryHeatmapTitle', {
      defaultMessage: '[TLSOC Sample] Outcomes by Source Country',
    }),
    {
      type: 'heatmap',
      params: {
        type: 'heatmap',
        addTooltip: true,
        addLegend: true,
        enableHover: true,
        legendPosition: 'right',
        times: [],
        colorsNumber: 6,
        colorSchema: 'Reds',
        setColorRange: false,
        colorsRange: [],
        invertColors: false,
        percentageMode: false,
        valueAxes: [
          { show: false, id: 'ValueAxis-1', type: 'value', scale: { type: 'linear', defaultYExtents: false }, labels: { show: false, rotate: 0, color: '#555', overwriteColor: false } },
        ],
      },
      aggs: [
        { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
        { id: '2', enabled: true, type: 'terms', schema: 'segment', params: { field: 'source.geo.country_iso_code', size: 8, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing', customLabel: 'Source Country' } },
        { id: '3', enabled: true, type: 'terms', schema: 'group', params: { field: 'event.outcome', size: 3, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing', customLabel: 'Outcome' } },
      ],
    }
  ),

  vis(
    VIS.categoryDonut,
    i18n.translate('tlsoc.sampleData.securityLogs.categoryDonutTitle', {
      defaultMessage: '[TLSOC Sample] Events by Category',
    }),
    {
      type: 'pie',
      params: {
        type: 'pie',
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        isDonut: true,
        labels: { show: false, values: true, last_level: true, truncate: 100 },
      },
      aggs: [
        { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
        { id: '2', enabled: true, type: 'terms', schema: 'segment', params: { field: 'event.category', size: 5, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing' } },
        { id: '3', enabled: true, type: 'terms', schema: 'segment', params: { field: 'event.outcome', size: 3, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing' } },
      ],
    }
  ),

  vis(
    VIS.geoMap,
    i18n.translate('tlsoc.sampleData.securityLogs.geoMapTitle', {
      defaultMessage: '[TLSOC Sample] Event Origins',
    }),
    {
      type: 'tile_map',
      aggs: [
        { id: '1', enabled: true, type: 'count', params: {}, schema: 'metric' },
        { id: '2', enabled: true, type: 'geohash_grid', params: { field: 'source.geo.location', autoPrecision: true, precision: 2, useGeocentroid: true, isFilteredByCollar: true }, schema: 'segment' },
      ],
      params: {
        colorSchema: 'Yellow to Red',
        mapType: 'Scaled Circle Markers',
        isDesaturated: true,
        addTooltip: true,
        heatClusterSize: 1.5,
        legendPosition: 'bottomright',
        mapZoom: 2,
        mapCenter: [0, 0],
        wms: {
          enabled: false,
          url: '',
          options: { version: '', layers: '', format: 'image/png', transparent: true, attribution: '', styles: '' },
          selectedTmsLayer: { origin: 'elastic_maps_service', id: 'road_map', minZoom: 0, maxZoom: 14, attribution: '<a rel="noreferrer noopener" href="https://www.openstreetmap.org/copyright">Map data © OpenStreetMap contributors</a>' },
        },
      },
    },
    '',
    { visualization: '7.10.0' }
  ),

  vis(
    VIS.scannerTable,
    i18n.translate('tlsoc.sampleData.securityLogs.scannerTableTitle', {
      defaultMessage: '[TLSOC Sample] Top 404 Paths (Web Scanner)',
    }),
    {
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: { columnIndex: null, direction: null },
        showTotal: false,
        totalFunc: 'sum',
        percentageCol: '',
      },
      aggs: [
        { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
        { id: '2', enabled: true, type: 'terms', schema: 'bucket', params: { field: 'url.path', size: 10, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing', customLabel: 'Probed path' } },
        { id: '3', enabled: true, type: 'terms', schema: 'bucket', params: { field: 'source.ip', size: 3, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing', customLabel: 'Source IP' } },
      ],
    },
    'http.response.status_code:404'
  ),

  vis(
    VIS.targetedAccounts,
    i18n.translate('tlsoc.sampleData.securityLogs.targetedAccountsTitle', {
      defaultMessage: '[TLSOC Sample] Most-Targeted Accounts',
    }),
    {
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: { columnIndex: null, direction: null },
        showTotal: false,
        totalFunc: 'sum',
        percentageCol: '',
      },
      aggs: [
        { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
        { id: '2', enabled: true, type: 'terms', schema: 'bucket', params: { field: 'user.name', size: 10, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing', customLabel: 'Account' } },
        { id: '3', enabled: true, type: 'terms', schema: 'bucket', params: { field: 'host.name', size: 3, order: 'desc', orderBy: '1', otherBucket: false, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing', customLabel: 'Host' } },
      ],
    },
    'event.category:authentication and event.outcome:failure'
  ),

  {
    id: DASHBOARD_ID,
    type: 'dashboard',
    updated_at: '2026-07-15T00:00:00.000Z',
    version: '1',
    migrationVersion: {},
    attributes: {
      title: i18n.translate('tlsoc.sampleData.securityLogs.dashboardTitle', {
        defaultMessage: '[TLSOC Sample] Security Overview',
      }),
      hits: 0,
      description: i18n.translate('tlsoc.sampleData.securityLogs.dashboardDescription', {
        defaultMessage:
          'Security overview of the TLSOC Security Logs sample data — authentication and web telemetry with two seeded attacks (SSH brute force, web scanner).',
      }),
      panelsJSON: JSON.stringify([
        { version: '3.0.0', gridData: { x: 0, y: 0, w: 12, h: 12, i: 'p1' }, panelIndex: 'p1', embeddableConfig: { hidePanelTitles: true }, panelRefName: 'panel_0' },
        { version: '3.0.0', gridData: { x: 12, y: 0, w: 9, h: 6, i: 'p2' }, panelIndex: 'p2', embeddableConfig: {}, panelRefName: 'panel_1' },
        { version: '3.0.0', gridData: { x: 21, y: 0, w: 9, h: 6, i: 'p3' }, panelIndex: 'p3', embeddableConfig: {}, panelRefName: 'panel_2' },
        { version: '3.0.0', gridData: { x: 12, y: 6, w: 18, h: 6, i: 'p4' }, panelIndex: 'p4', embeddableConfig: {}, panelRefName: 'panel_3' },
        { version: '3.0.0', gridData: { x: 30, y: 0, w: 18, h: 12, i: 'p5' }, panelIndex: 'p5', embeddableConfig: {}, panelRefName: 'panel_4' },
        { version: '3.0.0', gridData: { x: 0, y: 12, w: 24, h: 14, i: 'p6' }, panelIndex: 'p6', embeddableConfig: {}, panelRefName: 'panel_5' },
        { version: '3.0.0', gridData: { x: 24, y: 12, w: 24, h: 14, i: 'p7' }, panelIndex: 'p7', embeddableConfig: {}, panelRefName: 'panel_6' },
        { version: '3.0.0', gridData: { x: 0, y: 26, w: 16, h: 14, i: 'p8' }, panelIndex: 'p8', embeddableConfig: {}, panelRefName: 'panel_7' },
        { version: '3.0.0', gridData: { x: 16, y: 26, w: 16, h: 14, i: 'p9' }, panelIndex: 'p9', embeddableConfig: {}, panelRefName: 'panel_8' },
        { version: '3.0.0', gridData: { x: 32, y: 26, w: 16, h: 14, i: 'p10' }, panelIndex: 'p10', embeddableConfig: {}, panelRefName: 'panel_9' },
        { version: '3.0.0', gridData: { x: 0, y: 40, w: 24, h: 16, i: 'p11' }, panelIndex: 'p11', embeddableConfig: {}, panelRefName: 'panel_10' },
        { version: '3.0.0', gridData: { x: 24, y: 40, w: 12, h: 16, i: 'p12' }, panelIndex: 'p12', embeddableConfig: {}, panelRefName: 'panel_11' },
        { version: '3.0.0', gridData: { x: 36, y: 40, w: 12, h: 16, i: 'p13' }, panelIndex: 'p13', embeddableConfig: {}, panelRefName: 'panel_12' },
      ]),
      optionsJSON: '{"hidePanelTitles":false,"useMargins":true}',
      version: 1,
      timeRestore: true,
      timeTo: 'now',
      timeFrom: 'now-7d',
      refreshInterval: { pause: true, value: 0 },
      kibanaSavedObjectMeta: {
        searchSourceJSON: '{"query":{"language":"kuery","query":""},"filter":[]}',
      },
    },
    references: [
      { id: VIS.markdown, name: 'panel_0', type: 'visualization' },
      { id: VIS.totalEvents, name: 'panel_1', type: 'visualization' },
      { id: VIS.uniqueIps, name: 'panel_2', type: 'visualization' },
      { id: VIS.authFailures, name: 'panel_3', type: 'visualization' },
      { id: VIS.storyPie, name: 'panel_4', type: 'visualization' },
      { id: VIS.authArea, name: 'panel_5', type: 'visualization' },
      { id: VIS.httpLine, name: 'panel_6', type: 'visualization' },
      { id: VIS.topIps, name: 'panel_7', type: 'visualization' },
      { id: VIS.countryHeatmap, name: 'panel_8', type: 'visualization' },
      { id: VIS.categoryDonut, name: 'panel_9', type: 'visualization' },
      { id: VIS.geoMap, name: 'panel_10', type: 'visualization' },
      { id: VIS.scannerTable, name: 'panel_11', type: 'visualization' },
      { id: VIS.targetedAccounts, name: 'panel_12', type: 'visualization' },
    ],
  },
];
