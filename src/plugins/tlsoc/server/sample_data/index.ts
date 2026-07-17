/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * "TLSOC Security Logs" sample dataset — registered into the home plugin's sample-data registry
 * from TLSOC's own plugin (zero home-plugin edits; see the interlude-task plan, 2026-07-15).
 * Structure mirrors the stock providers in home/server/services/sample_data/data_sets/*.
 */

import path from 'path';
import { i18n } from '@osd/i18n';
import { SampleDatasetSchema } from '../../../home/server/services/sample_data/lib/sample_dataset_registry_types';
import {
  appendDataSourceId,
  getSavedObjectsWithDataSource,
  overwriteSavedObjectsWithWorkspaceId,
} from '../../../home/server/services/sample_data/data_sets';
import { fieldMappings } from './field_mappings';
import { getSavedObjects, PATTERN_ID, DASHBOARD_ID } from './saved_objects';

export const tlsocSecurityLogsSpecProvider = function (): SampleDatasetSchema {
  return {
    id: 'tlsoc-security',
    name: i18n.translate('tlsoc.sampleData.securityLogs.name', {
      defaultMessage: 'TLSOC Security Logs',
    }),
    description: i18n.translate('tlsoc.sampleData.securityLogs.description', {
      defaultMessage:
        'ECS-compliant multi-source SIEM telemetry — web apps, proxies, firewalls, email, SSH/PAM ' +
        'auth, IDS/WAF, DNS, an ERP, and an EDR — across a simulated campus estate, with seeded ' +
        'brute-force and WAF/IDS attack stories, for testing TLSOC detections, investigations, and visualizations.',
    }),
    previewImagePath: '/plugins/tlsoc/assets/sample_data_resources/security_logs/dashboard.svg',
    darkPreviewImagePath:
      '/plugins/tlsoc/assets/sample_data_resources/security_logs/dashboard_dark.svg',
    overviewDashboard: DASHBOARD_ID,
    getDataSourceIntegratedDashboard: appendDataSourceId(DASHBOARD_ID),
    appLinks: [],
    defaultIndex: PATTERN_ID,
    getDataSourceIntegratedDefaultIndex: appendDataSourceId(PATTERN_ID),
    savedObjects: getSavedObjects(),
    getDataSourceIntegratedSavedObjects: (dataSourceId?: string, dataSourceTitle?: string) =>
      getSavedObjectsWithDataSource(getSavedObjects(), dataSourceId, dataSourceTitle),
    getWorkspaceIntegratedSavedObjects: (workspaceId: string) =>
      overwriteSavedObjectsWithWorkspaceId(getSavedObjects(), workspaceId),
    dataIndices: [
      {
        // Must EQUAL the dataset id: createIndexName() only produces the un-suffixed
        // `opensearch_dashboards_sample_data_tlsoc-security` (= the bundled data view's title)
        // when dataIndexId === dataset id.
        id: 'tlsoc-security',
        dataPath: path.join(__dirname, './tlsoc_security_logs.json.gz'),
        fields: fieldMappings,
        // event.ingested must shift by the SAME delta as @timestamp on install (preserves the
        // realistic ingest lag baked in by generate_data.js) — both must be listed here.
        timeFields: ['@timestamp', 'event.ingested'],
        // Must match generate_data.js CURRENT_TIME_MARKER — install rebases docs relative to it.
        currentTimeMarker: '2026-01-05T00:00:00',
        preserveDayOfWeekTimeOfDay: true,
      },
    ],
    status: 'not_installed',
  };
};
