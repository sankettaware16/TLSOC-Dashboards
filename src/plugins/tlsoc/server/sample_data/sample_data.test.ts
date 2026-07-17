/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import fs from 'fs';
import Joi from 'joi';
import { sampleDataSchema } from '../../../home/server/services/sample_data/lib/sample_dataset_schema';
import { tlsocSecurityLogsSpecProvider } from './index';
import { PATTERN_ID, DASHBOARD_ID } from './saved_objects';

describe('tlsocSecurityLogsSpecProvider', () => {
  const spec = tlsocSecurityLogsSpecProvider();

  it('passes the home plugin Joi schema registerSampleDataset() validates against', () => {
    const { error } = Joi.object(sampleDataSchema).validate(spec);
    expect(error).toBeUndefined();
  });

  it('satisfies the registry id-match invariants (index-pattern and dashboard)', () => {
    // sample_data_registry.ts rejects specs whose defaultIndex / overviewDashboard have no
    // matching saved object — mirror those checks so a refactor fails HERE first.
    const pattern = spec.savedObjects.find(
      (so) => so.type === 'index-pattern' && so.id === spec.defaultIndex
    );
    const dashboard = spec.savedObjects.find(
      (so) => so.type === 'dashboard' && so.id === spec.overviewDashboard
    );
    expect(pattern).toBeDefined();
    expect(dashboard).toBeDefined();
    expect(spec.defaultIndex).toBe(PATTERN_ID);
    expect(spec.overviewDashboard).toBe(DASHBOARD_ID);
  });

  it('ships a NON-EMPTY index-pattern field cache (the 5a.1c empty-fields lesson)', () => {
    const pattern = spec.savedObjects.find((so) => so.type === 'index-pattern')!;
    const fields = JSON.parse((pattern.attributes as { fields: string }).fields);
    expect(fields.length).toBeGreaterThan(30);
    const names = fields.map((f: { name: string }) => f.name);
    expect(names).toContain('@timestamp'); // the timeFieldName MUST be in the cache
    expect(names).toContain('source.ip');
    expect(names).toContain('event.outcome');
  });

  it('names the index so it matches the bundled data view title', () => {
    // createIndexName() only yields the un-suffixed opensearch_dashboards_sample_data_<id>
    // (= the data view's title) when the dataIndex id equals the dataset id.
    const dataIndex = spec.dataIndices[0];
    expect(dataIndex.id).toBe(spec.id);
    const pattern = spec.savedObjects.find((so) => so.type === 'index-pattern')!;
    expect((pattern.attributes as { title: string }).title).toBe(
      `opensearch_dashboards_sample_data_${spec.id}`
    );
  });

  it('points dataPath at the committed gz artifact and keeps the marker in sync', () => {
    const dataIndex = spec.dataIndices[0];
    expect(fs.existsSync(dataIndex.dataPath)).toBe(true);
    // both time fields are shifted by the same delta at install so ingest lag
    // (event.ingested − @timestamp) is preserved for the cockpit's lag widget.
    expect(dataIndex.timeFields).toEqual(['@timestamp', 'event.ingested']);
    // generate_data.js writes docs relative to this marker — they must never drift apart.
    expect(dataIndex.currentTimeMarker).toBe('2026-01-05T00:00:00');
    const generator = fs.readFileSync(require.resolve('./generate_data.js'), 'utf8');
    expect(generator).toContain(`CURRENT_TIME_MARKER = '${dataIndex.currentTimeMarker}'`);
  });

  it('prefixes every saved object id when installed inside a workspace', () => {
    const prefixed = spec.getWorkspaceIntegratedSavedObjects('wsid');
    for (const so of prefixed) {
      expect(so.id.startsWith('wsid_')).toBe(true);
    }
    const dashboard = prefixed.find((so) => so.type === 'dashboard')!;
    for (const ref of dashboard.references) {
      expect(ref.id.startsWith('wsid_')).toBe(true);
    }
  });
});
