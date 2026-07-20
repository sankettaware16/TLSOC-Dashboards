/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { compileToBucketLevelMonitor } from './bucket_monitor';
import { compileToDocLevelMonitor } from './monitor';
import { buildMonitorForSave } from './save';
import { RuleDefinition, ThresholdRuleDefinition } from './types';

const stateless: RuleDefinition = {
  name: 'Web attack signature in URL',
  severity: 'high',
  index: 'fosstlsoc-logs-moodle-2026.05.16',
  group: {
    logic: 'OR',
    conditions: [
      { field: 'url.path', operator: 'contains', value: '../' },
      { field: 'url.path', operator: 'matches_regex', value: 'union.*select' },
    ],
  },
};

const stateful: ThresholdRuleDefinition = {
  name: 'DDoS: single-source request flood',
  severity: 'high',
  index: 'fosstlsoc-logs-moodle-2026.05.16',
  filter: { logic: 'AND', conditions: [{ field: 'http.request.method', operator: 'exists' }] },
  groupBy: ['source.ip'],
  window: { value: 5, unit: 'MINUTES' },
  threshold: { operator: 'gt', value: 1000 },
};

describe('buildMonitorForSave — the saved monitor is exactly the proven compiler output', () => {
  it('stateful → compileToBucketLevelMonitor verbatim (saved == dry-run tested)', () => {
    expect(buildMonitorForSave('stateful', stateful)).toEqual(compileToBucketLevelMonitor(stateful));
  });

  it('stateless → compileToDocLevelMonitor verbatim (saved == dry-run tested)', () => {
    expect(buildMonitorForSave('stateless', stateless)).toEqual(compileToDocLevelMonitor(stateless));
  });

  it('keeps enabled:true so the saved monitor actually runs on its schedule', () => {
    expect((buildMonitorForSave('stateless', stateless) as { enabled: boolean }).enabled).toBe(true);
    expect((buildMonitorForSave('stateful', stateful) as { enabled: boolean }).enabled).toBe(true);
  });

  it('does NOT attach ui_metadata (OS 3.7 strips it; the IR lives in a saved object instead)', () => {
    expect(
      (buildMonitorForSave('stateful', stateful) as { ui_metadata?: unknown }).ui_metadata
    ).toBeUndefined();
  });

  it('throws (never persists) an invalid rule — reuses the compiler validators', () => {
    expect(() => buildMonitorForSave('stateful', { ...stateful, groupBy: [] })).toThrow(
      /group by at least one field/i
    );
    expect(() => buildMonitorForSave('stateless', { ...stateless, index: '' })).toThrow(
      /data view/i
    );
  });
});
