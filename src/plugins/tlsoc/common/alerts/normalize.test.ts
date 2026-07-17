/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { normalizeAlert, normalizeFinding } from './normalize';
import { RuleRefMap } from './types';

// ---------------------------------------------------------------------------
// Realistic fixture data (verified raw JSON shapes from a live cluster)
// ---------------------------------------------------------------------------

const rawAlert = {
  id: 'alert-abc-123',
  monitor_id: 'm1',
  monitor_name: 'c-stateless',
  trigger_name: 'c-stateless matched',
  state: 'ACTIVE',
  severity: '2',
  finding_ids: ['f1'],
  related_doc_ids: ['d1|idx'],
  start_time: 1782288242054,
  last_notification_time: 1782288242100,
  acknowledged_time: null,
  end_time: null,
  error_message: null,
};

const rawFindingObj = {
  id: 'finding-xyz-456',
  monitor_id: 'm1',
  monitor_name: 'c-stateless',
  index: 'foo-*',
  queries: [
    {
      id: 'q1',
      name: 'http_method_exists',
      query: 'http.request.method:*',
      tags: ['tlsoc', 'stateless'],
    },
  ],
  timestamp: 1782288240000,
  related_doc_ids: ['d1|idx'],
};

// The Findings API wraps each finding:  { finding: RawFinding, document_list: [...] }
const rawFindingWrapper = {
  finding: rawFindingObj,
  document_list: [{ id: 'd1', index: 'idx' }],
};

const rules: RuleRefMap = {
  m1: { soId: 'so1', name: 'My Rule', mode: 'stateless', index: 'foo-*' },
};

// ---------------------------------------------------------------------------
// normalizeAlert
// ---------------------------------------------------------------------------

describe('normalizeAlert', () => {
  describe('rule join HIT', () => {
    const alert = normalizeAlert(rawAlert, rules);

    it('ruleKnown is true when monitorId matches the map', () => {
      expect(alert.ruleKnown).toBe(true);
    });

    it('rule.name equals the saved rule name', () => {
      expect(alert.rule?.name).toBe('My Rule');
    });

    it('rule.mode equals the saved rule mode', () => {
      expect(alert.rule?.mode).toBe('stateless');
    });

    it('rule.soId is set', () => {
      expect(alert.rule?.soId).toBe('so1');
    });

    it('maps monitorName from monitor_name', () => {
      expect(alert.monitorName).toBe('c-stateless');
    });

    it('maps triggerName from trigger_name', () => {
      expect(alert.triggerName).toBe('c-stateless matched');
    });

    it('severityLabel is "high" for severity "2"', () => {
      expect(alert.severityLabel).toBe('high');
    });

    it('state is "ACTIVE"', () => {
      expect(alert.state).toBe('ACTIVE');
    });

    it('findingIds is ["f1"]', () => {
      expect(alert.findingIds).toEqual(['f1']);
    });

    it('relatedDocIds is ["d1|idx"]', () => {
      expect(alert.relatedDocIds).toEqual(['d1|idx']);
    });

    it('startTime maps correctly', () => {
      expect(alert.startTime).toBe(1782288242054);
    });

    it('acknowledgedTime is null', () => {
      expect(alert.acknowledgedTime).toBeNull();
    });

    it('errorMessage is null', () => {
      expect(alert.errorMessage).toBeNull();
    });
  });

  describe('rule join MISS', () => {
    const alert = normalizeAlert(rawAlert, {});

    it('ruleKnown is false when monitorId is absent from map', () => {
      expect(alert.ruleKnown).toBe(false);
    });

    it('rule is null', () => {
      expect(alert.rule).toBeNull();
    });

    it('all other fields are still correctly mapped', () => {
      expect(alert.monitorName).toBe('c-stateless');
      expect(alert.triggerName).toBe('c-stateless matched');
      expect(alert.severityLabel).toBe('high');
      expect(alert.state).toBe('ACTIVE');
      expect(alert.findingIds).toEqual(['f1']);
    });
  });

  describe('defaults on empty object', () => {
    it('does not throw', () => {
      expect(() => normalizeAlert({})).not.toThrow();
    });

    it('produces safe empty defaults', () => {
      const alert = normalizeAlert({});
      expect(alert.id).toBe('');
      expect(alert.monitorId).toBe('');
      expect(alert.findingIds).toEqual([]);
      expect(alert.relatedDocIds).toEqual([]);
      expect(alert.startTime).toBeNull();
      expect(alert.ruleKnown).toBe(false);
      expect(alert.severityLabel).toBe('unknown');
      expect(alert.bucketKeys).toBeUndefined();
      expect(alert.parentBucketPath).toBeUndefined();
    });
  });

  describe('bucket-level fields (bucket_keys / parent_bucket_path)', () => {
    it('bucket_keys as a comma-separated STRING → split + trimmed array', () => {
      const alert = normalizeAlert({ ...rawAlert, bucket_keys: '66.66.66.66, 77.77.77.77' });
      expect(alert.bucketKeys).toEqual(['66.66.66.66', '77.77.77.77']);
    });

    it('bucket_keys as an ARRAY → stringified array, unchanged order', () => {
      const alert = normalizeAlert({ ...rawAlert, bucket_keys: ['66.66.66.66', '77.77.77.77'] });
      expect(alert.bucketKeys).toEqual(['66.66.66.66', '77.77.77.77']);
    });

    it('bucket_keys as a single-value string (no comma) → one-element array', () => {
      const alert = normalizeAlert({ ...rawAlert, bucket_keys: '66.66.66.66' });
      expect(alert.bucketKeys).toEqual(['66.66.66.66']);
    });

    it('bucket_keys ABSENT → bucketKeys is undefined (doc-level alert)', () => {
      const alert = normalizeAlert(rawAlert);
      expect(alert.bucketKeys).toBeUndefined();
    });

    it('bucket_keys empty string → undefined (not a one-element array of "")', () => {
      const alert = normalizeAlert({ ...rawAlert, bucket_keys: '' });
      expect(alert.bucketKeys).toBeUndefined();
    });

    it('parent_bucket_path maps to parentBucketPath when present', () => {
      const alert = normalizeAlert({ ...rawAlert, parent_bucket_path: 'source.ip' });
      expect(alert.parentBucketPath).toBe('source.ip');
    });

    it('parent_bucket_path absent → parentBucketPath is undefined', () => {
      const alert = normalizeAlert(rawAlert);
      expect(alert.parentBucketPath).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // WS-18 (PROB-18): live GET /_plugins/_alerting/monitors/alerts fixture — bucket data nests
  // under agg_alert_content, never at the top level.
  // -------------------------------------------------------------------------
  describe('agg_alert_content (live bucket-alert response shape, WS-18)', () => {
    const rawBucketAlert = {
      id: 'JNKZcZ8BxjOJSPnTUcrh',
      version: 1,
      monitor_id: 'c9KUcZ8BxjOJSPnTwMkL',
      monitor_name: 'SSH brute force >3 in 5m per IP',
      trigger_name: 'SSH brute force >3 in 5m per IP threshold breached',
      finding_ids: [],
      related_doc_ids: [],
      state: 'COMPLETED',
      error_message: null,
      severity: '1',
      start_time: 1784317301212,
      last_notification_time: 1784317301212,
      end_time: 1784317900911,
      acknowledged_time: null,
      agg_alert_content: {
        parent_bucket_path: 'tlsoc_groups',
        bucket_keys: ['10.8.0.10'],
        bucket: {
          doc_count: 14,
          key: { source_ip: '10.8.0.10' },
        },
      },
    };

    it('bucketKeys comes from the nested agg_alert_content.bucket_keys', () => {
      const alert = normalizeAlert(rawBucketAlert);
      expect(alert.bucketKeys).toEqual(['10.8.0.10']);
    });

    it('parentBucketPath comes from the nested agg_alert_content.parent_bucket_path', () => {
      const alert = normalizeAlert(rawBucketAlert);
      expect(alert.parentBucketPath).toBe('tlsoc_groups');
    });

    it('bucketDocCount is populated from agg_alert_content.bucket.doc_count', () => {
      const alert = normalizeAlert(rawBucketAlert);
      expect(alert.bucketDocCount).toBe(14);
    });

    it('bucketKeyMap is populated from agg_alert_content.bucket.key', () => {
      const alert = normalizeAlert(rawBucketAlert);
      expect(alert.bucketKeyMap).toEqual({ source_ip: '10.8.0.10' });
    });

    it('nested agg_alert_content wins over a conflicting top-level bucket_keys', () => {
      const alert = normalizeAlert({ ...rawBucketAlert, bucket_keys: 'should-be-ignored' });
      expect(alert.bucketKeys).toEqual(['10.8.0.10']);
    });

    it('top-level bucket_keys still lands when agg_alert_content is absent', () => {
      const alert = normalizeAlert({ ...rawAlert, bucket_keys: ['66.66.66.66'] });
      expect(alert.bucketKeys).toEqual(['66.66.66.66']);
    });

    it('doc-level alert (no agg_alert_content) is unchanged: no bucket fields at all', () => {
      const alert = normalizeAlert(rawAlert);
      expect(alert.bucketKeys).toBeUndefined();
      expect(alert.parentBucketPath).toBeUndefined();
      expect(alert.bucketDocCount).toBeUndefined();
      expect(alert.bucketKeyMap).toBeUndefined();
    });

    it('CSV-string fallback (non-list-API context) still parses via the top-level path', () => {
      const alert = normalizeAlert({ ...rawAlert, bucket_keys: '66.66.66.66, 77.77.77.77' });
      expect(alert.bucketKeys).toEqual(['66.66.66.66', '77.77.77.77']);
    });

    it('bucketDocCount absent-safe: non-numeric doc_count is dropped, not coerced', () => {
      const alert = normalizeAlert({
        ...rawBucketAlert,
        agg_alert_content: {
          ...rawBucketAlert.agg_alert_content,
          bucket: { doc_count: 'NaN-ish', key: {} },
        },
      });
      expect(alert.bucketDocCount).toBeUndefined();
    });

    it('bucketKeyMap absent-safe: non-object bucket.key is dropped, not coerced', () => {
      const alert = normalizeAlert({
        ...rawBucketAlert,
        agg_alert_content: {
          ...rawBucketAlert.agg_alert_content,
          bucket: { doc_count: 14, key: ['not', 'an', 'object'] },
        },
      });
      expect(alert.bucketKeyMap).toBeUndefined();
    });

    it('bucketDocCount/bucketKeyMap absent on a plain doc-level alert', () => {
      const alert = normalizeAlert(rawAlert);
      expect(alert.bucketDocCount).toBeUndefined();
      expect(alert.bucketKeyMap).toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// normalizeFinding
// ---------------------------------------------------------------------------

describe('normalizeFinding', () => {
  describe('with API WRAPPER { finding, document_list }', () => {
    const finding = normalizeFinding(rawFindingWrapper, rules);

    it('ruleKnown is true on join hit', () => {
      expect(finding.ruleKnown).toBe(true);
    });

    it('rule.name equals saved rule name', () => {
      expect(finding.rule?.name).toBe('My Rule');
    });

    it('maps id from finding.id', () => {
      expect(finding.id).toBe('finding-xyz-456');
    });

    it('maps index from finding.index', () => {
      expect(finding.index).toBe('foo-*');
    });

    it('maps monitorName from finding.monitor_name', () => {
      expect(finding.monitorName).toBe('c-stateless');
    });

    it('maps queries[0].query', () => {
      expect(finding.queries[0].query).toBe('http.request.method:*');
    });

    it('maps queries[0].tags', () => {
      expect(finding.queries[0].tags).toEqual(['tlsoc', 'stateless']);
    });

    it('maps timestamp', () => {
      expect(finding.timestamp).toBe(1782288240000);
    });

    it('maps relatedDocIds', () => {
      expect(finding.relatedDocIds).toEqual(['d1|idx']);
    });
  });

  describe('with BARE finding object (no wrapper)', () => {
    const finding = normalizeFinding(rawFindingObj, rules);

    it('still maps id correctly', () => {
      expect(finding.id).toBe('finding-xyz-456');
    });

    it('ruleKnown is true on join hit', () => {
      expect(finding.ruleKnown).toBe(true);
    });

    it('maps queries', () => {
      expect(finding.queries).toHaveLength(1);
      expect(finding.queries[0].name).toBe('http_method_exists');
    });
  });

  describe('rule join MISS', () => {
    const finding = normalizeFinding(rawFindingWrapper, {});

    it('ruleKnown is false', () => {
      expect(finding.ruleKnown).toBe(false);
    });

    it('rule is null', () => {
      expect(finding.rule).toBeNull();
    });

    it('other fields still mapped', () => {
      expect(finding.monitorName).toBe('c-stateless');
      expect(finding.index).toBe('foo-*');
    });
  });

  describe('defaults on empty object', () => {
    it('does not throw', () => {
      expect(() => normalizeFinding({})).not.toThrow();
    });

    it('produces safe empty defaults', () => {
      const finding = normalizeFinding({});
      expect(finding.id).toBe('');
      expect(finding.monitorId).toBe('');
      expect(finding.queries).toEqual([]);
      expect(finding.relatedDocIds).toEqual([]);
      expect(finding.timestamp).toBeNull();
      expect(finding.ruleKnown).toBe(false);
    });
  });
});
