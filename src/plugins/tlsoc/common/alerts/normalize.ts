/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { AlertState, FindingQuery, RuleRefMap, TlsocAlert, TlsocFinding } from './types';
import { severityLabel } from './severity';

/**
 * Normalize a raw `bucket_keys` value into a clean string array, or `undefined` when absent.
 * The live GET /_plugins/_alerting/monitors/alerts response (WS-18) nests this under
 * `agg_alert_content.bucket_keys` and it is ALWAYS an array of strings there (source:
 * common-utils Alert.kt → AggregationResultBucket.innerXContent). The comma-joined STRING shape
 * only exists upstream in the notification-template context (Alert.asTemplateArg), never on the
 * list API — kept here purely as a defensive fallback, not the documented list-API shape.
 */
function normalizeBucketKeys(raw: unknown): string[] | undefined {
  if (Array.isArray(raw)) return raw.map((v) => String(v));
  if (typeof raw === 'string' && raw.trim() !== '') {
    return raw.split(',').map((s) => s.trim());
  }
  return undefined;
}

/**
 * Normalize a raw Alerting alert (snake_case) → a typed {@link TlsocAlert} (camelCase).
 *
 * Every raw field is accessed defensively (`?.`/`??`) — the cluster JSON is untyped `any`
 * and fields may be absent, null, or in an unexpected shape. Join to a TLSOC rule via
 * `rules[monitorId]` when the map is supplied; ruleKnown is false when the monitor was
 * not created by a saved TLSOC detection.
 */
export function normalizeAlert(raw: any, rules: RuleRefMap = {}): TlsocAlert {
  const monitorId: string = raw?.monitor_id ?? '';
  const rule = rules[monitorId] ?? null;
  // WS-18: the live list-API response nests bucket data under agg_alert_content — prefer that,
  // falling back to a top-level shape (never observed on the list API, but defensive).
  const agg = raw?.agg_alert_content;
  const bucketKeys = normalizeBucketKeys(agg?.bucket_keys ?? raw?.bucket_keys);
  const parentBucketPath = agg?.parent_bucket_path ?? raw?.parent_bucket_path;
  const bucketDocCount = agg?.bucket?.doc_count;
  const bucketKeyMap = agg?.bucket?.key;
  return {
    id: raw?.id ?? '',
    monitorId,
    monitorName: raw?.monitor_name ?? '',
    triggerName: raw?.trigger_name ?? '',
    state: (raw?.state ?? 'ACTIVE') as AlertState,
    severity: raw?.severity ?? '',
    severityLabel: severityLabel(raw?.severity),
    findingIds: Array.isArray(raw?.finding_ids) ? raw.finding_ids : [],
    relatedDocIds: Array.isArray(raw?.related_doc_ids) ? raw.related_doc_ids : [],
    ...(bucketKeys !== undefined ? { bucketKeys } : {}),
    ...(parentBucketPath != null ? { parentBucketPath: String(parentBucketPath) } : {}),
    ...(typeof bucketDocCount === 'number' && Number.isFinite(bucketDocCount)
      ? { bucketDocCount }
      : {}),
    ...(bucketKeyMap != null && typeof bucketKeyMap === 'object' && !Array.isArray(bucketKeyMap)
      ? { bucketKeyMap }
      : {}),
    startTime: raw?.start_time ?? null,
    lastNotificationTime: raw?.last_notification_time ?? null,
    acknowledgedTime: raw?.acknowledged_time ?? null,
    endTime: raw?.end_time ?? null,
    errorMessage: raw?.error_message ?? null,
    rule,
    ruleKnown: rule !== null,
  };
}

/**
 * Normalize a raw Alerting finding → a typed {@link TlsocFinding} (camelCase).
 *
 * Accepts BOTH the API wrapper shape `{ finding: {...}, document_list: [...] }` and a bare
 * finding object — the `f = raw?.finding ?? raw` unwrap handles either case.
 */
export function normalizeFinding(raw: any, rules: RuleRefMap = {}): TlsocFinding {
  // The Findings API wraps each finding: { finding: RawFinding, document_list: any[] }.
  // Accept both the wrapper and a bare finding object.
  const f = raw?.finding ?? raw;
  const monitorId: string = f?.monitor_id ?? '';
  const rule = rules[monitorId] ?? null;
  const queries: FindingQuery[] = Array.isArray(f?.queries)
    ? f.queries.map((q: any) => ({
        id: q?.id ?? '',
        name: q?.name ?? '',
        query: q?.query ?? '',
        tags: Array.isArray(q?.tags) ? q.tags : [],
      }))
    : [];
  return {
    id: f?.id ?? '',
    monitorId,
    monitorName: f?.monitor_name ?? '',
    index: f?.index ?? '',
    queries,
    timestamp: f?.timestamp ?? null,
    relatedDocIds: Array.isArray(f?.related_doc_ids) ? f.related_doc_ids : [],
    rule,
    ruleKnown: rule !== null,
  };
}
