/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { DetectionMode } from '../detection/registry';
import type { Severity, ThreatEntry } from '../detection/types';

export type AlertState = 'ACTIVE' | 'ACKNOWLEDGED' | 'COMPLETED' | 'ERROR' | 'DELETED';

/**
 * A reference back to the TLSOC saved-object rule that owns this alert/finding. Widened (WS-1,
 * PROB-1) to carry the rule's triage/context metadata straight through the existing monitorId→rule
 * JOIN — an alert then arrives at the client already carrying everything an L1 needs, with no new
 * per-alert endpoint. All the new fields are OPTIONAL and copied 1:1 from `so.attributes.rule`
 * (plus `severity` from `so.attributes.severity`) — absent on rules saved before WS-1.
 */
export interface RuleRef {
  soId: string;
  name: string;
  mode: DetectionMode;
  /** The user-facing index pattern (from rule.index — NOT the executionAlias). */
  index: string;
  description?: string;
  /** The rule's saved severity (so.attributes.severity — a TLSOC Severity string). */
  severity?: string;
  /** Stateful (threshold) rules only — the fields the rule groups by; labels bucketKeys 1:1. */
  groupBy?: string[];
  threat?: ThreatEntry[];
  note?: string;
  investigationFields?: string[];
  riskScore?: number;
  falsePositives?: string[];
  references?: string[];
}

/** A map from OpenSearch Alerting monitor id → the TLSOC rule that created it. */
export type RuleRefMap = Record<string, RuleRef>;

/** A normalized TLSOC alert (camelCase, API-version-agnostic). */
export interface TlsocAlert {
  id: string;
  monitorId: string;
  monitorName: string;
  triggerName: string;
  state: AlertState;
  /** Raw severity string from the Alerting API (e.g. "1", "2"). */
  severity: string;
  /** Human-readable TLSOC severity label, or 'unknown' when not mappable. */
  severityLabel: Severity | 'unknown';
  findingIds: string[];
  relatedDocIds: string[];
  /**
   * Bucket-level (stateful/threshold) alerts only — the composite group-by key values that
   * crossed the threshold, in the same order as `rule.groupBy`. Absent on doc-level alerts.
   */
  bucketKeys?: string[];
  /** Bucket-level alerts only — the Alerting bucket path the trigger fired under. */
  parentBucketPath?: string;
  /**
   * Bucket-level alerts only (WS-18) — the group's document count in the trigger window (the raw
   * `agg_alert_content.bucket.doc_count`). Absent on doc-level alerts and when not a finite number.
   */
  bucketDocCount?: number;
  /**
   * Bucket-level alerts only (WS-18) — the raw composite-aggregation bucket `key` object (the
   * source of `agg_alert_content.bucket.key`). Keys are `compositeSourceName(field)` slugs (e.g.
   * `source.ip` → `source_ip`), NOT the dotted field path — look up via `compositeSourceName`, not
   * the field name directly. Preferred over the positional `bucketKeys` zip when present.
   */
  bucketKeyMap?: Record<string, unknown>;
  startTime: number | null;
  lastNotificationTime: number | null;
  acknowledgedTime: number | null;
  endTime: number | null;
  errorMessage: string | null;
  /** The TLSOC rule that created the monitor this alert belongs to, or null if not found. */
  rule: RuleRef | null;
  /** True when rule is non-null (the alert's monitor was created by a saved TLSOC detection). */
  ruleKnown: boolean;
  /**
   * PROB-29: an ADDITIVE display signal set at LIST-hydration time when this alert is still
   * ACKNOWLEDGED on the engine BUT has a live TLSOC reopen override (its case was reopened, and the
   * engine has no un-acknowledge API). The real `state` field stays ACKNOWLEDGED (honest); the UI
   * keys off this field to show the alert as reactivated ("Reopened · <case>") and include it in the
   * Active filter. Absent for every alert without a live override.
   */
  reopenedFromCase?: ReopenedFromCase;
}

/**
 * PROB-29: the minimal, client-facing projection of a `tlsoc-alert-override` merged onto a
 * normalized alert. Carries only what the UI needs to render the "Reopened · <case>" badge and the
 * honest flyout note — the full override SO (actor, monitorId) stays server-side.
 */
export interface ReopenedFromCase {
  caseId: string;
  caseName: string;
  reopenedAt: string;
}

/**
 * PROB-29: the attributes of a `tlsoc-alert-override` saved object (id = the alert id). Recorded on
 * case reopen for each linked alert the engine still reports ACKNOWLEDGED; deleted on re-close,
 * manual acknowledge, or lazily when the engine finally COMPLETES the alert.
 */
export interface AlertOverrideAttributes {
  alertId: string;
  caseId: string;
  caseName: string;
  monitorId: string;
  reopenedAt: string;
  reopenedBy: string;
}

/** A single query (doc-level monitor query) associated with a finding. */
export interface FindingQuery {
  id: string;
  name: string;
  query: string;
  tags: string[];
}

/** A normalized TLSOC finding (camelCase, API-version-agnostic). */
export interface TlsocFinding {
  id: string;
  monitorId: string;
  monitorName: string;
  /** The index the finding matched against. */
  index: string;
  queries: FindingQuery[];
  timestamp: number | null;
  relatedDocIds: string[];
  /** The TLSOC rule that created the monitor this finding belongs to, or null if not found. */
  rule: RuleRef | null;
  /** True when rule is non-null. */
  ruleKnown: boolean;
}
