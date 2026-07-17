/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { compositeSourceName } from '../detection/internal';
import { getPath } from './flatten';
import { TlsocAlert } from './types';

/**
 * Compose the up-front, plain-English "reason" sentence for an alert (WS-1, PROB-1: "an alert
 * carries no event context — an L1 cannot triage"). This is TLSOC's OWN template (not a copy of
 * any vendor's undocumented per-rule-type grammar), pure and independently testable.
 *
 * Three shapes, in priority order:
 *  - DOC-LEVEL, with a fetched source doc: who/what/where matched.
 *  - BUCKET-LEVEL (a threshold alert; `alert.bucketKeys` present, no doc): the group-by keys that
 *    crossed the threshold.
 *  - FALLBACK (neither a doc nor bucket keys): just names the rule + severity.
 *
 * Every field is read defensively — an absent field is simply omitted from the sentence rather
 * than rendering as "undefined" or throwing.
 */
export function buildReason(alert: TlsocAlert, doc?: Record<string, unknown>): string {
  const ruleName = alert.rule?.name || alert.monitorName || 'Unnamed rule';
  const severity = alert.severityLabel;

  if (doc) {
    const hostName = getPath(doc, 'host.name');
    const sourceIp = getPath(doc, 'source.ip');
    const sourcePort = getPath(doc, 'source.port');
    const userName = getPath(doc, 'user.name');

    const who = hostName != null && hostName !== '' ? `Event from ${hostName}` : 'Event';
    const ipPart =
      sourceIp != null && sourceIp !== ''
        ? sourcePort != null && sourcePort !== ''
          ? `${sourceIp}:${sourcePort}`
          : `${sourceIp}`
        : null;
    const userPart = userName != null && userName !== '' ? `user ${userName}` : null;
    const parenParts = [ipPart, userPart].filter((p): p is string => p != null);
    const paren = parenParts.length > 0 ? ` (${parenParts.join(', ')})` : '';

    return `${who}${paren} matched "${ruleName}" — ${severity} alert.`;
  }

  if (alert.bucketKeys && alert.bucketKeys.length > 0) {
    const groupBy = alert.rule?.groupBy ?? [];
    const lhs = groupBy.length > 0 ? groupBy.join(', ') : '';
    const rhs = alert.bucketKeys.join(', ');
    const crossed = lhs ? `${lhs} = ${rhs}` : rhs;
    // WS-18: when the bucket's window doc_count is known, lead with it — the analyst sees the
    // magnitude ("14 events") before the group-by, matching the fixture's decisive detail.
    const countPrefix =
      typeof alert.bucketDocCount === 'number' ? `${alert.bucketDocCount} events grouped by ` : '';
    if (countPrefix) {
      return `${countPrefix}${crossed} crossed the threshold — ${severity} alert.`;
    }
    return `"${ruleName}": ${crossed} crossed the rule threshold — ${severity} alert.`;
  }

  return `"${ruleName}" fired — ${severity} alert.`;
}

/** `{{field.path}}` placeholders, e.g. `{{host.name}}` or `{{ source.ip }}` (whitespace tolerated). */
const PLACEHOLDER_RE = /\{\{\s*([\w.]+)\s*\}\}/g;

/**
 * Substitute `{{field.path}}` placeholders in a triage-runbook markdown SOURCE string with values
 * read from `context` (a fetched doc's raw `_source`, or a small synthetic groupBy/bucketKeys
 * context for bucket alerts — see {@link buildBucketContext}). A missing/absent value renders as an
 * em dash, never as "undefined". Substitution happens on the markdown SOURCE, BEFORE it reaches
 * `EuiMarkdownFormat`'s default sanitizing pipeline (D-010) — the sanitizer still runs on the result.
 */
export function substituteFieldPlaceholders(
  markdown: string,
  context: Record<string, unknown> | undefined
): string {
  return markdown.replace(PLACEHOLDER_RE, (_match, path: string) => {
    const value = context ? getPath(context, path) : undefined;
    if (value === undefined || value === null) return '—';
    if (Array.isArray(value)) return value.join(', ');
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  });
}

/**
 * Build a small nested context object from a threshold rule's `groupBy` field paths and a bucket
 * alert's `bucketKeys` values, so dotted group-by fields (e.g. `source.ip`) resolve correctly
 * through {@link getPath}/{@link substituteFieldPlaceholders} — e.g.
 * `buildBucketContext(['source.ip'], ['66.66.66.66'])` → `{ source: { ip: '66.66.66.66' } }`.
 *
 * WS-18: when `bucketKeyMap` (the alert's raw composite-bucket `key`, keyed by
 * `compositeSourceName(field)`) is supplied, each groupBy field's value is looked up by NAME
 * (`bucketKeyMap[compositeSourceName(path)]`) rather than by position — this is correct even when
 * the API's `bucketKeys` ordering doesn't match `groupBy`. Falls back to the positional
 * `bucketKeys` zip when `bucketKeyMap` is absent or a field has no entry in it (backward-compatible
 * with callers that only ever had `bucketKeys`).
 *
 * Extra/missing entries on either side are ignored (defensive — the two arrays should be the same
 * length by construction, but this never throws if they briefly aren't).
 */
export function buildBucketContext(
  groupBy: string[],
  bucketKeys: string[],
  bucketKeyMap?: Record<string, unknown>
): Record<string, unknown> {
  const ctx: Record<string, unknown> = {};
  groupBy.forEach((path, i) => {
    const named = bucketKeyMap ? bucketKeyMap[compositeSourceName(path)] : undefined;
    const value = named !== undefined ? named : bucketKeys[i];
    if (value === undefined || !path) return;
    const segments = path.split('.');
    let cur = ctx;
    segments.forEach((seg, idx) => {
      if (idx === segments.length - 1) {
        cur[seg] = value;
      } else {
        if (typeof cur[seg] !== 'object' || cur[seg] === null || Array.isArray(cur[seg])) {
          cur[seg] = {};
        }
        cur = cur[seg] as Record<string, unknown>;
      }
    });
  });
  return ctx;
}
