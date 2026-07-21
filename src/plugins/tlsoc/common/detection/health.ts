/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * The HONEST rule-health model (v1.2.3 D8) — pure folds over the only run-health signals the
 * Alerting engine actually exposes, consumed by the LIST route (server/routes/monitors.ts) and
 * rendered by the saved-rules list.
 *
 * WHY THERE IS NO 'Succeeded' STATE (research_r2 §f, live-verified on OpenSearch 3.7):
 * - The engine keeps NO run history: monitor documents carry only `enabled`/`enabled_time`/
 *   `last_update_time`; there is no execution-log API, and monitor-metadata docs are unreachable
 *   through the Alerting search API. A successful no-trigger run leaves ZERO trace anywhere.
 * - Only FAILURES are (partially) observable: failing QUERY-LEVEL runs write/refresh ERROR-state
 *   alerts carrying `error_message`; `end_time` is set when the monitor recovers. BUCKET-level
 *   runtime failures write NO alert at all, and DOC-level bad queries silently match nothing —
 *   both failure classes are INVISIBLE here.
 * - "Last run" exists only for ENABLED monitors, via `GET /_plugins/_alerting/stats`
 *   `nodes.<id>.jobs_info[monitorId].last_execution_time`; disabled monitors have no signal.
 *
 * So the only statements TLSOC can make truthfully are the tri-state below: a rule is `failing`
 * (a live, un-ended ERROR alert exists), `off` (disabled — not running at all), or
 * `ok-unverified` ("no failures recorded" — which is NOT "succeeded": bucket/doc failures are
 * invisible, so absence of errors proves nothing). Rendering "Succeeded" would be a lie the UI
 * copy explicitly avoids.
 */

/** The tri-state health verdict. NEVER 'succeeded' — see the module doc for why. */
export type RuleHealthStatus = 'failing' | 'ok-unverified' | 'off';

/** The newest live failure signal for one monitor (from an un-ended ERROR-state alert). */
export interface RuleLastError {
  message: string;
  /** Epoch ms the failing streak STARTED (the ERROR alert's `start_time`) — "failing since". */
  at?: number;
}

/** The per-rule health block the LIST route returns (all engine-derived fields best-effort). */
export interface RuleHealthInfo {
  status: RuleHealthStatus;
  enabled: boolean;
  /** Epoch ms of the last scheduled execution (stats jobs_info) — enabled monitors only. */
  lastRun?: number;
  lastError?: RuleLastError;
  /** Epoch ms the monitor was last enabled (monitor doc `enabled_time`). */
  enabledTime?: number;
  /** Epoch ms the monitor doc was last written (monitor doc `last_update_time`). */
  lastUpdateTime?: number;
}

/**
 * Pure: fold raw Alerting get-alerts API alert objects (ideally pre-filtered with
 * `alertState=ERROR`, but re-checked here) into the newest LIVE failure per monitor id.
 *
 * - Only `state === 'ERROR'` alerts count, and only UN-ENDED ones (`end_time` unset): the engine
 *   sets `end_time` when a later run succeeds, so an ended ERROR alert means "recovered" — it
 *   must NOT mark the rule failing.
 * - Per monitor, the newest streak wins (greatest `start_time`).
 * - ERROR alerts carry quirks this fold must tolerate, never parse (research_r6 risk): an empty
 *   `severity: ''` and ids prefixed `error-alert-` — neither field is read here.
 * - Garbage entries (non-objects, missing monitor_id) are skipped, never thrown on.
 */
export function foldErrorAlerts(rawAlerts: unknown[]): Record<string, RuleLastError> {
  const newestStart: Record<string, number> = {};
  const out: Record<string, RuleLastError> = {};
  for (const raw of rawAlerts ?? []) {
    const a = raw as any;
    if (!a || typeof a !== 'object') continue;
    if (a.state !== 'ERROR') continue;
    if (a.end_time !== null && a.end_time !== undefined) continue; // ended = recovered
    const monitorId = a.monitor_id;
    if (typeof monitorId !== 'string' || monitorId === '') continue;
    const at = typeof a.start_time === 'number' ? a.start_time : undefined;
    const prev = newestStart[monitorId];
    if (prev !== undefined && (at ?? -Infinity) <= prev) continue;
    newestStart[monitorId] = at ?? -Infinity;
    out[monitorId] = {
      message:
        typeof a.error_message === 'string' && a.error_message !== ''
          ? a.error_message
          : 'The monitor run failed (no error message was recorded).',
      ...(at !== undefined ? { at } : {}),
    };
  }
  return out;
}

/**
 * Pure: fold a `GET /_plugins/_alerting/stats` response body into monitorId → last_execution_time
 * (epoch ms). `jobs_info` is per NODE and keyed by monitor id; a monitor can appear on several
 * nodes across rebalances, so the NEWEST timestamp wins. Only ENABLED monitors appear at all —
 * a missing id means "no signal", not "never ran". Any malformed shape folds to `{}`.
 */
export function foldJobsInfo(statsBody: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  const nodes = (statsBody as any)?.nodes;
  if (!nodes || typeof nodes !== 'object') return out;
  for (const node of Object.values(nodes as Record<string, any>)) {
    const jobs = node?.jobs_info;
    if (!jobs || typeof jobs !== 'object') continue;
    for (const [monitorId, info] of Object.entries(jobs as Record<string, any>)) {
      const t = info?.last_execution_time;
      if (typeof t !== 'number') continue;
      if (out[monitorId] === undefined || t > out[monitorId]) out[monitorId] = t;
    }
  }
  return out;
}

/**
 * Pure: combine the per-rule signals into the honest tri-state {@link RuleHealthInfo}.
 *
 * Precedence: `off` beats everything (a disabled rule is not running, so a lingering un-ended
 * ERROR alert from before the disable says nothing about its current state); then `failing`
 * (a live un-ended ERROR alert exists); else `ok-unverified` — deliberately NOT "succeeded",
 * because bucket-/doc-level failures leave no ERROR alert (see the module doc).
 */
export function computeRuleHealth(input: {
  enabled: boolean;
  lastRun?: number;
  lastError?: RuleLastError;
  enabledTime?: number;
  lastUpdateTime?: number;
}): RuleHealthInfo {
  const status: RuleHealthStatus = !input.enabled
    ? 'off'
    : input.lastError
    ? 'failing'
    : 'ok-unverified';
  return {
    status,
    enabled: input.enabled,
    ...(input.lastRun !== undefined ? { lastRun: input.lastRun } : {}),
    ...(input.lastError !== undefined ? { lastError: input.lastError } : {}),
    ...(input.enabledTime !== undefined ? { enabledTime: input.enabledTime } : {}),
    ...(input.lastUpdateTime !== undefined ? { lastUpdateTime: input.lastUpdateTime } : {}),
  };
}
