/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { schema } from '@osd/config-schema';
import { HttpAuth, IRouter, Logger, SavedObjectsClientContract } from '../../../../core/server';
import { ALERT_ACKNOWLEDGERS, callerHasAnyRole, forbidden } from '../lib/authz';
import { DetectionRuleAttributes } from '../../common/detection';
import { refreshSeenValuesSweep } from '../lib/new_terms_state';
import { syncStatelessMonitorTargets } from './monitors';
import { syncIndicatorListMonitors } from './value_lists';
import {
  AlertOverrideAttributes,
  RuleRefMap,
  TlsocAlert,
  applyAlertOverride,
  filterAlertsByRange,
  normalizeAlert,
  normalizeFinding,
  overrideOwners,
} from '../../common/alerts';
import { CaseAttributes } from '../../common/cases';
import { ALERT_OVERRIDE_SO_TYPE, CASE_SO_TYPE, DETECTION_RULE_SO_TYPE } from '../saved_objects';

/**
 * Build a map from OpenSearch Alerting monitor id → TLSOC rule reference by scanning all
 * `tlsoc-detection-rule` saved objects. Used to annotate alerts and findings with the rule
 * that created the monitor (the JOIN: alert/finding.monitor_id ↔ SO.attributes.monitorId).
 */
export async function buildRuleRefMap(soClient: SavedObjectsClientContract): Promise<RuleRefMap> {
  const found = await soClient.find<DetectionRuleAttributes>({
    type: DETECTION_RULE_SO_TYPE,
    perPage: 1000,
  });
  const map: RuleRefMap = {};
  for (const so of found.saved_objects) {
    const rule = so.attributes.rule as any;
    map[so.attributes.monitorId] = {
      soId: so.id,
      name: so.attributes.name,
      mode: so.attributes.mode,
      index: rule?.index ?? '',
      // WS-1 (PROB-1): carry the rule's triage/context metadata through the existing JOIN so an
      // alert arrives at the client already enriched — no new per-alert endpoint. All optional;
      // absent on rules saved before WS-1 (`rule` SO attribute is enabled:false/unmapped).
      description: rule?.description,
      severity: so.attributes.severity,
      // v1.2.3 D9: the builder stamps rule.groupBy as the suppression mirror, but an
      // API-authored suppressed rule may carry only suppression.groupBy — fall back to it so
      // the flyout labels bucket keys instead of degrading to positional "group key N".
      groupBy: rule?.groupBy ?? rule?.suppression?.groupBy,
      threat: rule?.threat,
      note: rule?.note,
      investigationFields: rule?.investigationFields,
      riskScore: rule?.riskScore,
      falsePositives: rule?.falsePositives,
      references: rule?.references,
    };
  }
  return map;
}

/**
 * Fetch raw alert objects for a set of alert ids THROUGH the Alerting plugin API (Task 5a.1d).
 *
 * Under OpenSearch Security the `.opendistro-alerting-*` system indices are protected: a direct
 * `_search` on them returns SILENTLY EMPTY (and writes 403) even for admin — only the Alerting
 * plugin's own API path can see them. The get-alerts API has no fetch-by-id parameter (probed on
 * OS 3.7: `alertIds`/`searchString` don't match ids), so this pages through
 * `GET /_plugins/_alerting/monitors/alerts` (which includes history/DELETED alerts) and the caller
 * filters with {@link partitionByIds}. Paging stops when every wanted id is found, a short page
 * signals the end, or the 10-page (10k-alert) honesty cap is hit — same cap pattern as 4.5c.
 */
export async function fetchAlertsByIds(
  esClient: any,
  ids: string[]
): Promise<any[]> {
  const wanted = new Set(ids);
  const collected: any[] = [];
  const PAGE_SIZE = 1000;
  const MAX_PAGES = 10;
  for (let page = 0; page < MAX_PAGES && wanted.size > 0; page++) {
    const resp = await esClient.transport.request({
      method: 'GET',
      path: '/_plugins/_alerting/monitors/alerts',
      querystring: {
        size: PAGE_SIZE,
        startIndex: page * PAGE_SIZE,
        sortString: 'start_time',
        sortOrder: 'desc',
      },
    });
    const alerts: any[] = (resp as any).body?.alerts ?? [];
    for (const a of alerts) {
      if (a?.id != null && wanted.has(a.id)) {
        collected.push(a);
        wanted.delete(a.id);
      }
    }
    if (alerts.length < PAGE_SIZE) break; // short page = no more alerts
  }
  return collected;
}

/**
 * PROB-29: MERGE the honest reopen display-overrides onto a normalized alert list.
 *
 * Loads every live `tlsoc-alert-override` (there are only as many as there are reopened alerts —
 * typically a handful, so ONE `find` is far cheaper than a per-alert bulkGet) and, for each returned
 * alert with a matching override, delegates to the pure {@link applyAlertOverride}: an alert the
 * engine still reports ACKNOWLEDGED gains an additive `reopenedFromCase`; an alert the engine has
 * moved on (COMPLETED/DELETED/ACTIVE) wins and its now-stale override is lazily deleted
 * (fire-and-forget). The merge is BEST-EFFORT: any SO failure logs and returns the alerts unchanged,
 * never breaking the Alerts list.
 */
export async function mergeAlertOverrides(
  soClient: SavedObjectsClientContract,
  alerts: TlsocAlert[],
  logger: Logger
): Promise<TlsocAlert[]> {
  let overrides: Map<string, AlertOverrideAttributes>;
  try {
    const found = await soClient.find<AlertOverrideAttributes>({
      type: ALERT_OVERRIDE_SO_TYPE,
      perPage: 1000,
    });
    overrides = new Map(found.saved_objects.map((so) => [so.id, so.attributes]));
  } catch (err) {
    logger.warn(`tlsoc alerts: reopen-override merge skipped (find failed): ${err.message}`);
    return alerts;
  }
  if (overrides.size === 0) return alerts;

  const staleIds: string[] = [];
  const merged = alerts.map((a) => {
    const override = overrides.get(a.id);
    if (!override) return a;
    const { alert, stale } = applyAlertOverride(a, override);
    if (stale) staleIds.push(a.id);
    return alert;
  });

  // Lazy stale-override cleanup — engine-COMPLETE-wins already decided display above; deleting the
  // dead SO is pure hygiene, so it's fire-and-forget and never blocks or fails the list response.
  if (staleIds.length > 0) {
    void deleteAlertOverrides(soClient, staleIds, logger, 'stale (engine no longer acknowledged)');
  }
  return merged;
}

/**
 * PROB-29: best-effort UNCONDITIONAL delete of reopen-override SOs (id = alert id). 404s are
 * tolerated (the override may already be gone). Never throws — the caller's real work must not fail
 * because a display-override could not be cleaned up.
 *
 * This clears the WHOLE override regardless of how many cases own it, so it is used only by the two
 * callers for which that is correct: MANUAL ACKNOWLEDGE (the analyst finished the alert, period —
 * every reopening case's claim is void) and STALE-ENGINE cleanup (the engine moved the alert off
 * ACKNOWLEDGED, so `owners` is irrelevant). Case-lifecycle removal (re-close / case-delete) must NOT
 * use this — it only drops the CALLING case from the ownership set; see {@link removeOverrideOwner}.
 */
export async function deleteAlertOverrides(
  soClient: SavedObjectsClientContract,
  alertIds: string[],
  logger: Logger,
  reason: string
): Promise<void> {
  await Promise.all(
    alertIds.map(async (id) => {
      try {
        await soClient.delete(ALERT_OVERRIDE_SO_TYPE, id);
      } catch (err: any) {
        const status = err?.output?.statusCode ?? err?.statusCode;
        if (status === 404) return; // already gone — the desired end state
        logger.warn(`tlsoc alerts: could not delete reopen override ${id} (${reason}): ${err.message}`);
      }
    })
  );
}

/**
 * PROB-30: REMOVE one case from a reopen-override's ownership set (the core fix). Used by the
 * case-lifecycle callers — re-close and case-delete — instead of an unconditional delete.
 *
 * For each alert id: read the override, resolve its ownership set through the {@link overrideOwners}
 * back-compat shim (a legacy single-owner doc reads as `[caseId]`), and drop `caseId`.
 *   - If this case was never an owner → nothing to do (another case's override, left untouched).
 *   - If the set EMPTIES → delete the SO (this was the last reopener).
 *   - Otherwise → PUT the trimmed `owners[]` back so the STILL-reopened cases keep their override.
 *
 * DISPLAY repoint: `caseId`/`caseName` show the most-recent reopener. If the LEAVING case was that
 * displayed owner, we repoint to a deterministic survivor — `owners[0]`, the earliest remaining
 * reopener (the reopen path appends, so index 0 is the oldest) — and best-effort re-fetch that
 * case's title so the badge keeps reading "Reopened · <case>" with a real name (falling back to ''
 * if the case can't be read; the LIST merge then shows the id, still honest). Never throws — a flaky
 * SO op must not block the case status change or the delete.
 */
export async function removeOverrideOwner(
  soClient: SavedObjectsClientContract,
  alertIds: string[],
  caseId: string,
  logger: Logger,
  reason: string
): Promise<void> {
  await Promise.all(
    alertIds.map(async (id) => {
      try {
        const so = await soClient.get<AlertOverrideAttributes>(ALERT_OVERRIDE_SO_TYPE, id);
        const before = overrideOwners(so.attributes);
        const owners = before.filter((c) => c !== caseId);
        if (owners.length === before.length) return; // this case never owned it — leave it alone
        if (owners.length === 0) {
          await soClient.delete(ALERT_OVERRIDE_SO_TYPE, id); // last reopener left — drop the SO
          return;
        }
        // A still-reopened case remains — trim the set. Repoint display only if the leaver was it.
        const patch: Partial<AlertOverrideAttributes> = { owners };
        if (so.attributes.caseId === caseId) {
          patch.caseId = owners[0];
          patch.caseName = await fetchCaseTitle(soClient, owners[0], logger);
        }
        await soClient.update<AlertOverrideAttributes>(ALERT_OVERRIDE_SO_TYPE, id, patch);
      } catch (err: any) {
        const status = err?.output?.statusCode ?? err?.statusCode;
        if (status === 404) return; // already gone — the desired end state
        logger.warn(
          `tlsoc alerts: could not remove override owner for ${id} (${reason}): ${err.message}`
        );
      }
    })
  );
}

/** Best-effort case title for the display repoint above; '' when the case can't be read. */
async function fetchCaseTitle(
  soClient: SavedObjectsClientContract,
  caseId: string,
  logger: Logger
): Promise<string> {
  try {
    const c = await soClient.get<CaseAttributes>(CASE_SO_TYPE, caseId);
    return c.attributes.title ?? '';
  } catch (err: any) {
    logger.warn(`tlsoc alerts: could not read case ${caseId} for override display repoint: ${err.message}`);
    return '';
  }
}

/**
 * Page through `/_plugins/_alerting/monitors/alerts` sorted desc by `start_time` (WS-3, PROB-3 —
 * the upstream get-alerts API has NO time parameter at all, verified). Mirrors
 * {@link fetchAlertsByIds}'s 10-page/10k-alert honesty cap, and additionally EARLY-EXITS once a
 * page's OLDEST `start_time` drops below `from` — results are strictly desc-sorted by construction,
 * so once that happens no later (older) page can contain a match either.
 *
 * `passthroughQuery` carries the caller's other filters (alertState, severityLevel, searchString,
 * monitorId) into every page request — `size`/`startIndex`/`sortString`/`sortOrder` are owned by
 * this function's own paging loop and are NOT accepted from the caller here.
 */
async function fetchAlertsInRange(
  esClient: any,
  from: number | undefined,
  passthroughQuery: Record<string, any>
): Promise<any[]> {
  const floor = from ?? -Infinity;
  const collected: any[] = [];
  const PAGE_SIZE = 1000;
  const MAX_PAGES = 10;
  for (let page = 0; page < MAX_PAGES; page++) {
    const resp = await esClient.transport.request({
      method: 'GET',
      path: '/_plugins/_alerting/monitors/alerts',
      querystring: {
        ...passthroughQuery,
        size: PAGE_SIZE,
        startIndex: page * PAGE_SIZE,
        sortString: 'start_time',
        sortOrder: 'desc',
      },
    });
    const alerts: any[] = (resp as any).body?.alerts ?? [];
    collected.push(...alerts);
    if (alerts.length < PAGE_SIZE) break; // short page = no more alerts anywhere
    const oldestOnPage = alerts[alerts.length - 1]?.start_time;
    if (typeof oldestOnPage === 'number' && oldestOnPage < floor) break; // nothing older can match
  }
  return collected;
}

/**
 * Register read-only Alerts + Findings proxy routes.
 *
 * GET  /api/tlsoc/alerts               — proxies /_plugins/_alerting/monitors/alerts; optional
 *                                         from/to (epoch ms) time-range filter (WS-3, PROB-3)
 * GET  /api/tlsoc/findings              — proxies /_plugins/_alerting/findings/_search
 * POST /api/tlsoc/alerts/_related_docs  — fetches the source docs behind an alert's relatedDocIds
 *
 * The list/findings routes join the raw Alerting response to TLSOC saved-object rules (via
 * monitorId) and return normalized camelCase types.
 */
export function registerAlertRoutes(router: IRouter, logger: Logger, auth?: HttpAuth) {
  // -------------------------------------------------------------------------
  // GET /api/tlsoc/alerts
  // -------------------------------------------------------------------------
  router.get(
    {
      path: '/api/tlsoc/alerts',
      validate: {
        query: schema.object(
          {
            alertState: schema.maybe(schema.string()),
            severityLevel: schema.maybe(schema.string()),
            searchString: schema.maybe(schema.string()),
            sortString: schema.maybe(schema.string()),
            sortOrder: schema.maybe(schema.string()),
            size: schema.maybe(schema.number()),
            startIndex: schema.maybe(schema.number()),
            monitorId: schema.maybe(schema.string()),
            // WS-3 (PROB-3): optional time-range filter, epoch ms. The upstream get-alerts API has
            // NO time parameter at all (verified) — when either bound is present, this route pages
            // the engine API itself (see fetchAlertsInRange) and filters with the pure
            // filterAlertsByRange helper. Absent → existing (unpaged) behavior, byte-identical.
            from: schema.maybe(schema.number()),
            to: schema.maybe(schema.number()),
          },
          { unknowns: 'ignore' }
        ),
      },
    },
    async (context, request, response) => {
      // URGENT HOTFIX: fire-and-forget drift repair for stateless rules whose index pattern's
      // backing concrete indices changed since save (daily rotation, new endpoints, ISM aging-out)
      // — see monitors.ts's syncStatelessMonitorTargets. The Alerts page polling this route every
      // ~30s gives the sync its cadence, using the CALLER's credentials (a background job would
      // have none). Internally debounced; NEVER blocks or fails this request on a sync error.
      void syncStatelessMonitorTargets(
        context.core.opensearch.client.asCurrentUser,
        context.core.savedObjects.client,
        logger
      ).catch((err) => logger.warn(`tlsoc alerts: background execution-target sync failed: ${err.message}`));

      // v1.2.3 D5: same fire-and-forget contract as its neighbor — caller's credentials,
      // internally 60s-debounced BEFORE the SO scan, never blocks or fails this request. Closes
      // the new-terms alert lifecycle: value fires → sweep marks it seen (≤~60s while anyone has
      // TLSOC open) → next monitor run drops the bucket → alert auto-COMPLETEs.
      void refreshSeenValuesSweep(
        context.core.opensearch.client.asCurrentUser,
        context.core.savedObjects.client,
        logger
      ).catch((err) => logger.warn(`tlsoc alerts: background seen-values sweep failed: ${err.message}`));

      // v1.2.3 D6: inline indicator-match monitors bake list values into their query — this
      // rewrites drifted ones after out-of-band list edits (the value-list PUT route already
      // fires it force:true for UI edits). Same never-throws, 60s-debounced contract.
      void syncIndicatorListMonitors(
        context.core.opensearch.client.asCurrentUser,
        context.core.savedObjects.client,
        logger
      ).catch((err) => logger.warn(`tlsoc alerts: background indicator-list sync failed: ${err.message}`));

      try {
        const q = request.query as Record<string, any>;
        const knownKeys = [
          'alertState',
          'severityLevel',
          'searchString',
          'sortString',
          'sortOrder',
          'size',
          'startIndex',
          'monitorId',
        ];

        const esClient = context.core.opensearch.client.asCurrentUser;
        const soClient = context.core.savedObjects.client;
        const rules = await buildRuleRefMap(soClient);

        const from: number | undefined = q.from;
        const to: number | undefined = q.to;

        let alerts: TlsocAlert[];
        let total: number;

        if (from !== undefined || to !== undefined) {
          // A time range is active. size/startIndex/sortString/sortOrder don't compose with
          // server-side range paging (this function owns paging+sort) and are ignored here; the
          // other filters (alertState, severityLevel, searchString, monitorId) still pass through.
          const passthrough: Record<string, any> = {};
          for (const key of ['alertState', 'severityLevel', 'searchString', 'monitorId']) {
            if (q[key] !== undefined) passthrough[key] = q[key];
          }
          const raw = await fetchAlertsInRange(esClient, from, passthrough);
          const normalized = raw.map((a: any) => normalizeAlert(a, rules));
          alerts = filterAlertsByRange(normalized, from, to);
          total = alerts.length;
        } else {
          // Existing (unpaged) behavior — byte-identical to pre-WS-3, pass through only the params
          // the Alerting API knows about.
          const querystring: Record<string, any> = {};
          for (const key of knownKeys) {
            if (q[key] !== undefined) {
              querystring[key] = q[key];
            }
          }
          const resp = await esClient.transport.request({
            method: 'GET',
            path: '/_plugins/_alerting/monitors/alerts',
            querystring,
          });
          const body = (resp as any).body;
          alerts = (body?.alerts ?? []).map((a: any) => normalizeAlert(a, rules));
          total = body?.totalAlerts ?? alerts.length;
        }

        // PROB-29: merge the honest reopen display-overrides. Additive only — `total` is unchanged
        // (the merge annotates alerts and lazily prunes dead override SOs; it never adds/removes rows).
        alerts = await mergeAlertOverrides(soClient, alerts, logger);

        return response.ok({ body: { alerts, total } });
      } catch (err) {
        logger.error(`tlsoc alerts list failed: ${err.message}`);
        return response.customError({
          statusCode: err.meta?.statusCode ?? 500,
          body: {
            message: `Could not list alerts: ${err.message}`,
            attributes: err.meta?.body,
          },
        });
      }
    }
  );

  // -------------------------------------------------------------------------
  // POST /api/tlsoc/alerts/_acknowledge — acknowledge alerts for one monitor
  // -------------------------------------------------------------------------
  router.post(
    {
      path: '/api/tlsoc/alerts/_acknowledge',
      validate: {
        body: schema.object({
          monitorId: schema.string(),
          alertIds: schema.arrayOf(schema.string(), { minSize: 1 }),
        }),
      },
    },
    async (context, request, response) => {
      // 5b.3c matrix: L1 analysts + managers acknowledge; detection engineers do not.
      if (!callerHasAnyRole(request, auth, ALERT_ACKNOWLEDGERS)) {
        return forbidden(response, 'acknowledge alerts');
      }
      const { monitorId, alertIds } = request.body as { monitorId: string; alertIds: string[] };
      try {
        const esClient = context.core.opensearch.client.asCurrentUser;
        const resp = await esClient.transport.request(
          {
            method: 'POST',
            path: `/_plugins/_alerting/monitors/${monitorId}/_acknowledge/alerts`,
            body: { alerts: alertIds }, // VERIFIED LIVE: field is "alerts", not "alert_ids"
          },
          // Fast-fail: the OpenSearch Alerting acknowledge action can deadlock cluster-side
          // (observed live: stuck, uncancellable ack tasks → ~120s silent hang). Cap the wait so
          // the UI gets a clear error toast in seconds instead of spinning. maxRetries:0 so a
          // timeout isn't multiplied by retries. Never fires when the engine is healthy (ack is ms).
          { requestTimeout: 15000, maxRetries: 0 }
        );
        const body = (resp as any).body;
        // PROB-29: the analyst finished this alert again — clear any reopen display-override so it
        // stops reading as reactivated. Best-effort + non-blocking: the acknowledge already
        // succeeded, so a failed override cleanup must never turn a 200 into an error (it self-heals
        // via the LIST merge's lazy stale-cleanup once the engine completes the alert anyway).
        void deleteAlertOverrides(
          context.core.savedObjects.client,
          alertIds,
          logger,
          'acknowledged again'
        ).catch((e) => logger.warn(`tlsoc acknowledge: override cleanup failed: ${e.message}`));
        return response.ok({ body: { success: body?.success ?? [], failed: body?.failed ?? [] } });
      } catch (err) {
        const isTimeout =
          err?.name === 'TimeoutError' || /timed?\s*out/i.test(err?.message ?? '');
        logger.error(`tlsoc acknowledge failed: ${err.message}`);
        return response.customError({
          statusCode: isTimeout ? 504 : err.meta?.statusCode ?? 500,
          body: {
            message: isTimeout
              ? 'Acknowledge timed out — the OpenSearch alerting service did not respond in time. ' +
                'It may be overloaded or need a restart; please try again.'
              : `Could not acknowledge alerts: ${err.message}`,
            attributes: err.meta?.body,
          },
        });
      }
    }
  );

  // -------------------------------------------------------------------------
  // POST /api/tlsoc/alerts/_related_docs — fetch the source docs behind an alert's relatedDocIds
  // (WS-1, PROB-1: the flyout's event-context fetch — related_doc_ids are "docId|index" pairs).
  // -------------------------------------------------------------------------
  router.post(
    {
      path: '/api/tlsoc/alerts/_related_docs',
      validate: {
        body: schema.object({
          ids: schema.arrayOf(schema.string(), { minSize: 1, maxSize: 20 }),
        }),
      },
    },
    async (context, request, response) => {
      const { ids } = request.body as { ids: string[] };
      try {
        // Each id is "docId|index" (public/alerts/format.ts documents the shape). Split on the
        // LAST "|" — doc ids shouldn't contain "|", but this stays correct if one ever does.
        const parsed = ids.map((raw) => {
          const sep = raw.lastIndexOf('|');
          return sep === -1
            ? { raw, id: raw, index: '' }
            : { raw, id: raw.slice(0, sep), index: raw.slice(sep + 1) };
        });

        const idsByIndex = new Map<string, string[]>();
        for (const p of parsed) {
          if (!p.index) continue; // no parseable index → reported not-found below, no query issued
          const list = idsByIndex.get(p.index) ?? [];
          list.push(p.id);
          idsByIndex.set(p.index, list);
        }

        const esClient = context.core.opensearch.client.asCurrentUser;
        // key: `${docId}|${index}` → the doc's raw _source.
        const foundSources = new Map<string, Record<string, unknown>>();

        await Promise.all(
          Array.from(idsByIndex.entries()).map(async ([index, docIds]) => {
            try {
              const { body } = await esClient.search({
                index,
                body: { query: { ids: { values: docIds } }, size: docIds.length },
                ignore_unavailable: true,
                allow_no_indices: true,
              });
              const hits = (body as any)?.hits?.hits ?? [];
              for (const hit of hits) {
                foundSources.set(`${hit._id}|${index}`, hit._source ?? {});
              }
            } catch (err) {
              // Tolerate a per-index failure (e.g. a deleted/missing index) — those docs simply
              // report found:false below rather than failing the whole request.
              logger.warn(`tlsoc related-docs: search on "${index}" failed: ${err.message}`);
            }
          })
        );

        const docs = parsed.map((p) => {
          const source = foundSources.get(`${p.id}|${p.index}`);
          return {
            id: p.id,
            index: p.index,
            found: source !== undefined,
            ...(source !== undefined ? { source } : {}),
          };
        });

        return response.ok({ body: { docs } });
      } catch (err) {
        logger.error(`tlsoc related-docs failed: ${err.message}`);
        return response.customError({
          statusCode: err.meta?.statusCode ?? 500,
          body: { message: `Could not fetch related documents: ${err.message}`, attributes: err.meta?.body },
        });
      }
    }
  );

  // -------------------------------------------------------------------------
  // GET /api/tlsoc/findings
  // -------------------------------------------------------------------------
  router.get(
    {
      path: '/api/tlsoc/findings',
      validate: {
        query: schema.object(
          {
            searchString: schema.maybe(schema.string()),
            sortString: schema.maybe(schema.string()),
            sortOrder: schema.maybe(schema.string()),
            size: schema.maybe(schema.number()),
            startIndex: schema.maybe(schema.number()),
          },
          { unknowns: 'ignore' }
        ),
      },
    },
    async (context, request, response) => {
      try {
        const q = request.query as Record<string, any>;
        const knownKeys = ['searchString', 'sortString', 'sortOrder', 'size', 'startIndex'];
        const querystring: Record<string, any> = {};
        for (const key of knownKeys) {
          if (q[key] !== undefined) {
            querystring[key] = q[key];
          }
        }

        const esClient = context.core.opensearch.client.asCurrentUser;
        const resp = await esClient.transport.request({
          method: 'GET',
          path: '/_plugins/_alerting/findings/_search',
          querystring,
        });

        const soClient = context.core.savedObjects.client;
        const rules = await buildRuleRefMap(soClient);

        const body = (resp as any).body;
        // Each element is { finding: RawFinding, document_list: any[] } — normalizeFinding unwraps.
        const findings = (body?.findings ?? []).map((wrapper: any) =>
          normalizeFinding(wrapper, rules)
        );

        return response.ok({ body: { findings, total: body?.total_findings ?? findings.length } });
      } catch (err) {
        logger.error(`tlsoc findings list failed: ${err.message}`);
        return response.customError({
          statusCode: err.meta?.statusCode ?? 500,
          body: {
            message: `Could not list findings: ${err.message}`,
            attributes: err.meta?.body,
          },
        });
      }
    }
  );
}
