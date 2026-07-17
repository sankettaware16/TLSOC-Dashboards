/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { schema } from '@osd/config-schema';
import { HttpAuth, IRouter, Logger, SavedObjectsClientContract } from '../../../../core/server';
import {
  callerHasAnyRole,
  DETECTION_WRITERS,
  forbidden,
  isWorkspaceAccessError,
  workspaceForbidden,
} from '../lib/authz';
import {
  DetectionRuleAttributes,
  RuleDefinition,
  ThresholdRuleDefinition,
  buildMonitorForSave,
  deriveAliasName,
  desiredExecutionTargets,
  executionTargetsDiffer,
} from '../../common/detection';
import { DETECTION_RULE_SO_TYPE } from '../saved_objects';

/* eslint-disable @typescript-eslint/no-explicit-any */

const MONITOR_API = '/_plugins/_alerting/monitors';
const TYPE = DETECTION_RULE_SO_TYPE;

/** An error carrying the HTTP status to surface (used by the shared prepare/dedup helpers). */
class RouteError extends Error {
  constructor(public statusCode: number, message: string, public attributes?: any) {
    super(message);
  }
}

type EsClient = any;
type SaveBody = {
  mode: 'stateful' | 'stateless';
  rule: Record<string, unknown>;
  /** PROB-19: create/update-time enable state. Absent → default true (create) or "keep current" (update). */
  enabled?: boolean;
};

/**
 * Resolve an index PATTERN to its current concrete index names via `cat.indices` — same idiom as
 * `server/routes/data_views.ts`'s `_ensure` route. A 404 (nothing matches) or any other cat.indices
 * error both degrade to `[]` (treated as "nothing to run against yet" by callers); non-404 errors
 * are logged so a real cluster problem isn't silently swallowed.
 */
async function resolveConcreteIndices(
  esClient: EsClient,
  logger: Logger,
  indexPattern: string
): Promise<string[]> {
  try {
    const catResp = await esClient.cat.indices({ index: indexPattern, format: 'json', h: 'index' });
    return ((catResp as any).body ?? [])
      .map((row: any) => row.index)
      .filter((idx: unknown): idx is string => !!idx);
  } catch (err: any) {
    const status = err?.meta?.statusCode ?? err?.statusCode;
    if (status !== 404) {
      logger.warn(`tlsoc: cat.indices for "${indexPattern}" failed, treating as no indices: ${err.message}`);
    }
    return [];
  }
}

/** Idempotently ADD one dot-free alias per concrete index (one `/_aliases` call, one action each). */
async function addPerIndexAliases(esClient: EsClient, concreteIndices: string[]): Promise<void> {
  await esClient.transport.request({
    method: 'POST',
    path: '/_aliases',
    body: {
      actions: concreteIndices.map((idx) => ({ add: { index: idx, alias: deriveAliasName(idx) } })),
    },
  });
}

/**
 * Compile a rule to its executable monitor and, for a STATELESS rule on a dotted/patterned index,
 * route it at dot-free per-CONCRETE-INDEX aliases (one alias per backing index — NOT one alias for
 * the whole pattern). Shared by create + update.
 *
 * WHY per-index, not a single pattern-level alias (the pre-hotfix approach, source-verified live on
 * the VM re-test to be a SILENT no-op the moment a pattern backs more than one concrete index):
 * OpenSearch 3.7 doc-level monitors reject both wildcard PATTERNS and dotted CONCRETE index names at
 * creation (verified live) — a stateless rule on a pattern must run against a dot-free alias. But
 * OS 3.7's doc-level runner only persists scan-checkpoint context for an alias's WRITE index
 * (source-confirmed: `MonitorMetadataService.createFullRunContext` → `IndexUtils.getWriteIndex`
 * returns `null` for a multi-backed alias with no write index → the run context resets to `{}`
 * every run → a zero-width scan window → the monitor finds nothing, EVER, with NO error — upstream
 * alerting issue #1290). Flagging `is_write_index` only "heals" ONE of the backing indices; the
 * rest stay permanently dead. FIX: one dot-free alias PER CONCRETE INDEX — each is single-backed so
 * it always has an implicit write index and its run context persists correctly (verified live on
 * the VM: 2/2 injected docs alerted with per-index aliases in the `doc_level_input.indices` list).
 */
async function prepareMonitor(
  esClient: EsClient,
  logger: Logger,
  mode: 'stateful' | 'stateless',
  rule: Record<string, unknown>
): Promise<{ monitor: Record<string, any>; executionAlias?: string; executionTargets?: string[] }> {
  let monitor: Record<string, any>;
  try {
    monitor = buildMonitorForSave(
      mode,
      (rule as unknown) as RuleDefinition & ThresholdRuleDefinition
    ) as any;
  } catch (err) {
    throw new RouteError(400, `Rule did not compile: ${err.message}`);
  }

  let executionAlias: string | undefined;
  let executionTargets: string[] | undefined;
  const ruleIndex = ((rule as any).index as string) ?? '';
  if (mode === 'stateless' && /[.*]/.test(ruleIndex)) {
    // Display-identity string only (backcompat for existing LIST/GET-ONE/UI consumers) — NOT
    // necessarily a live alias any more; `executionTargets` below is what the monitor actually runs.
    executionAlias = deriveAliasName(ruleIndex);

    const concreteIndices = await resolveConcreteIndices(esClient, logger, ruleIndex);
    if (concreteIndices.length === 0) {
      throw new RouteError(
        400,
        `No indices currently match "${ruleIndex}", so there is nothing for a single-event rule to run against yet.`
      );
    }

    executionTargets = desiredExecutionTargets(concreteIndices);
    try {
      await addPerIndexAliases(esClient, concreteIndices);
    } catch (err) {
      throw new RouteError(
        err.meta?.statusCode ?? 400,
        `Could not link "${ruleIndex}"'s indices to per-index aliases for single-event detection: ${err.message}`
      );
    }
    monitor.inputs[0].doc_level_input.indices = executionTargets;
  }
  return { monitor, executionAlias, executionTargets };
}

/**
 * Module-level debounce for {@link syncStatelessMonitorTargets}: it's invoked fire-and-forget on
 * every `GET /api/tlsoc/alerts` poll (the Alerts page auto-refreshes every ~30s) — this timestamp
 * caps a full drift-repair sweep to at most once per DEBOUNCE_MS, regardless of how many concurrent
 * pollers (open tabs) call it.
 */
let lastStatelessSyncAt = 0;
const STATELESS_SYNC_DEBOUNCE_MS = 60000;

/**
 * Drift repair for stateless (doc-level) rules whose index PATTERN's backing concrete indices
 * changed since the rule was last saved — daily index rotation, a new per-endpoint index joining
 * the pattern, an old one aging out of an ISM policy — WITHOUT requiring the user to re-save the
 * rule. For each stateless rule on a patterned/dotted index: resolve the pattern to its CURRENT
 * concrete indices, compute the desired per-index alias set ({@link desiredExecutionTargets}),
 * compare it to what the LIVE monitor's `doc_level_input.indices` currently lists
 * ({@link executionTargetsDiffer}); if they differ, ensure the (possibly new) aliases exist, PUT
 * the monitor with the new sorted target list, and update the rule SO's `executionTargets`.
 *
 * Debounced (see above) — cheap to call on every request. NEVER throws: a sync hiccup, or a single
 * rule's failure, must not break the caller's actual request (the Alerts list) — every failure is
 * caught, logged, and that rule is skipped (a later sweep will retry it).
 */
export async function syncStatelessMonitorTargets(
  esClient: EsClient,
  soClient: SavedObjectsClientContract,
  logger: Logger
): Promise<void> {
  const now = Date.now();
  if (now - lastStatelessSyncAt < STATELESS_SYNC_DEBOUNCE_MS) return;
  lastStatelessSyncAt = now;

  let statelessRules: Array<{ id: string; attributes: DetectionRuleAttributes }>;
  try {
    // Same "scan all + filter" idiom as buildRuleRefMap (server/routes/alerts.ts) — this SO type
    // has no dedicated query filter set up, and 1000 rules is the plugin-wide honesty cap already
    // used everywhere else this SO type is scanned.
    const found = await soClient.find<DetectionRuleAttributes>({ type: TYPE, perPage: 1000 });
    statelessRules = found.saved_objects.filter((so) => so.attributes.mode === 'stateless');
  } catch (err) {
    logger.warn(`tlsoc syncStatelessMonitorTargets: could not list rules, skipping this sweep: ${err.message}`);
    return;
  }

  for (const so of statelessRules) {
    const ruleIndex = (so.attributes.rule as any)?.index as string | undefined;
    if (!ruleIndex || !/[.*]/.test(ruleIndex)) continue; // not patterned/dotted → no aliasing involved

    try {
      const concreteIndices = await resolveConcreteIndices(esClient, logger, ruleIndex);
      if (concreteIndices.length === 0) continue; // nothing to sync against right now

      const desired = desiredExecutionTargets(concreteIndices);

      const monitorResp = await esClient.transport.request({
        method: 'GET',
        path: `${MONITOR_API}/${so.attributes.monitorId}`,
      });
      const monitor = (monitorResp as any).body?.monitor;
      const current: string[] = monitor?.inputs?.[0]?.doc_level_input?.indices ?? [];

      if (!executionTargetsDiffer(current, desired)) continue; // already in sync — cheap no-op

      if (!monitor?.inputs?.[0]?.doc_level_input) {
        logger.warn(
          `tlsoc syncStatelessMonitorTargets: monitor ${so.attributes.monitorId} has no doc_level_input, skipping "${so.attributes.name}"`
        );
        continue;
      }

      await addPerIndexAliases(esClient, concreteIndices);

      monitor.inputs[0].doc_level_input.indices = desired;
      await esClient.transport.request({
        method: 'PUT',
        path: `${MONITOR_API}/${so.attributes.monitorId}`,
        body: monitor,
        querystring: {
          refresh: 'wait_for',
          if_seq_no: (monitorResp as any).body?._seq_no,
          if_primary_term: (monitorResp as any).body?._primary_term,
        },
      });

      await soClient.create<DetectionRuleAttributes>(
        TYPE,
        { ...so.attributes, executionTargets: desired },
        { id: so.id, overwrite: true }
      );

      logger.info(
        `tlsoc syncStatelessMonitorTargets: "${so.attributes.name}" execution targets drifted — re-synced to ${desired.length} index alias(es)`
      );
    } catch (err) {
      logger.warn(
        `tlsoc syncStatelessMonitorTargets: sync failed for "${so.attributes.name}" (${so.id}), skipping: ${err.message}`
      );
    }
  }
}

/** Is `name` already used by ANOTHER TLSOC detection (excluding `excludeSoId`)? */
async function nameConflict(
  soClient: SavedObjectsClientContract,
  name: string,
  excludeSoId?: string
): Promise<boolean> {
  const found = await soClient.find<DetectionRuleAttributes>({
    type: TYPE,
    search: `"${name}"`,
    searchFields: ['name'],
    perPage: 100,
  });
  return found.saved_objects.some((so) => so.attributes.name === name && so.id !== excludeSoId);
}

const bodyValidation = {
  body: schema.object({
    mode: schema.oneOf([schema.literal('stateful'), schema.literal('stateless')]),
    rule: schema.object({}, { unknowns: 'allow' }),
    enabled: schema.maybe(schema.boolean()),
  }),
};
const idParam = { params: schema.object({ soId: schema.string() }) };
const toggleValidation = {
  params: schema.object({ soId: schema.string() }),
  body: schema.object({ enabled: schema.boolean() }),
};

/** Register all detection-monitor management routes (create / list / get / update / delete). */
export function registerMonitorRoutes(router: IRouter, logger: Logger, auth?: HttpAuth) {
  // CREATE — POST /api/tlsoc/detection/monitors
  router.post({ path: '/api/tlsoc/detection/monitors', validate: bodyValidation }, async (context, request, response) => {
    // 5b.3c matrix: only detection engineers (and superusers) manage detections.
    if (!callerHasAnyRole(request, auth, DETECTION_WRITERS)) {
      return forbidden(response, 'create detections');
    }
    const { mode, rule, enabled } = request.body as SaveBody;
    const soClient = context.core.savedObjects.client;
    const esClient = context.core.opensearch.client.asCurrentUser;
    const name = ((rule as any).name as string)?.trim() || 'Untitled detection';
    const severity = ((rule as any).severity as string) ?? 'medium';

    let monitor: Record<string, any>;
    let executionAlias: string | undefined;
    let executionTargets: string[] | undefined;
    try {
      if (await nameConflict(soClient, name)) {
        return response.customError({
          statusCode: 409,
          body: { message: `A detection named "${name}" already exists. Rename it, or edit the existing one.` },
        });
      }
      ({ monitor, executionAlias, executionTargets } = await prepareMonitor(esClient, logger, mode, rule));
      // Compiler always emits `enabled: true` — apply the caller's intent (default true) here.
      monitor.enabled = enabled ?? true;
    } catch (err) {
      if (err instanceof RouteError) {
        return response.customError({ statusCode: err.statusCode, body: { message: err.message } });
      }
      logger.error(`tlsoc create: ${err.message}`);
      return response.customError({ statusCode: 500, body: { message: err.message } });
    }

    let monitorId: string;
    try {
      const created = await esClient.transport.request({
        method: 'POST',
        path: MONITOR_API,
        body: monitor,
        querystring: { refresh: 'wait_for' },
      });
      monitorId = (created as any).body?._id;
      if (!monitorId) throw new Error('Alerting did not return a monitor id');
    } catch (err) {
      logger.error(`tlsoc create: monitor create failed: ${err.message}`);
      return response.customError({
        statusCode: err.meta?.statusCode ?? 500,
        body: { message: `Could not save detection: ${err.message}`, attributes: err.meta?.body },
      });
    }

    try {
      const so = await soClient.create<DetectionRuleAttributes>(TYPE, {
        name,
        mode,
        severity,
        monitorId,
        rule: (rule as unknown) as RuleDefinition | ThresholdRuleDefinition,
        ...(executionAlias ? { executionAlias } : {}),
        ...(executionTargets ? { executionTargets } : {}),
        enabled: enabled ?? true,
        createdAt: new Date().toISOString(),
      });
      return response.ok({ body: { id: monitorId, soId: so.id, name, executionAlias } });
    } catch (err) {
      logger.error(`tlsoc create: SO failed, rolling back monitor ${monitorId}: ${err.message}`);
      try {
        await esClient.transport.request({ method: 'DELETE', path: `${MONITOR_API}/${monitorId}` });
      } catch (rbErr) {
        logger.error(`tlsoc create: rollback failed: ${rbErr.message}`);
      }
      return response.customError({
        statusCode: 500,
        body: { message: `Could not record the detection rule; the monitor was rolled back: ${err.message}` },
      });
    }
  });

  // LIST — GET /api/tlsoc/detection/monitors
  router.get({ path: '/api/tlsoc/detection/monitors', validate: false }, async (context, request, response) => {
    const soClient = context.core.savedObjects.client;
    const esClient = context.core.opensearch.client.asCurrentUser;
    try {
      const found = await soClient.find<DetectionRuleAttributes>({ type: TYPE, perPage: 1000 });
      const rules = found.saved_objects.map((so) => ({
        soId: so.id,
        name: so.attributes.name,
        mode: so.attributes.mode,
        severity: so.attributes.severity,
        index: so.attributes.rule?.index,
        executionAlias: so.attributes.executionAlias,
        monitorId: so.attributes.monitorId,
        enabled: so.attributes.enabled ?? true,
        createdAt: so.attributes.createdAt,
      }));

      // Best-effort live reconciliation: the SO's `enabled` can drift from the monitor's actual
      // state (e.g. someone toggled it directly in Alerting). Live wins when we can read it;
      // any failure here must never fail the list request — the SO values just stand.
      try {
        const monitorIds = rules.map((r) => r.monitorId).filter((id): id is string => !!id);
        if (monitorIds.length > 0) {
          const searchResp = await esClient.transport.request({
            method: 'POST',
            path: `${MONITOR_API}/_search`,
            body: {
              query: { ids: { values: monitorIds } },
              _source: { includes: ['monitor.enabled'] },
            },
          });
          const hits: any[] = (searchResp as any).body?.hits?.hits ?? [];
          const liveEnabled = new Map<string, boolean>();
          hits.forEach((hit) => {
            const val = hit?._source?.monitor?.enabled;
            if (typeof val === 'boolean') liveEnabled.set(hit._id, val);
          });
          rules.forEach((r) => {
            const live = liveEnabled.get(r.monitorId);
            if (typeof live === 'boolean') r.enabled = live;
          });
        }
      } catch (err) {
        logger.warn(`tlsoc list: live enabled-state reconciliation skipped: ${err.message}`);
      }

      rules.sort((a, b) => (b.createdAt ?? '').localeCompare(a.createdAt ?? ''));
      return response.ok({ body: { rules } });
    } catch (err) {
      if (isWorkspaceAccessError(err)) return workspaceForbidden(response);
      logger.error(`tlsoc list: ${err.message}`);
      return response.customError({ statusCode: 500, body: { message: `Could not list detections: ${err.message}` } });
    }
  });

  // GET ONE — GET /api/tlsoc/detection/monitors/{soId} (for edit hydration)
  router.get({ path: '/api/tlsoc/detection/monitors/{soId}', validate: idParam }, async (context, request, response) => {
    const soClient = context.core.savedObjects.client;
    const { soId } = request.params as { soId: string };
    try {
      const so = await soClient.get<DetectionRuleAttributes>(TYPE, soId);
      const a = so.attributes;
      return response.ok({
        body: {
          soId: so.id,
          name: a.name,
          mode: a.mode,
          severity: a.severity,
          rule: a.rule,
          monitorId: a.monitorId,
          executionAlias: a.executionAlias,
          enabled: a.enabled ?? true,
        },
      });
    } catch (err) {
      if (err?.output?.statusCode === 404 || err?.statusCode === 404) {
        return response.notFound({ body: { message: `Detection ${soId} not found.` } });
      }
      logger.error(`tlsoc get: ${err.message}`);
      return response.customError({ statusCode: 500, body: { message: `Could not load detection: ${err.message}` } });
    }
  });

  // UPDATE — PUT /api/tlsoc/detection/monitors/{soId}
  router.put(
    { path: '/api/tlsoc/detection/monitors/{soId}', validate: { ...idParam, ...bodyValidation } },
    async (context, request, response) => {
      if (!callerHasAnyRole(request, auth, DETECTION_WRITERS)) {
        return forbidden(response, 'edit detections');
      }
      const { mode, rule, enabled } = request.body as SaveBody;
      const { soId } = request.params as { soId: string };
      const soClient = context.core.savedObjects.client;
      const esClient = context.core.opensearch.client.asCurrentUser;
      const name = ((rule as any).name as string)?.trim() || 'Untitled detection';
      const severity = ((rule as any).severity as string) ?? 'medium';

      let existing;
      try {
        existing = await soClient.get<DetectionRuleAttributes>(TYPE, soId);
      } catch (err) {
        return response.notFound({ body: { message: `Detection ${soId} not found.` } });
      }
      const monitorId = existing.attributes.monitorId;
      // THE TRAP: `prepareMonitor`'s compiler always emits `enabled: true` — without this, saving an
      // edit to a currently-DISABLED rule would silently re-enable it. Preserve the existing SO's
      // enabled state unless the caller explicitly passed one.
      const nextEnabled = enabled ?? existing.attributes.enabled ?? true;

      let monitor: Record<string, any>;
      let executionAlias: string | undefined;
      let executionTargets: string[] | undefined;
      try {
        // Dedup EXCLUDING self — editing a rule under its own name must not 409.
        if (await nameConflict(soClient, name, soId)) {
          return response.customError({
            statusCode: 409,
            body: { message: `Another detection named "${name}" already exists.` },
          });
        }
        ({ monitor, executionAlias, executionTargets } = await prepareMonitor(esClient, logger, mode, rule));
        monitor.enabled = nextEnabled;
      } catch (err) {
        if (err instanceof RouteError) {
          return response.customError({ statusCode: err.statusCode, body: { message: err.message } });
        }
        return response.customError({ statusCode: 500, body: { message: err.message } });
      }

      // Capture the current monitor body for rollback, then update it with optimistic concurrency.
      let oldBody: any;
      try {
        const cur = await esClient.transport.request({ method: 'GET', path: `${MONITOR_API}/${monitorId}` });
        oldBody = (cur as any).body?.monitor;
        const seqNo = (cur as any).body?._seq_no;
        const primaryTerm = (cur as any).body?._primary_term;
        await esClient.transport.request({
          method: 'PUT',
          path: `${MONITOR_API}/${monitorId}`,
          body: monitor,
          querystring: { refresh: 'wait_for', if_seq_no: seqNo, if_primary_term: primaryTerm },
        });
      } catch (err) {
        logger.error(`tlsoc update: monitor PUT failed: ${err.message}`);
        return response.customError({
          statusCode: err.meta?.statusCode ?? 500,
          body: { message: `Could not update detection: ${err.message}`, attributes: err.meta?.body },
        });
      }

      // Replace the SO (full overwrite, so a stateful edit drops a stale executionAlias/Targets). On
      // failure, revert the monitor to its captured previous body so the two stores never drift.
      try {
        await soClient.create<DetectionRuleAttributes>(
          TYPE,
          {
            name,
            mode,
            severity,
            monitorId,
            rule: (rule as unknown) as RuleDefinition | ThresholdRuleDefinition,
            ...(executionAlias ? { executionAlias } : {}),
            ...(executionTargets ? { executionTargets } : {}),
            enabled: nextEnabled,
            createdAt: existing.attributes.createdAt,
          },
          { id: soId, overwrite: true }
        );
        return response.ok({ body: { id: monitorId, soId, name, executionAlias } });
      } catch (err) {
        logger.error(`tlsoc update: SO failed, reverting monitor ${monitorId}: ${err.message}`);
        try {
          if (oldBody) {
            await esClient.transport.request({
              method: 'PUT',
              path: `${MONITOR_API}/${monitorId}`,
              body: oldBody,
              querystring: { refresh: 'wait_for' },
            });
          }
        } catch (rbErr) {
          logger.error(`tlsoc update: monitor revert failed: ${rbErr.message}`);
        }
        return response.customError({
          statusCode: 500,
          body: { message: `Could not record the updated rule; the monitor was reverted: ${err.message}` },
        });
      }
    }
  );

  // TOGGLE — POST /api/tlsoc/detection/monitors/{soId}/_toggle (PROB-19: enable/disable without a
  // full edit round-trip). Same GET-then-PUT-with-concurrency idiom as UPDATE's monitor write, but
  // touches only `enabled` — the rest of the monitor body is left exactly as Alerting has it.
  router.post(
    { path: '/api/tlsoc/detection/monitors/{soId}/_toggle', validate: toggleValidation },
    async (context, request, response) => {
      if (!callerHasAnyRole(request, auth, DETECTION_WRITERS)) {
        return forbidden(response, 'toggle detections');
      }
      const { soId } = request.params as { soId: string };
      const { enabled } = request.body as { enabled: boolean };
      const soClient = context.core.savedObjects.client;
      const esClient = context.core.opensearch.client.asCurrentUser;

      let so;
      try {
        so = await soClient.get<DetectionRuleAttributes>(TYPE, soId);
      } catch (err) {
        return response.notFound({ body: { message: `Detection ${soId} not found.` } });
      }
      const monitorId = so.attributes.monitorId;

      try {
        const cur = await esClient.transport.request({ method: 'GET', path: `${MONITOR_API}/${monitorId}` });
        const monitor = (cur as any).body?.monitor;
        if (!monitor) throw new Error('Alerting returned no monitor body');
        const seqNo = (cur as any).body?._seq_no;
        const primaryTerm = (cur as any).body?._primary_term;
        monitor.enabled = enabled;
        await esClient.transport.request({
          method: 'PUT',
          path: `${MONITOR_API}/${monitorId}`,
          body: monitor,
          querystring: { refresh: 'wait_for', if_seq_no: seqNo, if_primary_term: primaryTerm },
        });
      } catch (err) {
        logger.error(`tlsoc toggle: monitor PUT failed: ${err.message}`);
        return response.customError({
          statusCode: err.meta?.statusCode ?? 500,
          body: { message: `Could not ${enabled ? 'enable' : 'disable'} the detection: ${err.message}` },
        });
      }

      try {
        await soClient.create<DetectionRuleAttributes>(
          TYPE,
          { ...so.attributes, enabled },
          { id: soId, overwrite: true }
        );
        return response.ok({ body: { enabled } });
      } catch (err) {
        logger.error(`tlsoc toggle: SO write failed for ${soId}: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: {
            message: `The monitor was ${
              enabled ? 'enabled' : 'disabled'
            }, but recording it failed: ${err.message}`,
          },
        });
      }
    }
  );

  // DELETE — DELETE /api/tlsoc/detection/monitors/{soId}
  router.delete({ path: '/api/tlsoc/detection/monitors/{soId}', validate: idParam }, async (context, request, response) => {
    if (!callerHasAnyRole(request, auth, DETECTION_WRITERS)) {
      return forbidden(response, 'delete detections');
    }
    const soClient = context.core.savedObjects.client;
    const esClient = context.core.opensearch.client.asCurrentUser;
    const { soId } = request.params as { soId: string };

    let so;
    try {
      so = await soClient.get<DetectionRuleAttributes>(TYPE, soId);
    } catch (err) {
      return response.notFound({ body: { message: `Detection ${soId} not found.` } });
    }
    const { monitorId, executionAlias, executionTargets, rule } = so.attributes;

    // Delete the monitor first (tolerate already-gone so delete is idempotent), then the SO.
    try {
      await esClient.transport.request({ method: 'DELETE', path: `${MONITOR_API}/${monitorId}` });
    } catch (err) {
      if ((err.meta?.statusCode ?? err.statusCode) !== 404) {
        logger.error(`tlsoc delete: monitor delete failed: ${err.message}`);
        return response.customError({
          statusCode: err.meta?.statusCode ?? 500,
          body: { message: `Could not delete the detection's monitor: ${err.message}` },
        });
      }
    }
    try {
      await soClient.delete(TYPE, soId);
    } catch (err) {
      logger.error(`tlsoc delete: SO delete failed: ${err.message}`);
      return response.customError({ statusCode: 500, body: { message: `Could not delete detection: ${err.message}` } });
    }

    // Alias orphan cleanup: drop aliases only if no OTHER rule still uses them (TLSOC removes only
    // what it backfilled — aliases the user's Logstash template adds to future indices are theirs).
    // Covers BOTH the legacy pattern-level `executionAlias` (pre-hotfix rules that actually created
    // it) and the WS-hotfix per-index `executionTargets` (which may not correspond to `rule.index`
    // at all, so each is removed via a wildcard index target rather than assuming `rule.index`).
    if (executionAlias || (executionTargets && executionTargets.length > 0)) {
      try {
        const others = await soClient.find<DetectionRuleAttributes>({ type: TYPE, perPage: 1000 });

        if (executionAlias && rule?.index) {
          const stillUsed = others.saved_objects.some((o) => o.attributes.executionAlias === executionAlias);
          if (!stillUsed) {
            await esClient.transport
              .request({
                method: 'POST',
                path: '/_aliases',
                body: { actions: [{ remove: { index: rule.index, alias: executionAlias } }] },
              })
              .catch((err: any) =>
                logger.warn(`tlsoc delete: alias cleanup for ${executionAlias} skipped: ${err.message}`)
              );
          }
        }

        if (executionTargets && executionTargets.length > 0) {
          const stillUsedTargets = new Set<string>();
          others.saved_objects.forEach((o) =>
            (o.attributes.executionTargets ?? []).forEach((t) => stillUsedTargets.add(t))
          );
          const toRemove = executionTargets.filter((t) => !stillUsedTargets.has(t));
          await Promise.all(
            toRemove.map((alias) =>
              esClient.transport
                .request({
                  method: 'POST',
                  path: '/_aliases',
                  // Removed via a wildcard index target — we don't track which concrete index each
                  // per-index alias is attached to, and the alias name isn't reversible to it.
                  body: { actions: [{ remove: { index: '*', alias } }] },
                })
                .catch((err: any) =>
                  logger.warn(`tlsoc delete: execution-target alias cleanup for ${alias} skipped: ${err.message}`)
                )
            )
          );
        }
      } catch (err) {
        logger.warn(`tlsoc delete: alias cleanup skipped: ${err.message}`);
      }
    }
    return response.ok({ body: { deleted: true } });
  });
}
