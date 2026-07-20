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
  VALUE_LISTS_INDEX,
  VALUE_LIST_INLINE_MAX_VALUES,
  ValueListType,
  assertValidValueListInput,
  isValidValueListType,
  VALUE_LIST_TYPES,
  valueListIdFromName,
} from '../../common/value_lists';
import {
  INDICATOR_MATCH_MODE,
  IndicatorListMode,
  IndicatorMatchRuleDefinition,
  buildInlineIndicatorQuery,
  pickIndicatorListMode,
} from '../../common/detection/indicator_match';
import { DetectionRuleAttributes } from '../../common/detection';
import { DETECTION_RULE_SO_TYPE } from '../saved_objects';

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Value-list CRUD (v1.2.3 D6) — the storage layer behind Threat Intel's list manager and the
 * indicator-match rules' terms-lookup target.
 *
 * Storage: ONE doc per list in the TLSOC-owned cluster index {@link VALUE_LISTS_INDEX}
 * (`_id` = slug of the name, `{name, type, values[], updated_at}`), so the doc is DIRECTLY the
 * engine's terms-lookup target — a saved object can never be one without pointing analyst
 * monitors at `.kibana*` (research_r5 §3.4, the final storage ruling). All operations run with
 * the CALLER's credentials (`asCurrentUser`, the repo-wide pattern): the engine executes
 * monitors under the rule AUTHOR's security context, so the same roles that write rules must be
 * able to read this index anyway.
 *
 * PAYLOAD CAP (documented, research_r5 RISKS): OSD's route body default is 1,048,576 bytes
 * (src/core/server/http/http_config.ts) — one create/update request carries roughly 50-60k
 * short values. The hard per-list ceiling is 65536 (index.max_terms_count — the engine refuses
 * larger lookups at every monitor run, loudly); lists of long values near that ceiling would
 * need chunked updates, deliberately NOT built in v1.2.3.
 */

const MONITOR_API = '/_plugins/_alerting/monitors';
const LISTS_API = '/api/tlsoc/value_lists';

type EsClient = any;

/** The stored doc shape (snake_case on the wire, camelCase in API responses). */
interface StoredValueList {
  name: string;
  type: ValueListType;
  values: string[];
  updated_at: string;
}

/** An error carrying the HTTP status to surface (mirrors the monitors.ts RouteError idiom). */
class ValueListRouteError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message);
  }
}

function statusOf(err: any): number | undefined {
  return err?.meta?.statusCode ?? err?.statusCode;
}

/**
 * Create {@link VALUE_LISTS_INDEX} if it does not exist yet (first-write bootstrap). `values`
 * is keyword-mapped (the probes' lookup-target shape); `dynamic: false` so a stray field can
 * never grow the mapping. Racing creators are fine: already-exists is swallowed.
 */
async function ensureValueListsIndex(esClient: EsClient): Promise<void> {
  try {
    await esClient.transport.request({
      method: 'PUT',
      path: `/${VALUE_LISTS_INDEX}`,
      body: {
        settings: { index: { number_of_shards: 1, auto_expand_replicas: '0-1' } },
        mappings: {
          dynamic: false,
          properties: {
            name: { type: 'keyword' },
            type: { type: 'keyword' },
            values: { type: 'keyword' },
            updated_at: { type: 'date' },
          },
        },
      },
    });
  } catch (err: any) {
    const type = err?.meta?.body?.error?.type ?? err?.body?.error?.type;
    if (type === 'resource_already_exists_exception') return;
    throw err;
  }
}

/** Fetch one list doc; returns null when the list (or the whole index) does not exist. */
async function fetchValueList(
  esClient: EsClient,
  id: string
): Promise<StoredValueList | null> {
  try {
    const resp = await esClient.transport.request({
      method: 'GET',
      path: `/${VALUE_LISTS_INDEX}/_doc/${encodeURIComponent(id)}`,
    });
    const body = (resp as any).body;
    if (!body?.found || !body?._source) return null;
    return body._source as StoredValueList;
  } catch (err: any) {
    if (statusOf(err) === 404) return null;
    throw err;
  }
}

/** All indicator-match rules, from the SO registry (the plugin-wide 1000-rule honesty cap). */
async function findIndicatorMatchRules(
  soClient: SavedObjectsClientContract
): Promise<Array<{ id: string; attributes: DetectionRuleAttributes }>> {
  const found = await soClient.find<DetectionRuleAttributes>({
    type: DETECTION_RULE_SO_TYPE,
    perPage: 1000,
  });
  return found.saved_objects.filter((so) => so.attributes.mode === INDICATOR_MATCH_MODE);
}

/**
 * THE INDICATOR-MATCH SAVE GATE — called from monitors.ts prepareMonitor (serial integration)
 * for every create AND update of an 'indicator_match' rule, with the caller's client. It:
 *  1. fetches the referenced list (400 by name when missing — a rule on a ghost list would be
 *     a silently dead rule);
 *  2. RE-PICKS the compile shape from the list's CURRENT size ({@link pickIndicatorListMode} —
 *     refuses empty/over-ceiling lists) and STAMPS it onto the rule object (`rule.listMode`),
 *     which the route then persists — the server, not the client, owns the mode;
 *  3. for 'ip' lists, verifies via field_caps that the rule's event field is ip-mapped on the
 *     rule's indices: CIDR blocks only match against `ip` fields (research_r5 §4.3) — a keyword
 *     field would accept the rule and then silently never match a CIDR (the banned class).
 *
 * Returns the list's values so the caller can compile the inline shape without a second fetch.
 * Throws errors carrying `statusCode` (400 for authoring problems; cluster failures re-throw
 * untouched) — prepareMonitor maps them onto its RouteError.
 */
export async function prepareIndicatorMatchRule(
  esClient: EsClient,
  rule: Record<string, unknown>
): Promise<{ listMode: IndicatorListMode; values: string[] }> {
  const imRule = (rule as unknown) as IndicatorMatchRuleDefinition;
  const listId = typeof imRule.listId === 'string' ? imRule.listId : '';
  const list = listId === '' ? null : await fetchValueList(esClient, listId);
  if (!list) {
    throw new ValueListRouteError(
      400,
      `Value list "${listId}" was not found — create it under Threat Intel first.`
    );
  }

  let listMode: IndicatorListMode;
  try {
    listMode = pickIndicatorListMode(list.values.length);
  } catch (err: any) {
    throw new ValueListRouteError(400, err.message);
  }
  // Server-authoritative: persisted with the rule so the UI shows the shape that executes;
  // re-stamped here on EVERY save, so an update after list growth re-picks the mode.
  (rule as any).listMode = listMode;

  if (list.type === 'ip') {
    const noIndices =
      `No indices currently match "${imRule.index}", so the event field cannot be verified as ` +
      'ip-mapped yet — there is nothing for this rule to run against.';
    let caps: any;
    try {
      const resp = await esClient.fieldCaps({
        index: imRule.index,
        fields: [imRule.eventField],
        allow_no_indices: true,
        ignore_unavailable: true,
      });
      caps = (resp as any).body ?? {};
    } catch (err: any) {
      if (statusOf(err) === 404) throw new ValueListRouteError(400, noIndices);
      throw err;
    }
    // Zero matching concrete indices → field_caps "succeeds" having checked NOTHING (the same
    // trap as _validate's 0-shards) — refuse, mirroring the PPL gate (monitors.ts).
    if ((((caps?.indices as string[] | undefined) ?? []).length === 0)) {
      throw new ValueListRouteError(400, noIndices);
    }
    const types = Object.keys(caps?.fields?.[imRule.eventField] ?? {});
    if (types.length === 0) {
      throw new ValueListRouteError(
        400,
        `Event field "${imRule.eventField}" does not exist on "${imRule.index}" — an ` +
          'indicator-match rule on it could never fire.'
      );
    }
    const nonIp = types.filter((t) => t !== 'ip');
    if (nonIp.length > 0) {
      throw new ValueListRouteError(
        400,
        `Value list "${listId}" is an IP list, but event field "${imRule.eventField}" is mapped ` +
          `as "${nonIp[0]}" on "${imRule.index}" — CIDR blocks only match against ip-mapped ` +
          'fields, so the rule would silently miss them. Pick an ip-mapped field ' +
          '(e.g. source.ip, destination.ip).'
      );
    }
  }

  return { listMode, values: list.values };
}

/**
 * Module-level debounce for {@link syncIndicatorListMonitors} — same discipline as
 * syncStatelessMonitorTargets (monitors.ts): invoked fire-and-forget from the alerts poll, so a
 * full sweep runs at most once per DEBOUNCE_MS however many tabs poll. `force` (used by the
 * list-update route, where the change is KNOWN) bypasses it.
 */
let lastIndicatorSweepAt = 0;
const INDICATOR_SWEEP_DEBOUNCE_MS = 60000;

/**
 * Drift repair for INLINE indicator-match rules: their doc-level monitors carry the list values
 * BAKED INTO the query string, so a list edit leaves the monitor matching the OLD values until
 * rewritten. This sweep recompiles each inline rule's query from the list's current values and
 * PUTs the monitor when they differ. Lookup-mode rules need nothing — the engine resolves the
 * list doc at every run.
 *
 * Honesty notes (all research_r5-verified):
 * - One-run staleness is accepted: after a PUT the engine can still match against the OLD
 *   percolation query for one run (research_r5 §5) — documented, not fought.
 * - The sweep NEVER flips a rule's mode: a list grown past the inline cap is logged and skipped
 *   (the rule keeps matching the previously compiled values) — the mode re-pick belongs to the
 *   save path, where the author sees the switch. The list-update route surfaces affected rules.
 * - NEVER throws; per-rule try/catch (a later sweep retries), the sweep must not break the
 *   caller's request (the alerts poll — the integration hook, next to syncStatelessMonitorTargets).
 */
export async function syncIndicatorListMonitors(
  esClient: EsClient,
  soClient: SavedObjectsClientContract,
  logger: Logger,
  opts: { force?: boolean } = {}
): Promise<void> {
  const now = Date.now();
  if (!opts.force && now - lastIndicatorSweepAt < INDICATOR_SWEEP_DEBOUNCE_MS) return;
  lastIndicatorSweepAt = now;

  let rules: Array<{ id: string; attributes: DetectionRuleAttributes }>;
  try {
    rules = (await findIndicatorMatchRules(soClient)).filter(
      (so) => ((so.attributes.rule as any)?.listMode as string) === 'inline'
    );
  } catch (err: any) {
    logger.warn(`tlsoc syncIndicatorListMonitors: could not list rules, skipping this sweep: ${err.message}`);
    return;
  }

  const listCache = new Map<string, StoredValueList | null>();
  for (const so of rules) {
    const rule = (so.attributes.rule as unknown) as IndicatorMatchRuleDefinition;
    try {
      if (!listCache.has(rule.listId)) {
        listCache.set(rule.listId, await fetchValueList(esClient, rule.listId));
      }
      const list = listCache.get(rule.listId);
      if (!list) {
        logger.warn(
          `tlsoc syncIndicatorListMonitors: value list "${rule.listId}" is gone — "${so.attributes.name}" keeps its last compiled values`
        );
        continue;
      }
      if (list.values.length > VALUE_LIST_INLINE_MAX_VALUES) {
        logger.warn(
          `tlsoc syncIndicatorListMonitors: list "${rule.listId}" now has ${list.values.length} values (over the inline cap) — ` +
            `"${so.attributes.name}" keeps matching its previously compiled values until it is re-saved (it will then switch to lookup mode)`
        );
        continue;
      }

      const expected = buildInlineIndicatorQuery(rule, list.values);

      const monitorResp = await esClient.transport.request({
        method: 'GET',
        path: `${MONITOR_API}/${so.attributes.monitorId}`,
      });
      const monitor = (monitorResp as any).body?.monitor;
      const query = monitor?.inputs?.[0]?.doc_level_input?.queries?.[0];
      if (!query) {
        logger.warn(
          `tlsoc syncIndicatorListMonitors: monitor ${so.attributes.monitorId} has no doc-level query, skipping "${so.attributes.name}"`
        );
        continue;
      }
      if (query.query === expected) continue; // in sync — cheap no-op

      query.query = expected;
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
      logger.info(
        `tlsoc syncIndicatorListMonitors: "${so.attributes.name}" — list "${rule.listId}" changed, inline query rewritten (${list.values.length} values)`
      );
    } catch (err: any) {
      logger.warn(
        `tlsoc syncIndicatorListMonitors: sync failed for "${so.attributes.name}" (${so.id}), skipping: ${err.message}`
      );
    }
  }
}

const idParam = { params: schema.object({ id: schema.string() }) };

/** Register the value-list CRUD routes. Writes are DETECTION_WRITERS-guarded (5b.3c matrix —
 * lists exist only to feed detection rules, so list writers == detection writers). Reads are
 * open to any authenticated user, like the detections LIST. */
export function registerValueListRoutes(router: IRouter, logger: Logger, auth?: HttpAuth) {
  // LIST — GET /api/tlsoc/value_lists
  router.get({ path: LISTS_API, validate: false }, async (context, request, response) => {
    const esClient = context.core.opensearch.client.asCurrentUser;
    const soClient = context.core.savedObjects.client;
    try {
      let hits: any[] = [];
      try {
        const resp = await esClient.transport.request({
          method: 'POST',
          path: `/${VALUE_LISTS_INDEX}/_search`,
          body: { size: 1000, sort: [{ name: 'asc' }], query: { match_all: {} } },
        });
        hits = (resp as any).body?.hits?.hits ?? [];
      } catch (err: any) {
        // No lists ever created → no index. An empty manager page, not an error.
        if (statusOf(err) !== 404) throw err;
      }

      // Best-effort linked-rules counts (one SO scan) — NEVER fails the list.
      let linkCounts: Map<string, number> | null = null;
      try {
        linkCounts = new Map();
        (await findIndicatorMatchRules(soClient)).forEach((so) => {
          const listId = (so.attributes.rule as any)?.listId as string | undefined;
          if (listId) linkCounts!.set(listId, (linkCounts!.get(listId) ?? 0) + 1);
        });
      } catch (err: any) {
        linkCounts = null;
        logger.warn(`tlsoc value_lists list: linked-rule counts skipped: ${err.message}`);
      }

      const lists = hits.map((hit) => {
        const src = (hit._source ?? {}) as StoredValueList;
        return {
          id: hit._id as string,
          name: src.name,
          type: src.type,
          count: Array.isArray(src.values) ? src.values.length : 0,
          updatedAt: src.updated_at,
          ...(linkCounts ? { linkedRules: linkCounts.get(hit._id) ?? 0 } : {}),
        };
      });
      return response.ok({ body: { lists } });
    } catch (err: any) {
      if (isWorkspaceAccessError(err)) return workspaceForbidden(response);
      logger.error(`tlsoc value_lists list: ${err.message}`);
      return response.customError({
        statusCode: statusOf(err) ?? 500,
        body: { message: `Could not list value lists: ${err.message}` },
      });
    }
  });

  // GET ONE — GET /api/tlsoc/value_lists/{id} (full values, for the edit flyout + rule editors)
  router.get({ path: `${LISTS_API}/{id}`, validate: idParam }, async (context, request, response) => {
    const esClient = context.core.opensearch.client.asCurrentUser;
    const { id } = request.params as { id: string };
    try {
      const list = await fetchValueList(esClient, id);
      if (!list) {
        return response.notFound({ body: { message: `Value list "${id}" not found.` } });
      }
      return response.ok({
        body: {
          id,
          name: list.name,
          type: list.type,
          values: list.values,
          updatedAt: list.updated_at,
        },
      });
    } catch (err: any) {
      logger.error(`tlsoc value_lists get: ${err.message}`);
      return response.customError({
        statusCode: statusOf(err) ?? 500,
        body: { message: `Could not load value list: ${err.message}` },
      });
    }
  });

  // CREATE — POST /api/tlsoc/value_lists
  router.post(
    {
      path: LISTS_API,
      validate: {
        body: schema.object({
          name: schema.string(),
          // Checked in-handler so an unknown type 400s BY NAME (the registry discipline).
          type: schema.string(),
          values: schema.arrayOf(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      if (!callerHasAnyRole(request, auth, DETECTION_WRITERS)) {
        return forbidden(response, 'create value lists');
      }
      const { name, type, values } = request.body as {
        name: string;
        type: string;
        values: string[];
      };
      if (!isValidValueListType(type)) {
        return response.badRequest({
          body: {
            message: `Unknown value list type "${type}". Supported: ${VALUE_LIST_TYPES.join(', ')}.`,
          },
        });
      }
      const trimmedName = name.trim();
      try {
        assertValidValueListInput({ name: trimmedName, type, values });
      } catch (err: any) {
        return response.badRequest({ body: { message: err.message } });
      }
      const id = valueListIdFromName(trimmedName);
      const esClient = context.core.opensearch.client.asCurrentUser;
      const updatedAt = new Date().toISOString();
      try {
        await ensureValueListsIndex(esClient);
        // `_create` makes the write conflict-checked: an existing id 409s instead of clobbering.
        await esClient.transport.request({
          method: 'PUT',
          path: `/${VALUE_LISTS_INDEX}/_create/${encodeURIComponent(id)}`,
          body: { name: trimmedName, type, values, updated_at: updatedAt },
          querystring: { refresh: 'wait_for' },
        });
        return response.ok({ body: { id, name: trimmedName, type, count: values.length, updatedAt } });
      } catch (err: any) {
        if (statusOf(err) === 409) {
          return response.customError({
            statusCode: 409,
            body: {
              message: `A value list named "${trimmedName}" (id "${id}") already exists. Edit it, or pick another name.`,
            },
          });
        }
        logger.error(`tlsoc value_lists create: ${err.message}`);
        return response.customError({
          statusCode: statusOf(err) ?? 500,
          body: { message: `Could not create value list: ${err.message}` },
        });
      }
    }
  );

  // UPDATE — PUT /api/tlsoc/value_lists/{id}
  router.put(
    {
      path: `${LISTS_API}/{id}`,
      validate: {
        ...idParam,
        body: schema.object({
          name: schema.maybe(schema.string()),
          type: schema.maybe(schema.string()),
          values: schema.arrayOf(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      if (!callerHasAnyRole(request, auth, DETECTION_WRITERS)) {
        return forbidden(response, 'edit value lists');
      }
      const { id } = request.params as { id: string };
      const { name, type, values } = request.body as {
        name?: string;
        type?: string;
        values: string[];
      };
      const esClient = context.core.opensearch.client.asCurrentUser;
      const soClient = context.core.savedObjects.client;
      try {
        const existing = await fetchValueList(esClient, id);
        if (!existing) {
          return response.notFound({ body: { message: `Value list "${id}" not found.` } });
        }
        // The type is IMMUTABLE: rules referencing the list were save-gated against it (ip lists
        // require ip-mapped event fields) — flipping it would invalidate them behind their backs.
        if (type !== undefined && type !== existing.type) {
          return response.badRequest({
            body: {
              message: `A value list's type cannot change ("${existing.type}" → "${type}") — rules were validated against it. Create a new list instead.`,
            },
          });
        }
        const nextName = (name ?? existing.name).trim();
        // The id IS the slug of the name (it anchors rules' terms-lookups) — a rename may only
        // vary case/punctuation that keeps the slug identical.
        if (valueListIdFromName(nextName) !== id) {
          return response.badRequest({
            body: {
              message: `Renaming "${existing.name}" to "${nextName}" would change the list id ("${id}") that rules reference. Create a new list instead.`,
            },
          });
        }
        try {
          assertValidValueListInput({ name: nextName, type: existing.type, values });
        } catch (err: any) {
          return response.badRequest({ body: { message: err.message } });
        }

        const updatedAt = new Date().toISOString();
        await esClient.transport.request({
          method: 'PUT',
          path: `/${VALUE_LISTS_INDEX}/_doc/${encodeURIComponent(id)}`,
          body: { name: nextName, type: existing.type, values, updated_at: updatedAt },
          querystring: { refresh: 'wait_for' },
        });

        // Inline rules bake the values into their monitors — rewrite them NOW (force bypasses
        // the debounce; the alerts-poll hook covers edits made outside this route). Fire-and-
        // forget: a sweep hiccup must not fail the write that already happened.
        void syncIndicatorListMonitors(esClient, soClient, logger, { force: true }).catch(
          (err: any) => logger.warn(`tlsoc value_lists update: post-update sweep failed: ${err.message}`)
        );

        // HONESTY: a list grown past the inline cap leaves its inline rules matching the OLD
        // values (the sweep refuses to truncate) — name them so the author re-saves.
        let warning: string | undefined;
        if (values.length > VALUE_LIST_INLINE_MAX_VALUES) {
          try {
            const stuck = (await findIndicatorMatchRules(soClient))
              .filter(
                (so) =>
                  ((so.attributes.rule as any)?.listId as string) === id &&
                  ((so.attributes.rule as any)?.listMode as string) === 'inline'
              )
              .map((so) => so.attributes.name);
            if (stuck.length > 0) {
              warning =
                `This list now has ${values.length} values — over the ` +
                `${VALUE_LIST_INLINE_MAX_VALUES}-value inline limit. ${stuck.length} rule(s) ` +
                `(${stuck.map((n) => `"${n}"`).join(', ')}) keep matching the previous values ` +
                'until re-saved (they will then switch to lookup mode).';
            }
          } catch (err: any) {
            logger.warn(`tlsoc value_lists update: over-cap rule scan skipped: ${err.message}`);
          }
        }

        return response.ok({
          body: {
            id,
            name: nextName,
            type: existing.type,
            count: values.length,
            updatedAt,
            ...(warning ? { warning } : {}),
          },
        });
      } catch (err: any) {
        if (isWorkspaceAccessError(err)) return workspaceForbidden(response);
        logger.error(`tlsoc value_lists update: ${err.message}`);
        return response.customError({
          statusCode: statusOf(err) ?? 500,
          body: { message: `Could not update value list: ${err.message}` },
        });
      }
    }
  );

  // DELETE — DELETE /api/tlsoc/value_lists/{id}
  router.delete(
    { path: `${LISTS_API}/{id}`, validate: idParam },
    async (context, request, response) => {
      if (!callerHasAnyRole(request, auth, DETECTION_WRITERS)) {
        return forbidden(response, 'delete value lists');
      }
      const { id } = request.params as { id: string };
      const esClient = context.core.opensearch.client.asCurrentUser;
      const soClient = context.core.savedObjects.client;
      try {
        // IN-USE GUARD (fail-closed: if the rule scan fails, the delete fails): a deleted list
        // would kill lookup rules loudly at the next run and freeze inline rules on stale
        // values — refuse while ANY rule references it, naming the rules.
        const users = (await findIndicatorMatchRules(soClient)).filter(
          (so) => ((so.attributes.rule as any)?.listId as string) === id
        );
        if (users.length > 0) {
          const names = users.slice(0, 5).map((so) => `"${so.attributes.name}"`);
          const more = users.length > 5 ? ` and ${users.length - 5} more` : '';
          return response.customError({
            statusCode: 409,
            body: {
              message: `This value list is used by ${users.length} detection rule(s): ${names.join(', ')}${more}. Delete or re-point those rules first.`,
            },
          });
        }

        try {
          await esClient.transport.request({
            method: 'DELETE',
            path: `/${VALUE_LISTS_INDEX}/_doc/${encodeURIComponent(id)}`,
            querystring: { refresh: 'wait_for' },
          });
        } catch (err: any) {
          if (statusOf(err) === 404) {
            return response.notFound({ body: { message: `Value list "${id}" not found.` } });
          }
          throw err;
        }
        return response.ok({ body: { deleted: true } });
      } catch (err: any) {
        if (isWorkspaceAccessError(err)) return workspaceForbidden(response);
        logger.error(`tlsoc value_lists delete: ${err.message}`);
        return response.customError({
          statusCode: statusOf(err) ?? 500,
          body: { message: `Could not delete value list: ${err.message}` },
        });
      }
    }
  );
}
