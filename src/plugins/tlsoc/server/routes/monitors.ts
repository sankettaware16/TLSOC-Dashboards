/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import uuid from 'uuid';
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
  ANALYZED_TEXT_TYPES,
  DetectionMode,
  DetectionRuleAttributes,
  IndicatorMatchRuleDefinition,
  NewTermsRuleDefinition,
  PplRuleDefinition,
  RuleDefinition,
  ThresholdRuleDefinition,
  buildMonitorForSave,
  collectPplStringContextFields,
  compileIndicatorInlineToDocMonitor,
  deriveAliasName,
  desiredExecutionTargets,
  executionTargetsDiffer,
  getType,
  isValidMode,
  newTermsStateDocId,
  parsePpl,
  unknownTypeMessage,
} from '../../common/detection';
import {
  CustomQueryRuleDefinition,
  compileCustomQueryText,
} from '../../common/detection/custom_query';
import { bootstrapSeenValues, deleteSeenValuesDoc, SeenValuesResult } from '../lib/new_terms_state';
import { validateLuceneQuery } from './detection_validate';
import { prepareIndicatorMatchRule } from './value_lists';
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
  mode: DetectionMode;
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

/**
 * v1.2.3 W3 review (the D5 index gate): the seen-values bootstrap queries with
 * `allow_no_indices`, so against ZERO matching indices it "succeeds" having aggregated NOTHING —
 * an empty seen set that silently means "everything alerts as new" the moment the index appears,
 * when the design promised a LOUD save gate. So before any bootstrap, resolve the rule's index
 * pattern to its current concrete indices (the doc-kind path's exact idiom) and refuse by name
 * when nothing matches — mirroring the ppl/custom_query "No indices currently match" 400s.
 */
async function assertNewTermsIndicesExist(
  esClient: EsClient,
  logger: Logger,
  rule: Record<string, unknown>
): Promise<void> {
  const ruleIndex = String((rule as any).index ?? '');
  const concreteIndices = await resolveConcreteIndices(esClient, logger, ruleIndex);
  if (concreteIndices.length === 0) {
    throw new RouteError(
      400,
      `No indices currently match "${ruleIndex}", so there is nothing for this rule to run against yet.`
    );
  }
}

/** The additive create/update response field surfacing the D5 bootstrap snapshot (W3 review). */
function seenValuesResponseField(
  snapshot: SeenValuesResult | undefined
): { seenValues?: { count: number; truncated: boolean } } {
  return snapshot
    ? { seenValues: { count: snapshot.values.length, truncated: snapshot.truncated } }
    : {};
}

/**
 * v1.2.3 W2 review BLOCKING-1 (the server layer — the UNSKIPPABLE gate): a 'ppl' rule's `fieldMap`
 * is produced by the builder from data-view field caps, but nothing forces a caller to send one
 * (curl, an import, a client bug) — and a PPL rule whose string-context fields hit analyzed text
 * WITHOUT a keyword mapping compiles into a monitor that aggregates/matches on raw text and dies
 * at runtime with NO alert and NO error (the silent-dead-rule class, research_r2 §a). So the save
 * path re-parses the query, re-derives its string-context fields with the SAME shared enumerator
 * the builder uses ({@link collectPplStringContextFields}), asks the CLUSTER what those fields
 * really are (field_caps, caller credentials), and 400s BY NAME any analyzed-text field the
 * fieldMap does not correctly cover. Keyword/ip/date/numeric fields — and fields absent from the
 * matching indices — need no entry and pass untouched.
 */
async function assertPplFieldMapAgainstCluster(
  esClient: EsClient,
  rule: Record<string, unknown>
): Promise<void> {
  const pplRule = (rule as unknown) as PplRuleDefinition;
  const parsed = parsePpl(typeof pplRule.pplText === 'string' ? pplRule.pplText : '');
  if (!parsed.ok) return; // prepareMonitor's compile 400s parse errors with a better message
  const rawFields = collectPplStringContextFields(parsed.rule);
  if (rawFields.length === 0) return;

  const fieldMap: Record<string, string> =
    pplRule.fieldMap && typeof pplRule.fieldMap === 'object' ? pplRule.fieldMap : {};
  // Ask about the raw fields AND their claimed mappings, so a bogus mapping is caught too.
  const wanted = new Set<string>(rawFields);
  rawFields.forEach((f) => {
    const mapped = fieldMap[f];
    if (typeof mapped === 'string' && mapped !== '') wanted.add(mapped);
  });

  const noIndices = `No indices currently match "${pplRule.index}", so there is nothing for this rule to run against yet.`;
  let caps: any;
  try {
    const resp = await esClient.fieldCaps({
      index: pplRule.index,
      fields: [...wanted],
      allow_no_indices: true,
      ignore_unavailable: true,
    });
    caps = (resp as any).body ?? {};
  } catch (err: any) {
    if ((err?.meta?.statusCode ?? err?.statusCode) === 404) {
      throw new RouteError(400, noIndices);
    }
    throw err;
  }
  // Zero matching concrete indices → field_caps "succeeds" having checked NOTHING (the same trap
  // as _validate's 0-shards) — refuse, mirroring the doc-level path's no-matching-indices 400.
  if (((caps?.indices as string[] | undefined) ?? []).length === 0) {
    throw new RouteError(400, noIndices);
  }

  const capsFields: Record<string, Record<string, unknown>> = caps?.fields ?? {};
  const typesOf = (name: string): string[] => Object.keys(capsFields[name] ?? {});

  for (const field of rawFields) {
    const analyzed = typesOf(field).filter((t) => ANALYZED_TEXT_TYPES.has(t));
    if (analyzed.length === 0) continue; // keyword/ip/date/numeric (or absent) — passes as-is
    const mapped = fieldMap[field];
    if (typeof mapped !== 'string' || mapped === '') {
      throw new RouteError(
        400,
        `PPL rule field "${field}" is analyzed text ("${analyzed[0]}") on "${pplRule.index}" — ` +
          'grouping or matching it exactly would fail silently at monitor runtime. Re-save the ' +
          'rule from the builder with its matching data view selected so the field maps to a ' +
          `keyword subfield (e.g. "${field}.keyword"), or use a keyword field in the query.`
      );
    }
    const mappedTypes = typesOf(mapped);
    if (mappedTypes.length === 0) {
      throw new RouteError(
        400,
        `PPL rule field "${field}" maps to "${mapped}", but "${mapped}" does not exist on ` +
          `"${pplRule.index}". Re-save the rule from the builder with its matching data view selected.`
      );
    }
    if (mappedTypes.some((t) => ANALYZED_TEXT_TYPES.has(t))) {
      throw new RouteError(
        400,
        `PPL rule field "${field}" maps to "${mapped}", which is itself analyzed text ` +
          `("${mappedTypes.find((t) => ANALYZED_TEXT_TYPES.has(t))}") — map it to a keyword ` +
          'subfield instead.'
      );
    }
  }
}

/**
 * v1.2.3 W2 review BLOCKING-2 (the server layer): the Alerting engine NEVER validates doc-level
 * queries — a malformed Lucene query saves fine and matches nothing forever, with no error
 * (research_r2 §b). So before a 'custom_query' monitor is created/updated, the EXACT executed
 * Lucene (for 'kuery' rules, the translation — belt and braces on top of the client-side subset
 * check) is validated against the cluster's own parser via the shared detection_validate helper.
 * An invalid query or a nothing-matching index both 400 with the parser's/trap's own words.
 */
async function assertCustomQueryValidates(
  esClient: EsClient,
  rule: Record<string, unknown>
): Promise<void> {
  const cqRule = (rule as unknown) as CustomQueryRuleDefinition;
  // prepareMonitor's compile already ran assertValidCustomQueryRule + the DQL translation, so
  // this re-derivation cannot throw here; it yields the exact string the monitor will run.
  const lucene = compileCustomQueryText(cqRule);
  const verdict = await validateLuceneQuery(esClient, cqRule.index, lucene);
  if (!verdict.valid) {
    throw new RouteError(
      400,
      `The query did not validate against "${cqRule.index}": ${verdict.reason}`
    );
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
  mode: DetectionMode,
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

  // v1.2.3 W2 review: server-side silent-dead-rule gates. They run AFTER compile (so parse/shape
  // errors keep their richer messages) but BEFORE anything touches the cluster's monitors — with
  // the CALLER's credentials and the CLUSTER's own metadata/parsers, so no client (the builder,
  // curl, an import) can skip them. Shared by create AND update.
  if (mode === 'ppl') {
    await assertPplFieldMapAgainstCluster(esClient, rule);
  } else if (mode === 'custom_query') {
    await assertCustomQueryValidates(esClient, rule);
  } else if (mode === 'indicator_match') {
    // v1.2.3 D6: fetch the list, RE-PICK the shape from its CURRENT size (stamps rule.listMode —
    // the SO write downstream persists the same object), field_caps-verify ip lists target
    // ip-mapped fields. prepareIndicatorMatchRule throws Errors carrying statusCode 400 for
    // authoring problems; cluster failures have no statusCode → 500.
    let prepared: { listMode: 'inline' | 'lookup'; values: string[] };
    try {
      prepared = await prepareIndicatorMatchRule(esClient, rule);
    } catch (err) {
      throw new RouteError((err as any).statusCode ?? 500, err.message);
    }
    if (prepared.listMode === 'inline') {
      // Alert-quality upgrade for small lists: doc-level inline (related_doc_ids → flyout).
      monitor = (compileIndicatorInlineToDocMonitor(
        (rule as unknown) as IndicatorMatchRuleDefinition,
        prepared.values
      ) as unknown) as Record<string, any>;
    }
  }

  let executionAlias: string | undefined;
  let executionTargets: string[] | undefined;
  const ruleIndex = ((rule as any).index as string) ?? '';
  // Keyed off the COMPILED monitor's type, NOT the registry's static monitorKind (v1.2.3 D6):
  // indicator_match compiles doc OR bucket per rule (the inline upgrade above replaces `monitor`
  // first), and every other type's compiled monitor_type always equals its monitorKind — so this
  // keying is behavior-identical for them. EVERY doc-level monitor needs the per-index alias
  // routing (doc-level monitors reject dotted/patterned indices — #1290).
  if (monitor.monitor_type === 'doc_level_monitor' && /[.*]/.test(ruleIndex)) {
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
 * Does this rule's LIVE monitor run doc-level (and therefore need the per-index-alias drift
 * repair below)? True for every registry type whose monitorKind is 'doc', plus the INLINE half
 * of the indicator_match hybrid (v1.2.3 D6) — only inline indicator rules compile to doc-level
 * monitors; lookup ones (and every other bucket-kind type, new_terms included) take the raw
 * pattern and need no aliasing. An unregistered mode (a rule saved by a newer TLSOC) is skipped,
 * never crashed on. Exported so the selection logic is unit-testable in isolation (W3 review).
 */
export function needsExecutionTargetSync(attributes: DetectionRuleAttributes): boolean {
  if (!isValidMode(attributes.mode)) return false;
  if (attributes.mode === 'indicator_match') {
    return ((attributes.rule as any)?.listMode as string) === 'inline';
  }
  return getType(attributes.mode).monitorKind === 'doc';
}

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
    // used everywhere else this SO type is scanned. Selection lives in the exported
    // {@link needsExecutionTargetSync} predicate (unit-pinned): every doc-level type, which for
    // the indicator_match hybrid means its INLINE rules only.
    const found = await soClient.find<DetectionRuleAttributes>({ type: TYPE, perPage: 1000 });
    statelessRules = found.saved_objects.filter((so) => needsExecutionTargetSync(so.attributes));
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
    // The in-handler registry check replaces the old schema.oneOf mode literals, so a new registry
    // type needs no edit here; an unknown id 400s BY NAME instead of a generic schema error.
    mode: schema.string(),
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
    if (!isValidMode(mode)) {
      return response.badRequest({ body: { message: unknownTypeMessage(mode) } });
    }
    const soClient = context.core.savedObjects.client;
    const esClient = context.core.opensearch.client.asCurrentUser;
    const name = ((rule as any).name as string)?.trim() || 'Untitled detection';
    const severity = ((rule as any).severity as string) ?? 'medium';

    // v1.2.3 D5: two-phase identity for new-terms rules — the seen-state doc id derives from the
    // rule's SO id, but the state doc must exist BEFORE the monitor (its terms-lookup target) and
    // the monitor before the SO. So the SO id is PRE-GENERATED here and passed to soClient.create.
    let newTermsSoId: string | undefined;
    if (mode === 'new_terms') {
      newTermsSoId = uuid.v4();
      (rule as any).stateDocId = newTermsStateDocId(
        newTermsSoId,
        String((rule as any).termField ?? '')
      );
    }

    let monitor: Record<string, any>;
    let executionAlias: string | undefined;
    let executionTargets: string[] | undefined;
    let seenSnapshot: SeenValuesResult | undefined;
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
      // v1.2.3 D5: snapshot the seen values BEFORE the monitor POST — the compiled monitor's
      // terms-lookup doc MUST exist before its first run. The bootstrap aggregates on the term
      // field with the caller's credentials, so it doubles as the server save-gate: an
      // unaggregatable field or unreadable index fails LOUDLY here, before any monitor exists
      // (the D5 analog of the ppl/custom_query gates in prepareMonitor). Zero matching indices
      // refuse FIRST (W3 review: the bootstrap itself "succeeds" against nothing).
      if (mode === 'new_terms') {
        await assertNewTermsIndicesExist(esClient, logger, rule);
        try {
          seenSnapshot = await bootstrapSeenValues(
            esClient,
            (rule as unknown) as NewTermsRuleDefinition,
            (rule as any).stateDocId,
            newTermsSoId!
          );
        } catch (err) {
          throw new RouteError(
            400,
            `Could not snapshot the seen values for "${name}": ${err.message}`
          );
        }
      }
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
      // v1.2.3 W3 review (fix 2): the bootstrap already wrote the seen-state doc — roll it back
      // here too (best-effort, mirroring the SO-failure branch below), so a failed create leaves
      // no orphaned state doc behind.
      if (mode === 'new_terms') {
        await deleteSeenValuesDoc(esClient, (rule as any).stateDocId).catch((e: any) =>
          logger.warn(`tlsoc create: seen-state rollback skipped: ${e.message}`)
        );
      }
      return response.customError({
        statusCode: err.meta?.statusCode ?? 500,
        body: { message: `Could not save detection: ${err.message}`, attributes: err.meta?.body },
      });
    }

    try {
      const attributes: DetectionRuleAttributes = {
        name,
        mode,
        severity,
        monitorId,
        rule: (rule as unknown) as RuleDefinition | ThresholdRuleDefinition,
        ...(executionAlias ? { executionAlias } : {}),
        ...(executionTargets ? { executionTargets } : {}),
        enabled: enabled ?? true,
        createdAt: new Date().toISOString(),
      };
      // v1.2.3 D5: a new-terms SO gets the PRE-GENERATED id its seen-state doc id derives from.
      const so = newTermsSoId
        ? await soClient.create<DetectionRuleAttributes>(TYPE, attributes, { id: newTermsSoId })
        : await soClient.create<DetectionRuleAttributes>(TYPE, attributes);
      return response.ok({
        // `seenValues` (new_terms only) is ADDITIVE — W3 review: the builder warns on
        // truncated=true (degraded tracking) and on count===0 (everything will alert as new).
        body: {
          id: monitorId,
          soId: so.id,
          name,
          executionAlias,
          ...seenValuesResponseField(seenSnapshot),
        },
      });
    } catch (err) {
      logger.error(`tlsoc create: SO failed, rolling back monitor ${monitorId}: ${err.message}`);
      try {
        await esClient.transport.request({ method: 'DELETE', path: `${MONITOR_API}/${monitorId}` });
      } catch (rbErr) {
        logger.error(`tlsoc create: rollback failed: ${rbErr.message}`);
      }
      // v1.2.3 D5: the bootstrap already wrote the seen-state doc — roll it back too.
      if (mode === 'new_terms') {
        await deleteSeenValuesDoc(esClient, (rule as any).stateDocId).catch((e: any) =>
          logger.warn(`tlsoc create: seen-state rollback skipped: ${e.message}`)
        );
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
      if (!isValidMode(mode)) {
        return response.badRequest({ body: { message: unknownTypeMessage(mode) } });
      }
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
      // v1.2.3 W3 review D-A: the rule TYPE is IMMUTABLE after creation (the Elastic-shaped
      // contract). Every type owns lifecycle state keyed to its shape — seen-state docs, alias
      // targets, the monitor's fixed monitor_type — and a PUT that flips the mode would have to
      // migrate all of it atomically (the unverified monitor_type-flip-on-PUT class). Refused at
      // the API boundary, naming both types; the builder locks its type cards in edit sessions.
      if (mode !== existing.attributes.mode) {
        return response.badRequest({
          body: {
            message:
              `This detection is a "${existing.attributes.mode}" rule and the request sent ` +
              `"${mode}" — the rule type cannot be changed after creation. Create a new rule instead.`,
          },
        });
      }
      const monitorId = existing.attributes.monitorId;
      // THE TRAP: `prepareMonitor`'s compiler always emits `enabled: true` — without this, saving an
      // edit to a currently-DISABLED rule would silently re-enable it. Preserve the existing SO's
      // enabled state unless the caller explicitly passed one.
      const nextEnabled = enabled ?? existing.attributes.enabled ?? true;

      // v1.2.3 D5: ALWAYS re-inject the seen-state doc id (deterministic from soId + termField,
      // so a builder that dropped the field on round-trip is harmless).
      if (mode === 'new_terms') {
        (rule as any).stateDocId = newTermsStateDocId(soId, String((rule as any).termField ?? ''));
      }

      let monitor: Record<string, any>;
      let executionAlias: string | undefined;
      let executionTargets: string[] | undefined;
      let seenSnapshot: SeenValuesResult | undefined;
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
        // v1.2.3 D5: re-snapshot BEFORE the monitor write — termField/historyWindow/filter may
        // have changed (an edit redefines the rule), and the lookup doc must exist before the
        // next run. Same loud 400 save-gate semantics (and the same zero-indices refusal) as
        // CREATE's bootstrap. NOTE: when the termField changed, this writes the NEW doc id; the
        // OLD doc is removed only AFTER the monitor + SO writes both succeed (W3 review
        // BLOCKING-1: the live monitor still reads the old doc until the write lands — deleting
        // it first would leave a window where a running monitor's lookup 404s).
        if (mode === 'new_terms') {
          await assertNewTermsIndicesExist(esClient, logger, rule);
          try {
            seenSnapshot = await bootstrapSeenValues(
              esClient,
              (rule as unknown) as NewTermsRuleDefinition,
              (rule as any).stateDocId,
              soId
            );
          } catch (err) {
            throw new RouteError(
              400,
              `Could not snapshot the seen values for "${name}": ${err.message}`
            );
          }
        }
      } catch (err) {
        if (err instanceof RouteError) {
          return response.customError({ statusCode: err.statusCode, body: { message: err.message } });
        }
        return response.customError({ statusCode: 500, body: { message: err.message } });
      }

      // Capture the current monitor body, then write. SAME-KIND updates PUT in place with
      // optimistic concurrency. A CROSS-KIND compile — v1.2.3 D-B: an indicator_match rule whose
      // list crossed the inline cap, so the SAME (immutable) mode now compiles to the OTHER
      // monitor_type — must NEVER be PUT onto the existing monitor (flipping a live monitor's
      // monitor_type is unverified engine territory): the replacement monitor is CREATED here,
      // and the superseded one is deleted only AFTER the SO write succeeds (below).
      let oldBody: any;
      let nextMonitorId = monitorId;
      try {
        const cur = await esClient.transport.request({ method: 'GET', path: `${MONITOR_API}/${monitorId}` });
        oldBody = (cur as any).body?.monitor;
        const crossKind =
          typeof oldBody?.monitor_type === 'string' &&
          oldBody.monitor_type !== monitor.monitor_type;
        if (crossKind) {
          const created = await esClient.transport.request({
            method: 'POST',
            path: MONITOR_API,
            body: monitor,
            querystring: { refresh: 'wait_for' },
          });
          nextMonitorId = (created as any).body?._id;
          if (!nextMonitorId) throw new Error('Alerting did not return a monitor id');
        } else {
          const seqNo = (cur as any).body?._seq_no;
          const primaryTerm = (cur as any).body?._primary_term;
          await esClient.transport.request({
            method: 'PUT',
            path: `${MONITOR_API}/${monitorId}`,
            body: monitor,
            querystring: { refresh: 'wait_for', if_seq_no: seqNo, if_primary_term: primaryTerm },
          });
        }
      } catch (err) {
        logger.error(`tlsoc update: monitor write failed: ${err.message}`);
        return response.customError({
          statusCode: err.meta?.statusCode ?? 500,
          body: { message: `Could not update detection: ${err.message}`, attributes: err.meta?.body },
        });
      }
      const swappedMonitor = nextMonitorId !== monitorId;

      // Replace the SO (full overwrite, so a bucket-shape edit drops a stale executionAlias/
      // Targets; `monitorId` records the REPLACEMENT monitor on a cross-kind swap, which keeps
      // the LIST/GET-ONE reads and the alerts-route monitorId↔rule join pointed at the live
      // monitor). On failure, roll the monitor write back so the two stores never drift: a
      // same-kind PUT is reverted to its captured previous body; a swap deletes the JUST-CREATED
      // monitor instead — the old monitor was not touched yet, so old-monitor + old-SO remain a
      // consistent pair.
      try {
        await soClient.create<DetectionRuleAttributes>(
          TYPE,
          {
            name,
            mode,
            severity,
            monitorId: nextMonitorId,
            rule: (rule as unknown) as RuleDefinition | ThresholdRuleDefinition,
            ...(executionAlias ? { executionAlias } : {}),
            ...(executionTargets ? { executionTargets } : {}),
            enabled: nextEnabled,
            createdAt: existing.attributes.createdAt,
          },
          { id: soId, overwrite: true }
        );
      } catch (err) {
        logger.error(
          `tlsoc update: SO failed, ${
            swappedMonitor
              ? `rolling back replacement monitor ${nextMonitorId}`
              : `reverting monitor ${monitorId}`
          }: ${err.message}`
        );
        try {
          if (swappedMonitor) {
            await esClient.transport.request({
              method: 'DELETE',
              path: `${MONITOR_API}/${nextMonitorId}`,
            });
          } else if (oldBody) {
            await esClient.transport.request({
              method: 'PUT',
              path: `${MONITOR_API}/${monitorId}`,
              body: oldBody,
              querystring: { refresh: 'wait_for' },
            });
          }
        } catch (rbErr) {
          logger.error(`tlsoc update: monitor rollback failed: ${rbErr.message}`);
        }
        return response.customError({
          statusCode: 500,
          body: { message: `Could not record the updated rule; the monitor was reverted: ${err.message}` },
        });
      }

      // BOTH writes succeeded — best-effort cleanups only from here (W3 review BLOCKING-1
      // sequencing, mirroring the DELETE route): nothing the OLD monitor could still be reading
      // may be removed while it could still run.
      if (swappedMonitor) {
        // The superseded monitor of a cross-kind swap (D-B). Its still-active alerts move to the
        // engine's DELETED state — engine behavior, accepted (the replacement monitor re-fires
        // on the next run for anything still matching).
        await esClient.transport
          .request({ method: 'DELETE', path: `${MONITOR_API}/${monitorId}` })
          .catch((e: any) => {
            if ((e.meta?.statusCode ?? e.statusCode) !== 404) {
              logger.warn(
                `tlsoc update: superseded monitor ${monitorId} cleanup skipped (the replacement ${nextMonitorId} is live): ${e.message}`
              );
            }
          });
      }
      if (mode === 'new_terms') {
        // A termField change moved the seen-state doc id — drop the ORPHANED old doc now that
        // the rewritten monitor (reading the new id) and the SO are both durably in place.
        const oldDocId =
          ((existing.attributes.rule as any)?.stateDocId as string) ||
          newTermsStateDocId(soId, String((existing.attributes.rule as any)?.termField ?? ''));
        if (oldDocId && oldDocId !== (rule as any).stateDocId) {
          await deleteSeenValuesDoc(esClient, oldDocId).catch((e: any) =>
            logger.warn(`tlsoc update: old seen-state cleanup skipped: ${e.message}`)
          );
        }
      }

      return response.ok({
        body: {
          id: nextMonitorId,
          soId,
          name,
          executionAlias,
          ...seenValuesResponseField(seenSnapshot),
        },
      });
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

    // v1.2.3 D5: a new-terms rule owns a seen-state doc — drop it with the rule (best-effort; the
    // id is persisted on the rule and always recomputable from soId + termField).
    if (so.attributes.mode === 'new_terms') {
      const docId =
        ((so.attributes.rule as any)?.stateDocId as string) ||
        newTermsStateDocId(soId, String((so.attributes.rule as any)?.termField ?? ''));
      await deleteSeenValuesDoc(esClient, docId).catch((err: any) =>
        logger.warn(`tlsoc delete: seen-state cleanup for ${docId} skipped: ${err.message}`)
      );
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
