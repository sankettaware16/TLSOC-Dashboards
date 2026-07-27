/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { schema } from '@osd/config-schema';
import { HttpAuth, IRouter, Logger } from '../../../../core/server';
import {
  CaseAttributes,
  CaseComment,
  CaseStatus,
  CaseActivity,
  assertTransition,
  buildActivity,
  appendActivity,
  describeCreated,
  describeStatusChange,
  describeEdit,
  describeComment,
  describeAlertsLinked,
  describeAlertsAcknowledged,
  describeAlertsReopened,
} from '../../common/cases';
import {
  AlertOverrideAttributes,
  groupAckTargets,
  normalizeAlert,
  overrideOwners,
  partitionByIds,
} from '../../common/alerts';
import { buildRuleRefMap, fetchAlertsByIds, removeOverrideOwner } from './alerts';
import { getCurrentActor } from '../lib/current_actor';
import {
  callerHasAnyRole,
  CASE_ADMINS,
  CASE_STATUS_CHANGERS,
  CASE_WRITERS,
  forbidden,
  isWorkspaceAccessError,
  workspaceForbidden,
} from '../lib/authz';
import { ALERT_OVERRIDE_SO_TYPE, CASE_SO_TYPE } from '../saved_objects';

const TYPE = CASE_SO_TYPE;

const STATUS = schema.oneOf([
  schema.literal('New'),
  schema.literal('Assigned'),
  schema.literal('In Progress'),
  schema.literal('Contained'),
  schema.literal('Closed'),
]);

const SEVERITY = schema.oneOf([
  schema.literal('low'),
  schema.literal('medium'),
  schema.literal('high'),
  schema.literal('critical'),
]);

const idParam = { params: schema.object({ id: schema.string() }) };

function genId(): string {
  return `c-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Register all case management routes (create / list / get / update / delete / add-comment).
 * `auth` (core.http.auth) is the current-user seam: every mutation stamps the acting user
 * (via `getCurrentActor(request, auth)`) onto the activity actor / comment author / createdBy.
 * Falls back to 'analyst' when no authenticated identity is present (Task 5a.3).
 */
export function registerCaseRoutes(router: IRouter, logger: Logger, auth?: HttpAuth) {
  // CREATE — POST /api/tlsoc/cases
  router.post(
    {
      path: '/api/tlsoc/cases',
      validate: {
        body: schema.object({
          title: schema.string({ minLength: 1 }),
          severity: SEVERITY,
          description: schema.maybe(schema.string()),
          status: schema.maybe(STATUS),
          assignee: schema.maybe(schema.nullable(schema.string())),
          tags: schema.maybe(schema.arrayOf(schema.string())),
          linkedAlertIds: schema.maybe(schema.arrayOf(schema.string())),
          linkedFindingIds: schema.maybe(schema.arrayOf(schema.string())),
          createdFromAlertId: schema.maybe(schema.string()),
          category: schema.maybe(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      // 5b.3c matrix: any SOC role creates cases; unknown roles are read-only.
      if (!callerHasAnyRole(request, auth, CASE_WRITERS)) {
        return forbidden(response, 'create cases');
      }
      const soClient = context.core.savedObjects.client;
      const body = request.body as any;
      const now = nowIso();
      const actor = getCurrentActor(request, auth);
      const effectiveStatus: CaseStatus = (body.status as CaseStatus) ?? 'New';
      const attrs: CaseAttributes = {
        title: body.title,
        description: body.description ?? '',
        status: effectiveStatus,
        severity: body.severity,
        assignee: body.assignee ?? null,
        tags: body.tags ?? [],
        linkedAlertIds: body.linkedAlertIds ?? [],
        linkedFindingIds: body.linkedFindingIds ?? [],
        ...(body.createdFromAlertId ? { createdFromAlertId: body.createdFromAlertId } : {}),
        ...(body.category !== undefined ? { category: body.category } : {}),
        ...(effectiveStatus === 'Closed' ? { closedAt: now } : {}),
        createdBy: actor,
        comments: [],
        activity: [buildActivity('created', describeCreated({ fromAlert: !!body.createdFromAlertId }), actor, genId(), now)],
        createdAt: now,
        updatedAt: now,
      };
      try {
        const so = await soClient.create<CaseAttributes>(TYPE, attrs);
        return response.ok({ body: { id: so.id } });
      } catch (err) {
        logger.error(`tlsoc cases create: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not create case: ${err.message}` },
        });
      }
    }
  );

  // LIST — GET /api/tlsoc/cases
  router.get(
    { path: '/api/tlsoc/cases', validate: false },
    async (context, _request, response) => {
      const soClient = context.core.savedObjects.client;
      try {
        const found = await soClient.find<CaseAttributes>({ type: TYPE, perPage: 1000 });
        const rows = found.saved_objects
          .map((so) => {
            const a = so.attributes;
            return {
              id: so.id,
              title: a.title,
              status: a.status,
              severity: a.severity,
              assignee: a.assignee,
              tags: a.tags ?? [],
              category: a.category,
              closedAt: a.closedAt,
              linkedAlertCount: (a.linkedAlertIds ?? []).length,
              commentCount: (a.comments ?? []).length,
              createdAt: a.createdAt,
              updatedAt: a.updatedAt,
            };
          })
          .sort((a, b) => (b.updatedAt ?? '').localeCompare(a.updatedAt ?? ''));
        return response.ok({ body: { cases: rows } });
      } catch (err) {
        // A workspace the caller can't access must read as a clean 403, not a 500 (5b.3c).
        if (isWorkspaceAccessError(err)) return workspaceForbidden(response);
        logger.error(`tlsoc cases list: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not list cases: ${err.message}` },
        });
      }
    }
  );

  // GET ONE — GET /api/tlsoc/cases/{id}
  router.get(
    { path: '/api/tlsoc/cases/{id}', validate: idParam },
    async (context, request, response) => {
      const soClient = context.core.savedObjects.client;
      const { id } = request.params as { id: string };
      try {
        const so = await soClient.get<CaseAttributes>(TYPE, id);
        return response.ok({ body: { id: so.id, ...so.attributes } });
      } catch (err) {
        if (err?.output?.statusCode === 404 || err?.statusCode === 404) {
          return response.notFound({ body: { message: `Case ${id} not found.` } });
        }
        logger.error(`tlsoc cases get: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not load case: ${err.message}` },
        });
      }
    }
  );

  // GET ONE'S LINKED ALERTS (hydrated) — GET /api/tlsoc/cases/{id}/alerts
  router.get(
    { path: '/api/tlsoc/cases/{id}/alerts', validate: idParam },
    async (context, request, response) => {
      const soClient = context.core.savedObjects.client;
      const esClient = context.core.opensearch.client.asCurrentUser;
      const { id } = request.params as { id: string };
      let so: any;
      try {
        so = await soClient.get<CaseAttributes>(TYPE, id);
      } catch (err) {
        if (err?.output?.statusCode === 404 || err?.statusCode === 404) {
          return response.notFound({ body: { message: `Case ${id} not found.` } });
        }
        logger.error(`tlsoc cases alerts get: ${err.message}`);
        return response.customError({ statusCode: 500, body: { message: `Could not load case: ${err.message}` } });
      }
      const linkedAlertIds: string[] = so.attributes.linkedAlertIds ?? [];
      if (linkedAlertIds.length === 0) {
        return response.ok({ body: { alerts: [], missingIds: [] } });
      }
      try {
        // Through the Alerting PLUGIN API — a direct _search on the protected
        // .opendistro-alerting-* system indices returns silently empty under security (5a.1d).
        const rawAlerts = await fetchAlertsByIds(esClient, linkedAlertIds);
        const { found, missingIds } = partitionByIds(rawAlerts, linkedAlertIds);
        const rules = await buildRuleRefMap(soClient);
        const alerts = found.map((a: any) => ({ ...normalizeAlert(a, rules), raw: a }));
        return response.ok({ body: { alerts, missingIds } });
      } catch (err) {
        logger.error(`tlsoc cases alerts: ${err.message}`);
        return response.customError({
          statusCode: err.meta?.statusCode ?? 500,
          body: { message: `Could not load linked alerts: ${err.message}`, attributes: err.meta?.body },
        });
      }
    }
  );

  // ADD ALERTS TO A CASE (dedupe-append) — POST /api/tlsoc/cases/{id}/alerts
  router.post(
    {
      path: '/api/tlsoc/cases/{id}/alerts',
      validate: {
        ...idParam,
        body: schema.object({
          alertIds: schema.arrayOf(schema.string(), { minSize: 1 }),
          findingIds: schema.maybe(schema.arrayOf(schema.string())),
        }),
      },
    },
    async (context, request, response) => {
      // 5b.3c matrix: linking alerts into a case is a case-writer action.
      if (!callerHasAnyRole(request, auth, CASE_WRITERS)) {
        return forbidden(response, 'link alerts to cases');
      }
      const soClient = context.core.savedObjects.client;
      const { id } = request.params as { id: string };
      const body = request.body as { alertIds: string[]; findingIds?: string[] };
      let existing: any;
      try {
        existing = await soClient.get<CaseAttributes>(TYPE, id);
      } catch (err) {
        if (err?.output?.statusCode === 404 || err?.statusCode === 404) {
          return response.notFound({ body: { message: `Case ${id} not found.` } });
        }
        logger.error(`tlsoc cases add-alerts get: ${err.message}`);
        return response.customError({ statusCode: 500, body: { message: `Could not load case: ${err.message}` } });
      }
      const existingSet = new Set(existing.attributes.linkedAlertIds ?? []);
      const newlyAdded = body.alertIds.filter((a: string) => !existingSet.has(a)).length;
      const linkedAlertIds = Array.from(new Set([...(existing.attributes.linkedAlertIds ?? []), ...body.alertIds]));
      const linkedFindingIds = Array.from(new Set([...(existing.attributes.linkedFindingIds ?? []), ...(body.findingIds ?? [])]));
      const now = nowIso();
      const actor = getCurrentActor(request, auth);
      const alertsPatch: Record<string, any> = { linkedAlertIds, linkedFindingIds, updatedAt: now };
      if (newlyAdded > 0) {
        alertsPatch.activity = appendActivity(
          existing.attributes.activity,
          buildActivity('alerts_linked', describeAlertsLinked(newlyAdded), actor, genId(), now)
        );
      }
      try {
        await soClient.update<CaseAttributes>(TYPE, id, alertsPatch as any);
        return response.ok({ body: { linkedAlertCount: linkedAlertIds.length } });
      } catch (err) {
        logger.error(`tlsoc cases add-alerts: ${err.message}`);
        return response.customError({ statusCode: 500, body: { message: `Could not add alerts to case: ${err.message}` } });
      }
    }
  );

  // UPDATE — PUT /api/tlsoc/cases/{id}
  router.put(
    {
      path: '/api/tlsoc/cases/{id}',
      validate: {
        ...idParam,
        body: schema.object({
          title: schema.maybe(schema.string({ minLength: 1 })),
          description: schema.maybe(schema.string()),
          status: schema.maybe(STATUS),
          severity: schema.maybe(SEVERITY),
          assignee: schema.maybe(schema.nullable(schema.string())),
          tags: schema.maybe(schema.arrayOf(schema.string())),
          linkedAlertIds: schema.maybe(schema.arrayOf(schema.string())),
          linkedFindingIds: schema.maybe(schema.arrayOf(schema.string())),
          category: schema.maybe(schema.string()),
          // PROB-24: on a transition to Closed, also acknowledge the case's linked alerts in the
          // Alerting engine (default true — the close modal's checkbox). Ignored for any other
          // status change.
          acknowledgeAlerts: schema.maybe(schema.boolean()),
        }),
      },
    },
    async (context, request, response) => {
      const body = request.body as any;
      // 5b.3c matrix, most-restrictive field first: assignee changes are a manager action;
      // status transitions are L1/manager; any other field edit is open to all case writers.
      if (body.assignee !== undefined && !callerHasAnyRole(request, auth, CASE_ADMINS)) {
        return forbidden(response, 'assign cases');
      }
      if (body.status !== undefined && !callerHasAnyRole(request, auth, CASE_STATUS_CHANGERS)) {
        return forbidden(response, 'change case status');
      }
      if (!callerHasAnyRole(request, auth, CASE_WRITERS)) {
        return forbidden(response, 'edit cases');
      }
      const soClient = context.core.savedObjects.client;
      const { id } = request.params as { id: string };

      let existing: any;
      try {
        existing = await soClient.get<CaseAttributes>(TYPE, id);
      } catch (err) {
        if (err?.output?.statusCode === 404 || err?.statusCode === 404) {
          return response.notFound({ body: { message: `Case ${id} not found.` } });
        }
        logger.error(`tlsoc cases update get: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not load case: ${err.message}` },
        });
      }

      // Validate status transition if status is being changed
      if (body.status !== undefined && body.status !== existing.attributes.status) {
        try {
          assertTransition(existing.attributes.status as CaseStatus, body.status as CaseStatus);
        } catch (e: any) {
          return response.customError({
            statusCode: 400,
            body: { message: e.message },
          });
        }
      }

      const now = nowIso();
      const actor = getCurrentActor(request, auth);

      // PROB-24: closing a case acknowledges its linked alerts in the Alerting engine (unless the
      // caller opted out) — otherwise "case Closed" leaves its alerts ACTIVE forever on the Alerts
      // page. ACKNOWLEDGED is the analyst-done state (Alerting has no manual close; COMPLETED is
      // engine-managed), already-acknowledged/completed alerts are skipped, and EVERY failure path
      // is non-blocking: a flaky Alerting call must never prevent the case from closing — partial
      // results are recorded honestly in the audit trail instead.
      let ackActivity: CaseActivity | null = null;
      let reopenActivity: CaseActivity | null = null;
      const isClosing =
        body.status === 'Closed' && body.status !== existing.attributes.status;
      // PROB-29: a reopen is Closed → any non-Closed status. Its linked alerts were acknowledged on
      // close (the engine has no un-acknowledge API), so we reactivate them via TLSOC display
      // overrides instead of touching the protected alerting index.
      const isReopening =
        body.status !== undefined &&
        body.status !== 'Closed' &&
        existing.attributes.status === 'Closed';
      if (isClosing && body.acknowledgeAlerts !== false) {
        const linkedIds: string[] = existing.attributes.linkedAlertIds ?? [];
        if (linkedIds.length > 0) {
          try {
            const esClient = context.core.opensearch.client.asCurrentUser;
            const rawAlerts = await fetchAlertsByIds(esClient, linkedIds);
            const targets = groupAckTargets(
              rawAlerts.map((a: any) => ({ id: a?.id, monitorId: a?.monitor_id, state: a?.state }))
            );
            let acked = 0;
            let failed = 0;
            for (const t of targets) {
              try {
                await esClient.transport.request(
                  {
                    method: 'POST',
                    path: `/_plugins/_alerting/monitors/${t.monitorId}/_acknowledge/alerts`,
                    body: { alerts: t.alertIds }, // field name verified live (alerts.ts:285)
                  },
                  // Same fast-fail guard as the alerts route: the engine's acknowledge can
                  // deadlock cluster-side — cap the wait so a hung ack can't hang the case close.
                  { requestTimeout: 15000, maxRetries: 0 }
                );
                acked += t.alertIds.length;
              } catch (ackErr) {
                failed += t.alertIds.length;
                logger.warn(
                  `tlsoc cases close-ack: monitor ${t.monitorId} acknowledge failed: ${ackErr.message}`
                );
              }
            }
            if (acked > 0 || failed > 0) {
              ackActivity = buildActivity(
                'alerts_acknowledged',
                describeAlertsAcknowledged(acked, failed),
                actor,
                genId(),
                now
              );
            }
          } catch (err) {
            // Even listing the alerts failed — close the case anyway, just log it.
            logger.warn(`tlsoc cases close-ack: skipped (could not fetch linked alerts): ${err.message}`);
          }
        }
      }

      // PROB-29/30 RE-CLOSE: the alerts are acknowledged-done again FOR THIS CASE — drop THIS case
      // from each override's ownership set. Best-effort and non-blocking (removeOverrideOwner never
      // throws), and independent of the acknowledgeAlerts opt-out: a re-closed case's alerts must not
      // linger as "Reopened" for it regardless of whether the analyst re-acknowledged them. PROB-30:
      // if another still-reopened case also owns the override, it SURVIVES (owners trimmed, not
      // deleted); only when this was the last owner is the SO removed.
      if (isClosing) {
        const linkedIds: string[] = existing.attributes.linkedAlertIds ?? [];
        if (linkedIds.length > 0) {
          await removeOverrideOwner(soClient, linkedIds, id, logger, 'case re-closed');
        }
      }

      // PROB-29 REOPEN: for each linked alert the engine STILL reports ACKNOWLEDGED, upsert a display
      // override so it reads as active again (id = alert id, overwrite:true so a re-reopen refreshes
      // it). ACTIVE alerts (never acknowledged) and engine-COMPLETED alerts are left untouched — an
      // override only ever changes DISPLAY for an ACKNOWLEDGED alert. Non-blocking like the close-ack
      // path: a flaky Alerting/SO call must never prevent the case from reopening.
      if (isReopening) {
        const linkedIds: string[] = existing.attributes.linkedAlertIds ?? [];
        if (linkedIds.length > 0) {
          try {
            const esClient = context.core.opensearch.client.asCurrentUser;
            const rawAlerts = await fetchAlertsByIds(esClient, linkedIds);
            const acknowledged = rawAlerts.filter((a: any) => a?.state === 'ACKNOWLEDGED');
            let reopened = 0;
            let failed = 0;
            for (const a of acknowledged) {
              // PROB-30: UNION this case into the override's ownership set. Read any existing override
              // (a prior reopen by this or another case), resolve its owners through the back-compat
              // shim (legacy doc → [caseId]), and add this id. A 404/other read failure is treated as
              // "no existing override" → owners starts as [thisCase] (first reopen). Non-blocking.
              let existingOwners: string[] = [];
              try {
                const prev = await soClient.get<AlertOverrideAttributes>(ALERT_OVERRIDE_SO_TYPE, a.id);
                existingOwners = overrideOwners(prev.attributes);
              } catch (getErr) {
                existingOwners = [];
              }
              const owners = existingOwners.includes(id) ? existingOwners : [...existingOwners, id];
              const attrs: AlertOverrideAttributes = {
                alertId: a.id,
                owners,
                caseId: id, // DISPLAY: this (latest) reopener
                caseName: existing.attributes.title,
                monitorId: a?.monitor_id ?? '',
                reopenedAt: now,
                reopenedBy: actor,
              };
              try {
                await soClient.create<AlertOverrideAttributes>(ALERT_OVERRIDE_SO_TYPE, attrs, {
                  id: a.id,
                  overwrite: true,
                });
                reopened += 1;
              } catch (ovErr) {
                failed += 1;
                logger.warn(
                  `tlsoc cases reopen: could not write override for alert ${a.id}: ${ovErr.message}`
                );
              }
            }
            if (reopened > 0 || failed > 0) {
              reopenActivity = buildActivity(
                'alerts_reopened',
                describeAlertsReopened(reopened, failed),
                actor,
                genId(),
                now
              );
            }
          } catch (err) {
            // Listing the alerts failed — reopen the case anyway, just log it.
            logger.warn(`tlsoc cases reopen: skipped (could not fetch linked alerts): ${err.message}`);
          }
        }
      }

      // Build a partial patch of ONLY the provided fields + updatedAt
      const patch: Record<string, any> = { updatedAt: now };
      if (body.title !== undefined) patch.title = body.title;
      if (body.description !== undefined) patch.description = body.description;
      if (body.status !== undefined) patch.status = body.status;
      if (body.severity !== undefined) patch.severity = body.severity;
      if (body.assignee !== undefined) patch.assignee = body.assignee;
      if (body.tags !== undefined) patch.tags = body.tags;
      if (body.linkedAlertIds !== undefined) patch.linkedAlertIds = body.linkedAlertIds;
      if (body.linkedFindingIds !== undefined) patch.linkedFindingIds = body.linkedFindingIds;
      if (body.category !== undefined) patch.category = body.category;
      // closedAt lifecycle: server-set only, never from client body
      if (body.status !== undefined && body.status !== existing.attributes.status) {
        if (body.status === 'Closed') {
          patch.closedAt = now;
        } else if (existing.attributes.status === 'Closed') {
          patch.closedAt = null;
        }
      }

      // Activity tracking
      const newEntries: CaseActivity[] = [];
      if (body.status !== undefined && body.status !== existing.attributes.status) {
        newEntries.push(
          buildActivity(
            'status_changed',
            describeStatusChange(existing.attributes.status as CaseStatus, body.status as CaseStatus),
            actor,
            genId(),
            now
          )
        );
      }
      const changedFields: string[] = [];
      if (body.title !== undefined && body.title !== existing.attributes.title) changedFields.push('title');
      if (body.description !== undefined && body.description !== existing.attributes.description) changedFields.push('description');
      if (body.severity !== undefined && body.severity !== existing.attributes.severity) changedFields.push('severity');
      if (body.assignee !== undefined && (body.assignee ?? null) !== (existing.attributes.assignee ?? null)) changedFields.push('assignee');
      if (
        body.tags !== undefined &&
        JSON.stringify([...body.tags].sort()) !==
          JSON.stringify([...(existing.attributes.tags ?? [])].sort())
      ) {
        changedFields.push('tags');
      }
      if (body.category !== undefined && body.category !== existing.attributes.category) changedFields.push('category');
      if (changedFields.length > 0) {
        newEntries.push(
          buildActivity('edited', describeEdit(changedFields), actor, genId(), now)
        );
      }
      if (ackActivity) {
        newEntries.push(ackActivity); // after status_changed — reads as "closed, then acknowledged"
      }
      if (reopenActivity) {
        newEntries.push(reopenActivity); // after status_changed — reads as "reopened, then reactivated"
      }
      if (newEntries.length > 0) {
        patch.activity = [...(existing.attributes.activity ?? []), ...newEntries];
      }

      try {
        await soClient.update<CaseAttributes>(TYPE, id, patch);
        return response.ok({ body: { id } });
      } catch (err) {
        logger.error(`tlsoc cases update: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not update case: ${err.message}` },
        });
      }
    }
  );

  // DELETE — DELETE /api/tlsoc/cases/{id}
  router.delete(
    { path: '/api/tlsoc/cases/{id}', validate: idParam },
    async (context, request, response) => {
      // 5b.3c matrix: deleting a case is a manager action.
      if (!callerHasAnyRole(request, auth, CASE_ADMINS)) {
        return forbidden(response, 'delete cases');
      }
      const soClient = context.core.savedObjects.client;
      const { id } = request.params as { id: string };
      let existing: any;
      try {
        // GET first so we return 404 if not found
        existing = await soClient.get<CaseAttributes>(TYPE, id);
      } catch (err) {
        if (err?.output?.statusCode === 404 || err?.statusCode === 404) {
          return response.notFound({ body: { message: `Case ${id} not found.` } });
        }
        logger.error(`tlsoc cases delete get: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not load case: ${err.message}` },
        });
      }
      try {
        // PROB-29/30: best-effort remove THIS case from its alerts' reopen-override ownership sets
        // before deleting it, so a deleted case leaves none of its alerts falsely reading "Reopened"
        // for it — while any still-reopened case that shares the alert keeps its override (PROB-30).
        // Non-blocking — overrides also self-clean via the LIST merge once the engine completes.
        const linkedIds: string[] = existing?.attributes?.linkedAlertIds ?? [];
        if (linkedIds.length > 0) {
          await removeOverrideOwner(soClient, linkedIds, id, logger, 'case deleted');
        }
        await soClient.delete(TYPE, id);
        return response.ok({ body: { deleted: true } });
      } catch (err) {
        logger.error(`tlsoc cases delete: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not delete case: ${err.message}` },
        });
      }
    }
  );

  // ADD COMMENT — POST /api/tlsoc/cases/{id}/comments
  router.post(
    {
      path: '/api/tlsoc/cases/{id}/comments',
      validate: {
        ...idParam,
        // No client-supplied author — the comment author is the authenticated caller (5a.3),
        // derived server-side. Accepting a client author here would be a spoofable audit field.
        body: schema.object({
          text: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (context, request, response) => {
      // 5b.3c matrix: commenting is open to all SOC roles.
      if (!callerHasAnyRole(request, auth, CASE_WRITERS)) {
        return forbidden(response, 'comment on cases');
      }
      const soClient = context.core.savedObjects.client;
      const { id } = request.params as { id: string };
      const body = request.body as any;

      let existing: any;
      try {
        existing = await soClient.get<CaseAttributes>(TYPE, id);
      } catch (err) {
        if (err?.output?.statusCode === 404 || err?.statusCode === 404) {
          return response.notFound({ body: { message: `Case ${id} not found.` } });
        }
        logger.error(`tlsoc cases comment get: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not load case: ${err.message}` },
        });
      }

      const now = nowIso();
      const actor = getCurrentActor(request, auth);
      const comment: CaseComment = {
        id: genId(),
        author: actor,
        text: body.text,
        createdAt: now,
      };
      const comments = [...(existing.attributes.comments ?? []), comment];
      const activityAfterComment = appendActivity(
        existing.attributes.activity,
        buildActivity('commented', describeComment(), comment.author, genId(), now)
      );

      try {
        await soClient.update<CaseAttributes>(TYPE, id, { comments, activity: activityAfterComment, updatedAt: now });
        return response.ok({ body: comment });
      } catch (err) {
        logger.error(`tlsoc cases comment update: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not add comment: ${err.message}` },
        });
      }
    }
  );
}
