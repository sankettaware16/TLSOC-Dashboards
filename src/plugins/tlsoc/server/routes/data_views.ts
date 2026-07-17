/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { schema } from '@osd/config-schema';
import { IRouter, Logger } from '../../../../core/server';
import { getWorkspaceState } from '../../../../core/server/utils';
import { PluginStart as DataPluginStart } from '../../../data/server';
import { DuplicateIndexPatternError } from '../../../data/common';
import { OverviewConfig } from '../config';

/** The all-logs pattern the agentless pipeline writes to (PROB-2 / PROB-16 naming). Fallback when
 *  no `overview.logIndexPattern` config is threaded in (or it's empty). */
export const ALL_LOGS_INDEX_PATTERN = 'fosstlsoc-logs-*';

/**
 * Per-endpoint index names: `fosstlsoc-logs-<slug>-YYYY.MM.dd`. The capture group may itself
 * contain hyphens (that's fine, it's the whole slug). Legacy date-only indices
 * (`fosstlsoc-logs-YYYY.MM.dd`, no endpoint dimension) deliberately do NOT match.
 */
const ENDPOINT_INDEX_RE = /^fosstlsoc-logs-(.+)-\d{4}\.\d{2}\.\d{2}$/;

/** Bound on how many per-endpoint data views one `_ensure` call will create. */
const MAX_ENDPOINT_VIEWS = 50;

/** The data plugin's request-scoped index-patterns factory (threaded from `plugin.ts`). */
export type GetIndexPatternsServiceFactory = () => Promise<
  DataPluginStart['indexPatterns']['indexPatternsServiceFactory']
>;

function isDuplicateIndexPatternError(err: unknown): boolean {
  return err instanceof DuplicateIndexPatternError || (err as any)?.name === 'DuplicateIndexPatternError';
}

/**
 * The primary (base) data-view title this route ensures: the first entry of
 * `overview.logIndexPattern` (the pattern the Overview cockpit itself queries), falling back to
 * `ALL_LOGS_INDEX_PATTERN` when no config is threaded in or the config string is empty. Exported
 * so callers/tests can compute the same title the route will create without duplicating the logic.
 */
export function deriveBasePattern(overview?: OverviewConfig): string {
  return overview?.logIndexPattern?.split(',')[0]?.trim() || ALL_LOGS_INDEX_PATTERN;
}

/**
 * `POST /api/tlsoc/data_views/_ensure` — PROB-2 / PROB-2 WORKSPACE-FLOW fix.
 *
 * The distro ships no data view for the agentless pipeline's output, so the case Investigate tab
 * (and Discover/Visualize) has nothing to resolve `fosstlsoc-logs-*` against. A boot-time,
 * internal-repository-created data view would be invisible inside a workspace — index-pattern
 * saved objects are workspace-scoped via a strict `term {workspaces}` match at `find()` time — so
 * this route creates the view(s) REQUEST-SCOPED, via the data plugin's
 * `indexPatternsServiceFactory(request)`, letting the workspace wrapper inject the caller's
 * workspace (or none, outside a workspace) automatically. Idempotent: a duplicate title is treated
 * as already-ensured, not an error.
 *
 * Workspace-flow follow-up: the ORIGINAL fix let this route run out-of-band (e.g. a bare curl with
 * no `/w/<id>/` prefix) and happily create a GLOBAL (`workspaces:None`) view, which is then
 * invisible inside every workspace. The client now seeds this route on every workspace entry
 * (`public/plugin.ts`), and this route additionally refuses to create anything when
 * `workspaceEnabled` and no workspace id is present on the request (`skipped: 'no-workspace'`) —
 * defense in depth against ever creating another orphan this way.
 *
 * The base view is now ALWAYS created (no longer gated on concrete indices existing yet) — an
 * empty fields cache on a fresh workspace is harmless and self-heals the next time fields are
 * fetched, whereas skipping left the workspace with zero data views and no default index at all.
 * `skipFetchFields=true` is used throughout: the server-side `apiClient` stub
 * (`index_patterns_api_client.ts`) always throws on `getFieldsForWildcard`, so the
 * `skipFetchFields=false` path was already effectively dead — `true` is strictly cheaper/safer.
 */
export function registerDataViewsRoutes(
  router: IRouter,
  logger: Logger,
  getIndexPatternsServiceFactory: GetIndexPatternsServiceFactory,
  overview?: OverviewConfig,
  workspaceEnabled: boolean = false
) {
  const basePattern = deriveBasePattern(overview);

  router.post(
    {
      path: '/api/tlsoc/data_views/_ensure',
      validate: {
        body: schema.object({
          perEndpoint: schema.maybe(schema.boolean()),
        }),
      },
    },
    async (context, request, response) => {
      const perEndpoint = ((request.body as { perEndpoint?: boolean } | null) ?? {}).perEndpoint ?? false;

      // Orphan guard: when workspaces are enabled, refuse to create anything for a request that
      // carries no workspace id — that is exactly how the original bug produced global orphans
      // invisible to every workspace. Callers WITHIN a workspace always carry `/w/<id>/`, so this
      // only ever short-circuits genuinely out-of-band calls.
      if (workspaceEnabled) {
        const { requestWorkspaceId } = getWorkspaceState(request);
        if (!requestWorkspaceId) {
          return response.ok({ body: { ensured: [], defaultIndex: null, skipped: 'no-workspace' } });
        }
      }

      // A request-scoped index-patterns service instance — the workspace context flows in
      // automatically via the request, per the verified constraint above.
      let indexPatternsServiceFactory;
      try {
        indexPatternsServiceFactory = await getIndexPatternsServiceFactory();
      } catch (err: any) {
        logger.error(`tlsoc data_views _ensure: could not resolve the index-patterns service: ${err.message}`);
        return response.customError({
          statusCode: 500,
          body: { message: `Could not resolve the index-patterns service: ${err.message}` },
        });
      }
      const indexPatterns = await indexPatternsServiceFactory(request);

      const ensured: Array<{ title: string; created: boolean }> = [];

      // Always ensure the base view — never gated on concrete indices existing yet.
      try {
        await indexPatterns.createAndSave({ title: basePattern, timeFieldName: '@timestamp' }, false, true);
        ensured.push({ title: basePattern, created: true });
      } catch (err: any) {
        if (isDuplicateIndexPatternError(err)) {
          ensured.push({ title: basePattern, created: false });
        } else {
          logger.warn(`tlsoc data_views _ensure: could not create data view "${basePattern}": ${err.message}`);
        }
      }

      // Set the workspace's defaultIndex on EVERY call, not just first-create. Use the ROUTE-
      // HANDLER uiSettings client (`context.core.uiSettings.client`, request-scoped via
      // getScopedClient(request)) — verified live to actually land in the CURRENT workspace's
      // uiSettings, whereas `indexPatterns.setDefault()` (the factory's own config wrapper) did
      // NOT persist to workspace scope. `defaultIndex` is registered `scope: WORKSPACE`, so a plain
      // get/set auto-routes to the workspace. Only write when unset so we never stomp a user's
      // later pick, and so re-entry into an already-configured workspace is a no-op.
      let defaultIndex: string | null = null;
      try {
        const idsWithTitle = await indexPatterns.getIdsWithTitle(true);
        const baseEntry = idsWithTitle.find((entry) => entry.title === basePattern);
        if (baseEntry) {
          defaultIndex = baseEntry.id;
          const current = await context.core.uiSettings.client.get('defaultIndex');
          if (!current) {
            await context.core.uiSettings.client.set('defaultIndex', baseEntry.id);
          }
        }
      } catch (err: any) {
        logger.warn(`tlsoc data_views _ensure: could not set the workspace default index: ${err.message}`);
      }

      // Per-endpoint views (best-effort): derive slugs from concrete index names matching the base
      // pattern. Unlike the base view, these ARE skip-if-none — there is nothing useful to create
      // when no per-endpoint indices exist yet.
      if (perEndpoint) {
        const esClient = context.core.opensearch.client.asCurrentUser;
        let indices: string[] = [];
        try {
          const catResp = await esClient.cat.indices({
            index: basePattern,
            format: 'json',
            h: 'index',
          });
          indices = ((catResp.body as Array<{ index?: string }>) ?? [])
            .map((row) => row.index)
            .filter((idx): idx is string => !!idx);
        } catch (err: any) {
          const status = err?.meta?.statusCode ?? err?.statusCode;
          if (status !== 404) {
            logger.warn(`tlsoc data_views _ensure: cat.indices failed, treating as no indices: ${err.message}`);
          }
          indices = [];
        }

        const slugs = new Set<string>();
        for (const idx of indices) {
          const m = ENDPOINT_INDEX_RE.exec(idx);
          if (m) slugs.add(m[1]);
        }

        for (const slug of Array.from(slugs).slice(0, MAX_ENDPOINT_VIEWS)) {
          const title = `fosstlsoc-logs-${slug}-*`;
          try {
            await indexPatterns.createAndSave({ title, timeFieldName: '@timestamp' }, false, true);
            ensured.push({ title, created: true });
          } catch (err: any) {
            if (isDuplicateIndexPatternError(err)) {
              ensured.push({ title, created: false });
            } else {
              logger.warn(`tlsoc data_views _ensure: could not create data view "${title}": ${err.message}`);
            }
          }
        }
      }

      return response.ok({ body: { ensured, defaultIndex } });
    }
  );
}
