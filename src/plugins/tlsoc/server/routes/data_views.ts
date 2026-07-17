/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { schema } from '@osd/config-schema';
import { IRouter, Logger } from '../../../../core/server';
import { PluginStart as DataPluginStart } from '../../../data/server';
import { DuplicateIndexPatternError } from '../../../data/common';

/** The all-logs pattern the agentless pipeline writes to (PROB-2 / PROB-16 naming). */
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
 * `POST /api/tlsoc/data_views/_ensure` — PROB-2 fix.
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
 * Never creates a view whose title matches ZERO concrete indices — that saves an empty fields
 * cache that silently breaks Discover, so step (a) below is a hard gate, not an optimization.
 */
export function registerDataViewsRoutes(
  router: IRouter,
  logger: Logger,
  getIndexPatternsServiceFactory: GetIndexPatternsServiceFactory
) {
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
      const esClient = context.core.opensearch.client.asCurrentUser;

      // (a) Concrete indices matching the all-logs pattern. None → skip entirely; creating a data
      // view against zero matching indices would silently save an empty fields cache (verified
      // failure mode — breaks Discover).
      let indices: string[] = [];
      try {
        const catResp = await esClient.cat.indices({
          index: ALL_LOGS_INDEX_PATTERN,
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

      if (indices.length === 0) {
        return response.ok({ body: { ensured: [], skipped: 'no-indices' } });
      }

      // (d) Per-endpoint slugs, derived from the concrete index names, deduped + capped.
      const titles = [ALL_LOGS_INDEX_PATTERN];
      if (perEndpoint) {
        const slugs = new Set<string>();
        for (const idx of indices) {
          const m = ENDPOINT_INDEX_RE.exec(idx);
          if (m) slugs.add(m[1]);
        }
        for (const slug of Array.from(slugs).slice(0, MAX_ENDPOINT_VIEWS)) {
          titles.push(`fosstlsoc-logs-${slug}-*`);
        }
      }

      // (b) A request-scoped index-patterns service instance — the workspace context flows in
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

      // (c)/(d) Ensure each title. Fields fetch live (indices exist by construction of step a).
      // Per-title failures are tolerated — collected in the log, execution continues.
      const ensured: Array<{ title: string; created: boolean }> = [];
      for (const title of titles) {
        try {
          await indexPatterns.createAndSave({ title, timeFieldName: '@timestamp' }, false, false);
          ensured.push({ title, created: true });
        } catch (err: any) {
          if (isDuplicateIndexPatternError(err)) {
            ensured.push({ title, created: false });
          } else {
            logger.warn(`tlsoc data_views _ensure: could not create data view "${title}": ${err.message}`);
          }
        }
      }

      return response.ok({ body: { ensured } });
    }
  );
}
