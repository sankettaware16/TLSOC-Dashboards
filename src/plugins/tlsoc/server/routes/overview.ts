/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { schema } from '@osd/config-schema';
import { IRouter, Logger } from '../../../../core/server';
import { OverviewConfig } from '../config';
import { OverviewViewModel } from '../../common/overview/types';
import {
  windowToDuration,
  resolveDimensions,
  fieldPresent,
  fieldCapsFields,
  buildFilterClauses,
  buildOverviewAggs,
  buildInventoryAggs,
  toOverviewViewModel,
  mapInventory,
  OverviewFilters,
} from '../overview/query';

/** A query param that may arrive as a single string or an array; normalize to string[]. */
const strOrArray = schema.maybe(schema.oneOf([schema.string(), schema.arrayOf(schema.string())]));
function asArray(v: string | string[] | undefined): string[] | undefined {
  if (v === undefined) return undefined;
  return Array.isArray(v) ? v : [v];
}

/**
 * GET /api/tlsoc/overview?window=&org=&dept=&env=&endpoint=&logSource=
 *
 * The SIEM collection cockpit. Aggregates the agentless pipeline's output into coverage/health,
 * asset-discovery (new/silent), source-type breakdown, volume leaders, geo/ASN and recent events —
 * mapping-aware, gated to whatever the data contains, scoped by the filter bar. Runs asCurrentUser.
 *
 * States: pristine (no docs all-time / index_not_found), live, live+emptyWindow (quiet range).
 */
export function registerOverviewRoutes(router: IRouter, logger: Logger, overview: OverviewConfig) {
  router.get(
    {
      path: '/api/tlsoc/overview',
      validate: {
        query: schema.object(
          {
            window: schema.maybe(schema.string()),
            org: strOrArray,
            dept: strOrArray,
            env: strOrArray,
            endpoint: strOrArray,
            logSource: strOrArray,
          },
          { unknowns: 'ignore' }
        ),
      },
    },
    async (context, request, response) => {
      const index = overview.logIndexPattern;
      const q = request.query as Record<string, string | string[] | undefined>;
      const win = windowToDuration(q.window as string | undefined);
      const filters: OverviewFilters = {
        org: asArray(q.org),
        dept: asArray(q.dept),
        env: asArray(q.env),
        endpoint: asArray(q.endpoint),
        logSource: asArray(q.logSource),
      };
      const client = context.core.opensearch.client.asCurrentUser;
      const pristine = (): OverviewViewModel => ({ state: 'pristine', indexPattern: index });

      try {
        const { body: caps } = await client.fieldCaps({
          index,
          fields: fieldCapsFields(),
          ignore_unavailable: true,
          allow_no_indices: true,
        });
        const dims = resolveDimensions(caps as any);
        const hasIngested = fieldPresent(caps as any, 'event.ingested');
        const filterClauses = buildFilterClauses(filters, dims);

        const { body } = await client.search({
          index,
          body: buildOverviewAggs(win, dims, hasIngested, filterClauses) as Record<string, unknown>,
          ignore_unavailable: true,
          allow_no_indices: true,
        });

        const total = (body.hits?.total as { value?: number } | undefined)?.value ?? 0;

        if (total === 0) {
          const { body: countBody } = await client.count({ index, ignore_unavailable: true, allow_no_indices: true });
          if (!countBody.count) return response.ok({ body: pristine() });
          const { body: latest } = await client.search({
            index,
            body: { size: 1, sort: [{ '@timestamp': 'desc' }], _source: ['@timestamp'] },
            ignore_unavailable: true,
            allow_no_indices: true,
          });
          const latestHit = latest.hits?.hits?.[0]?._source as { '@timestamp'?: string } | undefined;
          return response.ok({
            body: {
              state: 'live',
              indexPattern: index,
              window: win,
              filters,
              emptyWindow: true,
              latestEventAllTime: latestHit?.['@timestamp'] ?? null,
              ...toOverviewViewModel(body, 0),
            } as OverviewViewModel,
          });
        }

        // Asset-discovery inventory (wide baseline, non-time filters applied). Best-effort: a
        // failure here must not sink the whole cockpit.
        let inventory = {};
        try {
          const { body: invBody } = await client.search({
            index,
            body: buildInventoryAggs(dims, filterClauses) as Record<string, unknown>,
            ignore_unavailable: true,
            allow_no_indices: true,
          });
          inventory = mapInventory(invBody, Date.now());
        } catch (invErr) {
          logger.warn(`tlsoc overview inventory failed: ${invErr.message}`);
        }

        return response.ok({
          body: {
            state: 'live',
            indexPattern: index,
            window: win,
            filters,
            ...toOverviewViewModel(body, total),
            ...inventory,
          } as OverviewViewModel,
        });
      } catch (err) {
        const status = err?.meta?.statusCode ?? err?.statusCode;
        const type = err?.meta?.body?.error?.type ?? err?.body?.error?.type;
        if (status === 404 || type === 'index_not_found_exception') {
          return response.ok({ body: pristine() });
        }
        logger.error(`tlsoc overview failed: ${err.message}`);
        return response.customError({
          statusCode: status ?? 500,
          body: { message: `Could not load overview: ${err.message}`, attributes: err.meta?.body },
        });
      }
    }
  );
}
