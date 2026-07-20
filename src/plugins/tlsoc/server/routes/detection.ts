/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { schema } from '@osd/config-schema';
import { IRouter, Logger } from '../../../../core/server';
import { getType, isValidMode, unknownTypeMessage } from '../../common/detection';

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Pull the fired group-key arrays out of a bucket-level Alerting `_execute` response.
 * Triggered groups live at
 *   `trigger_results[<triggerId>].agg_result_buckets[<key>].agg_alert_content.bucket_keys`
 * (e.g. `["66.66.66.66"]`) — VERIFIED LIVE against OpenSearch 3.7 Alerting (the keys are nested under
 * `agg_alert_content`, one level deeper than the docs/model suggested). A flat `bucket_keys` is kept
 * as a fallback for other versions.
 */
function extractFiredGroups(executeBody: any): string[][] {
  const triggerResults = executeBody?.trigger_results ?? {};
  const groups: string[][] = [];
  Object.values(triggerResults).forEach((triggerResult: any) => {
    const buckets = triggerResult?.agg_result_buckets ?? {};
    Object.values(buckets).forEach((bucket: any) => {
      const keys = bucket?.agg_alert_content?.bucket_keys ?? bucket?.bucket_keys;
      if (Array.isArray(keys)) {
        groups.push(keys);
      }
    });
  });
  return groups;
}

/**
 * POST /api/tlsoc/detection/_execute — compile a no-code rule and DRY-RUN it against OpenSearch
 * Alerting (no monitor is saved, no actions fire). Returns the compiled monitor (so the caller can
 * see exactly what executed), the raw `_execute` response, and the list of fired group keys.
 *
 * Optional `timeRange` evaluates the compiled (stateful) monitor over an absolute window instead of
 * the relative one it emits — a backtest affordance of this test endpoint. The compiler is NOT
 * changed: it still emits the production-correct relative `{{period_end}}` window.
 */
export function registerExecuteDetectionRoute(router: IRouter, logger: Logger) {
  router.post(
    {
      path: '/api/tlsoc/detection/_execute',
      validate: {
        body: schema.object({
          // The registry check below replaces the old schema.oneOf mode literals, so a new registry
          // type needs no edit here; an unknown id 400s BY NAME instead of a generic schema error.
          mode: schema.string(),
          rule: schema.object({}, { unknowns: 'allow' }),
          timeRange: schema.maybe(
            schema.object({ from: schema.string(), to: schema.string() })
          ),
        }),
      },
    },
    async (context, request, response) => {
      const { mode, rule, timeRange } = request.body as {
        mode: string;
        rule: Record<string, unknown>;
        timeRange?: { from: string; to: string };
      };

      if (!isValidMode(mode)) {
        return response.badRequest({ body: { message: unknownTypeMessage(mode) } });
      }
      const ruleType = getType(mode);

      // 1) Compile the rule via the type registry (the same unit-tested code in common/detection).
      let monitor: Record<string, any>;
      try {
        monitor = ruleType.compile(rule) as any;
      } catch (err) {
        return response.badRequest({ body: { message: `Rule did not compile: ${err.message}` } });
      }

      // 2) Optional backtest: evaluate the compiled monitor over an absolute window. Keyed off the
      // registry's monitorKind — only bucket-level monitors carry the @timestamp range search input
      // this rewrites (doc-level monitors have no window at all).
      if (timeRange && ruleType.monitorKind === 'bucket') {
        const filters = monitor?.inputs?.[0]?.search?.query?.query?.bool?.filter;
        const rangeClause = Array.isArray(filters)
          ? filters.find((f: any) => f?.range?.['@timestamp'])
          : undefined;
        if (rangeClause) {
          rangeClause.range['@timestamp'] = {
            gte: timeRange.from,
            lte: timeRange.to,
            format: 'strict_date_optional_time',
          };
        }
      }

      // 3) Dry-run against the cluster (no save, no actions): POST .../monitors/_execute?dryrun=true.
      const client = context.core.opensearch.client.asCurrentUser;
      try {
        const executed = await client.transport.request({
          method: 'POST',
          path: '/_plugins/_alerting/monitors/_execute',
          body: monitor,
          querystring: { dryrun: 'true' },
        });
        const executeBody = (executed as any).body;
        return response.ok({
          body: {
            accepted: true,
            firedGroups: extractFiredGroups(executeBody),
            monitor,
            execute: executeBody,
          },
        });
      } catch (err) {
        logger.error(`tlsoc detection _execute failed: ${err.message}`);
        return response.customError({
          statusCode: err.meta?.statusCode ?? 500,
          body: {
            message: `Alerting _execute failed: ${err.message}`,
            attributes: err.meta?.body,
          },
        });
      }
    }
  );
}
