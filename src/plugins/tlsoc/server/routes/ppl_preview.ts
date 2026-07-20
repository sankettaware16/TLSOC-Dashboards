/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { schema } from '@osd/config-schema';
import { IRouter, Logger } from '../../../../core/server';
import { buildPplPreviewQuery, parsePpl } from '../../common/detection/ppl_parse';

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * POST /api/tlsoc/detection/_ppl_preview (v1.2.3 D3, research_r4.md §6) — run a PPL detection
 * query as an ADVISORY preview against `POST /_plugins/_ppl`.
 *
 * - The query is RE-PARSED server-side with the same subset parser the editor uses — the client
 *   is never trusted; anything outside the subset 400s with the named construct before it can
 *   reach the engine.
 * - The executed text is GENERATED: the user query with the rule window injected as a
 *   time-field conjunct into the last pre-stats `where` (or a new one), plus `| head 100`. The
 *   window uses `date_sub(now(), interval n unit)` — NEVER `timestampadd`, whose lowercase units
 *   silently constant-fold the filter to FALSE on 3.7 (zero rows, no error — the R4 trap).
 * - Runs `asCurrentUser` (the alerts.ts/data_views.ts idiom): the security plugin enforces the
 *   CALLING user's index permissions plus the PPL cluster permission. Like the `_execute`
 *   dry-run route (detection.ts), preview is open to any authenticated user — it writes nothing.
 * - Engine errors map to clean route responses (SyntaxCheckException / FIELD_NOT_FOUND /
 *   INDEX_NOT_FOUND / 403), mirroring detection.ts's customError shape for the rest.
 */
export function registerPplPreviewRoutes(router: IRouter, logger: Logger) {
  router.post(
    {
      path: '/api/tlsoc/detection/_ppl_preview',
      validate: {
        body: schema.object({
          pplText: schema.string(),
          /** The data view's time field — the injected window conjunct is written against it. */
          timeField: schema.string(),
          windowValue: schema.number(),
          windowUnit: schema.oneOf([
            schema.literal('MINUTES'),
            schema.literal('HOURS'),
            schema.literal('DAYS'),
          ]),
        }),
      },
    },
    async (context, request, response) => {
      const { pplText, timeField, windowValue, windowUnit } = request.body;

      // 1) Never trust the client: re-parse and REJECT on any parse error, naming the construct.
      const parsed = parsePpl(pplText);
      if (!parsed.ok) {
        const first = parsed.errors[0];
        return response.badRequest({
          body: {
            message: `PPL query is invalid — ${first.construct}: ${first.reason}`,
            attributes: { errors: parsed.errors },
          },
        });
      }
      if (!(Number.isInteger(windowValue) && windowValue > 0)) {
        return response.badRequest({
          body: { message: 'windowValue must be a positive integer.' },
        });
      }
      // The time field is backtick-quoted into the generated query; backticks have no escape.
      if (timeField.trim() === '' || timeField.includes('`')) {
        return response.badRequest({
          body: { message: `Invalid time field "${timeField}".` },
        });
      }

      // 2) Generate the preview text (window conjunct + head cap).
      const query = buildPplPreviewQuery(pplText, timeField, {
        value: windowValue,
        unit: windowUnit,
      });

      // 3) Execute as the calling user.
      const client = context.core.opensearch.client.asCurrentUser;
      try {
        const executed = await client.transport.request({
          method: 'POST',
          path: '/_plugins/_ppl',
          body: { query },
        });
        const body = (executed as any).body ?? {};
        return response.ok({
          body: {
            query,
            schema: Array.isArray(body.schema) ? body.schema : [],
            datarows: Array.isArray(body.datarows) ? body.datarows : [],
            total: typeof body.total === 'number' ? body.total : 0,
            size: typeof body.size === 'number' ? body.size : 0,
          },
        });
      } catch (err) {
        const statusCode: number | undefined = err.meta?.statusCode;
        const engineBody = err.meta?.body;
        // The engine wraps some errors as {error:{reason,details,type}} and others flat
        // ({code,type,context}) — read both shapes defensively (research_r2 §c).
        const engineError = engineBody?.error ?? engineBody ?? {};
        const type: string | undefined = engineError.type ?? engineBody?.type;
        const code: string | undefined = engineBody?.code ?? engineError.code;
        const details: string =
          engineError.details ?? engineError.reason ?? err.message ?? 'unknown engine error';
        const indices = parsed.rule.indices.join(', ');

        if (statusCode === 403 || statusCode === 401) {
          return response.forbidden({
            body: {
              message:
                `You lack permission to query "${indices}" with PPL — it needs the PPL cluster ` +
                'permission plus read access to the index.',
            },
          });
        }
        if (code === 'INDEX_NOT_FOUND' || type === 'IndexNotFoundException') {
          return response.notFound({
            body: { message: `Index not found: ${indices}.` },
          });
        }
        if (code === 'FIELD_NOT_FOUND') {
          return response.badRequest({
            body: { message: `The engine rejected a field in the query: ${details}` },
          });
        }
        if (type === 'SyntaxCheckException') {
          // Should be rare — the subset parser pre-validates — but surface it raw if it happens.
          return response.badRequest({
            body: { message: `The engine rejected the PPL query: ${details}` },
          });
        }
        logger.error(`tlsoc ppl preview failed: ${err.message}`);
        return response.customError({
          statusCode: statusCode ?? 500,
          body: {
            message: `PPL preview failed: ${details}`,
            attributes: engineBody,
          },
        });
      }
    }
  );
}
