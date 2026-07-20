/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { schema } from '@osd/config-schema';
import { IRouter, Logger } from '../../../../core/server';
import {
  formatDqlTranslationErrors,
  translateDqlToLucene,
} from '../../common/detection/dql_to_lucene';

/**
 * POST /api/tlsoc/detection/_validate — pre-save validation for D2 custom-query rules.
 *
 * WHY: the Alerting engine NEVER validates doc-level queries — a malformed query is accepted at
 * save and silently matches nothing forever (the silent-failure class, research_r2 §b). So TLSOC
 * validates BEFORE save with the cluster's own parser: `GET /<index>/_validate/query` over a
 * `query_string` clause (live-verified on OpenSearch 3.7: invalid → valid:false + the full Lucene
 * ParseException with line/column in explanations[].error — research_r3 §5).
 *
 * DQL ('kuery') is parsed + subset-translated server-side with the SAME code the compiler uses
 * (common/detection/dql_to_lucene.ts), then the TRANSLATED Lucene is validated against the
 * cluster — belt and braces: what gets validated is exactly what the monitor will run.
 *
 * THE 0-SHARDS TRAP (live-verified): with allow_no_indices=true a nothing-matching pattern
 * returns `valid:true` with `_shards.total: 0` — "valid" while NOTHING was checked. That is
 * reported as valid:false ("cannot validate yet"), mirroring the save path's no-matching-indices
 * error (monitors.ts prepareMonitor).
 *
 * Read-only and open to any authenticated user (the detection.ts dry-run idiom): it runs with the
 * caller's own credentials via asCurrentUser and changes nothing.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

/** The cluster's answer about one Lucene query: usable, or not (with the parser's own words). */
export type LuceneValidationVerdict = { valid: true } | { valid: false; reason: string };

/**
 * Validate a Lucene `query_string` against `index` with the cluster's own parser — the shared
 * core of the pre-save gate (v1.2.3 W2 review, BLOCKING-2). Used by the interactive `_validate`
 * route below AND by the save path (monitors.ts prepareMonitor), so a custom-query rule can never
 * be persisted without the exact executed Lucene having parsed against real shards.
 *
 * Returns a VERDICT for invalid queries, the 0-shards trap, and 404s (all "the query/index is the
 * problem" outcomes); throws only on real cluster failures (auth, connectivity, 5xx).
 */
export async function validateLuceneQuery(
  esClient: any,
  index: string,
  lucene: string
): Promise<LuceneValidationVerdict> {
  const noIndices = `no indices currently match "${index}" — cannot validate yet`;
  try {
    const resp = await esClient.transport.request({
      method: 'GET',
      path: `/${encodeURIComponent(index)}/_validate/query`,
      querystring: {
        allow_no_indices: 'true',
        ignore_unavailable: 'true',
        explain: 'true',
      },
      body: {
        // The exact clause shape the doc-level runner gives the query (query_string), so the
        // cluster parses precisely what will execute. analyze_wildcard mirrors runtime behavior
        // for leading/trailing wildcards.
        query: { query_string: { query: lucene, analyze_wildcard: true } },
      },
    });
    const body = (resp as any).body ?? {};

    // "valid" with zero shards means NOTHING was validated (the live-verified trap).
    if ((body?._shards?.total ?? 0) === 0) {
      return { valid: false, reason: noIndices };
    }
    if (body?.valid === false) {
      const details = ((body?.explanations ?? []) as any[])
        .map((e) => e?.error)
        .filter((e): e is string => typeof e === 'string' && e.length > 0);
      return {
        valid: false,
        reason: details.length > 0 ? details.join('\n') : 'The query is invalid.',
      };
    }
    return { valid: true };
  } catch (err: any) {
    // A 404 despite allow_no_indices (e.g. a concrete not-found name on some engine versions)
    // is the same "nothing to validate against yet" situation, not a server failure.
    if ((err?.meta?.statusCode ?? err?.statusCode) === 404) {
      return { valid: false, reason: noIndices };
    }
    throw err;
  }
}

export function registerDetectionValidateRoutes(router: IRouter, logger: Logger) {
  router.post(
    {
      path: '/api/tlsoc/detection/_validate',
      validate: {
        body: schema.object({
          index: schema.string(),
          query: schema.string(),
          // Checked in-handler so an unknown language 400s BY NAME (the registry discipline).
          language: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      const { index, query, language } = request.body as {
        index: string;
        query: string;
        language: string;
      };

      if (language !== 'lucene' && language !== 'kuery') {
        return response.badRequest({
          body: { message: `Unsupported query language "${language}". Supported: lucene, kuery.` },
        });
      }

      // DQL: parse + subset-translate first (client-equivalent — same module the compiler uses).
      // A parse/subset failure is a VERDICT on the query, not a server error: 200 + valid:false.
      let lucene = query;
      if (language === 'kuery') {
        const translated = translateDqlToLucene(query);
        if (!translated.ok) {
          return response.ok({
            body: { valid: false, reason: formatDqlTranslationErrors(translated.errors) },
          });
        }
        lucene = translated.lucene;
      }

      const esClient = context.core.opensearch.client.asCurrentUser;
      try {
        const verdict = await validateLuceneQuery(esClient, index, lucene);
        return response.ok({ body: verdict });
      } catch (err: any) {
        logger.error(`tlsoc detection _validate failed: ${err.message}`);
        return response.customError({
          statusCode: err?.meta?.statusCode ?? 500,
          body: {
            message: `Query validation failed: ${err.message}`,
            attributes: err?.meta?.body,
          },
        });
      }
    }
  );
}
