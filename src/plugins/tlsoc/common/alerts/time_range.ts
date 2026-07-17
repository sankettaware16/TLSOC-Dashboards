/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import dateMath from '@elastic/datemath';

/** The epoch-ms bounds resolved from a pair of datemath strings (WS-3, PROB-3). */
export interface ResolvedDateRange {
  from?: number;
  to?: number;
}

/** Parse one datemath bound → epoch ms, or `undefined` on empty/unparseable/invalid input. */
function parseBound(value: string | undefined, roundUp: boolean, now: Date | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = dateMath.parse(value, { roundUp, forceNow: now });
  if (!parsed || !parsed.isValid()) return undefined;
  return parsed.valueOf();
}

/**
 * Resolve a pair of datemath strings (e.g. `'now-24h'` / `'now'`, or an absolute ISO string) to
 * epoch milliseconds — the shape TLSOC's `GET /api/tlsoc/alerts` route accepts as `from`/`to` query
 * params. `end` is round-up parsed (`'now-24h'/'now'` → the end of "now", not its start instant;
 * matters for calendar-rounded strings like `'now/d'`).
 *
 * Pure given an explicit `now` (tests inject a fixed reference instant via datemath's own
 * `forceNow`, so this is fully deterministic). The client calls this with NO `now` override so it
 * always resolves against the real current instant — which is exactly what makes a relative range
 * like `'now-24h'..'now'` roll forward on every auto-refresh fetch instead of freezing at whatever
 * moment the picker was last touched (WS-1/3 design: "convert datemath → epoch ms AT FETCH TIME").
 *
 * An unparseable/empty/invalid string resolves to `undefined` for that bound — degrades to "no
 * bound" rather than throwing, so a stray or partial picker string can never crash a fetch.
 */
export function resolveDateMathRange(
  start: string | undefined,
  end: string | undefined,
  now?: Date
): ResolvedDateRange {
  return {
    from: parseBound(start, false, now),
    to: parseBound(end, true, now),
  };
}
