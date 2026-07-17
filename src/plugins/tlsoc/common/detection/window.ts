/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TimeWindow } from './types';

/**
 * The single source of truth for the stateful time window T.
 *
 * The `@timestamp` range filter and the Sigma correlation `timespan` are ALL derived here from ONE
 * {@link TimeWindow} — T — and ONLY from T. There is no second place that computes T, so the range
 * filter and the timespan can never drift out of sync — the window-sync gotcha is eliminated by
 * construction, not merely tested against. Compilers must call this and use its output verbatim;
 * they must never recompute the range date-math themselves.
 *
 * The monitor `schedule` period, by contrast, is derived from the OPTIONAL cadence R (`runEvery`,
 * WS-20 / PROB-20) when supplied, falling back to T when it is not — R and T are deliberately
 * different knobs: R controls how often the monitor RUNS, T controls what window it evaluates.
 * Widening T's range using R (a "look-back") would silently change "N in T" semantics, so R never
 * touches `rangeFrom`/`timespan` — only `schedule`.
 */

/** Date-math abbreviation for each window unit. */
const UNIT_ABBREV: Record<TimeWindow['unit'], string> = {
  MINUTES: 'm',
  HOURS: 'h',
  DAYS: 'd',
};

export interface CompiledWindow {
  /** The monitor schedule period — the monitor runs once per window. */
  schedule: { period: { interval: number; unit: TimeWindow['unit'] } };
  /** The `@timestamp` range-filter lower bound, e.g. '{{period_end}}||-5m'. */
  rangeFrom: string;
  /** The same window expressed as a Sigma correlation `timespan`, e.g. '5m'. */
  timespan: string;
}

/**
 * Derive the schedule, the range-filter lower bound, and the Sigma timespan.
 *
 * `schedule.period` comes from `runEvery` (R) when given, otherwise from `window` (T) — the legacy
 * default, byte-identical to the pre-WS-20 single-arg behavior. `rangeFrom` and `timespan` ALWAYS
 * come from `window` (T) alone, regardless of `runEvery` — see the file docblock.
 */
export function buildWindow(window: TimeWindow, runEvery?: TimeWindow): CompiledWindow {
  const abbrev = UNIT_ABBREV[window.unit];
  const schedulePeriod = runEvery ?? window;
  return {
    schedule: { period: { interval: schedulePeriod.value, unit: schedulePeriod.unit } },
    rangeFrom: `{{period_end}}||-${window.value}${abbrev}`,
    timespan: `${window.value}${abbrev}`,
  };
}
