/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TimeWindow } from './types';

/**
 * The single source of truth for the stateful time window T.
 *
 * The bucket-level monitor's schedule, its `@timestamp` range filter, and the Sigma correlation
 * `timespan` are ALL derived here from one {@link TimeWindow}. There is no second place that computes
 * T, so the three can never drift out of sync — the window-sync gotcha is eliminated by construction,
 * not merely tested against. Compilers must call this and use its output verbatim; they must never
 * recompute the schedule interval or the range date-math themselves.
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

/** Derive the schedule, the range-filter lower bound, and the Sigma timespan from one window. */
export function buildWindow(window: TimeWindow): CompiledWindow {
  const abbrev = UNIT_ABBREV[window.unit];
  return {
    schedule: { period: { interval: window.value, unit: window.unit } },
    rangeFrom: `{{period_end}}||-${window.value}${abbrev}`,
    timespan: `${window.value}${abbrev}`,
  };
}
