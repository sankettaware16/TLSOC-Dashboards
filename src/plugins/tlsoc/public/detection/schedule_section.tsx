/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from 'react';
import {
  EuiFieldNumber,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiTitle,
} from '@elastic/eui';
import { DetectionMode } from './ui_options';
import { TimeWindow } from '../../common/detection';

interface Props {
  mode: DetectionMode;
  /** The configured cadence R. Undefined = "use the default" (see the per-mode helper text). */
  runEvery?: TimeWindow;
  /** The threshold window T (stateful mode only) — used to validate R ≤ T for display purposes. */
  window?: TimeWindow;
  onChange: (runEvery: TimeWindow | undefined) => void;
}

/** Unit options for the "run every" cadence. Defined locally — ui_options.ts stays untouched. */
const RUN_EVERY_UNIT_OPTIONS: Array<{ value: TimeWindow['unit']; text: string }> = [
  { value: 'MINUTES', text: 'minutes' },
  { value: 'HOURS', text: 'hours' },
  { value: 'DAYS', text: 'days' },
];

/**
 * Display-only minutes conversion, so the inline validation below can compare R and T even when
 * they're expressed in different units. This is NOT the authoritative check — assertValidThresholdRule
 * in common/detection/internal.ts (windowMinutes) is what the compiler actually enforces.
 */
const MINUTES_PER_UNIT: Record<TimeWindow['unit'], number> = {
  MINUTES: 1,
  HOURS: 60,
  DAYS: 60 * 24,
};

function minutesOf(tw: TimeWindow): number {
  return tw.value * MINUTES_PER_UNIT[tw.unit];
}

/**
 * The "Schedule" panel — lets the analyst configure R, the monitor's run-every cadence (WS-20 /
 * PROB-20). Pure/presentational: it renders `runEvery` and reports changes via `onChange`; it never
 * touches the threshold window T (the range filter/timespan) — that stays wired to the "Threshold"
 * panel elsewhere in the builder. Wiring this into DetectionBuilder is the integrator's job.
 */
export function ScheduleSection({ mode, runEvery, window, onChange }: Props) {
  const defaultUnit: TimeWindow['unit'] =
    mode === 'stateful' && window ? window.unit : 'MINUTES';
  // Tracks the unit shown in the dropdown even while the value field is empty (no runEvery yet), so
  // picking a unit before typing a number doesn't get lost.
  const [unit, setUnit] = useState<TimeWindow['unit']>(runEvery?.unit ?? defaultUnit);

  useEffect(() => {
    if (runEvery) setUnit(runEvery.unit);
  }, [runEvery]);

  const displayValue = runEvery?.value ?? '';

  const isInvalid =
    mode === 'stateful' && !!runEvery && !!window && minutesOf(runEvery) > minutesOf(window);

  const helpText =
    mode === 'stateful'
      ? 'Default: once per threshold window (T). Must be ≤ the window — the evaluation window ' +
        'itself stays T; that is also why there is no separate "look-back": widening the window ' +
        'would change what "more than N in T" means.'
      : 'How often new events are scanned for matches. Default: every 1 minute.';

  return (
    <EuiPanel hasShadow={false} hasBorder>
      <EuiTitle size="xs">
        <h2>Schedule</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiFlexGroup>
        <EuiFlexItem grow={false} style={{ width: 160 }}>
          <EuiFormRow
            label="Run every"
            helpText={helpText}
            isInvalid={isInvalid}
            error={isInvalid ? 'Run-every must not exceed the threshold window.' : undefined}
          >
            <EuiFieldNumber
              placeholder="Default"
              min={1}
              value={displayValue}
              isInvalid={isInvalid}
              onChange={(e) => {
                const raw = e.target.value;
                if (raw === '') {
                  onChange(undefined);
                  return;
                }
                const n = Number(raw);
                onChange(Number.isNaN(n) ? undefined : { value: n, unit });
              }}
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false} style={{ width: 160 }}>
          <EuiFormRow label="Unit">
            <EuiSelect
              options={RUN_EVERY_UNIT_OPTIONS}
              value={unit}
              onChange={(e) => {
                const nextUnit = e.target.value as TimeWindow['unit'];
                setUnit(nextUnit);
                if (runEvery) onChange({ value: runEvery.value, unit: nextUnit });
              }}
            />
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>
    </EuiPanel>
  );
}
