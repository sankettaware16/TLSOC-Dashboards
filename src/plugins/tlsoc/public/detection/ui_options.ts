/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { CountThreshold, DetectionOperator, Severity, TimeWindow } from '../../common/detection';

// DetectionMode's single source of truth is the rule-type registry (common/detection/registry.ts);
// the type chooser is the registry-driven card grid (type_registry.tsx), which replaced the old
// MODE_OPTIONS button group here (v1.2.3 D1).

/** Per-operator UI metadata: the label, how many values it takes, and whether the value is numeric. */
export interface OperatorOption {
  value: DetectionOperator;
  text: string;
  arity: 'value' | 'list' | 'none';
  numeric?: boolean;
}

/** The v1 operator set, surfaced in the builder. Order = how they appear in the dropdown. */
export const OPERATOR_OPTIONS: OperatorOption[] = [
  { value: 'equals', text: 'equals', arity: 'value' },
  { value: 'not_equals', text: 'does not equal', arity: 'value' },
  { value: 'contains', text: 'contains', arity: 'value' },
  { value: 'not_contains', text: 'does not contain', arity: 'value' },
  { value: 'starts_with', text: 'starts with', arity: 'value' },
  { value: 'ends_with', text: 'ends with', arity: 'value' },
  { value: 'is_one_of', text: 'is one of', arity: 'list' },
  { value: 'is_not_one_of', text: 'is not one of', arity: 'list' },
  { value: 'exists', text: 'exists', arity: 'none' },
  { value: 'not_exists', text: 'does not exist', arity: 'none' },
  { value: 'gt', text: 'greater than (>)', arity: 'value', numeric: true },
  { value: 'gte', text: 'greater than or equal (>=)', arity: 'value', numeric: true },
  { value: 'lt', text: 'less than (<)', arity: 'value', numeric: true },
  { value: 'lte', text: 'less than or equal (<=)', arity: 'value', numeric: true },
  { value: 'matches_regex', text: 'matches regex', arity: 'value' },
];

export const SEVERITY_OPTIONS: Array<{ value: Severity; text: string }> = [
  { value: 'low', text: 'Low' },
  { value: 'medium', text: 'Medium' },
  { value: 'high', text: 'High' },
  { value: 'critical', text: 'Critical' },
];

export const WINDOW_UNIT_OPTIONS: Array<{ value: TimeWindow['unit']; text: string }> = [
  { value: 'MINUTES', text: 'minutes' },
  { value: 'HOURS', text: 'hours' },
  { value: 'DAYS', text: 'days' },
];

export const THRESHOLD_OP_OPTIONS: Array<{ value: CountThreshold['operator']; text: string }> = [
  { value: 'gt', text: 'more than (>)' },
  { value: 'gte', text: 'at least (>=)' },
  { value: 'lt', text: 'fewer than (<)' },
  { value: 'lte', text: 'at most (<=)' },
];
