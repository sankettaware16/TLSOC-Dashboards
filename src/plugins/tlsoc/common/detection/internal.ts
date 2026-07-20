/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  Condition,
  CountThreshold,
  LIST_OPERATORS,
  RuleDefinition,
  Severity,
  ThresholdRuleDefinition,
  TimeWindow,
  VALUELESS_OPERATORS,
} from './types';

/**
 * Shared, side-effect-free helpers used by BOTH compile targets, so the Sigma and doc-level
 * monitor outputs derive severity, validation, and naming identically (decision D-008).
 */

/** TLSOC severity → Sigma `level`. */
export const SEVERITY_TO_SIGMA_LEVEL: Record<Severity, string> = {
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'critical',
};

/**
 * TLSOC severity → OpenSearch Alerting trigger severity ("1".."5", where 1 is most severe).
 * See the Alerting monitor API: triggers[].*.severity.
 */
export const SEVERITY_TO_MONITOR_SEVERITY: Record<Severity, string> = {
  critical: '1',
  high: '2',
  medium: '3',
  low: '4',
};

/** Minutes per {@link TimeWindow} unit, for comparing two windows expressed in different units. */
const MINUTES_PER_UNIT: Record<TimeWindow['unit'], number> = {
  MINUTES: 1,
  HOURS: 60,
  DAYS: 60 * 24,
};

/** Express a {@link TimeWindow} in minutes, so windows in different units can be compared. */
export function windowMinutes(window: TimeWindow): number {
  return window.value * MINUTES_PER_UNIT[window.unit];
}

/** Validate a rule before compiling; throws an Error with a clear, user-facing message. */
export function assertValidRule(rule: RuleDefinition): void {
  if (!rule || typeof rule.name !== 'string' || rule.name.trim() === '') {
    throw new Error('Detection rule must have a non-empty name.');
  }
  if (typeof rule.index !== 'string' || rule.index.trim() === '') {
    throw new Error(`Detection rule "${rule.name}" must specify a data view.`);
  }
  if (!rule.group || !Array.isArray(rule.group.conditions) || rule.group.conditions.length === 0) {
    throw new Error(`Detection rule "${rule.name}" must have at least one condition.`);
  }
  rule.group.conditions.forEach((condition, index) =>
    assertValidCondition(condition, index, rule.name)
  );
  if (rule.runEvery && !(rule.runEvery.value > 0 && Number.isInteger(rule.runEvery.value))) {
    throw new Error(`Detection rule "${rule.name}" must have a positive run-every value.`);
  }
}

function assertValidCondition(condition: Condition, index: number, ruleName: string): void {
  const where = `condition ${index} ("${condition?.field}") in rule "${ruleName}"`;
  if (!condition || typeof condition.field !== 'string' || condition.field.trim() === '') {
    throw new Error(`${where}: a field is required.`);
  }
  if (LIST_OPERATORS.has(condition.operator)) {
    if (!Array.isArray(condition.values) || condition.values.length === 0) {
      throw new Error(`${where}: operator "${condition.operator}" requires a non-empty values list.`);
    }
  } else if (!VALUELESS_OPERATORS.has(condition.operator)) {
    if (condition.value === undefined || condition.value === null || condition.value === '') {
      throw new Error(`${where}: operator "${condition.operator}" requires a value.`);
    }
  }
}

/** Produce a slug usable as an OpenSearch doc-level monitor query id/name ([a-z0-9_]). */
export function slugify(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return slug || 'tlsoc_rule';
}

/** Threshold comparison operator → Painless comparator for the bucket-level trigger condition. */
export const PAINLESS_OP: Record<CountThreshold['operator'], string> = {
  gt: '>',
  gte: '>=',
  lt: '<',
  lte: '<=',
};

/** A composite-aggregation source name must not contain dots; derive a safe key from a field. */
export function compositeSourceName(field: string): string {
  return field.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'group';
}

/** Validate a stateful threshold rule before compiling; throws with a clear, user-facing message. */
export function assertValidThresholdRule(rule: ThresholdRuleDefinition): void {
  if (!rule || typeof rule.name !== 'string' || rule.name.trim() === '') {
    throw new Error('Threshold rule must have a non-empty name.');
  }
  if (typeof rule.index !== 'string' || rule.index.trim() === '') {
    throw new Error(`Threshold rule "${rule.name}" must specify a data view.`);
  }
  if (!rule.filter || !Array.isArray(rule.filter.conditions) || rule.filter.conditions.length === 0) {
    throw new Error(`Threshold rule "${rule.name}" must have at least one filter condition.`);
  }
  rule.filter.conditions.forEach((condition, index) =>
    assertValidCondition(condition, index, rule.name)
  );
  if (!Array.isArray(rule.groupBy) || rule.groupBy.length === 0) {
    throw new Error(`Threshold rule "${rule.name}" must group by at least one field.`);
  }
  if (!rule.window || !(rule.window.value > 0)) {
    throw new Error(`Threshold rule "${rule.name}" must have a positive time window.`);
  }
  if (!rule.threshold || !Number.isInteger(rule.threshold.value) || rule.threshold.value < 0) {
    throw new Error(`Threshold rule "${rule.name}" must have a non-negative integer threshold.`);
  }
  if (rule.runEvery) {
    if (!(rule.runEvery.value > 0 && Number.isInteger(rule.runEvery.value))) {
      throw new Error(`Threshold rule "${rule.name}" must have a positive run-every value.`);
    }
    if (windowMinutes(rule.runEvery) > windowMinutes(rule.window)) {
      throw new Error(
        `Threshold rule "${rule.name}": run-every must not exceed the threshold window — a longer ` +
          'cadence would leave time the rule never evaluates.'
      );
    }
  }
}
