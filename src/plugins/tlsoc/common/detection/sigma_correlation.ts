/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { dump } from 'js-yaml';
import { RuleDefinition, ThresholdRuleDefinition } from './types';
import { SEVERITY_TO_SIGMA_LEVEL, assertValidThresholdRule, slugify } from './internal';
import { buildSigmaRule } from './sigma';
import { buildWindow } from './window';

/**
 * Compile a stateful threshold rule to a portable Sigma EVENT_COUNT CORRELATION rule. Per decision
 * D-008 this is an EXPORT artifact only — OpenSearch does not execute Sigma correlation rules (they
 * are consumed by pySigma-compatible tooling); the bucket-level monitor is the execution path.
 *
 * Emits a two-document YAML: the correlation rule first, then a base detection rule (built from the
 * filter via the stateless compiler) carrying the top-level `name:` the correlation references. The
 * `timespan` is taken from {@link buildWindow} — the SAME source of truth as the monitor's schedule —
 * so the Sigma window cannot drift from the monitor window.
 *
 * All field names (`correlation`, `type: event_count`, `rules`, `group-by`, `timespan`, `condition`,
 * the base-rule top-level `name`, and the `---` multi-document layout) are verified against the
 * SigmaHQ correlation-rules specification v2.1.0.
 */

const DUMP_OPTS = { lineWidth: -1, noRefs: true, sortKeys: false };

export function compileToSigmaCorrelation(rule: ThresholdRuleDefinition): string {
  assertValidThresholdRule(rule);
  const window = buildWindow(rule.window);
  const baseName = `${slugify(rule.name)}_base`;
  const level = SEVERITY_TO_SIGMA_LEVEL[rule.severity];

  // The base detection rule (the WHERE) — reuse the stateless Sigma compiler, then insert a top-level
  // `name:` right after `title:` so the correlation `rules:` list can reference it by name.
  const baseRuleDef: RuleDefinition = {
    name: `${rule.name} (base)`,
    description: rule.description,
    severity: rule.severity,
    index: rule.index,
    logSource: rule.logSource,
    group: rule.filter,
  };
  const baseDoc: Record<string, unknown> = {};
  Object.entries(buildSigmaRule(baseRuleDef)).forEach(([key, value]) => {
    baseDoc[key] = value;
    if (key === 'title') {
      baseDoc.name = baseName;
    }
  });

  // The correlation rule.
  const correlationDoc: Record<string, unknown> = { title: rule.name };
  if (rule.id !== undefined) correlationDoc.id = rule.id;
  correlationDoc.status = 'experimental';
  if (rule.description !== undefined) correlationDoc.description = rule.description;
  if (rule.references !== undefined) correlationDoc.references = rule.references;
  if (rule.author !== undefined) correlationDoc.author = rule.author;
  if (rule.date !== undefined) correlationDoc.date = rule.date;
  correlationDoc.correlation = {
    type: 'event_count',
    rules: [baseName],
    'group-by': [...rule.groupBy],
    timespan: window.timespan,
    condition: { [rule.threshold.operator]: rule.threshold.value },
  };
  correlationDoc.level = level;

  // Spec layout: the correlation rule first, then the base rule(s), separated by `---`.
  return `${dump(correlationDoc, DUMP_OPTS)}---\n${dump(baseDoc, DUMP_OPTS)}`;
}
