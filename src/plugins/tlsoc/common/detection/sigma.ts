/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { dump } from 'js-yaml';
import { Condition, ConditionGroup, RuleDefinition, ThreatEntry } from './types';
import { SEVERITY_TO_SIGMA_LEVEL, assertValidRule } from './internal';

/**
 * Compile the detection IR to a Sigma rule. Per decision D-008 the Sigma output is a PORTABLE
 * EXPORT artifact (shareable / interoperable) — it is NOT the execution path; the doc-level Alerting
 * monitor is what actually runs. The operator set here is kept in exact sync with {@link conditionToLucene}.
 */

interface SigmaBlock {
  /** The selection identifier referenced from `detection.condition`, e.g. 'sel0'. */
  key: string;
  /** The selection body, e.g. `{ 'source.ip|contains': 'x' }`. */
  body: Record<string, unknown>;
  /** Whether the `condition` string negates this block (`not selN`). */
  negate: boolean;
}

function detectionKey(field: string, modifier?: string): string {
  return modifier ? `${field}|${modifier}` : field;
}

/**
 * Build one named Sigma selection block for a predicate, plus whether the condition negates it.
 * Each predicate gets its OWN block so multiple predicates on the same field never collide and
 * negation composes correctly (`A and not B` rather than `not (A and B)`).
 */
function conditionToBlock(condition: Condition, index: number): SigmaBlock {
  const key = `sel${index}`;
  const { field, operator, value, values } = condition;
  switch (operator) {
    case 'equals':
      return { key, body: { [field]: value! }, negate: false };
    case 'not_equals':
      return { key, body: { [field]: value! }, negate: true };
    case 'contains':
      return { key, body: { [detectionKey(field, 'contains')]: value! }, negate: false };
    case 'not_contains':
      return { key, body: { [detectionKey(field, 'contains')]: value! }, negate: true };
    case 'starts_with':
      return { key, body: { [detectionKey(field, 'startswith')]: value! }, negate: false };
    case 'ends_with':
      return { key, body: { [detectionKey(field, 'endswith')]: value! }, negate: false };
    case 'is_one_of':
      return { key, body: { [field]: [...values!] }, negate: false };
    case 'is_not_one_of':
      return { key, body: { [field]: [...values!] }, negate: true };
    case 'exists':
      return { key, body: { [detectionKey(field, 'exists')]: true }, negate: false };
    case 'not_exists':
      return { key, body: { [detectionKey(field, 'exists')]: false }, negate: false };
    case 'gt':
      return { key, body: { [detectionKey(field, 'gt')]: value! }, negate: false };
    case 'gte':
      return { key, body: { [detectionKey(field, 'gte')]: value! }, negate: false };
    case 'lt':
      return { key, body: { [detectionKey(field, 'lt')]: value! }, negate: false };
    case 'lte':
      return { key, body: { [detectionKey(field, 'lte')]: value! }, negate: false };
    case 'matches_regex':
      return { key, body: { [detectionKey(field, 're')]: value! }, negate: false };
    default:
      // A new operator must be handled in BOTH compilers (the D-008 sync requirement).
      throw new Error(`Unsupported detection operator: ${(condition as Condition).operator}`);
  }
}

function buildConditionString(group: ConditionGroup, blocks: SigmaBlock[]): string {
  const joiner = group.logic === 'AND' ? ' and ' : ' or ';
  return blocks.map((block) => (block.negate ? `not ${block.key}` : block.key)).join(joiner);
}

/**
 * Derive Sigma `tags` from a rule's MITRE `threat` metadata: one `attack.<tactic_snake>` tag per
 * tactic, plus one `attack.<technique_id lowercased>` tag per technique/sub-technique — the
 * conventional Sigma ATT&CK tagging scheme. Returns `[]` when nothing is taggable (caller omits
 * the field entirely rather than emitting an empty list — matches the file's whitelist idiom).
 */
function tagsFromThreat(threat: ThreatEntry[]): string[] {
  const tags: string[] = [];
  for (const entry of threat) {
    if (entry.tactic?.name) {
      tags.push(`attack.${entry.tactic.name.toLowerCase().replace(/\s+/g, '_')}`);
    }
    for (const technique of entry.technique ?? []) {
      if (technique.id) tags.push(`attack.${technique.id.toLowerCase()}`);
      for (const sub of technique.subtechnique ?? []) {
        if (sub.id) tags.push(`attack.${sub.id.toLowerCase()}`);
      }
    }
  }
  return tags;
}

function buildLogSource(rule: RuleDefinition): Record<string, unknown> {
  const logsource: Record<string, unknown> = {};
  if (rule.logSource?.category) logsource.category = rule.logSource.category;
  if (rule.logSource?.product) logsource.product = rule.logSource.product;
  if (rule.logSource?.service) logsource.service = rule.logSource.service;
  // Sigma requires a logsource; fall back to the index pattern as a product hint when none is given.
  if (Object.keys(logsource).length === 0) logsource.product = rule.index;
  return logsource;
}

/** Build the Sigma rule as a plain object (handy for tests; serialized by {@link compileToSigma}). */
export function buildSigmaRule(rule: RuleDefinition): Record<string, unknown> {
  assertValidRule(rule);
  const blocks = rule.group.conditions.map(conditionToBlock);

  const detection: Record<string, unknown> = {};
  blocks.forEach((block) => {
    detection[block.key] = block.body;
  });
  detection.condition = buildConditionString(rule.group, blocks);

  const sigma: Record<string, unknown> = { title: rule.name };
  if (rule.id !== undefined) sigma.id = rule.id;
  sigma.status = 'experimental';
  if (rule.description !== undefined) sigma.description = rule.description;
  if (rule.references !== undefined) sigma.references = rule.references;
  if (rule.author !== undefined) sigma.author = rule.author;
  if (rule.date !== undefined) sigma.date = rule.date;
  if (rule.threat !== undefined) {
    const tags = tagsFromThreat(rule.threat);
    if (tags.length > 0) sigma.tags = tags;
  }
  if (rule.falsePositives !== undefined) sigma.falsepositives = rule.falsePositives;
  sigma.logsource = buildLogSource(rule);
  sigma.detection = detection;
  sigma.level = SEVERITY_TO_SIGMA_LEVEL[rule.severity];
  return sigma;
}

/** Compile a rule to a portable Sigma YAML string (export artifact only — not the execution path). */
export function compileToSigma(rule: RuleDefinition): string {
  return dump(buildSigmaRule(rule), { lineWidth: -1, noRefs: true, sortKeys: false });
}
