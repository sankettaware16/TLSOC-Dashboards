/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { RuleDefinition, ThresholdRuleDefinition } from './types';
import { assertValidRule, assertValidThresholdRule } from './internal';
import { compileSuppressedStatelessToBucketMonitor, compileToDocLevelMonitor } from './monitor';
import { compileToBucketLevelMonitor } from './bucket_monitor';
import { compileAggregationRule, thresholdRuleToAggregationInput } from './agg_compile';
import { compileToSigma } from './sigma';
import { compileToSigmaCorrelation } from './sigma_correlation';
import { assertValidPplRule, pplRuleToCompileInput, PplRuleDefinition } from './ppl_rule';
import {
  assertValidCustomQueryRule,
  compileCustomQueryToMonitor,
  compileSuppressedCustomQueryToBucketMonitor,
  CustomQueryRuleDefinition,
} from './custom_query';
import {
  NewTermsRuleDefinition,
  assertValidNewTermsRule,
  compileNewTermsToMonitor,
} from './new_terms';
import {
  IndicatorMatchRuleDefinition,
  assertValidIndicatorMatchRule,
  compileIndicatorLookupToBucketMonitor,
} from './indicator_match';

/**
 * The rule-TYPE registry (v1.2.3 D1) — the ONE place a detection type's execution contract lives.
 * Every shared dispatch point (buildMonitorForSave, the `_execute` dry-run route, the save routes'
 * mode validation, the doc-level alias/exec-target machinery) looks types up here instead of
 * branching on mode literals, so adding a rule type means adding ONE entry — no shared code edits.
 *
 * The type ids ARE the persisted `mode` strings ('stateful'/'stateless' verbatim): they are
 * keyword-indexed in every existing `tlsoc-detection-rule` SO, filtered on by the drift-repair
 * sweep, and carried in RuleRef.mode — renaming them would be a saved-object migration for zero
 * benefit. New types add NEW mode strings (the SO mapping is dynamic:false with `rule` unmapped,
 * so new ids and new IR shapes both round-trip with zero migration). Display labels live in the
 * public UI registry (public/detection/type_registry.tsx), which must expose the SAME id set
 * (pinned by a parity test).
 *
 * Entries WRAP the existing per-type compilers/validators — nothing moved — so the golden tests
 * (golden.test.ts, stateful_golden.test.ts) keep pinning the exact monitors existing rules compile
 * to, byte for byte.
 */

/** The registered detection type ids — the single source of truth for the (persisted) mode union. */
export type DetectionMode =
  | 'stateful'
  | 'stateless'
  | 'ppl'
  | 'custom_query'
  | 'new_terms'
  | 'indicator_match';

/**
 * What KIND of Alerting monitor a type compiles to. This — not the type id — is what the shared
 * machinery keys off: doc-level monitors reject dotted/patterned index names and silently stop
 * scanning multi-backed aliases (upstream alerting #1290), so EVERY 'doc' type must go through the
 * per-concrete-index alias routing and the drift-repair sweep; 'bucket' types need neither.
 */
export type MonitorKind = 'doc' | 'bucket';

/** One detection type's execution contract. `rule` is the type's own IR shape (unknown here). */
export interface RuleTypeDefinition {
  id: DetectionMode;
  monitorKind: MonitorKind;
  /** Throws with a user-facing message when the rule is invalid; a bad rule never compiles. */
  validate(rule: unknown): void;
  /** Compile the rule to the Alerting monitor JSON that executes it (validates first — throws). */
  compile(rule: unknown): Record<string, unknown>;
  /** Compile the rule to its portable Sigma YAML export, when the type is Sigma-exportable. */
  toSigma?(rule: unknown): string;
}

const statefulType: RuleTypeDefinition = {
  id: 'stateful',
  monitorKind: 'bucket',
  validate: (rule) => assertValidThresholdRule(rule as ThresholdRuleDefinition),
  compile: (rule) => {
    // v1.2.3 D4 routing: a rule WITH `advanced` metrics compiles through the aggregation
    // compiler; WITHOUT, the UNTOUCHED legacy path — stateful_golden.test.ts stays
    // byte-identical (the "existing rules keep working unchanged" guarantee).
    const threshold = rule as ThresholdRuleDefinition;
    return (threshold.advanced
      ? (compileAggregationRule(thresholdRuleToAggregationInput(threshold)) as unknown)
      : (compileToBucketLevelMonitor(threshold) as unknown)) as Record<string, unknown>;
  },
  toSigma: (rule) => compileToSigmaCorrelation(rule as ThresholdRuleDefinition),
};

const statelessType: RuleTypeDefinition = {
  id: 'stateless',
  monitorKind: 'doc',
  validate: (rule) => assertValidRule(rule as RuleDefinition),
  compile: (rule) => {
    // v1.2.3 D9 routing: a rule WITH `suppression` compiles to the grouped BUCKET monitor (the
    // honest doc→bucket conversion — one alert per group per window); WITHOUT, the UNTOUCHED
    // legacy doc-level path — golden.test.ts stays byte-identical. monitorKind stays 'doc':
    // prepareMonitor keys alias routing off the COMPILED monitor_type (the D6 hybrid
    // generalization), so suppressed rules skip the per-index aliasing with zero route edits.
    const stateless = rule as RuleDefinition;
    return ((stateless.suppression
      ? compileSuppressedStatelessToBucketMonitor(stateless)
      : compileToDocLevelMonitor(stateless)) as unknown) as Record<string, unknown>;
  },
  toSigma: (rule) => compileToSigma(rule as RuleDefinition),
};

/** v1.2.3 D2: the analyst writes the match as a DQL/Lucene query instead of condition rows.
 * Executes exactly like a stateless rule (doc-level monitor — findings + related docs); DQL goes
 * through the clean-room subset translator, whose rejections validate/compile re-throw VERBATIM.
 * NO toSigma — custom queries are not Sigma-exportable in v1.2.3. */
const customQueryType: RuleTypeDefinition = {
  id: 'custom_query',
  monitorKind: 'doc',
  validate: (rule) => assertValidCustomQueryRule(rule as CustomQueryRuleDefinition),
  compile: (rule) => {
    // v1.2.3 D9: same suppression routing as statelessType (the monitor.ts twin's idiom).
    const cq = rule as CustomQueryRuleDefinition;
    return ((cq.suppression
      ? compileSuppressedCustomQueryToBucketMonitor(cq)
      : compileCustomQueryToMonitor(cq)) as unknown) as Record<string, unknown>;
  },
};

/** v1.2.3 D3: the rule IS a PPL query (stored verbatim; re-parsed + lowered on every compile into
 * the shared aggregation compiler — the lossless-edit contract). NO toSigma — PPL rules are not
 * Sigma-exportable (Sigma correlation cannot express multi-metric having conditions). */
const pplType: RuleTypeDefinition = {
  id: 'ppl',
  monitorKind: 'bucket',
  validate: (rule) => assertValidPplRule(rule as PplRuleDefinition),
  compile: (rule) =>
    (compileAggregationRule(
      pplRuleToCompileInput(rule as PplRuleDefinition)
    ) as unknown) as Record<string, unknown>,
};

/** v1.2.3 D5: first-seen detection — fire once per never-before-seen value of ONE field.
 * The save route owns rule identity: it injects rule.stateDocId (newTermsStateDocId(soId,
 * termField)) BEFORE compile; '' routes a missing id into compileNewTermsToMonitor's named
 * throw (a 400 via prepareMonitor). NO toSigma — Sigma cannot express cross-run seen-state. */
const newTermsType: RuleTypeDefinition = {
  id: 'new_terms',
  monitorKind: 'bucket',
  validate: (rule) => assertValidNewTermsRule(rule as NewTermsRuleDefinition),
  compile: (rule) => {
    const newTermsRule = rule as NewTermsRuleDefinition;
    return (compileNewTermsToMonitor(
      newTermsRule,
      newTermsRule.stateDocId ?? ''
    ) as unknown) as Record<string, unknown>;
  },
};

/** v1.2.3 D6: fire when an event field's value appears in a value list (IOC list).
 * The rule is doc OR bucket per LIST SIZE (the D6 hybrid). The registry compile is the PURE leg —
 * the lookup bucket monitor (values-free, correct at any size); the save route upgrades small
 * lists to the inline doc-level shape (prepareIndicatorMatchRule in server/routes/value_lists.ts
 * fetches the values a pure compile cannot). monitorKind 'bucket' matches this pure compile;
 * the alias machinery keys off the COMPILED monitor_type (see prepareMonitor). NO toSigma. */
const indicatorMatchType: RuleTypeDefinition = {
  id: 'indicator_match',
  monitorKind: 'bucket',
  validate: (rule) => assertValidIndicatorMatchRule(rule as IndicatorMatchRuleDefinition),
  compile: (rule) =>
    (compileIndicatorLookupToBucketMonitor(
      rule as IndicatorMatchRuleDefinition
    ) as unknown) as Record<string, unknown>,
};

/**
 * Insertion order is presentation order (the UI card grid mirrors it), simplest first —
 * custom_query, stateless, stateful, ppl, new_terms, indicator_match. The BUILDER's default
 * selection stays 'stateful' (its seed default), independent of card order.
 */
const REGISTRY: Readonly<Record<DetectionMode, RuleTypeDefinition>> = {
  custom_query: customQueryType,
  stateless: statelessType,
  stateful: statefulType,
  ppl: pplType,
  new_terms: newTermsType,
  indicator_match: indicatorMatchType,
};

/** All registered types, in registration order. */
export function listTypes(): RuleTypeDefinition[] {
  return Object.values(REGISTRY);
}

/** Is `id` a registered type id? (The runtime check behind the DetectionMode type.) */
export function isValidMode(id: string): id is DetectionMode {
  return Object.prototype.hasOwnProperty.call(REGISTRY, id);
}

/**
 * The reject-by-name message for an unknown type id — shared by {@link getType}'s throw and the
 * routes' 400s, so an unknown mode is ALWAYS named exactly, never silently reinterpreted.
 */
export function unknownTypeMessage(id: string): string {
  return `Unknown detection rule type "${id}". Registered types: ${listTypes()
    .map((t) => t.id)
    .join(', ')}.`;
}

/** Look up a type by id; throws (naming the id) for an unregistered one. */
export function getType(id: string): RuleTypeDefinition {
  if (!isValidMode(id)) {
    throw new Error(unknownTypeMessage(id));
  }
  return REGISTRY[id];
}
