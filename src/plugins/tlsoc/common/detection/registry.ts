/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { RuleDefinition, ThresholdRuleDefinition } from './types';
import { assertValidRule, assertValidThresholdRule } from './internal';
import { compileToDocLevelMonitor } from './monitor';
import { compileToBucketLevelMonitor } from './bucket_monitor';
import { compileToSigma } from './sigma';
import { compileToSigmaCorrelation } from './sigma_correlation';

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
export type DetectionMode = 'stateful' | 'stateless';

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
  compile: (rule) =>
    (compileToBucketLevelMonitor(rule as ThresholdRuleDefinition) as unknown) as Record<
      string,
      unknown
    >,
  toSigma: (rule) => compileToSigmaCorrelation(rule as ThresholdRuleDefinition),
};

const statelessType: RuleTypeDefinition = {
  id: 'stateless',
  monitorKind: 'doc',
  validate: (rule) => assertValidRule(rule as RuleDefinition),
  compile: (rule) =>
    (compileToDocLevelMonitor(rule as RuleDefinition) as unknown) as Record<string, unknown>,
  toSigma: (rule) => compileToSigma(rule as RuleDefinition),
};

/** Insertion order is presentation order (the UI card grid mirrors it): stateful is the default. */
const REGISTRY: Readonly<Record<DetectionMode, RuleTypeDefinition>> = {
  stateful: statefulType,
  stateless: statelessType,
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
