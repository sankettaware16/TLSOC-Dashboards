/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The TLSOC stateless detection IR (intermediate representation).
 *
 * A no-code rule is authored as a flat group of field / operator / value predicates joined by a
 * single AND or OR. This IR is the shared input to BOTH stateless compile targets (decision D-008):
 *   - {@link compileToSigma}           → a portable Sigma YAML rule (export artifact only)
 *   - {@link compileToDocLevelMonitor} → an OpenSearch doc-level Alerting monitor (what executes)
 *
 * The two targets MUST stay in exact sync on the {@link DetectionOperator} set below — every
 * operator that compiles to Sigma must also compile to a doc-level monitor.
 *
 * Stateful "> N within T" correlation is intentionally NOT expressible here — that is a
 * bucket-level Alerting monitor, handled by a separate compiler (Task 3.2).
 */

/** The v1 operator set. Every operator here compiles to BOTH Sigma and a doc-level monitor query. */
export type DetectionOperator =
  | 'equals'
  | 'not_equals'
  | 'contains'
  | 'not_contains'
  | 'starts_with'
  | 'ends_with'
  | 'is_one_of'
  | 'is_not_one_of'
  | 'exists'
  | 'not_exists'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'matches_regex';

/** All v1 operators, in canonical order. Used to enforce Sigma ⇄ monitor sync in tests. */
export const ALL_DETECTION_OPERATORS: readonly DetectionOperator[] = [
  'equals',
  'not_equals',
  'contains',
  'not_contains',
  'starts_with',
  'ends_with',
  'is_one_of',
  'is_not_one_of',
  'exists',
  'not_exists',
  'gt',
  'gte',
  'lt',
  'lte',
  'matches_regex',
];

/** Operators that take no value (the `value`/`values` fields are ignored). */
export const VALUELESS_OPERATORS: ReadonlySet<DetectionOperator> = new Set([
  'exists',
  'not_exists',
]);

/** Operators that take a list of values (`values`); all others take a single `value`. */
export const LIST_OPERATORS: ReadonlySet<DetectionOperator> = new Set([
  'is_one_of',
  'is_not_one_of',
]);

/** A single field / operator / value predicate (a leaf of the condition). */
export interface Condition {
  /** The (ECS) field name, e.g. 'source.ip'. The compiler is field-agnostic. */
  field: string;
  operator: DetectionOperator;
  /** Single value — for every operator except the list ops and the valueless ops. */
  value?: string | number;
  /** List of values — for is_one_of / is_not_one_of. */
  values?: Array<string | number>;
  /**
   * The raw OpenSearch mapping type of `field` (e.g. 'keyword', 'text', 'match_only_text'),
   * captured by the builder at authoring time from the data view's `esTypes` (its first entry).
   * Drives fieldType-aware Lucene compilation (see lucene.ts) so `contains`/`not_contains` emit a
   * quoted phrase on analyzed text fields instead of a substring wildcard. Absent on legacy rules
   * saved before this field existed — the compiler falls back to the pre-existing wildcard
   * behavior for those, so old rules keep compiling byte-identically.
   */
  fieldType?: string;
}

/** A flat group of conditions joined by one logical operator. (Nested groups: deferred past v1.) */
export interface ConditionGroup {
  logic: 'AND' | 'OR';
  conditions: Condition[];
}

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** Optional Sigma logsource descriptor. */
export interface LogSource {
  category?: string;
  product?: string;
  service?: string;
}

/**
 * One MITRE ATT&CK technique (or sub-technique) reference, ECS `threat.technique.*` shape —
 * this is the public MITRE taxonomy, not Elastic-proprietary (clean-room, see WS-1 design notes).
 */
export interface ThreatTechnique {
  id: string;
  name: string;
  reference: string;
  /** Sub-techniques of this technique (e.g. T1110.001 under T1110), when the author breaks it down. */
  subtechnique?: ThreatTechnique[];
}

/** A single MITRE ATT&CK classification of a rule, ECS `threat.*` shape (framework/tactic/technique). */
export interface ThreatEntry {
  framework: 'MITRE ATT&CK';
  tactic?: { id: string; name: string; reference: string };
  technique?: ThreatTechnique[];
}

/**
 * Optional triage/context metadata shared by BOTH {@link RuleDefinition} and
 * {@link ThresholdRuleDefinition} (WS-1, PROB-1 — "an alert carries no event context"). Everything
 * here is OPTIONAL and absent on rules saved before this field existed; the SO attribute `rule` is
 * `enabled:false` (unmapped), so new fields round-trip through GET-ONE/edit with ZERO migration.
 */
export interface RuleMetadataFields {
  /** MITRE ATT&CK classification(s) of this rule. */
  threat?: ThreatEntry[];
  /** Markdown triage runbook — rendered via EuiMarkdownFormat's DEFAULT plugin pipeline (D-010). */
  note?: string;
  /** Fields to additionally highlight in the alert flyout, on top of the built-in default set. */
  investigationFields?: string[];
  /** 0-100 risk score for the rule. */
  riskScore?: number;
  /** Known false-positive scenarios for this rule, surfaced to the triaging analyst. */
  falsePositives?: string[];
}

/** A complete no-code detection rule — the builder's output and the compilers' input. */
export interface RuleDefinition extends RuleMetadataFields {
  /** Stable rule id (UUID). Optional; callers may supply one for deterministic output. */
  id?: string;
  name: string;
  description?: string;
  severity: Severity;
  /** The index / data-view pattern the rule runs against, e.g. 'fosstlsoc-logs-*'. */
  index: string;
  logSource?: LogSource;
  group: ConditionGroup;
  references?: string[];
  author?: string;
  /** Date string (YYYY/MM/DD per Sigma convention). Optional; caller-supplied for determinism. */
  date?: string;
}

/**
 * A time window for stateful "> N within T" rules. This is the single source of truth for T —
 * {@link buildWindow} derives the monitor schedule, the @timestamp range filter, and the Sigma
 * timespan from it, so they can never drift apart (the window-sync gotcha).
 */
export interface TimeWindow {
  value: number;
  unit: 'MINUTES' | 'HOURS' | 'DAYS';
}

/** A per-group count comparison, e.g. `> 10`. */
export interface CountThreshold {
  operator: 'gt' | 'gte' | 'lt' | 'lte';
  value: number;
}

/**
 * A stateful threshold rule: "> N events matching `filter` within `window`, grouped by `groupBy`".
 * Compiles to a bucket-level OpenSearch Alerting monitor (decision D-008). The `filter` reuses the
 * stateless IR ({@link ConditionGroup}) and the stateless Lucene compiler — so the two tasks compose.
 */
export interface ThresholdRuleDefinition extends RuleMetadataFields {
  id?: string;
  name: string;
  description?: string;
  severity: Severity;
  index: string;
  logSource?: LogSource;
  /** The events that count toward the threshold (the WHERE). Reuses the stateless IR. */
  filter: ConditionGroup;
  /** One or more fields to group counts by (composite-aggregation sources). At least one. */
  groupBy: string[];
  /** The time window T — the single source of truth feeding schedule + range filter + timespan. */
  window: TimeWindow;
  /** The per-group count threshold, e.g. `{ operator: 'gt', value: 10 }`. */
  threshold: CountThreshold;
  references?: string[];
  author?: string;
  date?: string;
}
