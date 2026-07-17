/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { RuleDefinition, ThresholdRuleDefinition } from './types';
import { compileToDocLevelMonitor } from './monitor';
import { compileToBucketLevelMonitor } from './bucket_monitor';

/** The two detection modes the builder can author (mirrors the public UI's DetectionMode). */
export type DetectionMode = 'stateful' | 'stateless';

/**
 * Compile a no-code rule to the OpenSearch Alerting monitor to PERSIST (Task 3.5a, decision D-008).
 *
 * The result is the SAME compiler output the dry-run uses ({@link compileToBucketLevelMonitor} /
 * {@link compileToDocLevelMonitor}), so a SAVED monitor runs exactly what `_execute` already proved
 * fires — there is no second path. Throws (never builds) on an invalid rule, reusing the compiler's
 * own `assertValid*Rule` validators, so a bad rule never reaches the cluster.
 *
 * The monitor is a PURE EXECUTOR — it does NOT carry the original rule. OpenSearch 3.7 Alerting
 * strips `ui_metadata` on persist (verified live: create echoes it, GET returns it stripped), so the
 * editable rule IR is stored separately in a `tlsoc-detection-rule` OSD saved object
 * ({@link DetectionRuleAttributes}) — the lossless round-trip source for edit (Task 3.5b).
 */
export function buildMonitorForSave(
  mode: DetectionMode,
  rule: RuleDefinition | ThresholdRuleDefinition
): Record<string, unknown> {
  return mode === 'stateful'
    ? ((compileToBucketLevelMonitor(rule as ThresholdRuleDefinition) as unknown) as Record<
        string,
        unknown
      >)
    : ((compileToDocLevelMonitor(rule as RuleDefinition) as unknown) as Record<string, unknown>);
}

/**
 * Attributes of a `tlsoc-detection-rule` saved object — the editable record AND the registry of
 * detections TLSOC created. `rule` holds the exact no-code IR so the builder can re-open it
 * losslessly (Task 3.5b); `monitorId` links to the Alerting monitor that executes it.
 */
export interface DetectionRuleAttributes {
  name: string;
  mode: DetectionMode;
  severity: string;
  /** The id of the OpenSearch Alerting monitor this rule created (the executor). */
  monitorId: string;
  /** The exact no-code rule the user built — the lossless edit round-trip source. */
  rule: RuleDefinition | ThresholdRuleDefinition;
  /**
   * For STATELESS rules on a patterned/dotted index only: a dot-free "display identity" alias name
   * derived from the rule's index PATTERN (`deriveAliasName(rule.index)`). Kept for backcompat with
   * existing LIST/GET-ONE consumers and UI display — NOT necessarily a live OpenSearch alias as of
   * the WS hotfix (see `executionTargets` for what the monitor actually runs against). Absent for
   * stateful rules. (Task 3.5b.)
   */
  executionAlias?: string;
  /**
   * For STATELESS rules on a patterned/dotted index only: the SORTED list of per-CONCRETE-INDEX
   * dot-free aliases the doc-level monitor's `doc_level_input.indices` actually targets (one alias
   * per backing index — a single pattern-level alias silently stops scanning once it backs more
   * than one index; see `common/detection/exec_targets.ts` for why). Kept in sync with the live
   * monitor by `syncStatelessMonitorTargets` (server/routes/monitors.ts) as daily indices roll.
   * Unmapped SO attribute — round-trips via `_source` with zero migration. Absent for stateful rules
   * and for rules saved before the WS hotfix (until their next sync/edit).
   */
  executionTargets?: string[];
  /**
   * Mirrors the Alerting monitor's `enabled` flag (PROB-19). ABSENT means `true` — rules saved
   * before v1.2 had no notion of disable, so a missing value is "always was enabled". Unmapped SO
   * attribute (round-trips via `_source`), same zero-migration idiom as `executionTargets`.
   */
  enabled?: boolean;
  /** ISO-8601 timestamp the rule was saved. */
  createdAt: string;
}
