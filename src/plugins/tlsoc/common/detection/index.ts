/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * TLSOC stateless detection compiler (Phase 3, decision D-008).
 *
 * One IR ({@link RuleDefinition}) → two outputs:
 *   - {@link compileToSigma}           — a portable Sigma YAML rule (export artifact)
 *   - {@link compileToDocLevelMonitor} — an OpenSearch doc-level Alerting monitor (what executes)
 *
 * Pure functions, no runtime/UI/backend dependencies — unit-testable in isolation.
 */

export * from './types';
export { buildSigmaRule, compileToSigma } from './sigma';
export { compileSuppressedStatelessToBucketMonitor, compileToDocLevelMonitor } from './monitor';
export type { DocLevelMonitor, DocLevelQuery } from './monitor';
export { compileSuppressedCustomQueryToBucketMonitor } from './custom_query';
export { conditionToLucene, conditionGroupToLucene, ANALYZED_TEXT_TYPES } from './lucene';
export { buildWindow } from './window';
export type { CompiledWindow } from './window';
export { compileToBucketLevelMonitor } from './bucket_monitor';
export type { BucketLevelMonitor } from './bucket_monitor';
export { compileToSigmaCorrelation } from './sigma_correlation';
export { getType, isValidMode, listTypes, unknownTypeMessage } from './registry';
export type { DetectionMode, MonitorKind, RuleTypeDefinition } from './registry';
export { buildMonitorForSave } from './save';
export type { DetectionRuleAttributes } from './save';
export { deriveAliasName } from './alias';
export { desiredExecutionTargets, executionTargetsDiffer } from './exec_targets';
export { parseSigmaImport } from './sigma_import';
export type { SigmaImportSuccess, SigmaImportFailure, MitreCatalogLookup } from './sigma_import';
// v1.2.3 W2a — the shared aggregation-rule compiler + its frozen IR (D4 no-code + D3 PPL feed it).
export {
  compileAggregationRule,
  thresholdRuleToAggregationInput,
  validateAggregationInput,
  validateAggregationSpec,
  FILTERED_METRIC_AGG,
} from './agg_compile';
export type {
  AggregationSpec,
  AggregationCompileInput,
  AggFilter,
  HavingExpr,
  MetricDef,
  MetricFn,
} from './agg_types';
// v1.2.3 W2b — the PPL subset parser + the 'ppl' rule IR/lowering.
export { parsePpl, buildPplPreviewQuery } from './ppl_parse';
export type {
  PplParseResult,
  PplParseError,
  PplRuleAst,
  FieldRef,
  WhereExpr,
  MetricAgg,
  PplHavingExpr,
} from './ppl_parse';
export {
  assertValidPplRule,
  collectPplStringContextFields,
  lowerPplToCompileInput,
  pplRuleToCompileInput,
  makeFieldResolver,
  likePatternToWildcard,
} from './ppl_rule';
export type { PplRuleDefinition, ResolveField } from './ppl_rule';
// v1.2.3 W3a — the D5 new-terms (first-seen) rule IR + compiler + seen-state constants.
export {
  DEFAULT_NEW_TERMS_HISTORY_WINDOW,
  DETECTION_STATE_INDEX,
  NEW_TERMS_MODE,
  assertValidNewTermsRule,
  compileNewTermsToMonitor,
  newTermsStateDocId,
} from './new_terms';
export type { NewTermsRuleDefinition } from './new_terms';
// v1.2.3 W3b — the D6 indicator-match rule IR + hybrid compilers.
export {
  INDICATOR_MATCH_MODE,
  assertValidIndicatorMatchRule,
  buildInlineIndicatorQuery,
  compileIndicatorInlineToDocMonitor,
  compileIndicatorLookupToBucketMonitor,
  pickIndicatorListMode,
} from './indicator_match';
export type { IndicatorMatchRuleDefinition, IndicatorListMode } from './indicator_match';
// v1.2.3 W4a — the D8 honest health model + native/Sigma export surfaces (W4 integration:
// consumers may import the submodules directly too — the custom_query precedent — but the
// barrel re-exports keep the public surface consistent with every earlier wave's).
export { computeRuleHealth, foldErrorAlerts, foldJobsInfo } from './health';
export type { RuleHealthInfo, RuleHealthStatus, RuleLastError } from './health';
export {
  NATIVE_EXPORT_KIND,
  NATIVE_EXPORT_VERSION,
  buildNativeBulkExport,
  buildNativeEnvelope,
  canExportSigma,
  parseNativeImport,
  sigmaExportUnavailableReason,
} from './export';
export type { NativeImportResult, NativeRuleEnvelope } from './export';
// v1.2.3 W4b — the D9 exceptions emitters (suppression's converters are exported with their
// compile modules above).
export {
  MAX_EXCEPTION_ENTRIES,
  applyExceptionsToLucene,
  exceptionFieldNames,
  exceptionsToFilterClause,
  exceptionsToLucene,
  exceptionsToMustNot,
  isValidCidr,
  ruleHasExceptions,
  validateExceptions,
} from './exceptions';
export type { ExceptionEntry, ExceptionOp } from './exceptions';
