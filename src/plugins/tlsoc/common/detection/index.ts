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
export { compileToDocLevelMonitor } from './monitor';
export type { DocLevelMonitor, DocLevelQuery } from './monitor';
export { conditionToLucene, conditionGroupToLucene } from './lucene';
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
