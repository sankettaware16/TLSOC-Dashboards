/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { ComponentType, LazyExoticComponent, lazy } from 'react';
import {
  Condition,
  ConditionGroup,
  CountThreshold,
  DetectionMode,
  TimeWindow,
} from '../../common/detection';
import { FieldOption } from './use_data_view_fields';

/**
 * The rule-type UI registry (v1.2.3 D1) — the presentation half of the two-layer type registry.
 * React components cannot live in common/, so the execution contract (validate/compile/monitorKind)
 * stays in common/detection/registry.ts and everything the BUILDER needs per type lives here: the
 * "Create detection" card, the per-type editor panel, the saved-list badge, and how the type can be
 * previewed. The two layers MUST expose the same id set — pinned by type_registry.test.ts — and the
 * ids are the persisted mode strings verbatim (see the common registry docblock for why they are
 * never renamed).
 */

/**
 * Props every per-type editor receives from the builder. ALL form state stays in the builder (as it
 * did pre-decomposition), so switching detection types never loses the analyst's in-progress
 * conditions — editors are purely presentational. v1 contract: the superset of what the two
 * existing no-code editors need (the threshold slice is ignored by doc-kind editors).
 */
export interface RuleEditorProps {
  /** Fields of the selected data view (empty until one is chosen). */
  fields: FieldOption[];
  loadingFields: boolean;
  fieldsError: string | null;
  /** Whether a data view is selected — gates "Add condition". */
  hasDataView: boolean;
  logic: ConditionGroup['logic'];
  conditions: Condition[];
  onLogicChange: (logic: ConditionGroup['logic']) => void;
  onConditionChange: (index: number, next: Condition) => void;
  onConditionAdd: () => void;
  onConditionRemove: (index: number) => void;
  groupBy: string[];
  onGroupByChange: (groupBy: string[]) => void;
  windowValue: number;
  onWindowValueChange: (value: number) => void;
  windowUnit: TimeWindow['unit'];
  onWindowUnitChange: (unit: TimeWindow['unit']) => void;
  thresholdOp: CountThreshold['operator'];
  onThresholdOpChange: (op: CountThreshold['operator']) => void;
  thresholdValue: number;
  onThresholdValueChange: (value: number) => void;
}

/**
 * How the builder's "Test this rule" panel works for a type. 'bucket-dryrun' = the proven
 * Alerting `_execute?dryrun=true` backtest; 'search-sample' = a plain search preview (doc-level
 * monitors cannot be dry-run unsaved — upstream alerting #1295 — so doc-kind types must never
 * use the dryrun path).
 */
export type PreviewStrategy = 'bucket-dryrun' | 'search-sample';

export interface RuleTypeUiDefinition {
  id: DetectionMode;
  /** The "Create detection" type-chooser card (Elastic-shaped grid). */
  card: { label: string; description: string; icon: string };
  /** The per-type editor panel, lazily imported so unused editors never load. */
  editor: LazyExoticComponent<ComponentType<RuleEditorProps>>;
  /** The saved-rules list "Type" badge. */
  listBadge: { label: string; color: string };
  previewStrategy: PreviewStrategy;
}

const statefulUi: RuleTypeUiDefinition = {
  id: 'stateful',
  card: {
    label: 'Threshold (no-code)',
    description:
      'Fire when more than N matching events occur within a time window, grouped by a field ' +
      '(e.g. a request flood from one source IP). Tested live against your data.',
    icon: 'visBarVertical',
  },
  editor: lazy(() =>
    import('./editors/stateful_editor').then((m) => ({ default: m.StatefulEditor }))
  ),
  listBadge: { label: 'Threshold', color: 'primary' },
  previewStrategy: 'bucket-dryrun',
};

const statelessUi: RuleTypeUiDefinition = {
  id: 'stateless',
  card: {
    label: 'Single event (no-code)',
    description:
      'Fire on any single document that matches the conditions (a Sigma-style rule). ' +
      'Exports to Sigma and compiles to a doc-level monitor.',
    icon: 'document',
  },
  editor: lazy(() =>
    import('./editors/stateless_editor').then((m) => ({ default: m.StatelessEditor }))
  ),
  listBadge: { label: 'Single-event', color: 'hollow' },
  previewStrategy: 'search-sample',
};

/** Registration order = card-grid order — mirrors the common registry (stateful is the default). */
const UI_REGISTRY: readonly RuleTypeUiDefinition[] = [statefulUi, statelessUi];

/** All registered UI types, in registration (card-grid) order. */
export function listUiTypes(): RuleTypeUiDefinition[] {
  return [...UI_REGISTRY];
}

/** Look up a UI type by id, or undefined — for display surfaces that must not crash on unknowns. */
export function findUiType(id: string): RuleTypeUiDefinition | undefined {
  return UI_REGISTRY.find((t) => t.id === id);
}

/** Look up a UI type by id; throws (naming the id) for an unregistered one. */
export function getUiType(id: string): RuleTypeUiDefinition {
  const found = findUiType(id);
  if (!found) {
    const known = UI_REGISTRY.map((t) => t.id).join(', ');
    throw new Error(`Unknown detection rule type "${id}". Registered types: ${known}.`);
  }
  return found;
}
