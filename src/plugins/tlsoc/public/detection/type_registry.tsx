/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { ComponentType, LazyExoticComponent, lazy } from 'react';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../../data/public';
import {
  Condition,
  ConditionGroup,
  CountThreshold,
  DetectionMode,
  TimeWindow,
} from '../../common/detection';
import type { AggregationSpec } from '../../common/detection/agg_types';
import type { CustomQueryLanguage } from '../../common/detection/custom_query';
import type { PplPreviewData } from './ppl_preview_table';
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

  /**
   * v1.2.3 D4 (optional): the rule's advanced aggregation spec + change callback. Only the
   * stateful editor consumes them; it renders its "Advanced metrics" accordion only when the
   * callback is provided.
   */
  advanced?: AggregationSpec;
  onAdvancedChange?: (next: AggregationSpec | undefined) => void;

  /** v1.2.3 D3 (optional): the PPL query text (builder state) — only the PPL editor consumes it. */
  pplText?: string;
  onPplTextChange?: (text: string) => void;
  /**
   * v1.2.3 D3 (optional): runs the server-side preview (POST /api/tlsoc/detection/_ppl_preview)
   * with the builder's data-view time field and current window. Absent → Preview is hidden.
   */
  onPreview?: (pplText: string) => Promise<PplPreviewData>;

  /**
   * v1.2.3 D2 (optional, mirrors CustomQueryEditorProps): core/data services plus the query form
   * state the custom-query editor's SearchBar + validation need. Only that editor consumes them.
   */
  core?: CoreStart;
  data?: DataPublicPluginStart;
  /** The selected data view's id — resolved to the data-view object for SearchBar suggestions. */
  dataViewId?: string;
  /** The selected data view's index pattern (rule.index) — what the server validates against. */
  indexPattern?: string;
  queryText?: string;
  queryLanguage?: CustomQueryLanguage;
  onQueryTextChange?: (queryText: string) => void;
  onQueryLanguageChange?: (language: CustomQueryLanguage) => void;
  /**
   * v1.2.3 W2 review (BLOCKING-2): the builder OWNS the server-side `_validate` verdict (it gates
   * Save on it), and threads it here for display. `queryCheck` is always the verdict for the
   * CURRENT (language, index, query) triple — a stale verdict arrives as status 'idle'.
   * `onQueryValidate` asks the builder to run a fresh validation (the editor calls it on
   * blur/submit); the builder dedupes, so calling it repeatedly is cheap.
   */
  queryCheck?: QueryValidationState;
  onQueryValidate?: () => void;
}

/** The server-side `_validate` verdict for the current custom query (BLOCKING-2 save gate). */
export interface QueryValidationState {
  status: 'idle' | 'checking' | 'valid' | 'invalid' | 'error';
  reason?: string;
}

/**
 * How the builder's "Test this rule" panel works for a type. 'bucket-dryrun' = the proven
 * Alerting `_execute?dryrun=true` backtest; 'search-sample' = a plain search preview (doc-level
 * monitors cannot be dry-run unsaved — upstream alerting #1295 — so doc-kind types must never
 * use the dryrun path); 'ppl-preview' = the type's editor embeds its OWN preview (the PPL
 * editor's Preview button + result table) and the builder renders NO shared test panel at all.
 */
export type PreviewStrategy = 'bucket-dryrun' | 'search-sample' | 'ppl-preview';

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

/** v1.2.3 D2: the analyst writes the match as a query instead of no-code condition rows. */
const customQueryUi: RuleTypeUiDefinition = {
  id: 'custom_query',
  card: {
    label: 'Custom query (DQL/Lucene)',
    description:
      'Fire on any single document matching a query you write — DQL (with autocomplete) or ' +
      'Lucene. Validated against your data before saving; compiles to a doc-level monitor.',
    icon: 'search',
  },
  editor: lazy(() =>
    import('./editors/custom_query_editor').then((m) => ({ default: m.CustomQueryEditor }))
  ),
  listBadge: { label: 'Custom query', color: 'accent' },
  previewStrategy: 'search-sample',
};

/** v1.2.3 D3: the power-user escape hatch — the rule is a PPL query with its own preview. */
const pplUi: RuleTypeUiDefinition = {
  id: 'ppl',
  card: {
    label: 'Advanced (PPL)',
    description:
      'Write the detection as a PPL query — where-filters, multiple metrics (count, dc, sum, ' +
      'avg, min, max) and a multi-condition threshold. For rules the no-code forms cannot express.',
    icon: 'console',
  },
  editor: lazy(() => import('./editors/ppl_editor').then((m) => ({ default: m.PplEditor }))),
  listBadge: { label: 'PPL', color: 'accent' },
  previewStrategy: 'ppl-preview',
};

/**
 * Registration order = card-grid order — mirrors the common registry's insertion order
 * (simplest first, Elastic-shaped). The builder's DEFAULT selection stays 'stateful' (its seed
 * default), independent of card order.
 */
const UI_REGISTRY: readonly RuleTypeUiDefinition[] = [
  customQueryUi,
  statelessUi,
  statefulUi,
  pplUi,
];

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
