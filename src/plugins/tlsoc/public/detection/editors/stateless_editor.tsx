/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { RuleEditorProps } from '../type_registry';
import { MatchSection } from './match_section';

/**
 * The 'stateless' (single-event) per-type editor: exactly the shared Match panel — a doc-level
 * rule is nothing but its conditions (v1.2.3 D1 decomposition of detection_builder.tsx).
 */
export function StatelessEditor(props: RuleEditorProps) {
  return <MatchSection {...props} />;
}
