/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The investigation grid's preferred _source columns (Task 4.5c). SOC-relevant for web/apache logs;
 * each is shown ONLY when the case's data view actually has the field, so the grid works on ANY index.
 * (The Time column is handled separately in the UI from the data view's timeFieldName.)
 */
export const PREFERRED_COLUMN_FIELDS = [
  'source.ip',
  'http.request.method',
  'http.response.status_code',
];

export interface ColumnPlan {
  /** Preferred fields that exist in the index, in preferred order (absent ones are skipped, not blank). */
  fields: string[];
  /** True when NONE of the preferred fields exist → the UI falls back to a single "Document" summary column. */
  fallbackSummary: boolean;
}

/**
 * Pure (decision pinned by columns.test.ts): from the data view's available field names, select which
 * preferred columns to render. Absent preferred fields are dropped (so a different-shaped index never
 * shows a broken/empty column); if none are present, signal the "Document" summary fallback.
 */
export function planColumns(
  availableFieldNames: string[],
  preferred: string[] = PREFERRED_COLUMN_FIELDS
): ColumnPlan {
  const available = new Set(availableFieldNames);
  const fields = preferred.filter((f) => available.has(f)); // preserves preferred order, not input order
  return { fields, fallbackSummary: fields.length === 0 };
}
