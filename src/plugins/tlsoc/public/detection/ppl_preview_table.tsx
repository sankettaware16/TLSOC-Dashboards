/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useMemo } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiSpacer, EuiText } from '@elastic/eui';

/**
 * Renders a `POST /_plugins/_ppl` response (schema + positional datarows) for the PPL editor's
 * Preview panel (v1.2.3 D3, research_r4.md §6): column headers from schema[].name, right-aligned
 * numeric columns, em-dash for nulls, the engine total, and the honest preview-vs-monitor
 * divergence copy (null groups appear here but never alert; no dedup in preview).
 */

export interface PplPreviewColumn {
  name: string;
  type: string;
}

/** The preview route's response body (mirrors the engine's schema/datarows shape). */
export interface PplPreviewData {
  schema: PplPreviewColumn[];
  datarows: Array<Array<string | number | boolean | null>>;
  total: number;
  size: number;
  /** The GENERATED query the server actually ran (window conjunct + head cap injected). */
  query?: string;
}

/** Engine column types that render right-aligned (observed live: bigint,int,double,…). */
const NUMERIC_TYPES = new Set([
  'bigint',
  'int',
  'integer',
  'long',
  'short',
  'byte',
  'double',
  'float',
]);

const EM_DASH = '—';

/** One preview row keyed by positional column id (c0, c1, …) plus the __row identity key. */
type PreviewRow = Record<string, string | number | boolean | null>;

function renderCell(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined) {
    return EM_DASH;
  }
  return String(value);
}

export function PplPreviewTable({ preview }: { preview: PplPreviewData }) {
  const { schema, datarows, total } = preview;

  const columns = useMemo(
    () =>
      schema.map(
        (col, index): EuiBasicTableColumn<PreviewRow> => ({
          field: `c${index}`,
          name: col.name,
          align: NUMERIC_TYPES.has(col.type) ? 'right' : 'left',
          render: renderCell,
        })
      ),
    [schema]
  );

  const items = useMemo(
    () =>
      datarows.map((row, rowIndex) => {
        const item: PreviewRow = { __row: rowIndex };
        row.forEach((value, colIndex) => {
          item[`c${colIndex}`] = value;
        });
        return item;
      }),
    [datarows]
  );

  if (schema.length === 0) {
    return (
      <EuiText size="s" color="subdued">
        <p>The preview returned no columns.</p>
      </EuiText>
    );
  }

  return (
    <>
      <EuiText size="xs" color="subdued">
        <p>
          Showing {datarows.length} row{datarows.length === 1 ? '' : 's'} (engine total: {total};
          preview is capped at 100 rows).
        </p>
      </EuiText>
      <EuiSpacer size="xs" />
      <EuiBasicTable
        tableCaption="PPL preview results"
        columns={columns}
        items={items}
        itemId="__row"
        noItemsMessage="No groups matched in the preview window."
      />
      <EuiSpacer size="s" />
      <EuiText size="xs" color="subdued">
        <p>
          Preview is advisory — the saved rule is authoritative. The preview may include groups
          where a group-by field is missing (shown as {EM_DASH}); the saved rule skips those
          groups. The preview applies no alert dedup or suppression, and dc() counts are
          approximate.
        </p>
      </EuiText>
    </>
  );
}
