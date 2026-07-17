/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiPanel, EuiTitle, EuiSpacer, EuiText, EuiHealth, EuiBasicTable, EuiBasicTableColumn } from '@elastic/eui';
import { SourceTypeBucket } from '../../../common/overview/types';
import { compactNumber } from '../format';
import { typeColor } from '../type_colors';

interface SourceTypeBreakdownProps {
  sourceTypes: SourceTypeBucket[];
  onSelectType?: (type: string) => void;
}

/**
 * Source-type mix — the panel that proves this is a real multi-source SIEM, not one web log.
 * A stacked proportion bar + a ranked table (events / % / sources / endpoints per type).
 */
export const SourceTypeBreakdown: React.FC<SourceTypeBreakdownProps> = ({ sourceTypes, onSelectType }) => {
  const total = sourceTypes.reduce((s, t) => s + t.events, 0);

  const columns: Array<EuiBasicTableColumn<SourceTypeBucket>> = [
    {
      field: 'label',
      name: 'Source type',
      render: (label: string, row: SourceTypeBucket) => (
        <EuiHealth color={typeColor(row.type)}>
          <EuiText size="xs">{label}</EuiText>
        </EuiHealth>
      ),
    },
    {
      field: 'events',
      name: 'Events',
      width: '90px',
      align: 'right',
      render: (v: number) => (
        <EuiText size="xs">
          <strong>{compactNumber(v)}</strong> <span style={{ opacity: 0.6 }}>{total ? `${Math.round((v / total) * 100)}%` : ''}</span>
        </EuiText>
      ),
    },
    { field: 'sources', name: 'Sources', width: '80px', align: 'right', render: (v: number) => <EuiText size="xs">{v}</EuiText> },
    { field: 'endpoints', name: 'Hosts', width: '70px', align: 'right', render: (v: number) => <EuiText size="xs">{v}</EuiText> },
  ];

  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="m" style={{ height: '100%' }}>
      <EuiTitle size="xxs">
        <h3>Source types</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      {total === 0 ? (
        <EuiText size="s" color="subdued">
          <p>No source data in this range.</p>
        </EuiText>
      ) : (
        <>
          {/* proportion bar */}
          <div style={{ display: 'flex', height: 12, borderRadius: 6, overflow: 'hidden' }}>
            {sourceTypes.map((t) => (
              <div
                key={t.type}
                title={`${t.label}: ${t.events} (${Math.round((t.events / total) * 100)}%)`}
                style={{ width: `${(t.events / total) * 100}%`, backgroundColor: typeColor(t.type) }}
              />
            ))}
          </div>
          <EuiSpacer size="m" />
          <EuiBasicTable
            items={sourceTypes}
            columns={columns}
            tableLayout="fixed"
            rowProps={(row: SourceTypeBucket) =>
              onSelectType ? { onClick: () => onSelectType(row.type), style: { cursor: 'pointer' } } : {}
            }
          />
        </>
      )}
    </EuiPanel>
  );
};
