/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiPanel, EuiTitle, EuiSpacer, EuiBasicTable, EuiBasicTableColumn, EuiBadge, EuiText, EuiHealth } from '@elastic/eui';
import { RecentEvent } from '../../../common/overview/types';
import { classifySource, SOURCE_TYPE_LABELS, SourceType } from '../../../common/overview/source_types';
import { typeColor } from '../type_colors';

interface RecentEventsTableProps {
  events: RecentEvent[];
}

function outcomeColor(outcome: string | null): string {
  if (outcome === 'failure') return 'danger';
  if (outcome === 'success') return 'success';
  return 'hollow';
}

/** The freshest events across all source types — the "what just happened" table. */
export const RecentEventsTable: React.FC<RecentEventsTableProps> = ({ events }) => {
  const columns: Array<EuiBasicTableColumn<RecentEvent>> = [
    {
      field: 'timestamp',
      name: 'Time',
      width: '150px',
      render: (ts: string | null) => <EuiText size="xs">{ts ? new Date(ts).toLocaleString() : '—'}</EuiText>,
    },
    {
      field: 'sourceProgram',
      name: 'Source',
      width: '150px',
      truncateText: true,
      render: (prog: string | null) => {
        const t = classifySource(prog);
        return (
          <EuiHealth color={typeColor(t)}>
            <EuiText size="xs" className="eui-textTruncate" title={prog ?? ''}>
              {SOURCE_TYPE_LABELS[t as SourceType] ?? t}
            </EuiText>
          </EuiHealth>
        );
      },
    },
    { field: 'endpoint', name: 'Endpoint', width: '110px', truncateText: true, render: (v: string | null) => <EuiText size="xs">{v ?? '—'}</EuiText> },
    {
      field: 'kind',
      name: 'Kind',
      width: '70px',
      render: (v: string | null) => (v === 'alert' ? <EuiBadge color="warning">alert</EuiBadge> : <EuiText size="xs">{v ?? '—'}</EuiText>),
    },
    {
      field: 'outcome',
      name: 'Outcome',
      width: '90px',
      render: (v: string | null) => (v ? <EuiBadge color={outcomeColor(v)}>{v}</EuiBadge> : '—'),
    },
    { field: 'sourceIp', name: 'Source IP', width: '120px', render: (v: string | null) => <EuiText size="xs">{v ?? '—'}</EuiText> },
    { field: 'country', name: 'Country', width: '110px', render: (v: string | null) => <EuiText size="xs">{v ?? '—'}</EuiText> },
    {
      field: 'ruleName',
      name: 'Detail',
      truncateText: true,
      render: (rule: string | null, row: RecentEvent) => (
        <EuiText size="xs" className="eui-textTruncate" title={rule ?? row.path ?? row.user ?? ''}>
          {rule ?? row.path ?? (row.user ? `user: ${row.user}` : '—')}
        </EuiText>
      ),
    },
  ];

  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="m">
      <EuiTitle size="xxs">
        <h3>Recent events</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiBasicTable items={events} columns={columns} tableLayout="fixed" noItemsMessage="No events in this range." />
    </EuiPanel>
  );
};
