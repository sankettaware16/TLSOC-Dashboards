/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { EuiPanel, EuiTitle, EuiSpacer, EuiBasicTable, EuiBasicTableColumn, EuiBadge, EuiText, EuiHealth } from '@elastic/eui';
import { RecentEvent } from '../../../common/overview/types';
import { classifySource, SOURCE_TYPE_LABELS, SourceType } from '../../../common/overview/source_types';
import { typeColor } from '../type_colors';

interface RecentEventsTableProps {
  events: RecentEvent[];
}

function outcomeColor(outcome: string | null): string {
  const values = (outcome ?? '').split(', ');
  if (values.includes('failure')) return 'danger';
  if (values.includes('success')) return 'success';
  return 'hollow';
}

const PAGE_SIZE = 25;

/** The freshest events across all source types — the "what just happened" table. */
export const RecentEventsTable: React.FC<RecentEventsTableProps> = ({ events }) => {
  const [pageIndex, setPageIndex] = useState(0);
  // A refresh may shrink the list — keep the page in range.
  useEffect(() => {
    const maxPage = Math.max(0, Math.ceil(events.length / PAGE_SIZE) - 1);
    if (pageIndex > maxPage) setPageIndex(maxPage);
  }, [events.length, pageIndex]);
  const pageEvents = events.slice(pageIndex * PAGE_SIZE, pageIndex * PAGE_SIZE + PAGE_SIZE);

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
    {
      // Internal deployment → source.geo.country is empty; show the envelope origin (dept) instead,
      // with org/env in the tooltip. Falls back to country if a geo-mapped (external) IP ever appears.
      field: 'dept',
      name: 'Dept',
      width: '110px',
      render: (_: string | null, row: RecentEvent) => {
        const label = row.dept ?? row.country ?? '—';
        const tip = [row.org, row.env, row.country].filter(Boolean).join(' · ');
        return (
          <EuiText size="xs" className="eui-textTruncate" title={tip || undefined}>
            {label}
          </EuiText>
        );
      },
    },
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
      <EuiBasicTable
        items={pageEvents}
        columns={columns}
        tableLayout="fixed"
        noItemsMessage="No events in this range."
        pagination={{
          pageIndex,
          pageSize: PAGE_SIZE,
          totalItemCount: events.length,
          showPerPageOptions: false,
        }}
        onChange={({ page }: { page?: { index: number } }) => {
          if (page) setPageIndex(page.index);
        }}
      />
    </EuiPanel>
  );
};
