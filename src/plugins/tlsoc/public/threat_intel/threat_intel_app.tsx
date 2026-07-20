/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useCallback, useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTableColumn,
  EuiButton,
  EuiCallOut,
  EuiConfirmModal,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
  EuiInMemoryTable,
  EuiLoadingSpinner,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { ValueListType } from '../../common/value_lists';
import { ValueListFlyout } from './value_list_flyout';

/**
 * The Threat Intel app (v1.2.3 D6) — the value-lists manager that replaces the section's
 * ComingSoon placeholder ("wiring Threat Intel to something real"). Value lists are the
 * indicator (IOC) sets that indicator-match detection rules match events against; the list docs
 * double as the engine's terms-lookup targets, so this page IS the threat-intel data plane.
 */

interface ValueListRow {
  id: string;
  name: string;
  type: ValueListType;
  count: number;
  updatedAt: string;
  /** Absent when the best-effort rule scan failed server-side. */
  linkedRules?: number;
}

interface Props {
  core: CoreStart;
}

export function ThreatIntelApp({ core }: Props) {
  const [lists, setLists] = useState<ValueListRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [flyout, setFlyout] = useState<{ open: boolean; existing: ValueListRow | null }>({
    open: false,
    existing: null,
  });
  const [pendingDelete, setPendingDelete] = useState<ValueListRow | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = (await core.http.get('/api/tlsoc/value_lists')) as { lists: ValueListRow[] };
      setLists(resp.lists ?? []);
    } catch (e: any) {
      setError(e?.body?.message ?? e?.message ?? 'Could not load value lists');
    } finally {
      setLoading(false);
    }
  }, [core]);

  useEffect(() => {
    void load();
  }, [load]);

  const onDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    setError(null);
    try {
      await core.http.delete(`/api/tlsoc/value_lists/${encodeURIComponent(pendingDelete.id)}`);
      setPendingDelete(null);
      await load();
    } catch (e: any) {
      // The in-use guard answers 409 naming the rules — surface it verbatim.
      setError(e?.body?.message ?? e?.message ?? 'Delete failed');
      setPendingDelete(null);
    } finally {
      setDeleting(false);
    }
  };

  const columns: Array<EuiBasicTableColumn<ValueListRow>> = [
    { field: 'name', name: 'Name', sortable: true, truncateText: true },
    {
      field: 'type',
      name: 'Type',
      sortable: true,
      width: '120px',
      render: (type: ValueListType) => (
        <EuiBadge color={type === 'ip' ? 'primary' : 'hollow'}>
          {type === 'ip' ? 'IP / CIDR' : 'Keyword'}
        </EuiBadge>
      ),
    },
    { field: 'count', name: 'Values', sortable: true, width: '110px' },
    {
      field: 'linkedRules',
      name: 'Used by rules',
      sortable: true,
      width: '130px',
      render: (linked: number | undefined) => (linked === undefined ? '—' : linked),
    },
    {
      field: 'updatedAt',
      name: 'Updated',
      sortable: true,
      render: (d: string) => (d ? new Date(d).toLocaleString() : '—'),
    },
    {
      name: 'Actions',
      actions: [
        {
          name: 'Edit',
          description: 'Edit this list’s values',
          icon: 'pencil',
          type: 'icon',
          onClick: (row: ValueListRow) => setFlyout({ open: true, existing: row }),
        },
        {
          name: 'Delete',
          description: 'Delete this list (refused while rules use it)',
          icon: 'trash',
          color: 'danger',
          type: 'icon',
          onClick: (row: ValueListRow) => setPendingDelete(row),
        },
      ],
    },
  ];

  return (
    <EuiPage paddingSize="l">
      <EuiPageBody>
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
          <EuiFlexItem>
            <EuiTitle size="l">
              <h1>Threat intelligence</h1>
            </EuiTitle>
            <EuiText color="subdued" size="s">
              <p>
                Value lists of indicators (IOCs) — IPs, CIDR blocks, domains, hashes — that
                indicator-match detection rules check events against. Small lists (≤ 900 values)
                compile into the rule itself; larger lists are looked up live at every run.
              </p>
            </EuiText>
          </EuiFlexItem>
          <EuiFlexGroup gutterSize="s" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiButton iconType="refresh" onClick={load}>
                Refresh
              </EuiButton>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton
                fill
                iconType="plusInCircle"
                onClick={() => setFlyout({ open: true, existing: null })}
              >
                New value list
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlexGroup>
        <EuiSpacer size="m" />

        {error ? (
          <>
            <EuiCallOut color="danger" iconType="alert" title="Something went wrong">
              <p>{error}</p>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        ) : null}
        {notice ? (
          <>
            <EuiCallOut color="warning" iconType="iInCircle" title="Heads up">
              <p>{notice}</p>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        ) : null}

        <EuiPanel hasBorder hasShadow={false}>
          {loading ? (
            <EuiFlexGroup justifyContent="center" alignItems="center" gutterSize="s">
              <EuiFlexItem grow={false}>
                <EuiLoadingSpinner size="m" />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiText size="s">Loading value lists…</EuiText>
              </EuiFlexItem>
            </EuiFlexGroup>
          ) : lists.length === 0 ? (
            <EuiEmptyPrompt
              iconType="globe"
              title={<h2>No value lists yet</h2>}
              body={
                <p>
                  Create a list of indicators, then build an “Indicator match (IOC)” detection
                  rule on it under Detections.
                </p>
              }
              actions={
                <EuiButton
                  fill
                  iconType="plusInCircle"
                  onClick={() => setFlyout({ open: true, existing: null })}
                >
                  Create your first list
                </EuiButton>
              }
            />
          ) : (
            <EuiInMemoryTable
              items={lists}
              columns={columns}
              rowHeader="name"
              pagination={{ initialPageSize: 20, pageSizeOptions: [10, 20, 50] }}
              sorting={{ sort: { field: 'name', direction: 'asc' as const } }}
              search={{ box: { incremental: true, placeholder: 'Filter lists…' } }}
            />
          )}
        </EuiPanel>
      </EuiPageBody>

      {flyout.open ? (
        <ValueListFlyout
          core={core}
          existing={
            flyout.existing
              ? { id: flyout.existing.id, name: flyout.existing.name, type: flyout.existing.type }
              : null
          }
          onClose={() => setFlyout({ open: false, existing: null })}
          onSaved={(warning) => {
            setFlyout({ open: false, existing: null });
            setNotice(warning ?? null);
            void load();
          }}
        />
      ) : null}

      {pendingDelete ? (
        <EuiConfirmModal
          title={`Delete "${pendingDelete.name}"?`}
          onCancel={() => setPendingDelete(null)}
          onConfirm={onDelete}
          cancelButtonText="Cancel"
          confirmButtonText="Delete list"
          buttonColor="danger"
          isLoading={deleting}
        >
          <p>
            Deleting is refused while any detection rule references this list — those rules would
            silently stop matching new indicators otherwise.
          </p>
        </EuiConfirmModal>
      ) : null}
    </EuiPage>
  );
}
