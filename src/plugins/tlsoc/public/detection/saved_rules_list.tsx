/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useCallback, useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiCallOut,
  EuiConfirmModal,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';

/** One row of the saved-detections list (shape returned by GET /api/tlsoc/detection/monitors). */
export interface SavedRuleRow {
  soId: string;
  name: string;
  mode: 'stateful' | 'stateless';
  severity: string;
  index?: string;
  executionAlias?: string;
  monitorId: string;
  createdAt?: string;
}

interface Props {
  core: CoreStart;
  onCreate: () => void;
  onEdit: (soId: string) => void;
}

/** Lists saved `tlsoc-detection-rule` detections with Edit / Delete (delete removes monitor + SO). */
export function SavedRulesList({ core, onCreate, onEdit }: Props) {
  const [rules, setRules] = useState<SavedRuleRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<SavedRuleRow | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const resp = (await core.http.get('/api/tlsoc/detection/monitors')) as any;
      setRules(resp?.rules ?? []);
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const err = e as any;
      setError(err?.body?.message ?? err?.message ?? 'Could not load detections');
    } finally {
      setLoading(false);
    }
  }, [core]);

  useEffect(() => {
    load();
  }, [load]);

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await core.http.delete(`/api/tlsoc/detection/monitors/${pendingDelete.soId}`);
      setPendingDelete(null);
      await load();
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const err = e as any;
      setError(err?.body?.message ?? err?.message ?? 'Could not delete detection');
      setPendingDelete(null);
    } finally {
      setDeleting(false);
    }
  };

  const columns: Array<EuiBasicTableColumn<SavedRuleRow>> = [
    { field: 'name', name: 'Name', sortable: true, truncateText: true },
    {
      field: 'mode',
      name: 'Type',
      render: (m: string) => (
        <EuiBadge color={m === 'stateful' ? 'primary' : 'hollow'}>
          {m === 'stateful' ? 'Threshold' : 'Single-event'}
        </EuiBadge>
      ),
    },
    { field: 'severity', name: 'Severity', sortable: true },
    { field: 'index', name: 'Index', truncateText: true },
    {
      field: 'createdAt',
      name: 'Created',
      sortable: true,
      render: (d?: string) => (d ? new Date(d).toLocaleString() : '—'),
    },
    {
      name: 'Actions',
      actions: [
        {
          name: 'Edit',
          description: 'Edit this detection',
          icon: 'pencil',
          type: 'icon',
          onClick: (r: SavedRuleRow) => onEdit(r.soId),
        },
        {
          name: 'Delete',
          description: 'Delete this detection',
          icon: 'trash',
          color: 'danger',
          type: 'icon',
          onClick: (r: SavedRuleRow) => setPendingDelete(r),
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
              <h1>Detections</h1>
            </EuiTitle>
            <EuiText color="subdued" size="s">
              <p>Saved detection rules. Each runs as an OpenSearch Alerting monitor.</p>
            </EuiText>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton fill iconType="plusInCircle" onClick={onCreate}>
              Create detection
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="l" />

        {error ? (
          <>
            <EuiCallOut color="danger" iconType="alert" title="Something went wrong">
              <p>{error}</p>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        ) : null}

        <EuiPanel hasShadow={false} hasBorder>
          {loading ? (
            <EuiFlexGroup justifyContent="center" alignItems="center" gutterSize="s">
              <EuiFlexItem grow={false}>
                <EuiLoadingSpinner size="m" />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiText size="s">Loading detections…</EuiText>
              </EuiFlexItem>
            </EuiFlexGroup>
          ) : rules.length === 0 ? (
            <EuiEmptyPrompt
              iconType="securityApp"
              title={<h2>No detections yet</h2>}
              body={<p>Create your first detection to start watching your data.</p>}
              actions={
                <EuiButton fill iconType="plusInCircle" onClick={onCreate}>
                  Create your first detection
                </EuiButton>
              }
            />
          ) : (
            <EuiBasicTable items={rules} columns={columns} rowHeader="name" />
          )}
        </EuiPanel>
      </EuiPageBody>

      {pendingDelete ? (
        <EuiConfirmModal
          title={`Delete “${pendingDelete.name}”?`}
          onCancel={() => setPendingDelete(null)}
          onConfirm={confirmDelete}
          cancelButtonText="Cancel"
          confirmButtonText="Delete detection"
          buttonColor="danger"
          isLoading={deleting}
        >
          <p>
            This permanently removes the detection and its OpenSearch Alerting monitor. This cannot be
            undone.
          </p>
        </EuiConfirmModal>
      ) : null}
    </EuiPage>
  );
}
