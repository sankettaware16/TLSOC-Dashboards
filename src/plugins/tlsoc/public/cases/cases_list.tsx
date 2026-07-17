/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonGroup,
  EuiCallOut,
  EuiComboBox,
  EuiConfirmModal,
  EuiEmptyPrompt,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { CaseStatus, CASE_CATEGORIES, summarizeCases, formatDuration } from '../../common/cases';
import { CaseRow, useCases } from './use_cases';

interface Props {
  core: CoreStart;
  onOpen: (id: string) => void;
}

function statusColor(s: CaseStatus): string {
  switch (s) {
    case 'New':
      return 'default';
    case 'Assigned':
      return 'primary';
    case 'In Progress':
      return 'accent';
    case 'Contained':
      return 'warning';
    case 'Closed':
      return 'hollow';
    default:
      return 'default';
  }
}

function sevColor(s: string): string {
  switch (s) {
    case 'critical':
      return 'danger';
    case 'high':
      return 'warning';
    case 'medium':
      return 'default';
    case 'low':
      return 'hollow';
    default:
      return 'hollow';
  }
}

export function CasesList({ core, onOpen }: Props) {
  const { cases, loading, error, reload, createCase, deleteCase } = useCases(core);

  const [statusFilter, setStatusFilter] = useState<string>('open');
  const [sevFilter, setSevFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<CaseRow | null>(null);

  // Create modal state
  const [createTitle, setCreateTitle] = useState('');
  const [createSeverity, setCreateSeverity] = useState('medium');
  const [createDescription, setCreateDescription] = useState('');
  const [createCategory, setCreateCategory] = useState('');
  const [createTags, setCreateTags] = useState<string[]>([]);
  const [creating, setCreating] = useState(false);

  const statusFilterOptions = [
    { id: 'all', label: 'All' },
    { id: 'open', label: 'Open' },
    { id: 'closed', label: 'Closed' },
  ];

  const sevFilterOptions = [
    { id: 'all', label: 'All' },
    { id: 'critical', label: 'Critical' },
    { id: 'high', label: 'High' },
    { id: 'medium', label: 'Medium' },
    { id: 'low', label: 'Low' },
  ];

  const allTagOptions = Array.from(
    new Set(cases.flatMap((c) => c.tags ?? []))
  ).map((t) => ({ label: t }));

  const visible = cases.filter((c) => {
    const statusMatch =
      statusFilter === 'all' ||
      (statusFilter === 'open' && c.status !== 'Closed') ||
      (statusFilter === 'closed' && c.status === 'Closed');
    const sevMatch = sevFilter === 'all' || c.severity === sevFilter;
    const categoryMatch =
      categoryFilter === 'all' || (c.category || '') === categoryFilter;
    const tagMatch =
      tagFilter.length === 0 || tagFilter.some((t) => (c.tags ?? []).includes(t));
    return statusMatch && sevMatch && categoryMatch && tagMatch;
  });

  const columns: Array<EuiBasicTableColumn<CaseRow>> = [
    {
      field: 'title',
      name: 'Title',
      truncateText: true,
    },
    {
      field: 'status',
      name: 'Status',
      render: (_: any, row: CaseRow) => (
        <EuiBadge color={statusColor(row.status)}>{row.status}</EuiBadge>
      ),
    },
    {
      field: 'severity',
      name: 'Severity',
      render: (_: any, row: CaseRow) => (
        <EuiBadge color={sevColor(row.severity)}>{row.severity}</EuiBadge>
      ),
    },
    {
      field: 'tags',
      name: 'Tags',
      render: (_: any, row: CaseRow) =>
        row.tags && row.tags.length > 0 ? (
          <EuiFlexGroup gutterSize="xs" wrap responsive={false}>
            {row.tags.map((t) => (
              <EuiFlexItem grow={false} key={t}>
                <EuiBadge>{t}</EuiBadge>
              </EuiFlexItem>
            ))}
          </EuiFlexGroup>
        ) : (
          '—'
        ),
    },
    {
      field: 'category',
      name: 'Category',
      render: (cat: string | undefined) => cat || 'Uncategorized',
    },
    {
      field: 'assignee',
      name: 'Assignee',
      render: (assignee: string | null) => assignee ?? '—',
    },
    {
      field: 'linkedAlertCount',
      name: 'Alerts',
    },
    {
      field: 'commentCount',
      name: 'Comments',
    },
    {
      field: 'updatedAt',
      name: 'Updated',
      render: (d: string) => new Date(d).toLocaleString(),
    },
    {
      name: 'Actions',
      actions: [
        {
          name: 'Delete',
          description: 'Delete this case',
          icon: 'trash',
          color: 'danger',
          type: 'icon',
          onClick: (row: CaseRow) => setPendingDelete(row),
        },
      ],
    },
  ];

  const openCreateModal = () => {
    setCreateTitle('');
    setCreateSeverity('medium');
    setCreateDescription('');
    setCreateCategory('');
    setCreateTags([]);
    setShowCreate(true);
  };

  const handleCreate = async () => {
    if (!createTitle.trim()) return;
    setCreating(true);
    const id = await createCase({
      title: createTitle.trim(),
      severity: createSeverity as any,
      description: createDescription.trim() || undefined,
      category: createCategory || undefined,
      tags: createTags.length > 0 ? createTags : undefined,
    });
    setCreating(false);
    if (id) {
      setShowCreate(false);
      onOpen(id);
    }
  };

  const summary = summarizeCases(
    cases.map((c) => ({ status: c.status, createdAt: c.createdAt, closedAt: c.closedAt }))
  );

  return (
    <EuiPage paddingSize="l">
      <EuiPageBody>
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
          <EuiFlexItem>
            <EuiTitle size="l">
              <h1>Cases</h1>
            </EuiTitle>
            <EuiText color="subdued" size="s">
              <p>Track investigations end to end.</p>
            </EuiText>
          </EuiFlexItem>
          <EuiFlexGroup gutterSize="s" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiButton iconType="refresh" onClick={reload}>
                Refresh
              </EuiButton>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton fill iconType="plusInCircle" onClick={openCreateModal}>
                New case
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlexGroup>
        <EuiSpacer size="m" />

        {/* Stat-cards row */}
        <EuiFlexGroup gutterSize="m" responsive={false}>
          <EuiFlexItem>
            <EuiPanel hasBorder hasShadow={false} paddingSize="m">
              <EuiTitle size="l">
                <span>{summary.open}</span>
              </EuiTitle>
              <EuiText size="s" color="subdued">
                <p>Open</p>
              </EuiText>
            </EuiPanel>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiPanel hasBorder hasShadow={false} paddingSize="m">
              <EuiTitle size="l">
                <span>{summary.inProgress}</span>
              </EuiTitle>
              <EuiText size="s" color="subdued">
                <p>In Progress</p>
              </EuiText>
            </EuiPanel>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiPanel hasBorder hasShadow={false} paddingSize="m">
              <EuiTitle size="l">
                <span>{summary.closed}</span>
              </EuiTitle>
              <EuiText size="s" color="subdued">
                <p>Closed</p>
              </EuiText>
            </EuiPanel>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiPanel hasBorder hasShadow={false} paddingSize="m">
              <EuiTitle size="l">
                <span>{formatDuration(summary.avgTimeToCloseMs)}</span>
              </EuiTitle>
              <EuiText size="s" color="subdued">
                <p>Avg time to close</p>
              </EuiText>
            </EuiPanel>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="m" />

        <EuiFlexGroup gutterSize="m" alignItems="center">
          <EuiFlexItem grow={false}>
            <EuiButtonGroup
              legend="Filter by status"
              options={statusFilterOptions}
              idSelected={statusFilter}
              onChange={(id) => setStatusFilter(id)}
              buttonSize="s"
            />
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonGroup
              legend="Filter by severity"
              options={sevFilterOptions}
              idSelected={sevFilter}
              onChange={(id) => setSevFilter(id)}
              buttonSize="s"
            />
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiSelect
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              options={[
                { value: 'all', text: 'All categories' },
                ...CASE_CATEGORIES.map((c) => ({ value: c, text: c })),
              ]}
              aria-label="Filter by category"
            />
          </EuiFlexItem>
          <EuiFlexItem style={{ minWidth: 200 }}>
            <EuiComboBox
              placeholder="Filter by tags"
              options={allTagOptions}
              selectedOptions={tagFilter.map((t) => ({ label: t }))}
              onChange={(opts) => setTagFilter(opts.map((o) => o.label))}
              isClearable
            />
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="l" />

        {error ? (
          <>
            <EuiCallOut color="danger" iconType="alert" title="Could not load cases">
              <p>{error}</p>
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
                <EuiText size="s">Loading cases…</EuiText>
              </EuiFlexItem>
            </EuiFlexGroup>
          ) : cases.length === 0 ? (
            <EuiEmptyPrompt
              iconType="folderClosed"
              title={<h2>No cases yet</h2>}
              body={<p>Create a case to start tracking an investigation.</p>}
              actions={
                <EuiButton fill iconType="plusInCircle" onClick={openCreateModal}>
                  Create your first case
                </EuiButton>
              }
            />
          ) : (
            <EuiBasicTable
              items={visible}
              columns={columns}
              rowHeader="title"
              rowProps={(row) => ({
                onClick: () => onOpen(row.id),
                style: { cursor: 'pointer' },
              })}
            />
          )}
        </EuiPanel>
      </EuiPageBody>

      {showCreate ? (
        <EuiModal onClose={() => setShowCreate(false)}>
          <EuiModalHeader>
            <EuiModalHeaderTitle>New case</EuiModalHeaderTitle>
          </EuiModalHeader>
          <EuiModalBody>
            <EuiForm>
              <EuiFormRow label="Title" isInvalid={createTitle.trim() === ''} error="Title is required">
                <EuiFieldText
                  value={createTitle}
                  onChange={(e) => setCreateTitle(e.target.value)}
                  placeholder="Enter a title for this case"
                />
              </EuiFormRow>
              <EuiFormRow label="Severity">
                <EuiSelect
                  value={createSeverity}
                  onChange={(e) => setCreateSeverity(e.target.value)}
                  options={[
                    { value: 'low', text: 'Low' },
                    { value: 'medium', text: 'Medium' },
                    { value: 'high', text: 'High' },
                    { value: 'critical', text: 'Critical' },
                  ]}
                />
              </EuiFormRow>
              <EuiFormRow label="Description">
                <EuiTextArea
                  value={createDescription}
                  onChange={(e) => setCreateDescription(e.target.value)}
                  placeholder="Optional description"
                  rows={4}
                />
              </EuiFormRow>
              <EuiFormRow label="Category">
                <EuiSelect
                  value={createCategory}
                  onChange={(e) => setCreateCategory(e.target.value)}
                  options={[
                    { value: '', text: 'Uncategorized' },
                    ...CASE_CATEGORIES.map((c) => ({ value: c, text: c })),
                  ]}
                />
              </EuiFormRow>
              <EuiFormRow label="Tags">
                <EuiComboBox
                  noSuggestions
                  placeholder="Add tags"
                  selectedOptions={createTags.map((t) => ({ label: t }))}
                  onCreateOption={(val) => {
                    const v = val.trim();
                    if (v && !createTags.includes(v)) setCreateTags([...createTags, v]);
                  }}
                  onChange={(opts) => setCreateTags(opts.map((o) => o.label))}
                />
              </EuiFormRow>
            </EuiForm>
          </EuiModalBody>
          <EuiModalFooter>
            <EuiButton onClick={() => setShowCreate(false)}>Cancel</EuiButton>
            <EuiButton
              fill
              isDisabled={!createTitle.trim()}
              isLoading={creating}
              onClick={handleCreate}
            >
              Create case
            </EuiButton>
          </EuiModalFooter>
        </EuiModal>
      ) : null}

      {pendingDelete ? (
        <EuiConfirmModal
          title={`Delete "${pendingDelete.title}"?`}
          onCancel={() => setPendingDelete(null)}
          onConfirm={async () => {
            await deleteCase(pendingDelete.id);
            setPendingDelete(null);
          }}
          cancelButtonText="Cancel"
          confirmButtonText="Delete case"
          buttonColor="danger"
        >
          <p>This permanently removes the case and cannot be undone.</p>
        </EuiConfirmModal>
      ) : null}
    </EuiPage>
  );
}
