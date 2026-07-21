/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiComboBox,
  EuiConfirmModal,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiInMemoryTable,
  EuiLoadingSpinner,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DetectionMode, ThreatEntry, getType } from '../../common/detection';
import type { RuleHealthInfo } from '../../common/detection/health';
import {
  buildNativeBulkExport,
  buildNativeEnvelope,
  sigmaExportUnavailableReason,
} from '../../common/detection/export';
import { EnabledToggle } from './enabled_toggle';
import { findUiType, listUiTypes } from './type_registry';
import {
  BulkRunResult,
  mergeTags,
  runBulkAddTags,
  runBulkDelete,
  runBulkToggle,
  summarizeBulk,
} from './bulk_actions';

/** One row of the saved-detections list (shape returned by GET /api/tlsoc/detection/monitors). */
export interface SavedRuleRow {
  soId: string;
  name: string;
  mode: DetectionMode;
  severity: string;
  index?: string;
  executionAlias?: string;
  monitorId: string;
  createdAt?: string;
  enabled: boolean;
  /** v1.2.3 D8 additive fields — absent on responses from an older server. */
  threat?: ThreatEntry[];
  riskScore?: number;
  tags?: string[];
  updatedAt?: string;
  sigmaEligible?: boolean;
  health?: RuleHealthInfo;
}

/** Row + the flat computed field the EuiSearchBar health filter needs (it can't reach health.status). */
type FilterableRow = SavedRuleRow & { healthStatus: RuleHealthInfo['status'] };

interface Props {
  core: CoreStart;
  onCreate: () => void;
  onEdit: (soId: string) => void;
  onImport: () => void;
  /** Mounts the "Install starter pack" button (v1.2.3 D10). Absent → the button is not shown. */
  onInstallPack?: () => void;
  /**
   * ATT&CK technique id to filter the rows by (v1.2.3 D10 — the coverage matrix's cell click).
   * The matrix passes TOP-LEVEL ids only; matching mirrors foldCoverage's roll-up (see
   * {@link ruleMatchesTechnique}). null/absent = no filter.
   */
  techniqueFilter?: string | null;
  /** Called when the user clears the technique filter chip. */
  onTechniqueFilterChange?: (id: string | null) => void;
}

/**
 * Does this rule's `threat[]` reference `techniqueId` (a TOP-LEVEL ATT&CK technique id)?
 * Mirrors foldCoverage's roll-up (coverage_matrix.tsx) WITHOUT the lazy catalog: a sub-technique
 * id is its parent's id plus a ".NNN" suffix, so `id === techniqueId || id.startsWith(`${id}.`)`
 * matches both the technique itself and its sub-techniques, wherever they appear (technique[]
 * entries OR nested subtechnique[]). Unknown/malformed entries are tolerated, never crashed on.
 */
export function ruleMatchesTechnique(
  threat: ThreatEntry[] | undefined,
  techniqueId: string
): boolean {
  if (!Array.isArray(threat)) return false;
  const matches = (id: unknown) =>
    typeof id === 'string' && (id === techniqueId || id.startsWith(`${techniqueId}.`));
  for (const entry of threat) {
    const techniques = Array.isArray(entry?.technique) ? entry.technique : [];
    for (const tech of techniques) {
      if (matches(tech?.id)) return true;
      const subs = Array.isArray(tech?.subtechnique) ? tech.subtechnique : [];
      if (subs.some((s) => matches(s?.id))) return true;
    }
  }
  return false;
}

/** The plugin-wide honesty cap: the LIST route scans at most this many rule saved objects. */
const LIST_CAP = 1000;

const formatTime = (value?: string | number) =>
  value !== undefined && value !== null && value !== '' ? new Date(value).toLocaleString() : '—';

/** Trigger a browser download of `content` as `filename`. */
function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

const fileSlug = (name: string) =>
  name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'tlsoc-rule';

/**
 * The HONEST health badge (v1.2.3 D8). Never "Succeeded": the engine keeps no run history and
 * bucket-/doc-level failures are invisible, so the strongest truthful claim for a running rule
 * is "no failures recorded" (see common/detection/health.ts for the full why).
 */
function HealthBadge({ health }: { health?: RuleHealthInfo }) {
  if (!health) return <EuiText size="s">—</EuiText>;
  if (health.status === 'off') {
    return <EuiBadge color="default">Off</EuiBadge>;
  }
  if (health.status === 'failing') {
    const since = health.lastError?.at ? ` (since ${formatTime(health.lastError.at)})` : '';
    return (
      <EuiToolTip
        position="top"
        content={`${health.lastError?.message ?? 'The monitor run failed.'}${since}`}
      >
        <EuiBadge color="danger">Failing</EuiBadge>
      </EuiToolTip>
    );
  }
  return (
    <EuiToolTip
      position="top"
      content={
        'No failures recorded. The engine reports failures only — successful runs leave no ' +
        'trace, and threshold/single-event runtime failures can be invisible — so TLSOC never ' +
        'claims a run "Succeeded".'
      }
    >
      <EuiBadge color="hollow">OK — no failures recorded</EuiBadge>
    </EuiToolTip>
  );
}

/**
 * Lists saved `tlsoc-detection-rule` detections (v1.2.3 D8 rebuild): searchable/filterable
 * EuiInMemoryTable with health, tags and risk columns, per-row native/Sigma export, and a
 * selection-driven bulk toolbar looping the EXISTING per-rule routes (no bulk server routes).
 */
export function SavedRulesList({
  core,
  onCreate,
  onEdit,
  onImport,
  onInstallPack,
  techniqueFilter,
  onTechniqueFilterChange,
}: Props) {
  const [rules, setRules] = useState<SavedRuleRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<SavedRuleRow | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [selection, setSelection] = useState<FilterableRow[]>([]);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false);
  const [showTagModal, setShowTagModal] = useState(false);
  const [tagOptions, setTagOptions] = useState<Array<{ label: string }>>([]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = (await core.http.get('/api/tlsoc/detection/monitors')) as any;
      setRules(resp?.rules ?? []);
      setSelection([]); // stale selections after a reload would act on gone/changed rows
    } catch (e) {
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
      const err = e as any;
      setError(err?.body?.message ?? err?.message ?? 'Could not delete detection');
      setPendingDelete(null);
    } finally {
      setDeleting(false);
    }
  };

  // ---- per-row export ---------------------------------------------------------------------

  /** GET-ONE (the edit-hydration route) — the full rule for a single-row export. */
  const fetchFullRule = async (soId: string): Promise<{ mode: DetectionMode; rule: any }> => {
    const resp = (await core.http.get(`/api/tlsoc/detection/monitors/${soId}`)) as any;
    return { mode: resp.mode, rule: resp.rule };
  };

  const exportNative = async (row: SavedRuleRow) => {
    try {
      const { mode, rule } = await fetchFullRule(row.soId);
      downloadFile(
        JSON.stringify(buildNativeEnvelope(mode, rule), null, 2),
        `${fileSlug(row.name)}.json`,
        'application/json'
      );
    } catch (e) {
      const err = e as any;
      core.notifications.toasts.addDanger({
        title: 'Could not export rule',
        text: err?.body?.message ?? err?.message ?? 'Failed to load the saved rule',
      });
    }
  };

  const exportSigma = async (row: SavedRuleRow) => {
    try {
      const { mode, rule } = await fetchFullRule(row.soId);
      // Re-check on the FULL rule — the row flag is advisory (an advanced/exceptions caveat
      // added since the list loaded must still refuse by name).
      const reason = sigmaExportUnavailableReason(mode, rule);
      if (reason !== null) {
        core.notifications.toasts.addWarning({ title: 'Sigma export unavailable', text: reason });
        return;
      }
      downloadFile(getType(mode).toSigma!(rule), `${fileSlug(row.name)}.yml`, 'text/yaml');
    } catch (e) {
      const err = e as any;
      core.notifications.toasts.addDanger({
        title: 'Could not export rule',
        text: err?.body?.message ?? err?.message ?? 'Failed to compile the Sigma export',
      });
    }
  };

  const exportSelected = async () => {
    if (selection.length === 0) return;
    setBulkBusy(true);
    try {
      // One LIST call with the full rules — the SO scan already holds them server-side.
      const resp = (await core.http.get('/api/tlsoc/detection/monitors', {
        query: { includeRule: 'true' },
      })) as any;
      const wanted = new Set(selection.map((r) => r.soId));
      const rows = ((resp?.rules ?? []) as any[]).filter((r) => wanted.has(r.soId) && r.rule);
      if (rows.length === 0) {
        core.notifications.toasts.addWarning('None of the selected rules could be exported.');
        return;
      }
      downloadFile(
        JSON.stringify(
          buildNativeBulkExport(rows.map((r) => ({ mode: r.mode, rule: r.rule }))),
          null,
          2
        ),
        `tlsoc-rules-${new Date().toISOString().slice(0, 10)}.json`,
        'application/json'
      );
      if (rows.length < selection.length) {
        core.notifications.toasts.addWarning(
          `Exported ${rows.length} of ${selection.length} selected rules (the rest were not found on re-read).`
        );
      }
    } catch (e) {
      const err = e as any;
      core.notifications.toasts.addDanger({
        title: 'Could not export selection',
        text: err?.body?.message ?? err?.message ?? 'Failed to load the rules',
      });
    } finally {
      setBulkBusy(false);
    }
  };

  // ---- bulk actions (PROB-25 idiom: sequential loops, ONE summary toast, ONE reload) --------

  const toastResult = (verb: string, result: BulkRunResult) => {
    const summary = summarizeBulk(verb, result);
    if (summary.color === 'success') {
      core.notifications.toasts.addSuccess(summary.title);
    } else if (summary.color === 'warning') {
      core.notifications.toasts.addWarning({ title: summary.title, text: summary.text });
    } else {
      core.notifications.toasts.addDanger({ title: summary.title, text: summary.text });
    }
  };

  const bulkToggle = async (enable: boolean) => {
    setBulkBusy(true);
    try {
      const result = await runBulkToggle(core.http, selection, enable);
      toastResult(enable ? 'Enabled' : 'Disabled', result);
      await load();
    } finally {
      setBulkBusy(false);
    }
  };

  const bulkDelete = async () => {
    setBulkBusy(true);
    try {
      const result = await runBulkDelete(core.http, selection);
      toastResult('Deleted', result);
      setConfirmBulkDelete(false);
      await load();
    } finally {
      setBulkBusy(false);
    }
  };

  const bulkAddTags = async () => {
    const tags = tagOptions.map((o) => o.label);
    if (tags.length === 0) return;
    setBulkBusy(true);
    try {
      const result = await runBulkAddTags(core.http, selection, tags);
      toastResult('Tagged', result);
      setShowTagModal(false);
      setTagOptions([]);
      await load();
    } finally {
      setBulkBusy(false);
    }
  };

  // ---- table -------------------------------------------------------------------------------

  const items: FilterableRow[] = useMemo(() => {
    // v1.2.3 D10: the coverage-matrix technique filter narrows the rows BEFORE the search bar
    // (its own filters compose on top of this base set).
    const base = techniqueFilter
      ? rules.filter((r) => ruleMatchesTechnique(r.threat, techniqueFilter))
      : rules;
    return base.map((r) => ({
      ...r,
      healthStatus: r.health?.status ?? (r.enabled ? 'ok-unverified' : 'off'),
    }));
  }, [rules, techniqueFilter]);

  // A changed technique filter can hide selected rows — clear the (table-remounted, see the
  // table's key below) selection so bulk actions never act on rows the analyst can't see.
  useEffect(() => {
    setSelection([]);
  }, [techniqueFilter]);

  const allTags = useMemo(() => {
    const set = new Set<string>();
    rules.forEach((r) => (r.tags ?? []).forEach((t) => set.add(t)));
    return Array.from(set).sort();
  }, [rules]);

  const columns: Array<EuiBasicTableColumn<FilterableRow>> = [
    { field: 'name', name: 'Name', sortable: true, truncateText: true },
    {
      field: 'mode',
      name: 'Type',
      // Badge label/color come from the UI registry; an unregistered mode (a rule saved by a newer
      // TLSOC) degrades to its raw id in a hollow badge instead of crashing the list.
      render: (m: string) => {
        const badge = findUiType(m)?.listBadge;
        return <EuiBadge color={badge?.color ?? 'hollow'}>{badge?.label ?? m}</EuiBadge>;
      },
    },
    { field: 'severity', name: 'Severity', sortable: true, width: '90px' },
    {
      field: 'riskScore',
      name: 'Risk',
      sortable: true,
      width: '70px',
      render: (score?: number) => (typeof score === 'number' ? String(score) : '—'),
    },
    {
      field: 'tags',
      name: 'Tags',
      render: (tags?: string[]) =>
        tags && tags.length > 0 ? (
          <EuiFlexGroup gutterSize="xs" wrap responsive={false}>
            {tags.slice(0, 3).map((t) => (
              <EuiFlexItem grow={false} key={t}>
                <EuiBadge color="hollow">{t}</EuiBadge>
              </EuiFlexItem>
            ))}
            {tags.length > 3 ? (
              <EuiFlexItem grow={false}>
                <EuiToolTip content={tags.slice(3).join(', ')}>
                  <EuiBadge color="hollow">+{tags.length - 3}</EuiBadge>
                </EuiToolTip>
              </EuiFlexItem>
            ) : null}
          </EuiFlexGroup>
        ) : (
          '—'
        ),
    },
    {
      field: 'enabled',
      name: 'Enabled',
      width: '90px',
      render: (_enabled: boolean, r: FilterableRow) => (
        <EnabledToggle
          core={core}
          soId={r.soId}
          mode={r.mode}
          enabled={r.enabled}
          onChanged={() => load()}
        />
      ),
    },
    {
      field: 'health.lastRun',
      name: 'Last run',
      // Only ENABLED monitors have a last-run signal (scheduler stats) — '—' is honest, not
      // missing data: the engine keeps no run history for disabled monitors at all.
      render: (_: unknown, r: FilterableRow) =>
        r.enabled && r.health?.lastRun ? formatTime(r.health.lastRun) : '—',
    },
    {
      field: 'healthStatus',
      name: 'Health',
      render: (_: unknown, r: FilterableRow) => <HealthBadge health={r.health} />,
    },
    {
      field: 'updatedAt',
      name: 'Updated',
      sortable: true,
      render: (d?: string) => formatTime(d),
    },
    {
      name: 'Actions',
      actions: [
        {
          name: 'Edit',
          description: 'Edit this detection',
          icon: 'pencil',
          type: 'icon',
          onClick: (r: FilterableRow) => onEdit(r.soId),
        },
        {
          name: 'Export (native JSON)',
          description: 'Download this rule as a re-importable TLSOC JSON envelope',
          icon: 'exportAction',
          type: 'icon',
          onClick: (r: FilterableRow) => exportNative(r),
        },
        {
          name: 'Export (Sigma)',
          description: 'Download this rule as portable Sigma YAML',
          icon: 'share',
          type: 'icon',
          available: (r: FilterableRow) => r.sigmaEligible === true,
          onClick: (r: FilterableRow) => exportSigma(r),
        },
        {
          name: 'Delete',
          description: 'Delete this detection',
          icon: 'trash',
          color: 'danger',
          type: 'icon',
          onClick: (r: FilterableRow) => setPendingDelete(r),
        },
      ],
    },
  ];

  const search = {
    box: { incremental: true, placeholder: 'Search detections…' },
    filters: [
      {
        type: 'field_value_selection' as const,
        field: 'mode',
        name: 'Type',
        multiSelect: 'or' as const,
        options: listUiTypes().map((t) => ({ value: t.id, name: t.listBadge.label })),
      },
      {
        type: 'is' as const,
        field: 'enabled',
        name: 'Enabled',
      },
      {
        type: 'field_value_selection' as const,
        field: 'healthStatus',
        name: 'Health',
        multiSelect: 'or' as const,
        options: [
          { value: 'failing', name: 'Failing' },
          { value: 'ok-unverified', name: 'OK — no failures recorded' },
          { value: 'off', name: 'Off' },
        ],
      },
      {
        type: 'field_value_selection' as const,
        field: 'tags',
        name: 'Tags',
        multiSelect: 'or' as const,
        options: allTags.map((t) => ({ value: t, name: t })),
      },
    ],
  };

  const bulkToolbar =
    selection.length > 0 ? (
      <>
        <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false} wrap>
          <EuiFlexItem grow={false}>
            <EuiText size="s">
              <strong>
                {selection.length} selected{' '}
              </strong>
            </EuiText>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="s" iconType="play" isDisabled={bulkBusy} onClick={() => bulkToggle(true)}>
              Enable
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="s" iconType="pause" isDisabled={bulkBusy} onClick={() => bulkToggle(false)}>
              Disable
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="s" iconType="tag" isDisabled={bulkBusy} onClick={() => setShowTagModal(true)}>
              Add tags
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="s" iconType="exportAction" isDisabled={bulkBusy} onClick={exportSelected}>
              Export selected
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty
              size="s"
              iconType="trash"
              color="danger"
              isDisabled={bulkBusy}
              onClick={() => setConfirmBulkDelete(true)}
            >
              Delete
            </EuiButtonEmpty>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="s" />
      </>
    ) : null;

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
            <EuiFlexGroup gutterSize="s">
              {onInstallPack ? (
                <EuiFlexItem grow={false}>
                  <EuiButton iconType="package" onClick={onInstallPack}>
                    Install starter pack
                  </EuiButton>
                </EuiFlexItem>
              ) : null}
              <EuiFlexItem grow={false}>
                <EuiButton iconType="importAction" onClick={onImport}>
                  Import rule
                </EuiButton>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton fill iconType="plusInCircle" onClick={onCreate}>
                  Create detection
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
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

        {rules.length >= LIST_CAP ? (
          <>
            <EuiCallOut
              size="s"
              color="warning"
              title={`Showing the first ${LIST_CAP} rules — the list (and its bulk actions) is capped there.`}
            />
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
              actions={[
                <EuiButton fill iconType="plusInCircle" onClick={onCreate} key="create">
                  Create your first detection
                </EuiButton>,
                <EuiButton iconType="importAction" onClick={onImport} key="import">
                  Import rule
                </EuiButton>,
              ]}
            />
          ) : (
            <>
              {techniqueFilter ? (
                <>
                  {/* v1.2.3 D10: the visible technique-filter chip — clearing it hands null
                      back to the owner (DetectionsApp holds the state). */}
                  <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
                    <EuiFlexItem grow={false}>
                      <EuiBadge
                        color="primary"
                        iconType="cross"
                        iconSide="right"
                        iconOnClick={() => onTechniqueFilterChange?.(null)}
                        iconOnClickAriaLabel="Clear the ATT&CK technique filter"
                      >
                        ATT&amp;CK technique: {techniqueFilter}
                      </EuiBadge>
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiText size="s" color="subdued">
                        {items.length} of {rules.length} rule{rules.length === 1 ? '' : 's'} match
                      </EuiText>
                    </EuiFlexItem>
                  </EuiFlexGroup>
                  <EuiSpacer size="s" />
                </>
              ) : null}
              {bulkToolbar}
              <EuiInMemoryTable
                // Remounted when the technique filter changes, so the table's INTERNAL selection
                // state resets in lockstep with the cleared `selection` copy above.
                key={techniqueFilter ?? 'all'}
                items={items}
                columns={columns}
                rowHeader="name"
                itemId="soId"
                search={search as any}
                sorting={true}
                pagination={{ initialPageSize: 20, pageSizeOptions: [10, 20, 50] }}
                selection={{ onSelectionChange: setSelection }}
                isSelectable
              />
            </>
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

      {confirmBulkDelete ? (
        <EuiConfirmModal
          title={`Delete ${selection.length} detection${selection.length === 1 ? '' : 's'}?`}
          onCancel={() => setConfirmBulkDelete(false)}
          onConfirm={bulkDelete}
          cancelButtonText="Cancel"
          confirmButtonText={`Delete ${selection.length} detection${selection.length === 1 ? '' : 's'}`}
          buttonColor="danger"
          isLoading={bulkBusy}
        >
          <p>
            This permanently removes each selected detection and its OpenSearch Alerting monitor.
            This cannot be undone.
          </p>
        </EuiConfirmModal>
      ) : null}

      {showTagModal ? (
        <EuiModal onClose={() => setShowTagModal(false)} style={{ minWidth: 420 }}>
          <EuiModalHeader>
            <EuiModalHeaderTitle>
              Add tags to {selection.length} rule{selection.length === 1 ? '' : 's'}
            </EuiModalHeaderTitle>
          </EuiModalHeader>
          <EuiModalBody>
            <EuiFormRow
              label="Tags"
              helpText="Added on top of each rule's existing tags (max 20 per rule, 50 characters each)."
            >
              <EuiComboBox
                noSuggestions
                placeholder="Type a tag and press Enter"
                selectedOptions={tagOptions}
                onCreateOption={(value: string) => {
                  const tag = value.trim();
                  if (tag === '') return;
                  setTagOptions((prev) => mergeTags(prev.map((o) => o.label), [tag]).map((label) => ({ label })));
                }}
                onChange={(opts: Array<{ label: string }>) => setTagOptions([...opts])}
              />
            </EuiFormRow>
          </EuiModalBody>
          <EuiModalFooter>
            <EuiButtonEmpty onClick={() => setShowTagModal(false)}>Cancel</EuiButtonEmpty>
            <EuiButton fill isDisabled={tagOptions.length === 0 || bulkBusy} isLoading={bulkBusy} onClick={bulkAddTags}>
              Add tags
            </EuiButton>
          </EuiModalFooter>
        </EuiModal>
      ) : null}
    </EuiPage>
  );
}
