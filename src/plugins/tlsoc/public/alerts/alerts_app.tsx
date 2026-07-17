/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useCallback, useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonGroup,
  EuiCallOut,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSpacer,
  EuiSuperDatePicker,
  EuiText,
  EuiTitle,
  OnRefreshChangeProps,
  OnTimeChangeProps,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../../data/public';
import type { DiscoverStart } from '../../../discover/public';
import { TlsocAlert } from '../../common/alerts';
import { buildCaseFromAlert } from '../../common/cases';
import { sortAlerts } from './sort';
import { useAlerts } from './use_alerts';
import { sevColor, stateColor, entityOf } from './format';
import { AddToCaseModal } from './add_to_case_modal';
import { AlertFlyout } from './alert_flyout';

interface Props {
  core: CoreStart;
  data: DataPublicPluginStart;
  discover?: DiscoverStart;
}

const DEFAULT_REFRESH_INTERVAL_MS = 30000;

export function AlertsApp({ core, data, discover }: Props) {
  // WS-3 (PROB-3): the time-range + auto-refresh state driving the EuiSuperDatePicker header.
  const [start, setStart] = useState('now-24h');
  const [end, setEnd] = useState('now');
  const [isPaused, setIsPaused] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(DEFAULT_REFRESH_INTERVAL_MS);

  // Single polling source: EuiSuperDatePicker's own internal timer (armed by onRefresh below,
  // driven by isPaused/refreshInterval) calls reload() directly. The hook's own refreshMs-driven
  // setInterval is intentionally left at 0/off here — wiring BOTH would poll the engine Alerting
  // API at ~2x the intended rate for every open Alerts tab (this page is left open all day).
  // refreshMs stays a capability of useAlerts itself for any future headless caller without a
  // picker; alerts_app.tsx just doesn't drive it. Fetch-time datemath resolution (inside `load()`)
  // still makes 'now-24h'..'now' roll forward on every picker-driven poll either way.
  const { alerts, loading, error, reload, acknowledge } = useAlerts(core, { start, end });
  const [dataViews, setDataViews] = useState<Array<{ id: string; title: string }>>([]);
  const [stateFilter, setStateFilter] = useState<string>('active');
  const [sevFilter, setSevFilter] = useState<string>('all');
  const [selected, setSelected] = useState<TlsocAlert | null>(null);
  const [bulkSelected, setBulkSelected] = useState<TlsocAlert[]>([]);
  const [showAddToCase, setShowAddToCase] = useState(false);
  const [addTargets, setAddTargets] = useState<TlsocAlert[]>([]);

  const onTimeChange = useCallback(({ start: s, end: e }: OnTimeChangeProps) => {
    setStart(s);
    setEnd(e);
  }, []);

  const onRefreshChange = useCallback(({ isPaused: p, refreshInterval: ri }: OnRefreshChangeProps) => {
    setIsPaused(p);
    setRefreshInterval(ri);
  }, []);

  useEffect(() => {
    data.dataViews
      .getIdsWithTitle()
      .then((dv) => setDataViews(dv))
      .catch(() => setDataViews([]));
  }, [data]);

  const canInvestigate = useCallback(
    (a: TlsocAlert): boolean => {
      return (
        !!discover?.urlGenerator && !!a.rule?.index && dataViews.some((dv) => dv.title === a.rule!.index)
      );
    },
    [discover, dataViews]
  );

  const investigate = useCallback(
    async (a: TlsocAlert) => {
      const dv = dataViews.find((d) => d.title === a.rule?.index);
      if (!dv || !discover?.urlGenerator) {
        core.notifications.toasts.addWarning(
          `Create a data view for "${a.rule?.index}" to investigate`
        );
        return;
      }
      const from = new Date((a.startTime ?? Date.now()) - 30 * 60000).toISOString();
      const to = new Date((a.startTime ?? Date.now()) + 30 * 60000).toISOString();
      const url = await discover.urlGenerator.createUrl({
        indexPatternId: dv.id,
        query: { language: 'kuery', query: '' },
        timeRange: { from, to },
      });
      core.application.navigateToApp('discover', { path: url.substring(url.indexOf('#')) });
    },
    [core, discover, dataViews]
  );

  const createCaseFromAlert = useCallback(
    async (a: TlsocAlert) => {
      try {
        const input = buildCaseFromAlert(a);
        const resp = (await core.http.post('/api/tlsoc/cases', {
          body: JSON.stringify(input),
        })) as any;
        core.notifications.toasts.addSuccess('Case created from alert');
        core.application.navigateToApp('tlsoc_cases', { path: `#/case/${resp.id}` });
      } catch (e) {
        const err = e as any;
        core.notifications.toasts.addDanger({
          title: 'Could not create case',
          text: err?.body?.message ?? err?.message ?? 'Failed',
        });
      }
    },
    [core]
  );

  const stateFilterOptions = [
    { id: 'all', label: 'All' },
    { id: 'active', label: 'Active' },
    { id: 'acknowledged', label: 'Acknowledged' },
  ];

  const sevFilterOptions = [
    { id: 'all', label: 'All' },
    { id: 'critical', label: 'Critical' },
    { id: 'high', label: 'High' },
    { id: 'medium', label: 'Medium' },
    { id: 'low', label: 'Low' },
  ];

  const visible = sortAlerts(
    alerts.filter((a) => {
      const stateMatch =
        stateFilter === 'all' ||
        (stateFilter === 'active' && a.state === 'ACTIVE') ||
        (stateFilter === 'acknowledged' && a.state === 'ACKNOWLEDGED');
      const sevMatch = sevFilter === 'all' || a.severityLabel === sevFilter;
      return stateMatch && sevMatch;
    })
  );

  const columns: Array<EuiBasicTableColumn<TlsocAlert>> = [
    {
      field: 'severityLabel',
      name: 'Severity',
      render: (_: any, a: TlsocAlert) => (
        <EuiBadge color={sevColor(a.severityLabel)}>{a.severityLabel}</EuiBadge>
      ),
    },
    {
      field: 'rule',
      name: 'Rule',
      render: (_: any, a: TlsocAlert) =>
        a.ruleKnown && a.rule ? (
          <span>{a.rule.name}</span>
        ) : (
          <EuiText color="subdued" size="s">
            Unknown rule ({a.monitorName})
          </EuiText>
        ),
    },
    {
      field: 'triggerName',
      name: 'Trigger',
      truncateText: true,
      render: (_: any, a: TlsocAlert) => (
        <div>
          {a.triggerName}
          <EuiText color="subdued" size="xs">
            {a.monitorName}
          </EuiText>
        </div>
      ),
    },
    {
      field: 'state',
      name: 'State',
      render: (_: any, a: TlsocAlert) => (
        <EuiBadge color={stateColor(a.state)}>{a.state}</EuiBadge>
      ),
    },
    {
      field: 'startTime',
      name: 'Time',
      sortable: false,
      render: (t?: number | null) => (t ? new Date(t).toLocaleString() : '—'),
    },
    {
      field: 'relatedDocIds',
      name: 'Entity',
      truncateText: true,
      render: (_: any, a: TlsocAlert) => entityOf(a),
    },
    {
      name: 'Actions',
      actions: [
        {
          name: 'Acknowledge',
          description: 'Acknowledge this alert',
          icon: 'check',
          type: 'icon',
          available: (a: TlsocAlert) => a.state === 'ACTIVE',
          onClick: (a: TlsocAlert) => acknowledge(a.monitorId, [a.id]),
        },
        {
          name: 'Investigate',
          description: 'Investigate in Discover',
          icon: 'discoverApp',
          type: 'icon',
          enabled: (a: TlsocAlert) => canInvestigate(a),
          onClick: (a: TlsocAlert) => investigate(a),
        },
        {
          name: 'Create case',
          description: 'Create a case from this alert',
          icon: 'folderClosed',
          type: 'icon',
          onClick: (a: TlsocAlert) => createCaseFromAlert(a),
        },
        {
          name: 'Add to case',
          description: 'Add this alert to a case',
          icon: 'listAdd',
          type: 'icon',
          onClick: (a: TlsocAlert) => { setAddTargets([a]); setShowAddToCase(true); },
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
              <h1>Alerts</h1>
            </EuiTitle>
            <EuiText color="subdued" size="s">
              <p>
                Triage fired detections — prioritize, acknowledge, and investigate.
              </p>
            </EuiText>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiSuperDatePicker
              start={start}
              end={end}
              onTimeChange={onTimeChange}
              isPaused={isPaused}
              refreshInterval={refreshInterval}
              onRefreshChange={onRefreshChange}
              onRefresh={reload}
            />
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="m" />

        <EuiFlexGroup gutterSize="m" alignItems="center">
          <EuiFlexItem grow={false}>
            <EuiButtonGroup
              legend="Filter by state"
              options={stateFilterOptions}
              idSelected={stateFilter}
              onChange={(id) => setStateFilter(id)}
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
        </EuiFlexGroup>
        <EuiSpacer size="l" />

        {error ? (
          <>
            <EuiCallOut color="danger" iconType="alert" title="Could not load alerts">
              <p>{error}</p>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        ) : null}

        {bulkSelected.length > 0 ? (
          <EuiFlexGroup gutterSize="s" alignItems="center">
            <EuiFlexItem grow={false}>
              <EuiText size="s">{bulkSelected.length} selected</EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton
                size="s"
                iconType="listAdd"
                onClick={() => { setAddTargets(bulkSelected); setShowAddToCase(true); }}
              >
                Add to case
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        ) : null}
        <EuiSpacer size="s" />

        <EuiPanel hasBorder hasShadow={false}>
          {loading ? (
            <EuiFlexGroup justifyContent="center" alignItems="center" gutterSize="s">
              <EuiFlexItem grow={false}>
                <EuiLoadingSpinner size="m" />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiText size="s">Loading alerts…</EuiText>
              </EuiFlexItem>
            </EuiFlexGroup>
          ) : visible.length === 0 ? (
            <EuiEmptyPrompt
              iconType="bell"
              title={<h2>No alerts</h2>}
              body={
                <p>Alerts from your detections will appear here as monitors fire.</p>
              }
            />
          ) : (
            <EuiBasicTable
              items={visible}
              columns={columns}
              rowHeader="triggerName"
              itemId="id"
              selection={{ onSelectionChange: (sel: TlsocAlert[]) => setBulkSelected(sel) }}
              rowProps={(a) => ({
                onClick: () => setSelected(a),
                style: { cursor: 'pointer' },
              })}
            />
          )}
        </EuiPanel>
      </EuiPageBody>

      {showAddToCase ? (
        <AddToCaseModal
          core={core}
          alerts={addTargets}
          onClose={() => setShowAddToCase(false)}
          onDone={() => { setShowAddToCase(false); setBulkSelected([]); }}
        />
      ) : null}

      {selected ? (
        <AlertFlyout
          core={core}
          alert={selected}
          onClose={() => setSelected(null)}
          onAcknowledge={() => {
            acknowledge(selected.monitorId, [selected.id]);
            setSelected(null);
          }}
          canInvestigate={canInvestigate(selected)}
          onInvestigate={() => investigate(selected)}
          onCreateCase={() => createCaseFromAlert(selected)}
        />
      ) : null}
    </EuiPage>
  );
}
