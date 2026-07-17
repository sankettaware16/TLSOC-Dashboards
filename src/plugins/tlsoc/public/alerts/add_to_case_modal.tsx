/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useEffect, useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiComboBox,
  EuiComboBoxOptionOption,
  EuiFieldText,
  EuiFormRow,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSelect,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { TlsocAlert } from '../../common/alerts';
import { buildCaseFromAlert } from '../../common/cases';

interface Props {
  core: CoreStart;
  alerts: TlsocAlert[];
  onClose: () => void;
  onDone?: () => void;
}

interface CaseOption {
  id: string;
  title: string;
  status: string;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function highestSeverity(alerts: TlsocAlert[]): string {
  let best = 'medium';
  let bestRank = 0;
  for (const a of alerts) {
    const rank = SEV_RANK[a.severityLabel] ?? 0;
    if (rank > bestRank) {
      bestRank = rank;
      best = a.severityLabel;
    }
  }
  return best;
}

export function AddToCaseModal({ core, alerts, onClose, onDone }: Props) {
  const alertIds = alerts.map((a) => a.id);
  const findingIds = Array.from(new Set(alerts.flatMap((a) => a.findingIds ?? [])));

  const defaultTitle = alerts.length > 0 ? buildCaseFromAlert(alerts[0]).title : '';
  const defaultSeverity = highestSeverity(alerts);

  const [mode, setMode] = useState<'existing' | 'new'>('existing');
  const [cases, setCases] = useState<CaseOption[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>('');
  const [newTitle, setNewTitle] = useState<string>(defaultTitle);
  const [newSeverity, setNewSeverity] = useState<string>(defaultSeverity);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    core.http
      .get('/api/tlsoc/cases')
      .then((resp: any) => setCases(resp.cases ?? []))
      .catch(() => setCases([]));
  }, [core]);

  const modeOptions = [
    { id: 'existing', label: 'Existing case' },
    { id: 'new', label: 'New case' },
  ];

  const caseComboOptions: EuiComboBoxOptionOption[] = cases.map((c) => ({
    label: `${c.title} (${c.status})`,
    value: c.id,
  }));

  const selectedComboOptions = selectedCaseId
    ? caseComboOptions.filter((o) => o.value === selectedCaseId)
    : [];

  const isConfirmDisabled =
    busy ||
    (mode === 'existing' && !selectedCaseId) ||
    (mode === 'new' && !newTitle.trim());

  const handleConfirm = async () => {
    setBusy(true);
    try {
      if (mode === 'existing') {
        await core.http.post(`/api/tlsoc/cases/${selectedCaseId}/alerts`, {
          body: JSON.stringify({ alertIds, findingIds }),
        });
        core.notifications.toasts.addSuccess(`${alertIds.length} alert(s) added`);
        core.application.navigateToApp('tlsoc_cases', {
          path: `#/case/${selectedCaseId}`,
        });
        onDone?.();
      } else {
        const input = {
          ...buildCaseFromAlert(alerts[0]),
          title: newTitle,
          severity: newSeverity,
          linkedAlertIds: alertIds,
          linkedFindingIds: findingIds,
        };
        const resp = (await core.http.post('/api/tlsoc/cases', {
          body: JSON.stringify(input),
        })) as any;
        core.notifications.toasts.addSuccess(`${alertIds.length} alert(s) added`);
        core.application.navigateToApp('tlsoc_cases', {
          path: `#/case/${resp.id}`,
        });
        onDone?.();
      }
    } catch (err: any) {
      core.notifications.toasts.addDanger({
        title: 'Could not add to case',
        text: err?.body?.message ?? err?.message ?? 'Failed',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <EuiModal onClose={onClose} style={{ minWidth: 480 }}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>Add {alertIds.length} alert(s) to a case</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiButtonGroup
          legend="Mode"
          options={modeOptions}
          idSelected={mode}
          onChange={(id) => setMode(id as 'existing' | 'new')}
          buttonSize="s"
        />
        <EuiSpacer size="m" />

        {mode === 'existing' ? (
          <EuiFormRow label="Select case">
            <EuiComboBox
              placeholder="Search for a case…"
              singleSelection={{ asPlainText: true }}
              options={caseComboOptions}
              selectedOptions={selectedComboOptions}
              onChange={(opts) => setSelectedCaseId((opts[0]?.value as string) ?? '')}
              isClearable
            />
          </EuiFormRow>
        ) : (
          <>
            <EuiFormRow label="Case title" isInvalid={!newTitle.trim()} error="Title is required">
              <EuiFieldText
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                placeholder="Enter a title for the new case"
              />
            </EuiFormRow>
            <EuiFormRow label="Severity">
              <EuiSelect
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value)}
                options={[
                  { value: 'low', text: 'Low' },
                  { value: 'medium', text: 'Medium' },
                  { value: 'high', text: 'High' },
                  { value: 'critical', text: 'Critical' },
                ]}
              />
            </EuiFormRow>
          </>
        )}

        <EuiSpacer size="s" />
        <EuiText size="s" color="subdued">
          <p>{alertIds.length} alert(s) will be linked.</p>
        </EuiText>
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
        <EuiButton fill isDisabled={isConfirmDisabled} isLoading={busy} onClick={handleConfirm}>
          {mode === 'existing' ? 'Add to case' : 'Create & add'}
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
}
