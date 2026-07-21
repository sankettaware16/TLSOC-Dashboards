/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFieldText,
  EuiFormRow,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { MitreCatalogLookup, parseSigmaImport } from '../../common/detection';
import { PACK_DEFAULT_INDEX, PackRule, STARTER_PACK } from '../../common/detection/starter_pack';
import { findUiType } from './type_registry';

interface Props {
  core: CoreStart;
  onClose: () => void;
  /** Called once after an install run that created at least one rule — reload the list. */
  onInstalled?: () => void;
}

type InstallState = 'pending' | 'installing' | 'installed' | 'skipped' | 'failed';

interface RuleStatus {
  state: InstallState;
  /** Failure detail, shown verbatim — per-rule failures are surfaced honestly, never rolled up. */
  detail?: string;
}

/**
 * The starter-pack install modal (v1.2.3 D10) — previews the 10 bundled rules, lets the user
 * REBIND one index/data-view pattern for all of them, then installs each through the EXISTING
 * import + create paths: Sigma rules are parsed client-side by `parseSigmaImport` (the
 * sigma_import_modal precedent, MITRE catalog via async import — never static, it's a ~200 KB
 * chunk), native rules POST their bundled `{mode, rule}` directly. Everything installs with
 * `enabled: false` (safe/quiet by default); a 409 name conflict means "already installed" and is
 * skipped idempotently (PROB-25 summary-toast idiom: one toast, per-rule detail in the table).
 */
export function StarterPackModal({ core, onClose, onInstalled }: Props) {
  const [indexPattern, setIndexPattern] = useState(PACK_DEFAULT_INDEX);
  const [installing, setInstalling] = useState(false);
  const [ran, setRan] = useState(false);
  const [statuses, setStatuses] = useState<Record<string, RuleStatus>>({});

  const setStatus = (id: string, status: RuleStatus) =>
    setStatuses((prev) => ({ ...prev, [id]: status }));

  const install = async () => {
    const pattern = indexPattern.trim();
    if (!pattern) return;
    setInstalling(true);
    setStatuses({});

    // The MITRE catalog resolves attack.* tags to rule.threat. Optional — the importer degrades
    // to unresolved-tag warnings without it — so a chunk-load failure must not block the install.
    let catalog: MitreCatalogLookup | undefined;
    try {
      catalog = ((await import('../../common/mitre'))
        .ATTACK_CATALOG as unknown) as MitreCatalogLookup;
    } catch {
      catalog = undefined;
    }

    let installed = 0;
    let skipped = 0;
    let failed = 0;

    for (const pack of STARTER_PACK) {
      setStatus(pack.id, { state: 'installing' });

      let mode: string;
      let rule: Record<string, unknown>;
      if (pack.kind === 'sigma') {
        const parsed = parseSigmaImport(pack.yaml!, { catalog });
        if (!parsed.ok) {
          // Should be impossible while the pack invariant test is green — surface it by name.
          failed += 1;
          setStatus(pack.id, {
            state: 'failed',
            detail: parsed.errors.map((e) => `${e.construct}: ${e.reason}`).join('; '),
          });
          continue;
        }
        mode = parsed.mode;
        rule = (parsed.rule as unknown) as Record<string, unknown>;
      } else {
        mode = pack.native!.mode;
        // Deep-copy so a re-run after a failure never mutates the bundled pack object.
        rule = JSON.parse(JSON.stringify(pack.native!.rule)) as Record<string, unknown>;
      }

      // THE REBIND: one user-chosen pattern applied to every rule (bundled index = hint only).
      rule.index = pattern;

      try {
        await core.http.post('/api/tlsoc/detection/monitors', {
          // enabled:false — installing content must never start scanning without an explicit
          // analyst decision (safe/quiet by default, research_r6 §C3).
          body: JSON.stringify({ mode, rule, enabled: false }),
        });
        installed += 1;
        setStatus(pack.id, { state: 'installed' });
      } catch (e) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const err = e as any;
        const statusCode = err?.response?.status ?? err?.body?.statusCode;
        if (statusCode === 409) {
          // Name conflict = already installed (the create route dedups by rule name) — the
          // idempotent skip that makes "Install starter pack" safe to click twice.
          skipped += 1;
          setStatus(pack.id, { state: 'skipped' });
        } else {
          failed += 1;
          setStatus(pack.id, {
            state: 'failed',
            detail: err?.body?.message ?? err?.message ?? 'Failed',
          });
        }
      }
    }

    // PROB-25 idiom: ONE summary toast, whatever happened per rule.
    const summary = `Installed ${installed} · already present ${skipped} · failed ${failed}`;
    if (failed > 0) {
      core.notifications.toasts.addDanger({ title: 'Starter pack: some rules failed', text: summary });
    } else if (installed > 0) {
      core.notifications.toasts.addSuccess({ title: 'Starter pack installed', text: summary });
    } else {
      core.notifications.toasts.addInfo({ title: 'Starter pack already installed', text: summary });
    }

    setInstalling(false);
    setRan(true);
    if (installed > 0 && onInstalled) onInstalled();
  };

  const columns: Array<EuiBasicTableColumn<PackRule>> = [
    { field: 'title', name: 'Rule', truncateText: true },
    {
      field: 'expectedMode',
      name: 'Type',
      width: '140px',
      render: (m: string) => {
        const badge = findUiType(m)?.listBadge;
        return <EuiBadge color={badge?.color ?? 'hollow'}>{badge?.label ?? m}</EuiBadge>;
      },
    },
    {
      field: 'mitre',
      name: 'MITRE ATT&CK',
      width: '180px',
      render: (ids: string[]) => (
        <>
          {ids.map((id) => (
            <EuiBadge key={id} color="hollow">
              {id}
            </EuiBadge>
          ))}
        </>
      ),
    },
    {
      name: 'Status',
      width: '200px',
      render: (pack: PackRule) => {
        const status = statuses[pack.id];
        if (!status) return <EuiText size="xs" color="subdued">—</EuiText>;
        switch (status.state) {
          case 'installing':
            return <EuiBadge color="default">Installing…</EuiBadge>;
          case 'installed':
            return <EuiBadge color="success">Installed (disabled)</EuiBadge>;
          case 'skipped':
            return <EuiBadge color="default">Already present</EuiBadge>;
          case 'failed':
            return (
              <EuiText size="xs" color="danger">
                Failed: {status.detail}
              </EuiText>
            );
          default:
            return <EuiText size="xs" color="subdued">—</EuiText>;
        }
      },
    },
  ];

  return (
    <EuiModal onClose={onClose} style={{ minWidth: 760 }}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>Install starter pack</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiText size="s">
          <p>
            10 curated detections for a campus SOC (SSH brute force, web scanning, WAF/IDS
            bursts, DNS anomalies…). All rules install <strong>disabled</strong> — review each
            one, then enable it from the list. Rules that already exist (by name) are skipped.
          </p>
        </EuiText>
        <EuiSpacer size="m" />
        <EuiFormRow
          label="Index pattern for all rules"
          helpText={
            'Applied to every rule in the pack. The rules reference ECS field names (e.g. ' +
            'source.ip, url.path, user_agent.original.keyword) — bind them to a data view with ' +
            'those mappings, such as the TLSOC sample security data or your ECS log pipeline.'
          }
        >
          <EuiFieldText
            value={indexPattern}
            onChange={(e) => setIndexPattern(e.target.value)}
            disabled={installing}
            placeholder={PACK_DEFAULT_INDEX}
          />
        </EuiFormRow>
        <EuiSpacer size="m" />
        <EuiBasicTable items={[...STARTER_PACK]} columns={columns} rowHeader="title" />
        {ran ? (
          <>
            <EuiSpacer size="m" />
            <EuiCallOut
              size="s"
              color="primary"
              iconType="iInCircle"
              title="Rules install disabled — enable the ones you want from the Detections list."
            />
          </>
        ) : null}
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose} isDisabled={installing}>
          {ran ? 'Close' : 'Cancel'}
        </EuiButtonEmpty>
        <EuiButton
          fill
          onClick={install}
          isLoading={installing}
          isDisabled={installing || !indexPattern.trim()}
        >
          {ran ? 'Run again' : 'Install 10 rules'}
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
}
