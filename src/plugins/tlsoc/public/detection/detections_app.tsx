/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { EuiTab, EuiTabs } from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../../data/public';
import {
  DetectionMode,
  IndicatorMatchRuleDefinition,
  NewTermsRuleDefinition,
  PplRuleDefinition,
  RuleDefinition,
  ThresholdRuleDefinition,
} from '../../common/detection';
import type { CustomQueryRuleDefinition } from '../../common/detection/custom_query';
import { CoverageMatrix } from './coverage_matrix';
import { DetectionBuilder } from './detection_builder';
import { SavedRulesList } from './saved_rules_list';
import { SigmaImportModal } from './sigma_import_modal';
import { StarterPackModal } from './starter_pack_modal';

interface Props {
  core: CoreStart;
  data: DataPublicPluginStart;
}

/** The full rule union — every shape the builder's `initialRule` accepts (all six modes). */
type AnyRuleDefinition =
  | RuleDefinition
  | ThresholdRuleDefinition
  | PplRuleDefinition
  | CustomQueryRuleDefinition
  | NewTermsRuleDefinition
  | IndicatorMatchRuleDefinition;

interface EditTarget {
  soId: string;
  mode: DetectionMode;
  rule: AnyRuleDefinition;
  enabled: boolean;
}

/**
 * A rule successfully parsed by {@link SigmaImportModal}, awaiting the builder to open it.
 * `rule` is the FULL union (v1.2.3 W4 integration): the modal's native-JSON tab can carry ANY
 * registered mode, not just the two Sigma-importable ones.
 */
interface ImportTarget {
  mode: DetectionMode;
  rule: AnyRuleDefinition;
  warnings: string[];
}

/**
 * The "Detections" app: a saved-rules LIST as the landing view, with the no-code builder as a
 * create/edit sub-view (Task 3.5c). Edit hydrates the builder from the saved object's stored rule
 * (the lossless IR round-trip) — no reverse-engineering of the compiled monitor.
 *
 * v1.2.3 D10: the landing view gains tabs — `Rules | ATT&CK coverage` (state-based, the app has
 * no router) — plus the starter-pack install modal. Clicking a covered technique cell in the
 * matrix selects that technique and switches to the Rules tab (the list-side filter wiring is
 * W4a's `techniqueFilter` prop — passed loosely below until the list grows it).
 */
export function DetectionsApp({ core, data }: Props) {
  const [view, setView] = useState<'list' | 'builder'>('list');
  const [tab, setTab] = useState<'rules' | 'coverage'>('rules');
  const [editTarget, setEditTarget] = useState<EditTarget | null>(null);
  const [importTarget, setImportTarget] = useState<ImportTarget | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [showStarterPack, setShowStarterPack] = useState(false);
  // Bumped when the starter pack installed rules, so the list remounts and reloads.
  const [listRefresh, setListRefresh] = useState(0);
  // The technique picked in the coverage matrix (null = no selection).
  const [techniqueFilter, setTechniqueFilter] = useState<string | null>(null);
  // Bumped on every import so the builder remounts (key) instead of reusing stale state.
  const [importCounter, setImportCounter] = useState(0);

  const openCreate = () => {
    setEditTarget(null);
    setImportTarget(null);
    setView('builder');
  };

  const openEdit = async (soId: string) => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const resp = (await core.http.get(`/api/tlsoc/detection/monitors/${soId}`)) as any;
      setEditTarget({ soId, mode: resp.mode, rule: resp.rule, enabled: resp.enabled ?? true });
      setImportTarget(null);
      setView('builder');
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const err = e as any;
      core.notifications.toasts.addDanger({
        title: 'Could not open detection',
        text: err?.body?.message ?? err?.message ?? 'Failed to load the saved rule',
      });
    }
  };

  const backToList = () => {
    setEditTarget(null);
    setImportTarget(null);
    setView('list');
  };

  if (view === 'builder') {
    // key forces a fresh builder per create/edit/import so its state seeds from the right rule.
    const key = editTarget?.soId ?? (importTarget ? `import-${importCounter}` : 'create');
    return (
      <DetectionBuilder
        key={key}
        core={core}
        data={data}
        editSoId={editTarget?.soId}
        initialMode={editTarget?.mode ?? importTarget?.mode}
        initialRule={editTarget?.rule ?? importTarget?.rule}
        initialEnabled={editTarget?.enabled}
        importWarnings={importTarget?.warnings}
        onDone={backToList}
      />
    );
  }

  return (
    <>
      <div style={{ margin: '16px 24px 0' }}>
        <EuiTabs>
          <EuiTab isSelected={tab === 'rules'} onClick={() => setTab('rules')}>
            Rules
          </EuiTab>
          <EuiTab isSelected={tab === 'coverage'} onClick={() => setTab('coverage')}>
            ATT&amp;CK coverage
          </EuiTab>
        </EuiTabs>
      </div>
      {tab === 'coverage' ? (
        <CoverageMatrix
          core={core}
          onSelectTechnique={(id) => {
            setTechniqueFilter(id);
            setTab('rules');
          }}
        />
      ) : (
        // W4 integration: the technique filter / starter-pack wiring is now TYPED — the list
        // grew the real props (techniqueFilter narrows its rows and renders the clearable chip,
        // so the interim "Technique X selected" callout here is gone).
        <SavedRulesList
          key={`list-${listRefresh}`}
          core={core}
          onCreate={openCreate}
          onEdit={openEdit}
          onImport={() => setShowImport(true)}
          onInstallPack={() => setShowStarterPack(true)}
          techniqueFilter={techniqueFilter}
          onTechniqueFilterChange={setTechniqueFilter}
        />
      )}
      {showStarterPack ? (
        <StarterPackModal
          core={core}
          onClose={() => setShowStarterPack(false)}
          onInstalled={() => setListRefresh((c) => c + 1)}
        />
      ) : null}
      {showImport ? (
        <SigmaImportModal
          onParsed={(r) => {
            setImportTarget({ mode: r.mode, rule: r.rule, warnings: r.warnings });
            setImportCounter((c) => c + 1);
            setEditTarget(null);
            setShowImport(false);
            setView('builder');
          }}
          onClose={() => setShowImport(false)}
        />
      ) : null}
    </>
  );
}
