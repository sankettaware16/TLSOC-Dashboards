/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../../data/public';
import { DetectionMode, RuleDefinition, ThresholdRuleDefinition } from '../../common/detection';
import { DetectionBuilder } from './detection_builder';
import { SavedRulesList } from './saved_rules_list';

interface Props {
  core: CoreStart;
  data: DataPublicPluginStart;
}

interface EditTarget {
  soId: string;
  mode: DetectionMode;
  rule: RuleDefinition | ThresholdRuleDefinition;
}

/**
 * The "Detections" app: a saved-rules LIST as the landing view, with the no-code builder as a
 * create/edit sub-view (Task 3.5c). Edit hydrates the builder from the saved object's stored rule
 * (the lossless IR round-trip) — no reverse-engineering of the compiled monitor.
 */
export function DetectionsApp({ core, data }: Props) {
  const [view, setView] = useState<'list' | 'builder'>('list');
  const [editTarget, setEditTarget] = useState<EditTarget | null>(null);

  const openCreate = () => {
    setEditTarget(null);
    setView('builder');
  };

  const openEdit = async (soId: string) => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const resp = (await core.http.get(`/api/tlsoc/detection/monitors/${soId}`)) as any;
      setEditTarget({ soId, mode: resp.mode, rule: resp.rule });
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
    setView('list');
  };

  if (view === 'builder') {
    // key forces a fresh builder per create/edit so its state seeds from the right rule.
    return (
      <DetectionBuilder
        key={editTarget?.soId ?? 'create'}
        core={core}
        data={data}
        editSoId={editTarget?.soId}
        initialMode={editTarget?.mode}
        initialRule={editTarget?.rule}
        onDone={backToList}
      />
    );
  }

  return <SavedRulesList core={core} onCreate={openCreate} onEdit={openEdit} />;
}
