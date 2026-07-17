/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { EuiSwitch, EuiToolTip } from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DetectionMode } from '../../common/detection';

interface Props {
  core: CoreStart;
  soId: string;
  mode: DetectionMode;
  enabled: boolean;
  /** Called with the new state once the toggle round-trip succeeds. */
  onChanged: (enabled: boolean) => void;
}

/**
 * Compressed enable/disable switch for one saved detection (PROB-19). Pure presentational — it
 * owns only its own in-flight/loading state and reports success back via `onChanged`; wiring it
 * into the saved-rules list or builder is the caller's job.
 *
 * Stateless rules keep their doc-level monitor's scan checkpoint across a disable (OpenSearch
 * Alerting does not clear it), so re-enabling one evaluates everything indexed while it was off —
 * flagged with a tooltip only while the switch is OFF, so it doesn't clutter the common case.
 */
export function EnabledToggle({ core, soId, mode, enabled, onChanged }: Props) {
  const [loading, setLoading] = useState(false);

  const toggle = async () => {
    const next = !enabled;
    setLoading(true);
    try {
      await core.http.post(`/api/tlsoc/detection/monitors/${soId}/_toggle`, {
        body: JSON.stringify({ enabled: next }),
      });
      onChanged(next);
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const err = e as any;
      core.notifications.toasts.addDanger({
        title: `Could not ${next ? 'enable' : 'disable'} detection`,
        text: err?.body?.message ?? err?.message ?? 'The toggle failed.',
      });
    } finally {
      setLoading(false);
    }
  };

  const switchEl = (
    <EuiSwitch
      compressed
      showLabel={false}
      label=""
      aria-label="Enable or disable this detection"
      checked={enabled}
      disabled={loading}
      onChange={toggle}
    />
  );

  if (mode === 'stateless' && !enabled) {
    return (
      <EuiToolTip content="Events indexed while this rule was off will be evaluated when it resumes.">
        {switchEl}
      </EuiToolTip>
    );
  }
  return switchEl;
}
