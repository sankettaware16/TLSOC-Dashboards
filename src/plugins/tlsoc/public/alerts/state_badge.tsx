/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { EuiBadge, EuiToolTip } from '@elastic/eui';
import { TlsocAlert } from '../../common/alerts';
import { stateColor } from './format';

// Shared by the Alerts page and the case Alerts tab; the tooltip shows the real engine state (PROB-29).
export function AlertStateBadge({ alert }: { alert: TlsocAlert }) {
  if (alert.reopenedFromCase) {
    return (
      <EuiToolTip
        content={`Engine state: ${alert.state}. Reactivated by reopening case "${alert.reopenedFromCase.caseName}".`}
      >
        <EuiBadge color="accent" iconType="refresh">
          Reopened · {alert.reopenedFromCase.caseName}
        </EuiBadge>
      </EuiToolTip>
    );
  }
  return <EuiBadge color={stateColor(alert.state)}>{alert.state}</EuiBadge>;
}
