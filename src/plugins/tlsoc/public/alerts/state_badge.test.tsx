/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { mount } from 'enzyme';
import { normalizeAlert } from '../../common/alerts';
import { AlertStateBadge } from './state_badge';

const alert = (state: string) => normalizeAlert({ id: 'a1', monitor_id: 'm1', state }, {});

describe('AlertStateBadge', () => {
  it('shows the honest engine state for a plain alert', () => {
    expect(mount(<AlertStateBadge alert={alert('ACKNOWLEDGED')} />).text()).toBe('ACKNOWLEDGED');
  });

  it('shows "Reopened · <case>" for an alert carrying a reopen override (PROB-29)', () => {
    const reopened = {
      ...alert('ACKNOWLEDGED'),
      reopenedFromCase: { caseId: 'c1', caseName: 'Brute force', reopenedAt: 't' },
    };
    expect(mount(<AlertStateBadge alert={reopened} />).text()).toBe('Reopened · Brute force');
  });
});
