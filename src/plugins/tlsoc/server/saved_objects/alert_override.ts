/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { SavedObjectsType } from '../../../../core/server';

/** The saved-object type that records a TLSOC display override reopening a case's alert (PROB-29). */
export const ALERT_OVERRIDE_SO_TYPE = 'tlsoc-alert-override';

/**
 * A `tlsoc-alert-override` saved object is TLSOC's HONEST display override for an alert whose case
 * was reopened (PROB-29 Option B). The OpenSearch Alerting engine has NO un-acknowledge API and its
 * `.opendistro-alerting-*` indices are protected, so when an analyst reopens a Closed case we cannot
 * flip the linked alerts back to ACTIVE on the engine. Instead we store this TLSOC-owned override
 * (id = the alert id) and MERGE it at display time: an alert the engine still reports ACKNOWLEDGED
 * is shown as reactivated (a "Reopened · <case>" badge, included by the Active filter) while its real
 * engine state stays visible and untouched. The override is deleted when the analyst acknowledges the
 * alert again, when the case is re-closed, or lazily when the engine finally COMPLETES the alert.
 *
 * All fields are simple keyword/date; `dynamic:false` (zero-migration idiom, same as case/detection-rule).
 * `namespaceType:'single'` keeps overrides in the same workspace scope as the `tlsoc-case` they mirror.
 */
export const alertOverrideSavedObjectType: SavedObjectsType = {
  name: ALERT_OVERRIDE_SO_TYPE,
  hidden: false,
  namespaceType: 'single',
  mappings: {
    dynamic: false,
    properties: {
      alertId: { type: 'keyword' },
      caseId: { type: 'keyword' },
      caseName: { type: 'keyword' },
      monitorId: { type: 'keyword' },
      reopenedAt: { type: 'date' },
      reopenedBy: { type: 'keyword' },
    },
  },
};
