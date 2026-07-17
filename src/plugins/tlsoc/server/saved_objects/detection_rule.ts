/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { SavedObjectsType } from '../../../../core/server';

/** The saved-object type that stores a no-code detection rule (Task 3.5a). */
export const DETECTION_RULE_SO_TYPE = 'tlsoc-detection-rule';

/**
 * A `tlsoc-detection-rule` saved object is the editable record + registry of detections TLSOC
 * created. The OpenSearch Alerting monitor (linked by `monitorId`) executes the rule; this object
 * holds the exact no-code IR (`rule`) so the builder can re-open it losslessly for edit (Task 3.5b).
 * We store it here because OS 3.7 Alerting strips `ui_metadata` from a monitor on persist.
 *
 * `rule` is `enabled:false` — stored verbatim but not indexed (we never query its internals).
 * `namespaceType:'single'` keeps detections global for v1 (revisit if/when workspaces scope them).
 */
export const detectionRuleSavedObjectType: SavedObjectsType = {
  name: DETECTION_RULE_SO_TYPE,
  hidden: false,
  namespaceType: 'single',
  management: {
    defaultSearchField: 'name',
    importableAndExportable: true,
    getTitle(obj) {
      return (obj.attributes as { name?: string }).name ?? obj.id;
    },
  },
  mappings: {
    dynamic: false,
    properties: {
      name: { type: 'keyword' },
      mode: { type: 'keyword' },
      severity: { type: 'keyword' },
      monitorId: { type: 'keyword' },
      createdAt: { type: 'date' },
      rule: { type: 'object', enabled: false },
    },
  },
};
