/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { SavedObjectsType } from '../../../../core/server';

export const CASE_SO_TYPE = 'tlsoc-case';

/**
 * A `tlsoc-case` saved object represents an investigation case in the TLSOC SOC platform (Task 4.3).
 * Cases are seeded from triaged alerts (the alert→case loop-closer) or created manually. The `comments`
 * array is stored verbatim but not indexed (enabled:false) — we never query individual comment fields.
 * `namespaceType:'single'` keeps cases global for v1 (revisit if/when workspaces scope them).
 */
export const caseSavedObjectType: SavedObjectsType = {
  name: CASE_SO_TYPE,
  hidden: false,
  namespaceType: 'single',
  management: {
    defaultSearchField: 'title',
    importableAndExportable: true,
    getTitle(obj) {
      return (obj.attributes as { title?: string }).title ?? obj.id;
    },
  },
  mappings: {
    dynamic: false,
    properties: {
      title: { type: 'keyword' },
      description: { type: 'text' },
      status: { type: 'keyword' },
      severity: { type: 'keyword' },
      assignee: { type: 'keyword' },
      tags: { type: 'keyword' },
      linkedAlertIds: { type: 'keyword' },
      linkedFindingIds: { type: 'keyword' },
      createdFromAlertId: { type: 'keyword' },
      createdAt: { type: 'date' },
      updatedAt: { type: 'date' },
      category: { type: 'keyword' },
      closedAt: { type: 'date' },
      comments: { type: 'object', enabled: false },
      activity: { type: 'object', enabled: false },
    },
  },
};
