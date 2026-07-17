/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The TLSOC user directory (Task 5b.4a): a single, global, hidden saved object caching the
 * assignable SOC users. WHY IT EXISTS: the security internal-users API is admin-gated, so a
 * manager's assignee picker came back empty once the fixtures lost all_access (5b.3b). Admin
 * requests refresh this cache from the live API; everyone else reads the cache. It is the
 * interim answer until 5b.4b provisions users through TLSOC itself (which will write this
 * directory directly).
 *
 * hidden:true keeps it out of Saved Objects management and import/export;
 * namespaceType:'agnostic' + the workspace_id_consumer exclusion in the users route keep it
 * a single GLOBAL doc rather than one per workspace.
 */

import { SavedObjectsType } from '../../../../core/server';

export const USER_DIRECTORY_SO_TYPE = 'tlsoc-user-directory';
export const USER_DIRECTORY_SO_ID = 'directory';

export const userDirectorySavedObjectType: SavedObjectsType = {
  name: USER_DIRECTORY_SO_TYPE,
  hidden: true,
  namespaceType: 'agnostic',
  mappings: {
    dynamic: false,
    properties: {
      updatedAt: { type: 'date' },
      users: { type: 'object', enabled: false },
    },
  },
};
