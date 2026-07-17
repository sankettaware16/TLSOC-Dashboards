/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { IRouter, Logger, SavedObjectsServiceStart } from '../../../../core/server';
import { assignableUsersFromInternal, AssignableUser } from '../../common/users/assignable';
import { USER_DIRECTORY_SO_ID, USER_DIRECTORY_SO_TYPE } from '../saved_objects/user_directory';

/**
 * The TLSOC users route (Tasks 5a.4 + 5b.4a) — the source for the real-user assignee picker.
 *
 * 5b.4a flow: callers who may read the security internal-users API (admins) get the LIVE list —
 * filtered by the assignable-user governance rule (`attributes.tlsoc_role` present; demo service
 * accounts excluded) — and the result is written to the global tlsoc-user-directory cache.
 * Everyone else (manager/l1/engineer — the API is admin-gated) gets the CACHED directory, so the
 * picker works for every SOC role without granting anyone the security REST API. Degrades to []
 * only when security is off or the cache has never been primed. 5b.4b replaces the priming with
 * real TLSOC user provisioning.
 */
export function registerUserRoutes(
  router: IRouter,
  logger: Logger,
  getSavedObjects?: () => Promise<SavedObjectsServiceStart>
) {
  router.get(
    { path: '/api/tlsoc/users', validate: false },
    async (context, request, response) => {
      // The directory client: workspace-id injection excluded so the cache is ONE global doc
      // (not one per workspace); hidden type opted in.
      const directoryClient = getSavedObjects
        ? (await getSavedObjects()).getScopedClient(request, {
            includedHiddenTypes: [USER_DIRECTORY_SO_TYPE],
            excludedWrappers: ['workspace_id_consumer'],
          })
        : undefined;

      try {
        const esClient = context.core.opensearch.client.asCurrentUser;
        const resp = await esClient.transport.request({
          method: 'GET',
          path: '/_plugins/_security/api/internalusers',
        });
        const users = assignableUsersFromInternal((resp as any).body ?? {});
        if (directoryClient) {
          try {
            await directoryClient.create(
              USER_DIRECTORY_SO_TYPE,
              { users, updatedAt: new Date().toISOString() },
              { id: USER_DIRECTORY_SO_ID, overwrite: true }
            );
          } catch (cacheErr) {
            logger.warn(`tlsoc user directory refresh failed: ${cacheErr.message}`);
          }
        }
        return response.ok({ body: { users, source: 'live' } });
      } catch (err) {
        // Admin-gated API denied this caller (or security is off) → serve the cached directory.
        if (directoryClient) {
          try {
            const cached = await directoryClient.get<{ users: AssignableUser[] }>(
              USER_DIRECTORY_SO_TYPE,
              USER_DIRECTORY_SO_ID
            );
            return response.ok({
              body: { users: cached.attributes.users ?? [], source: 'cache' },
            });
          } catch (cacheErr) {
            logger.warn(`tlsoc users cache unavailable: ${cacheErr.message}`);
          }
        }
        logger.warn(`tlsoc users list unavailable: ${err.message}`);
        return response.ok({ body: { users: [], source: 'none' } });
      }
    }
  );
}
