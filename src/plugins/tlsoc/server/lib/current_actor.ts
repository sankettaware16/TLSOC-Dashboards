/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { HttpAuth, OpenSearchDashboardsRequest } from '../../../../core/server';
import { getPrincipalsFromRequest } from '../../../../core/server/utils';

/**
 * The actor recorded when no authenticated identity is available — the exact value every case
 * mutation used before Phase 5a, so security-off dev boots behave identically.
 */
export const FALLBACK_ACTOR = 'analyst';

/**
 * Resolve the calling user's identity for TLSOC audit fields (Task 5a.2 — the 5a seam).
 *
 * Wraps core's `getPrincipalsFromRequest` (the same primitive the workspace permission control
 * uses): when the vendored security-dashboards-plugin has authenticated the request, its auth
 * state carries `authInfo.user_name` (and `backend_roles`; there is no `user_id` in the
 * OpenSearch Security shape) and this returns that username. In every other situation —
 * auth status `unknown` (no auth registered: security-off dev), `unauthenticated`, a missing
 * `auth` service, or any unexpected state — it falls back to {@link FALLBACK_ACTOR} rather than
 * throwing, because audit attribution must never break a case mutation.
 */
export function getCurrentActor(
  request: OpenSearchDashboardsRequest,
  auth?: HttpAuth
): string {
  try {
    const principals = getPrincipalsFromRequest(request, auth);
    const users = principals.users ?? [];
    return users.length > 0 && users[0] ? users[0] : FALLBACK_ACTOR;
  } catch (err) {
    return FALLBACK_ACTOR;
  }
}
