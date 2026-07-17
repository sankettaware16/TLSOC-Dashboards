/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TLSOC per-role route authorization (Task 5b.3c) — the product-level enforcement of the
 * human-approved role matrix, on top of the engine-level RBAC from 5b.3b.
 *
 * Roles are the caller's BACKEND ROLES read from the cached auth state — deliberately NOT
 * `attributes.tlsoc_role`: attribute VALUES never reach the auth state (the security plugin's
 * authinfo carries only attribute NAMES), while backend_roles are cached per-request AND are
 * the same key the engine role mappings use (single source of truth, zero extra round-trips).
 *
 * Fail-closed on writes: an authenticated user with no recognized TLSOC backend role is
 * read-only. Security-off dev (`unknown` auth status, no registered scheme) allows everything —
 * the same philosophy as getCurrentActor's 'analyst' fallback: local dev must never brick.
 */

import {
  HttpAuth,
  OpenSearchDashboardsRequest,
  OpenSearchDashboardsResponseFactory,
} from '../../../../core/server';

/** The superuser backend role — tlsoc-super and the cluster admin carry it. Always allowed. */
export const ROLE_SUPER = 'admin';
export const ROLE_L1 = 'tlsoc_l1';
export const ROLE_MANAGER = 'tlsoc_manager';
export const ROLE_ENGINEER = 'tlsoc_engineer';

/** Convenience tiers matching the approved matrix. */
export const CASE_WRITERS = [ROLE_L1, ROLE_MANAGER, ROLE_ENGINEER];
export const CASE_STATUS_CHANGERS = [ROLE_L1, ROLE_MANAGER];
export const CASE_ADMINS = [ROLE_MANAGER];
export const DETECTION_WRITERS = [ROLE_ENGINEER];
export const ALERT_ACKNOWLEDGERS = [ROLE_L1, ROLE_MANAGER];

interface AuthStateWithInfo {
  authInfo?: {
    backend_roles?: string[];
  };
}

/**
 * The caller's backend roles from the cached auth state.
 * Returns `null` when no auth scheme is registered (security-off dev) — callers must treat
 * null as allow-all. Returns `[]` for authenticated users whose state carries no roles
 * (fail closed).
 */
export function getCallerBackendRoles(
  request: OpenSearchDashboardsRequest,
  auth?: HttpAuth
): string[] | null {
  if (!auth) return null;
  try {
    const { status, state } = auth.get<AuthStateWithInfo>(request);
    if (status === 'unknown') return null;
    if (status !== 'authenticated') return [];
    return state?.authInfo?.backend_roles ?? [];
  } catch (e) {
    return [];
  }
}

/** True when the caller holds the superuser role or any of the allowed roles (or dev mode). */
export function callerHasAnyRole(
  request: OpenSearchDashboardsRequest,
  auth: HttpAuth | undefined,
  allowed: string[]
): boolean {
  const roles = getCallerBackendRoles(request, auth);
  if (roles === null) return true;
  if (roles.includes(ROLE_SUPER)) return true;
  return allowed.some((role) => roles.includes(role));
}

/** The standard clean 403 for a matrix denial. */
export function forbidden(response: OpenSearchDashboardsResponseFactory, action: string) {
  return response.forbidden({
    body: {
      message: `Your role does not allow this action: ${action}. Ask a SOC manager or your administrator.`,
    },
  });
}

/**
 * The workspace wrapper rejects requests scoped to a workspace the caller cannot access with a
 * bad-request "Exist invalid workspaces" (WorkspaceIdConsumerWrapper.checkWorkspacesExist).
 * Surfacing that as a 500 is wrong — it is an access denial. Detect it so route catch blocks
 * can answer with a clean 403 instead.
 */
export function isWorkspaceAccessError(e: unknown): boolean {
  const err = e as { output?: { statusCode?: number }; message?: unknown };
  return (
    err?.output?.statusCode === 400 &&
    typeof err?.message === 'string' &&
    err.message.includes('Exist invalid workspaces')
  );
}

/** The standard clean 403 for a workspace-membership denial. */
export function workspaceForbidden(response: OpenSearchDashboardsResponseFactory) {
  return response.forbidden({
    body: { message: 'You do not have access to this workspace.' },
  });
}
