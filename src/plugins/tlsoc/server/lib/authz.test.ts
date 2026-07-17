/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  callerHasAnyRole,
  getCallerBackendRoles,
  isWorkspaceAccessError,
  ROLE_ENGINEER,
  ROLE_L1,
  ROLE_MANAGER,
} from './authz';
import { HttpAuth, OpenSearchDashboardsRequest } from '../../../../core/server';

const request = {} as OpenSearchDashboardsRequest;

const authWith = (status: string, backendRoles?: string[]): HttpAuth =>
  (({
    get: jest.fn().mockReturnValue({
      status,
      state: backendRoles === undefined ? undefined : { authInfo: { backend_roles: backendRoles } },
    }),
    isAuthenticated: jest.fn(),
  } as unknown) as HttpAuth);

describe('getCallerBackendRoles', () => {
  it('returns null (dev-mode allow) when no auth service exists', () => {
    expect(getCallerBackendRoles(request, undefined)).toBeNull();
  });

  it('returns null when no auth scheme is registered (unknown status)', () => {
    expect(getCallerBackendRoles(request, authWith('unknown'))).toBeNull();
  });

  it('returns [] (fail closed) for unauthenticated status', () => {
    expect(getCallerBackendRoles(request, authWith('unauthenticated'))).toEqual([]);
  });

  it('returns the backend roles for an authenticated caller', () => {
    expect(getCallerBackendRoles(request, authWith('authenticated', ['tlsoc_l1']))).toEqual([
      'tlsoc_l1',
    ]);
  });

  it('returns [] (fail closed) when the authenticated state has no roles', () => {
    expect(getCallerBackendRoles(request, authWith('authenticated'))).toEqual([]);
  });

  it('returns [] (fail closed) when auth.get throws', () => {
    const auth = ({ get: jest.fn().mockImplementation(() => { throw new Error('boom'); }) } as unknown) as HttpAuth;
    expect(getCallerBackendRoles(request, auth)).toEqual([]);
  });
});

describe('callerHasAnyRole (the matrix guard)', () => {
  it('allows everything in security-off dev', () => {
    expect(callerHasAnyRole(request, authWith('unknown'), [ROLE_MANAGER])).toBe(true);
  });

  it('always allows the superuser backend role', () => {
    expect(callerHasAnyRole(request, authWith('authenticated', ['admin']), [ROLE_MANAGER])).toBe(true);
  });

  it('allows a caller holding one of the allowed roles', () => {
    expect(callerHasAnyRole(request, authWith('authenticated', ['tlsoc_l1']), [ROLE_L1, ROLE_MANAGER])).toBe(true);
  });

  it('denies a caller whose roles do not intersect the allowed set', () => {
    expect(callerHasAnyRole(request, authWith('authenticated', [ROLE_ENGINEER]), [ROLE_MANAGER])).toBe(false);
  });

  it('denies an authenticated caller with NO recognized role (fail closed)', () => {
    expect(callerHasAnyRole(request, authWith('authenticated', ['some_other_role']), [ROLE_L1])).toBe(false);
    expect(callerHasAnyRole(request, authWith('authenticated', []), [ROLE_L1])).toBe(false);
  });
});

describe('isWorkspaceAccessError', () => {
  it('matches the wrapper bad-request for inaccessible workspaces', () => {
    expect(
      isWorkspaceAccessError({ output: { statusCode: 400 }, message: 'Exist invalid workspaces' })
    ).toBe(true);
  });

  it('does not match other errors', () => {
    expect(isWorkspaceAccessError({ output: { statusCode: 400 }, message: 'other' })).toBe(false);
    expect(isWorkspaceAccessError({ output: { statusCode: 500 }, message: 'Exist invalid workspaces' })).toBe(false);
    expect(isWorkspaceAccessError(new Error('Exist invalid workspaces'))).toBe(false);
  });
});
