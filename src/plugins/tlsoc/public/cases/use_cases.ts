/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useCallback, useEffect, useState } from 'react';
import { CoreStart } from 'opensearch-dashboards/public';
import { CaseStatus, CaseComment, CaseCreateInput, CaseActivity } from '../../common/cases';
import { TlsocAlert } from '../../common/alerts';

export interface CaseRow {
  id: string;
  title: string;
  status: CaseStatus;
  severity: string;
  assignee: string | null;
  tags: string[];
  category?: string;
  closedAt?: string;
  linkedAlertCount: number;
  commentCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface CaseFull {
  id: string;
  title: string;
  description: string;
  status: CaseStatus;
  severity: string;
  assignee: string | null;
  tags: string[];
  category?: string;
  closedAt?: string;
  linkedAlertIds: string[];
  linkedFindingIds: string[];
  createdFromAlertId?: string;
  comments: CaseComment[];
  activity?: CaseActivity[];
  createdAt: string;
  updatedAt: string;
  createdBy?: string;
}

export function useCases(core: CoreStart) {
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = (await core.http.get('/api/tlsoc/cases')) as any;
      setCases(resp?.cases ?? []);
    } catch (e) {
      const err = e as any;
      setError(err?.body?.message ?? err?.message ?? 'Could not load cases');
    } finally {
      setLoading(false);
    }
  }, [core]);

  useEffect(() => {
    reload();
  }, [reload]);

  const createCase = useCallback(
    async (input: CaseCreateInput): Promise<string | null> => {
      try {
        const resp = (await core.http.post('/api/tlsoc/cases', {
          body: JSON.stringify(input),
        })) as any;
        core.notifications.toasts.addSuccess('Case created');
        return resp.id as string;
      } catch (e) {
        const err = e as any;
        core.notifications.toasts.addDanger({
          title: 'Could not create case',
          text: err?.body?.message ?? err?.message ?? 'Failed',
        });
        return null;
      }
    },
    [core]
  );

  const deleteCase = useCallback(
    async (id: string): Promise<void> => {
      try {
        await core.http.delete(`/api/tlsoc/cases/${id}`);
        core.notifications.toasts.addSuccess('Case deleted');
        await reload();
      } catch (e) {
        const err = e as any;
        core.notifications.toasts.addDanger({
          title: 'Could not delete case',
          text: err?.body?.message ?? err?.message ?? 'Failed',
        });
      }
    },
    [core, reload]
  );

  return { cases, loading, error, reload, createCase, deleteCase };
}

export function useCase(core: CoreStart, id: string) {
  const [caseItem, setCaseItem] = useState<CaseFull | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = (await core.http.get(`/api/tlsoc/cases/${id}`)) as any;
      setCaseItem(resp as CaseFull);
    } catch (e) {
      const err = e as any;
      setError(err?.body?.message ?? err?.message ?? 'Could not load case');
    } finally {
      setLoading(false);
    }
  }, [core, id]);

  useEffect(() => {
    reload();
  }, [reload]);

  const updateCase = useCallback(
    async (patch: Record<string, any>): Promise<boolean> => {
      try {
        await core.http.put(`/api/tlsoc/cases/${id}`, {
          body: JSON.stringify(patch),
        });
        core.notifications.toasts.addSuccess('Case updated');
        await reload();
        return true;
      } catch (e) {
        const err = e as any;
        core.notifications.toasts.addDanger({
          title: 'Could not update case',
          text: err?.body?.message ?? err?.message ?? 'Failed',
        });
        return false;
      }
    },
    [core, id, reload]
  );

  const addComment = useCallback(
    async (text: string): Promise<void> => {
      try {
        // No author — the server derives the comment author from the authenticated caller (5a.3).
        await core.http.post(`/api/tlsoc/cases/${id}/comments`, {
          body: JSON.stringify({ text }),
        });
        await reload();
      } catch (e) {
        const err = e as any;
        core.notifications.toasts.addDanger({
          title: 'Could not add comment',
          text: err?.body?.message ?? err?.message ?? 'Failed',
        });
      }
    },
    [core, id, reload]
  );

  return { caseItem, loading, error, reload, updateCase, addComment };
}

export interface HydratedAlert extends TlsocAlert { raw?: any; }

export function useCaseAlerts(core: CoreStart, id: string) {
  const [alerts, setAlerts] = useState<HydratedAlert[]>([]);
  const [missingIds, setMissingIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const resp = (await core.http.get(`/api/tlsoc/cases/${id}/alerts`)) as any;
      setAlerts(resp?.alerts ?? []); setMissingIds(resp?.missingIds ?? []);
    } catch (e) { const err = e as any; setError(err?.body?.message ?? err?.message ?? 'Could not load linked alerts'); }
    finally { setLoading(false); }
  }, [core, id]);
  useEffect(() => { load(); }, [load]);
  return { alerts, missingIds, loading, error, reload: load };
}
