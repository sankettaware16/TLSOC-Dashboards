/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useEffect, useState } from 'react';
import { CoreStart } from 'opensearch-dashboards/public';
import { TlsocAlert } from '../../common/alerts';

/** One doc fetched via POST /api/tlsoc/alerts/_related_docs. */
export interface RelatedDoc {
  id: string;
  index: string;
  found: boolean;
  source?: Record<string, unknown>;
}

/** The flyout only ever needs the first few docs to build the reason sentence + event context. */
const MAX_RELATED_DOCS = 5;

/**
 * Lazily fetch the source docs behind an alert's `relatedDocIds` when the alert flyout opens
 * (WS-1, PROB-1). Keyed on the alert id — reruns only when a DIFFERENT alert is selected, not on
 * every re-render. Bucket-level alerts (a threshold alert with `bucketKeys`, no single triggering
 * doc) and alerts with no related docs skip the fetch entirely.
 */
export function useRelatedDocs(core: CoreStart, alert: TlsocAlert | null) {
  const [docs, setDocs] = useState<RelatedDoc[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDocs([]);
    setError(null);
    setLoading(false);
    if (!alert) return;
    // Bucket-level alerts carry group-by keys, not a single source document — nothing to fetch.
    if (alert.bucketKeys && alert.bucketKeys.length > 0) return;
    const ids = (alert.relatedDocIds ?? []).slice(0, MAX_RELATED_DOCS);
    if (ids.length === 0) return;

    let active = true;
    setLoading(true);
    core.http
      .post('/api/tlsoc/alerts/_related_docs', { body: JSON.stringify({ ids }) })
      .then((resp: any) => {
        if (active) setDocs(resp?.docs ?? []);
      })
      .catch((e: any) => {
        if (active) setError(e?.body?.message ?? e?.message ?? 'Could not load related documents');
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
    // Keyed on the alert id (per the flyout contract) — re-fetches only for a NEWLY selected alert.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [core, alert?.id]);

  return { docs, loading, error };
}
