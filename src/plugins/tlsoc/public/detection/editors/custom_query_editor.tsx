/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useMemo, useState } from 'react';
import {
  EuiCallOut,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../../../data/public';
import { doesKueryExpressionHaveLuceneSyntaxError } from '../../../../data/common';
import {
  formatDqlTranslationErrors,
  translateDqlToLucene,
} from '../../../common/detection/dql_to_lucene';
import type { CustomQueryLanguage } from '../../../common/detection/custom_query';
import type { QueryValidationState, RuleEditorProps } from '../type_registry';

/**
 * The 'custom_query' per-type editor (v1.2.3 D2): the analyst writes the match as a DQL or Lucene
 * query instead of no-code condition rows. The input is `data.ui.SearchBar` — the STATEFUL,
 * pre-wired variant tlsoc already embeds in investigation_tab.tsx (core/data/storage come baked
 * in; DQL autocomplete and the DQL↔Lucene language switcher come free). The bare QueryStringInput
 * needs an OpenSearchDashboardsContextProvider the tlsoc app doesn't mount (research_r3 §3).
 *
 * Validation is two-layered (research_r3 §5):
 *  1. CLIENT, instant, DQL only: fromKueryExpression via the shared subset translator (syntax
 *     errors with caret position + reject-by-name subset errors — the exact strings compile
 *     throws), plus the "this looks like Lucene" hint.
 *  2. SERVER, on blur/submit, both languages: POST /api/tlsoc/detection/_validate proxies the
 *     cluster's own parser — the Alerting engine NEVER validates doc-level queries, so an
 *     unvalidated typo would be a silently dead rule (research_r2 §b). The BUILDER owns this
 *     verdict (v1.2.3 W2 review, BLOCKING-2 — Save is gated on it, and the save route
 *     re-validates server-side regardless); this editor only *requests* a run (`onQueryValidate`
 *     on blur/submit) and *renders* the threaded-in `queryCheck` state.
 *
 * PROP THREADING: RuleEditorProps is the D1 v1 contract (the two no-code editors' superset) and
 * does not carry core/data/query state. Every extra prop below is OPTIONAL so this component
 * remains a valid registry `ComponentType<RuleEditorProps>`; until the builder threads them
 * (serial integration) the editor renders an explicit "integration pending" callout instead of
 * crashing. The exact threading required is listed in the D2 integration notes.
 */
export interface CustomQueryEditorProps extends RuleEditorProps {
  core?: CoreStart;
  data?: DataPublicPluginStart;
  /** The selected data view's id — resolved to the data-view object for SearchBar suggestions. */
  dataViewId?: string;
  /** The selected data view's index pattern (rule.index) — what the server validates against. */
  indexPattern?: string;
  queryText?: string;
  queryLanguage?: CustomQueryLanguage;
  onQueryTextChange?: (queryText: string) => void;
  onQueryLanguageChange?: (language: CustomQueryLanguage) => void;
}

export function CustomQueryEditor(props: CustomQueryEditorProps) {
  const {
    core,
    data,
    dataViewId,
    indexPattern,
    queryText = '',
    queryLanguage = 'kuery',
    onQueryTextChange,
    onQueryLanguageChange,
    queryCheck,
    onQueryValidate,
  } = props;

  const [dv, setDv] = useState<any>(null);
  const [dvError, setDvError] = useState<string | null>(null);
  // The builder owns the server verdict (it gates Save on it); absent threading = never checked.
  const serverCheck: QueryValidationState = queryCheck ?? { status: 'idle' };

  // Resolve the selected data view for SearchBar suggestions (the investigation_tab idiom).
  useEffect(() => {
    let cancelled = false;
    setDv(null);
    setDvError(null);
    if (!data || !dataViewId) return;
    (async () => {
      try {
        const resolved = await data.dataViews.get(dataViewId);
        if (!cancelled) setDv(resolved);
      } catch (e) {
        if (!cancelled) setDvError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [data, dataViewId]);

  // Layer 1 — instant client-side DQL verdict via the SHARED translator (same strings as compile).
  const clientCheck = useMemo(() => {
    if (queryLanguage !== 'kuery' || queryText.trim() === '') return null;
    const result = translateDqlToLucene(queryText);
    if (result.ok) return null;
    let luceneHint = false;
    try {
      luceneHint = doesKueryExpressionHaveLuceneSyntaxError(queryText);
    } catch {
      luceneHint = false;
    }
    return { message: formatDqlTranslationErrors(result.errors), luceneHint };
  }, [queryLanguage, queryText]);

  // Layer 2 — the cluster’s own parser, on blur / submit. The BUILDER runs it (Save is gated
  // on the verdict) and dedupes repeats for an unchanged (language, index, query) triple; a
  // standing client-side verdict makes the round-trip moot.
  const requestServerValidation = () => {
    if (!onQueryValidate || !indexPattern || queryText.trim() === '') return;
    if (clientCheck) return; // a client-side verdict already stands — no round-trip needed
    onQueryValidate();
  };

  const onQueryBarChange = (payload: any) => {
    const q = payload?.query;
    if (!q) return;
    if (typeof q.query === 'string' && q.query !== queryText) onQueryTextChange?.(q.query);
    if ((q.language === 'kuery' || q.language === 'lucene') && q.language !== queryLanguage) {
      onQueryLanguageChange?.(q.language);
    }
  };

  const onQueryBarSubmit = (payload: any) => {
    onQueryBarChange(payload);
    // Submit is an explicit "I'm done typing" — validate right away (state updates land first).
    setTimeout(requestServerValidation, 0);
  };

  if (!core || !data) {
    return (
      <EuiPanel hasShadow={false} hasBorder>
        <EuiTitle size="xs">
          <h2>Query — which events match</h2>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiCallOut
          color="warning"
          iconType="iInCircle"
          title="The custom-query editor is not wired up yet"
        >
          <p>
            The builder must pass its core/data services and the query form state to this editor (D2
            serial integration) before it can render the query bar.
          </p>
        </EuiCallOut>
      </EuiPanel>
    );
  }

  const SearchBar = data.ui.SearchBar as any;
  const I18nContext = core.i18n.Context;

  return (
    <EuiPanel hasShadow={false} hasBorder>
      <EuiTitle size="xs">
        <h2>Query — which events match</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiText size="s" color="subdued">
        <p>
          Write the match as a query — DQL (with autocomplete) or Lucene; switch with the language
          selector in the bar. DQL here supports a subset (and/or/not, field:value, value lists,
          wildcards, ranges, field:* exists) because doc-level rules execute as Lucene; full DQL is
          available in threshold rules. The query is checked against your data before you can rely
          on it — the alerting engine itself never validates doc-level queries.
        </p>
      </EuiText>
      <EuiSpacer size="s" />

      {!props.hasDataView || !dataViewId ? (
        <EuiCallOut
          color="primary"
          iconType="iInCircle"
          title="Select a data view first — suggestions and validation need one."
        />
      ) : dvError ? (
        <EuiCallOut color="danger" iconType="alert" title="Could not load the data view">
          <p>{dvError}</p>
        </EuiCallOut>
      ) : !dv ? (
        <EuiLoadingSpinner size="m" />
      ) : (
        <I18nContext>
          {/* onBlur bubbles from the query input (React focusout) — the cheap "left the field"
              trigger the stateful SearchBar doesn't expose directly. */}
          <div onBlur={requestServerValidation}>
            <SearchBar
              appName="tlsoc-detections"
              indexPatterns={[dv]}
              query={{ query: queryText, language: queryLanguage }}
              showQueryInput={true}
              showDatePicker={false}
              showFilterBar={false}
              showSaveQuery={false}
              onQueryChange={onQueryBarChange}
              onQuerySubmit={onQueryBarSubmit}
            />
          </div>
        </I18nContext>
      )}

      {clientCheck ? (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut color="danger" iconType="alert" title="This DQL can’t compile to a rule">
            <EuiText size="s" style={{ whiteSpace: 'pre-wrap' }}>
              <p>{clientCheck.message}</p>
            </EuiText>
            {clientCheck.luceneHint ? (
              <p>
                This looks like Lucene syntax — switch the language selector in the query bar to
                Lucene.
              </p>
            ) : null}
          </EuiCallOut>
        </>
      ) : null}

      {serverCheck.status === 'checking' ? (
        <>
          <EuiSpacer size="s" />
          <EuiText size="s" color="subdued">
            <p>
              <EuiLoadingSpinner size="s" /> Validating against {indexPattern}…
            </p>
          </EuiText>
        </>
      ) : serverCheck.status === 'valid' ? (
        <>
          <EuiSpacer size="s" />
          <EuiText size="s" color="success">
            <p>✓ The query is valid against {indexPattern}.</p>
          </EuiText>
        </>
      ) : serverCheck.status === 'invalid' ? (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut color="danger" iconType="alert" title="The query did not validate">
            <EuiText size="s" style={{ whiteSpace: 'pre-wrap' }}>
              <p>{serverCheck.reason}</p>
            </EuiText>
          </EuiCallOut>
        </>
      ) : serverCheck.status === 'error' ? (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut color="warning" iconType="alert" title="Could not validate the query">
            <p>{serverCheck.reason}</p>
          </EuiCallOut>
        </>
      ) : null}
    </EuiPanel>
  );
}
