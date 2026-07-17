/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from 'react';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../../data/public';
import { CasesList } from './cases_list';
import { CaseDetail } from './case_detail';

interface Props {
  core: CoreStart;
  data: DataPublicPluginStart;
}

export function CasesApp({ core, data }: Props) {
  const [view, setView] = useState<'list' | 'detail'>('list');
  const [caseId, setCaseId] = useState<string | null>(null);

  useEffect(() => {
    // deep-link: loop-closer navigates here with #/case/<id>
    const m = window.location.hash.match(/#\/case\/([^/?&]+)/);
    if (m) {
      setCaseId(m[1]);
      setView('detail');
    }
  }, []);

  const openDetail = (id: string) => {
    setCaseId(id);
    setView('detail');
    window.history.replaceState(null, '', `#/case/${id}`);
  };

  const backToList = () => {
    setCaseId(null);
    setView('list');
    window.history.replaceState(null, '', '#');
  };

  if (view === 'detail' && caseId) {
    return <CaseDetail key={caseId} core={core} data={data} caseId={caseId} onBack={backToList} />;
  }

  return <CasesList core={core} onOpen={openDetail} />;
}
