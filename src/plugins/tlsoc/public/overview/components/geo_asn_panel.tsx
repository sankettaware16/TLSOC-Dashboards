/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiFlexGroup, EuiFlexItem } from '@elastic/eui';
import { TermBucket } from '../../../common/overview/types';
import { TopList } from './top_list';

interface GeoAsnPanelProps {
  countries?: TermBucket[];
  asns?: TermBucket[];
}

/**
 * Geo + ASN — "where is the external traffic from and who owns it". Country + ASN ranked lists
 * (a coordinate map needs source.geo.location as geo_point; the ranked lists are the robust,
 * always-available form and read cleanly in dark mode).
 */
export const GeoAsnPanel: React.FC<GeoAsnPanelProps> = ({ countries, asns }) => {
  const hasGeo = countries && countries.length > 0;
  const hasAsn = asns && asns.length > 0;
  if (!hasGeo && !hasAsn) return null;
  return (
    <EuiFlexGroup gutterSize="l">
      {hasGeo && (
        <EuiFlexItem>
          <TopList title="Top countries (source geo)" buckets={countries!} />
        </EuiFlexItem>
      )}
      {hasAsn && (
        <EuiFlexItem>
          <TopList title="Top networks (ASN owner)" buckets={asns!} />
        </EuiFlexItem>
      )}
    </EuiFlexGroup>
  );
};
