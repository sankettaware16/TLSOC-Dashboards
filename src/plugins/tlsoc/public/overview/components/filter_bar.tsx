/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiFlexGroup, EuiFlexItem, EuiComboBox, EuiComboBoxOptionOption, EuiButtonEmpty } from '@elastic/eui';
import { TermBucket } from '../../../common/overview/types';

export interface OverviewFilterState {
  org: string[];
  dept: string[];
  env: string[];
  endpoint: string[];
  logSource: string[];
}

export const EMPTY_FILTERS: OverviewFilterState = { org: [], dept: [], env: [], endpoint: [], logSource: [] };

export function filtersActive(f: OverviewFilterState): boolean {
  return f.org.length + f.dept.length + f.env.length + f.endpoint.length + f.logSource.length > 0;
}

interface FilterBarProps {
  filters: OverviewFilterState;
  onChange: (next: OverviewFilterState) => void;
  options: {
    org?: TermBucket[];
    dept?: TermBucket[];
    env?: TermBucket[];
    endpoint?: TermBucket[];
    logSource?: TermBucket[];
  };
}

const toOptions = (buckets?: TermBucket[]): EuiComboBoxOptionOption[] =>
  (buckets ?? []).map((b) => ({ label: b.key, value: b.key }));
const toSelected = (values: string[]): EuiComboBoxOptionOption[] => values.map((v) => ({ label: v, value: v }));

/** Metadata filter bar — every SIEM dimension scopes all panels. Empty dimensions are hidden. */
export const FilterBar: React.FC<FilterBarProps> = ({ filters, onChange, options }) => {
  const box = (
    key: keyof OverviewFilterState,
    placeholder: string,
    opts?: TermBucket[]
  ) => {
    if (!opts || opts.length <= 1) return null; // nothing meaningful to filter on
    return (
      <EuiFlexItem style={{ minWidth: 170, maxWidth: 260 }} key={key}>
        <EuiComboBox
          compressed
          placeholder={placeholder}
          options={toOptions(opts)}
          selectedOptions={toSelected(filters[key])}
          onChange={(sel) => onChange({ ...filters, [key]: sel.map((s) => String(s.value ?? s.label)) })}
          isClearable
        />
      </EuiFlexItem>
    );
  };

  return (
    <EuiFlexGroup gutterSize="s" alignItems="center" wrap responsive={false}>
      {box('org', 'Organization', options.org)}
      {box('dept', 'Department', options.dept)}
      {box('env', 'Environment', options.env)}
      {box('endpoint', 'Endpoint', options.endpoint)}
      {box('logSource', 'Log source', options.logSource)}
      {filtersActive(filters) && (
        <EuiFlexItem grow={false}>
          <EuiButtonEmpty size="s" iconType="cross" onClick={() => onChange(EMPTY_FILTERS)}>
            Clear filters
          </EuiButtonEmpty>
        </EuiFlexItem>
      )}
    </EuiFlexGroup>
  );
};
