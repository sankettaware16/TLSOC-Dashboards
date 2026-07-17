/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { createHistogramConfigs } from './create_histogram_configs';
import { DataPublicPluginStart, IndexPattern } from '../../../../../../data/public';

const makeIndexPattern = (timeFieldName: string | undefined, fieldNames: string[]) =>
  (({
    timeFieldName,
    fields: {
      getByName: (name: string) => (fieldNames.includes(name) ? { name } : undefined),
    },
  } as unknown) as IndexPattern);

const makeData = () => {
  const createAggConfigs = jest.fn().mockReturnValue({ aggs: [] });
  const showError = jest.fn();
  const data = ({
    query: { timefilter: { timefilter: { getTime: () => ({ from: 'now-15m', to: 'now' }) } } },
    search: { aggs: { createAggConfigs }, showError },
  } as unknown) as DataPublicPluginStart;
  return { data, createAggConfigs, showError };
};

describe('createHistogramConfigs', () => {
  it('builds agg configs when the time field exists on the index pattern', () => {
    const { data, createAggConfigs, showError } = makeData();
    const result = createHistogramConfigs(makeIndexPattern('@timestamp', ['@timestamp']), 'auto', data);

    expect(result).toEqual({ aggs: [] });
    expect(createAggConfigs).toHaveBeenCalledTimes(1);
    expect(showError).not.toHaveBeenCalled();
  });

  it('skips quietly (no global error toast) when timeFieldName is missing from the field cache', () => {
    // TLSOC: the sticky 5-minute "Could not locate that index-pattern-field" toast — a data
    // view whose stored fields lack its own time field must not route through showError.
    const { data, createAggConfigs, showError } = makeData();
    const result = createHistogramConfigs(makeIndexPattern('@timestamp', ['other-field']), 'auto', data);

    expect(result).toBeUndefined();
    expect(createAggConfigs).not.toHaveBeenCalled();
    expect(showError).not.toHaveBeenCalled();
  });

  it('skips quietly when the index pattern has no timeFieldName at all', () => {
    const { data, createAggConfigs, showError } = makeData();
    const result = createHistogramConfigs(makeIndexPattern(undefined, ['@timestamp']), 'auto', data);

    expect(result).toBeUndefined();
    expect(createAggConfigs).not.toHaveBeenCalled();
    expect(showError).not.toHaveBeenCalled();
  });

  it('still surfaces genuine agg-construction failures via showError', () => {
    const { data, createAggConfigs, showError } = makeData();
    createAggConfigs.mockImplementation(() => {
      throw new Error('boom');
    });
    const result = createHistogramConfigs(makeIndexPattern('@timestamp', ['@timestamp']), 'auto', data);

    expect(result).toBeUndefined();
    expect(showError).toHaveBeenCalledTimes(1);
  });
});
