/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { DataPublicPluginStart, IndexPattern } from '../../../../../../data/public';

export function createHistogramConfigs(
  indexPattern: IndexPattern,
  histogramInterval: string,
  data: DataPublicPluginStart
) {
  // TLSOC: a data view whose stored field cache lacks its own timeFieldName (e.g. created via
  // the raw saved-objects API, or the index does not exist yet) used to fall through to the
  // catch below, and showError() raises a GLOBAL toast that lingers for 5 minutes and re-fires
  // on every fetch. There is no histogram to build without the time field — skip quietly.
  if (!indexPattern.timeFieldName || !indexPattern.fields.getByName(indexPattern.timeFieldName)) {
    return;
  }

  const visStateAggs = [
    {
      type: 'count',
      schema: 'metric',
    },
    {
      type: 'date_histogram',
      schema: 'segment',
      params: {
        field: indexPattern.timeFieldName,
        interval: histogramInterval,
        timeRange: data.query.timefilter.timefilter.getTime(),
      },
    },
  ];

  // If index pattern is created before the index, this function will fail since the required fields for the histogram agg will be missing.
  try {
    return data.search.aggs.createAggConfigs(indexPattern, visStateAggs);
  } catch (error) {
    // Just display the error to the user but continue to render the rest of the page
    data.search.showError(error as Error);
    return;
  }
}
