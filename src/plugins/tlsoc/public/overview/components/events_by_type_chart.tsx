/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  Chart,
  Settings,
  Axis,
  BarSeries,
  ScaleType,
  Position,
  DARK_THEME,
  LIGHT_THEME,
  niceTimeFormatByDay,
  timeFormatter,
} from '@elastic/charts';
import { EUI_CHARTS_THEME_DARK, EUI_CHARTS_THEME_LIGHT } from '@elastic/eui/dist/eui_charts_theme';
import { EuiPanel, EuiTitle, EuiSpacer } from '@elastic/eui';
import { TypeTimeBucket } from '../../../common/overview/types';
import { SOURCE_TYPE_LABELS, SourceType } from '../../../common/overview/source_types';
import { typeColor } from '../type_colors';

interface EventsByTypeChartProps {
  data: TypeTimeBucket[];
  darkMode: boolean;
}

/** Events over time, stacked by SIEM source type — a single type spiking is the visible anomaly. */
export const EventsByTypeChart: React.FC<EventsByTypeChartProps> = ({ data, darkMode }) => {
  const rows: Array<{ t: number; type: string; count: number }> = [];
  const seenTypes = new Set<string>();
  for (const bucket of data) {
    if (bucket.byType.length > 0) {
      for (const s of bucket.byType) {
        rows.push({ t: bucket.t, type: SOURCE_TYPE_LABELS[s.key as SourceType] ?? s.key, count: s.count });
        seenTypes.add(s.key);
      }
    } else if (bucket.total > 0) {
      rows.push({ t: bucket.t, type: 'events', count: bucket.total });
    }
  }
  const euiTheme = darkMode ? EUI_CHARTS_THEME_DARK.theme : EUI_CHARTS_THEME_LIGHT.theme;
  const colors = Array.from(seenTypes).map((t) => typeColor(t));

  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="m">
      <EuiTitle size="xxs">
        <h3>Events over time, by source type</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      <div style={{ height: 260 }}>
        {/* @ts-expect-error TS2322 @elastic/charts Chart size typing is broken in this version; Discover suppresses the same way. */}
        <Chart size="100%">
          <Settings
            theme={colors.length ? { ...euiTheme, colors: { vizColors: colors } } : euiTheme}
            baseTheme={darkMode ? DARK_THEME : LIGHT_THEME}
            showLegend
            legendPosition={Position.Right}
          />
          <Axis id="bottom" position={Position.Bottom} tickFormat={timeFormatter(niceTimeFormatByDay(2))} showGridLines={false} />
          <Axis id="left" position={Position.Left} showGridLines ticks={4} />
          <BarSeries
            id="events"
            xScaleType={ScaleType.Time}
            yScaleType={ScaleType.Linear}
            xAccessor="t"
            yAccessors={['count']}
            splitSeriesAccessors={['type']}
            stackAccessors={['t']}
            data={rows}
          />
        </Chart>
      </div>
    </EuiPanel>
  );
};
