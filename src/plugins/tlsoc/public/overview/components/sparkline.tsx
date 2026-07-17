/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';

interface SparklineProps {
  values: number[];
  width?: number;
  height?: number;
}

/**
 * A minimal inline-SVG sparkline. Uses `currentColor` for the stroke so it inherits the
 * surrounding text color and is correct in both light and dark themes with zero theme wiring.
 */
export const Sparkline: React.FC<SparklineProps> = ({ values, width = 120, height = 28 }) => {
  if (!values || values.length < 2) {
    return <svg width={width} height={height} aria-hidden />;
  }
  const max = Math.max(...values, 1);
  const stepX = width / (values.length - 1);
  const points = values
    .map((v, i) => {
      const x = i * stepX;
      const y = height - (v / max) * (height - 2) - 1;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="events per minute, last 60 minutes"
      style={{ display: 'block', color: 'currentColor', opacity: 0.85 }}
    >
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth={1.5} />
    </svg>
  );
};
