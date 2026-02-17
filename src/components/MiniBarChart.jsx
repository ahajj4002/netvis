import React from 'react';
import { formatBytes } from '../utils';

/**
 * Mini bar chart for bandwidth or numeric series.
 */
export function MiniBarChart({ data, color, height = 60, valueFormatter }) {
  const max = Math.max(...data.map((d) => d.value), 1);
  const fmt = valueFormatter || ((v) => formatBytes(v));

  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', height, gap: '2px' }}>
      {data.map((d, i) => (
        <div
          key={i}
          style={{
            flex: 1,
            height: `${(d.value / max) * 100}%`,
            background: color,
            borderRadius: '2px 2px 0 0',
            minHeight: '2px',
            opacity: 0.7 + (i / data.length) * 0.3,
          }}
          title={`${d.label}: ${fmt(d.value)}`}
        />
      ))}
    </div>
  );
}
