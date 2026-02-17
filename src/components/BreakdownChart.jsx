import React from 'react';
import { colors } from '../theme';
import { formatBytes } from '../utils';

const chartColors = [
  colors.accent,
  colors.purple,
  colors.success,
  colors.warning,
  colors.pink,
  colors.orange,
  colors.danger,
  colors.textMuted,
];

/**
 * Protocol/application breakdown bars with legend.
 */
export function BreakdownChart({ data, title }) {
  const total = Object.values(data).reduce((a, b) => a + b, 0) || 1;
  const sorted = Object.entries(data)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  return (
    <div>
      <div style={{ fontSize: '11px', color: colors.textMuted, marginBottom: '12px' }}>
        {title}
      </div>
      <div
        style={{
          display: 'flex',
          gap: '4px',
          marginBottom: '12px',
          height: '8px',
          borderRadius: '4px',
          overflow: 'hidden',
        }}
      >
        {sorted.map(([name, value], i) => (
          <div
            key={name}
            style={{
              width: `${(value / total) * 100}%`,
              background: chartColors[i % chartColors.length],
              minWidth: '4px',
            }}
            title={`${name}: ${formatBytes(value)}`}
          />
        ))}
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
        {sorted.map(([name, value], i) => (
          <div
            key={name}
            style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px' }}
          >
            <div
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '2px',
                background: chartColors[i % chartColors.length],
              }}
            />
            <span style={{ color: colors.textMuted }}>{name}</span>
            <span style={{ color: colors.text }}>{formatBytes(value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
