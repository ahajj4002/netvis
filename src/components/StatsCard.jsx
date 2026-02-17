import React from 'react';
import { colors } from '../theme';

/**
 * Dashboard stat card: title, value, optional subtitle and accent color.
 */
export function StatsCard({ title, value, subtitle, icon, color, trend }) {
  return (
    <div
      style={{
        background: colors.bgCard,
        border: `1px solid ${colors.border}`,
        borderRadius: '12px',
        padding: '16px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          position: 'absolute',
          top: '-20px',
          right: '-20px',
          width: '80px',
          height: '80px',
          background: color,
          opacity: 0.1,
          borderRadius: '50%',
        }}
      />
      <div style={{ fontSize: '11px', color: colors.textMuted, marginBottom: '4px' }}>
        {title}
      </div>
      <div style={{ fontSize: '24px', fontWeight: 700, color }}>{value}</div>
      {subtitle && (
        <div style={{ fontSize: '10px', color: colors.textDim, marginTop: '4px' }}>
          {subtitle}
        </div>
      )}
    </div>
  );
}
