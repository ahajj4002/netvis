import React from 'react';
import { colors } from '../theme';

/**
 * Security alerts list with severity styling.
 */
export function AlertsPanel({ alerts }) {
  const severityColors = {
    critical: colors.danger,
    high: colors.orange,
    medium: colors.warning,
    low: colors.textMuted,
  };

  return (
    <div
      style={{
        background: colors.bgCard,
        border: `1px solid ${colors.border}`,
        borderRadius: '12px',
        padding: '16px',
        height: '100%',
      }}
    >
      <div
        style={{
          fontSize: '12px',
          fontWeight: 600,
          color: colors.text,
          marginBottom: '12px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
        }}
      >
        <span style={{ color: colors.danger }}>⚠</span>
        SECURITY ALERTS ({alerts?.length || 0})
      </div>

      <div style={{ maxHeight: '250px', overflow: 'auto' }}>
        {(!alerts || alerts.length === 0) ? (
          <div
            style={{
              color: colors.textMuted,
              fontSize: '11px',
              textAlign: 'center',
              padding: '20px',
            }}
          >
            No alerts detected
          </div>
        ) : (
          alerts.map((alert, i) => (
            <div
              key={i}
              style={{
                background: colors.bgTertiary,
                borderRadius: '8px',
                padding: '10px',
                marginBottom: '8px',
                borderLeft: `3px solid ${severityColors[alert.severity] || colors.textMuted}`,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                <span
                  style={{
                    fontSize: '9px',
                    fontWeight: 600,
                    color: severityColors[alert.severity],
                    textTransform: 'uppercase',
                  }}
                >
                  {alert.severity}
                </span>
                <span style={{ fontSize: '9px', color: colors.textDim }}>
                  {alert.timestamp?.split('T')[1]?.substring(0, 8)}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: colors.text }}>{alert.message}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
