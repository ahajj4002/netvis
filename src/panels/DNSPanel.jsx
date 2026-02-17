import React from 'react';
import { colors } from '../theme';

/**
 * DNS monitor panel: top domains and queries by device.
 */
export function DNSPanel({ dnsData }) {
  if (!dnsData) return null;

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
        <span style={{ color: colors.purple }}>◉</span>
        DNS QUERIES ({dnsData.total_queries || 0})
      </div>

      <div style={{ marginBottom: '16px' }}>
        <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>
          TOP DOMAINS
        </div>
        <div style={{ maxHeight: '150px', overflow: 'auto' }}>
          {(dnsData.top_domains || []).slice(0, 10).map(([domain, count], i) => (
            <div
              key={domain}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                padding: '4px 0',
                borderBottom: i < 9 ? `1px solid ${colors.border}` : 'none',
                fontSize: '11px',
              }}
            >
              <span
                style={{
                  color: colors.text,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: '180px',
                }}
              >
                {domain}
              </span>
              <span style={{ color: colors.accent }}>{count}</span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>
          BY DEVICE
        </div>
        <div style={{ maxHeight: '120px', overflow: 'auto' }}>
          {Object.entries(dnsData.queries_by_ip || {}).slice(0, 8).map(([ip, queries]) => (
            <div
              key={ip}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                padding: '4px 0',
                fontSize: '11px',
              }}
            >
              <span style={{ color: colors.textMuted }}>{ip}</span>
              <span style={{ color: colors.success }}>{queries.length} queries</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
