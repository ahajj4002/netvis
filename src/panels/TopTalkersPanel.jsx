import React from 'react';
import { colors } from '../theme';
import { formatBytes } from '../utils';

const serviceColors = {
  'Amazon AWS': '#FF9900',
  Google: '#4285F4',
  'Microsoft Azure': '#00A4EF',
  Cloudflare: '#F38020',
  'Meta/Facebook': '#1877F2',
  Apple: '#A3AAAE',
  Netflix: '#E50914',
  'Akamai CDN': '#0096D6',
  'SSDP/UPnP Multicast': colors.purple,
  'Private Network': colors.success,
};

/**
 * Top talkers list with bytes, service tags, and progress bars.
 */
export function TopTalkersPanel({ talkers, devices }) {
  const maxBytes = talkers?.[0]?.bytes || 1;

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
        <span style={{ color: colors.success }}>▲</span>
        TOP TALKERS
      </div>

      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
          maxHeight: '350px',
          overflow: 'auto',
        }}
      >
        {(talkers || []).slice(0, 12).map((talker, i) => {
          const ip = talker.ip || talker[0];
          const bytes = talker.bytes || talker[1];
          const service = talker.service || '';
          const hostname = talker.hostname || '';
          const country = talker.country || '';
          const org = talker.org || '';
          const isLocal = talker.is_local;

          const pct = (bytes / maxBytes) * 100;
          const barColor =
            serviceColors[service] || (isLocal ? colors.success : colors.accentDim);

          return (
            <div
              key={ip}
              style={{
                background: colors.bgTertiary,
                borderRadius: '8px',
                padding: '10px',
                borderLeft: `3px solid ${barColor}`,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  marginBottom: '4px',
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '11px', color: colors.text, fontWeight: 500 }}>
                    {hostname || ip}
                  </div>
                  {hostname && (
                    <div style={{ fontSize: '9px', color: colors.textDim }}>{ip}</div>
                  )}
                </div>
                <span
                  style={{
                    fontSize: '11px',
                    color: colors.accent,
                    fontWeight: 600,
                    marginLeft: '8px',
                  }}
                >
                  {formatBytes(bytes)}
                </span>
              </div>

              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '4px',
                  marginBottom: '6px',
                }}
              >
                {service && (
                  <span
                    style={{
                      fontSize: '9px',
                      background: barColor + '22',
                      color: barColor,
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontWeight: 500,
                    }}
                  >
                    {service}
                  </span>
                )}
                {country && country !== 'Local' && country !== 'Unknown' && (
                  <span
                    style={{
                      fontSize: '9px',
                      background: colors.bgSecondary,
                      color: colors.textMuted,
                      padding: '2px 6px',
                      borderRadius: '4px',
                    }}
                  >
                    📍 {country}
                  </span>
                )}
                {org && !service && (
                  <span
                    style={{
                      fontSize: '9px',
                      color: colors.textDim,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      maxWidth: '150px',
                    }}
                  >
                    {org}
                  </span>
                )}
              </div>

              <div
                style={{
                  height: '3px',
                  background: colors.bgSecondary,
                  borderRadius: '2px',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${pct}%`,
                    height: '100%',
                    background: barColor,
                    borderRadius: '2px',
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
