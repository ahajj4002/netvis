import React from 'react';
import { colors } from '../theme';

/**
 * Intelligence summary panel: story summary, insights, top domains, exposed services.
 */
export function IntelStoryPanel({ story }) {
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
        <span style={{ color: colors.accent }}>◆</span>
        INTEL STORY
      </div>

      {!story ? (
        <div style={{ color: colors.textMuted, fontSize: '11px' }}>
          Waiting for telemetry…
        </div>
      ) : (
        <>
          <div
            style={{
              fontSize: '11px',
              color: colors.text,
              lineHeight: 1.5,
              background: colors.bgTertiary,
              borderRadius: '8px',
              padding: '10px',
              marginBottom: '10px',
            }}
          >
            {story.summary}
          </div>

          <div style={{ marginBottom: '10px' }}>
            <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '6px' }}>
              KEY INSIGHTS
            </div>
            <div style={{ maxHeight: '120px', overflow: 'auto' }}>
              {(story.insights || []).slice(0, 6).map((item, i) => (
                <div
                  key={i}
                  style={{ fontSize: '11px', color: colors.text, marginBottom: '6px' }}
                >
                  • {item}
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
            <div style={{ background: colors.bgTertiary, borderRadius: '6px', padding: '8px' }}>
              <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>
                TOP DOMAINS
              </div>
              {(story.top_domains || []).slice(0, 3).map((d, i) => (
                <div
                  key={`${d.domain}-${i}`}
                  style={{ fontSize: '10px', color: colors.text, marginBottom: '3px' }}
                >
                  {d.domain} <span style={{ color: colors.accent }}>({d.count})</span>
                </div>
              ))}
            </div>
            <div style={{ background: colors.bgTertiary, borderRadius: '6px', padding: '8px' }}>
              <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>
                EXPOSED SERVICES
              </div>
              {(story.exposed_services || []).slice(0, 3).map((s, i) => (
                <div
                  key={`${s.ip}-${s.port}-${i}`}
                  style={{ fontSize: '10px', color: colors.text, marginBottom: '3px' }}
                >
                  {s.ip}:{s.port} <span style={{ color: colors.warning }}>{s.service}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
