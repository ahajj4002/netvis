import React, { useMemo } from 'react';
import { colors } from '../theme';
import { extractLogInsights, compactValue, compactObjectLine } from '../utils';

/**
 * Log insight viewer: interpretation, count cards, metadata, sections.
 */
export function LogParsedView({ payload }) {
  const insights = useMemo(() => extractLogInsights(payload), [payload]);

  const toneColor = {
    neutral: colors.accent,
    success: colors.success,
    warning: colors.warning,
    danger: colors.danger,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div
        style={{
          background: colors.bgTertiary,
          border: `1px solid ${colors.border}`,
          borderRadius: '10px',
          padding: '10px',
        }}
      >
        <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>
          Interpretation
        </div>
        {insights.highlights.map((h, i) => (
          <div
            key={`${h.text}-${i}`}
            style={{
              fontSize: '11px',
              color: toneColor[h.tone] || colors.text,
              marginBottom: '5px',
            }}
          >
            - {h.text}
          </div>
        ))}
      </div>

      {insights.countCards.length > 0 && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
            gap: '8px',
          }}
        >
          {insights.countCards.slice(0, 12).map((c) => (
            <div
              key={c.label}
              style={{
                background: colors.bgTertiary,
                border: `1px solid ${colors.border}`,
                borderRadius: '10px',
                padding: '8px',
              }}
            >
              <div style={{ fontSize: '9px', color: colors.textMuted }}>{c.label}</div>
              <div
                style={{
                  fontSize: '16px',
                  fontWeight: 900,
                  color: toneColor[c.tone] || colors.accent,
                }}
              >
                {c.value}
              </div>
            </div>
          ))}
        </div>
      )}

      {insights.metadata.length > 0 && (
        <div
          style={{
            background: colors.bgTertiary,
            border: `1px solid ${colors.border}`,
            borderRadius: '10px',
            padding: '10px',
          }}
        >
          <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>
            Run Metadata
          </div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: '8px',
            }}
          >
            {insights.metadata.map((m) => (
              <div
                key={`${m.label}-${m.value}`}
                style={{
                  background: colors.bgCard,
                  border: `1px solid ${colors.border}`,
                  borderRadius: '8px',
                  padding: '8px',
                }}
              >
                <div style={{ fontSize: '9px', color: colors.textMuted }}>{m.label}</div>
                <div
                  style={{
                    fontSize: '10px',
                    color: colors.text,
                    marginTop: '2px',
                    wordBreak: 'break-word',
                  }}
                >
                  {m.value}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {insights.sections.map((sec) => (
        <div
          key={sec.title}
          style={{
            background: colors.bgTertiary,
            border: `1px solid ${colors.border}`,
            borderRadius: '10px',
            padding: '10px',
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              gap: '10px',
              marginBottom: '8px',
            }}
          >
            <div style={{ fontSize: '10px', color: colors.text, fontWeight: 800 }}>
              {sec.title}
            </div>
            <div style={{ fontSize: '9px', color: colors.textMuted }}>
              {sec.total} item(s){sec.truncated ? ' (showing first 25)' : ''}
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {sec.rows.map((row, i) => (
              <div
                key={`${sec.title}-${i}`}
                style={{
                  background: colors.bgCard,
                  border: `1px solid ${colors.border}`,
                  borderRadius: '8px',
                  padding: '7px',
                }}
              >
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>
                  #{i + 1}
                </div>
                <div
                  style={{
                    fontSize: '10px',
                    color: colors.text,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {typeof row === 'object' ? compactObjectLine(row) : compactValue(row)}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      {insights.sections.length === 0 && insights.primitives.length > 0 && (
        <div
          style={{
            background: colors.bgTertiary,
            border: `1px solid ${colors.border}`,
            borderRadius: '10px',
            padding: '10px',
          }}
        >
          <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>
            Primary Output Fields
          </div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: '8px',
            }}
          >
            {insights.primitives.map((p) => (
              <div
                key={`${p.key}-${p.value}`}
                style={{
                  background: colors.bgCard,
                  border: `1px solid ${colors.border}`,
                  borderRadius: '8px',
                  padding: '8px',
                }}
              >
                <div style={{ fontSize: '9px', color: colors.textMuted }}>{p.key}</div>
                <div style={{ fontSize: '10px', color: colors.text, marginTop: '2px' }}>
                  {p.value}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
