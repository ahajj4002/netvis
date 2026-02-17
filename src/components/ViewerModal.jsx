import React from 'react';
import { colors } from '../theme';

/**
 * Shared overlay for viewing JSON or text content (e.g. coursework/workbench artifacts).
 */
export function ViewerModal({ open, title, loading, error, isJson, json, content, onClose }) {
  if (!open) return null;

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.65)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
        zIndex: 9999,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(1100px, 92vw)',
          height: 'min(700px, 86vh)',
          background: colors.bgCard,
          border: `1px solid ${colors.border}`,
          borderRadius: '12px',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '10px 12px',
            borderBottom: `1px solid ${colors.border}`,
            background: colors.bgTertiary,
          }}
        >
          <div style={{ color: colors.text, fontSize: '11px', fontWeight: 800 }}>
            {title}
          </div>
          <button
            onClick={onClose}
            style={{
              padding: '6px 10px',
              background: colors.bgCard,
              border: `1px solid ${colors.border}`,
              borderRadius: '8px',
              color: colors.text,
              fontSize: '10px',
              cursor: 'pointer',
            }}
          >
            Close
          </button>
        </div>

        <div
          style={{
            flex: 1,
            minHeight: 0,
            overflow: 'auto',
            padding: '12px',
          }}
        >
          {loading && (
            <div style={{ fontSize: '10px', color: colors.textMuted }}>Loading…</div>
          )}
          {error && (
            <div style={{ fontSize: '10px', color: colors.danger }}>{error}</div>
          )}
          {!loading && !error && isJson && (
            <pre
              style={{
                margin: 0,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontSize: '10px',
                color: colors.text,
              }}
            >
              {JSON.stringify(json || {}, null, 2)}
            </pre>
          )}
          {!loading && !error && !isJson && (
            <pre
              style={{
                margin: 0,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontSize: '10px',
                color: colors.text,
              }}
            >
              {(content || '').toString()}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
