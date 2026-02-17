import React, { useState, useMemo } from 'react';
import { colors } from '../theme';

/**
 * NIP-style event timeline with category and entity filters.
 */
export function TimelinePanel({ timeline }) {
  const allItems = Array.isArray(timeline) ? timeline : [];
  const [filterCategory, setFilterCategory] = useState('');
  const [filterEntity, setFilterEntity] = useState('');

  const categories = useMemo(() => {
    const cats = new Set();
    allItems.forEach((ev) => {
      if (ev.category) cats.add(ev.category);
    });
    return Array.from(cats).sort();
  }, [allItems]);

  const items = useMemo(() => {
    let filtered = allItems;
    if (filterCategory) filtered = filtered.filter((ev) => (ev.category || '') === filterCategory);
    if (filterEntity.trim()) {
      const q = filterEntity.trim().toLowerCase();
      filtered = filtered.filter((ev) =>
        ((ev.entity || '') + ' ' + (ev.summary || '')).toLowerCase().includes(q)
      );
    }
    return filtered;
  }, [allItems, filterCategory, filterEntity]);

  const colorForCategory = (cat) => {
    const c = (cat || '').toString().toLowerCase();
    if (c.includes('alert') || c.includes('anomaly')) return colors.danger;
    if (c.includes('device.discovered') || c === 'discovery') return colors.success;
    if (c.includes('port.opened') || c.includes('service.banner')) return colors.warning;
    if (c.includes('technique') || c.includes('correlation')) return colors.accent;
    if (c.includes('capture') || c.includes('threat')) return colors.purple;
    return colors.textMuted;
  };

  const fmtTs = (ts) => {
    const s = (ts || '').toString();
    return s.replace('T', ' ').replace('Z', '').slice(0, 19);
  };

  return (
    <div
      style={{
        background: colors.bgCard,
        border: `1px solid ${colors.border}`,
        borderRadius: '12px',
        padding: '16px',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        minHeight: '260px',
      }}
    >
      <div
        style={{
          fontSize: '12px',
          fontWeight: 700,
          color: colors.text,
          marginBottom: '8px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
        }}
      >
        <span style={{ color: colors.accent }}>&#9673;</span>
        TIMELINE ({items.length}/{allItems.length})
      </div>

      <div style={{ display: 'flex', gap: '6px', marginBottom: '10px', flexWrap: 'wrap' }}>
        <select
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value)}
          style={{
            fontSize: '10px',
            padding: '3px 6px',
            borderRadius: '6px',
            border: `1px solid ${colors.border}`,
            background: colors.bgTertiary,
            color: colors.text,
          }}
        >
          <option value="">All categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <input
          value={filterEntity}
          onChange={(e) => setFilterEntity(e.target.value)}
          placeholder="Filter entity/text..."
          style={{
            fontSize: '10px',
            padding: '3px 8px',
            borderRadius: '6px',
            border: `1px solid ${colors.border}`,
            background: colors.bgTertiary,
            color: colors.text,
            flex: 1,
            minWidth: '100px',
            outline: 'none',
          }}
        />
        {(filterCategory || filterEntity) && (
          <button
            onClick={() => {
              setFilterCategory('');
              setFilterEntity('');
            }}
            style={{
              fontSize: '9px',
              padding: '3px 8px',
              borderRadius: '6px',
              border: `1px solid ${colors.danger}55`,
              background: `${colors.danger}22`,
              color: colors.danger,
              cursor: 'pointer',
            }}
          >
            Clear
          </button>
        )}
      </div>

      {items.length === 0 ? (
        <div style={{ color: colors.textMuted, fontSize: '11px' }}>
          {allItems.length === 0
            ? 'No timeline events yet. Start capture, run a scan, or run multi-chain.'
            : 'No events match the current filter.'}
        </div>
      ) : (
        <div style={{ flex: 1, overflow: 'auto' }}>
          {items.slice(0, 200).map((ev, i) => (
            <div
              key={i}
              style={{
                padding: '10px 10px',
                borderRadius: '10px',
                border: `1px solid ${colors.border}`,
                background: colors.bgTertiary,
                marginBottom: '8px',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  gap: '10px',
                  marginBottom: '6px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                  <span
                    style={{
                      background: `${colorForCategory(ev.category)}22`,
                      border: `1px solid ${colorForCategory(ev.category)}44`,
                      color: colorForCategory(ev.category),
                      padding: '2px 8px',
                      borderRadius: '999px',
                      fontSize: '9px',
                      fontWeight: 800,
                      whiteSpace: 'nowrap',
                      cursor: 'pointer',
                    }}
                    onClick={() => setFilterCategory(ev.category)}
                  >
                    {ev.category}
                  </span>
                  <span
                    style={{
                      color: colors.textMuted,
                      fontSize: '10px',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      cursor: 'pointer',
                    }}
                    onClick={() => setFilterEntity(ev.entity || '')}
                  >
                    {ev.entity || ''}
                  </span>
                </div>
                <span style={{ color: colors.textDim, fontSize: '10px', whiteSpace: 'nowrap' }}>
                  {fmtTs(ev.timestamp)}
                </span>
              </div>
              <div style={{ color: colors.text, fontSize: '11px', lineHeight: 1.4 }}>
                {ev.summary}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
