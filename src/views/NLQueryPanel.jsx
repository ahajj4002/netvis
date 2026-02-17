import React from 'react';
import { colors } from '../theme';
import { API_BASE } from '../api';

/**
 * Natural language query panel for NIP.
 */
export function NLQueryPanel({ query, setQuery, result, setResult, loading, setLoading }) {
  const card = {
    background: colors.bgTertiary,
    border: `1px solid ${colors.border}`,
    borderRadius: '12px',
    padding: '16px',
    marginTop: '12px',
  };

  const runQuery = async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/nip/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });
      setResult(await res.json());
    } catch (e) {
      setResult({ error: e.message });
    }
    setLoading(false);
  };

  const examples = [
    'Which devices sent the most data?',
    'Show me everything 10.136.18.128 did',
    'Are any devices talking to malicious IPs?',
    'What changed since yesterday?',
    'Which devices are highest risk?',
    'Top DNS domains queried',
  ];

  return (
    <div style={card}>
      <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>
        Network Intelligence Query
      </div>
      <div style={{ marginTop: '10px', display: 'flex', gap: '8px' }}>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') runQuery();
          }}
          placeholder="Ask a question about the network..."
          style={{
            flex: 1,
            fontSize: '11px',
            padding: '8px 12px',
            borderRadius: '8px',
            border: `1px solid ${colors.border}`,
            background: colors.bgCard,
            color: colors.text,
            outline: 'none',
          }}
        />
        <button
          onClick={runQuery}
          disabled={loading}
          style={{
            fontSize: '10px',
            padding: '6px 16px',
            borderRadius: '8px',
            border: `1px solid ${colors.accent}`,
            background: `${colors.accent}22`,
            color: colors.accent,
            cursor: 'pointer',
            whiteSpace: 'nowrap',
          }}
        >
          {loading ? '...' : 'Query'}
        </button>
      </div>
      <div style={{ marginTop: '8px', display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
        {examples.map((ex) => (
          <button
            key={ex}
            onClick={() => setQuery(ex)}
            style={{
              fontSize: '9px',
              padding: '3px 8px',
              borderRadius: '999px',
              border: `1px solid ${colors.border}`,
              background: colors.bgCard,
              color: colors.textMuted,
              cursor: 'pointer',
            }}
          >
            {ex}
          </button>
        ))}
      </div>
      {result?.explanation && (
        <div style={{ marginTop: '10px', fontSize: '10px', color: colors.accent }}>
          {result.explanation}
        </div>
      )}
      {result?.results && (
        <div style={{ marginTop: '8px', maxHeight: '400px', overflow: 'auto' }}>
          <pre
            style={{
              fontSize: '10px',
              color: colors.textMuted,
              whiteSpace: 'pre-wrap',
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            {JSON.stringify(result.results, null, 2).slice(0, 5000)}
          </pre>
        </div>
      )}
      {result?.error && (
        <div style={{ marginTop: '10px', fontSize: '10px', color: colors.danger }}>
          {result.error}
        </div>
      )}
    </div>
  );
}
