import React, { useEffect } from 'react';
import { colors } from '../theme';
import { API_BASE } from '../api';

/**
 * Intelligence quality metrics dashboard for NIP.
 */
export function QualityPanel({
  metrics,
  setMetrics,
  loading,
  setLoading,
  hasLoaded,
  setHasLoaded,
}) {
  const card = {
    background: colors.bgTertiary,
    border: `1px solid ${colors.border}`,
    borderRadius: '12px',
    padding: '16px',
    marginTop: '12px',
  };

  const refresh = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/nip/quality`);
      setMetrics(await res.json());
    } catch (e) {
      setMetrics({ error: e.message });
    }
    setLoading(false);
    setHasLoaded(true);
  };

  useEffect(() => {
    if (!hasLoaded) refresh();
  }, [hasLoaded]);

  const disc = metrics?.discovery;
  const risk = metrics?.risk_distribution;
  const anom = metrics?.anomaly;

  return (
    <div style={card}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>
          Intelligence Quality Metrics
        </div>
        <button
          onClick={refresh}
          disabled={loading}
          style={{
            fontSize: '10px',
            padding: '4px 12px',
            borderRadius: '6px',
            border: `1px solid ${colors.accent}`,
            background: `${colors.accent}22`,
            color: colors.accent,
            cursor: 'pointer',
          }}
        >
          {loading ? '...' : 'Refresh'}
        </button>
      </div>
      {disc && (
        <div
          style={{
            marginTop: '12px',
            background: colors.bgCard,
            padding: '10px',
            borderRadius: '8px',
          }}
        >
          <div style={{ fontSize: '11px', fontWeight: 700, color: colors.text }}>
            Discovery Completeness
          </div>
          <div style={{ marginTop: '6px', fontSize: '10px', color: colors.textMuted }}>
            Discovered: {disc.discovered} devices
            {disc.completeness_pct != null && (
              <span> ({disc.completeness_pct}% of ground truth)</span>
            )}
          </div>
        </div>
      )}
      {risk && risk.count > 0 && (
        <div
          style={{
            marginTop: '8px',
            background: colors.bgCard,
            padding: '10px',
            borderRadius: '8px',
          }}
        >
          <div style={{ fontSize: '11px', fontWeight: 700, color: colors.text }}>
            Risk Score Distribution
          </div>
          <div
            style={{
              marginTop: '6px',
              display: 'grid',
              gridTemplateColumns: 'repeat(4,1fr)',
              gap: '6px',
            }}
          >
            {Object.entries(risk.buckets || {}).map(([k, v]) => (
              <div key={k} style={{ textAlign: 'center' }}>
                <div
                  style={{
                    fontSize: '14px',
                    fontWeight: 900,
                    color:
                      k === 'critical'
                        ? colors.danger
                        : k === 'high'
                          ? colors.orange
                          : k === 'medium'
                            ? colors.warning
                            : colors.success,
                  }}
                >
                  {v}
                </div>
                <div style={{ fontSize: '9px', color: colors.textMuted }}>{k}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: '6px', fontSize: '9px', color: colors.textMuted }}>
            range: {risk.min?.toFixed(2)} — {risk.max?.toFixed(2)}, mean: {risk.mean?.toFixed(2)}
          </div>
        </div>
      )}
      {anom && (
        <div
          style={{
            marginTop: '8px',
            background: colors.bgCard,
            padding: '10px',
            borderRadius: '8px',
          }}
        >
          <div style={{ fontSize: '11px', fontWeight: 700, color: colors.text }}>
            Anomaly Detection
          </div>
          <div style={{ marginTop: '6px', fontSize: '10px', color: colors.textMuted }}>
            Total alerts: {anom.total_alerts}
            {anom.precision != null && (
              <span>
                {' '}
                | Precision: {anom.precision} | Recall: {anom.recall}
              </span>
            )}
          </div>
        </div>
      )}
      {metrics?.error && (
        <div style={{ marginTop: '10px', fontSize: '10px', color: colors.danger }}>
          {metrics.error}
        </div>
      )}
    </div>
  );
}
