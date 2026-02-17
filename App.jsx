import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';

// ============================================================================
// NETVIS PRO - Advanced Network Security Visualization Platform
// ============================================================================

const API_BASE = (import.meta.env.VITE_API_BASE || '/api').replace(/\/+$/, '');

async function fetchJsonOrThrow(url, options) {
  const res = await fetch(url, options);
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const reason = (data && (data.reason || data.error || data.message)) || res.statusText || 'request_failed';
    throw new Error(`HTTP ${res.status}: ${reason}`);
  }
  return data || {};
}

// Cyberpunk / Security Operations aesthetic
const colors = {
  bg: '#0a0e17',
  bgSecondary: '#111827',
  bgTertiary: '#1a2234',
  bgCard: '#0d1321',
  border: '#1e3a5f',
  borderLight: '#2d4a6f',
  text: '#e2e8f0',
  textMuted: '#64748b',
  textDim: '#475569',
  accent: '#00d4ff',
  accentDim: '#0891b2',
  success: '#10b981',
  warning: '#f59e0b',
  danger: '#ef4444',
  purple: '#8b5cf6',
  pink: '#ec4899',
  orange: '#f97316',
  gradient1: 'linear-gradient(135deg, #00d4ff 0%, #8b5cf6 100%)',
  gradient2: 'linear-gradient(135deg, #f59e0b 0%, #ef4444 100%)',
};

// Device type icons
const deviceIcons = {
  gateway: 'M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5',
  server: 'M4 4h16v4H4zm0 6h16v4H4zm0 6h16v4H4z',
  workstation: 'M4 4h16v12H4zm0 14h16v2H4zm6-8h4',
  laptop: 'M4 6h16v10H4zm2 12h12v2H6z',
  phone: 'M7 2h10v20H7zm3 17h4',
  iot: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 4a1 1 0 110 2 1 1 0 010-2zm0 4a1 1 0 110 2 1 1 0 010-2z',
  printer: 'M6 2h12v6H6zm0 12h12v6H6zM4 8h16v8H4z',
  unknown: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 14v2m0-6a2 2 0 100-4 2 2 0 000 4z',
};

function getDeviceType(device) {
  const hostname = (device.hostname || '').toLowerCase();
  const vendor = (device.vendor || '').toLowerCase();
  const deviceType = (device.os || '').toLowerCase();
  
  if (device.is_gateway) return 'gateway';
  if (deviceType.includes('router')) return 'gateway';
  if (deviceType.includes('server') || deviceType.includes('nas')) return 'server';
  if (deviceType.includes('macbook') || deviceType.includes('laptop') || deviceType.includes('computer')) return 'laptop';
  if (deviceType.includes('phone') || deviceType.includes('smartphone')) return 'phone';
  if (deviceType.includes('printer')) return 'printer';
  if (deviceType.includes('iot') || deviceType.includes('smart') || deviceType.includes('esp')) return 'iot';
  if (hostname.includes('server') || hostname.includes('nas')) return 'server';
  if (device.is_local) return 'workstation';
  
  return 'unknown';
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatNumber(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toString();
}

// ============================================================================
// Dashboard Stats Cards
// ============================================================================

function StatsCard({ title, value, subtitle, icon, color, trend }) {
  return (
    <div style={{
      background: colors.bgCard,
      border: `1px solid ${colors.border}`,
      borderRadius: '12px',
      padding: '16px',
      position: 'relative',
      overflow: 'hidden'
    }}>
      <div style={{
        position: 'absolute',
        top: '-20px',
        right: '-20px',
        width: '80px',
        height: '80px',
        background: color,
        opacity: 0.1,
        borderRadius: '50%'
      }} />
      <div style={{ fontSize: '11px', color: colors.textMuted, marginBottom: '4px' }}>
        {title}
      </div>
      <div style={{ fontSize: '24px', fontWeight: 700, color }}>
        {value}
      </div>
      {subtitle && (
        <div style={{ fontSize: '10px', color: colors.textDim, marginTop: '4px' }}>
          {subtitle}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Mini Bar Chart
// ============================================================================

function MiniBarChart({ data, color, height = 60, valueFormatter }) {
  const max = Math.max(...data.map(d => d.value), 1);
  const fmt = valueFormatter || ((v) => formatBytes(v));
  
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', height, gap: '2px' }}>
      {data.map((d, i) => (
        <div
          key={i}
          style={{
            flex: 1,
            height: `${(d.value / max) * 100}%`,
            background: color,
            borderRadius: '2px 2px 0 0',
            minHeight: '2px',
            opacity: 0.7 + (i / data.length) * 0.3
          }}
          title={`${d.label}: ${fmt(d.value)}`}
        />
      ))}
    </div>
  );
}

// ============================================================================
// Protocol/Application Breakdown
// ============================================================================

function BreakdownChart({ data, title }) {
  const total = Object.values(data).reduce((a, b) => a + b, 0) || 1;
  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const chartColors = [colors.accent, colors.purple, colors.success, colors.warning, colors.pink, colors.orange, colors.danger, colors.textMuted];
  
  return (
    <div>
      <div style={{ fontSize: '11px', color: colors.textMuted, marginBottom: '12px' }}>
        {title}
      </div>
      <div style={{ display: 'flex', gap: '4px', marginBottom: '12px', height: '8px', borderRadius: '4px', overflow: 'hidden' }}>
        {sorted.map(([name, value], i) => (
          <div
            key={name}
            style={{
              width: `${(value / total) * 100}%`,
              background: chartColors[i % chartColors.length],
              minWidth: '4px'
            }}
            title={`${name}: ${formatBytes(value)}`}
          />
        ))}
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
        {sorted.map(([name, value], i) => (
          <div key={name} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: chartColors[i % chartColors.length] }} />
            <span style={{ color: colors.textMuted }}>{name}</span>
            <span style={{ color: colors.text }}>{formatBytes(value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// DNS Monitor Panel
// ============================================================================

function DNSPanel({ dnsData }) {
  if (!dnsData) return null;
  
  return (
    <div style={{
      background: colors.bgCard,
      border: `1px solid ${colors.border}`,
      borderRadius: '12px',
      padding: '16px',
      height: '100%'
    }}>
      <div style={{ 
        fontSize: '12px', 
        fontWeight: 600, 
        color: colors.text, 
        marginBottom: '12px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <span style={{ color: colors.purple }}>◉</span>
        DNS QUERIES ({dnsData.total_queries || 0})
      </div>
      
      {/* Top Domains */}
      <div style={{ marginBottom: '16px' }}>
        <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>
          TOP DOMAINS
        </div>
        <div style={{ maxHeight: '150px', overflow: 'auto' }}>
          {(dnsData.top_domains || []).slice(0, 10).map(([domain, count], i) => (
            <div key={domain} style={{
              display: 'flex',
              justifyContent: 'space-between',
              padding: '4px 0',
              borderBottom: i < 9 ? `1px solid ${colors.border}` : 'none',
              fontSize: '11px'
            }}>
              <span style={{ color: colors.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '180px' }}>
                {domain}
              </span>
              <span style={{ color: colors.accent }}>{count}</span>
            </div>
          ))}
        </div>
      </div>
      
      {/* Queries by Device */}
      <div>
        <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>
          BY DEVICE
        </div>
        <div style={{ maxHeight: '120px', overflow: 'auto' }}>
          {Object.entries(dnsData.queries_by_ip || {}).slice(0, 8).map(([ip, queries]) => (
            <div key={ip} style={{
              display: 'flex',
              justifyContent: 'space-between',
              padding: '4px 0',
              fontSize: '11px'
            }}>
              <span style={{ color: colors.textMuted }}>{ip}</span>
              <span style={{ color: colors.success }}>{queries.length} queries</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Timeline Panel (NIP-style event feed)
// ============================================================================

function TimelinePanel({ timeline }) {
  const allItems = Array.isArray(timeline) ? timeline : [];
  const [filterCategory, setFilterCategory] = useState('');
  const [filterEntity, setFilterEntity] = useState('');

  const categories = useMemo(() => {
    const cats = new Set();
    allItems.forEach(ev => { if (ev.category) cats.add(ev.category); });
    return Array.from(cats).sort();
  }, [allItems]);

  const items = useMemo(() => {
    let filtered = allItems;
    if (filterCategory) filtered = filtered.filter(ev => (ev.category || '') === filterCategory);
    if (filterEntity.trim()) {
      const q = filterEntity.trim().toLowerCase();
      filtered = filtered.filter(ev => ((ev.entity || '') + ' ' + (ev.summary || '')).toLowerCase().includes(q));
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
    <div style={{
      background: colors.bgCard,
      border: `1px solid ${colors.border}`,
      borderRadius: '12px',
      padding: '16px',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      minHeight: '260px'
    }}>
      <div style={{
        fontSize: '12px',
        fontWeight: 700,
        color: colors.text,
        marginBottom: '8px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <span style={{ color: colors.accent }}>&#9673;</span>
        TIMELINE ({items.length}/{allItems.length})
      </div>

      <div style={{ display: 'flex', gap: '6px', marginBottom: '10px', flexWrap: 'wrap' }}>
        <select value={filterCategory} onChange={e => setFilterCategory(e.target.value)} style={{ fontSize: '10px', padding: '3px 6px', borderRadius: '6px', border: `1px solid ${colors.border}`, background: colors.bgTertiary, color: colors.text }}>
          <option value="">All categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <input value={filterEntity} onChange={e => setFilterEntity(e.target.value)} placeholder="Filter entity/text..." style={{ fontSize: '10px', padding: '3px 8px', borderRadius: '6px', border: `1px solid ${colors.border}`, background: colors.bgTertiary, color: colors.text, flex: 1, minWidth: '100px', outline: 'none' }} />
        {(filterCategory || filterEntity) && <button onClick={() => { setFilterCategory(''); setFilterEntity(''); }} style={{ fontSize: '9px', padding: '3px 8px', borderRadius: '6px', border: `1px solid ${colors.danger}55`, background: `${colors.danger}22`, color: colors.danger, cursor: 'pointer' }}>Clear</button>}
      </div>

      {items.length === 0 ? (
        <div style={{ color: colors.textMuted, fontSize: '11px' }}>
          {allItems.length === 0 ? 'No timeline events yet. Start capture, run a scan, or run multi-chain.' : 'No events match the current filter.'}
        </div>
      ) : (
        <div style={{ flex: 1, overflow: 'auto' }}>
          {items.slice(0, 200).map((ev, i) => (
            <div key={i} style={{
              padding: '10px 10px',
              borderRadius: '10px',
              border: `1px solid ${colors.border}`,
              background: colors.bgTertiary,
              marginBottom: '8px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', marginBottom: '6px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                  <span style={{
                    background: `${colorForCategory(ev.category)}22`,
                    border: `1px solid ${colorForCategory(ev.category)}44`,
                    color: colorForCategory(ev.category),
                    padding: '2px 8px',
                    borderRadius: '999px',
                    fontSize: '9px',
                    fontWeight: 800,
                    whiteSpace: 'nowrap',
                    cursor: 'pointer',
                  }} onClick={() => setFilterCategory(ev.category)}>{ev.category}</span>
                  <span style={{ color: colors.textMuted, fontSize: '10px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'pointer' }} onClick={() => setFilterEntity(ev.entity || '')}>
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

// ============================================================================
// Network Info Panel - Shows diagnostic info, VPN detection, etc.
// ============================================================================

function NetworkInfoPanel({ diag, status }) {
  if (!diag) return null;
  
  const isVPN = diag.vpn_detected;
  const canScan = diag.can_arp_scan;
  
  return (
    <div style={{
      background: isVPN ? `${colors.warning}11` : colors.bgCard,
      border: `1px solid ${isVPN ? colors.warning : colors.border}`,
      borderRadius: '12px',
      padding: '16px',
      marginBottom: '16px'
    }}>
      <div style={{ 
        fontSize: '12px', 
        fontWeight: 600, 
        color: colors.text, 
        marginBottom: '12px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <span style={{ fontSize: '16px' }}>{isVPN ? '🔐' : '🌐'}</span>
        NETWORK INFO
        {isVPN && (
          <span style={{ 
            background: colors.warning, 
            color: colors.bg, 
            padding: '2px 8px', 
            borderRadius: '4px', 
            fontSize: '9px',
            fontWeight: 700
          }}>
            VPN DETECTED
          </span>
        )}
      </div>
      
      {/* Network Details Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>LOCAL IP</div>
          <div style={{ fontSize: '13px', color: colors.success, fontFamily: 'monospace' }}>{diag.local_ip}</div>
        </div>
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>GATEWAY</div>
          <div style={{ fontSize: '13px', color: colors.accent, fontFamily: 'monospace' }}>{diag.gateway_ip}</div>
        </div>
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>SUBNET</div>
          <div style={{ fontSize: '13px', color: colors.text, fontFamily: 'monospace' }}>{diag.network}</div>
        </div>
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>PUBLIC IP</div>
          <div style={{ fontSize: '13px', color: colors.purple, fontFamily: 'monospace' }}>{diag.public_ip || 'Unknown'}</div>
        </div>
        {diag.dns_servers && diag.dns_servers.length > 0 && (
          <div>
            <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>DNS SERVERS</div>
            <div style={{ fontSize: '11px', color: colors.text, fontFamily: 'monospace' }}>
              {diag.dns_servers.slice(0, 2).join(', ')}
            </div>
          </div>
        )}
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>NETWORK TYPE</div>
          <div style={{ fontSize: '11px', color: colors.text, textTransform: 'capitalize' }}>
            {diag.network_type === 'vpn_or_enterprise' ? '🔐 VPN/Enterprise' : 
             diag.network_type === 'home' ? '🏠 Home Network' :
             diag.network_type === 'corporate' ? '🏢 Corporate' : '❓ Unknown'}
          </div>
        </div>
      </div>
      
      {/* Issues */}
      {diag.issues && diag.issues.length > 0 && (
        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '10px', color: colors.warning, marginBottom: '6px', fontWeight: 600 }}>
            ⚠️ ISSUES DETECTED
          </div>
          <div style={{ background: colors.bgTertiary, borderRadius: '6px', padding: '8px' }}>
            {diag.issues.map((issue, i) => (
              <div key={i} style={{ fontSize: '10px', color: colors.textMuted, marginBottom: i < diag.issues.length - 1 ? '4px' : 0 }}>
                • {issue}
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* Recommendations */}
      {diag.recommendations && diag.recommendations.length > 0 && (
        <div>
          <div style={{ fontSize: '10px', color: colors.success, marginBottom: '6px', fontWeight: 600 }}>
            💡 RECOMMENDATIONS
          </div>
          <div style={{ background: colors.bgTertiary, borderRadius: '6px', padding: '8px' }}>
            {diag.recommendations.slice(0, 3).map((rec, i) => (
              <div key={i} style={{ fontSize: '10px', color: colors.textMuted, marginBottom: i < 2 ? '4px' : 0 }}>
                • {rec}
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* Scan Status */}
      <div style={{ 
        marginTop: '12px', 
        padding: '10px', 
        background: canScan ? `${colors.success}15` : `${colors.warning}15`,
        borderRadius: '6px',
        border: `1px solid ${canScan ? colors.success : colors.warning}33`
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '16px' }}>{canScan ? '✅' : '🔄'}</span>
            <div>
              <div style={{ fontSize: '11px', fontWeight: 600, color: canScan ? colors.success : colors.warning }}>
                {canScan ? 'Standard ARP Scan Available' : 'Smart Scan Mode Active'}
              </div>
              <div style={{ fontSize: '9px', color: colors.textMuted, marginTop: '2px' }}>
                {canScan 
                  ? 'Fast device discovery via ARP broadcasting'
                  : 'Using ICMP + TCP probing for VPN/restricted networks'
                }
              </div>
            </div>
          </div>
          {!canScan && diag.network_type && (
            <div style={{
              padding: '4px 10px',
              background: colors.purple,
              borderRadius: '12px',
              fontSize: '9px',
              fontWeight: 600,
              color: '#fff',
              textTransform: 'uppercase',
              letterSpacing: '0.5px'
            }}>
              {diag.network_type.replace('_', ' ')}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


// ============================================================================
// Alerts Panel
// ============================================================================

function AlertsPanel({ alerts }) {
  const severityColors = {
    critical: colors.danger,
    high: colors.orange,
    medium: colors.warning,
    low: colors.textMuted
  };
  
  return (
    <div style={{
      background: colors.bgCard,
      border: `1px solid ${colors.border}`,
      borderRadius: '12px',
      padding: '16px',
      height: '100%'
    }}>
      <div style={{ 
        fontSize: '12px', 
        fontWeight: 600, 
        color: colors.text, 
        marginBottom: '12px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <span style={{ color: colors.danger }}>⚠</span>
        SECURITY ALERTS ({alerts?.length || 0})
      </div>
      
      <div style={{ maxHeight: '250px', overflow: 'auto' }}>
        {(!alerts || alerts.length === 0) ? (
          <div style={{ color: colors.textMuted, fontSize: '11px', textAlign: 'center', padding: '20px' }}>
            No alerts detected
          </div>
        ) : (
          alerts.map((alert, i) => (
            <div key={i} style={{
              background: colors.bgTertiary,
              borderRadius: '8px',
              padding: '10px',
              marginBottom: '8px',
              borderLeft: `3px solid ${severityColors[alert.severity] || colors.textMuted}`
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                <span style={{ 
                  fontSize: '9px', 
                  fontWeight: 600,
                  color: severityColors[alert.severity],
                  textTransform: 'uppercase'
                }}>
                  {alert.severity}
                </span>
                <span style={{ fontSize: '9px', color: colors.textDim }}>
                  {alert.timestamp?.split('T')[1]?.substring(0, 8)}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: colors.text }}>
                {alert.message}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Top Talkers Panel
// ============================================================================

function TopTalkersPanel({ talkers, devices }) {
  const maxBytes = talkers?.[0]?.bytes || 1;
  
  // Service colors
  const serviceColors = {
    'Amazon AWS': '#FF9900',
    'Google': '#4285F4',
    'Microsoft Azure': '#00A4EF',
    'Cloudflare': '#F38020',
    'Meta/Facebook': '#1877F2',
    'Apple': '#A3AAAE',
    'Netflix': '#E50914',
    'Akamai CDN': '#0096D6',
    'SSDP/UPnP Multicast': colors.purple,
    'Private Network': colors.success,
  };
  
  return (
    <div style={{
      background: colors.bgCard,
      border: `1px solid ${colors.border}`,
      borderRadius: '12px',
      padding: '16px',
      height: '100%'
    }}>
      <div style={{ 
        fontSize: '12px', 
        fontWeight: 600, 
        color: colors.text, 
        marginBottom: '12px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <span style={{ color: colors.success }}>▲</span>
        TOP TALKERS
      </div>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '350px', overflow: 'auto' }}>
        {(talkers || []).slice(0, 12).map((talker, i) => {
          // Handle both old format [ip, bytes] and new format {ip, bytes, service, ...}
          const ip = talker.ip || talker[0];
          const bytes = talker.bytes || talker[1];
          const service = talker.service || '';
          const hostname = talker.hostname || '';
          const country = talker.country || '';
          const org = talker.org || '';
          const isLocal = talker.is_local;
          
          const pct = (bytes / maxBytes) * 100;
          const barColor = serviceColors[service] || (isLocal ? colors.success : colors.accentDim);
          
          return (
            <div key={ip} style={{ 
              background: colors.bgTertiary, 
              borderRadius: '8px', 
              padding: '10px',
              borderLeft: `3px solid ${barColor}`
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '4px' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '11px', color: colors.text, fontWeight: 500 }}>
                    {hostname || ip}
                  </div>
                  {hostname && (
                    <div style={{ fontSize: '9px', color: colors.textDim }}>{ip}</div>
                  )}
                </div>
                <span style={{ fontSize: '11px', color: colors.accent, fontWeight: 600, marginLeft: '8px' }}>
                  {formatBytes(bytes)}
                </span>
              </div>
              
              {/* Service/Location info */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '6px' }}>
                {service && (
                  <span style={{ 
                    fontSize: '9px', 
                    background: barColor + '22',
                    color: barColor,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontWeight: 500
                  }}>
                    {service}
                  </span>
                )}
                {country && country !== 'Local' && country !== 'Unknown' && (
                  <span style={{ 
                    fontSize: '9px', 
                    background: colors.bgSecondary,
                    color: colors.textMuted,
                    padding: '2px 6px',
                    borderRadius: '4px'
                  }}>
                    📍 {country}
                  </span>
                )}
                {org && !service && (
                  <span style={{ 
                    fontSize: '9px', 
                    color: colors.textDim,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    maxWidth: '150px'
                  }}>
                    {org}
                  </span>
                )}
              </div>
              
              {/* Progress bar */}
              <div style={{ 
                height: '3px', 
                background: colors.bgSecondary, 
                borderRadius: '2px',
                overflow: 'hidden'
              }}>
                <div style={{
                  width: `${pct}%`,
                  height: '100%',
                  background: barColor,
                  borderRadius: '2px'
                }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ============================================================================
// Intelligence Story Panel
// ============================================================================

function IntelStoryPanel({ story }) {
  return (
    <div style={{
      background: colors.bgCard,
      border: `1px solid ${colors.border}`,
      borderRadius: '12px',
      padding: '16px',
      height: '100%'
    }}>
      <div style={{
        fontSize: '12px',
        fontWeight: 600,
        color: colors.text,
        marginBottom: '12px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <span style={{ color: colors.accent }}>◆</span>
        INTEL STORY
      </div>

      {!story ? (
        <div style={{ color: colors.textMuted, fontSize: '11px' }}>Waiting for telemetry…</div>
      ) : (
        <>
          <div style={{
            fontSize: '11px',
            color: colors.text,
            lineHeight: 1.5,
            background: colors.bgTertiary,
            borderRadius: '8px',
            padding: '10px',
            marginBottom: '10px'
          }}>
            {story.summary}
          </div>

          <div style={{ marginBottom: '10px' }}>
            <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '6px' }}>KEY INSIGHTS</div>
            <div style={{ maxHeight: '120px', overflow: 'auto' }}>
              {(story.insights || []).slice(0, 6).map((item, i) => (
                <div key={i} style={{ fontSize: '11px', color: colors.text, marginBottom: '6px' }}>
                  • {item}
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
            <div style={{ background: colors.bgTertiary, borderRadius: '6px', padding: '8px' }}>
              <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>TOP DOMAINS</div>
              {(story.top_domains || []).slice(0, 3).map((d, i) => (
                <div key={`${d.domain}-${i}`} style={{ fontSize: '10px', color: colors.text, marginBottom: '3px' }}>
                  {d.domain} <span style={{ color: colors.accent }}>({d.count})</span>
                </div>
              ))}
            </div>
            <div style={{ background: colors.bgTertiary, borderRadius: '6px', padding: '8px' }}>
              <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>EXPOSED SERVICES</div>
              {(story.exposed_services || []).slice(0, 3).map((s, i) => (
                <div key={`${s.ip}-${s.port}-${i}`} style={{ fontSize: '10px', color: colors.text, marginBottom: '3px' }}>
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

// ============================================================================
// Coursework View (Rubric-Oriented)
// ============================================================================

function humanizeKey(key) {
  return String(key || '')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function compactValue(value) {
  if (value === null || value === undefined || value === '') return '-';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (Number.isFinite(value) && Math.abs(value) >= 1024 && Number.isInteger(value)) {
      return formatNumber(value);
    }
    return Number.isFinite(value) ? String(Math.round(value * 1000) / 1000) : String(value);
  }
  if (typeof value === 'string') {
    return value.length > 140 ? `${value.slice(0, 137)}...` : value;
  }
  if (Array.isArray(value)) return `${value.length} item(s)`;
  if (typeof value === 'object') return `${Object.keys(value || {}).length} field(s)`;
  return String(value);
}

function compactObjectLine(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return compactValue(obj);
  const pairs = Object.entries(obj)
    .filter(([k]) => !String(k).startsWith('_'))
    .slice(0, 6)
    .map(([k, v]) => `${k}=${compactValue(v)}`);
  return pairs.length ? pairs.join('  |  ') : '{}';
}

function extractLogInsights(payload) {
  const root = payload && typeof payload === 'object' ? payload : {};
  const result = (root.result && typeof root.result === 'object') ? root.result : {};

  const metadata = [];
  const pushMeta = (label, value) => {
    if (value === undefined || value === null || value === '') return;
    metadata.push({ label, value: compactValue(value), raw: value });
  };
  pushMeta('Session', root.session_id);
  pushMeta('Module', root.module);
  pushMeta('Technique', result.technique || root.technique);
  pushMeta('Generated', root.generated_at);
  pushMeta('Started', root.started_at);
  pushMeta('Finished', root.finished_at);
  pushMeta('Scanner IP', root.scanner_local_ip);
  pushMeta('Target', result.target || result.host || result.ip || result.network);
  pushMeta('Interface', result.interface);

  const countCards = [];
  const seenLabels = new Set();
  const addCount = (label, value, tone = 'neutral') => {
    if (value === undefined || value === null || value === '' || value === 0) return;
    if (seenLabels.has(label)) return;
    seenLabels.add(label);
    countCards.push({ label, value: compactValue(value), tone });
  };

  const arrayCandidates = [
    ['Hosts', 'hosts', 'neutral'],
    ['Alive Hosts', 'alive_hosts', 'neutral'],
    ['Open Ports', 'open_ports', 'warning'],
    ['Fingerprints', 'fingerprints', 'neutral'],
    ['Alerts', 'alerts', 'danger'],
    ['Matches', 'matches', 'warning'],
    ['Suspicious Domains', 'suspicious_domains', 'danger'],
    ['Risk Entries', 'device_risk', 'warning'],
    ['Clusters', 'clusters', 'neutral'],
    ['Timeline Events', 'timeline', 'neutral'],
    ['Leases', 'leases', 'neutral'],
    ['Queries', 'queries', 'neutral'],
    ['Flows', 'flows', 'neutral'],
  ];
  for (const [label, key, tone] of arrayCandidates) {
    const v = result[key];
    if (Array.isArray(v) && v.length) addCount(label, v.length, tone);
  }

  for (const [k, v] of Object.entries(result)) {
    if (typeof v !== 'number' || !Number.isFinite(v)) continue;
    if (!/(count|total|duration|elapsed|observed|windows|nodes|edges|matches|packets|bytes|rate)/i.test(k)) continue;
    const label = humanizeKey(k);
    if (/bytes/i.test(k)) addCount(label, formatBytes(Math.max(0, Number(v))), 'neutral');
    else addCount(label, v, 'neutral');
  }

  const sections = [];
  const addSection = (title, items) => {
    if (!Array.isArray(items) || items.length === 0) return;
    sections.push({
      title,
      total: items.length,
      rows: items.slice(0, 25),
      truncated: items.length > 25,
    });
  };

  addSection('Discovered Hosts', result.hosts || result.alive_hosts || []);
  addSection('Open Services/Ports', result.open_ports || result.services || []);
  addSection('Protocol Fingerprints', result.fingerprints || []);
  addSection('Risk Findings', result.device_risk || []);
  addSection('Threat Matches', result.matches || []);
  addSection('Suspicious DNS', result.suspicious_domains || []);
  addSection('Attack Chain Phases', result.phases || []);
  addSection('Timeline', result.timeline || []);
  addSection('Clusters', result.clusters || []);
  addSection('DHCP Leases', result.leases || []);
  addSection('Top Domains', result.top_domains || []);
  addSection('Queries', result.queries || []);
  addSection('Alerts', result.alerts || []);

  const highlights = [];
  if (Array.isArray(result.suspicious_domains) && result.suspicious_domains.length > 0) {
    highlights.push({ tone: 'danger', text: `${result.suspicious_domains.length} suspicious DNS domain(s) flagged.` });
  }
  if (Array.isArray(result.matches) && result.matches.length > 0) {
    highlights.push({ tone: 'warning', text: `${result.matches.length} threat/intel match(es) detected.` });
  }
  if (Array.isArray(result.open_ports) && result.open_ports.length > 0) {
    highlights.push({ tone: 'warning', text: `${result.open_ports.length} open port/service finding(s) reported.` });
  }
  if (Array.isArray(result.device_risk) && result.device_risk.length > 0) {
    const high = result.device_risk.filter((r) => Number(r?.score || 0) >= 0.6).length;
    if (high > 0) highlights.push({ tone: 'danger', text: `${high} device(s) have risk score >= 0.60.` });
  }
  if (result.ok === false || root.error) {
    highlights.push({ tone: 'danger', text: 'This run reported a failure or partial error condition.' });
  }
  if (highlights.length === 0) {
    highlights.push({ tone: 'success', text: 'No high-severity indicators detected in this log summary.' });
  }

  const primitives = Object.entries(result)
    .filter(([_k, v]) => ['string', 'number', 'boolean'].includes(typeof v))
    .slice(0, 20)
    .map(([k, v]) => ({ key: humanizeKey(k), value: compactValue(v) }));

  return { metadata, countCards, sections, highlights, primitives };
}

function LogParsedView({ payload }) {
  const insights = useMemo(() => extractLogInsights(payload), [payload]);

  const toneColor = {
    neutral: colors.accent,
    success: colors.success,
    warning: colors.warning,
    danger: colors.danger,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '10px', padding: '10px' }}>
        <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>Interpretation</div>
        {insights.highlights.map((h, i) => (
          <div key={`${h.text}-${i}`} style={{ fontSize: '11px', color: toneColor[h.tone] || colors.text, marginBottom: '5px' }}>
            - {h.text}
          </div>
        ))}
      </div>

      {insights.countCards.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '8px' }}>
          {insights.countCards.slice(0, 12).map((c) => (
            <div key={c.label} style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '10px', padding: '8px' }}>
              <div style={{ fontSize: '9px', color: colors.textMuted }}>{c.label}</div>
              <div style={{ fontSize: '16px', fontWeight: 900, color: toneColor[c.tone] || colors.accent }}>{c.value}</div>
            </div>
          ))}
        </div>
      )}

      {insights.metadata.length > 0 && (
        <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '10px', padding: '10px' }}>
          <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>Run Metadata</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '8px' }}>
            {insights.metadata.map((m) => (
              <div key={`${m.label}-${m.value}`} style={{ background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '8px', padding: '8px' }}>
                <div style={{ fontSize: '9px', color: colors.textMuted }}>{m.label}</div>
                <div style={{ fontSize: '10px', color: colors.text, marginTop: '2px', wordBreak: 'break-word' }}>{m.value}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {insights.sections.map((sec) => (
        <div key={sec.title} style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '10px', padding: '10px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', marginBottom: '8px' }}>
            <div style={{ fontSize: '10px', color: colors.text, fontWeight: 800 }}>{sec.title}</div>
            <div style={{ fontSize: '9px', color: colors.textMuted }}>
              {sec.total} item(s){sec.truncated ? ' (showing first 25)' : ''}
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {sec.rows.map((row, i) => (
              <div key={`${sec.title}-${i}`} style={{ background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '8px', padding: '7px' }}>
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>#{i + 1}</div>
                <div style={{ fontSize: '10px', color: colors.text, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  {typeof row === 'object' ? compactObjectLine(row) : compactValue(row)}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      {insights.sections.length === 0 && insights.primitives.length > 0 && (
        <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '10px', padding: '10px' }}>
          <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>Primary Output Fields</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '8px' }}>
            {insights.primitives.map((p) => (
              <div key={`${p.key}-${p.value}`} style={{ background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '8px', padding: '8px' }}>
                <div style={{ fontSize: '9px', color: colors.textMuted }}>{p.key}</div>
                <div style={{ fontSize: '10px', color: colors.text, marginTop: '2px' }}>{p.value}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CourseworkView({ status }) {
  const network = status?.network || '192.168.56.0/24';
  const ifaceHint = (status?.interfaces && status.interfaces[0]) ? status.interfaces[0] : 'eth0';

  const [cwStatus, setCwStatus] = useState(null);
  const [cwLoading, setCwLoading] = useState(false);
  const [logBrowser, setLogBrowser] = useState({ open: false, module: null, files: [], loading: false, selected: null, content: null, error: null });
  const [logTab, setLogTab] = useState('summary');
  const [viewer, setViewer] = useState({ open: false, title: '', loading: false, error: null, isJson: true, json: null, content: '' });
  const [cwJobs, setCwJobs] = useState([]);
  const [jobsLoading, setJobsLoading] = useState(false);
  const [showRunnerAdvanced, setShowRunnerAdvanced] = useState(false);
	  const [runner, setRunner] = useState(() => ({
    network,
    iface: ifaceHint,
    targetIp: '',
    zombieIp: '',
    tcpPorts: '22,80,443',
    udpPorts: '53,123,161',
	    bannerPorts: '21,22,25,80,443',
	    domain: '',
	    dnsServer: '8.8.8.8',
		    reverseCidr: '',
		    reverseMax: 256,
		    dhcpServer: '',
		    snmpCommunity: 'public',
		    mqttPort: 1883,
		    coapPort: 5683,
		    wirelessIface: ifaceHint,
		    cveProduct: '',
		    cveVersion: '',
		    feedPath: 'samples/threat_indicators.json',
		    extraSnis: '',
		    anchorTs: '',
		    graphT1: '',
		    graphT2: '',
		    decoysCsv: '',
	    durationShort: 60,
	    durationLong: 600,
	    durationArpwatch: 300,
    maxTuples: 10,
    httpPort: 80,
    httpUseTls: false,
    tlsPort: 443,
    dport: 80,
    fragsize: 8,
    overlap: true,
    ttlMethod: 'icmp',
    maxHops: 20,
    labOk: false,
	    netflowPort: 2055,
	    pcapPath: '',
	    pcapOut: 'report/capture.pcap',
	    bpf: '',
	    suricataEve: 'report/suricata/eve.json',
	    zeekNotice: 'report/zeek/notice.log',
	  }));

  const refreshCw = async () => {
    setCwLoading(true);
    try {
      const data = await fetchJsonOrThrow(`${API_BASE}/coursework/status`);
      setCwStatus(data);
    } catch (e) {
      console.error('Failed to load coursework status:', e);
    }
    setCwLoading(false);
  };

  useEffect(() => { refreshCw(); }, []);
  useEffect(() => {
    // Fill defaults from live status without overwriting user edits.
    setRunner((r) => ({
      ...r,
      network: r.network || network,
      iface: r.iface || ifaceHint,
    }));
  }, [network, ifaceHint]);

  const refreshJobs = async () => {
    setJobsLoading(true);
    try {
      const data = await fetchJsonOrThrow(`${API_BASE}/coursework/jobs?limit=20`);
      setCwJobs(data?.jobs || []);
    } catch (e) {
      console.error('Failed to load coursework jobs:', e);
      setCwJobs([]);
    }
    setJobsLoading(false);
  };

  useEffect(() => { refreshJobs(); }, []);
  useEffect(() => {
    const active = (cwJobs || []).some((j) => (j.status === 'queued' || j.status === 'running'));
    if (!active) return;
    const t = setInterval(() => { refreshJobs(); refreshCw(); }, 2000);
    return () => clearInterval(t);
  }, [cwJobs]);

  const startJob = async (module, action, params) => {
    try {
      await fetchJsonOrThrow(`${API_BASE}/coursework/jobs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ module, action, params })
      });
      refreshJobs();
      refreshCw();
    } catch (e) {
      console.error(`Failed to start coursework job ${module}:${action}:`, e);
    }
  };

  const openLogBrowser = async (module, initialFile = null) => {
    setLogTab('summary');
    setLogBrowser({ open: true, module, files: [], loading: true, selected: null, content: null, error: null });
    try {
      const data = await fetchJsonOrThrow(`${API_BASE}/coursework/logs/${module}?limit=100`);
      const files = data?.files || [];
      setLogBrowser((s) => ({ ...s, files, loading: false }));
      const chosen = initialFile || files[0]?.file;
      if (chosen) await loadLogFile(module, chosen);
    } catch (e) {
      setLogBrowser((s) => ({ ...s, loading: false, error: `Failed to load log list: ${e.message || 'unknown error'}` }));
    }
  };

  const loadLogFile = async (module, filename) => {
    setLogTab('summary');
    setLogBrowser((s) => ({ ...s, loading: true, selected: filename, content: null, error: null }));
    try {
      const data = await fetchJsonOrThrow(`${API_BASE}/coursework/log/${module}/${encodeURIComponent(filename)}`);
      setLogBrowser((s) => ({ ...s, loading: false, content: data }));
    } catch (e) {
      setLogBrowser((s) => ({ ...s, loading: false, error: `Failed to load log file: ${e.message || 'unknown error'}` }));
    }
  };

  const closeLogBrowser = () => setLogBrowser((s) => ({ ...s, open: false }));

  const openArtifact = async (name) => {
    setViewer({ open: true, title: name, loading: true, error: null, isJson: true, json: null, content: '' });
    try {
      const data = await fetchJsonOrThrow(`${API_BASE}/coursework/report/${encodeURIComponent(name)}`);
      if (data?.json !== undefined) {
        setViewer({ open: true, title: name, loading: false, error: null, isJson: true, json: data.json, content: '' });
      } else {
        setViewer({ open: true, title: name, loading: false, error: null, isJson: false, json: null, content: data?.content || '' });
      }
    } catch (e) {
      setViewer({ open: true, title: name, loading: false, error: `Failed to load artifact: ${e.message || 'unknown error'}`, isJson: true, json: null, content: '' });
    }
  };

  const closeViewer = () => setViewer((s) => ({ ...s, open: false }));

  const openJobLog = (job) => {
    const mod = job?.module;
    const lp = job?.log_path || '';
    const fname = lp ? lp.split('/').pop() : '';
    if (mod && fname) openLogBrowser(mod, fname);
  };

  const targetOr = (v, placeholder) => (v && v.toString().trim()) ? v.toString().trim() : placeholder;
  const parseCsv = (s) => (s || '').split(',').map(x => x.trim()).filter(Boolean);

	  const blocks = [
    {
      module: 'mod1',
      title: 'Module 1: Link-Layer Discovery',
      desc: 'Active ARP, passive ARP, and MAC randomization with timing/coverage metrics.',
      cmds: [
        {
          label: '1a Active ARP Enumeration',
          cmd: `sudo venv/bin/python mod1/link_layer_discovery.py active --network ${runner.network} --interface ${runner.iface}`,
          run: { module: 'mod1', action: 'active', params: { network: runner.network, interface: runner.iface } },
          needs: ['network', 'iface']
        },
        {
          label: '1b Passive ARP Observation',
          cmd: `sudo venv/bin/python mod1/link_layer_discovery.py passive --duration ${runner.durationLong} --interface ${runner.iface}`,
          run: { module: 'mod1', action: 'passive', params: { interface: runner.iface, duration: runner.durationLong } },
          needs: ['iface']
        },
        {
          label: '1c MAC Address Randomization',
          cmd: `sudo venv/bin/python mod1/link_layer_discovery.py randomized --network ${runner.network} --interface ${runner.iface}`,
          run: { module: 'mod1', action: 'randomized', params: { network: runner.network, interface: runner.iface } },
          needs: ['network', 'iface']
        },
      ],
    },
    {
      module: 'mod2',
      title: 'Module 2: Transport Scans',
      desc: 'SYN/connect/FIN/XMAS/NULL/UDP/ACK scans with logging and timing controls.',
      cmds: [
        {
          label: '2a TCP SYN (Half-Open)',
          cmd: `sudo venv/bin/python mod2/transport_scans.py --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.tcpPorts} syn`,
          run: runner.targetIp ? { module: 'mod2', action: 'syn', params: { hosts: [runner.targetIp], ports: runner.tcpPorts } } : null,
          needs: ['targetIp', 'tcpPorts']
        },
        {
          label: '2b TCP Connect',
          cmd: `sudo venv/bin/python mod2/transport_scans.py --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.tcpPorts} connect`,
          run: runner.targetIp ? { module: 'mod2', action: 'connect', params: { hosts: [runner.targetIp], ports: runner.tcpPorts } } : null,
          needs: ['targetIp', 'tcpPorts']
        },
        {
          label: '2c TCP FIN',
          cmd: `sudo venv/bin/python mod2/transport_scans.py --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.tcpPorts} fin`,
          run: runner.targetIp ? { module: 'mod2', action: 'fin', params: { hosts: [runner.targetIp], ports: runner.tcpPorts } } : null,
          needs: ['targetIp', 'tcpPorts']
        },
        {
          label: '2d TCP XMAS',
          cmd: `sudo venv/bin/python mod2/transport_scans.py --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.tcpPorts} xmas`,
          run: runner.targetIp ? { module: 'mod2', action: 'xmas', params: { hosts: [runner.targetIp], ports: runner.tcpPorts } } : null,
          needs: ['targetIp', 'tcpPorts']
        },
        {
          label: '2e TCP NULL',
          cmd: `sudo venv/bin/python mod2/transport_scans.py --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.tcpPorts} null`,
          run: runner.targetIp ? { module: 'mod2', action: 'null', params: { hosts: [runner.targetIp], ports: runner.tcpPorts } } : null,
          needs: ['targetIp', 'tcpPorts']
        },
        {
          label: '2f UDP Scan',
          cmd: `sudo venv/bin/python mod2/transport_scans.py --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.udpPorts} udp`,
          run: runner.targetIp ? { module: 'mod2', action: 'udp', params: { hosts: [runner.targetIp], ports: runner.udpPorts } } : null,
          needs: ['targetIp', 'udpPorts']
        },
        {
          label: '2g TCP ACK Scan',
          cmd: `sudo venv/bin/python mod2/transport_scans.py --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.tcpPorts} ack`,
          run: runner.targetIp ? { module: 'mod2', action: 'ack', params: { hosts: [runner.targetIp], ports: runner.tcpPorts } } : null,
          needs: ['targetIp', 'tcpPorts']
        },
      ],
    },
    {
      module: 'mod3',
      title: 'Module 3: IP-Layer Techniques',
      desc: 'Fragmentation, TTL path inference, IPID profiling, and lab-only spoofing exercises.',
      cmds: [
        {
          label: '3a IP Fragmentation',
          cmd: `sudo venv/bin/python mod3/ip_layer_techniques.py frag --target ${targetOr(runner.targetIp, '<TARGET_IP>')} --dport ${runner.dport} --fragsize ${runner.fragsize}${runner.overlap ? ' --overlap' : ''}`,
          run: runner.targetIp ? { module: 'mod3', action: 'frag', params: { target: runner.targetIp, dport: runner.dport, fragsize: runner.fragsize, overlap: runner.overlap } } : null,
          needs: ['targetIp']
        },
        {
          label: '3b TTL-Based Path Inference',
          cmd: `sudo venv/bin/python mod3/ip_layer_techniques.py ttl --target ${targetOr(runner.targetIp, '<TARGET_IP>')} --max-hops ${runner.maxHops} --method ${runner.ttlMethod} --dport ${runner.dport}`,
          run: runner.targetIp ? { module: 'mod3', action: 'ttl', params: { target: runner.targetIp, max_hops: runner.maxHops, method: runner.ttlMethod, dport: runner.dport } } : null,
          needs: ['targetIp']
        },
        {
          label: '3c IPID Profile',
          cmd: `sudo venv/bin/python mod3/ip_layer_techniques.py ipid --zombie ${targetOr(runner.zombieIp, '<ZOMBIE_IP>')} --probes 25`,
          run: runner.zombieIp ? { module: 'mod3', action: 'ipid', params: { zombie: runner.zombieIp, probes: 25 } } : null,
          needs: ['zombieIp']
        },
        {
          label: '3c IPID Sweep (Find Zombies)',
          cmd: `sudo venv/bin/python mod3/ip_layer_techniques.py ipid-sweep --network ${runner.network} --max-hosts 64 --probes 12`,
          run: { module: 'mod3', action: 'ipid-sweep', params: { network: runner.network, max_hosts: 64, probes: 12 } },
          needs: ['network']
        },
        {
          label: '3c Idle Scan (Lab Only)',
          cmd: `sudo venv/bin/python mod3/ip_layer_techniques.py idle --lab-ok --zombie ${targetOr(runner.zombieIp, '<ZOMBIE_IP>')} --target ${targetOr(runner.targetIp, '<TARGET_IP>')} --dport ${runner.dport}`,
          run: (runner.labOk && runner.zombieIp && runner.targetIp) ? { module: 'mod3', action: 'idle', params: { lab_ok: true, zombie: runner.zombieIp, target: runner.targetIp, dport: runner.dport } } : null,
          needs: ['labOk', 'zombieIp', 'targetIp']
        },
        {
          label: '3d Decoy Mixing (Lab Only)',
          cmd: `sudo venv/bin/python mod3/ip_layer_techniques.py decoy --lab-ok --target ${targetOr(runner.targetIp, '<TARGET_IP>')} --dport ${runner.dport} --decoy <DECOY_IP_1> --decoy <DECOY_IP_2>`,
          run: (runner.labOk && runner.targetIp && parseCsv(runner.decoysCsv).length > 0) ? { module: 'mod3', action: 'decoy', params: { lab_ok: true, target: runner.targetIp, dport: runner.dport, decoys: parseCsv(runner.decoysCsv) } } : null,
          needs: ['labOk', 'targetIp', 'decoysCsv']
        },
      ],
    },
    {
      module: 'mod4',
      title: 'Module 4: Timing + Rate Control',
      desc: 'Fixed-rate profiles, jitter distributions, and tuple ordering randomization.',
      cmds: [
        {
          label: '4a Fixed-Rate Profiles',
          cmd: `sudo venv/bin/python mod4/timing_rate_control.py fixed --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.tcpPorts} --max-tuples ${runner.maxTuples}`,
          run: runner.targetIp ? { module: 'mod4', action: 'fixed', params: { hosts: [runner.targetIp], ports: runner.tcpPorts, max_tuples: runner.maxTuples } } : null,
          needs: ['targetIp', 'tcpPorts']
        },
        {
          label: '4b Randomized Jitter',
          cmd: `sudo venv/bin/python mod4/timing_rate_control.py jitter --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.tcpPorts} --base-delay 0.4 --max-tuples ${runner.maxTuples}`,
          run: runner.targetIp ? { module: 'mod4', action: 'jitter', params: { hosts: [runner.targetIp], ports: runner.tcpPorts, base_delay: 0.4, max_tuples: runner.maxTuples } } : null,
          needs: ['targetIp', 'tcpPorts']
        },
        {
          label: '4c Target Ordering Randomization',
          cmd: `sudo venv/bin/python mod4/timing_rate_control.py order --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.tcpPorts} --delay 0.4 --max-tuples ${runner.maxTuples}`,
          run: runner.targetIp ? { module: 'mod4', action: 'order', params: { hosts: [runner.targetIp], ports: runner.tcpPorts, delay: 0.4, max_tuples: runner.maxTuples } } : null,
          needs: ['targetIp', 'tcpPorts']
        },
      ],
    },
    {
      module: 'mod5',
      title: 'Module 5: App Fingerprinting',
      desc: 'Banner grabs, TLS chain parsing, HTTP security posture, TCP fingerprints, DNS enumeration, passive DNS.',
      cmds: [
        {
          label: '5a Banner Grabbing',
          cmd: `sudo venv/bin/python mod5/app_fingerprinting.py banner --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --ports ${runner.bannerPorts}`,
          run: runner.targetIp ? { module: 'mod5', action: 'banner', params: { host: runner.targetIp, ports: runner.bannerPorts } } : null,
          needs: ['targetIp', 'bannerPorts']
        },
        {
          label: '5b TLS Certificate Inspection',
          cmd: `venv/bin/python mod5/app_fingerprinting.py tls --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --port ${runner.tlsPort}`,
          run: runner.targetIp ? { module: 'mod5', action: 'tls', params: { host: runner.targetIp, port: runner.tlsPort } } : null,
          needs: ['targetIp']
        },
        {
          label: '5c HTTP Header Analysis',
          cmd: `venv/bin/python mod5/app_fingerprinting.py http --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --port ${runner.httpPort}${runner.httpUseTls ? ' --tls' : ''}`,
          run: runner.targetIp ? { module: 'mod5', action: 'http', params: { host: runner.targetIp, port: runner.httpPort, use_tls: runner.httpUseTls } } : null,
          needs: ['targetIp']
        },
        {
          label: '5d TCP Stack Fingerprinting',
          cmd: `sudo venv/bin/python mod5/app_fingerprinting.py tcpfp --host ${targetOr(runner.targetIp, '<TARGET_IP>')} --dport ${runner.dport}`,
          run: runner.targetIp ? { module: 'mod5', action: 'tcpfp', params: { host: runner.targetIp, dport: runner.dport } } : null,
          needs: ['targetIp']
        },
	        {
	          label: '5e DNS Enumeration',
	          cmd: `venv/bin/python mod5/app_fingerprinting.py dns --domain ${targetOr(runner.domain, '<DOMAIN>')} --server ${runner.dnsServer}${runner.reverseCidr ? ` --reverse-cidr ${runner.reverseCidr} --reverse-max ${runner.reverseMax}` : ''}`,
	          run: runner.domain ? { module: 'mod5', action: 'dns', params: { domain: runner.domain, server: runner.dnsServer, reverse_cidr: runner.reverseCidr, reverse_max: runner.reverseMax } } : null,
	          needs: ['domain']
	        },
        {
          label: '5e Passive DNS (Lab)',
          cmd: `sudo venv/bin/python mod5/app_fingerprinting.py passive-dns --interface ${runner.iface} --duration ${runner.durationShort}`,
          run: { module: 'mod5', action: 'passive-dns', params: { interface: runner.iface, duration: runner.durationShort } },
          needs: ['iface']
        },
      ],
    },
    {
      module: 'mod6',
      title: 'Module 6: Passive Collection',
      desc: 'Promisc capture parsing L2–L7, SPAN via pcap ingestion, NetFlow v5 analytics.',
      cmds: [
	        {
	          label: '6a Promiscuous-Mode Capture',
	          cmd: `sudo venv/bin/python mod6/passive_collection.py promisc --interface ${runner.iface} --duration ${runner.durationShort}${runner.bpf ? ` --bpf \"${runner.bpf}\"` : ''}${runner.pcapOut ? ` --pcap-out ${runner.pcapOut}` : ''}`,
	          run: { module: 'mod6', action: 'promisc', params: { interface: runner.iface, duration: runner.durationShort, bpf: runner.bpf, pcap_out: runner.pcapOut } },
	          needs: ['iface']
	        },
        {
          label: '6b SPAN / Mirror Ingestion (PCAP)',
          cmd: `venv/bin/python mod6/passive_collection.py pcap --path ${targetOr(runner.pcapPath, '/path/to/span_capture.pcap')}`,
          run: runner.pcapPath ? { module: 'mod6', action: 'pcap', params: { path: runner.pcapPath } } : null,
          needs: ['pcapPath']
        },
        {
          label: '6c NetFlow v5 Collection',
          cmd: `sudo venv/bin/python mod6/passive_collection.py netflow --listen-port ${runner.netflowPort} --duration ${runner.durationShort}`,
          run: { module: 'mod6', action: 'netflow', params: { listen_port: runner.netflowPort, duration: runner.durationShort } },
          needs: []
        },
      ],
    },
	    {
	      module: 'mod7',
	      title: 'Module 7: Detection',
	      desc: 'Suricata rules, Zeek script, ARPwatch-style monitoring, and NetFlow-based alerting.',
	      cmds: [
	        {
	          label: '7a Suricata Offline (PCAP)',
	          cmd: `suricata -r ${targetOr(runner.pcapPath, '/path/to/capture.pcap')} -S mod7/suricata.rules -l report/suricata`,
	          run: runner.pcapPath ? { module: 'mod7', action: 'suricata-offline', params: { pcap_path: runner.pcapPath } } : null,
	          needs: ['pcapPath']
	        },
	        {
	          label: '7b Zeek Offline (PCAP)',
	          cmd: `zeek -r ${targetOr(runner.pcapPath, '/path/to/capture.pcap')} mod7/zeek/scan_detect.zeek`,
	          run: runner.pcapPath ? { module: 'mod7', action: 'zeek-offline', params: { pcap_path: runner.pcapPath } } : null,
	          needs: ['pcapPath']
	        },
	        {
	          label: '7c ARPwatch-Style Monitor',
	          cmd: `sudo venv/bin/python mod7/arpwatch_like.py --interface ${runner.iface} --duration ${runner.durationArpwatch}`,
          run: { module: 'mod7', action: 'arpwatch', params: { interface: runner.iface, duration: runner.durationArpwatch } },
          needs: ['iface']
        },
        {
          label: '7c NetFlow Alerting',
          cmd: `sudo venv/bin/python mod7/netflow_detect.py --listen-port ${runner.netflowPort} --duration ${runner.durationShort}`,
          run: { module: 'mod7', action: 'netflow-detect', params: { listen_port: runner.netflowPort, duration: runner.durationShort } },
          needs: []
        },
        {
          label: 'Detection Matrix (Helper)',
          cmd: `venv/bin/python mod7/detection_matrix.py --suricata-eve ${runner.suricataEve} --zeek-notice ${runner.zeekNotice}`,
          run: { module: 'mod7', action: 'detection-matrix', params: { suricata_eve: runner.suricataEve, zeek_notice: runner.zeekNotice } },
          needs: []
        },
      ],
    },
	  ];

	  blocks.push(
	    {
	      module: 'ipv6',
	      title: 'IPv6 Techniques',
	      desc: 'NDP, RA, passive IPv6 discovery, and SLAAC policy analysis.',
	      cmds: [
	        {
	          label: 'IPv6 Neighbor Discovery',
	          cmd: `sudo venv/bin/python ipv6/ipv6_discovery.py nd-scan --interface ${runner.iface}`,
	          run: { module: 'ipv6', action: 'nd-scan', params: { interface: runner.iface } },
	          needs: ['iface']
	        },
	        {
	          label: 'IPv6 Router Advertisement Scan',
	          cmd: `sudo venv/bin/python ipv6/ipv6_discovery.py ra-scan --interface ${runner.iface}`,
	          run: { module: 'ipv6', action: 'ra-scan', params: { interface: runner.iface } },
	          needs: ['iface']
	        },
	        {
	          label: 'Passive IPv6 NDP Monitor',
	          cmd: `sudo venv/bin/python ipv6/ipv6_discovery.py passive-ndp --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'ipv6', action: 'passive-ndp', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	        {
	          label: 'IPv6 SLAAC Fingerprint',
	          cmd: `venv/bin/python ipv6/ipv6_discovery.py slaac-fp`,
	          run: { module: 'ipv6', action: 'slaac-fp', params: {} },
	          needs: []
	        },
	      ],
	    },
	    {
	      module: 'dhcp',
	      title: 'DHCP Intelligence',
	      desc: 'Passive DHCP lease intelligence, DHCP fingerprinting, and rogue server detection.',
	      cmds: [
	        {
	          label: 'Passive DHCP Monitor',
	          cmd: `sudo venv/bin/python dhcp/dhcp_intel.py passive-dhcp --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'dhcp', action: 'passive-dhcp', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	        {
	          label: 'DHCP Fingerprinting',
	          cmd: `sudo venv/bin/python dhcp/dhcp_intel.py fingerprint --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'dhcp', action: 'fingerprint', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	        {
	          label: 'Rogue DHCP Detection',
	          cmd: `sudo venv/bin/python dhcp/dhcp_intel.py rogue-detect --interface ${runner.iface}${runner.dhcpServer ? ` --known-server-ip ${runner.dhcpServer}` : ''}`,
	          run: { module: 'dhcp', action: 'rogue-detect', params: { interface: runner.iface, known_server_ip: runner.dhcpServer } },
	          needs: ['iface']
	        },
	      ],
	    },
	    {
	      module: 'discovery',
	      title: 'Multicast/Broadcast Discovery',
	      desc: 'mDNS, SSDP/UPnP, NBNS, LLMNR, and WS-Discovery inventory.',
	      cmds: [
	        {
	          label: 'mDNS Active Discovery',
	          cmd: `sudo venv/bin/python discovery/multicast_discovery.py mdns --interface ${runner.iface}`,
	          run: { module: 'discovery', action: 'mdns', params: { interface: runner.iface } },
	          needs: ['iface']
	        },
	        {
	          label: 'mDNS Passive Monitor',
	          cmd: `sudo venv/bin/python discovery/multicast_discovery.py mdns-passive --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'discovery', action: 'mdns-passive', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	        {
	          label: 'SSDP/UPnP Discovery',
	          cmd: `venv/bin/python discovery/multicast_discovery.py ssdp --interface ${runner.iface}`,
	          run: { module: 'discovery', action: 'ssdp', params: { interface: runner.iface } },
	          needs: ['iface']
	        },
	        {
	          label: 'NBNS Query',
	          cmd: `venv/bin/python discovery/multicast_discovery.py nbns --hosts ${targetOr(runner.targetIp, '<TARGET_IP>')}`,
	          run: runner.targetIp ? { module: 'discovery', action: 'nbns', params: { hosts: [runner.targetIp] } } : { module: 'discovery', action: 'nbns', params: { network: runner.network, max_hosts: 64 } },
	          needs: ['network']
	        },
	        {
	          label: 'LLMNR Passive Monitor',
	          cmd: `sudo venv/bin/python discovery/multicast_discovery.py llmnr-passive --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'discovery', action: 'llmnr-passive', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	        {
	          label: 'WS-Discovery Scan',
	          cmd: `venv/bin/python discovery/multicast_discovery.py wsd --interface ${runner.iface}`,
	          run: { module: 'discovery', action: 'wsd', params: { interface: runner.iface } },
	          needs: ['iface']
	        },
	      ],
	    },
	    {
	      module: 'icmp',
	      title: 'ICMP Recon',
	      desc: 'Echo sweep plus timestamp, address-mask, and ICMP OS hints.',
	      cmds: [
	        {
	          label: 'ICMP Echo Sweep',
	          cmd: `sudo venv/bin/python icmp/icmp_recon.py echo-sweep --network ${runner.network}`,
	          run: { module: 'icmp', action: 'echo-sweep', params: { network: runner.network } },
	          needs: ['network']
	        },
	        {
	          label: 'ICMP Timestamp Request',
	          cmd: `sudo venv/bin/python icmp/icmp_recon.py timestamp --target ${targetOr(runner.targetIp, '<TARGET_IP>')}`,
	          run: runner.targetIp ? { module: 'icmp', action: 'timestamp', params: { target: runner.targetIp } } : null,
	          needs: ['targetIp']
	        },
	        {
	          label: 'ICMP Address Mask Request',
	          cmd: `sudo venv/bin/python icmp/icmp_recon.py address-mask --target ${targetOr(runner.targetIp, '<TARGET_IP>')}`,
	          run: runner.targetIp ? { module: 'icmp', action: 'address-mask', params: { target: runner.targetIp } } : null,
	          needs: ['targetIp']
	        },
	        {
	          label: 'ICMP OS Fingerprint',
	          cmd: `sudo venv/bin/python icmp/icmp_recon.py icmp-os-fp --target ${targetOr(runner.targetIp, '<TARGET_IP>')}`,
	          run: runner.targetIp ? { module: 'icmp', action: 'icmp-os-fp', params: { target: runner.targetIp } } : null,
	          needs: ['targetIp']
	        },
	      ],
	    },
	    {
	      module: 'tls',
	      title: 'TLS Fingerprints',
	      desc: 'Passive JA3/JA3S and encrypted-traffic statistical labeling.',
	      cmds: [
	        {
	          label: 'JA3 Passive Capture',
	          cmd: `sudo venv/bin/python tls/tls_fingerprints.py ja3 --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'tls', action: 'ja3', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	        {
	          label: 'JA3S Passive Capture',
	          cmd: `sudo venv/bin/python tls/tls_fingerprints.py ja3s --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'tls', action: 'ja3s', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	        {
	          label: 'Encrypted Traffic Classification',
	          cmd: `sudo venv/bin/python tls/tls_fingerprints.py traffic-classify --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'tls', action: 'traffic-classify', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	      ],
	    },
	    {
	      module: 'dns',
	      title: 'DNS Advanced',
	      desc: 'DNS tunnel heuristics, DoH/DoT usage detection, and DGA scoring.',
	      cmds: [
	        {
	          label: 'DNS Tunnel Detection',
	          cmd: `sudo venv/bin/python dns/dns_advanced.py tunnel-detect --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'dns', action: 'tunnel-detect', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	        {
	          label: 'DoH/DoT Detection',
	          cmd: `sudo venv/bin/python dns/dns_advanced.py doh-detect --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'dns', action: 'doh-detect', params: { interface: runner.iface, duration: runner.durationShort, extra_snis: parseCsv(runner.extraSnis) } },
	          needs: ['iface']
	        },
	        {
	          label: 'DGA Detection',
	          cmd: `sudo venv/bin/python dns/dns_advanced.py dga-detect --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'dns', action: 'dga-detect', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	      ],
	    },
	    {
	      module: 'snmp',
	      title: 'SNMP Enumeration',
	      desc: 'Read-only SNMP walk for system and topology hints.',
	      cmds: [
	        {
	          label: 'SNMP Walk',
	          cmd: `venv/bin/python snmp/snmp_enum.py --target ${targetOr(runner.targetIp, '<TARGET_IP>')} --community ${runner.snmpCommunity}`,
	          run: runner.targetIp ? { module: 'snmp', action: 'walk', params: { target: runner.targetIp, community: runner.snmpCommunity, mode: 'system' } } : null,
	          needs: ['targetIp']
	        },
	      ],
	    },
	    {
	      module: 'ssh',
	      title: 'SSH Deep Analysis',
	      desc: 'Host key fingerprints and SSH algorithm security audit.',
	      cmds: [
	        {
	          label: 'SSH Host Key Fingerprint',
	          cmd: `venv/bin/python ssh/ssh_analysis.py host-key-fp --target ${targetOr(runner.targetIp, '<TARGET_IP>')}`,
	          run: runner.targetIp ? { module: 'ssh', action: 'host-key-fp', params: { target: runner.targetIp, port: 22 } } : null,
	          needs: ['targetIp']
	        },
	        {
	          label: 'SSH Algorithm Audit',
	          cmd: `venv/bin/python ssh/ssh_analysis.py algo-audit --target ${targetOr(runner.targetIp, '<TARGET_IP>')}`,
	          run: runner.targetIp ? { module: 'ssh', action: 'algo-audit', params: { target: runner.targetIp, port: 22 } } : null,
	          needs: ['targetIp']
	        },
	      ],
	    },
	    {
	      module: 'smb',
	      title: 'SMB / Windows Enumeration',
	      desc: 'SMB shares, session metadata (best effort), and SMB OS hints.',
	      cmds: [
	        {
	          label: 'SMB Share Enumeration',
	          cmd: `venv/bin/python smb/smb_enum.py enum-shares --target ${targetOr(runner.targetIp, '<TARGET_IP>')}`,
	          run: runner.targetIp ? { module: 'smb', action: 'enum-shares', params: { target: runner.targetIp } } : null,
	          needs: ['targetIp']
	        },
	        {
	          label: 'SMB Session Enumeration',
	          cmd: `venv/bin/python smb/smb_enum.py enum-sessions --target ${targetOr(runner.targetIp, '<TARGET_IP>')}`,
	          run: runner.targetIp ? { module: 'smb', action: 'enum-sessions', params: { target: runner.targetIp } } : null,
	          needs: ['targetIp']
	        },
	        {
	          label: 'SMB OS Discovery',
	          cmd: `venv/bin/python smb/smb_enum.py os-discovery --target ${targetOr(runner.targetIp, '<TARGET_IP>')}`,
	          run: runner.targetIp ? { module: 'smb', action: 'os-discovery', params: { target: runner.targetIp } } : null,
	          needs: ['targetIp']
	        },
	      ],
	    },
	    {
	      module: 'iot',
	      title: 'IoT Protocol Enumeration',
	      desc: 'MQTT topic observation and CoAP resource discovery.',
	      cmds: [
	        {
	          label: 'MQTT Broker Enumeration',
	          cmd: `venv/bin/python iot/iot_enum.py mqtt-enum --target ${targetOr(runner.targetIp, '<TARGET_IP>')} --port ${runner.mqttPort} --duration ${Math.max(8, runner.durationShort)}`,
	          run: runner.targetIp ? { module: 'iot', action: 'mqtt-enum', params: { target: runner.targetIp, port: runner.mqttPort, duration: Math.max(8, runner.durationShort) } } : null,
	          needs: ['targetIp']
	        },
	        {
	          label: 'CoAP Resource Discovery',
	          cmd: `venv/bin/python iot/iot_enum.py coap-discover --target ${targetOr(runner.targetIp, '<TARGET_IP>')} --port ${runner.coapPort}`,
	          run: runner.targetIp ? { module: 'iot', action: 'coap-discover', params: { target: runner.targetIp, port: runner.coapPort } } : null,
	          needs: ['targetIp']
	        },
	      ],
	    },
	    {
	      module: 'wifi',
	      title: 'WiFi Passive Discovery',
	      desc: 'Monitor-mode passive scan for SSIDs/BSSIDs/clients.',
	      cmds: [
	        {
	          label: 'WiFi Passive Scan',
	          cmd: `sudo venv/bin/python wifi/wifi_scan.py --interface ${runner.wirelessIface || runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'wifi', action: 'passive-scan', params: { interface: runner.wirelessIface || runner.iface, duration: runner.durationShort } },
	          needs: ['wirelessIface']
	        },
	      ],
	    },
	    {
	      module: 'vlan',
	      title: 'VLAN / L2 Discovery',
	      desc: 'Passive CDP/LLDP/DTP sniffing for VLAN/switch metadata.',
	      cmds: [
	        {
	          label: 'VLAN Discovery',
	          cmd: `sudo venv/bin/python vlan/vlan_discovery.py --interface ${runner.iface} --duration ${runner.durationShort}`,
	          run: { module: 'vlan', action: 'discover', params: { interface: runner.iface, duration: runner.durationShort } },
	          needs: ['iface']
	        },
	      ],
	    },
	    {
	      module: 'analysis',
	      title: 'Analysis Engine',
	      desc: 'Temporal baselines, anomaly/risk scoring, identity resolution, and graph/time correlation.',
	      cmds: [
	        {
	          label: 'Compute Baseline (IP)',
	          cmd: `venv/bin/python -c \"analysis via API runner\"`,
	          run: runner.targetIp ? { module: 'analysis', action: 'compute-baseline', params: { ip: runner.targetIp, limit: 240 } } : null,
	          needs: ['targetIp']
	        },
	        {
	          label: 'Anomaly Score (IP)',
	          cmd: `venv/bin/python -c \"analysis via API runner\"`,
	          run: runner.targetIp ? { module: 'analysis', action: 'anomaly-score', params: { ip: runner.targetIp, limit: 240 } } : null,
	          needs: ['targetIp']
	        },
	        {
	          label: 'Community Detection',
	          cmd: `venv/bin/python -c \"analysis via API runner\"`,
	          run: { module: 'analysis', action: 'community-detect', params: { limit: 15000 } },
	          needs: []
	        },
	        {
	          label: 'Risk Scoring',
	          cmd: `venv/bin/python -c \"analysis via API runner\"`,
	          run: { module: 'analysis', action: 'risk-score', params: {} },
	          needs: []
	        },
	        {
	          label: 'Attack Chain Reconstruction',
	          cmd: `venv/bin/python -c \"analysis via API runner\"`,
	          run: { module: 'analysis', action: 'attack-chain', params: {} },
	          needs: []
	        },
	        {
	          label: 'Temporal Correlation',
	          cmd: `venv/bin/python -c \"analysis via API runner\"`,
	          run: runner.anchorTs ? { module: 'analysis', action: 'temporal-correlate', params: { ts: runner.anchorTs, entity: runner.targetIp || '', window_seconds: 300 } } : null,
	          needs: ['anchorTs']
	        },
	        {
	          label: 'Graph Time Diff',
	          cmd: `venv/bin/python -c \"analysis via API runner\"`,
	          run: (runner.graphT1 && runner.graphT2) ? { module: 'analysis', action: 'graph-diff', params: { t1: runner.graphT1, t2: runner.graphT2 } } : null,
	          needs: ['graphT1', 'graphT2']
	        },
	      ],
	    },
	    {
	      module: 'threat',
	      title: 'Threat Intelligence',
	      desc: 'CVE lookup, IP/domain reputation checks, and local feed synchronization.',
	      cmds: [
	        {
	          label: 'CVE Lookup',
	          cmd: `venv/bin/python -c \"threat lookup via API runner\"`,
	          run: runner.cveProduct ? { module: 'threat', action: 'cve-lookup', params: { product: runner.cveProduct, version: runner.cveVersion, max_results: 20 } } : null,
	          needs: ['cveProduct']
	        },
	        {
	          label: 'IP Reputation Check',
	          cmd: `venv/bin/python -c \"threat ip-reputation via API runner\"`,
	          run: { module: 'threat', action: 'ip-reputation', params: { feed_path: runner.feedPath } },
	          needs: []
	        },
	        {
	          label: 'Domain Reputation Check',
	          cmd: `venv/bin/python -c \"threat domain-reputation via API runner\"`,
	          run: { module: 'threat', action: 'domain-reputation', params: { feed_path: runner.feedPath } },
	          needs: []
	        },
	        {
	          label: 'Threat Feed Sync',
	          cmd: `venv/bin/python -c \"threat feed-sync via API runner\"`,
	          run: { module: 'threat', action: 'feed-sync', params: { feed_path: runner.feedPath } },
	          needs: []
	        },
	      ],
	    }
	  );

	  const copy = async (text) => {
	    try { await navigator.clipboard?.writeText(text); } catch {}
	  };
	  const fieldStyle = { display: 'flex', flexDirection: 'column', gap: '4px' };
	  const labelStyle = { fontSize: '9px', color: colors.textMuted };
	  const inputStyle = {
	    background: colors.bgCard,
	    border: `1px solid ${colors.border}`,
	    borderRadius: '8px',
	    padding: '8px',
	    color: colors.text,
	    fontSize: '10px',
	    outline: 'none'
	  };

	  return (
	    <div style={{ padding: '16px', overflow: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>
      <div style={{
        background: colors.bgCard,
        border: `1px solid ${colors.border}`,
        borderRadius: '12px',
        padding: '16px',
        marginBottom: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', marginBottom: '8px' }}>
          <div style={{ fontSize: '14px', fontWeight: 700, color: colors.text }}>
            Coursework Mode (Rubric Checklist)
          </div>
          <button onClick={refreshCw} style={{
            padding: '6px 10px',
            background: colors.bgTertiary,
            border: `1px solid ${colors.border}`,
            borderRadius: '8px',
            color: colors.text,
            fontSize: '10px',
            cursor: 'pointer'
          }}>
            {cwLoading ? 'Refreshing…' : 'Refresh'}
          </button>
	        </div>
		        <div style={{ fontSize: '11px', color: colors.textMuted, lineHeight: 1.5 }}>
		          Logs are written to <span style={{ color: colors.accent }}>logs/&lt;module&gt;/</span>. Use <span style={{ color: colors.success }}>Run</span> to execute from the UI (lab network only), or <span style={{ color: colors.accent }}>Copy</span> to run from a terminal.
	          The NetVis GUI is optional per rubric but helps visualize assets/flows and produce a “network story”.
	        </div>

		        {cwStatus?.logs && (
		          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(92px, 1fr))', gap: '8px', marginTop: '12px' }}>
		            {(() => {
		              const pref = ['mod1','mod2','mod3','mod4','mod5','mod6','mod7','ipv6','dhcp','discovery','icmp','tls','dns','snmp','ssh','smb','iot','wifi','vlan','analysis','threat'];
		              const present = Object.keys(cwStatus.logs || {});
		              const ordered = [...pref.filter((m) => present.includes(m)), ...present.filter((m) => !pref.includes(m)).sort()];
		              return ordered.map((m) => {
		                const count = cwStatus?.logs?.[m]?.count || 0;
		                const ok = count > 0;
		                return (
		                  <div key={m} style={{
		                    background: colors.bgTertiary,
		                    border: `1px solid ${ok ? colors.success : colors.border}`,
		                    borderRadius: '10px',
		                    padding: '8px'
		                  }}>
		                    <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>{m.toUpperCase()}</div>
		                    <div style={{ fontSize: '11px', fontWeight: 800, color: ok ? colors.success : colors.textDim }}>{count}</div>
		                  </div>
		                );
		              });
		            })()}
		          </div>
		        )}

	        {cwStatus?.report && (
	          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '12px' }}>
	            {Object.entries(cwStatus.report).map(([name, meta]) => {
	              if (!meta?.exists) return null;
	              return (
	                <button key={name} onClick={() => openArtifact(name)} style={{
	                  padding: '6px 10px',
	                  background: colors.bgTertiary,
	                  border: `1px solid ${colors.border}`,
	                  borderRadius: '8px',
	                  color: colors.text,
	                  fontSize: '10px',
	                  cursor: 'pointer'
	                }}>
	                  Open {name}
	                </button>
	              );
	            })}
	          </div>
	        )}

	        <div style={{
	          marginTop: '14px',
	          background: colors.bgTertiary,
	          border: `1px solid ${colors.border}`,
	          borderRadius: '12px',
	          padding: '12px'
	        }}>
	          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
	            <div style={{ fontSize: '11px', fontWeight: 800, color: colors.text }}>Runner Settings</div>
	            <button onClick={() => setShowRunnerAdvanced(v => !v)} style={{
	              padding: '6px 10px',
	              background: colors.bgCard,
	              border: `1px solid ${colors.border}`,
	              borderRadius: '8px',
	              color: colors.text,
	              fontSize: '10px',
	              cursor: 'pointer'
	            }}>{showRunnerAdvanced ? 'Hide Advanced' : 'Show Advanced'}</button>
	          </div>

	          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '10px', marginTop: '10px' }}>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Network CIDR</div>
	              <input value={runner.network} onChange={(e) => setRunner(r => ({ ...r, network: e.target.value }))} style={inputStyle} placeholder="192.168.56.0/24" />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Interface</div>
	              {(status?.interfaces && status.interfaces.length > 0) ? (
	                <select value={runner.iface} onChange={(e) => setRunner(r => ({ ...r, iface: e.target.value }))} style={inputStyle}>
	                  {status.interfaces.map((itf) => (
	                    <option key={itf} value={itf}>{itf}</option>
	                  ))}
	                </select>
	              ) : (
	                <input value={runner.iface} onChange={(e) => setRunner(r => ({ ...r, iface: e.target.value }))} style={inputStyle} placeholder="eth0" />
	              )}
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Target IP</div>
	              <input value={runner.targetIp} onChange={(e) => setRunner(r => ({ ...r, targetIp: e.target.value }))} style={inputStyle} placeholder="192.168.56.10" />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Zombie IP (Idle Scan)</div>
	              <input value={runner.zombieIp} onChange={(e) => setRunner(r => ({ ...r, zombieIp: e.target.value }))} style={inputStyle} placeholder="192.168.56.20" />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>TCP Ports (CSV)</div>
	              <input value={runner.tcpPorts} onChange={(e) => setRunner(r => ({ ...r, tcpPorts: e.target.value }))} style={inputStyle} placeholder="22,80,443" />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>UDP Ports (CSV)</div>
	              <input value={runner.udpPorts} onChange={(e) => setRunner(r => ({ ...r, udpPorts: e.target.value }))} style={inputStyle} placeholder="53,123,161" />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Banner Ports (CSV)</div>
	              <input value={runner.bannerPorts} onChange={(e) => setRunner(r => ({ ...r, bannerPorts: e.target.value }))} style={inputStyle} placeholder="21,22,25,80,443" />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Decoys (CSV)</div>
	              <input value={runner.decoysCsv} onChange={(e) => setRunner(r => ({ ...r, decoysCsv: e.target.value }))} style={inputStyle} placeholder="192.168.56.30,192.168.56.31" />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Domain (DNS Enum)</div>
	              <input value={runner.domain} onChange={(e) => setRunner(r => ({ ...r, domain: e.target.value }))} style={inputStyle} placeholder="example.com" />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>DNS Server</div>
	              <input value={runner.dnsServer} onChange={(e) => setRunner(r => ({ ...r, dnsServer: e.target.value }))} style={inputStyle} placeholder="8.8.8.8" />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Duration Short (s)</div>
	              <input type="number" value={runner.durationShort} onChange={(e) => setRunner(r => ({ ...r, durationShort: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Duration Long (s)</div>
	              <input type="number" value={runner.durationLong} onChange={(e) => setRunner(r => ({ ...r, durationLong: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>ARPwatch Duration (s)</div>
	              <input type="number" value={runner.durationArpwatch} onChange={(e) => setRunner(r => ({ ...r, durationArpwatch: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	            </div>
	            <div style={fieldStyle}>
	              <div style={labelStyle}>Max Tuples (Module 4)</div>
	              <input type="number" value={runner.maxTuples} onChange={(e) => setRunner(r => ({ ...r, maxTuples: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	            </div>
	            <div style={{ ...fieldStyle, flexDirection: 'row', alignItems: 'center', gap: '8px', paddingTop: '14px' }}>
	              <input type="checkbox" checked={runner.labOk} onChange={(e) => setRunner(r => ({ ...r, labOk: e.target.checked }))} />
	              <div style={{ fontSize: '10px', color: runner.labOk ? colors.warning : colors.textMuted, fontWeight: 800 }}>lab_ok (spoofing)</div>
	            </div>
	          </div>

	          {showRunnerAdvanced && (
	            <div style={{ marginTop: '12px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '10px' }}>
	              <div style={fieldStyle}>
	                <div style={labelStyle}>dport</div>
	                <input type="number" value={runner.dport} onChange={(e) => setRunner(r => ({ ...r, dport: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	              </div>
	              <div style={fieldStyle}>
	                <div style={labelStyle}>fragsize</div>
	                <input type="number" value={runner.fragsize} onChange={(e) => setRunner(r => ({ ...r, fragsize: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	              </div>
	              <div style={{ ...fieldStyle, flexDirection: 'row', alignItems: 'center', gap: '8px', paddingTop: '14px' }}>
	                <input type="checkbox" checked={runner.overlap} onChange={(e) => setRunner(r => ({ ...r, overlap: e.target.checked }))} />
	                <div style={{ fontSize: '10px', color: colors.textMuted, fontWeight: 800 }}>overlap frags</div>
	              </div>
	              <div style={fieldStyle}>
	                <div style={labelStyle}>TTL method</div>
	                <select value={runner.ttlMethod} onChange={(e) => setRunner(r => ({ ...r, ttlMethod: e.target.value }))} style={inputStyle}>
	                  <option value="icmp">icmp</option>
	                  <option value="tcp">tcp</option>
	                </select>
	              </div>
	              <div style={fieldStyle}>
	                <div style={labelStyle}>Max hops</div>
	                <input type="number" value={runner.maxHops} onChange={(e) => setRunner(r => ({ ...r, maxHops: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	              </div>
	              <div style={fieldStyle}>
	                <div style={labelStyle}>HTTP port</div>
	                <input type="number" value={runner.httpPort} onChange={(e) => setRunner(r => ({ ...r, httpPort: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	              </div>
	              <div style={{ ...fieldStyle, flexDirection: 'row', alignItems: 'center', gap: '8px', paddingTop: '14px' }}>
	                <input type="checkbox" checked={runner.httpUseTls} onChange={(e) => setRunner(r => ({ ...r, httpUseTls: e.target.checked }))} />
	                <div style={{ fontSize: '10px', color: colors.textMuted, fontWeight: 800 }}>HTTP over TLS</div>
	              </div>
	              <div style={fieldStyle}>
	                <div style={labelStyle}>TLS port</div>
	                <input type="number" value={runner.tlsPort} onChange={(e) => setRunner(r => ({ ...r, tlsPort: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	              </div>
	              <div style={fieldStyle}>
	                <div style={labelStyle}>NetFlow listen port</div>
	                <input type="number" value={runner.netflowPort} onChange={(e) => setRunner(r => ({ ...r, netflowPort: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
	              </div>
		              <div style={fieldStyle}>
		                <div style={labelStyle}>PCAP path (SPAN)</div>
		                <input value={runner.pcapPath} onChange={(e) => setRunner(r => ({ ...r, pcapPath: e.target.value }))} style={inputStyle} placeholder="/path/to/file.pcap" />
		              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>PCAP output (capture)</div>
			                <input value={runner.pcapOut} onChange={(e) => setRunner(r => ({ ...r, pcapOut: e.target.value }))} style={inputStyle} placeholder="report/capture.pcap" />
			                <button onClick={() => setRunner(r => ({ ...r, pcapPath: (r.pcapOut || r.pcapPath) }))} style={{
			                  marginTop: '6px',
			                  padding: '6px 10px',
			                  background: colors.bgCard,
			                  border: `1px solid ${colors.border}`,
			                  borderRadius: '8px',
			                  color: colors.text,
			                  fontSize: '10px',
			                  cursor: 'pointer'
			                }}>Use As PCAP Path</button>
			              </div>
		              <div style={fieldStyle}>
		                <div style={labelStyle}>BPF filter (optional)</div>
		                <input value={runner.bpf} onChange={(e) => setRunner(r => ({ ...r, bpf: e.target.value }))} style={inputStyle} placeholder="arp or port 53" />
		              </div>
	              <div style={fieldStyle}>
	                <div style={labelStyle}>Suricata eve.json</div>
	                <input value={runner.suricataEve} onChange={(e) => setRunner(r => ({ ...r, suricataEve: e.target.value }))} style={inputStyle} />
	              </div>
		              <div style={fieldStyle}>
		                <div style={labelStyle}>Zeek notice.log</div>
		                <input value={runner.zeekNotice} onChange={(e) => setRunner(r => ({ ...r, zeekNotice: e.target.value }))} style={inputStyle} />
		              </div>
		              <div style={fieldStyle}>
		                <div style={labelStyle}>Reverse CIDR (PTR sweep)</div>
		                <input value={runner.reverseCidr} onChange={(e) => setRunner(r => ({ ...r, reverseCidr: e.target.value }))} style={inputStyle} placeholder="192.168.56.0/24" />
		              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>Reverse Max (PTR)</div>
			                <input type="number" value={runner.reverseMax} onChange={(e) => setRunner(r => ({ ...r, reverseMax: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>DHCP Known Server IP</div>
			                <input value={runner.dhcpServer} onChange={(e) => setRunner(r => ({ ...r, dhcpServer: e.target.value }))} style={inputStyle} placeholder="192.168.56.1" />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>SNMP Community</div>
			                <input value={runner.snmpCommunity} onChange={(e) => setRunner(r => ({ ...r, snmpCommunity: e.target.value }))} style={inputStyle} placeholder="public" />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>MQTT Port</div>
			                <input type="number" value={runner.mqttPort} onChange={(e) => setRunner(r => ({ ...r, mqttPort: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>CoAP Port</div>
			                <input type="number" value={runner.coapPort} onChange={(e) => setRunner(r => ({ ...r, coapPort: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>Wireless Interface</div>
			                <input value={runner.wirelessIface} onChange={(e) => setRunner(r => ({ ...r, wirelessIface: e.target.value }))} style={inputStyle} placeholder="wlan0" />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>Threat Feed Path</div>
			                <input value={runner.feedPath} onChange={(e) => setRunner(r => ({ ...r, feedPath: e.target.value }))} style={inputStyle} placeholder="samples/threat_indicators.json" />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>CVE Product</div>
			                <input value={runner.cveProduct} onChange={(e) => setRunner(r => ({ ...r, cveProduct: e.target.value }))} style={inputStyle} placeholder="OpenSSH" />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>CVE Version</div>
			                <input value={runner.cveVersion} onChange={(e) => setRunner(r => ({ ...r, cveVersion: e.target.value }))} style={inputStyle} placeholder="8.9" />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>Extra DoH SNIs (CSV)</div>
			                <input value={runner.extraSnis} onChange={(e) => setRunner(r => ({ ...r, extraSnis: e.target.value }))} style={inputStyle} placeholder="resolver.example.com" />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>Temporal Anchor TS (ISO)</div>
			                <input value={runner.anchorTs} onChange={(e) => setRunner(r => ({ ...r, anchorTs: e.target.value }))} style={inputStyle} placeholder="2026-02-16T12:00:00" />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>Graph Diff T1 (ISO)</div>
			                <input value={runner.graphT1} onChange={(e) => setRunner(r => ({ ...r, graphT1: e.target.value }))} style={inputStyle} placeholder="2026-02-16T11:00:00" />
			              </div>
			              <div style={fieldStyle}>
			                <div style={labelStyle}>Graph Diff T2 (ISO)</div>
			                <input value={runner.graphT2} onChange={(e) => setRunner(r => ({ ...r, graphT2: e.target.value }))} style={inputStyle} placeholder="2026-02-16T12:00:00" />
			              </div>
			            </div>
			          )}
		        </div>

	        <div style={{
	          marginTop: '12px',
	          background: colors.bgTertiary,
	          border: `1px solid ${colors.border}`,
	          borderRadius: '12px',
	          padding: '12px'
	        }}>
	          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
	            <div style={{ fontSize: '11px', fontWeight: 800, color: colors.text }}>Coursework Jobs</div>
	            <button onClick={refreshJobs} style={{
	              padding: '6px 10px',
	              background: colors.bgCard,
	              border: `1px solid ${colors.border}`,
	              borderRadius: '8px',
	              color: colors.text,
	              fontSize: '10px',
	              cursor: 'pointer'
	            }}>{jobsLoading ? 'Refreshing…' : 'Refresh Jobs'}</button>
	          </div>
		          <div style={{ fontSize: '9px', color: colors.textMuted, marginTop: '6px' }}>
		            Jobs run on the backend and write logs under <span style={{ color: colors.accent }}>logs/&lt;module&gt;/</span>. While jobs are running, this list auto-refreshes.
	          </div>

	          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px', maxHeight: '220px', overflow: 'auto' }}>
	            {(cwJobs || []).length === 0 && (
	              <div style={{ fontSize: '10px', color: colors.textMuted }}>No jobs yet.</div>
	            )}
	            {(cwJobs || []).map((j) => {
	              const isBad = j.status === 'failed';
	              const isDone = j.status === 'completed';
	              return (
	                <div key={j.job_id} style={{
	                  background: colors.bgCard,
	                  border: `1px solid ${isBad ? colors.danger : colors.border}`,
	                  borderRadius: '10px',
	                  padding: '10px',
	                  display: 'flex',
	                  alignItems: 'flex-start',
	                  justifyContent: 'space-between',
	                  gap: '10px'
	                }}>
	                  <div style={{ minWidth: 0 }}>
	                    <div style={{ fontSize: '10px', fontWeight: 900, color: colors.text }}>
	                      {j.module}:{j.action} <span style={{ color: colors.textMuted, fontWeight: 600 }}>({(j.job_id || '').slice(0, 8)})</span>
	                    </div>
	                    <div style={{ fontSize: '9px', color: isBad ? colors.danger : colors.textMuted, marginTop: '4px' }}>
	                      {j.status} {typeof j.progress === 'number' ? `${j.progress}%` : ''} {j.message || ''}
	                    </div>
	                    {j.error && (
	                      <div style={{ fontSize: '9px', color: colors.danger, marginTop: '4px', whiteSpace: 'pre-wrap' }}>{j.error}</div>
	                    )}
	                  </div>
	                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', alignItems: 'flex-end' }}>
	                    {isDone && j.log_path && (
	                      <button onClick={() => openJobLog(j)} style={{
	                        padding: '6px 10px',
	                        background: colors.accent,
	                        border: 'none',
	                        borderRadius: '8px',
	                        color: colors.bg,
	                        fontSize: '10px',
	                        fontWeight: 800,
	                        cursor: 'pointer'
		                      }}>View Results</button>
	                    )}
	                  </div>
	                </div>
	              );
	            })}
	          </div>
	        </div>
	      </div>

	      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
	        {blocks.map((b) => (
	          <div key={b.title} style={{
            background: colors.bgCard,
            border: `1px solid ${colors.border}`,
            borderRadius: '12px',
            padding: '16px'
	          }}>
	            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', marginBottom: '6px' }}>
	              <div style={{ fontSize: '12px', fontWeight: 700, color: colors.text }}>{b.title}</div>
	              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
	                <button onClick={() => openLogBrowser(b.module)} style={{
	                  padding: '5px 8px',
	                  background: colors.bgTertiary,
	                  border: `1px solid ${colors.border}`,
	                  borderRadius: '8px',
	                  color: colors.text,
	                  fontSize: '10px',
	                  cursor: 'pointer'
		                }}>View Logs</button>
	                {cwStatus?.logs?.[b.module] && (
	                  <div style={{
	                    fontSize: '10px',
	                    color: (cwStatus.logs[b.module].count || 0) > 0 ? colors.success : colors.textMuted,
	                    background: colors.bgTertiary,
	                    border: `1px solid ${colors.border}`,
	                    borderRadius: '999px',
	                    padding: '3px 8px',
	                    whiteSpace: 'nowrap'
	                  }}>
	                    {(cwStatus.logs[b.module].count || 0)} log(s)
	                  </div>
	                )}
	              </div>
	            </div>
		            <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '10px' }}>{b.desc}</div>
		            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
		              {b.cmds.map((item, i) => {
		                const cmdText = (typeof item === 'string') ? item : (item.cmd || '');
		                const label = (typeof item === 'string') ? '' : (item.label || '');
		                const runSpec = (typeof item === 'string') ? null : (item.run || null);
		                const canRun = !!(runSpec && runSpec.module && runSpec.action);
		                return (
		                  <div key={i} style={{
		                    background: colors.bgTertiary,
		                    border: `1px solid ${colors.border}`,
		                    borderRadius: '8px',
		                    padding: '10px',
		                    display: 'flex',
		                    gap: '10px',
		                    alignItems: 'flex-start'
		                  }}>
		                    <div style={{ flex: 1, minWidth: 0 }}>
		                      {label && (
		                        <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>{label}</div>
		                      )}
		                      <code style={{ color: colors.text, fontSize: '10px', whiteSpace: 'pre-wrap' }}>{cmdText}</code>
		                    </div>
		                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
		                      <button onClick={() => copy(cmdText)} style={{
		                        background: colors.accent,
		                        border: 'none',
		                        borderRadius: '6px',
		                        padding: '6px 10px',
		                        cursor: 'pointer',
		                        fontSize: '10px',
		                        fontWeight: 700,
		                        color: colors.bg
		                      }}>Copy</button>
		                      <button disabled={!canRun} onClick={() => { if (canRun) startJob(runSpec.module, runSpec.action, runSpec.params); }} style={{
		                        background: canRun ? colors.success : colors.bgCard,
		                        border: `1px solid ${canRun ? colors.success : colors.border}`,
		                        borderRadius: '6px',
		                        padding: '6px 10px',
		                        cursor: canRun ? 'pointer' : 'not-allowed',
		                        fontSize: '10px',
		                        fontWeight: 800,
		                        color: canRun ? colors.bg : colors.textMuted,
		                        opacity: canRun ? 1 : 0.7
		                      }}>Run</button>
		                    </div>
		                  </div>
		                );
		              })}
		            </div>
		          </div>
		        ))}
		      </div>

	      {logBrowser.open && (
	        <div onClick={closeLogBrowser} style={{
	          position: 'fixed',
	          inset: 0,
	          background: 'rgba(0,0,0,0.65)',
	          display: 'flex',
	          alignItems: 'center',
	          justifyContent: 'center',
	          padding: '16px',
	          zIndex: 9999
	        }}>
	          <div onClick={(e) => e.stopPropagation()} style={{
	            width: 'min(1100px, 92vw)',
	            height: 'min(700px, 86vh)',
	            background: colors.bgCard,
	            border: `1px solid ${colors.border}`,
	            borderRadius: '12px',
	            overflow: 'hidden',
	            display: 'flex',
	            flexDirection: 'column'
	          }}>
	            <div style={{
	              display: 'flex',
	              justifyContent: 'space-between',
	              alignItems: 'center',
	              padding: '10px 12px',
	              borderBottom: `1px solid ${colors.border}`,
	              background: colors.bgTertiary
	            }}>
		              <div style={{ color: colors.text, fontSize: '11px', fontWeight: 800 }}>
		                Result Explorer: {logBrowser.module}
		              </div>
		              <button onClick={closeLogBrowser} style={{
	                padding: '6px 10px',
	                background: colors.bgCard,
	                border: `1px solid ${colors.border}`,
	                borderRadius: '8px',
	                color: colors.text,
	                fontSize: '10px',
	                cursor: 'pointer'
		              }}>Close</button>
		            </div>

		            <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
	              <div style={{
	                width: '280px',
	                borderRight: `1px solid ${colors.border}`,
	                background: colors.bgTertiary,
	                overflow: 'auto',
	                padding: '10px'
	              }}>
	                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '8px' }}>
	                  Files (latest first)
	                </div>
	                {(logBrowser.files || []).length === 0 && !logBrowser.loading && (
	                  <div style={{ fontSize: '10px', color: colors.textMuted }}>No logs yet.</div>
	                )}
	                {(logBrowser.files || []).map((f) => {
	                  const active = f.file === logBrowser.selected;
	                  return (
	                    <div key={f.file} onClick={() => loadLogFile(logBrowser.module, f.file)} style={{
	                      padding: '8px',
	                      borderRadius: '10px',
	                      border: `1px solid ${active ? colors.accent : colors.border}`,
	                      background: active ? colors.bgCard : 'transparent',
	                      cursor: 'pointer',
	                      marginBottom: '8px'
	                    }}>
	                      <div style={{ fontSize: '10px', color: colors.text, fontWeight: 800, wordBreak: 'break-word' }}>{f.file}</div>
	                      <div style={{ fontSize: '9px', color: colors.textMuted, marginTop: '2px' }}>
	                        {(f.technique || '').toString()}
	                      </div>
	                    </div>
	                  );
	                })}
	              </div>

		              <div style={{ flex: 1, minWidth: 0, overflow: 'auto', padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                      <button onClick={() => setLogTab('summary')} style={{
                        padding: '6px 10px',
                        background: logTab === 'summary' ? colors.accent : colors.bgTertiary,
                        border: `1px solid ${logTab === 'summary' ? colors.accent : colors.border}`,
                        borderRadius: '8px',
                        color: logTab === 'summary' ? colors.bg : colors.text,
                        fontSize: '10px',
                        fontWeight: 800,
                        cursor: 'pointer'
                      }}>Parsed Summary</button>
                      <button onClick={() => setLogTab('raw')} style={{
                        padding: '6px 10px',
                        background: logTab === 'raw' ? colors.accent : colors.bgTertiary,
                        border: `1px solid ${logTab === 'raw' ? colors.accent : colors.border}`,
                        borderRadius: '8px',
                        color: logTab === 'raw' ? colors.bg : colors.text,
                        fontSize: '10px',
                        fontWeight: 800,
                        cursor: 'pointer'
                      }}>Raw JSON</button>
                    </div>
		                {logBrowser.loading && (
		                  <div style={{ fontSize: '10px', color: colors.textMuted }}>Loading…</div>
		                )}
		                {logBrowser.error && (
		                  <div style={{ fontSize: '10px', color: colors.danger }}>{logBrowser.error}</div>
		                )}
		                {!logBrowser.loading && !logBrowser.error && logBrowser.content && logTab === 'summary' && (
                      <LogParsedView payload={logBrowser.content} />
                    )}
                    {!logBrowser.loading && !logBrowser.error && logBrowser.content && logTab === 'raw' && (
		                  <pre style={{
		                    margin: 0,
		                    whiteSpace: 'pre-wrap',
		                    wordBreak: 'break-word',
		                    fontSize: '10px',
		                    color: colors.text
		                  }}>{JSON.stringify(logBrowser.content, null, 2)}</pre>
		                )}
		              </div>
		            </div>
		          </div>
	        </div>
	      )}

	      {viewer.open && (
	        <div onClick={closeViewer} style={{
	          position: 'fixed',
	          inset: 0,
	          background: 'rgba(0,0,0,0.65)',
	          display: 'flex',
	          alignItems: 'center',
	          justifyContent: 'center',
	          padding: '16px',
	          zIndex: 9999
	        }}>
	          <div onClick={(e) => e.stopPropagation()} style={{
	            width: 'min(1100px, 92vw)',
	            height: 'min(700px, 86vh)',
	            background: colors.bgCard,
	            border: `1px solid ${colors.border}`,
	            borderRadius: '12px',
	            overflow: 'hidden',
	            display: 'flex',
	            flexDirection: 'column'
	          }}>
	            <div style={{
	              display: 'flex',
	              justifyContent: 'space-between',
	              alignItems: 'center',
	              padding: '10px 12px',
	              borderBottom: `1px solid ${colors.border}`,
	              background: colors.bgTertiary
	            }}>
	              <div style={{ color: colors.text, fontSize: '11px', fontWeight: 800 }}>
	                {viewer.title}
	              </div>
	              <button onClick={closeViewer} style={{
	                padding: '6px 10px',
	                background: colors.bgCard,
	                border: `1px solid ${colors.border}`,
	                borderRadius: '8px',
	                color: colors.text,
	                fontSize: '10px',
	                cursor: 'pointer'
	              }}>Close</button>
	            </div>

	            <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: '12px' }}>
	              {viewer.loading && (
	                <div style={{ fontSize: '10px', color: colors.textMuted }}>Loading…</div>
	              )}
	              {viewer.error && (
	                <div style={{ fontSize: '10px', color: colors.danger }}>{viewer.error}</div>
	              )}
	              {!viewer.loading && !viewer.error && viewer.isJson && (
	                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '10px', color: colors.text }}>
	                  {JSON.stringify(viewer.json || {}, null, 2)}
	                </pre>
	              )}
	              {!viewer.loading && !viewer.error && !viewer.isJson && (
	                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '10px', color: colors.text }}>
	                  {(viewer.content || '').toString()}
	                </pre>
	              )}
	            </div>
	          </div>
	        </div>
	      )}
	    </div>
	  );
}

// ============================================================================
// Workbench View (Multi-Chain + Story Synthesis)
// ============================================================================

function WorkbenchView({ status }) {
  const defaultNetwork = status?.network || '192.168.56.0/24';
  const ifaceHint = (status?.interfaces && status.interfaces[0]) ? status.interfaces[0] : 'eth0';

  const [cfg, setCfg] = useState(() => ({
    profile: 'standard',
    network: defaultNetwork,
    interface: ifaceHint,
    maxHosts: 32,
    targetIp: '',
    zombieIp: '',
    tcpPorts: '22,80,443',
    udpPorts: '53,123,161',
    bannerPorts: '21,22,25,80,443',
    durationShort: 60,
    durationLong: 600,
    durationArpwatch: 120,
    dport: 80,
    fragsize: 8,
    overlap: true,
    ttlMethod: 'icmp',
    maxHops: 20,
    labOk: false,
    decoysCsv: '',
    domain: '',
    dnsServer: '8.8.8.8',
	    netflowPort: 2055,
	    bpf: '',
	    suricataEve: 'report/suricata/eve.json',
	    zeekNotice: 'report/zeek/notice.log',
	  }));

  const [jobs, setJobs] = useState([]);
  const [jobsLoading, setJobsLoading] = useState(false);
  const [story, setStory] = useState(null);
  const [storyLoading, setStoryLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [viewer, setViewer] = useState({ open: false, title: '', loading: false, error: null, isJson: true, json: null, content: '' });
  const [selectedIp, setSelectedIp] = useState(null);
  const [isNarrow, setIsNarrow] = useState(false);

  useEffect(() => {
    setCfg((c) => ({
      ...c,
      network: c.network || defaultNetwork,
      interface: c.interface || ifaceHint,
    }));
  }, [defaultNetwork, ifaceHint]);

  useEffect(() => {
    const upd = () => setIsNarrow((window.innerWidth || 1024) < 980);
    upd();
    window.addEventListener('resize', upd);
    return () => window.removeEventListener('resize', upd);
  }, []);

  const parseCsv = (s) => (s || '').split(',').map(x => x.trim()).filter(Boolean);

  const refreshJobs = async () => {
    setJobsLoading(true);
    try {
      const data = await fetchJsonOrThrow(`${API_BASE}/coursework/jobs?limit=30`);
      const all = data?.jobs || [];
      setJobs(all.filter(j => j.module === 'pipeline'));
    } catch (e) {
      console.error('Failed to load pipeline jobs:', e);
      setJobs([]);
    }
    setJobsLoading(false);
  };

  useEffect(() => { refreshJobs(); }, []);
  useEffect(() => {
    const active = (jobs || []).some((j) => (j.status === 'queued' || j.status === 'running'));
    if (!active) return;
    const t = setInterval(() => { refreshJobs(); }, 2000);
    return () => clearInterval(t);
  }, [jobs]);

  const startMultichain = async () => {
    setErr(null);
    setStory(null);
    try {
      await fetchJsonOrThrow(`${API_BASE}/coursework/jobs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          module: 'pipeline',
          action: 'multichain',
          params: {
            profile: cfg.profile,
            network: cfg.network,
            interface: cfg.interface,
            maxHosts: cfg.maxHosts,
            targetIp: cfg.targetIp,
            zombieIp: cfg.zombieIp,
            tcpPorts: cfg.tcpPorts,
            udpPorts: cfg.udpPorts,
            bannerPorts: cfg.bannerPorts,
            durationShort: cfg.durationShort,
            durationLong: cfg.durationLong,
            durationArpwatch: cfg.durationArpwatch,
            dport: cfg.dport,
            fragsize: cfg.fragsize,
            overlap: cfg.overlap,
            ttlMethod: cfg.ttlMethod,
            maxHops: cfg.maxHops,
            labOk: cfg.labOk,
            decoys: parseCsv(cfg.decoysCsv),
            domain: cfg.domain,
            dnsServer: cfg.dnsServer,
            netflowPort: cfg.netflowPort,
            bpf: cfg.bpf,
            suricataEve: cfg.suricataEve,
            zeekNotice: cfg.zeekNotice,
          }
        })
      });
      refreshJobs();
    } catch (e) {
      setErr(`Failed to start multichain job: ${e.message || 'unknown error'}`);
    }
  };

  const loadStory = async () => {
    setStoryLoading(true);
    setErr(null);
    try {
      const data = await fetchJsonOrThrow(`${API_BASE}/coursework/report/multichain_story.json`);
      setStory(data?.json || null);
    } catch (e) {
      setErr(`No multichain story found yet: ${e.message || 'run multichain first'}`);
      setStory(null);
    }
    setStoryLoading(false);
  };

  useEffect(() => {
    const ips = (story?.host_profiles || []).map(h => h?.ip).filter(Boolean);
    if (!ips.length) return;
    setSelectedIp((cur) => (cur && ips.includes(cur)) ? cur : ips[0]);
  }, [story]);

  const openArtifact = async (name) => {
    setViewer({ open: true, title: name, loading: true, error: null, isJson: true, json: null, content: '' });
    try {
      const data = await fetchJsonOrThrow(`${API_BASE}/coursework/report/${encodeURIComponent(name)}`);
      if (data?.json !== undefined) {
        setViewer({ open: true, title: name, loading: false, error: null, isJson: true, json: data.json, content: '' });
      } else {
        setViewer({ open: true, title: name, loading: false, error: null, isJson: false, json: null, content: data?.content || '' });
      }
    } catch (e) {
      setViewer({ open: true, title: name, loading: false, error: `Failed to load artifact: ${e.message || 'unknown error'}`, isJson: true, json: null, content: '' });
    }
  };

  const closeViewer = () => setViewer((s) => ({ ...s, open: false }));

  const latest = (jobs || [])[0];

  const fieldStyle = { display: 'flex', flexDirection: 'column', gap: '4px' };
  const labelStyle = { fontSize: '9px', color: colors.textMuted };
  const inputStyle = {
    background: colors.bgTertiary,
    border: `1px solid ${colors.border}`,
    borderRadius: '10px',
    padding: '8px',
    color: colors.text,
    fontSize: '10px',
    outline: 'none'
  };

  return (
    <div style={{ padding: '16px', overflow: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>
      <div style={{ display: 'grid', gridTemplateColumns: isNarrow ? '1fr' : '420px 1fr', gap: '16px', alignItems: 'start' }}>
        <div style={{ background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '16px' }}>
          <div style={{ fontSize: '14px', fontWeight: 900, color: colors.text, marginBottom: '6px' }}>
            Multi-Chain Discovery Workbench
          </div>
          <div style={{ fontSize: '10px', color: colors.textMuted, lineHeight: 1.5, marginBottom: '12px' }}>
            One button runs a staged recon chain and synthesizes a casefile + narrative story. Private targets only; spoofing requires <span style={{ color: colors.warning }}>lab_ok</span>.
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div style={fieldStyle}>
              <div style={labelStyle}>Profile</div>
              <select value={cfg.profile} onChange={(e) => setCfg(c => ({ ...c, profile: e.target.value }))} style={inputStyle}>
                <option value="quick">quick</option>
                <option value="standard">standard</option>
                <option value="deep">deep</option>
              </select>
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>Max Hosts</div>
              <input type="number" value={cfg.maxHosts} onChange={(e) => setCfg(c => ({ ...c, maxHosts: parseInt(e.target.value || '0', 10) }))} style={inputStyle} />
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>Network CIDR</div>
              <input value={cfg.network} onChange={(e) => setCfg(c => ({ ...c, network: e.target.value }))} style={inputStyle} placeholder="192.168.56.0/24" />
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>Interface</div>
              {(status?.interfaces && status.interfaces.length > 0) ? (
                <select value={cfg.interface} onChange={(e) => setCfg(c => ({ ...c, interface: e.target.value }))} style={inputStyle}>
                  {status.interfaces.map((itf) => <option key={itf} value={itf}>{itf}</option>)}
                </select>
              ) : (
                <input value={cfg.interface} onChange={(e) => setCfg(c => ({ ...c, interface: e.target.value }))} style={inputStyle} />
              )}
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>Target IP (optional)</div>
              <input value={cfg.targetIp} onChange={(e) => setCfg(c => ({ ...c, targetIp: e.target.value }))} style={inputStyle} placeholder="192.168.56.10" />
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>TCP Ports (CSV)</div>
              <input value={cfg.tcpPorts} onChange={(e) => setCfg(c => ({ ...c, tcpPorts: e.target.value }))} style={inputStyle} />
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>UDP Ports (CSV)</div>
              <input value={cfg.udpPorts} onChange={(e) => setCfg(c => ({ ...c, udpPorts: e.target.value }))} style={inputStyle} />
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>Banner Ports (CSV)</div>
              <input value={cfg.bannerPorts} onChange={(e) => setCfg(c => ({ ...c, bannerPorts: e.target.value }))} style={inputStyle} />
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>Domain (DNS Enum, optional)</div>
              <input value={cfg.domain} onChange={(e) => setCfg(c => ({ ...c, domain: e.target.value }))} style={inputStyle} placeholder="example.com" />
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>DNS Server</div>
              <input value={cfg.dnsServer} onChange={(e) => setCfg(c => ({ ...c, dnsServer: e.target.value }))} style={inputStyle} />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginTop: '12px' }}>
            <button onClick={startMultichain} style={{
              padding: '10px 12px',
              background: colors.accent,
              border: 'none',
              borderRadius: '10px',
              color: colors.bg,
              fontSize: '11px',
              fontWeight: 900,
              cursor: 'pointer'
            }}>Run Multi-Chain</button>
            <button onClick={loadStory} style={{
              padding: '10px 12px',
              background: colors.bgTertiary,
              border: `1px solid ${colors.border}`,
              borderRadius: '10px',
              color: colors.text,
              fontSize: '11px',
              fontWeight: 800,
              cursor: 'pointer'
            }}>{storyLoading ? 'Loading…' : 'Load Latest Story'}</button>
            <button onClick={() => openArtifact('multichain_story.md')} style={{
              padding: '10px 12px',
              background: colors.bgTertiary,
              border: `1px solid ${colors.border}`,
              borderRadius: '10px',
              color: colors.text,
              fontSize: '11px',
              cursor: 'pointer'
            }}>Open Story.md</button>
            <button onClick={refreshJobs} style={{
              padding: '10px 12px',
              background: colors.bgTertiary,
              border: `1px solid ${colors.border}`,
              borderRadius: '10px',
              color: colors.text,
              fontSize: '11px',
              cursor: 'pointer'
            }}>{jobsLoading ? 'Refreshing…' : 'Refresh Jobs'}</button>
          </div>

          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginTop: '10px' }}>
            <input type="checkbox" checked={cfg.labOk} onChange={(e) => setCfg(c => ({ ...c, labOk: e.target.checked }))} />
            <div style={{ fontSize: '10px', fontWeight: 900, color: cfg.labOk ? colors.warning : colors.textMuted }}>lab_ok (enable spoofing steps in deep profile)</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '8px' }}>
            <div style={fieldStyle}>
              <div style={labelStyle}>Zombie IP (idle scan)</div>
              <input value={cfg.zombieIp} onChange={(e) => setCfg(c => ({ ...c, zombieIp: e.target.value }))} style={inputStyle} />
            </div>
            <div style={fieldStyle}>
              <div style={labelStyle}>Decoys (CSV)</div>
              <input value={cfg.decoysCsv} onChange={(e) => setCfg(c => ({ ...c, decoysCsv: e.target.value }))} style={inputStyle} />
            </div>
          </div>

          {err && <div style={{ marginTop: '10px', fontSize: '10px', color: colors.danger }}>{err}</div>}

          {latest && (
            <div style={{
              marginTop: '12px',
              background: colors.bgTertiary,
              border: `1px solid ${colors.border}`,
              borderRadius: '12px',
              padding: '10px'
            }}>
              <div style={{ fontSize: '10px', fontWeight: 900, color: colors.text }}>
                Latest Job: {latest.job_id?.slice(0, 8)} <span style={{ color: colors.textMuted }}>({latest.status} {latest.progress || 0}%)</span>
              </div>
              <div style={{ fontSize: '9px', color: colors.textMuted, marginTop: '4px' }}>{latest.message || ''}</div>
              {latest.error && <div style={{ fontSize: '9px', color: colors.danger, marginTop: '6px', whiteSpace: 'pre-wrap' }}>{latest.error}</div>}
            </div>
          )}
        </div>

        <div style={{ background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '16px', minHeight: '560px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', marginBottom: '10px' }}>
            <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>Aggregated Story</div>
            <div style={{ fontSize: '10px', color: colors.textMuted }}>
              {story?.generated_at ? `generated_at=${story.generated_at}` : 'no story loaded'}
            </div>
          </div>

          {!story && (
            <div style={{ fontSize: '11px', color: colors.textMuted, lineHeight: 1.6 }}>
              Run multi-chain and then load the latest story. The story is written to <span style={{ color: colors.accent }}>report/multichain_story.md</span> and <span style={{ color: colors.accent }}>report/multichain_story.json</span>.
            </div>
          )}

          {story && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '12px' }}>
                <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '10px' }}>
                  <div style={{ fontSize: '9px', color: colors.textMuted }}>HOSTS</div>
                  <div style={{ fontSize: '16px', fontWeight: 900, color: colors.accent }}>{story?.summary?.hosts_discovered ?? '-'}</div>
                </div>
                <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '10px' }}>
                  <div style={{ fontSize: '9px', color: colors.textMuted }}>FINGERPRINTED</div>
                  <div style={{ fontSize: '16px', fontWeight: 900, color: colors.purple }}>{story?.summary?.hosts_fingerprinted ?? '-'}</div>
                </div>
                <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '10px' }}>
                  <div style={{ fontSize: '9px', color: colors.textMuted }}>OPEN PORTS</div>
                  <div style={{ fontSize: '16px', fontWeight: 900, color: colors.success }}>{story?.summary?.open_ports_total ?? '-'}</div>
                </div>
                <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '10px' }}>
                  <div style={{ fontSize: '9px', color: colors.textMuted }}>RISK EXPOSURES</div>
                  <div style={{ fontSize: '16px', fontWeight: 900, color: colors.warning }}>{story?.summary?.high_risk_exposures ?? '-'}</div>
                </div>
              </div>

              {story?.story_panel?.summary && (
                <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '12px', marginBottom: '12px' }}>
                  <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '6px' }}>Brief</div>
                  <div style={{ fontSize: '11px', color: colors.text, lineHeight: 1.5, marginBottom: '8px' }}>
                    {story.story_panel.summary}
                  </div>
                  {(story.story_panel.insights || []).slice(0, 6).map((ln, i) => (
                    <div key={i} style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '4px' }}>- {ln}</div>
                  ))}
                </div>
              )}

              <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '12px', marginBottom: '12px' }}>
                <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '6px' }}>Narrative</div>
                {(story?.narrative?.high_level || []).map((ln, i) => (
                  <div key={i} style={{ fontSize: '11px', color: colors.text, marginBottom: '4px' }}>- {ln}</div>
                ))}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '12px' }}>
                <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '12px', overflow: 'auto' }}>
                  <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>Assets</div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '10px', color: colors.text }}>
                    <thead>
                      <tr style={{ color: colors.textMuted, fontSize: '9px' }}>
                        <th style={{ textAlign: 'left', padding: '6px' }}>IP</th>
                        <th style={{ textAlign: 'left', padding: '6px' }}>Vendor</th>
                        <th style={{ textAlign: 'left', padding: '6px' }}>Open Ports</th>
                        <th style={{ textAlign: 'left', padding: '6px' }}>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(story.assets || []).map((a) => (
                        <tr key={a.ip} style={{ borderTop: `1px solid ${colors.border}` }}>
                          <td style={{ padding: '6px' }}>{a.ip}</td>
                          <td style={{ padding: '6px', color: colors.textMuted }}>{a.vendor || ''}</td>
                          <td style={{ padding: '6px' }}>{(a.open_tcp_ports || []).join(', ')}</td>
                          <td style={{ padding: '6px', color: (a.risk_ports || []).length > 0 ? colors.warning : colors.textMuted }}>{(a.risk_ports || []).join(', ')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '12px', overflow: 'auto' }}>
                  <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '8px' }}>Risk Exposures</div>
                  {(story.exposures || []).length === 0 ? (
                    <div style={{ fontSize: '10px', color: colors.textMuted }}>No high-risk exposures detected.</div>
                  ) : (
                    (story.exposures || []).slice(0, 200).map((e, i) => (
                      <div key={i} style={{ fontSize: '11px', color: colors.text, marginBottom: '4px' }}>
                        {e.ip}:{e.port} <span style={{ color: colors.warning }}>{e.service}</span>
                      </div>
                    ))
                  )}

                  {(story?.story_panel?.top_domains || []).length > 0 && (
                    <div style={{ marginTop: '10px', paddingTop: '10px', borderTop: `1px solid ${colors.border}` }}>
                      <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '6px' }}>Top Domains (Passive DNS)</div>
                      {(story.story_panel.top_domains || []).slice(0, 8).map((d, i) => (
                        <div key={i} style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '4px' }}>
                          {d.domain} <span style={{ color: colors.accent }}>({d.count})</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {(story.host_profiles || []).length > 0 && (
                <div style={{ marginTop: '12px', display: 'grid', gridTemplateColumns: isNarrow ? '1fr' : '1fr 1.2fr', gap: '12px' }}>
                  <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '12px', overflow: 'auto' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', marginBottom: '8px' }}>
                      <div style={{ fontSize: '10px', color: colors.textMuted }}>Host Profiles</div>
                      <button onClick={() => openArtifact('multichain_casefile.json')} style={{
                        padding: '6px 10px',
                        background: colors.bgCard,
                        border: `1px solid ${colors.border}`,
                        borderRadius: '8px',
                        color: colors.text,
                        fontSize: '10px',
                        cursor: 'pointer'
                      }}>Open Casefile</button>
                    </div>
                    {(story.host_profiles || []).slice(0, 200).map((h) => {
                      const active = h.ip === selectedIp;
                      return (
                        <div key={h.ip} onClick={() => setSelectedIp(h.ip)} style={{
                          padding: '8px',
                          borderRadius: '10px',
                          border: `1px solid ${active ? colors.accent : colors.border}`,
                          background: active ? colors.bgCard : 'transparent',
                          cursor: 'pointer',
                          marginBottom: '8px'
                        }}>
                          <div style={{ fontSize: '11px', color: colors.text, fontWeight: 900 }}>{h.ip}</div>
                          <div style={{ fontSize: '9px', color: colors.textMuted, marginTop: '2px' }}>
                            ports={(h.open_tcp_ports || []).length} risk={(h.risk_ports || []).length} web={h.web_posture_worst || 'unknown'}
                          </div>
                          {h.vendor && <div style={{ fontSize: '9px', color: colors.textDim, marginTop: '2px' }}>{h.vendor}</div>}
                        </div>
                      );
                    })}
                  </div>

                  <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '12px', overflow: 'auto' }}>
                    {(() => {
                      const sel = (story.host_profiles || []).find(x => x.ip === selectedIp) || (story.host_profiles || [])[0];
                      if (!sel) return <div style={{ fontSize: '10px', color: colors.textMuted }}>Select a host to view details.</div>;
                      return (
                        <>
                          <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text, marginBottom: '6px' }}>{sel.ip}</div>
                          <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '10px' }}>
                            {(sel.open_tcp_ports || []).length} open TCP · {(sel.risk_ports || []).length} risk ports · web={sel.web_posture_worst || 'unknown'}
                          </div>

                          {(sel.os_hints || []).length > 0 && (
                            <div style={{ marginBottom: '10px' }}>
                              <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '6px' }}>OS Hints</div>
                              {(sel.os_hints || []).slice(0, 6).map((h, i) => (
                                <div key={i} style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '4px' }}>
                                  {h.hint} <span style={{ color: colors.accent }}>({h.confidence})</span> <span style={{ color: colors.textDim }}>{h.evidence}</span>
                                </div>
                              ))}
                            </div>
                          )}

                          <div style={{ marginBottom: '10px' }}>
                            <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '6px' }}>Services</div>
                            {(sel.services || []).length === 0 ? (
                              <div style={{ fontSize: '10px', color: colors.textMuted }}>No services recorded.</div>
                            ) : (
                              (sel.services || []).slice(0, 80).map((s, i) => (
                                <div key={i} style={{ padding: '8px', borderRadius: '10px', border: `1px solid ${colors.border}`, background: colors.bgCard, marginBottom: '8px' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                                    <div style={{ fontSize: '11px', color: colors.text, fontWeight: 900 }}>
                                      {s.proto}:{s.port} {s.risk_label ? <span style={{ color: colors.warning }}>({s.risk_label})</span> : null}
                                    </div>
                                    <div style={{ fontSize: '10px', color: colors.textMuted }}>
                                      {(s.banner_intel || {}).product ? `${(s.banner_intel || {}).product}/${(s.banner_intel || {}).version || ''}` : ''}
                                    </div>
                                  </div>
                                  {(s.banner_intel || {}).service && (
                                    <div style={{ fontSize: '10px', color: colors.textMuted, marginTop: '4px' }}>
                                      service={(s.banner_intel || {}).service} {((s.banner_intel || {}).os_hint) ? <span style={{ color: colors.textDim }}>os_hint={String((s.banner_intel || {}).os_hint).slice(0, 120)}</span> : null}
                                    </div>
                                  )}
                                  {s.banner && (
                                    <div style={{ fontSize: '10px', color: colors.textDim, marginTop: '6px', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                      {String(s.banner).slice(0, 260)}
                                    </div>
                                  )}
                                </div>
                              ))
                            )}
                          </div>

                          {sel.ack_firewall_inference && (
                            <div style={{ marginBottom: '10px' }}>
                              <div style={{ fontSize: '10px', color: colors.textMuted, marginBottom: '6px' }}>Firewall Inference (ACK Scan)</div>
                              <div style={{ fontSize: '10px', color: colors.textMuted }}>
                                {sel.ack_firewall_inference.inference} · filtered_ports={sel.ack_firewall_inference.filtered_ports} · unfiltered_ports={sel.ack_firewall_inference.unfiltered_ports}
                              </div>
                            </div>
                          )}
                        </>
                      );
                    })()}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {viewer.open && (
        <div onClick={closeViewer} style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.65)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '16px',
          zIndex: 9999
        }}>
          <div onClick={(e) => e.stopPropagation()} style={{
            width: 'min(1100px, 92vw)',
            height: 'min(700px, 86vh)',
            background: colors.bgCard,
            border: `1px solid ${colors.border}`,
            borderRadius: '12px',
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '10px 12px',
              borderBottom: `1px solid ${colors.border}`,
              background: colors.bgTertiary
            }}>
              <div style={{ color: colors.text, fontSize: '11px', fontWeight: 800 }}>
                {viewer.title}
              </div>
              <button onClick={closeViewer} style={{
                padding: '6px 10px',
                background: colors.bgCard,
                border: `1px solid ${colors.border}`,
                borderRadius: '8px',
                color: colors.text,
                fontSize: '10px',
                cursor: 'pointer'
              }}>Close</button>
            </div>

            <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: '12px' }}>
              {viewer.loading && (
                <div style={{ fontSize: '10px', color: colors.textMuted }}>Loading…</div>
              )}
              {viewer.error && (
                <div style={{ fontSize: '10px', color: colors.danger }}>{viewer.error}</div>
              )}
              {!viewer.loading && !viewer.error && viewer.isJson && (
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '10px', color: colors.text }}>
                  {JSON.stringify(viewer.json || {}, null, 2)}
                </pre>
              )}
              {!viewer.loading && !viewer.error && !viewer.isJson && (
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '10px', color: colors.text }}>
                  {(viewer.content || '').toString()}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Brain Panel (Phase 4 — Situation Assessor + Strategy Planner)
// ============================================================================

function BrainPanel({ plan, setPlan, loading, setLoading, stealth, setStealth, refreshAppData }) {
  const card = { background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '16px', marginTop: '12px' };
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState([]);
  const [cycle, setCycle] = useState(0);
  const [phase, setPhase] = useState('idle');
  const [dashTab, setDashTab] = useState('devices');
  const [findings, setFindings] = useState({ devices: {}, dns: {}, services: [], captures: [], communities: [], threats: [], techniques_run: 0 });
  const stopRef = useRef(false);
  const logEndRef = useRef(null);
  const completedRef = useRef(new Set());

  const addLog = useCallback((type, msg) => {
    const ts = new Date().toLocaleTimeString();
    setLog(prev => [...prev.slice(-200), { ts, type, msg, id: Date.now() + Math.random() }]);
  }, []);

  useEffect(() => { if (logEndRef.current) logEndRef.current.scrollIntoView({ behavior: 'smooth' }); }, [log]);

  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  const ingest = useCallback((techId, target, r) => {
    setFindings(prev => {
      const f = { ...prev, devices: { ...prev.devices }, dns: { ...prev.dns }, services: [...prev.services], captures: [...prev.captures], communities: [...prev.communities], threats: [...prev.threats], techniques_run: prev.techniques_run + 1 };
      const ensureDev = (ip) => { if (ip && !f.devices[ip]) f.devices[ip] = { ip, mac: '', hostname: '', os: '', ports: [], services: [], risk: null, vendor: '', source: [] }; return ip ? f.devices[ip] : null; };
      // ARP hosts (list of objects or strings)
      if (r.hosts?.length) {
        for (const h of r.hosts) {
          if (typeof h === 'string') { const d = ensureDev(h); if (d && !d.source.includes(techId)) d.source.push(techId); }
          else if (h.ip) { const d = ensureDev(h.ip); if (h.mac) d.mac = h.mac; if (h.hostname || h.name) d.hostname = h.hostname || h.name; if (h.vendor) d.vendor = h.vendor; if (!d.source.includes(techId)) d.source.push(techId); }
        }
      }
      // ARP hosts_table (dict: ip -> {mac,...})
      if (r.hosts_table && typeof r.hosts_table === 'object') {
        for (const [ip, info] of Object.entries(r.hosts_table)) {
          const d = ensureDev(ip); if (d && info.mac) d.mac = info.mac; if (d && info.vendor) d.vendor = info.vendor; if (d && !d.source.includes(techId)) d.source.push(techId);
        }
      }
      // Discovered list
      if (r.discovered?.length) {
        for (const h of r.discovered) {
          if (typeof h === 'string') { ensureDev(h); }
          else if (h.ip) { const d = ensureDev(h.ip); if (h.mac) d.mac = h.mac; }
        }
      }
      // Alive hosts (ICMP sweep)
      if (r.alive_hosts?.length) {
        for (const h of r.alive_hosts) {
          if (typeof h === 'string') { ensureDev(h); }
          else if (h.ip) { const d = ensureDev(h.ip); if (h.ttl) d.services = [...new Set([...d.services, `TTL:${h.ttl}`])]; }
        }
      }
      // Banner results
      if (r.technique === 'banner_grabbing' && r.results?.length) {
        const d = ensureDev(target || r.host);
        for (const p of r.results) {
          if (p.has_banner && p.banner) { if (d) d.ports = [...new Set([...d.ports, p.port])]; f.services.push({ ip: target||r.host, port: p.port, banner: p.banner, service: p.intel?.service||'', product: p.intel?.product||'', version: p.intel?.version||'' }); }
          else if (p.intel?.service) { if (d) d.ports = [...new Set([...d.ports, p.port])]; f.services.push({ ip: target||r.host, port: p.port, banner: '', service: p.intel.service, product: p.intel.product||'', version: '' }); }
        }
      }
      // OS fingerprint
      if (r.best_guess && target) { const d = ensureDev(target); if (d && !d.os) d.os = `${r.best_guess} (${(r.confidence*100||0).toFixed(0)}%)`; }
      if (r.os_guess && target) { const d = ensureDev(target); if (d) d.os = r.os_guess; }
      // HTTP headers
      if (r.headers?.server && target) { const d = ensureDev(target); if (d) d.services.push(`HTTP: ${r.headers.server}`); }
      if (r.error === 'request_failed_ConnectionRefusedError' && target) { /* no HTTP server */ }
      // Risk scores
      if (r.device_risk?.length) { for (const dr of r.device_risk) { if (dr.ip) { const d = ensureDev(dr.ip); if (d) d.risk = dr.score; } } }
      // Port scans (SYN/FIN/ACK/etc)
      if (r.results?.length && (r.technique?.includes('_scan') || r.technique?.includes('scan'))) {
        const d = ensureDev(target || r.host);
        for (const p of r.results) {
          if (p.state === 'open' && d) { d.ports = [...new Set([...d.ports, p.port])]; }
          if (p.service && d) f.services.push({ ip: target||r.host, port: p.port, service: p.service, banner: '', product: '', version: '' });
        }
      }
      // Open ports array
      if (r.open_ports?.length && target) {
        const d = ensureDev(target);
        if (d) d.ports = [...new Set([...d.ports, ...r.open_ports])];
      }
      // ip_mac_table (passive ARP)
      if (r.ip_mac_table?.length) {
        for (const e of r.ip_mac_table) {
          if (e.ip) { const d = ensureDev(e.ip); if (d && e.mac) d.mac = e.mac; if (!d.source.includes('passive_arp')) d.source.push('passive_arp'); }
        }
      }
      // SSH fingerprint
      if (r.host_key && target) { const d = ensureDev(target); if (d) d.services.push(`SSH: ${r.key_type||'?'} ${(r.fingerprint||'').slice(0,20)}`); }
      // TLS cert
      if (r.subject_cn && target) { const d = ensureDev(target); if (d) { d.hostname = d.hostname || r.subject_cn; d.services.push(`TLS: ${r.subject_cn}`); } }
      // SSDP/UPnP devices
      if (r.devices?.length) { for (const dev of r.devices) { const d = ensureDev(dev.ip || dev.host); if (d) { d.hostname = d.hostname || dev.friendly_name || dev.name || ''; if (!d.source.includes('ssdp')) d.source.push('ssdp'); } } }
      // mDNS
      if (r.records_sample?.length) { for (const rec of r.records_sample) { if (rec.name) f.dns[rec.name] = { ...(f.dns[rec.name]||{count:0,type:'mDNS'}), count: (f.dns[rec.name]?.count||0)+1, type: 'mDNS' }; } }
      if (r.service_types?.length) { for (const st of r.service_types) f.dns[st] = { ...(f.dns[st]||{count:0,type:'mDNS-service'}), count: 1, type: 'mDNS-service' }; }
      // NBNS names
      if (r.results?.length && r.technique === 'nbns_node_status_query') { for (const nr of r.results) { if (nr.ip && nr.names?.length) { const d = ensureDev(nr.ip); if (d) d.hostname = d.hostname || nr.names[0]; } } }
      // Passive DNS
      if (r.top_domains?.length) { for (const td of r.top_domains) { const dom = td.domain || td.name || td[0]; const cnt = td.count || td[1] || 1; if (dom) f.dns[dom] = { ...(f.dns[dom]||{count:0,type:'DNS'}), count: (f.dns[dom]?.count||0)+cnt, type: 'DNS' }; } }
      if (r.queries?.length) { for (const q of r.queries) { const dom = q.domain || q.name; if (dom) { f.dns[dom] = { ...(f.dns[dom]||{count:0,type:'DNS',queriedBy:[]}), count: (f.dns[dom]?.count||0)+1, type: 'DNS' }; if (q.src_ip && !f.dns[dom].queriedBy?.includes(q.src_ip)) (f.dns[dom].queriedBy = f.dns[dom].queriedBy||[]).push(q.src_ip); } } }
      // Traffic capture (keys may be at top or under .analysis)
      if (r.technique === 'promiscuous_mode_capture' || techId.includes('promisc')) {
        const a = r.analysis || {};
        const pkts = r.packets_captured || r.frames_captured || r.frames_observed || 0;
        const dur = r.duration_seconds || r.elapsed_seconds || r.capture_duration_seconds || 0;
        const tt = a.top_talkers || r.top_talkers || [];
        const protos = a.protocol_counts || r.protocol_breakdown || {};
        f.captures.push({ ts: new Date().toISOString(), frames: pkts, duration: dur, protocols: protos, topTalkers: tt, uniqueIPs: a.unique_ips || 0, uniqueMACs: a.unique_macs || 0 });
        for (const t of tt) { if (t.ip) ensureDev(t.ip); }
        if (a.ips?.length) { for (const ip of a.ips) ensureDev(ip); }
      }
      // DHCP
      if (r.leases?.length) { for (const l of r.leases) { if (l.ip) { const d = ensureDev(l.ip); if (d) { if (l.hostname) d.hostname = l.hostname; if (l.mac) d.mac = l.mac; if (l.vendor_class) d.vendor = l.vendor_class; } } } }
      // SNMP walk -> hostname + OS + sysInfo
      if (r.system && typeof r.system === 'object') {
        const ip = target || r.target;
        if (ip) { const d = ensureDev(ip); if (d) { if (r.system.sysName && !d.hostname) d.hostname = r.system.sysName; if (r.system.sysDescr && !d.os) d.os = r.system.sysDescr.slice(0,80); d.services = [...new Set([...d.services, 'SNMP'])]; } }
      }
      // SMB enum -> hostname + OS
      if ((r.hostname || r.os) && techId.includes('smb')) {
        const ip = target || r.target;
        if (ip) { const d = ensureDev(ip); if (d) { if (r.hostname && !d.hostname) d.hostname = r.hostname; if (r.os && !d.os) d.os = r.os; d.services = [...new Set([...d.services, 'SMB'])]; } }
      }
      // SMB shares
      if (r.shares?.length && target) {
        const d = ensureDev(target);
        if (d) d.services = [...new Set([...d.services, ...r.shares.map(s => `SMB:${s.name||s}`)])];
      }
      // Community detection
      if (r.clusters?.length) f.communities = r.clusters;
      // Threats
      if (r.threat_hits?.length) f.threats = [...f.threats, ...r.threat_hits];
      if (r.cves?.length) f.threats = [...f.threats, ...r.cves.map(c => ({ type: 'CVE', ...c }))];
      // MAC vendor
      if (r.hosts?.length) { for (const h of r.hosts) { if (typeof h === 'object' && h.ip && h.mac) { const d = ensureDev(h.ip); if (d && h.mac) d.mac = h.mac; } } }
      // TLS JA3 -> extract SNI domains (the REAL domains: instagram.com, etc.)
      if (r.fingerprints?.length) {
        for (const fp of r.fingerprints) {
          if (fp.sni) {
            f.dns[fp.sni] = { ...(f.dns[fp.sni]||{count:0,type:'TLS-SNI',queriedBy:[]}), count: (f.dns[fp.sni]?.count||0)+1, type: 'TLS-SNI' };
            if (fp.src_ip && !(f.dns[fp.sni].queriedBy||[]).includes(fp.src_ip)) (f.dns[fp.sni].queriedBy = f.dns[fp.sni].queriedBy||[]).push(fp.src_ip);
            if (fp.dst_ip) { const d = ensureDev(fp.dst_ip); if (d && !d.hostname) d.hostname = fp.sni; }
          }
        }
      }
      // Encrypted traffic classification -> flows with dst IPs
      if (r.flows?.length) {
        for (const fl of r.flows) {
          if (fl.dst_ip) { const d = ensureDev(fl.dst_ip); if (d) d.services = [...new Set([...d.services, `${fl.label||'encrypted'}:${fl.dst_port||443}`])]; }
        }
      }
      // DNS DoH/DoT detection -> domains using encrypted DNS
      if (r.doh_flows?.length) { for (const fl of r.doh_flows) { if (fl.sni) f.dns[fl.sni] = { ...(f.dns[fl.sni]||{count:0,type:'DoH'}), count: (f.dns[fl.sni]?.count||0)+1, type: 'DoH' }; } }
      if (r.dot_flows?.length) { for (const fl of r.dot_flows) { if (fl.server_ip) f.dns[`DoT:${fl.server_ip}`] = { count: 1, type: 'DoT' }; } }
      // DNS DGA detection -> suspicious domains
      if (r.suspicious_domains?.length) { for (const sd of r.suspicious_domains) { const dom = sd.domain || sd.name; if (dom) f.dns[dom] = { ...(f.dns[dom]||{count:0,type:'DGA-suspect'}), count: 1, type: 'DGA-suspect', score: sd.score }; } }
      // LLMNR
      if (r.failed_lookups_sample?.length) { for (const fl of r.failed_lookups_sample) { if (fl.name) f.dns[fl.name] = { ...(f.dns[fl.name]||{count:0,type:'LLMNR-fail'}), count: (f.dns[fl.name]?.count||0)+1, type: 'LLMNR-fail' }; } }
      return f;
    });
  }, []);

  const pollJob = async (jobId, label) => {
    for (let i = 0; i < 45; i++) {
      if (stopRef.current) return { status: 'stopped' };
      await sleep(2000);
      try {
        const r = await fetch(`${API_BASE}/coursework/jobs/${jobId}`);
        const j = await r.json();
        if (j.status === 'completed') { addLog('ok', `${label} completed`); return j; }
        if (j.status === 'failed') { addLog('err', `${label} failed: ${j.error || '?'}`); return j; }
        if (i % 5 === 4) addLog('wait', `${label} running (${j.progress||0}%)...`);
      } catch { break; }
    }
    addLog('err', `${label} timed out — moving on`);
    return { status: 'timeout' };
  };

  const brainLoop = useCallback(async () => {
    stopRef.current = false;
    setRunning(true);
    setLog([]);
    completedRef.current = new Set();
    setFindings({ devices: {}, dns: {}, services: [], captures: [], communities: [], threats: [], techniques_run: 0 });
    let loopNum = 0;

    while (!stopRef.current) {
      loopNum++;
      setCycle(loopNum);
      setPhase('assess');
      addLog('brain', `Cycle ${loopNum}: Assessing network...`);
      let planData;
      try {
        const res = await fetch(`${API_BASE}/nip/brain/plan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ stealth }) });
        planData = await res.json();
        setPlan(planData);
      } catch (e) { addLog('err', `Assessment failed: ${e.message}`); await sleep(5000); continue; }
      if (stopRef.current) break;

      const summary = planData?.situation_summary;
      if (summary) addLog('info', `${summary.total_devices} devices | ${summary.coverage_pct}% coverage | ${summary.stale} stale | ${summary.unresolved_alerts} alerts`);

      const techniques = [];
      for (const p of (planData?.plan || [])) { for (const t of (p.techniques || [])) techniques.push({ ...t, objective: p.objective?.type }); }

      // Passive/monitor techniques should run every cycle (they capture new traffic)
      const passiveTechniques = new Set(['mod6.promisc','mod5.passive_dns','tls.ja3','tls.ja3_fingerprint','dhcp.passive_monitor','mod7.arpwatch','ipv6.passive_ndp','discovery.mdns_passive','discovery.llmnr','dns.tunnel_detect','dns.doh_detect','dns.dga_detect']);
      const fresh = techniques.filter(t => passiveTechniques.has(t.technique_id) || !completedRef.current.has(`${t.technique_id}::${t.target||''}`));
      if (fresh.length === 0) {
        addLog('brain', `All ${techniques.length} planned techniques already completed. Waiting 30s...`);
        setPhase('idle');
        for (let w = 0; w < 30 && !stopRef.current; w++) await sleep(1000);
        completedRef.current.clear();
        continue;
      }

      addLog('brain', `${fresh.length} new technique(s) to run (${techniques.length - fresh.length} already done)`);
      setPhase('execute');

      // Pick at least 1 per objective, then spread by target
      const byObj = {};
      for (const t of fresh) { const o = t.objective||'other'; (byObj[o] = byObj[o]||[]).push(t); }
      const picks = [];
      for (const o of Object.keys(byObj)) { if (byObj[o].length) picks.push(byObj[o].shift()); }
      const rest = fresh.filter(t => !picks.includes(t));
      const seen = new Set(picks.map(t => t.target||'_'));
      const sp = [], df = [];
      for (const t of rest) { const k = t.target||'_'; if (!seen.has(k)) { seen.add(k); sp.push(t); } else df.push(t); }
      const toRun = [...picks, ...sp, ...df].slice(0, 8);

      for (const tech of toRun) {
        if (stopRef.current) break;
        const tkey = `${tech.technique_id}::${tech.target||''}`;
        const label = `${tech.technique_id}${tech.target ? ' @ '+tech.target : ''}`;
        addLog('run', `[${tech.objective}] ${label} — ${tech.reason}`);

        try {
          const execRes = await fetch(`${API_BASE}/nip/brain/execute`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ technique_id: tech.technique_id, target: tech.target||'' }) });
          const execData = await execRes.json();
          if (!execRes.ok || execData.error) { addLog('err', `${tech.technique_id}: ${execData.error||'failed'}`); completedRef.current.add(tkey); continue; }

          const jobId = execData.job_id;
          addLog('info', `Job ${jobId?.slice(0,8)}... started`);
          const result = await pollJob(jobId, tech.technique_id);
          if (result.status === 'stopped') break;
          completedRef.current.add(tkey);

          if (result.status === 'completed' && result.result) {
            let r = typeof result.result === 'string' ? JSON.parse(result.result) : result.result;
            if (r && r.result && typeof r.result === 'object' && r.module) r = r.result;
            ingest(tech.technique_id, tech.target, r);
            // Short summary for log
            const bits = [];
            if (r.hosts?.length) bits.push(`${r.hosts.length} hosts`);
            if (r.best_guess) bits.push(`OS: ${r.best_guess}`);
            if (r.device_risk?.length) bits.push(`${r.device_risk.length} risk-scored`);
            if (r.clusters?.length) bits.push(`${r.clusters.length} communities`);
            if (r.top_domains?.length) bits.push(`${r.top_domains.length} DNS domains`);
            if (r.service_types?.length) bits.push(`${r.service_types.length} service types`);
            if (r.packets_captured||r.frames_captured||r.frames_observed) bits.push(`${r.packets_captured||r.frames_captured||r.frames_observed} packets`);
            if (r.leases?.length) bits.push(`${r.leases.length} DHCP leases`);
            if (r.devices?.length) bits.push(`${r.devices.length} UPnP devices`);
            if (r.threat_hits?.length) bits.push(`${r.threat_hits.length} threats`);
            if (r.fingerprints?.length) { const snis = r.fingerprints.filter(f=>f.sni).map(f=>f.sni); const uniq = [...new Set(snis)]; bits.push(`${uniq.length} TLS domains: ${uniq.slice(0,4).join(', ')}${uniq.length>4?'...':''}`); }
            if (r.flows?.length) bits.push(`${r.flows.length} encrypted flows`);
            if (r.error) bits.push(`err: ${String(r.error).slice(0,40)}`);
            if (r.results?.length && r.technique === 'banner_grabbing') { const b = r.results.filter(x=>x.has_banner).length; bits.push(b ? `${b} banners` : `${r.results.length} ports scanned`); }
            addLog('found', bits.length ? bits.join(' | ') : `done`);
          }
        } catch (e) { addLog('err', `${tech.technique_id}: ${e.message}`); completedRef.current.add(tkey); }
      }

      // Push new discoveries into the main app (graph, dashboard, etc.)
      if (refreshAppData) refreshAppData();

      if (stopRef.current) break;
      setPhase('cooldown');
      addLog('brain', `Cycle ${loopNum} done. Reassessing in 10s...`);
      for (let w = 0; w < 10 && !stopRef.current; w++) await sleep(1000);
    }
    setPhase('idle');
    setRunning(false);
    addLog('brain', 'Brain stopped.');
  }, [stealth, addLog, setPlan, ingest, refreshAppData]);

  const handleStop = () => { stopRef.current = true; addLog('brain', 'Stopping...'); };

  const logColors = { brain: colors.accent, info: colors.textMuted, run: colors.warning, ok: colors.success, found: '#4ade80', err: colors.danger, wait: colors.textMuted };
  const logIcons = { brain: '\u{1F9E0}', info: '\u2139\uFE0F', run: '\u25B6\uFE0F', ok: '\u2705', found: '\u{1F4A1}', err: '\u274C', wait: '\u23F3' };

  const devList = Object.values(findings.devices).sort((a,b) => (a.ip||'').localeCompare(b.ip||'', undefined, { numeric: true }));
  const dnsList = Object.entries(findings.dns).sort((a,b) => (b[1].count||0) - (a[1].count||0));
  const svcList = findings.services;
  const tabBtn = (id, label, count) => (
    <button key={id} onClick={() => setDashTab(id)} style={{ fontSize: '9px', padding: '3px 10px', borderRadius: '5px', border: `1px solid ${dashTab===id ? colors.accent : colors.border}`, background: dashTab===id ? `${colors.accent}22` : 'transparent', color: dashTab===id ? colors.accent : colors.textMuted, cursor: 'pointer', fontWeight: 700 }}>
      {label}{count > 0 ? ` (${count})` : ''}
    </button>
  );
  const cellS = { fontSize: '9px', padding: '3px 6px', borderBottom: `1px solid ${colors.border}`, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '180px' };
  const hdrS = { ...cellS, fontWeight: 800, color: colors.textMuted, position: 'sticky', top: 0, background: colors.bgCard, zIndex: 1 };

  return (
    <div style={card}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>
          Brain (Autonomous Researcher)
          {running && <span style={{ marginLeft: '8px', fontSize: '9px', color: colors.accent, animation: 'pulse 1.5s infinite' }}>CYCLE {cycle} — {phase.toUpperCase()}</span>}
        </div>
        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
          <span style={{ fontSize: '8px', color: colors.textMuted }}>{findings.techniques_run} techniques | {devList.length} devices | {dnsList.length} domains</span>
          {!running ? (
            <button onClick={brainLoop} style={{ fontSize: '10px', padding: '4px 14px', borderRadius: '6px', border: `1px solid ${colors.success}`, background: `${colors.success}22`, color: colors.success, cursor: 'pointer', fontWeight: 700 }}>Start Research</button>
          ) : (
            <button onClick={handleStop} style={{ fontSize: '10px', padding: '4px 14px', borderRadius: '6px', border: `1px solid ${colors.danger}`, background: `${colors.danger}22`, color: colors.danger, cursor: 'pointer', fontWeight: 700 }}>Stop</button>
          )}
        </div>
      </div>

      <div style={{ marginTop: '6px', display: 'flex', gap: '8px', alignItems: 'center' }}>
        <label style={{ fontSize: '9px', color: colors.textMuted }}>Stealth: {stealth.toFixed(1)}</label>
        <input type="range" min="0" max="1" step="0.1" value={stealth} onChange={e => setStealth(parseFloat(e.target.value))} disabled={running} style={{ flex: 1 }} />
        <button onClick={async () => {
          try {
            const st = await fetch(`${API_BASE}/mitm/status`).then(r=>r.json());
            if (st.active || st.running) {
              await fetch(`${API_BASE}/mitm/stop`, { method: 'POST' });
              addLog('brain', 'MITM stopped');
            } else {
              await fetch(`${API_BASE}/mitm/start`, { method: 'POST' });
              addLog('brain', 'MITM started — full domain + URL visibility');
            }
          } catch (e) { addLog('err', `MITM: ${e.message}`); }
        }} style={{ fontSize: '8px', padding: '3px 8px', borderRadius: '5px', border: `1px solid ${colors.purple}`, background: `${colors.purple}22`, color: colors.purple, cursor: 'pointer', fontWeight: 700, whiteSpace: 'nowrap' }}>MITM</button>
      </div>

      {plan?.situation_summary && (
        <div style={{ marginTop: '8px', display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '6px' }}>
          {[{ val: plan.situation_summary.total_devices, label: 'Known', col: colors.accent }, { val: plan.situation_summary.coverage_pct+'%', label: 'Coverage', col: colors.success }, { val: plan.situation_summary.stale, label: 'Stale', col: colors.warning }, { val: plan.situation_summary.unresolved_alerts, label: 'Alerts', col: colors.danger }].map(({val,label,col}) => (
            <div key={label} style={{ background: colors.bgCard, padding: '4px', borderRadius: '6px', textAlign: 'center' }}>
              <div style={{ fontSize: '13px', fontWeight: 900, color: col }}>{val}</div>
              <div style={{ fontSize: '7px', color: colors.textMuted }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Activity Log */}
      <div style={{ marginTop: '8px', background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '8px', padding: '6px', height: '160px', overflow: 'auto', fontFamily: 'monospace' }}>
        {log.length === 0 && <div style={{ fontSize: '10px', color: colors.textMuted, textAlign: 'center', marginTop: '60px' }}>Click "Start Research" to begin</div>}
        {log.map(e => (
          <div key={e.id} style={{ fontSize: '8.5px', lineHeight: '14px', color: logColors[e.type]||colors.textMuted }}>
            <span style={{ opacity: 0.4 }}>{e.ts}</span> {logIcons[e.type]||''} {e.msg}
          </div>
        ))}
        <div ref={logEndRef} />
      </div>

      {/* Findings Dashboard */}
      {(devList.length > 0 || dnsList.length > 0 || svcList.length > 0) && (<>
        <div style={{ marginTop: '8px', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
          {tabBtn('devices', 'Devices', devList.length)}
          {tabBtn('dns', 'DNS/Names', dnsList.length)}
          {tabBtn('services', 'Services', svcList.length)}
          {tabBtn('analysis', 'Analysis', findings.communities.length + findings.threats.length)}
          {tabBtn('captures', 'Traffic', findings.captures.length)}
        </div>

        <div style={{ marginTop: '6px', background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '8px', height: '220px', overflow: 'auto' }}>
          {dashTab === 'devices' && (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead><tr>{['IP','MAC','Hostname','OS','Ports','Risk','Source'].map(h => <th key={h} style={hdrS}>{h}</th>)}</tr></thead>
              <tbody>{devList.map(d => (
                <tr key={d.ip} style={{ cursor: 'default' }}>
                  <td style={{ ...cellS, color: colors.accent, fontWeight: 700 }}>{d.ip}</td>
                  <td style={{ ...cellS, color: colors.textMuted }}>{d.mac||'—'}</td>
                  <td style={{ ...cellS, color: d.hostname ? '#4ade80' : colors.textMuted }}>{d.hostname||'—'}</td>
                  <td style={{ ...cellS, color: d.os ? colors.warning : colors.textMuted }}>{d.os||'—'}</td>
                  <td style={{ ...cellS, color: d.ports.length ? colors.success : colors.textMuted }}>{d.ports.length ? d.ports.sort((a,b)=>a-b).join(',') : '—'}</td>
                  <td style={{ ...cellS, color: d.risk != null ? (d.risk > 50 ? colors.danger : d.risk > 20 ? colors.warning : colors.success) : colors.textMuted }}>{d.risk != null ? d.risk.toFixed(1) : '—'}</td>
                  <td style={{ ...cellS, color: colors.textMuted, fontSize: '8px' }}>{d.source.join(', ')||'—'}</td>
                </tr>
              ))}</tbody>
            </table>
          )}

          {dashTab === 'dns' && (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead><tr>{['Domain / Name','Type','Count','Queried By'].map(h => <th key={h} style={hdrS}>{h}</th>)}</tr></thead>
              <tbody>{dnsList.map(([name, info]) => (
                <tr key={name}>
                  <td style={{ ...cellS, color: name.includes('.') ? colors.accent : '#4ade80', fontWeight: 600, maxWidth: '250px' }}>{name}</td>
                  <td style={{ ...cellS, color: colors.textMuted }}>{info.type||'—'}</td>
                  <td style={{ ...cellS, color: colors.warning }}>{info.count||1}</td>
                  <td style={{ ...cellS, color: colors.textMuted, fontSize: '8px' }}>{(info.queriedBy||[]).slice(0,3).join(', ')||'—'}</td>
                </tr>
              ))}</tbody>
            </table>
          )}

          {dashTab === 'services' && (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead><tr>{['IP','Port','Service','Product','Banner'].map(h => <th key={h} style={hdrS}>{h}</th>)}</tr></thead>
              <tbody>{svcList.map((s,i) => (
                <tr key={i}>
                  <td style={{ ...cellS, color: colors.accent }}>{s.ip}</td>
                  <td style={{ ...cellS, color: colors.warning }}>{s.port}</td>
                  <td style={{ ...cellS, color: colors.success }}>{s.service||'—'}</td>
                  <td style={{ ...cellS, color: colors.textMuted }}>{s.product||'—'}</td>
                  <td style={{ ...cellS, color: colors.textMuted, maxWidth: '200px' }}>{s.banner?.slice(0,60)||'—'}</td>
                </tr>
              ))}</tbody>
            </table>
          )}

          {dashTab === 'analysis' && (
            <div style={{ padding: '8px', fontSize: '9px' }}>
              {findings.communities.length > 0 && (<div>
                <div style={{ fontWeight: 800, color: colors.text, marginBottom: '4px' }}>Traffic Communities ({findings.communities.length})</div>
                {findings.communities.map((c,i) => <div key={i} style={{ color: colors.textMuted, marginBottom: '2px' }}>Cluster {i+1}: {(c.members||c.nodes||[]).slice(0,6).join(', ')}{(c.members||c.nodes||[]).length>6?'...':''}</div>)}
              </div>)}
              {findings.threats.length > 0 && (<div style={{ marginTop: '8px' }}>
                <div style={{ fontWeight: 800, color: colors.danger, marginBottom: '4px' }}>Threats ({findings.threats.length})</div>
                {findings.threats.map((t,i) => <div key={i} style={{ color: colors.danger, marginBottom: '2px' }}>{t.type||'threat'}: {t.indicator||t.id||t.ip||'?'} — {t.description||t.summary||''}</div>)}
              </div>)}
              {findings.communities.length === 0 && findings.threats.length === 0 && <div style={{ color: colors.textMuted, textAlign: 'center', marginTop: '80px' }}>No analysis results yet — Brain will run community detection and threat checks</div>}
            </div>
          )}

          {dashTab === 'captures' && (
            <div style={{ padding: '8px', fontSize: '9px' }}>
              {findings.captures.length > 0 ? findings.captures.map((c,i) => (
                <div key={i} style={{ marginBottom: '8px', background: colors.bgTertiary, padding: '6px', borderRadius: '6px' }}>
                  <div style={{ fontWeight: 700, color: colors.text }}>{c.frames} packets in {c.duration?.toFixed(1)}s {c.uniqueIPs ? `| ${c.uniqueIPs} unique IPs, ${c.uniqueMACs} MACs` : ''}</div>
                  {c.protocols && Object.keys(c.protocols).length > 0 && (<div style={{ color: colors.textMuted, marginTop: '4px' }}>
                    <span style={{ fontWeight: 700, color: colors.text }}>Protocols:</span>{' '}
                    {Object.entries(c.protocols).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([p,n])=>`${p}: ${n}`).join(' | ')}
                  </div>)}
                  {c.topTalkers?.length > 0 && (<div style={{ marginTop: '6px' }}>
                    <div style={{ fontWeight: 700, color: colors.text, marginBottom: '2px' }}>Top Talkers:</div>
                    {c.topTalkers.slice(0,10).map((t,j) => (
                      <div key={j} style={{ display: 'flex', gap: '8px', color: colors.textMuted, marginBottom: '1px' }}>
                        <span style={{ color: colors.accent, minWidth: '110px' }}>{t.ip||t.src}</span>
                        <span style={{ color: colors.warning }}>{t.bytes ? `${(t.bytes/1024).toFixed(1)} KB` : `${t.packets||'?'} pkts`}</span>
                      </div>
                    ))}
                  </div>)}
                </div>
              )) : <div style={{ color: colors.textMuted, textAlign: 'center', marginTop: '80px' }}>No traffic captures yet — Brain will run promiscuous capture</div>}
            </div>
          )}
        </div>
      </>)}

      {plan?.error && <div style={{ marginTop: '6px', fontSize: '9px', color: colors.danger }}>{plan.error}</div>}
    </div>
  );
}

// ============================================================================
// NL Query Panel (Phase 6.3 — Natural Language Query)
// ============================================================================

function NLQueryPanel({ query, setQuery, result, setResult, loading, setLoading }) {
  const card = { background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '16px', marginTop: '12px' };

  const runQuery = async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/nip/query`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query }) });
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
      <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>Network Intelligence Query</div>
      <div style={{ marginTop: '10px', display: 'flex', gap: '8px' }}>
        <input value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') runQuery(); }}
          placeholder="Ask a question about the network..."
          style={{ flex: 1, fontSize: '11px', padding: '8px 12px', borderRadius: '8px', border: `1px solid ${colors.border}`, background: colors.bgCard, color: colors.text, outline: 'none' }} />
        <button onClick={runQuery} disabled={loading} style={{ fontSize: '10px', padding: '6px 16px', borderRadius: '8px', border: `1px solid ${colors.accent}`, background: `${colors.accent}22`, color: colors.accent, cursor: 'pointer', whiteSpace: 'nowrap' }}>
          {loading ? '...' : 'Query'}
        </button>
      </div>
      <div style={{ marginTop: '8px', display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
        {examples.map(ex => (
          <button key={ex} onClick={() => { setQuery(ex); }} style={{ fontSize: '9px', padding: '3px 8px', borderRadius: '999px', border: `1px solid ${colors.border}`, background: colors.bgCard, color: colors.textMuted, cursor: 'pointer' }}>{ex}</button>
        ))}
      </div>
      {result?.explanation && <div style={{ marginTop: '10px', fontSize: '10px', color: colors.accent }}>{result.explanation}</div>}
      {result?.results && (
        <div style={{ marginTop: '8px', maxHeight: '400px', overflow: 'auto' }}>
          <pre style={{ fontSize: '10px', color: colors.textMuted, whiteSpace: 'pre-wrap', lineHeight: 1.6, margin: 0 }}>
            {JSON.stringify(result.results, null, 2).slice(0, 5000)}
          </pre>
        </div>
      )}
      {result?.error && <div style={{ marginTop: '10px', fontSize: '10px', color: colors.danger }}>{result.error}</div>}
    </div>
  );
}

// ============================================================================
// Quality Panel (Phase 7.3 — Intelligence Quality Metrics)
// ============================================================================

function QualityPanel({ metrics, setMetrics, loading, setLoading, hasLoaded, setHasLoaded }) {
  const card = { background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '16px', marginTop: '12px' };

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

  useEffect(() => { if (!hasLoaded) refresh(); }, [hasLoaded]);

  const disc = metrics?.discovery;
  const risk = metrics?.risk_distribution;
  const anom = metrics?.anomaly;

  return (
    <div style={card}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>Intelligence Quality Metrics</div>
        <button onClick={refresh} disabled={loading} style={{ fontSize: '10px', padding: '4px 12px', borderRadius: '6px', border: `1px solid ${colors.accent}`, background: `${colors.accent}22`, color: colors.accent, cursor: 'pointer' }}>
          {loading ? '...' : 'Refresh'}
        </button>
      </div>
      {disc && (
        <div style={{ marginTop: '12px', background: colors.bgCard, padding: '10px', borderRadius: '8px' }}>
          <div style={{ fontSize: '11px', fontWeight: 700, color: colors.text }}>Discovery Completeness</div>
          <div style={{ marginTop: '6px', fontSize: '10px', color: colors.textMuted }}>
            Discovered: {disc.discovered} devices
            {disc.completeness_pct != null && <span> ({disc.completeness_pct}% of ground truth)</span>}
          </div>
        </div>
      )}
      {risk && risk.count > 0 && (
        <div style={{ marginTop: '8px', background: colors.bgCard, padding: '10px', borderRadius: '8px' }}>
          <div style={{ fontSize: '11px', fontWeight: 700, color: colors.text }}>Risk Score Distribution</div>
          <div style={{ marginTop: '6px', display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '6px' }}>
            {Object.entries(risk.buckets || {}).map(([k,v]) => (
              <div key={k} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '14px', fontWeight: 900, color: k === 'critical' ? colors.danger : k === 'high' ? colors.orange : k === 'medium' ? colors.warning : colors.success }}>{v}</div>
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
        <div style={{ marginTop: '8px', background: colors.bgCard, padding: '10px', borderRadius: '8px' }}>
          <div style={{ fontSize: '11px', fontWeight: 700, color: colors.text }}>Anomaly Detection</div>
          <div style={{ marginTop: '6px', fontSize: '10px', color: colors.textMuted }}>
            Total alerts: {anom.total_alerts}
            {anom.precision != null && <span> | Precision: {anom.precision} | Recall: {anom.recall}</span>}
          </div>
        </div>
      )}
      {metrics?.error && <div style={{ marginTop: '10px', fontSize: '10px', color: colors.danger }}>{metrics.error}</div>}
    </div>
  );
}

// ============================================================================
// NIP View (Roadmap Substrate Console)
// ============================================================================

function NipView({ status, devices, nipPanelState, updateNipState, refreshAppData }) {
  const ps = nipPanelState || {};
  const [tab, setTabLocal] = useState(ps.nipTab || 'metrics');
  const setTab = useCallback((t) => { setTabLocal(t); if (updateNipState) updateNipState({ nipTab: t }); }, [updateNipState]);
  const [daemon, setDaemon] = useState(null);
  const [techniques, setTechniques] = useState([]);
  const [events, setEvents] = useState([]);
  const [metrics, setMetrics] = useState([]);
  const [baseline, setBaseline] = useState(null);
  const [threat, setThreat] = useState(null);
  const [threatLoading, setThreatLoading] = useState(false);
  const [err, setErr] = useState(null);

  // Persistent panel state (survives main-view switches via App-level ref)
  const [brainPlan, setBrainPlanLocal] = useState(ps.brainPlan);
  const [brainLoading, setBrainLoadingLocal] = useState(ps.brainLoading || false);
  const [brainStealth, setBrainStealthLocal] = useState(ps.brainStealth ?? 0.5);
  const setBrainPlan = useCallback((v) => { setBrainPlanLocal(v); if (updateNipState) updateNipState({ brainPlan: v }); }, [updateNipState]);
  const setBrainLoading = useCallback((v) => { setBrainLoadingLocal(v); if (updateNipState) updateNipState({ brainLoading: v }); }, [updateNipState]);
  const setBrainStealth = useCallback((v) => { setBrainStealthLocal(v); if (updateNipState) updateNipState({ brainStealth: v }); }, [updateNipState]);

  const [nlQuery, setNlQueryLocal] = useState(ps.nlQuery || '');
  const [nlResult, setNlResultLocal] = useState(ps.nlResult);
  const [nlLoading, setNlLoadingLocal] = useState(ps.nlLoading || false);
  const setNlQuery = useCallback((v) => { setNlQueryLocal(v); if (updateNipState) updateNipState({ nlQuery: v }); }, [updateNipState]);
  const setNlResult = useCallback((v) => { setNlResultLocal(v); if (updateNipState) updateNipState({ nlResult: v }); }, [updateNipState]);
  const setNlLoading = useCallback((v) => { setNlLoadingLocal(v); if (updateNipState) updateNipState({ nlLoading: v }); }, [updateNipState]);

  const [qualityMetrics, setQualityMetricsLocal] = useState(ps.qualityMetrics);
  const [qualityLoading, setQualityLoadingLocal] = useState(ps.qualityLoading || false);
  const [qualityHasLoaded, setQualityHasLoadedLocal] = useState(ps.qualityHasLoaded || false);
  const setQualityMetrics = useCallback((v) => { setQualityMetricsLocal(v); if (updateNipState) updateNipState({ qualityMetrics: v }); }, [updateNipState]);
  const setQualityLoading = useCallback((v) => { setQualityLoadingLocal(v); if (updateNipState) updateNipState({ qualityLoading: v }); }, [updateNipState]);
  const setQualityHasLoaded = useCallback((v) => { setQualityHasLoadedLocal(v); if (updateNipState) updateNipState({ qualityHasLoaded: v }); }, [updateNipState]);

  const [cfg, setCfg] = useState(() => ({
    intervalSeconds: 10,
    alpha: 0.2,
    eventLimit: 200,
    metricsLimit: 120,
    threatPath: '',
  }));

  const ips = (devices || []).map(d => d?.ip).filter(Boolean);
  const [selectedIp, setSelectedIp] = useState('');
  const [customIp, setCustomIp] = useState('');
  const focusIp = (customIp || '').trim() ? (customIp || '').trim() : (selectedIp || '').trim();

  useEffect(() => {
    if (!selectedIp && ips.length > 0) setSelectedIp(ips[0]);
  }, [ips.join('|')]);

  const fetchJson = async (url, opts = {}) => {
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
    return data;
  };

  const refreshDaemon = async () => {
    try {
      const data = await fetchJson(`${API_BASE}/nip/daemon/status`);
      setDaemon(data?.daemon || null);
    } catch {}
  };

  const refreshTechniques = async () => {
    try {
      const data = await fetchJson(`${API_BASE}/nip/techniques`);
      setTechniques(data?.techniques || []);
    } catch {}
  };

  const refreshEvents = async () => {
    try {
      const data = await fetchJson(`${API_BASE}/nip/events?limit=${encodeURIComponent(cfg.eventLimit)}`);
      setEvents(data?.events || []);
    } catch {}
  };

  const refreshMetrics = async () => {
    if (!focusIp) return;
    try {
      const data = await fetchJson(`${API_BASE}/nip/metrics?ip=${encodeURIComponent(focusIp)}&limit=${encodeURIComponent(cfg.metricsLimit)}`);
      setMetrics(data?.metrics || []);
    } catch {}
  };

  const refreshBaseline = async () => {
    if (!focusIp) return;
    try {
      const data = await fetchJson(`${API_BASE}/nip/baselines?ip=${encodeURIComponent(focusIp)}`);
      setBaseline(data?.baseline || null);
    } catch {}
  };

  const refreshAll = async () => {
    setErr(null);
    await Promise.all([
      refreshDaemon(),
      refreshTechniques(),
      refreshEvents(),
    ]);
    await Promise.all([
      refreshMetrics(),
      refreshBaseline(),
    ]);
  };

  useEffect(() => { refreshAll(); }, []);
  useEffect(() => { refreshMetrics(); refreshBaseline(); }, [focusIp, cfg.metricsLimit]);
  useEffect(() => { refreshEvents(); }, [cfg.eventLimit]);

  useEffect(() => {
    const t = setInterval(() => {
      refreshDaemon();
      if (tab === 'events') refreshEvents();
      if (tab === 'metrics') refreshMetrics();
    }, 4000);
    return () => clearInterval(t);
  }, [tab, focusIp, cfg.eventLimit, cfg.metricsLimit]);

  const startDaemon = async () => {
    setErr(null);
    try {
      const data = await fetchJson(`${API_BASE}/nip/daemon/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interval_seconds: cfg.intervalSeconds, alpha: cfg.alpha }),
      });
      setDaemon(data?.daemon || null);
    } catch (e) {
      setErr(`Failed to start daemon: ${e.message || e.toString()}`);
    }
  };

  const stopDaemon = async () => {
    setErr(null);
    try {
      const data = await fetchJson(`${API_BASE}/nip/daemon/stop`, { method: 'POST' });
      setDaemon(data?.daemon || null);
    } catch (e) {
      setErr(`Failed to stop daemon: ${e.message || e.toString()}`);
    }
  };

  const runThreatCheck = async () => {
    setErr(null);
    setThreatLoading(true);
    try {
      const qp = (cfg.threatPath || '').trim() ? `?path=${encodeURIComponent((cfg.threatPath || '').trim())}` : '';
      const data = await fetchJson(`${API_BASE}/nip/threat/check${qp}`);
      setThreat(data || null);
      setTab('threat');
    } catch (e) {
      setErr(`Threat check failed: ${e.message || e.toString()}`);
    }
    setThreatLoading(false);
  };

  const card = {
    background: colors.bgCard,
    border: `1px solid ${colors.border}`,
    borderRadius: '12px',
    padding: '14px',
  };

  const inputStyle = {
    background: colors.bgTertiary,
    border: `1px solid ${colors.border}`,
    borderRadius: '10px',
    padding: '8px',
    color: colors.text,
    fontSize: '10px',
    outline: 'none',
    width: '100%',
  };

  const smallBtn = (active) => ({
    padding: '7px 10px',
    background: active ? colors.accent : colors.bgTertiary,
    border: `1px solid ${active ? colors.accent : colors.border}`,
    borderRadius: '10px',
    color: active ? colors.bg : colors.text,
    fontSize: '10px',
    fontWeight: 900,
    cursor: 'pointer',
  });

  const metricSeries = (metrics || []).slice().reverse();
  const bytesOutSeries = metricSeries.slice(-48).map((m) => ({
    value: Number(m.bytes_out || 0),
    label: String(m.timestamp || '').slice(11, 19) || 't',
  }));
  const uniqPortsSeries = metricSeries.slice(-48).map((m) => ({
    value: Number(m.unique_dst_ports || 0),
    label: String(m.timestamp || '').slice(11, 19) || 't',
  }));
  const dnsSeries = metricSeries.slice(-48).map((m) => ({
    value: Number(m.dns_queries || 0),
    label: String(m.timestamp || '').slice(11, 19) || 't',
  }));

  return (
    <div style={{ padding: '16px', overflow: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '420px 1fr', gap: '16px', alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={card}>
            <div style={{ fontSize: '14px', fontWeight: 900, color: colors.text }}>NIP Console</div>
            <div style={{ fontSize: '10px', color: colors.textMuted, marginTop: '6px', lineHeight: 1.5 }}>
              Roadmap substrate: techniques registry, event bus, and temporal baselines. Capture auto-starts the daemon; you can also control it here.
            </div>
            {err && <div style={{ marginTop: '10px', fontSize: '10px', color: colors.danger }}>{err}</div>}
          </div>

          <div style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px' }}>
              <div style={{ fontSize: '11px', fontWeight: 900, color: colors.text }}>Metrics Daemon</div>
              <div style={{
                fontSize: '10px',
                fontWeight: 900,
                color: daemon?.running ? colors.success : colors.textMuted,
              }}>{daemon?.running ? 'RUNNING' : 'STOPPED'}</div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '10px' }}>
              <div>
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>interval_seconds</div>
                <input
                  type="number"
                  value={cfg.intervalSeconds}
                  onChange={(e) => setCfg((c) => ({ ...c, intervalSeconds: parseInt(e.target.value || '0', 10) }))}
                  style={inputStyle}
                  min={2}
                />
              </div>
              <div>
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>alpha (EWMA)</div>
                <input
                  type="number"
                  value={cfg.alpha}
                  onChange={(e) => setCfg((c) => ({ ...c, alpha: parseFloat(e.target.value || '0') }))}
                  style={inputStyle}
                  step="0.05"
                  min={0.01}
                  max={0.9}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
              <button onClick={startDaemon} style={{ ...smallBtn(true), background: colors.success, borderColor: colors.success, color: colors.bg }}>Start</button>
              <button onClick={stopDaemon} style={{ ...smallBtn(false), background: colors.danger, borderColor: colors.danger, color: '#fff' }}>Stop</button>
              <button onClick={refreshDaemon} style={smallBtn(false)}>Refresh</button>
            </div>

            <div style={{ marginTop: '10px', fontSize: '10px', color: colors.textMuted, lineHeight: 1.6 }}>
              baseline_hosts={daemon?.baseline_hosts ?? '-'} · last_tick_at={daemon?.last_tick_at || '-'}
            </div>
          </div>

          <div style={card}>
            <div style={{ fontSize: '11px', fontWeight: 900, color: colors.text }}>Focus</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '10px' }}>
              <div>
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>Device IP</div>
                <select value={selectedIp} onChange={(e) => setSelectedIp(e.target.value)} style={inputStyle}>
                  {(ips.length ? ips : ['']).map((ip) => (
                    <option key={ip || 'none'} value={ip}>{ip || '(no devices yet)'}</option>
                  ))}
                </select>
              </div>
              <div>
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>Custom IP (override)</div>
                <input value={customIp} onChange={(e) => setCustomIp(e.target.value)} style={inputStyle} placeholder="192.168.56.10" />
              </div>
              <div>
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>metrics_limit</div>
                <input
                  type="number"
                  value={cfg.metricsLimit}
                  onChange={(e) => setCfg((c) => ({ ...c, metricsLimit: parseInt(e.target.value || '0', 10) }))}
                  style={inputStyle}
                  min={10}
                  max={800}
                />
              </div>
              <div>
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>events_limit</div>
                <input
                  type="number"
                  value={cfg.eventLimit}
                  onChange={(e) => setCfg((c) => ({ ...c, eventLimit: parseInt(e.target.value || '0', 10) }))}
                  style={inputStyle}
                  min={20}
                  max={2000}
                />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '10px' }}>
              <div>
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>threat_path (optional)</div>
                <input
                  value={cfg.threatPath}
                  onChange={(e) => setCfg((c) => ({ ...c, threatPath: e.target.value }))}
                  style={inputStyle}
                  placeholder="samples/threat_indicators.json"
                />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '4px' }}>threat.check</div>
                <button onClick={runThreatCheck} style={{
                  padding: '8px',
                  background: colors.bgTertiary,
                  border: `1px solid ${colors.border}`,
                  borderRadius: '10px',
                  color: colors.text,
                  fontSize: '10px',
                  fontWeight: 900,
                  cursor: 'pointer'
                }}>{threatLoading ? 'Checking…' : 'Run Threat Check'}</button>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
              <button onClick={refreshAll} style={{ ...smallBtn(true), background: colors.accent, borderColor: colors.accent, color: colors.bg }}>Refresh All</button>
              <button onClick={() => { refreshMetrics(); refreshBaseline(); }} style={smallBtn(false)}>Refresh Metrics</button>
              <button onClick={refreshEvents} style={smallBtn(false)}>Refresh Events</button>
            </div>
            <div style={{ marginTop: '10px', fontSize: '10px', color: colors.textMuted }}>
              focus_ip=<span style={{ color: colors.accent }}>{focusIp || '-'}</span>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ ...card, padding: '12px' }}>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button onClick={() => setTab('metrics')} style={smallBtn(tab === 'metrics')}>Metrics</button>
              <button onClick={() => setTab('events')} style={smallBtn(tab === 'events')}>Events</button>
              <button onClick={() => setTab('threat')} style={smallBtn(tab === 'threat')}>Threat</button>
              <button onClick={() => setTab('techniques')} style={smallBtn(tab === 'techniques')}>Techniques</button>
              <button onClick={() => setTab('brain')} style={smallBtn(tab === 'brain')}>Brain</button>
              <button onClick={() => setTab('query')} style={smallBtn(tab === 'query')}>Query</button>
              <button onClick={() => setTab('quality')} style={smallBtn(tab === 'quality')}>Quality</button>
            </div>
          </div>

          {tab === 'metrics' && (
            <>
              <div style={card}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
                  <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>Behavior Baseline</div>
                  <div style={{ fontSize: '10px', color: colors.textMuted }}>{baseline?.computed_at ? `computed_at=${baseline.computed_at}` : 'no baseline yet'}</div>
                </div>
                {baseline?.baseline && (
                  <div style={{ marginTop: '10px', display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '10px' }}>
                    <StatsCard title="AVG BYTES OUT" value={formatBytes(Math.round(baseline.baseline.avg_bytes_out || 0))} color={colors.accent} />
                    <StatsCard title="AVG BYTES IN" value={formatBytes(Math.round(baseline.baseline.avg_bytes_in || 0))} color={colors.success} />
                    <StatsCard title="AVG DST IPs" value={formatNumber(Math.round(baseline.baseline.avg_unique_dst_ips || 0))} color={colors.purple} />
                    <StatsCard title="AVG DST PORTS" value={formatNumber(Math.round(baseline.baseline.avg_unique_dst_ports || 0))} color={colors.warning} />
                    <StatsCard title="AVG DNS" value={formatNumber(Math.round(baseline.baseline.avg_dns_queries || 0))} color={colors.pink} />
                  </div>
                )}
                {!baseline?.baseline && (
                  <div style={{ marginTop: '10px', fontSize: '11px', color: colors.textMuted, lineHeight: 1.6 }}>
                    Start capture to generate per-window metrics and build a baseline. The daemon runs EWMA baselines by default.
                  </div>
                )}
                <div style={{ marginTop: '10px', fontSize: '10px', color: colors.textMuted }}>method={baseline?.method || '-'}</div>
              </div>

              <div style={card}>
                <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>Recent Metrics</div>
                <div style={{ fontSize: '10px', color: colors.textMuted, marginTop: '6px' }}>
                  windows={metrics?.length || 0} · newest={metrics?.[0]?.timestamp || '-'}
                </div>

                <div style={{ marginTop: '12px', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
                  <div>
                    <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '6px' }}>bytes_out</div>
                    <MiniBarChart data={bytesOutSeries} color={colors.accent} height={70} valueFormatter={(v) => formatBytes(v)} />
                  </div>
                  <div>
                    <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '6px' }}>unique_dst_ports</div>
                    <MiniBarChart data={uniqPortsSeries} color={colors.warning} height={70} valueFormatter={(v) => formatNumber(v)} />
                  </div>
                  <div>
                    <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '6px' }}>dns_queries</div>
                    <MiniBarChart data={dnsSeries} color={colors.pink} height={70} valueFormatter={(v) => formatNumber(v)} />
                  </div>
                </div>

                <div style={{ marginTop: '12px', maxHeight: '260px', overflow: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '10px' }}>
                    <thead>
                      <tr style={{ textAlign: 'left', color: colors.textMuted }}>
                        <th style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>ts</th>
                        <th style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>bytes_out</th>
                        <th style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>bytes_in</th>
                        <th style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>dst_ips</th>
                        <th style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>dst_ports</th>
                        <th style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>dns</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(metrics || []).slice(0, 25).map((m, i) => (
                        <tr key={i} style={{ color: colors.text }}>
                          <td style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>{String(m.timestamp || '').slice(11, 19) || '-'}</td>
                          <td style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>{formatBytes(m.bytes_out || 0)}</td>
                          <td style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>{formatBytes(m.bytes_in || 0)}</td>
                          <td style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>{formatNumber(m.unique_dst_ips || 0)}</td>
                          <td style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>{formatNumber(m.unique_dst_ports || 0)}</td>
                          <td style={{ padding: '6px 8px', borderBottom: `1px solid ${colors.border}` }}>{formatNumber(m.dns_queries || 0)}</td>
                        </tr>
                      ))}
                      {(metrics || []).length === 0 && (
                        <tr><td colSpan={6} style={{ padding: '10px 8px', color: colors.textMuted }}>No metrics yet. Start capture to generate data.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          {tab === 'events' && (
            <div style={card}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
                <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>Event Bus</div>
                <div style={{ fontSize: '10px', color: colors.textMuted }}>events={events?.length || 0}</div>
              </div>
              <div style={{ marginTop: '10px', maxHeight: '520px', overflow: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {(events || []).slice().reverse().map((ev) => {
                  const isAnom = String(ev.type || '').includes('anomaly');
                  return (
                    <div key={ev.id} style={{
                      background: colors.bgTertiary,
                      border: `1px solid ${isAnom ? colors.warning : colors.border}`,
                      borderRadius: '10px',
                      padding: '10px',
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                        <div style={{ fontSize: '10px', fontWeight: 900, color: isAnom ? colors.warning : colors.accent }}>
                          {ev.type}
                        </div>
                        <div style={{ fontSize: '9px', color: colors.textMuted }}>{String(ev.ts || '').replace('T', ' ').slice(0, 19)}</div>
                      </div>
                      <div style={{ marginTop: '6px', fontSize: '11px', color: colors.text, lineHeight: 1.5 }}>{ev.summary}</div>
                      <div style={{ marginTop: '6px', fontSize: '9px', color: colors.textMuted }}>
                        entity={ev.entity || '-'} · source={ev.source || '-'}
                      </div>
                    </div>
                  );
                })}
                {(events || []).length === 0 && (
                  <div style={{ fontSize: '11px', color: colors.textMuted }}>No events yet. Run coursework/multichain or start capture to generate events.</div>
                )}
              </div>
            </div>
          )}

          {tab === 'threat' && (
            <div style={card}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
                <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>Threat Check</div>
                <div style={{ fontSize: '10px', color: colors.textMuted }}>
                  {threat?.generated_at ? `generated_at=${String(threat.generated_at).replace('T',' ').slice(0, 19)}` : 'not run yet'}
                </div>
              </div>

              <div style={{ marginTop: '8px', fontSize: '10px', color: colors.textMuted, lineHeight: 1.6 }}>
                feed_path={threat?.feed_path || '(default)'} · indicators ips={threat?.indicators_loaded?.ips ?? 0} domains={threat?.indicators_loaded?.domains ?? 0} · matches total={threat?.counts?.total ?? 0}
              </div>

              <div style={{ marginTop: '10px', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
                <StatsCard title="FLOW MATCHES" value={threat?.counts?.flow_matches ?? 0} color={colors.warning} />
                <StatsCard title="DNS MATCHES" value={threat?.counts?.dns_matches ?? 0} color={colors.pink} />
                <StatsCard title="TOTAL" value={threat?.counts?.total ?? 0} color={(threat?.counts?.total || 0) > 0 ? colors.danger : colors.textMuted} />
                <StatsCard title="INDICATORS" value={`${threat?.indicators_loaded?.ips ?? 0}/${threat?.indicators_loaded?.domains ?? 0}`} subtitle="ips/domains" color={colors.accent} />
              </div>

              <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
                <button onClick={runThreatCheck} style={smallBtn(false)}>{threatLoading ? 'Checking…' : 'Run Again'}</button>
              </div>

              {!threat && (
                <div style={{ marginTop: '10px', fontSize: '11px', color: colors.textMuted, lineHeight: 1.6 }}>
                  Run Threat Check to compare recent flows and DNS queries against a local indicator file (default: <span style={{ color: colors.accent }}>samples/threat_indicators.json</span>).
                </div>
              )}

              {threat && (
                <div style={{ marginTop: '12px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '10px' }}>
                    <div style={{ fontSize: '10px', fontWeight: 900, color: colors.text, marginBottom: '8px' }}>Flow Matches</div>
                    <div style={{ maxHeight: '260px', overflow: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {(threat?.matches?.flows || []).slice(0, 40).map((m, i) => (
                        <div key={i} style={{ background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '10px', padding: '8px' }}>
                          <div style={{ fontSize: '10px', color: colors.text }}>
                            {m.src_ip} → {m.dst_ip}:{m.dst_port} <span style={{ color: colors.textMuted }}>({m.protocol}{m.application ? `/${m.application}` : ''})</span>
                          </div>
                          <div style={{ fontSize: '9px', color: colors.warning, marginTop: '4px' }}>
                            indicator_ip={m.indicator_ip || '-'} · bytes={formatBytes(m.byte_count || 0)}
                          </div>
                        </div>
                      ))}
                      {(threat?.matches?.flows || []).length === 0 && (
                        <div style={{ fontSize: '10px', color: colors.textMuted }}>No flow matches.</div>
                      )}
                    </div>
                  </div>

                  <div style={{ background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '10px' }}>
                    <div style={{ fontSize: '10px', fontWeight: 900, color: colors.text, marginBottom: '8px' }}>DNS Matches</div>
                    <div style={{ maxHeight: '260px', overflow: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {(threat?.matches?.dns || []).slice(0, 40).map((m, i) => (
                        <div key={i} style={{ background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '10px', padding: '8px' }}>
                          <div style={{ fontSize: '10px', color: colors.text }}>
                            {m.src_ip} · {m.domain}
                          </div>
                          <div style={{ fontSize: '9px', color: colors.pink, marginTop: '4px' }}>
                            indicator_domain={m.indicator_domain || '-'} · indicator_ip={m.indicator_ip || '-'}
                          </div>
                        </div>
                      ))}
                      {(threat?.matches?.dns || []).length === 0 && (
                        <div style={{ fontSize: '10px', color: colors.textMuted }}>No DNS matches.</div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {tab === 'techniques' && (
            <div style={card}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
                <div style={{ fontSize: '12px', fontWeight: 900, color: colors.text }}>Technique Registry</div>
                <div style={{ fontSize: '10px', color: colors.textMuted }}>count={techniques?.length || 0}</div>
              </div>
              <div style={{ marginTop: '10px', maxHeight: '520px', overflow: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {(techniques || []).map((t) => (
                  <div key={t.id} style={{
                    background: colors.bgTertiary,
                    border: `1px solid ${t.lab_only ? colors.warning : colors.border}`,
                    borderRadius: '10px',
                    padding: '10px',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                      <div style={{ fontSize: '11px', fontWeight: 900, color: colors.text }}>{t.name}</div>
                      <div style={{ fontSize: '9px', color: colors.textMuted }}>{t.scope} · {t.module}:{t.action}</div>
                    </div>
                    <div style={{ marginTop: '6px', fontSize: '10px', color: colors.textMuted, lineHeight: 1.5 }}>{t.description}</div>
	                    <div style={{ marginTop: '8px', display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
	                      {t.status && t.status !== 'available' && (
	                        <span style={{
	                          fontSize: '9px',
	                          padding: '2px 6px',
	                          borderRadius: '999px',
	                          background: t.status === 'declined' ? `${colors.danger}22` : `${colors.warning}22`,
	                          border: `1px solid ${t.status === 'declined' ? colors.danger : colors.warning}55`,
	                          color: t.status === 'declined' ? colors.danger : colors.warning
	                        }}>{t.status}</span>
	                      )}
	                      {(t.tags || []).slice(0, 8).map((tag) => (
	                        <span key={tag} style={{ fontSize: '9px', padding: '2px 6px', borderRadius: '999px', background: colors.bgCard, border: `1px solid ${colors.border}`, color: colors.textMuted }}>{tag}</span>
	                      ))}
                      {t.lab_only && <span style={{ fontSize: '9px', padding: '2px 6px', borderRadius: '999px', background: `${colors.warning}22`, border: `1px solid ${colors.warning}55`, color: colors.warning }}>lab_only</span>}
                      {t.requires_root && <span style={{ fontSize: '9px', padding: '2px 6px', borderRadius: '999px', background: `${colors.danger}22`, border: `1px solid ${colors.danger}55`, color: colors.danger }}>requires_root</span>}
                      {t.mode && <span style={{ fontSize: '9px', padding: '2px 6px', borderRadius: '999px', background: t.mode === 'passive' ? `${colors.success}22` : `${colors.accent}22`, border: `1px solid ${t.mode === 'passive' ? colors.success : colors.accent}55`, color: t.mode === 'passive' ? colors.success : colors.accent }}>{t.mode}</span>}
                      {typeof t.stealth === 'number' && <span style={{ fontSize: '9px', padding: '2px 6px', borderRadius: '999px', background: `${colors.purple}22`, border: `1px solid ${colors.purple}55`, color: colors.purple }}>stealth:{t.stealth.toFixed(1)}</span>}
                    </div>
                    {(t.consumes || []).length > 0 && (
                      <div style={{ marginTop: '8px', fontSize: '9px', color: colors.textMuted }}>
                        consumes: {(t.consumes || []).join(', ')}
                      </div>
                    )}
	                    {(t.provides || []).length > 0 && (
	                      <div style={{ marginTop: '4px', fontSize: '9px', color: colors.textMuted }}>
	                        provides: {(t.provides || []).join(', ')}
	                      </div>
	                    )}
	                    {t.estimated_time && t.estimated_time !== 'varies' && (
	                      <div style={{ marginTop: '4px', fontSize: '9px', color: colors.textMuted }}>
	                        time: {t.estimated_time}
	                      </div>
	                    )}
	                    {t.rationale && (
	                      <div style={{ marginTop: '6px', fontSize: '9px', color: colors.textMuted }}>
	                        note: {t.rationale}
	                      </div>
	                    )}
	                  </div>
	                ))}
                {(techniques || []).length === 0 && (
                  <div style={{ fontSize: '11px', color: colors.textMuted }}>No registry loaded (backend offline?).</div>
                )}
              </div>
            </div>
          )}

          <div style={{ display: tab === 'brain' ? 'block' : 'none' }}>
            <BrainPanel plan={brainPlan} setPlan={setBrainPlan} loading={brainLoading} setLoading={setBrainLoading} stealth={brainStealth} setStealth={setBrainStealth} refreshAppData={refreshAppData} />
          </div>
          {tab === 'query' && <NLQueryPanel query={nlQuery} setQuery={setNlQuery} result={nlResult} setResult={setNlResult} loading={nlLoading} setLoading={setNlLoading} />}
          {tab === 'quality' && <QualityPanel metrics={qualityMetrics} setMetrics={setQualityMetrics} loading={qualityLoading} setLoading={setQualityLoading} hasLoaded={qualityHasLoaded} setHasLoaded={setQualityHasLoaded} />}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Network Graph (Enhanced)
// ============================================================================

function useForceSimulation(nodes, edges, width, height) {
  const [positions, setPositions] = useState({});
  const simulationRef = useRef(null);
  
  useEffect(() => {
    if (nodes.length === 0) return;
    
    const nodePositions = {};
    nodes.forEach((node, i) => {
      if (node.is_gateway) {
        nodePositions[node.id] = { x: width / 2, y: height / 2, vx: 0, vy: 0 };
      } else {
        const angle = (i / nodes.length) * 2 * Math.PI;
        const radius = Math.min(width, height) * 0.35;
        nodePositions[node.id] = {
          x: width / 2 + radius * Math.cos(angle),
          y: height / 2 + radius * Math.sin(angle),
          vx: 0, vy: 0
        };
      }
    });
    
    const edgeMap = {};
    edges.forEach(e => {
      if (!edgeMap[e.source]) edgeMap[e.source] = [];
      if (!edgeMap[e.target]) edgeMap[e.target] = [];
      edgeMap[e.source].push(e.target);
      edgeMap[e.target].push(e.source);
    });
    
    const simulate = () => {
      const alpha = 0.1;
      const repulsion = 5000;
      const attraction = 0.01;
      const damping = 0.85;
      
      nodes.forEach(node => {
        const pos = nodePositions[node.id];
        let fx = 0, fy = 0;
        
        nodes.forEach(other => {
          if (node.id === other.id) return;
          const otherPos = nodePositions[other.id];
          const dx = pos.x - otherPos.x;
          const dy = pos.y - otherPos.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = repulsion / (dist * dist);
          fx += (dx / dist) * force;
          fy += (dy / dist) * force;
        });
        
        const connected = edgeMap[node.id] || [];
        connected.forEach(otherId => {
          const otherPos = nodePositions[otherId];
          if (!otherPos) return;
          const dx = otherPos.x - pos.x;
          const dy = otherPos.y - pos.y;
          fx += dx * attraction;
          fy += dy * attraction;
        });
        
        fx += (width / 2 - pos.x) * 0.001;
        fy += (height / 2 - pos.y) * 0.001;
        
        pos.vx = (pos.vx + fx * alpha) * damping;
        pos.vy = (pos.vy + fy * alpha) * damping;
        
        if (node.is_gateway) {
          pos.vx *= 0.1;
          pos.vy *= 0.1;
        }
      });
      
      nodes.forEach(node => {
        const pos = nodePositions[node.id];
        pos.x += pos.vx;
        pos.y += pos.vy;
        pos.x = Math.max(50, Math.min(width - 50, pos.x));
        pos.y = Math.max(50, Math.min(height - 50, pos.y));
      });
      
      setPositions({ ...nodePositions });
    };
    
    simulationRef.current = setInterval(simulate, 30);
    return () => { if (simulationRef.current) clearInterval(simulationRef.current); };
  }, [nodes, edges, width, height]);
  
  return positions;
}

function NetworkGraph({ devices, connections, onSelectDevice, selectedDevice, status }) {
  const containerRef = useRef(null);
  const [containerSize, setContainerSize] = useState({ width: 800, height: 500 });
  const [hoveredNode, setHoveredNode] = useState(null);
  const [hoveredEdge, setHoveredEdge] = useState(null);
  
  // Pan and zoom state
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  
  // Calculate canvas size based on number of devices
  const canvasSize = useMemo(() => {
    const minSize = 800;
    const deviceCount = devices.length;
    // Scale canvas based on device count
    const scale = Math.max(1, Math.sqrt(deviceCount / 10));
    return {
      width: Math.max(minSize, containerSize.width * scale),
      height: Math.max(minSize, containerSize.height * scale)
    };
  }, [devices.length, containerSize]);
  
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        setContainerSize({ width: rect.width, height: rect.height });
      }
    };
    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, []);
  
  // Mouse handlers for pan
  const handleMouseDown = (e) => {
    if (e.button === 0) { // Left click
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };
  
  const handleMouseMove = (e) => {
    if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };
  
  const handleMouseUp = () => {
    setIsDragging(false);
  };
  
  // Wheel handler for zoom (only when Ctrl/Cmd is held)
  const handleWheel = (e) => {
    // Only zoom if Ctrl/Cmd is held, otherwise allow normal page scroll
    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      const delta = e.deltaY > 0 ? 0.9 : 1.1;
      setZoom(z => Math.min(3, Math.max(0.3, z * delta)));
    }
    // Otherwise, let the event bubble up for normal scrolling
  };
  
  // Fit all nodes in view
  const fitToView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };
  
  const nodes = useMemo(() => 
    devices.map(d => ({ id: d.ip, ...d, type: getDeviceType(d) })), 
    [devices]
  );
  
  const edges = useMemo(() => {
    const edgeMap = {};
    const localIPs = new Set(devices.map(d => d.ip));
    const gatewayIP = devices.find(d => d.is_gateway)?.ip || status?.gateway_ip;
    
    connections.forEach(c => {
      let src = c.src_ip;
      let dst = c.dst_ip;
      
      const srcIsLocal = localIPs.has(src) || src.startsWith('192.168.') || src.startsWith('10.');
      const dstIsLocal = localIPs.has(dst) || dst.startsWith('192.168.') || dst.startsWith('10.');
      
      if (!localIPs.has(src) && !srcIsLocal) src = gatewayIP || '192.168.1.1';
      if (!localIPs.has(dst) && !dstIsLocal) dst = gatewayIP || '192.168.1.1';
      
      if (src === dst) return;
      if (!localIPs.has(src) && !localIPs.has(dst)) return;
      
      const key = [src, dst].sort().join('-');
      if (!edgeMap[key]) {
        edgeMap[key] = { source: src, target: dst, bytes: 0, packets: 0, protocols: new Set(), applications: new Set(), externalTraffic: !srcIsLocal || !dstIsLocal };
      }
      edgeMap[key].bytes += c.byte_count;
      edgeMap[key].packets += c.packet_count;
      edgeMap[key].protocols.add(c.protocol);
      if (c.application) edgeMap[key].applications.add(c.application);
    });
    
    return Object.values(edgeMap).map(e => ({
      ...e,
      protocols: Array.from(e.protocols),
      applications: Array.from(e.applications)
    }));
  }, [connections, devices, status?.gateway_ip]);
  
  const positions = useForceSimulation(nodes, edges, canvasSize.width, canvasSize.height);
  const maxBytes = Math.max(...edges.map(e => e.bytes), 1);
  
  const getEdgeWidth = (bytes) => 2 + (bytes / maxBytes) * 10;
  
  const getEdgeColor = (edge) => {
    if (hoveredEdge === edge) return colors.accent;
    if (edge.externalTraffic) return colors.warning;
    if (edge.protocols.includes('TCP')) return colors.accentDim;
    if (edge.protocols.includes('UDP')) return colors.purple;
    return colors.borderLight;
  };
  
  const getNodeColor = (node) => {
    if (selectedDevice?.ip === node.id) return colors.accent;
    if (hoveredNode === node.id) return colors.accent;
    if (node.is_gateway) return colors.warning;
    if (node.is_local) return colors.success;
    return colors.textMuted;
  };
  
  return (
    <div ref={containerRef} style={{
      width: '100%',
      height: '100%',
      background: `radial-gradient(ellipse at center, ${colors.bgSecondary} 0%, ${colors.bg} 100%)`,
      position: 'relative',
      overflow: 'hidden',
      borderRadius: '12px',
      border: `1px solid ${colors.border}`,
      cursor: isDragging ? 'grabbing' : 'grab'
    }}
    onMouseDown={handleMouseDown}
    onMouseMove={handleMouseMove}
    onMouseUp={handleMouseUp}
    onMouseLeave={handleMouseUp}
    onWheel={handleWheel}
    >
      {/* Zoom controls */}
      <div style={{
        position: 'absolute',
        top: '10px',
        right: '10px',
        zIndex: 10,
        display: 'flex',
        flexDirection: 'column',
        gap: '4px',
        background: colors.bgCard,
        padding: '6px',
        borderRadius: '8px',
        border: `1px solid ${colors.border}`
      }}>
        <button onClick={() => setZoom(z => Math.min(3, z * 1.2))} style={{
          width: '28px', height: '28px', border: 'none', borderRadius: '4px',
          background: colors.bgTertiary, color: colors.text, cursor: 'pointer', fontSize: '16px'
        }}>+</button>
        <button onClick={() => setZoom(z => Math.max(0.3, z * 0.8))} style={{
          width: '28px', height: '28px', border: 'none', borderRadius: '4px',
          background: colors.bgTertiary, color: colors.text, cursor: 'pointer', fontSize: '16px'
        }}>−</button>
        <button onClick={fitToView} title="Fit to view" style={{
          width: '28px', height: '28px', border: 'none', borderRadius: '4px',
          background: colors.bgTertiary, color: colors.text, cursor: 'pointer', fontSize: '12px'
        }}>⊙</button>
        <div style={{ fontSize: '9px', textAlign: 'center', color: colors.textMuted }}>{Math.round(zoom * 100)}%</div>
      </div>
      
      {/* Instructions */}
      <div style={{
        position: 'absolute',
        bottom: '10px',
        left: '10px',
        zIndex: 10,
        fontSize: '9px',
        color: colors.textMuted,
        background: `${colors.bgCard}cc`,
        padding: '4px 8px',
        borderRadius: '4px'
      }}>
        🖱️ Drag to pan • Ctrl+Scroll to zoom • {devices.length} devices
      </div>
      
      <svg width="100%" height="100%" style={{ position: 'absolute', opacity: 0.05 }}>
        <defs>
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke={colors.border} strokeWidth="0.5"/>
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />
      </svg>
      
      <svg 
        width={containerSize.width} 
        height={containerSize.height} 
        style={{ position: 'relative' }}
        viewBox={`${-pan.x/zoom} ${-pan.y/zoom} ${containerSize.width/zoom} ${containerSize.height/zoom}`}
      >
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
            <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        
        <g>
          {edges.map((edge, i) => {
            const sourcePos = positions[edge.source];
            const targetPos = positions[edge.target];
            if (!sourcePos || !targetPos) return null;
            
            return (
              <g key={i}>
                <line
                  x1={sourcePos.x} y1={sourcePos.y}
                  x2={targetPos.x} y2={targetPos.y}
                  stroke={getEdgeColor(edge)}
                  strokeWidth={getEdgeWidth(edge.bytes)}
                  strokeOpacity={hoveredEdge === edge ? 1 : 0.5}
                  strokeLinecap="round"
                  onMouseEnter={() => setHoveredEdge(edge)}
                  onMouseLeave={() => setHoveredEdge(null)}
                  style={{ cursor: 'pointer' }}
                />
                {edge.bytes > maxBytes * 0.1 && (
                  <circle r="4" fill={colors.accent} filter="url(#glow)">
                    <animateMotion
                      dur={`${3 - (edge.bytes / maxBytes) * 2}s`}
                      repeatCount="indefinite"
                      path={`M${sourcePos.x},${sourcePos.y} L${targetPos.x},${targetPos.y}`}
                    />
                  </circle>
                )}
              </g>
            );
          })}
        </g>
        
        <g>
          {nodes.map(node => {
            const pos = positions[node.id];
            if (!pos) return null;
            
            const nodeColor = getNodeColor(node);
            const isSelected = selectedDevice?.ip === node.id;
            const isHovered = hoveredNode === node.id;
            const radius = node.is_gateway ? 28 : 22;
            
            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={() => onSelectDevice(node)}
                style={{ cursor: 'pointer' }}
              >
                {(isSelected || isHovered) && (
                  <circle r={radius + 8} fill="none" stroke={nodeColor} strokeWidth="2" opacity="0.3" filter="url(#glow)" />
                )}
                <circle r={radius} fill={colors.bgTertiary} stroke={nodeColor} strokeWidth={isSelected ? 3 : 2} />
                <svg x={-12} y={-12} width={24} height={24} viewBox="0 0 24 24" fill="none" stroke={nodeColor} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d={deviceIcons[node.type] || deviceIcons.unknown} />
                </svg>
                <text y={radius + 14} textAnchor="middle" fill={colors.text} fontSize="10" fontFamily="JetBrains Mono, monospace" fontWeight="500">
                  {(node.hostname || node.ip).substring(0, 20)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      
      {hoveredEdge && positions[hoveredEdge.source] && positions[hoveredEdge.target] && (
        <div style={{
          position: 'absolute',
          left: (positions[hoveredEdge.source].x + positions[hoveredEdge.target].x) / 2,
          top: (positions[hoveredEdge.source].y + positions[hoveredEdge.target].y) / 2 - 70,
          transform: 'translateX(-50%)',
          background: colors.bgCard,
          border: `1px solid ${colors.border}`,
          borderRadius: '8px',
          padding: '10px 14px',
          pointerEvents: 'none',
          zIndex: 100,
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '11px',
          boxShadow: '0 4px 20px rgba(0,0,0,0.5)'
        }}>
          <div style={{ color: colors.text, marginBottom: '4px', fontWeight: 600 }}>
            {hoveredEdge.source} ↔ {hoveredEdge.target}
          </div>
          <div style={{ color: colors.textMuted }}>
            {formatBytes(hoveredEdge.bytes)} • {hoveredEdge.packets.toLocaleString()} pkts
          </div>
          <div style={{ color: colors.accentDim, marginTop: '4px' }}>
            {hoveredEdge.protocols.join(', ')}
          </div>
          {hoveredEdge.applications.length > 0 && (
            <div style={{ color: colors.purple, marginTop: '2px' }}>
              {hoveredEdge.applications.join(', ')}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Enhanced Device Panel
// ============================================================================

function DevicePanel({ device, connections, onClose, onPortScan }) {
  const [scanning, setScanning] = useState(false);
  const [bandwidth, setBandwidth] = useState(null);
  
  useEffect(() => {
    if (device) {
      fetch(`${API_BASE}/bandwidth/${device.ip}`)
        .then(res => res.json())
        .then(setBandwidth)
        .catch(() => {});
    }
  }, [device]);
  
  if (!device) return null;
  
  const deviceConnections = connections.filter(c => c.src_ip === device.ip || c.dst_ip === device.ip);
  const totalBytes = deviceConnections.reduce((sum, c) => sum + c.byte_count, 0);
  const totalPackets = deviceConnections.reduce((sum, c) => sum + c.packet_count, 0);
  
  const handlePortScan = async () => {
    setScanning(true);
    try {
      await fetch(`${API_BASE}/device/${device.ip}/scan`, { method: 'POST' });
      if (onPortScan) onPortScan();
    } finally {
      setScanning(false);
    }
  };
  
  return (
    <div style={{
      width: '360px',
      background: colors.bgSecondary,
      borderLeft: `1px solid ${colors.border}`,
      display: 'flex',
      flexDirection: 'column',
      fontFamily: 'JetBrains Mono, monospace'
    }}>
      <div style={{
        padding: '20px',
        borderBottom: `1px solid ${colors.border}`,
        background: colors.bgCard
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h3 style={{ margin: 0, color: colors.text, fontSize: '14px', fontWeight: 600 }}>
              {device.hostname || 'Unknown Device'}
            </h3>
            <div style={{ color: colors.accent, fontSize: '12px', marginTop: '4px' }}>{device.ip}</div>
            {device.os && <div style={{ color: colors.purple, fontSize: '10px', marginTop: '2px' }}>{device.os}</div>}
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: colors.textMuted, cursor: 'pointer', fontSize: '20px' }}>×</button>
        </div>
        
        <button onClick={handlePortScan} disabled={scanning} style={{
          marginTop: '12px',
          width: '100%',
          padding: '8px',
          background: colors.bgTertiary,
          border: `1px solid ${colors.border}`,
          borderRadius: '6px',
          color: colors.text,
          fontSize: '11px',
          cursor: scanning ? 'not-allowed' : 'pointer'
        }}>
          {scanning ? 'Scanning Ports...' : '🔍 Deep Scan Ports'}
        </button>
      </div>
      
      <div style={{ padding: '16px', borderBottom: `1px solid ${colors.border}` }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '11px' }}>
          <div><span style={{ color: colors.textMuted }}>MAC:</span> <span style={{ color: colors.text }}>{device.mac || 'Unknown'}</span></div>
          <div><span style={{ color: colors.textMuted }}>Vendor:</span> <span style={{ color: colors.text }}>{device.vendor || 'Unknown'}</span></div>
        </div>
        
        {device.open_ports?.length > 0 && (
          <div style={{ marginTop: '12px' }}>
            <div style={{ color: colors.textMuted, fontSize: '10px', marginBottom: '6px' }}>OPEN PORTS</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {device.open_ports.map(port => (
                <span key={port} style={{ background: colors.bgTertiary, color: colors.accent, padding: '2px 8px', borderRadius: '4px', fontSize: '10px' }}>
                  {port} {device.services?.[port] && `(${device.services[port]})`}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
      
      <div style={{ padding: '16px', borderBottom: `1px solid ${colors.border}` }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
          <StatsCard title="Data" value={formatBytes(totalBytes)} color={colors.accent} />
          <StatsCard title="Packets" value={formatNumber(totalPackets)} color={colors.purple} />
        </div>
        
        {bandwidth?.history?.length > 0 && (
          <div style={{ marginTop: '12px' }}>
            <div style={{ color: colors.textMuted, fontSize: '10px', marginBottom: '6px' }}>BANDWIDTH (last 60s)</div>
            <MiniBarChart 
              data={bandwidth.history.map(h => ({ value: h.bytes, label: h.timestamp }))} 
              color={colors.accent} 
            />
          </div>
        )}
      </div>
      
      <div style={{ flex: 1, overflow: 'auto', padding: '16px' }}>
        <div style={{ color: colors.textMuted, fontSize: '10px', marginBottom: '8px' }}>
          CONNECTIONS ({deviceConnections.length})
        </div>
        {deviceConnections.slice(0, 20).map((conn, i) => {
          const isOutgoing = conn.src_ip === device.ip;
          const otherDevice = isOutgoing ? conn.dst_ip : conn.src_ip;
          return (
            <div key={i} style={{ background: colors.bgTertiary, borderRadius: '6px', padding: '8px', marginBottom: '6px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                <span style={{ color: isOutgoing ? colors.accent : colors.success }}>{isOutgoing ? '→' : '←'}</span>
                <span style={{ color: colors.text, fontSize: '11px', flex: 1 }}>{otherDevice}</span>
                <span style={{ background: colors.bgSecondary, color: colors.accentDim, padding: '1px 4px', borderRadius: '3px', fontSize: '9px' }}>
                  {conn.protocol}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: colors.textDim, fontSize: '10px' }}>
                <span>{formatBytes(conn.byte_count)}</span>
                <span>{conn.application || `Port ${conn.dst_port}`}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ============================================================================
// Main App
// ============================================================================

export default function App() {
  const [status, setStatus] = useState({});
  const [devices, setDevices] = useState([]);
  const [connections, setConnections] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isCapturing, setIsCapturing] = useState(false);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState({});
  const [dnsData, setDnsData] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [view, setView] = useState('graph'); // graph, dashboard

  const [networkDiag, setNetworkDiag] = useState(null);
  const [scanMethod, setScanMethod] = useState('auto');
  const [scanProfile, setScanProfile] = useState('standard');
  const [scanJob, setScanJob] = useState(null);
  const [intelStory, setIntelStory] = useState(null);

  // Lifted NIP panel state — persists across main view switches
  const nipPanelState = useRef({
    brainPlan: null, brainLoading: false, brainStealth: 0.5,
    nlQuery: '', nlResult: null, nlLoading: false,
    qualityMetrics: null, qualityLoading: false, qualityHasLoaded: false,
    nipTab: 'metrics',
  });
  const [nipStateVersion, setNipStateVersion] = useState(0);
  const refreshAppData = useCallback(() => {
    Promise.all([
      fetch(`${API_BASE}/devices`).then(r => r.json()),
      fetch(`${API_BASE}/connections`).then(r => r.json()),
      fetch(`${API_BASE}/dns`).then(r => r.json()),
      fetch(`${API_BASE}/alerts`).then(r => r.json()),
      fetch(`${API_BASE}/intel/story`).then(r => r.json()),
    ]).then(([devData, connData, dnsRes, alertRes, storyRes]) => {
      if (devData.devices) setDevices(devData.devices);
      setConnections(connData.connections || []);
      setDnsData(dnsRes || null);
      setAlerts(alertRes.alerts || []);
      setIntelStory(storyRes || null);
    }).catch(() => {});
  }, []);

  const updateNipState = useCallback((patch) => {
    Object.assign(nipPanelState.current, patch);
    setNipStateVersion(v => v + 1);
  }, []);

  const refreshStatus = useCallback(() => {
    fetch(`${API_BASE}/status`)
      .then(res => res.json())
      .then(data => {
        setStatus(data);
        setIsCapturing(data.capturing);
      })
      .catch(() => setError('Backend not reachable'));
  }, []);

  // Keep status fresh (capture state, MITM status, interface/tool availability)
  useEffect(() => {
    refreshStatus();
    const interval = setInterval(refreshStatus, 5000);
    return () => clearInterval(interval);
  }, [refreshStatus]);

  // Initial data hydration (supports demo/pre-existing backend state)
  useEffect(() => {
    Promise.all([
      fetch(`${API_BASE}/devices`).then(r => r.json()),
      fetch(`${API_BASE}/connections`).then(r => r.json()),
      fetch(`${API_BASE}/stats`).then(r => r.json()),
      fetch(`${API_BASE}/dns`).then(r => r.json()),
      fetch(`${API_BASE}/alerts`).then(r => r.json()),
      fetch(`${API_BASE}/intel/story`).then(r => r.json()),
    ]).then(([devicesData, connData, statsData, dnsDataRes, alertsData, storyData]) => {
      if (devicesData.devices) setDevices(devicesData.devices);
      setConnections(connData.connections || []);
      setStats(statsData || {});
      setDnsData(dnsDataRes || null);
      setAlerts(alertsData.alerts || []);
      setIntelStory(storyData || null);
    }).catch(() => {});
  }, []);

  // Poll high-volume telemetry when capture or MITM collection is active
  useEffect(() => {
    if (!isCapturing && !status.mitm_active) return;
    const interval = setInterval(() => {
      Promise.all([
        fetch(`${API_BASE}/connections`).then(r => r.json()),
        fetch(`${API_BASE}/stats`).then(r => r.json()),
        fetch(`${API_BASE}/dns`).then(r => r.json()),
        fetch(`${API_BASE}/alerts`).then(r => r.json()),
        fetch(`${API_BASE}/devices`).then(r => r.json()),
        fetch(`${API_BASE}/intel/story`).then(r => r.json()),
      ]).then(([connData, statsData, dnsDataRes, alertsData, devicesData, storyData]) => {
        setConnections(connData.connections || []);
        setStats(statsData);
        setDnsData(dnsDataRes);
        setAlerts(alertsData.alerts || []);
        if (devicesData.devices) setDevices(devicesData.devices);
        setIntelStory(storyData);
      }).catch(() => {});
    }, 2000);
    return () => clearInterval(interval);
  }, [isCapturing, status.mitm_active]);

  // Story refresh even outside active capture windows
  useEffect(() => {
    const refreshStory = () => {
      fetch(`${API_BASE}/intel/story`)
        .then(res => res.json())
        .then(setIntelStory)
        .catch(() => {});
    };
    refreshStory();
    const interval = setInterval(refreshStory, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleScan = async () => {
    setIsScanning(true);
    setError(null);
    setScanJob(null);
    try {
      // Fetch network diagnosis first
      const diagRes = await fetch(`${API_BASE}/network/diagnose`);
      const diagData = await diagRes.json();
      setNetworkDiag(diagData);

      // Start async scan job with selected profile
      const res = await fetch(`${API_BASE}/scan/jobs`, {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile: scanProfile })
      });
      if (!res.ok) throw new Error('Failed to start scan job');
      const jobStart = await res.json();
      setScanJob(jobStart);

      let completed = false;
      let guard = 0;
      while (!completed && guard < 600) { // ~10 min guardrail
        guard += 1;
        await new Promise(resolve => setTimeout(resolve, 1000));
        const jobRes = await fetch(`${API_BASE}/scan/jobs/${jobStart.job_id}`);
        if (!jobRes.ok) throw new Error('Lost scan job status');
        const job = await jobRes.json();
        setScanJob(job);

        if (job.status === 'completed') {
          const result = job.result || {};
          setScanMethod(result.scan_method || 'arp');
          if (result.devices) setDevices(result.devices);
          setIntelStory(await fetch(`${API_BASE}/intel/story`).then(r => r.json()).catch(() => null));
          completed = true;
        } else if (job.status === 'failed') {
          throw new Error(job.error || 'Scan job failed');
        }
      }

      if (!completed) {
        throw new Error('Scan timed out');
      }
    } catch (e) {
      console.error('Scan error:', e);
      setError(e.message || 'Scan failed');
    }
    finally { setIsScanning(false); }
  };
  
  const handleClear = async () => {
    try {
      await fetch(`${API_BASE}/clear`, { method: 'POST' });
      setDevices([]); setConnections([]); setSelectedDevice(null);
      setStats({}); setDnsData(null); setAlerts([]);
      setScanJob(null);
      setIntelStory(null);
      setScanMethod('auto');
    } catch {}
  };
  
  const handleStartCapture = async () => {
    try {
      const res = await fetch(`${API_BASE}/capture/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
      const data = await res.json();
      setIsCapturing(data.capturing);
      refreshStatus();
    } catch (e) { 
      console.error('Start capture failed:', e);
      setError('Failed to start capture'); 
    }
  };
  
  const handleStopCapture = async () => {
    setIsCapturing(false); // Immediately update UI
    try {
      await fetch(`${API_BASE}/capture/stop`, { method: 'POST' });
      refreshStatus();
    } catch (e) {
      console.error('Stop capture failed:', e);
    }
  };
  
  // Sync capture state with server status
  useEffect(() => {
    if (status.capturing !== undefined) {
      setIsCapturing(status.capturing);
    }
  }, [status.capturing]);
  
  // MITM handlers - simplified to just show status and instructions
  const isMitmActive = status.mitm_active;
  
  const handleMitmClick = () => {
    if (isMitmActive) {
      // Show stop instructions
      if (confirm('MITM is running.\n\nTo stop it, press Ctrl+C in the terminal where it\'s running.\n\nOr click OK to send a stop signal (may not work if run externally).')) {
        fetch(`${API_BASE}/mitm/stop`, { method: 'POST' }).then(() => refreshStatus()).catch(() => {});
      }
    } else {
      // Show start instructions
      alert('To start MITM capture, run this in your terminal:\n\nsudo venv/bin/python mitm_capture.py\n\nThe data will automatically sync to this GUI!');
      
      // Copy command to clipboard
      navigator.clipboard?.writeText('sudo venv/bin/python mitm_capture.py').then(() => {
        // Silently copied
      }).catch(() => {});
    }
  };
  
  return (
    <div style={{ width: '100vw', minHeight: '100vh', display: 'flex', flexDirection: 'column', background: colors.bg, color: colors.text, overflow: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: ${colors.bgSecondary}; }
        ::-webkit-scrollbar-thumb { background: ${colors.border}; border-radius: 3px; }
        @keyframes pulse {
          0%, 100% { opacity: 1; box-shadow: 0 0 0 0 ${colors.danger}88; }
          50% { opacity: 0.9; box-shadow: 0 0 15px 3px ${colors.danger}66; }
        }
      `}</style>
      
      {/* Header */}
      <div style={{ background: colors.bgSecondary, borderBottom: `1px solid ${colors.border}`, padding: '10px 20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke={colors.accent} strokeWidth="2">
            <circle cx="12" cy="12" r="3"/><path d="M12 2v4m0 12v4M2 12h4m12 0h4"/><circle cx="12" cy="12" r="9" opacity="0.3"/>
          </svg>
          <span style={{ fontWeight: 700, fontSize: '18px', background: colors.gradient1, WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>NETVIS PRO</span>
        </div>
        
        <div style={{ width: '1px', height: '28px', background: colors.border }} />
        
        <div style={{ fontSize: '11px' }}>
          <span style={{ color: colors.textMuted }}>Network: </span><span style={{ color: colors.text }}>{status.network || '-'}</span>
        </div>
        <div style={{ fontSize: '11px' }}>
          <span style={{ color: colors.textMuted }}>Local: </span><span style={{ color: colors.success }}>{status.local_ip || '-'}</span>
        </div>
        
        <div style={{ flex: 1 }} />
        
        {/* View Toggle */}
		        <div style={{ display: 'flex', background: colors.bgTertiary, borderRadius: '6px', padding: '2px' }}>
		          {['graph', 'dashboard', 'workbench', 'nip', 'coursework'].map(v => (
		            <button key={v} onClick={() => setView(v)} style={{
		              padding: '6px 12px', border: 'none', borderRadius: '4px', fontSize: '11px', cursor: 'pointer',
		              background: view === v ? colors.accent : 'transparent',
		              color: view === v ? colors.bg : colors.textMuted
		            }}>
		              {v === 'graph' ? '🌐 Graph' : v === 'dashboard' ? '📊 Dashboard' : v === 'workbench' ? '🧠 Workbench' : v === 'nip' ? '🧩 NIP' : '🧾 Coursework'}
		            </button>
		          ))}
		        </div>
        
        <button onClick={handleClear} style={{ padding: '8px 14px', background: colors.bgTertiary, border: `1px solid ${colors.border}`, borderRadius: '6px', color: colors.text, fontSize: '11px', cursor: 'pointer' }}>Clear</button>
        <select
          value={scanProfile}
          onChange={(e) => setScanProfile(e.target.value)}
          style={{
            padding: '8px 10px',
            background: colors.bgTertiary,
            border: `1px solid ${colors.border}`,
            borderRadius: '6px',
            color: colors.text,
            fontSize: '11px',
            outline: 'none'
          }}
        >
          <option value="quick">Quick</option>
          <option value="standard">Standard</option>
          <option value="deep">Deep</option>
        </select>
        <button onClick={handleScan} disabled={isScanning} style={{ padding: '8px 14px', background: colors.accent, border: 'none', borderRadius: '6px', color: colors.bg, fontSize: '11px', fontWeight: 600, cursor: 'pointer' }}>
          {isScanning ? `Scanning ${scanJob?.progress || 0}%` : 'Scan Network'}
        </button>
        {isCapturing ? (
          <button onClick={handleStopCapture} style={{ padding: '8px 14px', background: colors.danger, border: 'none', borderRadius: '6px', color: '#fff', fontSize: '11px', fontWeight: 600, cursor: 'pointer' }}>Stop Capture</button>
        ) : (
          <button onClick={handleStartCapture} style={{ padding: '8px 14px', background: colors.success, border: 'none', borderRadius: '6px', color: colors.bg, fontSize: '11px', fontWeight: 600, cursor: 'pointer' }}>Start Capture</button>
        )}
        
        {/* MITM Button */}
        <button 
          onClick={handleMitmClick} 
          style={{ 
            padding: '8px 14px', 
            background: isMitmActive ? colors.danger : colors.purple, 
            border: 'none', 
            borderRadius: '6px', 
            color: '#fff', 
            fontSize: '11px', 
            fontWeight: 600, 
            cursor: 'pointer',
            animation: isMitmActive ? 'pulse 2s infinite' : 'none'
          }}
          title={isMitmActive ? "MITM is active - click for options" : "Click to see how to start MITM"}
        >
          {isMitmActive ? '🔴 MITM Active' : '🟣 MITM'}
        </button>
        
        <div style={{ display: 'flex', gap: '12px', marginLeft: '8px', fontSize: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: status.scapy_available ? colors.success : colors.textMuted }} />Scapy
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: status.nmap_available ? colors.success : colors.textMuted }} />Nmap
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: isCapturing ? colors.danger : colors.textMuted, boxShadow: isCapturing ? `0 0 8px ${colors.danger}` : 'none' }} />Live
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: status.mitm_active ? colors.purple : colors.textMuted, boxShadow: status.mitm_active ? `0 0 8px ${colors.purple}` : 'none' }} />MITM
          </div>
          {scanMethod !== 'auto' && (
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '4px',
              background: scanMethod === 'arp' ? `${colors.success}22` : `${colors.warning}22`,
              padding: '2px 8px',
              borderRadius: '10px',
              border: `1px solid ${scanMethod === 'arp' ? colors.success : colors.warning}44`
            }}>
              <div style={{ 
                width: '6px', 
                height: '6px', 
                borderRadius: '50%', 
                background: scanMethod === 'arp' ? colors.success : colors.warning 
              }} />
              {scanMethod === 'arp' ? 'ARP Scan' : 'ICMP+TCP'}
            </div>
          )}
        </div>
      </div>
      
      {error && <div style={{ background: colors.danger, color: '#fff', padding: '8px 20px', fontSize: '12px' }}>{error}</div>}
      {scanJob && (
        <div style={{
          background: colors.bgSecondary,
          borderBottom: `1px solid ${colors.border}`,
          padding: '8px 20px',
          fontSize: '11px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px'
        }}>
          <span style={{ color: colors.accent }}>Scan Job</span>
          <span style={{ color: colors.textMuted }}>{scanJob.job_id?.slice(0, 8)}</span>
          <span style={{ color: colors.text }}>{scanJob.status}</span>
          <span style={{ color: colors.success }}>{scanJob.progress || 0}%</span>
          <span style={{ color: colors.textMuted }}>{scanJob.message || ''}</span>
        </div>
      )}
      
	      {/* Main Content */}
	      <div style={{ flex: 1, display: 'flex', overflow: 'auto' }}>
	        {view === 'graph' ? (
	          <>
            <div style={{ flex: 1, padding: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Stats Row */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '12px' }}>
                <StatsCard title="DEVICES" value={devices.length} color={colors.accent} />
                <StatsCard title="CONNECTIONS" value={stats.connection_count || connections.length} color={colors.purple} />
                <StatsCard title="TRAFFIC" value={formatBytes(stats.total_bytes || 0)} color={colors.success} />
                <StatsCard title="PACKETS" value={formatNumber(stats.total_packets || 0)} color={colors.warning} />
                <StatsCard title="DNS QUERIES" value={stats.dns_query_count || 0} color={colors.pink} />
                <StatsCard title="ALERTS" value={alerts.length} color={alerts.length > 0 ? colors.danger : colors.textMuted} />
              </div>
              
              {/* Graph */}
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                {/* Show Network Info Panel when available */}
                {networkDiag && <NetworkInfoPanel diag={networkDiag} status={status} />}
                
                <div style={{ flex: 1 }}>
                  {devices.length === 0 ? (
                    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: colors.bgCard, borderRadius: '12px', border: `1px solid ${colors.border}` }}>
                      <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke={colors.textMuted} strokeWidth="1.5">
                        <circle cx="12" cy="12" r="3"/><path d="M12 2v4m0 12v4M2 12h4m12 0h4"/><circle cx="12" cy="12" r="9" opacity="0.3"/>
                      </svg>
                      <div style={{ color: colors.textMuted, marginTop: '16px', fontSize: '14px' }}>No devices discovered</div>
                      <div style={{ color: colors.textDim, marginTop: '8px', fontSize: '12px' }}>Click <strong>Scan Network</strong> to discover devices</div>
                    </div>
                  ) : (
                    <NetworkGraph devices={devices} connections={connections} selectedDevice={selectedDevice} onSelectDevice={setSelectedDevice} status={status} />
                  )}
                </div>
              </div>
            </div>
	            {selectedDevice && <DevicePanel device={selectedDevice} connections={connections} onClose={() => setSelectedDevice(null)} onPortScan={handleScan} />}
	          </>
		        ) : view === 'dashboard' ? (
		          /* Dashboard View */
		          <div style={{ flex: 1, padding: '16px', overflow: 'auto' }}>
	            {/* Network Info at top of dashboard */}
	            {networkDiag && <NetworkInfoPanel diag={networkDiag} status={status} />}
	            
	            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '16px' }}>
	              <StatsCard title="TOTAL TRAFFIC" value={formatBytes(stats.total_bytes || 0)} subtitle={`${formatNumber(stats.total_packets || 0)} packets`} color={colors.accent} />
	              <StatsCard title="INTERNAL" value={formatBytes(stats.internal_traffic || 0)} subtitle="Local network" color={colors.success} />
	              <StatsCard title="EXTERNAL" value={formatBytes(stats.external_traffic || 0)} subtitle="Internet traffic" color={colors.warning} />
	              <StatsCard title="ACTIVE DEVICES" value={devices.length} subtitle={`${stats.connection_count || 0} connections`} color={colors.purple} />
	            </div>
	            
	            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px', marginBottom: '16px' }}>
	              <div style={{ background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '16px' }}>
	                <BreakdownChart data={stats.protocols || {}} title="PROTOCOLS" />
	              </div>
	              <div style={{ background: colors.bgCard, border: `1px solid ${colors.border}`, borderRadius: '12px', padding: '16px' }}>
	                <BreakdownChart data={stats.applications || {}} title="APPLICATIONS" />
	              </div>
	              <TopTalkersPanel talkers={stats.top_talkers} devices={devices} />
	            </div>
	            
	            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
	              <DNSPanel dnsData={dnsData} />
	              <AlertsPanel alerts={alerts} />
		              <IntelStoryPanel story={intelStory} />
		            </div>

		            <div style={{ marginTop: '16px' }}>
		              <TimelinePanel timeline={intelStory?.timeline} />
		            </div>
		          </div>
			        ) : view === 'workbench' ? (
			          <WorkbenchView status={status} />
			        ) : view === 'nip' ? null : (
			          <CourseworkView status={status} />
			        )}
            {/* NipView always mounted so Brain loop survives main view switches */}
            <div style={{ display: view === 'nip' ? 'flex' : 'none', flex: 1, overflow: 'auto' }}>
              <NipView status={status} devices={devices} nipPanelState={nipPanelState.current} updateNipState={updateNipState} refreshAppData={refreshAppData} />
            </div>
		      </div>
      
      {/* Footer */}
      <div style={{ background: colors.bgSecondary, borderTop: `1px solid ${colors.border}`, padding: '8px 20px', display: 'flex', gap: '24px', fontSize: '11px' }}>
        <span><span style={{ color: colors.textMuted }}>Devices:</span> <span style={{ color: colors.accent }}>{devices.length}</span></span>
        <span><span style={{ color: colors.textMuted }}>Connections:</span> <span style={{ color: colors.purple }}>{connections.length}</span></span>
        <span><span style={{ color: colors.textMuted }}>Traffic:</span> <span style={{ color: colors.success }}>{formatBytes(stats.total_bytes || 0)}</span></span>
        <span><span style={{ color: colors.textMuted }}>DNS:</span> <span style={{ color: colors.pink }}>{stats.dns_query_count || 0}</span></span>
        <span><span style={{ color: colors.textMuted }}>Alerts:</span> <span style={{ color: alerts.length > 0 ? colors.danger : colors.textMuted }}>{alerts.length}</span></span>
        <span><span style={{ color: colors.textMuted }}>Risk Services:</span> <span style={{ color: (stats.high_risk_service_exposures || 0) > 0 ? colors.warning : colors.textMuted }}>{stats.high_risk_service_exposures || 0}</span></span>
      </div>
    </div>
  );
}
