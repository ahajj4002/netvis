import React from 'react';
import { colors } from '../theme';

/**
 * Network diagnostics panel: local IP, gateway, VPN detection, issues, recommendations.
 */
export function NetworkInfoPanel({ diag, status }) {
  if (!diag) return null;

  const isVPN = diag.vpn_detected;
  const canScan = diag.can_arp_scan;

  return (
    <div
      style={{
        background: isVPN ? `${colors.warning}11` : colors.bgCard,
        border: `1px solid ${isVPN ? colors.warning : colors.border}`,
        borderRadius: '12px',
        padding: '16px',
        marginBottom: '16px',
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
        <span style={{ fontSize: '16px' }}>{isVPN ? '🔐' : '🌐'}</span>
        NETWORK INFO
        {isVPN && (
          <span
            style={{
              background: colors.warning,
              color: colors.bg,
              padding: '2px 8px',
              borderRadius: '4px',
              fontSize: '9px',
              fontWeight: 700,
            }}
          >
            VPN DETECTED
          </span>
        )}
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '12px',
          marginBottom: '12px',
        }}
      >
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>
            LOCAL IP
          </div>
          <div style={{ fontSize: '13px', color: colors.success, fontFamily: 'monospace' }}>
            {diag.local_ip}
          </div>
        </div>
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>
            GATEWAY
          </div>
          <div style={{ fontSize: '13px', color: colors.accent, fontFamily: 'monospace' }}>
            {diag.gateway_ip}
          </div>
        </div>
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>
            SUBNET
          </div>
          <div style={{ fontSize: '13px', color: colors.text, fontFamily: 'monospace' }}>
            {diag.network}
          </div>
        </div>
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>
            PUBLIC IP
          </div>
          <div style={{ fontSize: '13px', color: colors.purple, fontFamily: 'monospace' }}>
            {diag.public_ip || 'Unknown'}
          </div>
        </div>
        {diag.dns_servers && diag.dns_servers.length > 0 && (
          <div>
            <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>
              DNS SERVERS
            </div>
            <div style={{ fontSize: '11px', color: colors.text, fontFamily: 'monospace' }}>
              {diag.dns_servers.slice(0, 2).join(', ')}
            </div>
          </div>
        )}
        <div>
          <div style={{ fontSize: '9px', color: colors.textMuted, marginBottom: '2px' }}>
            NETWORK TYPE
          </div>
          <div style={{ fontSize: '11px', color: colors.text, textTransform: 'capitalize' }}>
            {diag.network_type === 'vpn_or_enterprise'
              ? '🔐 VPN/Enterprise'
              : diag.network_type === 'home'
                ? '🏠 Home Network'
                : diag.network_type === 'corporate'
                  ? '🏢 Corporate'
                  : '❓ Unknown'}
          </div>
        </div>
      </div>

      {diag.issues && diag.issues.length > 0 && (
        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '10px', color: colors.warning, marginBottom: '6px', fontWeight: 600 }}>
            ⚠️ ISSUES DETECTED
          </div>
          <div style={{ background: colors.bgTertiary, borderRadius: '6px', padding: '8px' }}>
            {diag.issues.map((issue, i) => (
              <div
                key={i}
                style={{
                  fontSize: '10px',
                  color: colors.textMuted,
                  marginBottom: i < diag.issues.length - 1 ? '4px' : 0,
                }}
              >
                • {issue}
              </div>
            ))}
          </div>
        </div>
      )}

      {diag.recommendations && diag.recommendations.length > 0 && (
        <div>
          <div style={{ fontSize: '10px', color: colors.success, marginBottom: '6px', fontWeight: 600 }}>
            💡 RECOMMENDATIONS
          </div>
          <div style={{ background: colors.bgTertiary, borderRadius: '6px', padding: '8px' }}>
            {diag.recommendations.slice(0, 3).map((rec, i) => (
              <div
                key={i}
                style={{
                  fontSize: '10px',
                  color: colors.textMuted,
                  marginBottom: i < 2 ? '4px' : 0,
                }}
              >
                • {rec}
              </div>
            ))}
          </div>
        </div>
      )}

      <div
        style={{
          marginTop: '12px',
          padding: '10px',
          background: canScan ? `${colors.success}15` : `${colors.warning}15`,
          borderRadius: '6px',
          border: `1px solid ${canScan ? colors.success : colors.warning}33`,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '16px' }}>{canScan ? '✅' : '🔄'}</span>
            <div>
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  color: canScan ? colors.success : colors.warning,
                }}
              >
                {canScan ? 'Standard ARP Scan Available' : 'Smart Scan Mode Active'}
              </div>
              <div style={{ fontSize: '9px', color: colors.textMuted, marginTop: '2px' }}>
                {canScan
                  ? 'Fast device discovery via ARP broadcasting'
                  : 'Using ICMP + TCP probing for VPN/restricted networks'}
              </div>
            </div>
          </div>
          {!canScan && diag.network_type && (
            <div
              style={{
                padding: '4px 10px',
                background: colors.purple,
                borderRadius: '12px',
                fontSize: '9px',
                fontWeight: 600,
                color: '#fff',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
              }}
            >
              {diag.network_type.replace('_', ' ')}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
