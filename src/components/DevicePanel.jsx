import React, { useState, useEffect } from 'react';
import { colors } from '../theme';
import { formatBytes, formatNumber } from '../utils';
import { API_BASE } from '../api';
import { StatsCard } from './StatsCard';
import { MiniBarChart } from './MiniBarChart';

/**
 * Device detail sidebar: info, ports, bandwidth, connections.
 */
export function DevicePanel({ device, connections, onClose, onPortScan }) {
  const [scanning, setScanning] = useState(false);
  const [bandwidth, setBandwidth] = useState(null);

  useEffect(() => {
    if (device) {
      fetch(`${API_BASE}/bandwidth/${device.ip}`)
        .then((res) => res.json())
        .then(setBandwidth)
        .catch(() => {});
    }
  }, [device]);

  if (!device) return null;

  const deviceConnections = connections.filter(
    (c) => c.src_ip === device.ip || c.dst_ip === device.ip
  );
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
    <div
      style={{
        width: '360px',
        background: colors.bgSecondary,
        borderLeft: `1px solid ${colors.border}`,
        display: 'flex',
        flexDirection: 'column',
        fontFamily: 'JetBrains Mono, monospace',
      }}
    >
      <div
        style={{
          padding: '20px',
          borderBottom: `1px solid ${colors.border}`,
          background: colors.bgCard,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h3 style={{ margin: 0, color: colors.text, fontSize: '14px', fontWeight: 600 }}>
              {device.hostname || 'Unknown Device'}
            </h3>
            <div style={{ color: colors.accent, fontSize: '12px', marginTop: '4px' }}>
              {device.ip}
            </div>
            {device.os && (
              <div style={{ color: colors.purple, fontSize: '10px', marginTop: '2px' }}>
                {device.os}
              </div>
            )}
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: colors.textMuted,
              cursor: 'pointer',
              fontSize: '20px',
            }}
          >
            ×
          </button>
        </div>

        <button
          onClick={handlePortScan}
          disabled={scanning}
          style={{
            marginTop: '12px',
            width: '100%',
            padding: '8px',
            background: colors.bgTertiary,
            border: `1px solid ${colors.border}`,
            borderRadius: '6px',
            color: colors.text,
            fontSize: '11px',
            cursor: scanning ? 'not-allowed' : 'pointer',
          }}
        >
          {scanning ? 'Scanning Ports...' : '🔍 Deep Scan Ports'}
        </button>
      </div>

      <div style={{ padding: '16px', borderBottom: `1px solid ${colors.border}` }}>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '8px',
            fontSize: '11px',
          }}
        >
          <div>
            <span style={{ color: colors.textMuted }}>MAC:</span>{' '}
            <span style={{ color: colors.text }}>{device.mac || 'Unknown'}</span>
          </div>
          <div>
            <span style={{ color: colors.textMuted }}>Vendor:</span>{' '}
            <span style={{ color: colors.text }}>{device.vendor || 'Unknown'}</span>
          </div>
        </div>

        {device.open_ports?.length > 0 && (
          <div style={{ marginTop: '12px' }}>
            <div style={{ color: colors.textMuted, fontSize: '10px', marginBottom: '6px' }}>
              OPEN PORTS
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {device.open_ports.map((port) => (
                <span
                  key={port}
                  style={{
                    background: colors.bgTertiary,
                    color: colors.accent,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '10px',
                  }}
                >
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
          <StatsCard
            title="Packets"
            value={formatNumber(totalPackets)}
            color={colors.purple}
          />
        </div>

        {bandwidth?.history?.length > 0 && (
          <div style={{ marginTop: '12px' }}>
            <div style={{ color: colors.textMuted, fontSize: '10px', marginBottom: '6px' }}>
              BANDWIDTH (last 60s)
            </div>
            <MiniBarChart
              data={bandwidth.history.map((h) => ({ value: h.bytes, label: h.timestamp }))}
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
            <div
              key={i}
              style={{
                background: colors.bgTertiary,
                borderRadius: '6px',
                padding: '8px',
                marginBottom: '6px',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  marginBottom: '4px',
                }}
              >
                <span style={{ color: isOutgoing ? colors.accent : colors.success }}>
                  {isOutgoing ? '→' : '←'}
                </span>
                <span style={{ color: colors.text, fontSize: '11px', flex: 1 }}>
                  {otherDevice}
                </span>
                <span
                  style={{
                    background: colors.bgSecondary,
                    color: colors.accentDim,
                    padding: '1px 4px',
                    borderRadius: '3px',
                    fontSize: '9px',
                  }}
                >
                  {conn.protocol}
                </span>
              </div>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  color: colors.textDim,
                  fontSize: '10px',
                }}
              >
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
