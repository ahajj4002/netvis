import React, { useState, useRef, useMemo, useEffect } from 'react';
import { colors, deviceIcons } from '../theme';
import { getDeviceType, formatBytes } from '../utils';
import { useForceSimulation } from '../hooks/useForceSimulation';

/**
 * Canvas-based force-directed network graph with pan/zoom and device/edge tooltips.
 */
export function NetworkGraph({
  devices,
  connections,
  onSelectDevice,
  selectedDevice,
  status,
}) {
  const containerRef = useRef(null);
  const [containerSize, setContainerSize] = useState({ width: 800, height: 500 });
  const [hoveredNode, setHoveredNode] = useState(null);
  const [hoveredEdge, setHoveredEdge] = useState(null);

  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const canvasSize = useMemo(() => {
    const minSize = 800;
    const deviceCount = devices.length;
    const scale = Math.max(1, Math.sqrt(deviceCount / 10));
    return {
      width: Math.max(minSize, containerSize.width * scale),
      height: Math.max(minSize, containerSize.height * scale),
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

  const handleMouseDown = (e) => {
    if (e.button === 0) {
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

  const handleWheel = (e) => {
    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      const delta = e.deltaY > 0 ? 0.9 : 1.1;
      setZoom((z) => Math.min(3, Math.max(0.3, z * delta)));
    }
  };

  const fitToView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const nodes = useMemo(
    () => devices.map((d) => ({ id: d.ip, ...d, type: getDeviceType(d) })),
    [devices]
  );

  const edges = useMemo(() => {
    const edgeMap = {};
    const localIPs = new Set(devices.map((d) => d.ip));
    const gatewayIP = devices.find((d) => d.is_gateway)?.ip || status?.gateway_ip;

    connections.forEach((c) => {
      let src = c.src_ip;
      let dst = c.dst_ip;

      const srcIsLocal =
        localIPs.has(src) || src.startsWith('192.168.') || src.startsWith('10.');
      const dstIsLocal =
        localIPs.has(dst) || dst.startsWith('192.168.') || dst.startsWith('10.');

      if (!localIPs.has(src) && !srcIsLocal) src = gatewayIP || '192.168.1.1';
      if (!localIPs.has(dst) && !dstIsLocal) dst = gatewayIP || '192.168.1.1';

      if (src === dst) return;
      if (!localIPs.has(src) && !localIPs.has(dst)) return;

      const key = [src, dst].sort().join('-');
      if (!edgeMap[key]) {
        edgeMap[key] = {
          source: src,
          target: dst,
          bytes: 0,
          packets: 0,
          protocols: new Set(),
          applications: new Set(),
          externalTraffic: !srcIsLocal || !dstIsLocal,
        };
      }
      edgeMap[key].bytes += c.byte_count;
      edgeMap[key].packets += c.packet_count;
      edgeMap[key].protocols.add(c.protocol);
      if (c.application) edgeMap[key].applications.add(c.application);
    });

    return Object.values(edgeMap).map((e) => ({
      ...e,
      protocols: Array.from(e.protocols),
      applications: Array.from(e.applications),
    }));
  }, [connections, devices, status?.gateway_ip]);

  const positions = useForceSimulation(nodes, edges, canvasSize.width, canvasSize.height);
  const maxBytes = Math.max(...edges.map((e) => e.bytes), 1);

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
    <div
      ref={containerRef}
      style={{
        width: '100%',
        height: '100%',
        background: `radial-gradient(ellipse at center, ${colors.bgSecondary} 0%, ${colors.bg} 100%)`,
        position: 'relative',
        overflow: 'hidden',
        borderRadius: '12px',
        border: `1px solid ${colors.border}`,
        cursor: isDragging ? 'grabbing' : 'grab',
      }}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      onWheel={handleWheel}
    >
      <div
        style={{
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
          border: `1px solid ${colors.border}`,
        }}
      >
        <button
          onClick={() => setZoom((z) => Math.min(3, z * 1.2))}
          style={{
            width: '28px',
            height: '28px',
            border: 'none',
            borderRadius: '4px',
            background: colors.bgTertiary,
            color: colors.text,
            cursor: 'pointer',
            fontSize: '16px',
          }}
        >
          +
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(0.3, z * 0.8))}
          style={{
            width: '28px',
            height: '28px',
            border: 'none',
            borderRadius: '4px',
            background: colors.bgTertiary,
            color: colors.text,
            cursor: 'pointer',
            fontSize: '16px',
          }}
        >
          −
        </button>
        <button
          onClick={fitToView}
          title="Fit to view"
          style={{
            width: '28px',
            height: '28px',
            border: 'none',
            borderRadius: '4px',
            background: colors.bgTertiary,
            color: colors.text,
            cursor: 'pointer',
            fontSize: '12px',
          }}
        >
          ⊙
        </button>
        <div style={{ fontSize: '9px', textAlign: 'center', color: colors.textMuted }}>
          {Math.round(zoom * 100)}%
        </div>
      </div>

      <div
        style={{
          position: 'absolute',
          bottom: '10px',
          left: '10px',
          zIndex: 10,
          fontSize: '9px',
          color: colors.textMuted,
          background: `${colors.bgCard}cc`,
          padding: '4px 8px',
          borderRadius: '4px',
        }}
      >
        🖱️ Drag to pan • Ctrl+Scroll to zoom • {devices.length} devices
      </div>

      <svg width="100%" height="100%" style={{ position: 'absolute', opacity: 0.05 }}>
        <defs>
          <pattern id="graphGrid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path
              d="M 40 0 L 0 0 0 40"
              fill="none"
              stroke={colors.border}
              strokeWidth="0.5"
            />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#graphGrid)" />
      </svg>

      <svg
        width={containerSize.width}
        height={containerSize.height}
        style={{ position: 'relative' }}
        viewBox={`${-pan.x / zoom} ${-pan.y / zoom} ${containerSize.width / zoom} ${containerSize.height / zoom}`}
      >
        <defs>
          <filter id="graphGlow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
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
                  x1={sourcePos.x}
                  y1={sourcePos.y}
                  x2={targetPos.x}
                  y2={targetPos.y}
                  stroke={getEdgeColor(edge)}
                  strokeWidth={getEdgeWidth(edge.bytes)}
                  strokeOpacity={hoveredEdge === edge ? 1 : 0.5}
                  strokeLinecap="round"
                  onMouseEnter={() => setHoveredEdge(edge)}
                  onMouseLeave={() => setHoveredEdge(null)}
                  style={{ cursor: 'pointer' }}
                />
                {edge.bytes > maxBytes * 0.1 && (
                  <circle r="4" fill={colors.accent} filter="url(#graphGlow)">
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
          {nodes.map((node) => {
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
                  <circle
                    r={radius + 8}
                    fill="none"
                    stroke={nodeColor}
                    strokeWidth="2"
                    opacity="0.3"
                    filter="url(#graphGlow)"
                  />
                )}
                <circle
                  r={radius}
                  fill={colors.bgTertiary}
                  stroke={nodeColor}
                  strokeWidth={isSelected ? 3 : 2}
                />
                <svg
                  x={-12}
                  y={-12}
                  width={24}
                  height={24}
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke={nodeColor}
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d={deviceIcons[node.type] || deviceIcons.unknown} />
                </svg>
                <text
                  y={radius + 14}
                  textAnchor="middle"
                  fill={colors.text}
                  fontSize="10"
                  fontFamily="JetBrains Mono, monospace"
                  fontWeight="500"
                >
                  {(node.hostname || node.ip).substring(0, 20)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {hoveredEdge &&
        positions[hoveredEdge.source] &&
        positions[hoveredEdge.target] && (
          <div
            style={{
              position: 'absolute',
              left:
                (positions[hoveredEdge.source].x + positions[hoveredEdge.target].x) / 2,
              top:
                (positions[hoveredEdge.source].y + positions[hoveredEdge.target].y) / 2 -
                70,
              transform: 'translateX(-50%)',
              background: colors.bgCard,
              border: `1px solid ${colors.border}`,
              borderRadius: '8px',
              padding: '10px 14px',
              pointerEvents: 'none',
              zIndex: 100,
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '11px',
              boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
            }}
          >
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
