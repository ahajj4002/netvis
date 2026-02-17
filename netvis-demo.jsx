import React, { useState, useEffect, useRef, useMemo } from 'react';

// Demo data - simulating a real network
const DEMO_DEVICES = [
  { ip: "192.168.1.1", mac: "AA:BB:CC:DD:EE:01", hostname: "router.local", vendor: "Cisco", is_gateway: true, open_ports: [80, 443, 22], services: { 80: "HTTP", 443: "HTTPS", 22: "SSH" }},
  { ip: "192.168.1.10", mac: "AA:BB:CC:DD:EE:10", hostname: "workstation-1", vendor: "Dell", is_local: true, open_ports: [22, 3389], services: { 22: "SSH", 3389: "RDP" }},
  { ip: "192.168.1.20", mac: "AA:BB:CC:DD:EE:20", hostname: "server-web", vendor: "HP", open_ports: [80, 443, 22, 3306], services: { 80: "HTTP", 443: "HTTPS", 22: "SSH", 3306: "MySQL" }},
  { ip: "192.168.1.30", mac: "AA:BB:CC:DD:EE:30", hostname: "nas-storage", vendor: "Synology", open_ports: [22, 139, 445, 5000], services: { 22: "SSH", 139: "NetBIOS", 445: "SMB", 5000: "HTTP" }},
  { ip: "192.168.1.40", mac: "AA:BB:CC:DD:EE:40", hostname: "printer-office", vendor: "HP", open_ports: [80, 443, 9100], services: { 80: "HTTP", 443: "HTTPS", 9100: "RAW-Print" }},
  { ip: "192.168.1.50", mac: "AA:BB:CC:DD:EE:50", hostname: "iot-camera", vendor: "Hikvision", open_ports: [80, 554, 8000], services: { 80: "HTTP", 554: "RTSP", 8000: "SDK" }},
  { ip: "192.168.1.60", mac: "AA:BB:CC:DD:EE:60", hostname: "smart-tv", vendor: "Samsung", open_ports: [8001, 8002], services: { 8001: "WS-API", 8002: "HTTPS-API" }},
  { ip: "192.168.1.100", mac: "AA:BB:CC:DD:EE:A0", hostname: "laptop-alice", vendor: "Apple", open_ports: [], services: {}},
  { ip: "192.168.1.101", mac: "AA:BB:CC:DD:EE:A1", hostname: "phone-bob", vendor: "Samsung", open_ports: [], services: {}},
];

const DEMO_CONNECTIONS = [
  { src_ip: "192.168.1.10", dst_ip: "192.168.1.1", protocol: "TCP", src_port: 52341, dst_port: 443, packet_count: 1500, byte_count: 2500000 },
  { src_ip: "192.168.1.10", dst_ip: "192.168.1.20", protocol: "TCP", src_port: 52342, dst_port: 80, packet_count: 800, byte_count: 450000 },
  { src_ip: "192.168.1.10", dst_ip: "192.168.1.30", protocol: "TCP", src_port: 52343, dst_port: 445, packet_count: 2000, byte_count: 15000000 },
  { src_ip: "192.168.1.100", dst_ip: "192.168.1.1", protocol: "TCP", src_port: 52344, dst_port: 443, packet_count: 3000, byte_count: 8000000 },
  { src_ip: "192.168.1.100", dst_ip: "192.168.1.20", protocol: "TCP", src_port: 52345, dst_port: 443, packet_count: 500, byte_count: 120000 },
  { src_ip: "192.168.1.101", dst_ip: "192.168.1.1", protocol: "TCP", src_port: 52346, dst_port: 443, packet_count: 1200, byte_count: 3500000 },
  { src_ip: "192.168.1.60", dst_ip: "192.168.1.1", protocol: "TCP", src_port: 52347, dst_port: 443, packet_count: 5000, byte_count: 25000000 },
  { src_ip: "192.168.1.50", dst_ip: "192.168.1.30", protocol: "TCP", src_port: 52348, dst_port: 445, packet_count: 10000, byte_count: 500000000 },
  { src_ip: "192.168.1.20", dst_ip: "192.168.1.30", protocol: "TCP", src_port: 52349, dst_port: 3306, packet_count: 400, byte_count: 80000 },
  { src_ip: "192.168.1.40", dst_ip: "192.168.1.10", protocol: "TCP", src_port: 52350, dst_port: 9100, packet_count: 50, byte_count: 250000 },
];

const colors = {
  bg: '#0a0e17', bgSecondary: '#111827', bgTertiary: '#1a2234',
  border: '#1e3a5f', borderLight: '#2d4a6f',
  text: '#e2e8f0', textMuted: '#64748b',
  accent: '#00d4ff', accentDim: '#0891b2',
  success: '#10b981', warning: '#f59e0b', danger: '#ef4444',
  purple: '#8b5cf6', pink: '#ec4899',
};

const deviceIcons = {
  gateway: 'M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5',
  server: 'M4 4h16v4H4zm0 6h16v4H4zm0 6h16v4H4z',
  workstation: 'M4 4h16v12H4zm0 14h16v2H4zm6-8h4',
  laptop: 'M4 6h16v10H4zm2 12h12v2H6z',
  phone: 'M7 2h10v20H7zm3 17h4',
  iot: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 4a1 1 0 110 2 1 1 0 010-2zm0 4a1 1 0 110 2 1 1 0 010-2zm0 4a1 1 0 110 2 1 1 0 010-2z',
  printer: 'M6 2h12v6H6zm0 12h12v6H6zM4 8h16v8H4z',
  unknown: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 14v2m0-6a2 2 0 100-4 2 2 0 000 4z',
};

function getDeviceType(d) {
  const h = (d.hostname || '').toLowerCase();
  const v = (d.vendor || '').toLowerCase();
  if (d.is_gateway) return 'gateway';
  if (h.includes('server') || h.includes('nas')) return 'server';
  if (h.includes('laptop') || v.includes('apple')) return 'laptop';
  if (h.includes('phone')) return 'phone';
  if (h.includes('printer')) return 'printer';
  if (h.includes('camera') || h.includes('iot') || h.includes('smart')) return 'iot';
  if (h.includes('workstation') || d.is_local) return 'workstation';
  return 'unknown';
}

function formatBytes(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return (b / Math.pow(k, i)).toFixed(1) + ' ' + s[i];
}

function useForceSimulation(nodes, edges, width, height) {
  const [positions, setPositions] = useState({});
  
  useEffect(() => {
    if (!nodes.length) return;
    const pos = {};
    nodes.forEach((n, i) => {
      if (n.is_gateway) {
        pos[n.id] = { x: width / 2, y: height / 2, vx: 0, vy: 0 };
      } else {
        const a = (i / nodes.length) * 2 * Math.PI;
        const r = Math.min(width, height) * 0.32;
        pos[n.id] = { x: width/2 + r * Math.cos(a), y: height/2 + r * Math.sin(a), vx: 0, vy: 0 };
      }
    });
    
    const edgeMap = {};
    edges.forEach(e => {
      if (!edgeMap[e.source]) edgeMap[e.source] = [];
      if (!edgeMap[e.target]) edgeMap[e.target] = [];
      edgeMap[e.source].push(e.target);
      edgeMap[e.target].push(e.source);
    });
    
    const interval = setInterval(() => {
      nodes.forEach(n => {
        const p = pos[n.id];
        let fx = 0, fy = 0;
        nodes.forEach(o => {
          if (n.id === o.id) return;
          const op = pos[o.id];
          const dx = p.x - op.x, dy = p.y - op.y;
          const d = Math.sqrt(dx*dx + dy*dy) || 1;
          const f = 4000 / (d*d);
          fx += (dx/d) * f; fy += (dy/d) * f;
        });
        (edgeMap[n.id] || []).forEach(oid => {
          const op = pos[oid]; if (!op) return;
          fx += (op.x - p.x) * 0.008; fy += (op.y - p.y) * 0.008;
        });
        fx += (width/2 - p.x) * 0.001; fy += (height/2 - p.y) * 0.001;
        p.vx = (p.vx + fx * 0.1) * 0.85;
        p.vy = (p.vy + fy * 0.1) * 0.85;
        if (n.is_gateway) { p.vx *= 0.1; p.vy *= 0.1; }
      });
      nodes.forEach(n => {
        const p = pos[n.id];
        p.x = Math.max(60, Math.min(width-60, p.x + p.vx));
        p.y = Math.max(60, Math.min(height-60, p.y + p.vy));
      });
      setPositions({...pos});
    }, 30);
    return () => clearInterval(interval);
  }, [nodes, edges, width, height]);
  
  return positions;
}

function NetworkGraph({ devices, connections, selectedDevice, onSelectDevice }) {
  const ref = useRef(null);
  const [dim, setDim] = useState({ width: 700, height: 500 });
  const [hovered, setHovered] = useState(null);
  const [hoveredEdge, setHoveredEdge] = useState(null);
  
  useEffect(() => {
    const update = () => {
      if (ref.current) {
        const r = ref.current.getBoundingClientRect();
        setDim({ width: r.width, height: r.height });
      }
    };
    update();
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, []);
  
  const nodes = useMemo(() => devices.map(d => ({ id: d.ip, ...d, type: getDeviceType(d) })), [devices]);
  const edges = useMemo(() => {
    const m = {};
    connections.forEach(c => {
      const k = [c.src_ip, c.dst_ip].sort().join('-');
      if (!m[k]) m[k] = { source: c.src_ip, target: c.dst_ip, bytes: 0, packets: 0, protocols: new Set() };
      m[k].bytes += c.byte_count; m[k].packets += c.packet_count; m[k].protocols.add(c.protocol);
    });
    return Object.values(m).map(e => ({ ...e, protocols: [...e.protocols] }));
  }, [connections]);
  
  const positions = useForceSimulation(nodes, edges, dim.width, dim.height);
  const maxBytes = Math.max(...edges.map(e => e.bytes), 1);
  
  return (
    <div ref={ref} style={{ width: '100%', height: '100%', background: `radial-gradient(ellipse at center, ${colors.bgSecondary}, ${colors.bg})`, position: 'relative' }}>
      <svg style={{ position: 'absolute', opacity: 0.08, width: '100%', height: '100%' }}>
        <defs><pattern id="g" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M40 0L0 0 0 40" fill="none" stroke={colors.border} strokeWidth="0.5"/></pattern></defs>
        <rect width="100%" height="100%" fill="url(#g)"/>
      </svg>
      <svg width={dim.width} height={dim.height}>
        <defs>
          <filter id="glow"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        </defs>
        {edges.map((e, i) => {
          const s = positions[e.source], t = positions[e.target];
          if (!s || !t) return null;
          const w = 1 + (e.bytes / maxBytes) * 8;
          const isH = hoveredEdge === e;
          return (
            <g key={i}>
              <line x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke={isH ? colors.accent : colors.accentDim} strokeWidth={w} strokeOpacity={isH ? 1 : 0.35} strokeLinecap="round" style={{cursor:'pointer'}} onMouseEnter={() => setHoveredEdge(e)} onMouseLeave={() => setHoveredEdge(null)}/>
              {e.bytes > maxBytes * 0.1 && <circle r="3" fill={colors.accent}><animateMotion dur={`${3 - (e.bytes/maxBytes)*2}s`} repeatCount="indefinite" path={`M${s.x},${s.y}L${t.x},${t.y}`}/></circle>}
            </g>
          );
        })}
        {nodes.map(n => {
          const p = positions[n.id]; if (!p) return null;
          const isSel = selectedDevice?.ip === n.id;
          const isH = hovered === n.id;
          const c = isSel || isH ? colors.accent : n.is_gateway ? colors.warning : n.is_local ? colors.success : colors.textMuted;
          const r = n.is_gateway ? 26 : 20;
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`} style={{cursor:'pointer'}} onMouseEnter={() => setHovered(n.id)} onMouseLeave={() => setHovered(null)} onClick={() => onSelectDevice(n)}>
              {(isSel || isH) && <circle r={r+8} fill="none" stroke={c} strokeWidth="2" opacity="0.3" filter="url(#glow)"/>}
              <circle r={r} fill={colors.bgTertiary} stroke={c} strokeWidth={isSel ? 3 : 2}/>
              <svg x={-10} y={-10} width={20} height={20} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5"><path d={deviceIcons[n.type]}/></svg>
              <text y={r+14} textAnchor="middle" fill={colors.text} fontSize="10" fontFamily="system-ui">{n.hostname || n.ip}</text>
              {n.hostname && <text y={r+24} textAnchor="middle" fill={colors.textMuted} fontSize="8" fontFamily="monospace">{n.ip}</text>}
            </g>
          );
        })}
      </svg>
      {hoveredEdge && positions[hoveredEdge.source] && positions[hoveredEdge.target] && (
        <div style={{ position:'absolute', left:(positions[hoveredEdge.source].x + positions[hoveredEdge.target].x)/2, top:(positions[hoveredEdge.source].y + positions[hoveredEdge.target].y)/2 - 50, transform:'translateX(-50%)', background:colors.bgTertiary, border:`1px solid ${colors.border}`, borderRadius:6, padding:'6px 10px', pointerEvents:'none', fontSize:10, fontFamily:'monospace' }}>
          <div style={{color:colors.text}}>{hoveredEdge.source} ↔ {hoveredEdge.target}</div>
          <div style={{color:colors.textMuted}}>{formatBytes(hoveredEdge.bytes)} • {hoveredEdge.packets.toLocaleString()} pkts</div>
          <div style={{color:colors.accentDim}}>{hoveredEdge.protocols.join(', ')}</div>
        </div>
      )}
    </div>
  );
}

function SidePanel({ device, connections, onClose }) {
  if (!device) return null;
  const devConns = connections.filter(c => c.src_ip === device.ip || c.dst_ip === device.ip);
  const totalBytes = devConns.reduce((s, c) => s + c.byte_count, 0);
  return (
    <div style={{ width: 280, background: colors.bgSecondary, borderLeft: `1px solid ${colors.border}`, display: 'flex', flexDirection: 'column', fontFamily: 'system-ui', fontSize: 12 }}>
      <div style={{ padding: 16, borderBottom: `1px solid ${colors.border}`, display: 'flex', justifyContent: 'space-between' }}>
        <div>
          <div style={{ color: colors.text, fontWeight: 600 }}>{device.hostname || 'Unknown'}</div>
          <div style={{ color: colors.accent, fontSize: 11 }}>{device.ip}</div>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: colors.textMuted, cursor: 'pointer', fontSize: 16 }}>×</button>
      </div>
      <div style={{ padding: 16, borderBottom: `1px solid ${colors.border}` }}>
        {[['MAC', device.mac], ['Vendor', device.vendor], ['Type', getDeviceType(device)]].map(([l, v]) => (
          <div key={l} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ color: colors.textMuted }}>{l}</span><span style={{ color: colors.text }}>{v || 'Unknown'}</span>
          </div>
        ))}
        {device.open_ports?.length > 0 && (
          <div style={{ marginTop: 10 }}>
            <div style={{ color: colors.textMuted, fontSize: 9, marginBottom: 4 }}>OPEN PORTS</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {device.open_ports.map(p => <span key={p} style={{ background: colors.bgTertiary, color: colors.accent, padding: '2px 6px', borderRadius: 4, fontSize: 10 }}>{p}</span>)}
            </div>
          </div>
        )}
      </div>
      <div style={{ padding: 16, borderBottom: `1px solid ${colors.border}` }}>
        <div style={{ color: colors.textMuted, fontSize: 9, marginBottom: 8 }}>TRAFFIC</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {[['Data', formatBytes(totalBytes), colors.accent], ['Connections', devConns.length, colors.purple]].map(([l, v, c]) => (
            <div key={l} style={{ background: colors.bgTertiary, borderRadius: 6, padding: 10, textAlign: 'center' }}>
              <div style={{ color: c, fontSize: 14, fontWeight: 600 }}>{v}</div>
              <div style={{ color: colors.textMuted, fontSize: 9 }}>{l}</div>
            </div>
          ))}
        </div>
      </div>
      <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
        <div style={{ color: colors.textMuted, fontSize: 9, marginBottom: 8 }}>CONNECTIONS</div>
        {devConns.map((c, i) => {
          const out = c.src_ip === device.ip;
          return (
            <div key={i} style={{ background: colors.bgTertiary, borderRadius: 6, padding: 10, marginBottom: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ color: out ? colors.accent : colors.success, marginRight: 6 }}>{out ? '→' : '←'}</span>
                <span style={{ color: colors.text, fontSize: 11 }}>{out ? c.dst_ip : c.src_ip}</span>
                <span style={{ marginLeft: 'auto', background: colors.bgSecondary, color: colors.accentDim, padding: '2px 5px', borderRadius: 3, fontSize: 9 }}>{c.protocol}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: colors.textMuted, fontSize: 9 }}>
                <span>{formatBytes(c.byte_count)}</span><span>{c.packet_count} pkts</span><span>:{c.dst_port}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function App() {
  const [devices, setDevices] = useState([]);
  const [connections, setConnections] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loaded, setLoaded] = useState(false);
  
  const loadDemo = () => { setDevices(DEMO_DEVICES); setConnections(DEMO_CONNECTIONS); setLoaded(true); };
  
  return (
    <div style={{ width: '100%', height: '100vh', display: 'flex', flexDirection: 'column', background: colors.bg, color: colors.text, fontFamily: 'system-ui' }}>
      <div style={{ background: colors.bgSecondary, borderBottom: `1px solid ${colors.border}`, padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={colors.accent} strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M12 2v4m0 12v4M2 12h4m12 0h4"/><circle cx="12" cy="12" r="9" opacity="0.3"/></svg>
        <span style={{ fontWeight: 700, letterSpacing: '0.05em' }}>NETVIS</span>
        <span style={{ color: colors.textMuted, fontSize: 11 }}>Network Visualization Platform</span>
        <div style={{ flex: 1 }}/>
        <button onClick={loadDemo} style={{ background: loaded ? colors.bgTertiary : colors.accent, color: loaded ? colors.textMuted : colors.bg, border: 'none', borderRadius: 5, padding: '7px 14px', fontSize: 11, fontWeight: 600, cursor: 'pointer' }}>
          {loaded ? '✓ Demo Loaded' : 'Load Demo Data'}
        </button>
      </div>
      
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1 }}>
          {!loaded ? (
            <div style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke={colors.textMuted} strokeWidth="1.5"><circle cx="12" cy="12" r="3"/><path d="M12 2v4m0 12v4M2 12h4m12 0h4"/><circle cx="12" cy="12" r="9" opacity="0.3"/></svg>
              <div style={{ color: colors.textMuted, marginTop: 12, fontSize: 13 }}>Click "Load Demo Data" to see the network visualization</div>
            </div>
          ) : (
            <NetworkGraph devices={devices} connections={connections} selectedDevice={selected} onSelectDevice={setSelected}/>
          )}
        </div>
        {selected && <SidePanel device={selected} connections={connections} onClose={() => setSelected(null)}/>}
      </div>
      
      {loaded && (
        <div style={{ background: colors.bgSecondary, borderTop: `1px solid ${colors.border}`, padding: '10px 16px', display: 'flex', gap: 24, fontSize: 11 }}>
          <span><span style={{ color: colors.textMuted }}>Devices: </span><span style={{ color: colors.accent }}>{devices.length}</span></span>
          <span><span style={{ color: colors.textMuted }}>Connections: </span><span style={{ color: colors.purple }}>{connections.length}</span></span>
          <span><span style={{ color: colors.textMuted }}>Traffic: </span><span style={{ color: colors.success }}>{formatBytes(connections.reduce((s,c) => s + c.byte_count, 0))}</span></span>
          <span><span style={{ color: colors.textMuted }}>Tip: </span><span style={{ color: colors.textMuted }}>Click nodes for details, hover edges for traffic info</span></span>
        </div>
      )}
    </div>
  );
}
