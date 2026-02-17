/**
 * NetVis theme: colors and device icons.
 */

export const colors = {
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

export const deviceIcons = {
  gateway: 'M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5',
  server: 'M4 4h16v4H4zm0 6h16v4H4zm0 6h16v4H4z',
  workstation: 'M4 4h16v12H4zm0 14h16v2H4zm6-8h4',
  laptop: 'M4 6h16v10H4zm2 12h12v2H6z',
  phone: 'M7 2h10v20H7zm3 17h4',
  iot: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 4a1 1 0 110 2 1 1 0 010-2zm0 4a1 1 0 110 2 1 1 0 010-2z',
  printer: 'M6 2h12v6H6zm0 12h12v6H6zM4 8h16v8H4z',
  unknown: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 14v2m0-6a2 2 0 100-4 2 2 0 000 4z',
};

/** Card container style */
export const cardStyle = {
  background: colors.bgCard,
  border: `1px solid ${colors.border}`,
  borderRadius: '12px',
  padding: '16px',
};

/** Input field style */
export function inputStyle(overrides = {}) {
  return {
    background: colors.bgTertiary,
    border: `1px solid ${colors.border}`,
    borderRadius: '10px',
    padding: '8px',
    color: colors.text,
    fontSize: '10px',
    ...overrides,
  };
}
