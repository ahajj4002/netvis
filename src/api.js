/**
 * NetVis API helpers.
 */

export const API_BASE = (import.meta.env.VITE_API_BASE || '/api').replace(/\/+$/, '');

/**
 * Fetch JSON from URL; throw on non-OK with message from body or statusText.
 */
export async function fetchJsonOrThrow(url, options) {
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
