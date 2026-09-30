const BASE = '/api/v1';

// The approver token arrives once in the dashboard URL (`?token=...`, printed
// by `sandbox serve`), is kept for this tab only, and is removed from the URL.
const TOKEN_KEY = 'sandbox-approver-token';

export function apiToken(): string {
  try {
    const params = new URLSearchParams(window.location.search);
    const fromUrl = params.get('token');
    if (fromUrl) {
      sessionStorage.setItem(TOKEN_KEY, fromUrl);
      params.delete('token');
      const query = params.toString();
      window.history.replaceState(null, '', window.location.pathname + (query ? `?${query}` : '') + window.location.hash);
      return fromUrl;
    }
    return sessionStorage.getItem(TOKEN_KEY) ?? '';
  } catch {
    return '';
  }
}

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiToken()}`, ...options?.headers },
  });
  if (!res.ok) {
    // Surface the server's explanation (FastAPI puts it in `detail`) instead
    // of a bare status code, so the UI can show something actionable.
    let detail = '';
    try {
      const body = await res.json();
      detail = typeof body?.detail === 'string' ? body.detail : '';
    } catch {
      /* non-JSON error body — fall back to status */
    }
    throw new Error(detail || `API error: ${res.status}`);
  }
  return res.json();
}
