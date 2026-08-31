const BASE = '/api/v1';

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
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
