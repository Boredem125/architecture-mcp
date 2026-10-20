/**
 * Control-plane API client.
 *
 * Planned endpoints -- T8 (OIDC login) and T9 (orgs/projects/roles) confirm
 * the final shapes.  Until then these are the agreed contracts from M1_PLAN.md
 * D5/D6.  All requests use credentials: "same-origin" (cookie auth, no tokens
 * in localStorage/sessionStorage).
 */

const API_BASE = "/api/v1";

// ---------------------------------------------------------------------------
// Response types (planned; T8/T9 confirm)
// ---------------------------------------------------------------------------

export interface Org {
  id: string;
  slug: string;
  name: string;
}

export interface MeResponse {
  user_id: string;
  display_name: string;
  org: Org;
  roles: string[];
  csrf_token: string;
}

export interface Project {
  id: string;
  name: string;
}

export interface Member {
  user_id: string;
  display_name: string;
  role: string;
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

export class ApiUnavailableError extends Error {
  constructor() {
    super("Control-plane API not available");
    this.name = "ApiUnavailableError";
  }
}

export class NotAuthenticatedError extends Error {
  constructor() {
    super("Not authenticated");
    this.name = "NotAuthenticatedError";
  }
}

// ---------------------------------------------------------------------------
// Internal fetch helper
// ---------------------------------------------------------------------------

async function cpFetch<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...options,
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...options?.headers,
      },
    });
  } catch {
    throw new ApiUnavailableError();
  }

  if (res.status === 401) {
    throw new NotAuthenticatedError();
  }

  if (res.status === 404) {
    // A 404 on the API root likely means the control-plane server is not
    // running behind the proxy yet.
    throw new ApiUnavailableError();
  }

  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      detail = typeof body?.detail === "string" ? body.detail : "";
    } catch {
      /* non-JSON body */
    }
    throw new Error(detail || `API error: ${res.status}`);
  }

  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Login: browser navigation to GET /api/v1/auth/login?org=<slug>
// No fetch -- the browser navigates (form method="get" or location.assign).
// ---------------------------------------------------------------------------

/**
 * Build the login URL the browser should navigate to.
 * The actual navigation happens in the UI via a plain <form method="get">.
 */
export function loginUrl(orgSlug: string): string {
  return `${API_BASE}/auth/login?org=${encodeURIComponent(orgSlug)}`;
}

// ---------------------------------------------------------------------------
// GET /api/v1/me
// ---------------------------------------------------------------------------

export async function fetchMe(): Promise<MeResponse> {
  return cpFetch<MeResponse>("/me");
}

// ---------------------------------------------------------------------------
// GET /api/v1/projects
// ---------------------------------------------------------------------------

export async function fetchProjects(): Promise<Project[]> {
  return cpFetch<Project[]>("/projects");
}

// ---------------------------------------------------------------------------
// GET /api/v1/projects/{id}/members
// ---------------------------------------------------------------------------

export async function fetchMembers(projectId: string): Promise<Member[]> {
  return cpFetch<Member[]>(`/projects/${encodeURIComponent(projectId)}/members`);
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/logout  (X-CSRF-Token header)
// ---------------------------------------------------------------------------

export async function logout(csrfToken: string): Promise<void> {
  await cpFetch<unknown>("/auth/logout", {
    method: "POST",
    headers: {
      "X-CSRF-Token": csrfToken,
    },
  });
}
