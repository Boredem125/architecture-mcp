import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useCallback } from "react";
import {
  fetchMe,
  fetchProjects,
  fetchMembers,
  logout,
  loginUrl,
  NotAuthenticatedError,
  ApiUnavailableError,
} from "./api/client";
import type { MeResponse, Project, Member } from "./api/client";

// ---------------------------------------------------------------------------
// Login form -- navigates to the OIDC endpoint with location.assign, not a
// native form submit: CSP form-action 'self' would also block the redirect
// from /api/v1/auth/login on to the IdP.
// ---------------------------------------------------------------------------

function LoginForm() {
  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const slug = new FormData(e.currentTarget).get("org");
    if (typeof slug === "string" && slug.trim() !== "") {
      window.location.assign(loginUrl(slug.trim()));
    }
  };
  return (
    <div className="login-card">
      <h1 className="login-title">Agent Governance</h1>
      <p className="login-subtitle">Sign in to your organisation</p>
      <form onSubmit={onSubmit}>
        <label htmlFor="org-slug" className="login-label">
          Organisation slug
        </label>
        <input
          id="org-slug"
          name="org"
          type="text"
          required
          autoComplete="organization"
          className="login-input"
          placeholder="acme"
        />
        <button type="submit" className="login-button">
          Sign in
        </button>
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------
// API-unavailable banner
// ---------------------------------------------------------------------------

function ApiUnavailable() {
  return (
    <div className="unavailable-card">
      <h2 className="unavailable-title">Control-plane API not available</h2>
      <p className="unavailable-text">
        The API server is not reachable. Make sure the control-plane is running
        and the proxy is configured.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Member list for a selected project
// ---------------------------------------------------------------------------

function MemberList({ projectId }: { projectId: string }) {
  const { data, isLoading, error } = useQuery<Member[], Error>({
    queryKey: ["members", projectId],
    queryFn: () => fetchMembers(projectId),
  });

  if (isLoading) return <p className="status-text">Loading members...</p>;
  if (error) return <p className="error-text">{error.message}</p>;
  if (!data || data.length === 0)
    return <p className="status-text">No members.</p>;

  return (
    <table className="members-table">
      <thead>
        <tr>
          <th className="th-cell">Name</th>
          <th className="th-cell">Role</th>
        </tr>
      </thead>
      <tbody>
        {data.map((m) => (
          <tr key={m.user_id} className="member-row">
            <td className="td-cell">{m.display_name}</td>
            <td className="td-cell td-role">{m.role}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ---------------------------------------------------------------------------
// Projects section
// ---------------------------------------------------------------------------

function ProjectsSection() {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery<Project[], Error>({
    queryKey: ["projects"],
    queryFn: fetchProjects,
  });

  if (isLoading) return <p className="status-text">Loading projects...</p>;
  if (error) return <p className="error-text">{error.message}</p>;
  if (!data || data.length === 0)
    return <p className="status-text">No projects.</p>;

  return (
    <section className="section-card">
      <h2 className="section-title">Projects</h2>
      <ul className="project-list">
        {data.map((p) => (
          <li key={p.id}>
            <button
              type="button"
              className={
                selectedId === p.id
                  ? "project-button project-button-active"
                  : "project-button"
              }
              onClick={() => setSelectedId(selectedId === p.id ? null : p.id)}
            >
              {p.name}
            </button>
          </li>
        ))}
      </ul>
      {selectedId && (
        <div className="members-section">
          <h3 className="members-title">Members</h3>
          <MemberList projectId={selectedId} />
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// User info bar
// ---------------------------------------------------------------------------

function UserInfo({
  me,
  onLogout,
}: {
  me: MeResponse;
  onLogout: () => void;
}) {
  return (
    <header className="user-bar">
      <div>
        <span className="user-name">{me.display_name}</span>
        <span className="user-org">{me.org.name}</span>
        <span className="user-roles">
          {me.roles.join(", ")}
        </span>
      </div>
      <button type="button" className="logout-button" onClick={onLogout}>
        Sign out
      </button>
    </header>
  );
}

// ---------------------------------------------------------------------------
// Main App
// ---------------------------------------------------------------------------

export default function App() {
  const queryClient = useQueryClient();

  const {
    data: me,
    isLoading,
    error,
  } = useQuery<MeResponse, Error>({
    queryKey: ["me"],
    queryFn: fetchMe,
    retry: false,
  });

  const handleLogout = useCallback(async () => {
    if (!me) return;
    try {
      await logout(me.csrf_token);
    } catch {
      /* best-effort */
    }
    queryClient.clear();
    window.location.assign("/");
  }, [me, queryClient]);

  if (isLoading) {
    return <div className="page-center"><p className="status-text">Loading...</p></div>;
  }

  if (error instanceof ApiUnavailableError) {
    return <div className="page-center"><ApiUnavailable /></div>;
  }

  if (error instanceof NotAuthenticatedError || !me) {
    return <div className="page-center"><LoginForm /></div>;
  }

  return (
    <div className="app-shell">
      <UserInfo me={me} onLogout={handleLogout} />
      <main className="main-content">
        <ProjectsSection />
      </main>
    </div>
  );
}
