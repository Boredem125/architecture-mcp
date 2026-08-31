import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/agents': 'Agent Hub',
  '/policies': 'Policy Center',
  '/hitl': 'HITL Review',
  '/audit': 'Audit Log',
  '/security': 'Security Center',
  '/sessions': 'Sessions',
  '/live': 'Live Session',
};

export default function Layout() {
  const location = useLocation();
  const title = pageTitles[location.pathname] || 'AI Sandbox';

  return (
    <div className="flex min-h-screen bg-gray-950">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="flex items-center justify-between px-8 py-4 border-b border-gray-800 bg-gray-900/50">
          <h2 className="text-xl font-semibold text-white">{title}</h2>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-400">v0.1.0</span>
          </div>
        </header>
        <main className="flex-1 p-8 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
