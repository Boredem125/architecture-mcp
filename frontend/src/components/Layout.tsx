import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';

export default function Layout() {
  return (
    <div className="flex min-h-screen bg-gray-950">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="flex items-center justify-between px-8 py-4 border-b border-gray-800 bg-gray-900/50">
          <h2 className="text-xl font-semibold text-white">Control plane</h2>
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
