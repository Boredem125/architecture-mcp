import { NavLink } from 'react-router-dom';
import { Shield, LayoutDashboard } from 'lucide-react';

const navItems = [{ to: '/', icon: LayoutDashboard, label: 'Control plane' }];

export default function Sidebar() {
  return (
    <aside className="flex flex-col w-64 min-h-screen bg-gray-900 border-r border-gray-800">
      <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-800">
        <Shield className="w-8 h-8 text-blue-500" />
        <div>
          <h1 className="text-lg font-bold text-white">AI Sandbox</h1>
          <p className="text-xs text-gray-500">Agent Governance</p>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600/20 text-blue-400'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              }`
            }
          >
            <Icon className="w-5 h-5" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-4 border-t border-gray-800">
        <span className="text-xs text-gray-500">M0 shell</span>
      </div>
    </aside>
  );
}
