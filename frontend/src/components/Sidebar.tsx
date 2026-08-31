import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Bot,
  FileText,
  UserCheck,
  ScrollText,
  Shield,
  Monitor,
  PlugZap,
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/connect', icon: PlugZap, label: 'Connect Agent' },
  { to: '/agents', icon: Bot, label: 'Agent Hub' },
  { to: '/policies', icon: FileText, label: 'Policy Center' },
  { to: '/hitl', icon: UserCheck, label: 'HITL Review' },
  { to: '/audit', icon: ScrollText, label: 'Audit Log' },
  { to: '/security', icon: Shield, label: 'Security' },
  { to: '/sessions', icon: Monitor, label: 'Sessions' },
];

export default function Sidebar() {
  return (
    <aside className="flex flex-col w-64 min-h-screen bg-gray-900 border-r border-gray-800">
      <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-800">
        <Shield className="w-8 h-8 text-blue-500" />
        <div>
          <h1 className="text-lg font-bold text-white">AI Sandbox</h1>
          <p className="text-xs text-gray-500">Security System</p>
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
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="text-xs text-gray-500">System Online</span>
        </div>
      </div>
    </aside>
  );
}
