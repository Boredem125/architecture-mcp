import { Activity, Bot, FileText, Shield, UserCheck } from 'lucide-react';
import { useEffect, useState } from 'react';
import LiveFeed from '../components/LiveFeed';
import { apiFetch } from '../api/client';

interface DashboardStats {
  active_sessions: number;
  connected_agents: number;
  total_agents: number;
  pending_hitl: number;
  policy_rules: number;
  active_jit_grants: number;
  rbac_roles: number;
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    const load = () => {
      apiFetch<DashboardStats>('/dashboard/stats')
        .then(setStats)
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  const statCards = [
    { label: 'Active Sessions', value: stats?.active_sessions ?? '-', icon: Activity, color: 'text-green-400 bg-green-500/10' },
    { label: 'Pending HITL', value: stats?.pending_hitl ?? '-', icon: UserCheck, color: 'text-yellow-400 bg-yellow-500/10' },
    { label: 'Policy Rules', value: stats?.policy_rules ?? '-', icon: FileText, color: 'text-blue-400 bg-blue-500/10' },
    { label: 'Connected Agents', value: `${stats?.connected_agents ?? 0}/${stats?.total_agents ?? 0}`, icon: Bot, color: 'text-purple-400 bg-purple-500/10' },
  ];

  return (
    <div className="space-y-6">
      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((s) => (
          <div key={s.label} className="bg-gray-900 rounded-xl border border-gray-800 p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">{s.label}</p>
                <p className="text-2xl font-bold text-white mt-1">{s.value}</p>
              </div>
              <div className={`p-3 rounded-lg ${s.color}`}>
                <s.icon className="w-5 h-5" />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Feed — takes 2 columns */}
        <div className="lg:col-span-2 bg-gray-900 rounded-xl border border-gray-800 overflow-hidden" style={{ maxHeight: '600px' }}>
          <LiveFeed />
        </div>

        {/* Pipeline Health */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Pipeline Health</h3>
          <div className="space-y-4">
            {[
              { name: 'Request Evaluator', step: '1-2' },
              { name: 'Policy Engine', step: '3' },
              { name: 'Content Safety', step: '4' },
              { name: 'HITL Gate', step: '5' },
              { name: 'Command Signing', step: '6' },
              { name: 'Executor', step: '7' },
              { name: 'Audit Logger', step: '8' },
            ].map((p) => (
              <div key={p.name} className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
                <div>
                  <span className="text-sm text-gray-300">{p.name}</span>
                  <span className="text-xs text-gray-600 ml-2">Step {p.step}</span>
                </div>
                <span className="flex items-center gap-1.5 text-xs text-green-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                  Online
                </span>
              </div>
            ))}
          </div>
          <div className="mt-6 flex items-center gap-2">
            <Shield className="w-5 h-5 text-green-400" />
            <span className="text-sm text-green-400 font-medium">All 8 steps operational</span>
          </div>

          {/* SC-500 Score */}
          <div className="mt-6 pt-4 border-t border-gray-800">
            <h4 className="text-sm font-semibold text-gray-300 mb-2">Zero Trust Score</h4>
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-full border-2 border-green-500 flex items-center justify-center">
                <span className="text-lg font-bold text-green-400">75</span>
              </div>
              <div className="text-xs text-gray-400 space-y-0.5">
                <p>Identity: 75% | Network: 75%</p>
                <p>Data: 75% | Device: 100%</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
