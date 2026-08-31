import { useState } from 'react';
import { Power, Eye, X } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import type { Session } from '../types';

const mockSessions: Session[] = [
  { session_id: 'sess-a1b2', agent_id: 'claude-code-01', is_active: true, is_killed: false, total_requests: 42, deny_count: 1, hitl_count: 3, write_count: 8, started_at: '2025-01-15T10:30:00Z', expires_at: '2025-01-15T12:30:00Z', declared_task: 'Refactor authentication module' },
  { session_id: 'sess-c3d4', agent_id: 'codex-dev-02', is_active: true, is_killed: false, total_requests: 15, deny_count: 2, hitl_count: 1, write_count: 3, started_at: '2025-01-15T11:00:00Z', expires_at: '2025-01-15T13:00:00Z', declared_task: 'Fix database migration scripts' },
  { session_id: 'sess-e5f6', agent_id: 'custom-bot-x', is_active: true, is_killed: false, total_requests: 7, deny_count: 0, hitl_count: 0, write_count: 1, started_at: '2025-01-15T09:15:00Z', expires_at: '2025-01-15T11:15:00Z', declared_task: 'Generate API documentation' },
  { session_id: 'sess-g7h8', agent_id: 'hermes-scout', is_active: false, is_killed: true, total_requests: 88, deny_count: 12, hitl_count: 5, write_count: 0, started_at: '2025-01-15T08:00:00Z', expires_at: '2025-01-15T10:00:00Z', declared_task: 'Network reconnaissance scan' },
];

export default function Sessions() {
  const [selected, setSelected] = useState<Session | null>(null);

  return (
    <div className="space-y-6">
      <p className="text-gray-400">Monitor active sessions and use the kill switch for immediate termination.</p>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Session Table */}
        <div className="lg:col-span-2 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-3 pr-4">Session ID</th>
                <th className="pb-3 pr-4">Agent</th>
                <th className="pb-3 pr-4">Status</th>
                <th className="pb-3 pr-4">Requests</th>
                <th className="pb-3 pr-4">Denials</th>
                <th className="pb-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {mockSessions.map((s) => (
                <tr key={s.session_id} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                  <td className="py-3 pr-4 text-gray-300 font-mono text-xs">{s.session_id}</td>
                  <td className="py-3 pr-4 text-white">{s.agent_id}</td>
                  <td className="py-3 pr-4">
                    <StatusBadge status={s.is_killed ? 'killed' : s.is_active ? 'active' : 'disconnected'} />
                  </td>
                  <td className="py-3 pr-4 text-gray-300">{s.total_requests}</td>
                  <td className="py-3 pr-4 text-gray-300">{s.deny_count}</td>
                  <td className="py-3">
                    <div className="flex gap-2">
                      <button
                        onClick={() => setSelected(s)}
                        className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-800 rounded transition-colors"
                        title="View details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      {s.is_active && !s.is_killed && (
                        <button
                          className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors"
                          title="Kill session"
                        >
                          <Power className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Session Detail Panel */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          {selected ? (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-white font-semibold">Session Details</h3>
                <button onClick={() => setSelected(null)} className="text-gray-400 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Session ID</span>
                  <span className="text-gray-300 font-mono text-xs">{selected.session_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Agent</span>
                  <span className="text-white">{selected.agent_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Status</span>
                  <StatusBadge status={selected.is_killed ? 'killed' : selected.is_active ? 'active' : 'disconnected'} />
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Started</span>
                  <span className="text-gray-300 text-xs">{new Date(selected.started_at).toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Expires</span>
                  <span className="text-gray-300 text-xs">{new Date(selected.expires_at).toLocaleString()}</span>
                </div>
                <hr className="border-gray-800" />
                <div className="flex justify-between">
                  <span className="text-gray-500">Total Requests</span>
                  <span className="text-white font-medium">{selected.total_requests}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Denials</span>
                  <span className="text-red-400">{selected.deny_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">HITL Escalations</span>
                  <span className="text-yellow-400">{selected.hitl_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Writes</span>
                  <span className="text-blue-400">{selected.write_count}</span>
                </div>
                <hr className="border-gray-800" />
                <div>
                  <p className="text-gray-500 mb-1">Declared Task</p>
                  <p className="text-gray-300">{selected.declared_task}</p>
                </div>
              </div>
              {selected.is_active && !selected.is_killed && (
                <button className="w-full mt-4 flex items-center justify-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors">
                  <Power className="w-4 h-4" /> Kill Session
                </button>
              )}
            </div>
          ) : (
            <div className="text-center py-12">
              <Eye className="w-8 h-8 text-gray-600 mx-auto mb-2" />
              <p className="text-gray-500 text-sm">Select a session to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
