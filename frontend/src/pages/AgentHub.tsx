import { useState } from 'react';
import { Plus, X, Bot } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import type { AgentConnection } from '../types';

const mockAgents: AgentConnection[] = [
  { id: '1', name: 'claude-code-01', type: 'claude-code', status: 'connected', session_id: 'sess-a1b2', capabilities: ['file_read', 'file_write', 'shell_exec'], trust_level: 'elevated', connected_at: '2025-01-15T10:30:00Z' },
  { id: '2', name: 'codex-dev-02', type: 'codex', status: 'connected', session_id: 'sess-c3d4', capabilities: ['file_read', 'file_write'], trust_level: 'basic', connected_at: '2025-01-15T11:00:00Z' },
  { id: '3', name: 'hermes-scout', type: 'hermes', status: 'disconnected', capabilities: ['network_access', 'file_read'], trust_level: 'untrusted' },
  { id: '4', name: 'antigravity-01', type: 'antigravity', status: 'pending', capabilities: ['file_read'], trust_level: 'untrusted' },
  { id: '5', name: 'custom-bot-x', type: 'custom', status: 'connected', session_id: 'sess-e5f6', capabilities: ['file_read', 'shell_exec'], trust_level: 'basic', connected_at: '2025-01-15T09:15:00Z' },
];

export default function AgentHub() {
  const [showModal, setShowModal] = useState(false);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-gray-400">Manage connected AI agents and their trust levels.</p>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> Connect Agent
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {mockAgents.map((agent) => (
          <div key={agent.id} className="bg-gray-900 rounded-xl border border-gray-800 p-5 hover:border-gray-700 transition-colors">
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-gray-800 rounded-lg">
                  <Bot className="w-5 h-5 text-blue-400" />
                </div>
                <div>
                  <h3 className="text-white font-medium">{agent.name}</h3>
                  <p className="text-xs text-gray-500">{agent.type}</p>
                </div>
              </div>
              <StatusBadge status={agent.status} />
            </div>
            <div className="space-y-2 mt-4">
              <div className="flex justify-between text-sm">
                <span className="text-gray-500">Trust Level</span>
                <StatusBadge status={agent.trust_level} />
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-500">Session</span>
                <span className="text-gray-300 font-mono text-xs">{agent.session_id || '-'}</span>
              </div>
              <div className="pt-2">
                <p className="text-xs text-gray-500 mb-1">Capabilities</p>
                <div className="flex flex-wrap gap-1">
                  {agent.capabilities.map((cap) => (
                    <span key={cap} className="px-2 py-0.5 text-xs bg-gray-800 text-gray-400 rounded">
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Connect Agent Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Connect New Agent</h3>
              <button onClick={() => setShowModal(false)} className="text-gray-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Agent Name</label>
                <input type="text" className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500" placeholder="my-agent-01" />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Agent Type</label>
                <select className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500">
                  <option value="claude-code">Claude Code</option>
                  <option value="codex">Codex</option>
                  <option value="hermes">Hermes</option>
                  <option value="antigravity">Antigravity</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Declared Task</label>
                <textarea className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500 h-20 resize-none" placeholder="Describe the task this agent will perform..." />
              </div>
              <button className="w-full py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
                Connect
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
