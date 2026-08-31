import { useState } from 'react';
import { Download, ShieldCheck, Filter } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import type { AuditRecord } from '../types';

const mockRecords: AuditRecord[] = [
  { session_id: 'sess-a1b2', agent_id: 'claude-code-01', action_type: 'file_read', risk_tier: 'LOW', policy_decision: 'ALLOW', execution_result: 'SUCCESS', timestamp: '2025-01-15T10:35:00Z', chain_hash: 'a1b2c3d4e5f6' },
  { session_id: 'sess-a1b2', agent_id: 'claude-code-01', action_type: 'file_write', risk_tier: 'HIGH', policy_decision: 'ESCALATE', execution_result: 'PENDING_HITL', timestamp: '2025-01-15T10:36:00Z', chain_hash: 'f6e5d4c3b2a1' },
  { session_id: 'sess-c3d4', agent_id: 'codex-dev-02', action_type: 'shell_exec', risk_tier: 'CRITICAL', policy_decision: 'DENY', execution_result: 'BLOCKED', timestamp: '2025-01-15T10:37:00Z', chain_hash: '1a2b3c4d5e6f' },
  { session_id: 'sess-c3d4', agent_id: 'codex-dev-02', action_type: 'file_read', risk_tier: 'LOW', policy_decision: 'ALLOW', execution_result: 'SUCCESS', timestamp: '2025-01-15T10:38:00Z', chain_hash: '6f5e4d3c2b1a' },
  { session_id: 'sess-e5f6', agent_id: 'custom-bot-x', action_type: 'network_access', risk_tier: 'MEDIUM', policy_decision: 'ALLOW', execution_result: 'SUCCESS', timestamp: '2025-01-15T10:39:00Z', chain_hash: 'ab12cd34ef56' },
];

const decisionColor: Record<string, string> = {
  ALLOW: 'text-green-400',
  DENY: 'text-red-400',
  ESCALATE: 'text-yellow-400',
};

const resultColor: Record<string, string> = {
  SUCCESS: 'text-green-400',
  BLOCKED: 'text-red-400',
  PENDING_HITL: 'text-yellow-400',
};

export default function AuditLog() {
  const [sessionFilter, setSessionFilter] = useState('all');

  const filtered = sessionFilter === 'all'
    ? mockRecords
    : mockRecords.filter((r) => r.session_id === sessionFilter);

  const sessions = [...new Set(mockRecords.map((r) => r.session_id))];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-gray-400">Append-only audit log with cryptographic chain verification.</p>
        <div className="flex gap-3">
          <button className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm transition-colors">
            <ShieldCheck className="w-4 h-4" /> Verify Chain
          </button>
          <button className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm transition-colors">
            <Download className="w-4 h-4" /> Export
          </button>
        </div>
      </div>

      {/* Session Filter */}
      <div className="flex items-center gap-3">
        <Filter className="w-4 h-4 text-gray-500" />
        <select
          value={sessionFilter}
          onChange={(e) => setSessionFilter(e.target.value)}
          className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Sessions</option>
          {sessions.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {/* Log Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b border-gray-800">
              <th className="pb-3 pr-4">Timestamp</th>
              <th className="pb-3 pr-4">Session</th>
              <th className="pb-3 pr-4">Agent</th>
              <th className="pb-3 pr-4">Action</th>
              <th className="pb-3 pr-4">Risk</th>
              <th className="pb-3 pr-4">Decision</th>
              <th className="pb-3 pr-4">Result</th>
              <th className="pb-3">Chain Hash</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                <td className="py-3 pr-4 text-gray-400 font-mono text-xs">
                  {new Date(r.timestamp).toLocaleTimeString()}
                </td>
                <td className="py-3 pr-4 text-gray-300 font-mono text-xs">{r.session_id}</td>
                <td className="py-3 pr-4 text-gray-300">{r.agent_id}</td>
                <td className="py-3 pr-4 text-white">{r.action_type}</td>
                <td className="py-3 pr-4"><StatusBadge status={r.risk_tier} /></td>
                <td className={`py-3 pr-4 font-medium ${decisionColor[r.policy_decision] || 'text-gray-400'}`}>
                  {r.policy_decision}
                </td>
                <td className={`py-3 pr-4 ${resultColor[r.execution_result] || 'text-gray-400'}`}>
                  {r.execution_result}
                </td>
                <td className="py-3 text-gray-500 font-mono text-xs">{r.chain_hash}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
