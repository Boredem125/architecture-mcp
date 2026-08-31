import { useState } from 'react';
import { Plus, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import type { JITAccessGrant, RBACRole } from '../types';

const tabs = ['JIT Access', 'JEA', 'RBAC', 'Conditional Access', 'Zero Trust'] as const;

const mockJIT: JITAccessGrant[] = [
  { id: '1', agent_id: 'codex-dev-02', elevated_actions: ['shell_exec', 'file_write'], granted_at: '2025-01-15T10:00:00Z', expires_at: '2025-01-15T10:30:00Z', reason: 'Deploy hotfix to production', approved_by: 'admin@sandbox', active: true },
  { id: '2', agent_id: 'claude-code-01', elevated_actions: ['network_access'], granted_at: '2025-01-15T09:00:00Z', expires_at: '2025-01-15T09:15:00Z', reason: 'Fetch remote config', approved_by: 'admin@sandbox', active: false },
];

const mockRoles: RBACRole[] = [
  { id: '1', name: 'reader', permissions: ['file_read'], max_risk_tier: 'LOW', requires_mfa: false },
  { id: '2', name: 'developer', permissions: ['file_read', 'file_write', 'shell_exec'], max_risk_tier: 'HIGH', requires_mfa: true },
  { id: '3', name: 'admin', permissions: ['file_read', 'file_write', 'shell_exec', 'network_access', 'config_modify'], max_risk_tier: 'CRITICAL', requires_mfa: true },
];

const zeroTrustChecks = [
  { name: 'Verify explicitly', description: 'All requests authenticated and authorized', status: 'pass' },
  { name: 'Least privilege access', description: 'JIT/JEA enforced for elevated actions', status: 'pass' },
  { name: 'Assume breach', description: 'Session isolation, blast radius minimization', status: 'pass' },
  { name: 'Micro-segmentation', description: 'Zone-based network/action boundaries', status: 'pass' },
  { name: 'Continuous verification', description: 'Re-evaluate trust on every request', status: 'warning' },
  { name: 'Encrypted channels', description: 'All inter-zone communication encrypted', status: 'pass' },
  { name: 'Immutable audit log', description: 'Append-only with chain hashing', status: 'pass' },
  { name: 'Session time-boxing', description: 'Automatic expiry on all sessions', status: 'pass' },
];

const statusIcon: Record<string, React.ReactNode> = {
  pass: <CheckCircle className="w-5 h-5 text-green-400" />,
  warning: <AlertTriangle className="w-5 h-5 text-yellow-400" />,
  fail: <XCircle className="w-5 h-5 text-red-400" />,
};

export default function SecurityCenter() {
  const [activeTab, setActiveTab] = useState<(typeof tabs)[number]>('JIT Access');

  return (
    <div className="space-y-6">
      {/* Tabs */}
      <div className="flex border-b border-gray-800">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* JIT Access */}
      {activeTab === 'JIT Access' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-gray-400">Just-In-Time access grants with automatic expiry.</p>
            <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
              <Plus className="w-4 h-4" /> Grant JIT Access
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4">Agent</th>
                  <th className="pb-3 pr-4">Actions</th>
                  <th className="pb-3 pr-4">Reason</th>
                  <th className="pb-3 pr-4">Granted</th>
                  <th className="pb-3 pr-4">Expires</th>
                  <th className="pb-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {mockJIT.map((grant) => (
                  <tr key={grant.id} className="border-b border-gray-800/50">
                    <td className="py-3 pr-4 text-white">{grant.agent_id}</td>
                    <td className="py-3 pr-4">
                      <div className="flex flex-wrap gap-1">
                        {grant.elevated_actions.map((a) => (
                          <span key={a} className="px-2 py-0.5 text-xs bg-purple-500/20 text-purple-400 rounded">{a}</span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 pr-4 text-gray-400">{grant.reason}</td>
                    <td className="py-3 pr-4 text-gray-400 text-xs font-mono">{new Date(grant.granted_at).toLocaleTimeString()}</td>
                    <td className="py-3 pr-4 text-gray-400 text-xs font-mono">{new Date(grant.expires_at).toLocaleTimeString()}</td>
                    <td className="py-3">
                      <StatusBadge status={grant.active ? 'active' : 'disconnected'} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* JEA */}
      {activeTab === 'JEA' && (
        <div className="space-y-4">
          <p className="text-gray-400">Just Enough Administration -- minimum permissions for each role.</p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {mockRoles.map((role) => (
              <div key={role.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <h3 className="text-white font-semibold text-lg mb-1 capitalize">{role.name}</h3>
                <p className="text-xs text-gray-500 mb-3">Max risk: <StatusBadge status={role.max_risk_tier} /></p>
                <p className="text-xs text-gray-500 mb-2">Permissions:</p>
                <div className="flex flex-wrap gap-1">
                  {role.permissions.map((p) => (
                    <span key={p} className="px-2 py-0.5 text-xs bg-gray-800 text-gray-400 rounded">{p}</span>
                  ))}
                </div>
                {role.requires_mfa && (
                  <p className="text-xs text-yellow-400 mt-3">Requires MFA</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* RBAC */}
      {activeTab === 'RBAC' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-gray-400">Role-Based Access Control management.</p>
            <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
              <Plus className="w-4 h-4" /> Add Role
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4">Role</th>
                  <th className="pb-3 pr-4">Permissions</th>
                  <th className="pb-3 pr-4">Max Risk Tier</th>
                  <th className="pb-3">MFA Required</th>
                </tr>
              </thead>
              <tbody>
                {mockRoles.map((role) => (
                  <tr key={role.id} className="border-b border-gray-800/50">
                    <td className="py-3 pr-4 text-white font-medium capitalize">{role.name}</td>
                    <td className="py-3 pr-4">
                      <div className="flex flex-wrap gap-1">
                        {role.permissions.map((p) => (
                          <span key={p} className="px-2 py-0.5 text-xs bg-gray-800 text-gray-400 rounded">{p}</span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 pr-4"><StatusBadge status={role.max_risk_tier} /></td>
                    <td className="py-3">{role.requires_mfa ? <CheckCircle className="w-4 h-4 text-green-400" /> : <span className="text-gray-600">--</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Conditional Access */}
      {activeTab === 'Conditional Access' && (
        <div className="space-y-4">
          <p className="text-gray-400">Risk-based conditional access policies.</p>
          <div className="space-y-3">
            {[
              { rule: 'If risk_tier == CRITICAL, require HITL approval', enabled: true },
              { rule: 'If agent trust_level == untrusted, deny shell_exec', enabled: true },
              { rule: 'If session.deny_count > 5, kill session', enabled: true },
              { rule: 'If time outside business hours, elevate all risk tiers by 1', enabled: false },
              { rule: 'If agent connected < 1h, restrict to file_read only', enabled: true },
            ].map((policy, i) => (
              <div key={i} className="flex items-center justify-between bg-gray-900 border border-gray-800 rounded-lg p-4">
                <span className={`text-sm ${policy.enabled ? 'text-gray-300' : 'text-gray-600'}`}>{policy.rule}</span>
                <span className={`text-xs font-medium ${policy.enabled ? 'text-green-400' : 'text-gray-600'}`}>
                  {policy.enabled ? 'ENABLED' : 'DISABLED'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Zero Trust */}
      {activeTab === 'Zero Trust' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-gray-400">Zero Trust Architecture compliance scorecard.</p>
            <div className="text-right">
              <p className="text-3xl font-bold text-green-400">
                {Math.round((zeroTrustChecks.filter((c) => c.status === 'pass').length / zeroTrustChecks.length) * 100)}%
              </p>
              <p className="text-xs text-gray-500">Compliance Score</p>
            </div>
          </div>
          <div className="space-y-2">
            {zeroTrustChecks.map((check, i) => (
              <div key={i} className="flex items-center gap-4 bg-gray-900 border border-gray-800 rounded-lg p-4">
                {statusIcon[check.status]}
                <div>
                  <p className="text-white text-sm font-medium">{check.name}</p>
                  <p className="text-xs text-gray-500">{check.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
