import { useState, useEffect } from 'react';
import { CheckCircle, XCircle, Clock } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import type { HITLRequest } from '../types';

const mockRequests: HITLRequest[] = [
  {
    request_id: 'req-001',
    session_id: 'sess-a1b2',
    agent_id: 'claude-code-01',
    action_type: 'file_write',
    risk_tier: 'HIGH',
    parameters: { path: '/etc/nginx/nginx.conf', content_length: 2048 },
    escalation_reason: 'Write to system configuration file detected',
    submitted_at: new Date(Date.now() - 120000).toISOString(),
    timeout_at: new Date(Date.now() + 180000).toISOString(),
  },
  {
    request_id: 'req-002',
    session_id: 'sess-c3d4',
    agent_id: 'codex-dev-02',
    action_type: 'shell_exec',
    risk_tier: 'CRITICAL',
    parameters: { command: 'sudo systemctl restart nginx' },
    escalation_reason: 'Shell execution with sudo privilege escalation',
    submitted_at: new Date(Date.now() - 60000).toISOString(),
    timeout_at: new Date(Date.now() + 240000).toISOString(),
  },
];

function TimeoutCountdown({ timeoutAt }: { timeoutAt: string }) {
  const [remaining, setRemaining] = useState('');

  useEffect(() => {
    const update = () => {
      const diff = new Date(timeoutAt).getTime() - Date.now();
      if (diff <= 0) {
        setRemaining('EXPIRED');
        return;
      }
      const mins = Math.floor(diff / 60000);
      const secs = Math.floor((diff % 60000) / 1000);
      setRemaining(`${mins}:${secs.toString().padStart(2, '0')}`);
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [timeoutAt]);

  const isUrgent = remaining !== 'EXPIRED' && parseInt(remaining) < 2;

  return (
    <div className={`flex items-center gap-1.5 text-sm font-mono ${remaining === 'EXPIRED' ? 'text-red-400' : isUrgent ? 'text-yellow-400' : 'text-gray-400'}`}>
      <Clock className="w-4 h-4" />
      {remaining}
    </div>
  );
}

export default function HITLReview() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-gray-400">Human-in-the-loop approval queue. Timeout = automatic deny.</p>
        <span className="text-sm text-yellow-400 font-medium">{mockRequests.length} pending</span>
      </div>

      <div className="space-y-4">
        {mockRequests.map((req) => (
          <div key={req.request_id} className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="flex items-center gap-3 mb-1">
                  <h3 className="text-white font-medium">{req.action_type}</h3>
                  <StatusBadge status={req.risk_tier} />
                </div>
                <p className="text-sm text-gray-500">
                  {req.agent_id} -- Session {req.session_id}
                </p>
              </div>
              <TimeoutCountdown timeoutAt={req.timeout_at} />
            </div>

            <div className="bg-gray-950 rounded-lg p-4 mb-4">
              <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">Escalation Reason</p>
              <p className="text-sm text-yellow-300">{req.escalation_reason}</p>
            </div>

            <div className="bg-gray-950 rounded-lg p-4 mb-4">
              <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">Parameters</p>
              <pre className="text-sm text-gray-300 font-mono">
                {JSON.stringify(req.parameters, null, 2)}
              </pre>
            </div>

            <div className="flex gap-3">
              <button className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium transition-colors">
                <CheckCircle className="w-4 h-4" /> Approve
              </button>
              <button className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors">
                <XCircle className="w-4 h-4" /> Deny
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
