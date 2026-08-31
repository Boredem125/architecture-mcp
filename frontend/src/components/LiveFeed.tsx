import { useWebSocket, type PipelineEvent } from '../hooks/useWebSocket';

const EVENT_COLORS: Record<string, string> = {
  pipeline_start: 'bg-blue-500',
  step_completed: 'bg-green-500',
  step_failed: 'bg-red-500',
  pipeline_completed: 'bg-emerald-500',
  pipeline_error: 'bg-red-600',
  hitl_required: 'bg-amber-500',
};

const STEP_LABELS: Record<string, string> = {
  session_validation: 'Session Validation',
  token_validation: 'Token Validation',
  request_evaluator: 'Request Evaluator',
  policy_engine: 'Policy Engine',
  content_safety: 'Content Safety',
  hitl_gate: 'HITL Gate',
  command_signing: 'Command Signing',
  rollback_snapshot: 'Rollback Snapshot',
  execution: 'Execution',
  audit_write: 'Audit Write',
};

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function EventCard({ event }: { event: PipelineEvent }) {
  const dotColor = EVENT_COLORS[event.event] || 'bg-gray-500';
  const stepLabel = event.step_name ? (STEP_LABELS[event.step_name] || event.step_name) : '';

  return (
    <div className="flex items-start gap-3 px-4 py-3 border-b border-gray-700/50 hover:bg-gray-800/50 transition-colors">
      <div className="flex flex-col items-center mt-1">
        <span className={`w-2.5 h-2.5 rounded-full ${dotColor} animate-pulse`} />
        <span className="w-px h-full bg-gray-700 mt-1" />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 text-sm">
          <span className="font-mono text-gray-400">{formatTime(event.timestamp)}</span>
          <span className="font-semibold text-gray-200">{event.event.replace(/_/g, ' ')}</span>
          {event.agent_id && (
            <span className="px-1.5 py-0.5 bg-indigo-900/50 text-indigo-300 text-xs rounded font-mono">{event.agent_id}</span>
          )}
        </div>

        <div className="flex flex-wrap gap-2 mt-1">
          {stepLabel && (
            <span className="text-xs text-gray-400">
              Step {event.step}: {stepLabel}
            </span>
          )}
          {event.action_type && (
            <span className="px-1.5 py-0.5 bg-cyan-900/40 text-cyan-300 text-xs rounded">{event.action_type}</span>
          )}
          {event.risk_tier && (
            <span className={`px-1.5 py-0.5 text-xs rounded ${
              event.risk_tier === 'CRITICAL' ? 'bg-red-900/50 text-red-300' :
              event.risk_tier === 'HIGH' ? 'bg-orange-900/50 text-orange-300' :
              event.risk_tier === 'MEDIUM' ? 'bg-yellow-900/50 text-yellow-300' :
              'bg-green-900/50 text-green-300'
            }`}>{event.risk_tier}</span>
          )}
          {event.decision && (
            <span className={`px-1.5 py-0.5 text-xs rounded font-semibold ${
              event.decision === 'ALLOW' ? 'bg-green-900/50 text-green-300' :
              event.decision === 'DENY' ? 'bg-red-900/50 text-red-300' :
              'bg-yellow-900/50 text-yellow-300'
            }`}>{event.decision}</span>
          )}
          {event.result && (
            <span className="px-1.5 py-0.5 bg-gray-700 text-gray-300 text-xs rounded">{event.result}</span>
          )}
          {event.latency_ms !== undefined && (
            <span className="text-xs text-gray-500">{event.latency_ms}ms</span>
          )}
        </div>

        {event.reason && (
          <p className="text-xs text-gray-500 mt-1 truncate">{event.reason}</p>
        )}
        {event.error && (
          <p className="text-xs text-red-400 mt-1 truncate">{event.error}</p>
        )}

        <p className="text-[10px] text-gray-600 mt-1 font-mono">{event.request_id?.slice(0, 8)}... / {event.session_id?.slice(0, 8)}...</p>
      </div>
    </div>
  );
}

export default function LiveFeed() {
  const { events, connected, clearEvents } = useWebSocket();

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold text-gray-100">Live Pipeline Feed</h2>
          <span className={`flex items-center gap-1.5 text-xs ${connected ? 'text-green-400' : 'text-red-400'}`}>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500">{events.length} events</span>
          <button
            onClick={clearEvents}
            className="px-2 py-1 text-xs text-gray-400 hover:text-gray-200 bg-gray-800 rounded hover:bg-gray-700 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Event stream */}
      <div className="flex-1 overflow-y-auto">
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-gray-500">
            <div className="w-8 h-8 border-2 border-gray-600 border-t-blue-500 rounded-full animate-spin mb-3" />
            <p className="text-sm">Waiting for pipeline events...</p>
            <p className="text-xs mt-1">Submit a request through the API to see live events</p>
          </div>
        ) : (
          events.map((event, i) => (
            <EventCard key={`${event.request_id}-${event.event}-${i}`} event={event} />
          ))
        )}
      </div>
    </div>
  );
}
