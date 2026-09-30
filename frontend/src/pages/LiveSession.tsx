import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Shield, Square, CheckCircle, XCircle, Terminal, MessageSquare, ArrowLeft } from 'lucide-react';
import { apiFetch, apiToken } from '../api/client';

interface OutputLine {
  stream: string;
  line: string;
  timestamp?: number;
}

interface BrokerRequest {
  request_id: string;
  session_id: string;
  run_id: string;
  agent_id: string;
  command: string;
  state: string;
  created_at: number;
}

interface RunInfo {
  run_id: string;
  session_id: string;
  agent_id: string;
  app_type: string;
  jail_dir: string;
  jail_mode: string;
  state: string;
  pid: number | null;
  exit_code: number | null;
  started_at: number;
  stopped_at: number;
  fallback: boolean;
  fallback_reason: string;
}

interface TranslatedLine {
  original: OutputLine;
  translation: string;
}

export default function LiveSession() {
  const { runId } = useParams<{ runId: string }>();
  const navigate = useNavigate();
  const [run, setRun] = useState<RunInfo | null>(null);
  const [output, setOutput] = useState<OutputLine[]>([]);
  const [translations, setTranslations] = useState<TranslatedLine[]>([]);
  const [brokerRequests, setBrokerRequests] = useState<BrokerRequest[]>([]);
  const [error, setError] = useState('');
  const termRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Fetch initial run info
  useEffect(() => {
    if (!runId) return;
    apiFetch<RunInfo>(`/launch/${runId}`)
      .then(setRun)
      .catch((e) => setError(e.message));
  }, [runId]);

  // WebSocket for live streaming
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/events?token=${encodeURIComponent(apiToken())}`);
    wsRef.current = ws;

    ws.onmessage = (evt) => {
      const event = JSON.parse(evt.data);

      if (event.event === 'launch_output' && event.run_id === runId) {
        const line: OutputLine = {
          stream: event.stream,
          line: event.line,
          timestamp: event.timestamp,
        };
        setOutput((prev) => [...prev, line]);

        // Auto-translate via template fallback
        apiFetch<{ translation: string }>('/translate', {
          method: 'POST',
          body: JSON.stringify(event),
        }).then(({ translation }) => {
          setTranslations((prev) => [...prev, { original: line, translation }]);
        }).catch(() => {});
      }

      if (event.event === 'launch_exited' && event.run_id === runId) {
        setRun((prev) =>
          prev ? { ...prev, state: 'stopped', exit_code: event.exit_code } : prev
        );
      }

      if (event.event === 'broker_request' && event.run_id === runId) {
        setBrokerRequests((prev) => [
          ...prev,
          {
            request_id: event.request_id,
            session_id: event.session_id,
            run_id: event.run_id,
            agent_id: event.agent_id,
            command: event.command,
            state: 'pending',
            created_at: event.timestamp,
          },
        ]);
      }

      if (event.event === 'broker_decision' && brokerRequests.some(r => r.request_id === event.request_id)) {
        setBrokerRequests((prev) =>
          prev.map((r) =>
            r.request_id === event.request_id
              ? { ...r, state: event.decision }
              : r
          )
        );
      }
    };

    return () => {
      ws.close();
    };
  }, [runId]);

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight;
    }
  }, [output]);

  const handleStop = async () => {
    if (!runId) return;
    try {
      const result = await apiFetch<RunInfo>(`/launch/${runId}/stop`, {
        method: 'POST',
        body: '{}',
      });
      setRun(result);
    } catch (e: any) {
      setError(e.message);
    }
  };

  const handleBrokerDecision = async (requestId: string, decision: 'approve' | 'deny') => {
    try {
      await apiFetch(`/broker/${requestId}/${decision}`, {
        method: 'POST',
        body: JSON.stringify({
          reviewer_id: 'human-operator',
          reason: decision === 'approve' ? 'Approved by operator' : 'Denied by operator',
        }),
      });
      setBrokerRequests((prev) =>
        prev.map((r) =>
          r.request_id === requestId
            ? { ...r, state: decision === 'approve' ? 'approved' : 'denied' }
            : r
        )
      );
    } catch (e: any) {
      setError(e.message);
    }
  };

  const stateColor = run?.state === 'running'
    ? 'text-green-400'
    : run?.state === 'stopped'
    ? 'text-gray-400'
    : 'text-red-400';

  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-900/80">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate('/')} className="text-gray-400 hover:text-white">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <Shield className="w-6 h-6 text-blue-400" />
          <div>
            <h1 className="text-lg font-semibold">
              {run?.app_type || 'Loading...'}{' '}
              <span className={`text-sm ${stateColor}`}>({run?.state || '...'})</span>
            </h1>
            <p className="text-xs text-gray-500">
              Run: {runId} | Session: {run?.session_id || '...'} | PID: {run?.pid || '-'} | Jail: {run?.jail_mode || '...'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {run?.state === 'running' && (
            <button
              onClick={handleStop}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 rounded-lg text-sm font-medium transition-colors"
            >
              <Square className="w-4 h-4" /> Stop
            </button>
          )}
        </div>
      </header>

      {error && (
        <div className="mx-6 mt-4 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-300 text-sm">
          {error}
        </div>
      )}

      {run?.fallback && (
        <div className="mx-6 mt-4 p-3 bg-amber-900/20 border border-amber-600/40 rounded-lg text-amber-300 text-sm">
          <span className="font-medium">Demo mode:</span>{' '}
          {run.fallback_reason || 'The real CLI is not installed — running a jailed demo agent.'}
          {' '}The jail, live streaming, and privilege broker all work exactly the same.
        </div>
      )}

      {/* Broker approval prompts */}
      {brokerRequests.filter(r => r.state === 'pending').length > 0 && (
        <div className="mx-6 mt-4 space-y-3">
          {brokerRequests.filter(r => r.state === 'pending').map((req) => (
            <div key={req.request_id} className="p-4 bg-yellow-900/20 border border-yellow-600/40 rounded-lg">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-yellow-300 font-medium text-sm">Privileged Access Requested</p>
                  <p className="text-gray-300 text-sm mt-1 font-mono">{req.command}</p>
                  <p className="text-gray-500 text-xs mt-1">Request ID: {req.request_id}</p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleBrokerDecision(req.request_id, 'approve')}
                    className="flex items-center gap-1 px-3 py-1.5 bg-green-600 hover:bg-green-500 rounded text-sm font-medium transition-colors"
                  >
                    <CheckCircle className="w-4 h-4" /> Approve
                  </button>
                  <button
                    onClick={() => handleBrokerDecision(req.request_id, 'deny')}
                    className="flex items-center gap-1 px-3 py-1.5 bg-red-600 hover:bg-red-500 rounded text-sm font-medium transition-colors"
                  >
                    <XCircle className="w-4 h-4" /> Deny
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Main content: Terminal + Translation side panel */}
      <div className="flex-1 flex gap-0 mt-4 mx-6 mb-6 overflow-hidden">
        {/* Terminal */}
        <div className="flex-1 flex flex-col border border-gray-800 rounded-l-lg bg-gray-900/50 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-800 bg-gray-900">
            <Terminal className="w-4 h-4 text-green-400" />
            <span className="text-sm text-gray-300 font-medium">Live Output</span>
            <span className="text-xs text-gray-600 ml-auto">{output.length} lines</span>
          </div>
          <div ref={termRef} className="flex-1 p-4 overflow-y-auto font-mono text-sm space-y-0.5">
            {output.length === 0 && (
              <p className="text-gray-600 italic">Waiting for output...</p>
            )}
            {output.map((line, i) => (
              <div key={i} className={line.stream === 'stderr' ? 'text-red-400' : 'text-green-300'}>
                {line.line}
              </div>
            ))}
          </div>
        </div>

        {/* Translation side panel */}
        <div className="w-80 flex flex-col border border-l-0 border-gray-800 rounded-r-lg bg-gray-900/30 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-800 bg-gray-900">
            <MessageSquare className="w-4 h-4 text-blue-400" />
            <span className="text-sm text-gray-300 font-medium">Plain Language</span>
          </div>
          <div className="flex-1 p-4 overflow-y-auto text-sm space-y-2">
            {translations.length === 0 && (
              <p className="text-gray-600 italic">Translations will appear here...</p>
            )}
            {translations.map((t, i) => (
              <div key={i} className="text-gray-300 border-l-2 border-blue-500/30 pl-3 py-1">
                {t.translation}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Broker history */}
      {brokerRequests.filter(r => r.state !== 'pending').length > 0 && (
        <div className="mx-6 mb-6">
          <h3 className="text-sm font-medium text-gray-400 mb-2">Privilege Request History</h3>
          <div className="space-y-2">
            {brokerRequests.filter(r => r.state !== 'pending').map((req) => (
              <div key={req.request_id} className="flex items-center gap-3 p-2 bg-gray-900/50 border border-gray-800 rounded text-sm">
                {req.state === 'approved' ? (
                  <CheckCircle className="w-4 h-4 text-green-400" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-400" />
                )}
                <span className="text-gray-400 font-mono text-xs flex-1">{req.command}</span>
                <span className={`text-xs ${req.state === 'approved' ? 'text-green-400' : 'text-red-400'}`}>
                  {req.state.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
