import { useEffect, useRef, useState, useCallback } from 'react';

export interface PipelineEvent {
  event: string;
  request_id: string;
  session_id: string;
  timestamp: number;
  action_type?: string;
  agent_id?: string;
  step?: number;
  step_name?: string;
  decision?: string;
  reason?: string;
  risk_tier?: string;
  result?: string;
  latency_ms?: number;
  error?: string;
  command_hash?: string;
  snapshot_id?: string;
  intent?: string;
}

export function useWebSocket(maxEvents = 200) {
  const [events, setEvents] = useState<PipelineEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    // In dev, Vite proxies /api but not /ws — connect directly to backend
    const port = import.meta.env.DEV ? '8000' : window.location.port;
    const ws = new WebSocket(`${protocol}//${host}:${port}/ws/events`);

    ws.onopen = () => {
      setConnected(true);
    };

    ws.onmessage = (msg) => {
      try {
        const event: PipelineEvent = JSON.parse(msg.data);
        setEvents((prev) => {
          const next = [event, ...prev];
          return next.slice(0, maxEvents);
        });
      } catch { /* ignore malformed */ }
    };

    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;
      reconnectTimer.current = setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };

    wsRef.current = ws;
  }, [maxEvents]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, connected, clearEvents };
}
