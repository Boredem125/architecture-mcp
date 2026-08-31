export interface Session {
  session_id: string;
  agent_id: string;
  is_active: boolean;
  is_killed: boolean;
  total_requests: number;
  deny_count: number;
  hitl_count: number;
  write_count: number;
  started_at: string;
  expires_at: string;
  declared_task: string;
}

export interface PipelineStatus {
  request_id: string;
  session_id: string;
  status: 'PROCESSING' | 'COMPLETED' | 'DENIED' | 'HALTED';
  current_step: number;
  step_name: string;
  decision: string;
  reason: string;
  total_latency_ms: number;
}

export interface AgentConnection {
  id: string;
  name: string;
  type: 'claude-code' | 'codex' | 'hermes' | 'antigravity' | 'custom';
  status: 'connected' | 'disconnected' | 'pending';
  session_id?: string;
  capabilities: string[];
  trust_level: 'untrusted' | 'basic' | 'elevated';
  connected_at?: string;
}

export interface PolicyFile {
  id: string;
  name: string;
  content: string;
  uploaded_at: string;
  active: boolean;
  version: number;
}

export interface HITLRequest {
  request_id: string;
  session_id: string;
  agent_id: string;
  action_type: string;
  risk_tier: string;
  parameters: Record<string, any>;
  escalation_reason: string;
  submitted_at: string;
  timeout_at: string;
}

export interface AuditRecord {
  session_id: string;
  agent_id: string;
  action_type: string;
  risk_tier: string;
  policy_decision: string;
  execution_result: string;
  timestamp: string;
  chain_hash: string;
}

export type JITAccessGrant = {
  id: string;
  agent_id: string;
  elevated_actions: string[];
  granted_at: string;
  expires_at: string;
  reason: string;
  approved_by: string;
  active: boolean;
};

export type RBACRole = {
  id: string;
  name: string;
  permissions: string[];
  max_risk_tier: string;
  requires_mfa: boolean;
};
