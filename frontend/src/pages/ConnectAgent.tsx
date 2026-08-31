import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ArrowRight, Upload, ChevronRight, Check, AlertTriangle, Terminal, Copy } from 'lucide-react';
import { apiFetch } from '../api/client';

interface AgentOption {
  id: string;
  name: string;
  type: string;
  icon: string;
  description: string;
  capabilities: string[];
  color: string;
  borderColor: string;
  integration: 'hook' | 'sdk';
  integrationLabel: string;
}

const AGENTS: AgentOption[] = [
  {
    id: 'claude-code',
    name: 'Claude Code',
    type: 'claude-code',
    icon: 'C',
    description: 'Intercepts this running Claude Code instance via hooks. Every tool call (Read, Write, Bash) goes through the pipeline. No API key needed.',
    capabilities: ['READ', 'WRITE', 'EXECUTE'],
    color: 'from-orange-500/20 to-orange-600/5',
    borderColor: 'border-orange-500/30 hover:border-orange-400/60',
    integration: 'hook',
    integrationLabel: 'Hook Integration',
  },
  {
    id: 'codex',
    name: 'OpenAI Codex',
    type: 'codex',
    icon: 'O',
    description: 'Spawns a Codex agent via OpenAI SDK. Every tool call is sandboxed. Requires OpenAI API key.',
    capabilities: ['READ', 'WRITE'],
    color: 'from-green-500/20 to-green-600/5',
    borderColor: 'border-green-500/30 hover:border-green-400/60',
    integration: 'sdk',
    integrationLabel: 'SDK Spawn',
  },
  {
    id: 'antigravity',
    name: 'Antigravity',
    type: 'antigravity',
    icon: 'A',
    description: 'Spawns an autonomous dev agent with full-stack capabilities. Requires API key.',
    capabilities: ['READ', 'WRITE', 'EXECUTE', 'NETWORK'],
    color: 'from-purple-500/20 to-purple-600/5',
    borderColor: 'border-purple-500/30 hover:border-purple-400/60',
    integration: 'sdk',
    integrationLabel: 'SDK Spawn',
  },
  {
    id: 'hermes',
    name: 'Hermes',
    type: 'hermes',
    icon: 'H',
    description: 'Lightweight task agent for file operations. Minimal privilege surface. Requires API key.',
    capabilities: ['READ'],
    color: 'from-cyan-500/20 to-cyan-600/5',
    borderColor: 'border-cyan-500/30 hover:border-cyan-400/60',
    integration: 'sdk',
    integrationLabel: 'SDK Spawn',
  },
  {
    id: 'ollama',
    name: 'Ollama',
    type: 'ollama',
    icon: 'O',
    description: 'Run local LLMs via Ollama. No API key — runs entirely on your machine.',
    capabilities: ['READ', 'WRITE', 'EXECUTE'],
    color: 'from-white/10 to-gray-600/5',
    borderColor: 'border-gray-400/30 hover:border-gray-300/60',
    integration: 'sdk',
    integrationLabel: 'Local CLI',
  },
  {
    id: 'openclaw',
    name: 'OpenClaw',
    type: 'openclaw',
    icon: 'W',
    description: 'OpenClaw autonomous agent. Launch the real CLI in a jailed sandbox.',
    capabilities: ['READ', 'WRITE', 'EXECUTE'],
    color: 'from-rose-500/20 to-rose-600/5',
    borderColor: 'border-rose-500/30 hover:border-rose-400/60',
    integration: 'sdk',
    integrationLabel: 'Local CLI',
  },
  {
    id: 'custom',
    name: 'Custom Agent',
    type: 'custom',
    icon: '+',
    description: 'Connect any CLI agent. Define capabilities, trust level, and policies manually.',
    capabilities: ['READ'],
    color: 'from-gray-500/20 to-gray-600/5',
    borderColor: 'border-gray-500/30 hover:border-gray-400/60',
    integration: 'sdk',
    integrationLabel: 'Custom CLI',
  },
];

type Step = 'select' | 'configure' | 'policy' | 'connecting' | 'ready';

interface HookResult {
  sessionId: string;
  agentId: string;
  hookScript: string;
  hooksConfig: object;
  installInstructions: string[];
  autoInstalled: boolean;
  hookScriptPath?: string;
  settingsPath?: string;
}

interface SdkResult {
  runId: string;
  agentId: string;
  sessionId: string;
  status: string;
}

export default function ConnectAgent() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>('select');
  const [selectedAgent, setSelectedAgent] = useState<AgentOption | null>(null);
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [workspaceRoot, setWorkspaceRoot] = useState('');
  const [maxWrites, setMaxWrites] = useState(100);
  const [ttlMinutes, setTtlMinutes] = useState(60);
  const [policyContent, setPolicyContent] = useState('');
  const [policyName, setPolicyName] = useState('');
  // SDK-only fields
  const [apiKey, setApiKey] = useState('');
  const [selectedModel, setSelectedModel] = useState('');
  const [taskDescription, setTaskDescription] = useState('');
  // Results
  const [hookResult, setHookResult] = useState<HookResult | null>(null);
  const [sdkResult, setSdkResult] = useState<SdkResult | null>(null);
  const [error, setError] = useState('');
  const [currentSetupStep, setCurrentSetupStep] = useState(0);
  const [copied, setCopied] = useState(false);

  const handleSelectAgent = (agent: AgentOption) => {
    setSelectedAgent(agent);
    setCapabilities([...agent.capabilities]);
    setError('');
    setStep('configure');
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setPolicyName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      setPolicyContent(ev.target?.result as string || '');
    };
    reader.readAsText(file);
  };

  const toggleCapability = (cap: string) => {
    setCapabilities((prev) =>
      prev.includes(cap) ? prev.filter((c) => c !== cap) : [...prev, cap]
    );
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // --- HOOK CONNECT (Claude Code) ---
  const handleHookConnect = async () => {
    if (!selectedAgent) return;
    setStep('connecting');
    setError('');
    setCurrentSetupStep(0);

    try {
      setCurrentSetupStep(1);
      if (policyContent) {
        await apiFetch('/policies/upload', {
          method: 'POST',
          body: JSON.stringify({
            name: policyName || `${selectedAgent.type}-policy`,
            content: policyContent,
            category: 'agent-specific',
          }),
        });
      }
      await delay(300);

      setCurrentSetupStep(2);
      const result = await apiFetch<{
        session_id: string;
        agent_id: string;
        hook_script: string;
        hooks_config: object;
        install_instructions: string[];
      }>('/hook/connect', {
        method: 'POST',
        body: JSON.stringify({
          agent_name: 'claude-code',
          workspace_root: workspaceRoot || undefined,
          capabilities,
          max_writes: maxWrites,
          ttl_seconds: ttlMinutes * 60,
        }),
      });
      await delay(400);

      setCurrentSetupStep(3);
      await delay(300);

      setHookResult({
        sessionId: result.session_id,
        agentId: result.agent_id,
        hookScript: result.hook_script,
        hooksConfig: result.hooks_config,
        installInstructions: result.install_instructions,
        autoInstalled: result.auto_installed,
        hookScriptPath: result.hook_script_path,
        settingsPath: result.settings_path,
      });
      setCurrentSetupStep(4);
      setStep('ready');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed');
      setStep('configure');
    }
  };

  // --- SDK CONNECT (Codex, Hermes, etc.) ---
  const handleSdkConnect = async () => {
    if (!selectedAgent || !taskDescription) return;
    setStep('connecting');
    setError('');
    setCurrentSetupStep(0);

    try {
      setCurrentSetupStep(1);
      if (policyContent) {
        await apiFetch('/policies/upload', {
          method: 'POST',
          body: JSON.stringify({
            name: policyName || `${selectedAgent.type}-policy`,
            content: policyContent,
            category: 'agent-specific',
          }),
        });
      }
      await delay(300);

      setCurrentSetupStep(2);
      const run = await apiFetch<{
        run_id: string;
        agent_id: string;
        session_id: string;
        status: string;
        error: string | null;
      }>('/runtime/spawn', {
        method: 'POST',
        body: JSON.stringify({
          agent_type: selectedAgent.type,
          task: taskDescription,
          capabilities,
          workspace_root: workspaceRoot || '/tmp/workspace',
          max_writes: maxWrites,
          ttl_seconds: ttlMinutes * 60,
          api_key: apiKey || undefined,
          model: selectedModel || undefined,
        }),
      });

      if (run.error) {
        setError(run.error);
        setStep('configure');
        return;
      }

      await delay(300);
      setCurrentSetupStep(3);
      await delay(200);

      setSdkResult({
        runId: run.run_id,
        agentId: run.agent_id,
        sessionId: run.session_id,
        status: run.status,
      });
      setCurrentSetupStep(4);
      setStep('ready');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed');
      setStep('configure');
    }
  };

  // --- LAUNCH AS REAL APP (jailed CLI) ---
  const handleLaunchReal = async () => {
    if (!selectedAgent) return;
    setStep('connecting');
    setError('');
    setCurrentSetupStep(0);

    try {
      setCurrentSetupStep(1);
      await delay(300);
      setCurrentSetupStep(2);

      const run = await apiFetch<{
        run_id: string;
        session_id: string;
        agent_id: string;
        state: string;
        jail_mode: string;
      }>('/launch', {
        method: 'POST',
        body: JSON.stringify({
          app_type: selectedAgent.type,
          task_description: taskDescription,
          extra_args: [],
        }),
      });

      setCurrentSetupStep(3);
      await delay(200);
      setCurrentSetupStep(4);

      // Navigate to live session
      navigate(`/live/${run.run_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Launch failed');
      setStep('configure');
    }
  };

  const handleConnect = () => {
    if (selectedAgent?.integration === 'hook') {
      handleHookConnect();
    } else {
      handleSdkConnect();
    }
  };

  const isHook = selectedAgent?.integration === 'hook';
  const allCapabilities = ['READ', 'WRITE', 'EXECUTE', 'NETWORK', 'SECRET_ACCESS'];
  const connectDisabled = isHook ? false : !taskDescription;

  // --- STEP: Select Agent ---
  if (step === 'select') {
    return (
      <div className="min-h-screen bg-gray-950 flex flex-col items-center justify-center p-8">
        <div className="max-w-5xl w-full">
          <div className="text-center mb-12">
            <div className="flex items-center justify-center gap-3 mb-4">
              <Shield className="w-10 h-10 text-blue-500" />
              <h1 className="text-4xl font-bold text-white">AI Agent Sandbox</h1>
            </div>
            <p className="text-lg text-gray-400 max-w-2xl mx-auto">
              Connect an AI agent to operate inside a secure, policy-enforced sandbox.
              Every action is mediated through an 8-step security pipeline.
            </p>
          </div>

          <h2 className="text-xl font-semibold text-gray-200 mb-6">Connect to...</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {AGENTS.map((agent) => (
              <button
                key={agent.id}
                onClick={() => handleSelectAgent(agent)}
                className={`text-left p-6 rounded-xl border bg-gradient-to-br ${agent.color} ${agent.borderColor} transition-all duration-200 group`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="w-12 h-12 rounded-lg bg-gray-800/80 flex items-center justify-center text-xl font-bold text-white">
                    {agent.icon}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 text-[10px] rounded ${
                      agent.integration === 'hook'
                        ? 'bg-green-900/50 text-green-300 border border-green-800'
                        : 'bg-blue-900/50 text-blue-300 border border-blue-800'
                    }`}>
                      {agent.integration === 'hook' ? 'No API key' : 'API key'}
                    </span>
                    <ArrowRight className="w-5 h-5 text-gray-600 group-hover:text-gray-300 transition-colors" />
                  </div>
                </div>
                <h3 className="text-lg font-semibold text-white mb-1">{agent.name}</h3>
                <p className="text-sm text-gray-400 mb-3">{agent.description}</p>
                <div className="flex flex-wrap gap-1">
                  {agent.capabilities.map((cap) => (
                    <span key={cap} className="px-2 py-0.5 text-xs bg-gray-800/60 text-gray-300 rounded">
                      {cap}
                    </span>
                  ))}
                </div>
              </button>
            ))}
          </div>

          <p className="text-center text-xs text-gray-600 mt-8">
            All agents operate under deny-by-default policy. Zero trust. Every action audited.
          </p>
        </div>
      </div>
    );
  }

  // --- STEP: Configure ---
  if (step === 'configure' || step === 'policy') {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center p-8">
        <div className="max-w-2xl w-full">
          <button
            onClick={() => setStep('select')}
            className="text-sm text-gray-500 hover:text-gray-300 mb-6 flex items-center gap-1"
          >
            &larr; Back to agent selection
          </button>

          <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
            {/* Header */}
            <div className={`p-6 bg-gradient-to-r ${selectedAgent?.color}`}>
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-lg bg-gray-800 flex items-center justify-center text-2xl font-bold text-white">
                  {selectedAgent?.icon}
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-white">{selectedAgent?.name}</h2>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={`px-2 py-0.5 text-xs rounded ${
                      isHook
                        ? 'bg-green-900/50 text-green-300'
                        : 'bg-blue-900/50 text-blue-300'
                    }`}>
                      {selectedAgent?.integrationLabel}
                    </span>
                    <span className="text-sm text-gray-400">
                      {isHook ? 'Intercepts this Claude Code via hooks' : 'Spawns agent via SDK'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-gray-800">
              <button
                onClick={() => setStep('configure')}
                className={`flex-1 py-3 text-sm font-medium text-center transition-colors ${
                  step === 'configure' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                1. Sandbox Config
              </button>
              <button
                onClick={() => setStep('policy')}
                className={`flex-1 py-3 text-sm font-medium text-center transition-colors ${
                  step === 'policy' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                2. Security Policy
              </button>
            </div>

            <div className="p-6 space-y-5">
              {step === 'configure' ? (
                <>
                  {error && (
                    <div className="flex items-center gap-2 p-3 bg-red-900/30 border border-red-800 rounded-lg text-sm text-red-300">
                      <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                      {error}
                    </div>
                  )}

                  {isHook && (
                    <div className="flex items-start gap-3 p-3 bg-green-900/20 border border-green-800/50 rounded-lg">
                      <Terminal className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                      <div>
                        <p className="text-sm text-green-300 font-medium">Hook Integration</p>
                        <p className="text-xs text-gray-400 mt-1">
                          Intercepts the running Claude Code instance. Every tool call (Read, Write, Edit, Bash, Grep)
                          routes through the 8-step pipeline before execution. No API key needed.
                        </p>
                      </div>
                    </div>
                  )}

                  {!isHook && (
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">What will this agent do?</label>
                      <textarea
                        value={taskDescription}
                        onChange={(e) => setTaskDescription(e.target.value)}
                        className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500 h-24 resize-none"
                        placeholder="Describe the task... e.g., 'Read and analyze project source files, write a summary report'"
                      />
                      <p className="text-xs text-gray-500 mt-1">This is logged in the audit trail and visible to HITL reviewers.</p>
                    </div>
                  )}

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Allowed Actions (JEA)</label>
                    <div className="flex flex-wrap gap-2">
                      {allCapabilities.map((cap) => (
                        <button
                          key={cap}
                          onClick={() => toggleCapability(cap)}
                          className={`px-3 py-1.5 text-sm rounded-lg border transition-colors ${
                            capabilities.includes(cap)
                              ? cap === 'SECRET_ACCESS' || cap === 'EXECUTE'
                                ? 'bg-red-900/30 border-red-700 text-red-300'
                                : 'bg-blue-900/30 border-blue-700 text-blue-300'
                              : 'bg-gray-800 border-gray-700 text-gray-500 hover:text-gray-300'
                          }`}
                        >
                          {capabilities.includes(cap) && <span className="mr-1">&#10003;</span>}
                          {cap}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">Workspace Root</label>
                      <input
                        type="text"
                        value={workspaceRoot}
                        onChange={(e) => setWorkspaceRoot(e.target.value)}
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                        placeholder={isHook ? 'Auto-detect (cwd)' : '/tmp/workspace'}
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">Max Writes</label>
                      <input
                        type="number"
                        value={maxWrites}
                        onChange={(e) => setMaxWrites(parseInt(e.target.value) || 0)}
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Session TTL (JIT)</label>
                    <div className="flex items-center gap-3">
                      <input
                        type="range"
                        min={5}
                        max={120}
                        value={ttlMinutes}
                        onChange={(e) => setTtlMinutes(parseInt(e.target.value))}
                        className="flex-1"
                      />
                      <span className="text-sm text-gray-300 w-20 text-right">{ttlMinutes} min</span>
                    </div>
                  </div>

                  {!isHook && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                          API Key {selectedAgent?.type === 'codex' ? '(OpenAI)' : '(Anthropic)'}
                        </label>
                        <input
                          type="password"
                          value={apiKey}
                          onChange={(e) => setApiKey(e.target.value)}
                          className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                          placeholder="sk-... (or set env var on server)"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">Model (optional)</label>
                        <input
                          type="text"
                          value={selectedModel}
                          onChange={(e) => setSelectedModel(e.target.value)}
                          className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                          placeholder={selectedAgent?.type === 'codex' ? 'gpt-4o' : 'claude-sonnet-4-20250514'}
                        />
                      </div>
                    </>
                  )}

                  <div className="flex gap-3 pt-2">
                    <button
                      onClick={() => setStep('policy')}
                      className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
                    >
                      Upload Policy <ChevronRight className="w-4 h-4" />
                    </button>
                    <button
                      onClick={handleConnect}
                      disabled={connectDisabled}
                      className="flex-1 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
                    >
                      {isHook ? 'Activate Sandbox' : 'Spawn Agent'} <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                  <button
                    onClick={handleLaunchReal}
                    className="w-full mt-2 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
                  >
                    <Terminal className="w-4 h-4" /> Launch as Real App (Jailed)
                  </button>
                </>
              ) : (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Upload Security Policy (.rego)</label>
                    <div className="border-2 border-dashed border-gray-700 rounded-lg p-8 text-center hover:border-gray-500 transition-colors">
                      <Upload className="w-8 h-8 text-gray-500 mx-auto mb-3" />
                      <p className="text-sm text-gray-400 mb-2">
                        {policyName ? policyName : 'Drop a .rego file here or click to browse'}
                      </p>
                      <input
                        type="file"
                        accept=".rego,.json,.yaml,.yml"
                        onChange={handleFileUpload}
                        className="hidden"
                        id="policy-upload"
                      />
                      <label
                        htmlFor="policy-upload"
                        className="inline-block px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm cursor-pointer transition-colors"
                      >
                        Browse Files
                      </label>
                    </div>
                    {policyContent && (
                      <div className="mt-3 p-3 bg-gray-800 rounded-lg">
                        <p className="text-xs text-green-400 mb-2">Policy loaded: {policyName}</p>
                        <pre className="text-xs text-gray-400 overflow-auto max-h-40 font-mono">{policyContent.slice(0, 500)}</pre>
                      </div>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Or paste policy</label>
                    <textarea
                      value={policyContent}
                      onChange={(e) => { setPolicyContent(e.target.value); setPolicyName(policyName || 'custom-policy.rego'); }}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm font-mono focus:outline-none focus:border-blue-500 h-48 resize-none"
                      placeholder={`package sandbox.custom\n\ndefault allow := false\n\nallow {\n    input.action_type == "READ"\n}`}
                    />
                  </div>

                  <div className="flex gap-3 pt-2">
                    <button
                      onClick={() => setStep('configure')}
                      className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm font-medium transition-colors"
                    >
                      &larr; Back
                    </button>
                    <button
                      onClick={handleConnect}
                      disabled={connectDisabled}
                      className="flex-1 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
                    >
                      {isHook ? 'Activate Sandbox' : 'Spawn Agent'} <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                  <button
                    onClick={handleLaunchReal}
                    className="w-full mt-2 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
                  >
                    <Terminal className="w-4 h-4" /> Launch as Real App (Jailed)
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // --- STEP: Connecting ---
  if (step === 'connecting') {
    const steps = isHook
      ? ['Upload security policy', 'Create sandbox session', 'Generate hook configuration']
      : ['Upload security policy', 'Spawn sandboxed agent', 'Initialize pipeline'];
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center p-8">
        <div className="max-w-lg w-full bg-gray-900 rounded-xl border border-gray-800 p-8">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-12 h-12 rounded-lg bg-gray-800 flex items-center justify-center text-xl font-bold text-white">
              {selectedAgent?.icon}
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">{isHook ? 'Activating Sandbox' : 'Spawning Agent'}</h2>
              <p className="text-sm text-gray-400">{selectedAgent?.name}</p>
            </div>
          </div>
          <div className="space-y-4">
            {steps.map((label, i) => {
              const stepNum = i + 1;
              const isDone = currentSetupStep > stepNum;
              const isCurrent = currentSetupStep === stepNum;
              return (
                <div key={i} className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                    isDone ? 'bg-green-600 text-white' :
                    isCurrent ? 'bg-blue-600 text-white animate-pulse' :
                    'bg-gray-800 text-gray-500'
                  }`}>
                    {isDone ? <Check className="w-4 h-4" /> : stepNum}
                  </div>
                  <span className={`text-sm ${isDone ? 'text-green-400' : isCurrent ? 'text-white' : 'text-gray-500'}`}>
                    {label}
                  </span>
                  {isCurrent && <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  }

  // --- STEP: Ready (Hook) ---
  if (step === 'ready' && isHook && hookResult) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center p-8">
        <div className="max-w-2xl w-full bg-gray-900 rounded-xl border border-green-800/50 p-8">
          <div className="text-center mb-6">
            <div className="w-16 h-16 rounded-full bg-green-600/20 flex items-center justify-center mx-auto mb-4">
              <Check className="w-8 h-8 text-green-400" />
            </div>
            <h2 className="text-2xl font-bold text-white">Sandbox Active</h2>
            <p className="text-gray-400 mt-2">Session created. Now install the hook in Claude Code.</p>
          </div>

          <div className="bg-gray-800 rounded-lg p-4 mb-6 space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Session ID</span>
              <span className="text-gray-200 font-mono text-xs">{hookResult.sessionId}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Agent ID</span>
              <span className="text-gray-200 font-mono text-xs">{hookResult.agentId}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Capabilities</span>
              <div className="flex gap-1">
                {capabilities.map((c) => (
                  <span key={c} className="px-1.5 py-0.5 text-xs bg-gray-700 text-gray-300 rounded">{c}</span>
                ))}
              </div>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Expires</span>
              <span className="text-gray-200">{ttlMinutes} minutes</span>
            </div>
          </div>

          {/* Auto-install status */}
          <div className="space-y-3">
            {hookResult.autoInstalled ? (
              <>
                <div className="bg-green-900/20 rounded-lg p-4 border border-green-700/50">
                  <div className="flex items-center gap-2 mb-3">
                    <Check className="w-5 h-5 text-green-400" />
                    <p className="text-sm font-medium text-green-300">Hook auto-installed — no manual steps needed</p>
                  </div>
                  <div className="space-y-1.5">
                    {hookResult.hookScriptPath && (
                      <div className="flex items-start gap-2">
                        <span className="text-xs text-gray-500 mt-0.5">Script</span>
                        <code className="text-xs text-orange-300 font-mono break-all">{hookResult.hookScriptPath}</code>
                      </div>
                    )}
                    {hookResult.settingsPath && (
                      <div className="flex items-start gap-2">
                        <span className="text-xs text-gray-500 mt-0.5">Settings</span>
                        <code className="text-xs text-orange-300 font-mono break-all">{hookResult.settingsPath}</code>
                      </div>
                    )}
                  </div>
                </div>
                <div className="bg-yellow-900/20 rounded-lg p-3 border border-yellow-800/50">
                  <p className="text-xs text-yellow-300 font-medium mb-1">Restart Claude Code</p>
                  <p className="text-xs text-gray-400">
                    Settings were patched on disk. Claude Code picks up hook changes on next launch —
                    if it's already running, restart it once for the sandbox to take effect.
                  </p>
                </div>
              </>
            ) : (
              <>
                <div className="bg-red-900/20 rounded-lg p-4 border border-red-700/50">
                  <p className="text-sm font-medium text-red-300 mb-2">Auto-install failed — install manually</p>
                  <p className="text-xs text-gray-400 mb-3">{hookResult.installInstructions[0]}</p>
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-xs text-gray-400">Copy <code className="text-orange-400">sandbox_hook.py</code></p>
                    <button
                      onClick={() => copyToClipboard(hookResult.hookScript)}
                      className="flex items-center gap-1 px-2 py-1 text-xs text-gray-400 hover:text-white bg-gray-700 rounded"
                    >
                      <Copy className="w-3 h-3" />
                      {copied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre className="text-xs text-gray-300 bg-gray-900 p-3 rounded overflow-auto max-h-28 font-mono">{hookResult.hookScript.slice(0, 400)}...</pre>
                </div>
              </>
            )}

            <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700">
              <p className="text-xs text-green-400 font-medium mb-1">Pipeline now enforcing:</p>
              <p className="text-xs text-gray-400">
                Read, Write, Edit, Bash, Grep, Glob — every tool call goes through the 8-step pipeline.
                Actions outside granted capabilities are DENIED.
              </p>
            </div>
          </div>

          <div className="flex gap-3 mt-6">
            <button
              onClick={() => navigate('/')}
              className="flex-1 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
            >
              Open Dashboard <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => { setStep('select'); setHookResult(null); }}
              className="px-6 py-3 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm font-medium transition-colors"
            >
              Connect Another
            </button>
          </div>
        </div>
      </div>
    );
  }

  // --- STEP: Ready (SDK) ---
  if (step === 'ready' && !isHook && sdkResult) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center p-8">
        <div className="max-w-2xl w-full bg-gray-900 rounded-xl border border-green-800/50 p-8">
          <div className="text-center mb-8">
            <div className="w-16 h-16 rounded-full bg-green-600/20 flex items-center justify-center mx-auto mb-4">
              <Check className="w-8 h-8 text-green-400" />
            </div>
            <h2 className="text-2xl font-bold text-white">{selectedAgent?.name} is in the Sandbox</h2>
            <p className="text-gray-400 mt-2">Agent spawned with sandboxed tool execution.</p>
          </div>

          <div className="bg-gray-800 rounded-lg p-4 mb-6 space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Run ID</span>
              <span className="text-gray-200 font-mono">{sdkResult.runId.slice(0, 16)}...</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Agent ID</span>
              <span className="text-gray-200 font-mono">{sdkResult.agentId}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Session ID</span>
              <span className="text-gray-200 font-mono">{sdkResult.sessionId.slice(0, 16)}...</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Status</span>
              <span className={`font-medium ${
                sdkResult.status === 'running' ? 'text-green-400' :
                sdkResult.status === 'failed' ? 'text-red-400' : 'text-yellow-400'
              }`}>{sdkResult.status.toUpperCase()}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Capabilities</span>
              <div className="flex gap-1">
                {capabilities.map((c) => (
                  <span key={c} className="px-1.5 py-0.5 text-xs bg-gray-700 text-gray-300 rounded">{c}</span>
                ))}
              </div>
            </div>
          </div>

          <div className="bg-gray-800/50 rounded-lg p-4 mb-6 border border-gray-700">
            <p className="text-xs text-green-400 mb-1">Every tool call goes through the 8-step pipeline:</p>
            <p className="text-xs text-gray-400">
              Schema &rarr; Intent &rarr; Policy &rarr; Content Safety &rarr; HITL &rarr; Signing &rarr; Execution &rarr; Audit
            </p>
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => navigate('/')}
              className="flex-1 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
            >
              Open Dashboard <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => { setStep('select'); setSdkResult(null); }}
              className="px-6 py-3 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm font-medium transition-colors"
            >
              Connect Another
            </button>
          </div>
        </div>
      </div>
    );
  }

  return null;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
