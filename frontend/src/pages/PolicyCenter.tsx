import { useState } from 'react';
import { Upload, Eye, ToggleLeft, ToggleRight } from 'lucide-react';
import type { PolicyFile } from '../types';

const mockPolicies: PolicyFile[] = [
  { id: '1', name: 'file_access.rego', content: 'package sandbox.file_access\n\ndefault allow = false\n\nallow {\n  input.action == "file_read"\n  input.risk_tier == "LOW"\n}\n\nallow {\n  input.action == "file_write"\n  input.risk_tier != "CRITICAL"\n  input.hitl_approved == true\n}', uploaded_at: '2025-01-10T08:00:00Z', active: true, version: 3 },
  { id: '2', name: 'network_policy.rego', content: 'package sandbox.network\n\ndefault allow = false\n\nallow {\n  input.action == "http_get"\n  input.target_host in data.allowed_hosts\n}', uploaded_at: '2025-01-12T14:30:00Z', active: true, version: 1 },
  { id: '3', name: 'shell_exec.rego', content: 'package sandbox.shell\n\ndefault allow = false\n\n# Shell execution always requires HITL for CRITICAL tier\nescalate {\n  input.action == "shell_exec"\n  input.risk_tier == "CRITICAL"\n}', uploaded_at: '2025-01-14T09:15:00Z', active: false, version: 2 },
];

export default function PolicyCenter() {
  const [selected, setSelected] = useState<PolicyFile | null>(null);
  const [policies, setPolicies] = useState(mockPolicies);

  const togglePolicy = (id: string) => {
    setPolicies((prev) =>
      prev.map((p) => (p.id === id ? { ...p, active: !p.active } : p))
    );
  };

  return (
    <div className="space-y-6">
      <p className="text-gray-400">Upload and manage OPA Rego policy files for the sandbox pipeline.</p>

      {/* Upload Dropzone */}
      <div className="border-2 border-dashed border-gray-700 rounded-xl p-8 text-center hover:border-blue-500/50 transition-colors cursor-pointer">
        <Upload className="w-10 h-10 text-gray-500 mx-auto mb-3" />
        <p className="text-gray-400 text-sm">Drop .rego files here or click to upload</p>
        <p className="text-gray-600 text-xs mt-1">OPA Rego policy files only</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Policy List */}
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-white">Uploaded Policies</h3>
          {policies.map((policy) => (
            <div
              key={policy.id}
              onClick={() => setSelected(policy)}
              className={`bg-gray-900 border rounded-lg p-4 cursor-pointer transition-colors ${
                selected?.id === policy.id ? 'border-blue-500' : 'border-gray-800 hover:border-gray-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Eye className="w-4 h-4 text-gray-500" />
                  <div>
                    <p className="text-white text-sm font-medium">{policy.name}</p>
                    <p className="text-xs text-gray-500">v{policy.version} -- {new Date(policy.uploaded_at).toLocaleDateString()}</p>
                  </div>
                </div>
                <button
                  onClick={(e) => { e.stopPropagation(); togglePolicy(policy.id); }}
                  className="text-gray-400 hover:text-white"
                >
                  {policy.active ? (
                    <ToggleRight className="w-6 h-6 text-green-400" />
                  ) : (
                    <ToggleLeft className="w-6 h-6 text-gray-600" />
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Preview Panel */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h3 className="text-lg font-semibold text-white mb-3">
            {selected ? selected.name : 'Policy Preview'}
          </h3>
          {selected ? (
            <pre className="text-sm text-green-400 font-mono bg-gray-950 p-4 rounded-lg overflow-auto max-h-96">
              {selected.content}
            </pre>
          ) : (
            <p className="text-gray-500 text-sm">Select a policy to preview its content.</p>
          )}
        </div>
      </div>
    </div>
  );
}
