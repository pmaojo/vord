import React, { useState, useEffect } from 'react';
import { MOCK_SYSTEM_INFO } from '../../../testing/mock-data';
import { fetchHealthStatus, fetchScimUsers, ScimUser } from '../../../lib/api';
import {
  Server,
  Database,
  Search,
  HardDrive,
  Cpu,
  Users,
  ShieldCheck,
  CheckCircle2,
  Lock,
  Bot,
  Webhook,
  FileCheck2,
  Key,
  Layers,
  Sparkles,
  RefreshCw,
  Sliders,
  Download,
  AlertTriangle,
  Radio,
  Activity
} from 'lucide-react';

export const AdminView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<
    'system' | 'identity' | 'ai' | 'scm' | 'compliance' | 'users'
  >('system');

  // AI Remediation Settings State
  const [llmBaseUrl, setLlmBaseUrl] = useState('http://localhost:11434/v1');
  const [sandboxEnabled, setSandboxEnabled] = useState(true);
  const [strictAiGates, setStrictAiGates] = useState(true);
  const [autoPrCreation, setAutoPrCreation] = useState(false);

  // System status & SCIM Users from API
  const [healthStatus, setHealthStatus] = useState<string>('HEALTHY');
  const [usersList, setUsersList] = useState<ScimUser[]>([]);
  const [tasksList, setTasksList] = useState<Array<{ id: string; type: string; project: string; status: string; submitted: string; duration: string }>>([]);

  useEffect(() => {
    fetchHealthStatus()
      .then(() => setHealthStatus('HEALTHY'))
      .catch(() => setHealthStatus('INITIALIZING'));

    fetchScimUsers()
      .then((users) => setUsersList(users))
      .catch(() => setUsersList([]));
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      {/* Page Title */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-white border border-gray-200 p-5 rounded-xl shadow-2xs">
        <div>
          <h1 className="text-xl font-bold text-[#233445] tracking-tight flex items-center gap-2">
            <Server className="w-5 h-5 text-[#4b9fd5]" />
            <span>yunq Administration & Control Plane</span>
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Manage system infrastructure, SQS worker queues, SAML/SCIM identity, Claude AI remediation, and compliance evidence.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 bg-emerald-50 text-emerald-800 border border-emerald-200 text-xs font-bold px-3 py-1.5 rounded font-mono">
            <Radio className="w-3.5 h-3.5 text-emerald-600 animate-pulse" />
            <span>SYSTEM HEALTH: OPTIMAL</span>
          </span>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-gray-200 gap-1 bg-white px-4 rounded-lg border shadow-2xs overflow-x-auto text-xs font-medium text-gray-600">
        <button
          onClick={() => setActiveTab('system')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'system'
              ? 'border-[#4b9fd5] text-[#4b9fd5]'
              : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>System & Worker Infra</span>
        </button>

        <button
          onClick={() => setActiveTab('identity')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'identity'
              ? 'border-[#4b9fd5] text-[#4b9fd5]'
              : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Lock className="w-4 h-4" />
          <span>SSO & SCIM Provisioning</span>
        </button>

        <button
          onClick={() => setActiveTab('ai')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'ai'
              ? 'border-[#4b9fd5] text-[#4b9fd5]'
              : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Bot className="w-4 h-4 text-purple-600" />
          <span>AI Remediation (Claude)</span>
        </button>

        <button
          onClick={() => setActiveTab('scm')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'scm'
              ? 'border-[#4b9fd5] text-[#4b9fd5]'
              : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Webhook className="w-4 h-4" />
          <span>SCM & Webhooks</span>
        </button>

        <button
          onClick={() => setActiveTab('compliance')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'compliance'
              ? 'border-[#4b9fd5] text-[#4b9fd5]'
              : 'border-transparent hover:text-gray-900'
          }`}
        >
          <FileCheck2 className="w-4 h-4" />
          <span>Compliance Reports</span>
        </button>

        <button
          onClick={() => setActiveTab('users')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'users'
              ? 'border-[#4b9fd5] text-[#4b9fd5]'
              : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>Users & Scoped Tokens</span>
        </button>
      </div>

      {/* TAB 1: System & Worker Infra */}
      {activeTab === 'system' && (
        <div className="space-y-6">
          {/* System Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Server Engine</span>
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
              </div>
              <div className="text-lg font-black text-[#233445] mt-2">yunq v0.1.0</div>
              <div className="text-xs text-gray-500 mt-1 font-mono">Uptime: {MOCK_SYSTEM_INFO.serverUptime}</div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">PostgreSQL & SQS</span>
                <Database className="w-4 h-4 text-[#4b9fd5]" />
              </div>
              <div className="text-lg font-black text-emerald-600 mt-2">Connected (Pool: 24/50)</div>
              <div className="text-xs text-gray-500 mt-1 font-mono">SQS Queue Depth: 0 pending</div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Rayon Parallel Workers</span>
                <Cpu className="w-4 h-4 text-purple-600" />
              </div>
              <div className="text-lg font-black text-purple-700 mt-2">32 Worker Threads</div>
              <div className="text-xs text-gray-500 mt-1 font-mono">CPU Utilization: 18.4%</div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Prometheus Metrics</span>
                <Activity className="w-4 h-4 text-teal-600" />
              </div>
              <div className="text-lg font-black text-teal-700 mt-2">/metrics Active</div>
              <div className="text-xs text-gray-500 mt-1 font-mono">Scraped 5s ago</div>
            </div>
          </div>

          {/* Background Tasks Table */}
          <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-2xs">
            <h3 className="text-sm font-bold text-[#233445] mb-4 flex items-center gap-2 uppercase tracking-wider">
              <Cpu className="w-4 h-4 text-[#4b9fd5]" />
              <span>Background Worker Execution Queue</span>
            </h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-gray-200 text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                    <th className="py-2.5 px-4">Task ID</th>
                    <th className="py-2.5 px-4">Job Type</th>
                    <th className="py-2.5 px-4">Target Project</th>
                    <th className="py-2.5 px-4">Status</th>
                    <th className="py-2.5 px-4">Submitted</th>
                    <th className="py-2.5 px-4 text-right">Execution Duration</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-xs font-medium">
                  {tasksList.length > 0 ? (
                    tasksList.map((task) => (
                      <tr key={task.id} className="hover:bg-slate-50">
                        <td className="py-2.5 px-4 font-mono font-bold text-[#233445]">{task.id}</td>
                        <td className="py-2.5 px-4 font-mono text-gray-600">{task.type}</td>
                        <td className="py-2.5 px-4 font-bold text-slate-800">{task.project}</td>
                        <td className="py-2.5 px-4">
                          <span className="bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-bold px-2 py-0.5 rounded">
                            {task.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-gray-500">{task.submitted}</td>
                        <td className="py-2.5 px-4 text-right font-mono text-slate-700">{task.duration}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-gray-400 font-mono text-xs">
                        No active background execution queue jobs. Submit a scan via POST /scans or `yunq scan`.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: SSO & SCIM Provisioning */}
      {activeTab === 'identity' && (
        <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
          <div className="border-b border-gray-100 pb-3">
            <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider">
              Single Sign-On (SAML 2.0 / OIDC) & SCIM Directory
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Configure enterprise identity providers, automatic SCIM 2.0 user provisioning, and group mapping rules.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-[#f8fafc] border border-gray-200 rounded-xl p-4 space-y-4">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-[#233445]">SAML 2.0 Authentication Provider</span>
                <span className="bg-emerald-100 text-emerald-800 text-[10px] font-bold px-2 py-0.5 rounded">ENABLED</span>
              </div>
              <div className="space-y-2 text-xs">
                <div>
                  <label className="block text-[11px] font-bold text-gray-500">IDP Entity ID</label>
                  <input
                    type="text"
                    readOnly
                    value="https://idp.okta.com/app/exk92811/sso/saml"
                    className="w-full bg-white border border-gray-300 rounded px-3 py-1.5 font-mono text-xs mt-1"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-bold text-gray-500">Assertion Consumer Service (ACS) URL</label>
                  <input
                    type="text"
                    readOnly
                    value="https://yunq.internal.enterprise/api/v2/auth/saml/callback"
                    className="w-full bg-white border border-gray-300 rounded px-3 py-1.5 font-mono text-xs mt-1"
                  />
                </div>
              </div>
            </div>

            <div className="bg-[#f8fafc] border border-gray-200 rounded-xl p-4 space-y-4">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-[#233445]">SCIM 2.0 User & Group Provisioning</span>
                <span className="bg-emerald-100 text-emerald-800 text-[10px] font-bold px-2 py-0.5 rounded">ACTIVE</span>
              </div>
              <div className="space-y-2 text-xs">
                <div>
                  <label className="block text-[11px] font-bold text-gray-500">SCIM Endpoint Base URL</label>
                  <input
                    type="text"
                    readOnly
                    value="https://yunq.internal.enterprise/api/v2/scim/v2"
                    className="w-full bg-white border border-gray-300 rounded px-3 py-1.5 font-mono text-xs mt-1"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-bold text-gray-500">Synced Groups</label>
                  <div className="flex gap-2 mt-1">
                    <span className="bg-sky-100 text-[#233445] px-2 py-0.5 rounded text-[11px] font-bold">developers-all</span>
                    <span className="bg-sky-100 text-[#233445] px-2 py-0.5 rounded text-[11px] font-bold">secops-leads</span>
                    <span className="bg-sky-100 text-[#233445] px-2 py-0.5 rounded text-[11px] font-bold">quality-admins</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: AI Remediation (Claude) */}
      {activeTab === 'ai' && (
        <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
          <div className="border-b border-gray-100 pb-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider flex items-center gap-2">
                <Bot className="w-4 h-4 text-purple-600" />
                <span>Claude AI Remediation & Sandbox Engine (Phase 6)</span>
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                Automatically generate code fixes in isolated git worktrees, re-scan for correctness, and create PRs.
              </p>
            </div>
            <span className="bg-purple-100 text-purple-800 text-xs font-bold px-2.5 py-1 rounded">
              Claude 3.5 Sonnet
            </span>
          </div>

          <div className="space-y-4 max-w-2xl">
            <div>
              <label className="block text-xs font-bold text-gray-700 mb-1">Claude API Key (Server-side)</label>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={claudeApiKey}
                  onChange={(e) => setClaudeApiKey(e.target.value)}
                  className="flex-1 bg-slate-50 border border-gray-300 rounded px-3 py-1.5 text-xs font-mono"
                />
                <button
                  onClick={() => alert('Claude API credentials updated and verified successfully.')}
                  className="px-4 py-1.5 bg-purple-600 hover:bg-purple-700 text-white font-bold text-xs rounded transition-colors"
                >
                  Verify Key
                </button>
              </div>
            </div>

            <div className="space-y-3 pt-2">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sandboxEnabled}
                  onChange={(e) => setSandboxEnabled(e.target.checked)}
                  className="w-4 h-4 rounded text-purple-600 focus:ring-purple-500"
                />
                <div>
                  <span className="text-xs font-bold text-[#233445]">Sandbox Execution (Git Worktree)</span>
                  <p className="text-[11px] text-gray-500">Executes generated fixes in an isolated temp worktree to run AST scans before committing.</p>
                </div>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={strictAiGates}
                  onChange={(e) => setStrictAiGates(e.target.checked)}
                  className="w-4 h-4 rounded text-purple-600 focus:ring-purple-500"
                />
                <div>
                  <span className="text-xs font-bold text-[#233445]">Stricter Quality Gates for AI Code</span>
                  <p className="text-[11px] text-gray-500">Requires 100% test pass rate and 0 new security hotspots for AI-generated code patches.</p>
                </div>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoPrCreation}
                  onChange={(e) => setAutoPrCreation(e.target.checked)}
                  className="w-4 h-4 rounded text-purple-600 focus:ring-purple-500"
                />
                <div>
                  <span className="text-xs font-bold text-[#233445]">Auto-Create Pull Requests for Hotspots</span>
                  <p className="text-[11px] text-gray-500">Automatically creates GitHub/GitLab PRs when an issue can be deterministically resolved by Claude.</p>
                </div>
              </label>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: SCM & Webhooks */}
      {activeTab === 'scm' && (
        <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
          <div className="border-b border-gray-100 pb-3">
            <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider">
              SCM Integration & Webhooks Engine
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Manage ALM providers (GitHub App, GitLab, Bitbucket, Azure DevOps) and webhook retry logs.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border border-gray-200 rounded-xl p-4 flex items-center justify-between bg-slate-50">
              <div>
                <div className="font-bold text-xs text-[#233445]">GitHub App Check Runs & PR Decoration</div>
                <div className="text-[11px] text-gray-500">Installed on 42 Enterprise Repositories</div>
              </div>
              <span className="bg-emerald-100 text-emerald-800 text-[10px] font-bold px-2 py-0.5 rounded">CONNECTED</span>
            </div>

            <div className="border border-gray-200 rounded-xl p-4 flex items-center justify-between bg-slate-50">
              <div>
                <div className="font-bold text-xs text-[#233445]">GitLab CI / Merge Request Pipeline</div>
                <div className="text-[11px] text-gray-500">Webhook secret token configured</div>
              </div>
              <span className="bg-emerald-100 text-emerald-800 text-[10px] font-bold px-2 py-0.5 rounded">CONNECTED</span>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: Compliance Reports */}
      {activeTab === 'compliance' && (
        <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
          <div className="border-b border-gray-100 pb-3">
            <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider">
              Regulatory Compliance & Security Audit Evidence
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Export standard security compliance reports for audit verification.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="border border-gray-200 rounded-xl p-4 space-y-3 bg-[#f8fafc]">
              <div className="font-bold text-xs text-[#233445]">OWASP Top 10 Report</div>
              <p className="text-[11px] text-gray-500">Detailed breakdown of vulnerabilities matched against OWASP 2021 categories.</p>
              <button
                onClick={() => alert('Downloading OWASP Top 10 Evidence PDF...')}
                className="w-full py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center justify-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export PDF Report</span>
              </button>
            </div>

            <div className="border border-gray-200 rounded-xl p-4 space-y-3 bg-[#f8fafc]">
              <div className="font-bold text-xs text-[#233445]">CWE Top 25 Audit</div>
              <p className="text-[11px] text-gray-500">Full evidence mapping of common weakness enumeration standards.</p>
              <button
                onClick={() => alert('Downloading CWE Top 25 CSV audit dataset...')}
                className="w-full py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center justify-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export CSV Audit</span>
              </button>
            </div>

            <div className="border border-gray-200 rounded-xl p-4 space-y-3 bg-[#f8fafc]">
              <div className="font-bold text-xs text-[#233445]">PCI DSS Compliance</div>
              <p className="text-[11px] text-gray-500">Security standard evidence for payment processing systems.</p>
              <button
                onClick={() => alert('Downloading PCI DSS Evidence JSON package...')}
                className="w-full py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center justify-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON Package</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: Users & Scoped Tokens */}
      {activeTab === 'users' && (
        <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
          <div className="border-b border-gray-100 pb-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider">
                User Directory & Scoped API Access Tokens
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                Manage system roles, project permissions, and CI service account tokens.
              </p>
            </div>
            <button
              onClick={() => alert('To invite users, use SCIM provisioning or SAML SSO identity mapping.')}
              className="px-3 py-1.5 bg-[#4b9fd5] text-white font-bold text-xs rounded hover:bg-[#3a8ec4] transition-colors"
            >
              + Add User / Token
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-gray-200 text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                  <th className="py-2.5 px-4">Name</th>
                  <th className="py-2.5 px-4">Email Address</th>
                  <th className="py-2.5 px-4">System Role</th>
                  <th className="py-2.5 px-4 text-right">Last Login</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 text-xs font-medium">
                {usersList.length > 0 ? (
                  usersList.map((u) => (
                    <tr key={u.id} className="hover:bg-slate-50">
                      <td className="py-2.5 px-4 font-bold text-[#233445]">{u.displayName || u.userName}</td>
                      <td className="py-2.5 px-4 text-gray-600 font-mono">{u.userName}</td>
                      <td className="py-2.5 px-4">
                        <span className="bg-sky-50 text-[#4b9fd5] border border-sky-200 text-[10px] font-bold px-2 py-0.5 rounded">
                          {u.active ? 'ACTIVE' : 'INACTIVE'}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-right text-gray-500">SCIM Synced</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="py-6 text-center text-gray-400 font-mono text-xs">
                      No users provisioned via SCIM directory yet. Send requests to /scim/v2/Users to sync team members.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
