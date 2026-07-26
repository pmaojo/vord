import React, { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSystemInfo, useAuditLog, useQueueStatus } from '../../../lib/queries';
import {
  fetchScimUsers,
  ScimUser,
  downloadOwaspPdfReport,
  fetchWebhooks,
  fetchWebhookDeliveries,
  grantPermission,
  revokePermission,
} from '../../../lib/api';
import { formatUptimeSeconds } from '../../../lib/utils';
import {
  Server,
  Database,
  Users,
  ShieldCheck,
  CheckCircle2,
  Lock,
  Bot,
  Webhook,
  FileCheck2,
  Layers,
  Download,
  Radio,
  Loader2,
  AlertCircle,
  Plus,
  Trash2,
  ListTodo,
  XCircle,
  Clock,
} from 'lucide-react';

export const AdminView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<
    'system' | 'queue' | 'identity' | 'ai' | 'scm' | 'compliance' | 'users'
  >('system');

  const { data: systemInfo, isLoading: systemLoading } = useSystemInfo();

  const { data: usersList } = useQuery<ScimUser[]>({
    queryKey: ['scim-users'],
    queryFn: fetchScimUsers,
  });

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
            Manage system infrastructure, SCIM identity, Claude AI remediation, and compliance evidence.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {systemLoading ? (
            <span className="inline-flex items-center gap-1.5 bg-slate-100 text-slate-600 border border-slate-200 text-xs font-bold px-3 py-1.5 rounded font-mono">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>CHECKING...</span>
            </span>
          ) : systemInfo?.database.connected ? (
            <span className="inline-flex items-center gap-1.5 bg-emerald-50 text-emerald-800 border border-emerald-200 text-xs font-bold px-3 py-1.5 rounded font-mono">
              <Radio className="w-3.5 h-3.5 text-emerald-600 animate-pulse" />
              <span>DATABASE CONNECTED</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 bg-rose-50 text-rose-800 border border-rose-200 text-xs font-bold px-3 py-1.5 rounded font-mono">
              <Radio className="w-3.5 h-3.5 text-rose-600" />
              <span>DATABASE UNREACHABLE</span>
            </span>
          )}
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-gray-200 gap-1 bg-white px-4 rounded-lg border shadow-2xs overflow-x-auto text-xs font-medium text-gray-600">
        <button
          onClick={() => setActiveTab('system')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'system' ? 'border-[#4b9fd5] text-[#4b9fd5]' : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Server className="w-4 h-4" />
          <span>System Info</span>
        </button>

        <button
          onClick={() => setActiveTab('queue')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'queue' ? 'border-[#4b9fd5] text-[#4b9fd5]' : 'border-transparent hover:text-gray-900'
          }`}
        >
          <ListTodo className="w-4 h-4" />
          <span>Task Queue</span>
        </button>

        <button
          onClick={() => setActiveTab('identity')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'identity' ? 'border-[#4b9fd5] text-[#4b9fd5]' : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Lock className="w-4 h-4" />
          <span>SCIM Provisioning</span>
        </button>

        <button
          onClick={() => setActiveTab('ai')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'ai' ? 'border-[#4b9fd5] text-[#4b9fd5]' : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Bot className="w-4 h-4 text-purple-600" />
          <span>AI Remediation</span>
        </button>

        <button
          onClick={() => setActiveTab('scm')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'scm' ? 'border-[#4b9fd5] text-[#4b9fd5]' : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Webhook className="w-4 h-4" />
          <span>Webhooks</span>
        </button>

        <button
          onClick={() => setActiveTab('compliance')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'compliance' ? 'border-[#4b9fd5] text-[#4b9fd5]' : 'border-transparent hover:text-gray-900'
          }`}
        >
          <FileCheck2 className="w-4 h-4" />
          <span>Compliance Reports</span>
        </button>

        <button
          onClick={() => setActiveTab('users')}
          className={`py-3 px-3 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'users' ? 'border-[#4b9fd5] text-[#4b9fd5]' : 'border-transparent hover:text-gray-900'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>Users & Permissions</span>
        </button>
      </div>

      {activeTab === 'system' && <SystemTab systemInfo={systemInfo} loading={systemLoading} />}
      {activeTab === 'queue' && <QueueTab />}
      {activeTab === 'identity' && <IdentityTab usersList={usersList} />}
      {activeTab === 'ai' && <AiTab />}
      {activeTab === 'scm' && <WebhooksTab />}
      {activeTab === 'compliance' && <ComplianceTab />}
      {activeTab === 'users' && <UsersTab usersList={usersList} />}
    </div>
  );
};

interface SystemInfoShape {
  version: string;
  git_sha: string;
  uptime_seconds: number;
  database: { connected: boolean; postgres_version?: string | null };
  issues_total: number;
  hotspots_total: number;
  pending_scan_jobs: number;
}

const SystemTab: React.FC<{ systemInfo?: SystemInfoShape; loading: boolean }> = ({ systemInfo, loading }) => {
  if (loading) {
    return (
      <div className="flex items-center gap-2 text-sm text-slate-500 py-12 justify-center">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading system info...
      </div>
    );
  }
  if (!systemInfo) {
    return (
      <div className="bg-rose-50 border border-rose-200 text-rose-800 rounded-xl p-4 text-sm">
        Failed to reach GET /api/system/info.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Server</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-lg font-black text-[#233445] mt-2">yunq v{systemInfo.version}</div>
          <div className="text-xs text-gray-500 mt-1 font-mono">
            Uptime: {formatUptimeSeconds(systemInfo.uptime_seconds)} · {systemInfo.git_sha.slice(0, 8)}
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">PostgreSQL</span>
            <Database className="w-4 h-4 text-[#4b9fd5]" />
          </div>
          <div className={`text-lg font-black mt-2 ${systemInfo.database.connected ? 'text-emerald-600' : 'text-rose-600'}`}>
            {systemInfo.database.connected ? 'Connected' : 'Unreachable'}
          </div>
          <div className="text-xs text-gray-500 mt-1 font-mono">
            {systemInfo.database.postgres_version ?? 'version unknown'}
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Tracked Issues</span>
            <Layers className="w-4 h-4 text-purple-600" />
          </div>
          <div className="text-lg font-black text-purple-700 mt-2">{systemInfo.issues_total.toLocaleString()}</div>
          <div className="text-xs text-gray-500 mt-1 font-mono">{systemInfo.hotspots_total} hotspots</div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Scan Queue</span>
            <Radio className="w-4 h-4 text-teal-600" />
          </div>
          <div className="text-lg font-black text-teal-700 mt-2">{systemInfo.pending_scan_jobs} pending</div>
          <div className="text-xs text-gray-500 mt-1 font-mono">GET /api/system/info</div>
        </div>
      </div>
    </div>
  );
};

const QueueTab: React.FC = () => {
  const { data: queueStatus, isLoading, isError, error } = useQueueStatus();

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
      <div className="border-b border-gray-100 pb-3">
        <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider">Task Queue Status</h3>
        <p className="text-xs text-gray-500 mt-0.5">
          Backed by <code className="font-mono">GET /api/admin/queue/status</code> — real scan job depth,
          oldest-pending age, and recent failures (dead-lettered after 5 attempts). Bearer-authenticated,
          requires the <code className="font-mono">AdminAccess</code> permission.
        </p>
      </div>

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-slate-500 py-8 justify-center">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading queue status...
        </div>
      ) : isError ? (
        <div className="bg-amber-50 border border-amber-200 text-amber-800 rounded-lg p-4 text-xs flex items-start gap-2">
          <Lock className="w-4 h-4 shrink-0 mt-0.5" />
          <span>
            {error instanceof Error ? error.message : 'Sign in required'} — this endpoint requires an
            AdminAccess-scoped session, and this UI doesn't have a way to obtain one yet (personal access
            tokens always grant the Developer role), so it isn't reachable from here until that's built.
          </span>
        </div>
      ) : queueStatus ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Pending</span>
                <Clock className="w-4 h-4 text-amber-500" />
              </div>
              <div className="text-lg font-black text-amber-700 mt-2">{queueStatus.pending}</div>
              {queueStatus.oldest_pending_age_seconds != null && (
                <div className="text-xs text-gray-500 mt-1 font-mono">
                  oldest: {formatUptimeSeconds(queueStatus.oldest_pending_age_seconds)}
                </div>
              )}
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Processing</span>
                <Radio className="w-4 h-4 text-teal-600" />
              </div>
              <div className="text-lg font-black text-teal-700 mt-2">{queueStatus.processing}</div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Dead-lettered</span>
                <XCircle className="w-4 h-4 text-rose-600" />
              </div>
              <div className="text-lg font-black text-rose-700 mt-2">{queueStatus.dead}</div>
              <div className="text-xs text-gray-500 mt-1 font-mono">retry budget exhausted</div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">Recent Failures</span>
                <AlertCircle className="w-4 h-4 text-purple-600" />
              </div>
              <div className="text-lg font-black text-purple-700 mt-2">{queueStatus.recent_failures.length}</div>
            </div>
          </div>

          <div>
            <h4 className="text-[11px] font-bold text-gray-500 uppercase tracking-wider mb-2">
              Recent Failures & Diagnostics
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-gray-200 text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                    <th className="py-2.5 px-4">Project</th>
                    <th className="py-2.5 px-4">Status</th>
                    <th className="py-2.5 px-4">Attempts</th>
                    <th className="py-2.5 px-4">Last Error</th>
                    <th className="py-2.5 px-4">Updated</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-xs font-medium">
                  {queueStatus.recent_failures.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-gray-400 font-mono text-xs">
                        No failed jobs recorded.
                      </td>
                    </tr>
                  ) : (
                    queueStatus.recent_failures.map((job) => (
                      <tr key={job.id} className="hover:bg-slate-50">
                        <td className="py-2.5 px-4 font-bold text-[#233445] font-mono">{job.project}</td>
                        <td className="py-2.5 px-4">
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                              job.status === 'dead'
                                ? 'bg-rose-50 text-rose-700 border-rose-200'
                                : 'bg-amber-50 text-amber-700 border-amber-200'
                            }`}
                          >
                            {job.status.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 font-mono">{job.attempts}</td>
                        <td className="py-2.5 px-4 text-gray-600 max-w-md truncate" title={job.last_error ?? undefined}>
                          {job.last_error ?? '—'}
                        </td>
                        <td className="py-2.5 px-4 text-gray-500 font-mono">{job.updated_at}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
};

const IdentityTab: React.FC<{ usersList?: ScimUser[] }> = ({ usersList }) => (
  <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
    <div className="border-b border-gray-100 pb-3">
      <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider">SCIM 2.0 User Provisioning</h3>
      <p className="text-xs text-gray-500 mt-0.5">
        Live directory served at <code className="font-mono">GET /scim/v2/Users</code>. There is no SAML/OIDC
        metadata endpoint yet — SSO configuration isn't exposed here because the server doesn't have anything
        real to show for it.
      </p>
    </div>

    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr className="bg-slate-50 border-b border-gray-200 text-[11px] font-bold text-gray-500 uppercase tracking-wider">
            <th className="py-2.5 px-4">Display Name</th>
            <th className="py-2.5 px-4">Username</th>
            <th className="py-2.5 px-4">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 text-xs font-medium">
          {(usersList ?? []).length > 0 ? (
            usersList!.map((u) => (
              <tr key={u.id} className="hover:bg-slate-50">
                <td className="py-2.5 px-4 font-bold text-[#233445]">{u.displayName || u.userName}</td>
                <td className="py-2.5 px-4 text-gray-600 font-mono">{u.userName}</td>
                <td className="py-2.5 px-4">
                  <span className="bg-sky-50 text-[#4b9fd5] border border-sky-200 text-[10px] font-bold px-2 py-0.5 rounded">
                    {u.active ? 'ACTIVE' : 'INACTIVE'}
                  </span>
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={3} className="py-6 text-center text-gray-400 font-mono text-xs">
                No users provisioned via SCIM directory yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  </div>
);

const AiTab: React.FC = () => (
  <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
    <div className="border-b border-gray-100 pb-3">
      <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider flex items-center gap-2">
        <Bot className="w-4 h-4 text-purple-600" />
        <span>AI Remediation Agent</span>
      </h3>
      <p className="text-xs text-gray-500 mt-0.5">
        Wired to <code className="font-mono">POST /api/issues/{'{id}'}/assign-to-agent</code>. Every fix goes
        through generate → sandbox → re-scan → verdict before it's ever returned — that loop isn't a toggle, so
        there's nothing to configure here beyond the server's own environment.
      </p>
    </div>

    <div className="max-w-2xl space-y-3">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
        <div className="bg-slate-50 border border-gray-200 rounded-lg p-3">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">YUNQ_LLM_BASE_URL</div>
          <div className="text-slate-700">OpenAI-compatible endpoint (defaults to local Ollama)</div>
        </div>
        <div className="bg-slate-50 border border-gray-200 rounded-lg p-3">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">YUNQ_LLM_API_KEY</div>
          <div className="text-slate-700">Server-side secret — never entered through this UI</div>
        </div>
        <div className="bg-slate-50 border border-gray-200 rounded-lg p-3">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">YUNQ_LLM_MODEL</div>
          <div className="text-slate-700">Model name passed to the adapter (defaults to llama3)</div>
        </div>
        <div className="bg-slate-50 border border-gray-200 rounded-lg p-3">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">
            GITHUB_TOKEN / GITHUB_REPOSITORY
          </div>
          <div className="text-slate-700">Required to fetch the issue's real source before proposing a fix</div>
        </div>
      </div>
      <p className="text-[11px] text-gray-500 pt-2">
        These are read from the server process's environment at request time. Change them by redeploying
        yunq-server with updated env vars, not from the browser.
      </p>
    </div>
  </div>
);

const WebhooksTab: React.FC = () => {
  const webhooksQuery = useQuery({ queryKey: ['webhooks'], queryFn: fetchWebhooks, retry: false });
  const deliveriesQuery = useQuery({
    queryKey: ['webhook-deliveries'],
    queryFn: () => fetchWebhookDeliveries(20),
    retry: false,
  });

  const authRequired = webhooksQuery.isError;

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
      <div className="border-b border-gray-100 pb-3">
        <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider">Webhook Subscriptions</h3>
        <p className="text-xs text-gray-500 mt-0.5">
          Backed by <code className="font-mono">GET /api/webhooks</code> and{' '}
          <code className="font-mono">GET /api/webhooks/deliveries</code>, both bearer-authenticated.
        </p>
      </div>

      {authRequired ? (
        <div className="bg-amber-50 border border-amber-200 text-amber-800 rounded-lg p-4 text-xs flex items-start gap-2">
          <Lock className="w-4 h-4 shrink-0 mt-0.5" />
          <span>
            {webhooksQuery.error instanceof Error ? webhooksQuery.error.message : 'Sign in required'} — this UI
            doesn't have an OAuth session flow wired up yet, so webhook management isn't reachable from here
            until that's built.
          </span>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(webhooksQuery.data ?? []).length === 0 ? (
              <div className="text-xs text-gray-400 font-mono">No webhooks registered.</div>
            ) : (
              webhooksQuery.data!.map((hook) => (
                <div key={hook.id} className="border border-gray-200 rounded-xl p-4 bg-slate-50">
                  <div className="font-bold text-xs text-[#233445] font-mono truncate">{hook.url}</div>
                  <div className="text-[11px] text-gray-500 mt-1">{hook.events.join(', ')}</div>
                </div>
              ))
            )}
          </div>

          <div>
            <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Recent Deliveries</h4>
            <div className="space-y-1.5 text-xs font-mono">
              {(deliveriesQuery.data ?? []).length === 0 ? (
                <div className="text-gray-400">No delivery attempts recorded.</div>
              ) : (
                deliveriesQuery.data!.map((d) => (
                  <div key={`${d.delivery_id}-${d.attempt}`} className="flex items-center justify-between border-b border-gray-100 py-1.5">
                    <span>{d.event} → {d.webhook_id}</span>
                    <span className={d.outcome === 'success' ? 'text-emerald-600' : 'text-rose-600'}>
                      {d.outcome} ({d.http_status ?? '—'})
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

const ComplianceTab: React.FC = () => {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDownloadOwaspPdf = async () => {
    setDownloading(true);
    setError(null);
    try {
      const blob = await downloadOwaspPdfReport();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'owasp-compliance-report.pdf';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Download failed');
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-6">
      <div className="border-b border-gray-100 pb-3">
        <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider">
          Regulatory Compliance & Security Audit Evidence
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">
          The only export the server implements today is the OWASP PDF. CWE Top 25 / PCI DSS exports aren't
          built yet, so they aren't listed here as if they were.
        </p>
      </div>

      <div className="max-w-sm border border-gray-200 rounded-xl p-4 space-y-3 bg-[#f8fafc]">
        <div className="font-bold text-xs text-[#233445]">OWASP Top 10 Report</div>
        <p className="text-[11px] text-gray-500">
          ISO 32000-1 PDF, generated from <code className="font-mono">GET /api/compliance/owasp.pdf</code>.
        </p>
        <button
          onClick={handleDownloadOwaspPdf}
          disabled={downloading}
          className="w-full py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] disabled:opacity-60 text-white font-bold text-xs rounded transition-colors flex items-center justify-center gap-1.5"
        >
          {downloading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
          <span>{downloading ? 'Downloading...' : 'Export PDF Report'}</span>
        </button>
        {error && (
          <div className="text-[11px] text-rose-700 bg-rose-50 border border-rose-200 rounded px-2 py-1.5 flex items-center gap-1.5">
            <AlertCircle className="w-3 h-3 shrink-0" />
            {error}
          </div>
        )}
      </div>
    </div>
  );
};

const UsersTab: React.FC<{ usersList?: ScimUser[] }> = ({ usersList }) => {
  const queryClient = useQueryClient();
  const { data: auditLog } = useAuditLog('project_permission');
  const [projectKey, setProjectKey] = useState('');
  const [userLogin, setUserLogin] = useState('');
  const [role, setRole] = useState('viewer');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectKey || !userLogin) return;
    setSaving(true);
    setError(null);
    try {
      await grantPermission(projectKey, userLogin, role);
      setProjectKey('');
      setUserLogin('');
      queryClient.invalidateQueries({ queryKey: ['audit-log', 'project_permission'] });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to grant permission');
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async (key: string, user: string) => {
    try {
      await revokePermission(key, user);
      queryClient.invalidateQueries({ queryKey: ['audit-log', 'project_permission'] });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke permission');
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-4">
        <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider">SCIM Directory</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-gray-200 text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                <th className="py-2.5 px-4">Name</th>
                <th className="py-2.5 px-4">Username</th>
                <th className="py-2.5 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 text-xs font-medium">
              {(usersList ?? []).length > 0 ? (
                usersList!.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-50">
                    <td className="py-2.5 px-4 font-bold text-[#233445]">{u.displayName || u.userName}</td>
                    <td className="py-2.5 px-4 text-gray-600 font-mono">{u.userName}</td>
                    <td className="py-2.5 px-4">
                      <span className="bg-sky-50 text-[#4b9fd5] border border-sky-200 text-[10px] font-bold px-2 py-0.5 rounded">
                        {u.active ? 'ACTIVE' : 'INACTIVE'}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={3} className="py-6 text-center text-gray-400 font-mono text-xs">
                    No users provisioned via SCIM directory yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-2xs space-y-4">
        <div>
          <h3 className="text-sm font-bold text-[#233445] uppercase tracking-wider flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#4b9fd5]" />
            Project Permissions
          </h3>
          <p className="text-xs text-gray-500 mt-0.5">
            One fixed role per (project, user) — no groups, no templates. Backed by{' '}
            <code className="font-mono">PUT/DELETE /api/projects/{'{key}'}/permissions/{'{user}'}</code>.
          </p>
        </div>

        <form onSubmit={handleGrant} className="flex flex-wrap items-end gap-2">
          <div>
            <label className="block text-[10px] font-bold text-gray-500 uppercase mb-1">Project Key</label>
            <input
              type="text"
              value={projectKey}
              onChange={(e) => setProjectKey(e.target.value)}
              placeholder="yunq-core-platform"
              className="bg-slate-50 border border-gray-300 rounded px-2.5 py-1.5 text-xs font-mono"
              required
            />
          </div>
          <div>
            <label className="block text-[10px] font-bold text-gray-500 uppercase mb-1">User Login</label>
            <input
              type="text"
              value={userLogin}
              onChange={(e) => setUserLogin(e.target.value)}
              placeholder="octocat"
              className="bg-slate-50 border border-gray-300 rounded px-2.5 py-1.5 text-xs font-mono"
              required
            />
          </div>
          <div>
            <label className="block text-[10px] font-bold text-gray-500 uppercase mb-1">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="bg-slate-50 border border-gray-300 rounded px-2.5 py-1.5 text-xs font-bold"
            >
              <option value="admin">admin</option>
              <option value="editor">editor</option>
              <option value="viewer">viewer</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={saving}
            className="px-3 py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] disabled:opacity-60 text-white font-bold text-xs rounded flex items-center gap-1.5"
          >
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            Grant
          </button>
        </form>

        {error && (
          <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded px-2.5 py-1.5">
            {error}
          </div>
        )}

        <div>
          <h4 className="text-[11px] font-bold text-gray-500 uppercase tracking-wider mb-2">Recent Grants (Audit Log)</h4>
          <div className="space-y-1 text-xs font-mono">
            {(auditLog?.items ?? []).length === 0 ? (
              <div className="text-gray-400">No permission grants recorded yet.</div>
            ) : (
              auditLog!.items.map((entry) => {
                const [key, user] = entry.entity_id.split(':');
                const afterRole =
                  entry.after && typeof entry.after === 'object' && 'role' in (entry.after as Record<string, unknown>)
                    ? String((entry.after as Record<string, unknown>).role)
                    : null;
                return (
                  <div key={entry.id} className="flex items-center justify-between border-b border-gray-100 py-1.5">
                    <span>
                      {entry.action} · {key} → {user} {afterRole ? `(${afterRole})` : ''}
                    </span>
                    {afterRole && (
                      <button
                        onClick={() => handleRevoke(key, user)}
                        className="text-rose-500 hover:text-rose-700"
                        title="Revoke"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
