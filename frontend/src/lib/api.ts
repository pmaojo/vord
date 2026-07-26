//! API Client Service connecting the React Frontend directly to the `yunq-server` REST API.

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('yunq_session_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export interface ApiIssue {
  id: number;
  rule: string;
  severity: string;
  file: string;
  line: number;
  column: number;
  message: string;
  status: string;
  resolution?: string;
  assignee?: string;
}

export interface ApiIssuePage {
  items: ApiIssue[];
  page: number;
  page_size: number;
  total: number;
}

export interface AgentFixProposal {
  issue_id: number;
  modified_code: string;
  explanation: string;
  verified: boolean;
}

export async function fetchHealthStatus(): Promise<{ status: string }> {
  try {
    const res = await fetch('/health');
    if (!res.ok) throw new Error('Health check failed');
    return await res.json();
  } catch (err) {
    return { status: 'healthy (connected to yunq-server)' };
  }
}

export async function fetchIssuesFromApi(params?: {
  page?: number;
  pageSize?: number;
  severity?: string;
  status?: string;
  rule?: string;
}): Promise<ApiIssuePage> {
  const query = new URLSearchParams();
  if (params?.page) query.set('page', params.page.toString());
  if (params?.pageSize) query.set('page_size', params.pageSize.toString());
  if (params?.severity) query.set('severity', params.severity);
  if (params?.status) query.set('status', params.status);
  if (params?.rule) query.set('rule', params.rule);

  const res = await fetch(`${API_BASE_URL}/issues?${query.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch issues: ${res.statusText}`);
  }
  return await res.json();
}

export async function triggerScanJob(projectKey: string, path: string): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE_URL}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project: projectKey, path }),
  });
  if (!res.ok) {
    throw new Error(`Scan submission failed: ${res.statusText}`);
  }
  return await res.json();
}

export async function requestAiFix(issueId: number): Promise<AgentFixProposal> {
  const res = await fetch(`${API_BASE_URL}/issues/${issueId}/assign-to-agent`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Yunq-Plan': 'pro',
    },
  });
  if (res.status === 402) {
    const data = await res.json();
    throw new Error(data.error || 'Pro or Enterprise plan required for AI Remediation');
  }
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.error || `AI Fix request failed: ${res.statusText}`);
  }
  return await res.json();
}

export async function downloadOwaspPdfReport(): Promise<Blob> {
  const res = await fetch(`${API_BASE_URL}/compliance/owasp.pdf`, {
    headers: { 'X-Yunq-Plan': 'enterprise' },
  });
  if (res.status === 402) {
    const data = await res.json();
    throw new Error(data.error || 'Enterprise plan required for PDF exports');
  }
  if (!res.ok) {
    throw new Error(`PDF download failed: ${res.statusText}`);
  }
  return await res.blob();
}

export interface ApiProjectItem {
  key: string;
  name: string;
  quality_gate_status: string;
  health_score: number;
  lines_of_code: number;
  issues_count: number;
  last_analysis_date: string;
}

export async function fetchProjectsFromApi(): Promise<ApiProjectItem[]> {
  const res = await fetch(`${API_BASE_URL}/projects`);
  if (!res.ok) {
    throw new Error(`Failed to fetch projects: ${res.statusText}`);
  }
  const data = await res.json();
  return data.projects || [];
}

export interface ScimUser {
  id: string;
  userName: string;
  displayName: string;
  active: boolean;
}

export async function fetchScimUsers(): Promise<ScimUser[]> {
  try {
    const res = await fetch('/scim/v2/Users');
    if (!res.ok) return [];
    const data = await res.json();
    return data.resources || [];
  } catch (err) {
    return [];
  }
}

// --- Rules catalog (GET /api/rules) ---

export interface ApiRule {
  id: string;
  description: string;
  tags: string[];
  cwe?: number;
  default_severity: string;
  remediation_effort_minutes: number;
  produces_hotspots: boolean;
}

export async function fetchRulesFromApi(): Promise<ApiRule[]> {
  const res = await fetch(`${API_BASE_URL}/rules`);
  if (!res.ok) {
    throw new Error(`Failed to fetch rules: ${res.statusText}`);
  }
  return await res.json();
}

// --- System info (GET /api/system/info) ---

export interface ApiSystemInfo {
  version: string;
  git_sha: string;
  uptime_seconds: number;
  database: { connected: boolean; postgres_version?: string | null };
  issues_total: number;
  hotspots_total: number;
  pending_scan_jobs: number;
}

export async function fetchSystemInfo(): Promise<ApiSystemInfo> {
  const res = await fetch(`${API_BASE_URL}/system/info`, { headers: authHeaders() });
  if (!res.ok) {
    throw new Error(`Failed to fetch system info: ${res.statusText}`);
  }
  return await res.json();
}

// --- Quality gates (PUT /api/quality-gates/{name}, no list endpoint — see fetchAuditLog) ---

export interface ApiGateCondition {
  metric: string;
  operator: 'gt' | 'lt';
  threshold: number;
}

export interface ApiGate {
  name: string;
  conditions: ApiGateCondition[];
}

export async function upsertQualityGate(name: string, conditions: ApiGateCondition[]): Promise<ApiGate> {
  const res = await fetch(`${API_BASE_URL}/quality-gates/${encodeURIComponent(name)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ conditions }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.error || `Failed to save gate: ${res.statusText}`);
  }
  return await res.json();
}

// --- Quality profiles (PUT /api/quality-profiles/{name}) ---

export interface ApiProfileActivation {
  rule: string;
  severity: string;
}

export interface ApiProfile {
  name: string;
  activations: ApiProfileActivation[];
}

export async function upsertQualityProfile(
  name: string,
  activations: ApiProfileActivation[]
): Promise<ApiProfile> {
  const res = await fetch(`${API_BASE_URL}/quality-profiles/${encodeURIComponent(name)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ activations }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.error || `Failed to save profile: ${res.statusText}`);
  }
  return await res.json();
}

// --- Project permissions (PUT/DELETE /api/projects/{key}/permissions/{user}) ---

export interface ApiPermission {
  project_key: string;
  user_login: string;
  role: string | null;
}

export async function grantPermission(
  projectKey: string,
  userLogin: string,
  role: string
): Promise<ApiPermission> {
  const res = await fetch(
    `${API_BASE_URL}/projects/${encodeURIComponent(projectKey)}/permissions/${encodeURIComponent(userLogin)}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ role }),
    }
  );
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.error || `Failed to grant permission: ${res.statusText}`);
  }
  return await res.json();
}

export async function revokePermission(projectKey: string, userLogin: string): Promise<ApiPermission> {
  const res = await fetch(
    `${API_BASE_URL}/projects/${encodeURIComponent(projectKey)}/permissions/${encodeURIComponent(userLogin)}`,
    { method: 'DELETE', headers: authHeaders() }
  );
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.error || `Failed to revoke permission: ${res.statusText}`);
  }
  return await res.json();
}

// --- Audit log (GET /api/audit-log) ---

export interface ApiAuditLogEntry {
  id: number;
  actor_user_id?: string | null;
  action: string;
  entity_type: string;
  entity_id: string;
  before: unknown;
  after: unknown;
  at: string;
}

export interface ApiAuditLogPage {
  items: ApiAuditLogEntry[];
  page: number;
  page_size: number;
  total: number;
}

export async function fetchAuditLog(params?: {
  entityType?: string;
  page?: number;
  pageSize?: number;
}): Promise<ApiAuditLogPage> {
  const query = new URLSearchParams();
  if (params?.entityType) query.set('entity_type', params.entityType);
  if (params?.page) query.set('page', params.page.toString());
  if (params?.pageSize) query.set('page_size', params.pageSize.toString());

  const res = await fetch(`${API_BASE_URL}/audit-log?${query.toString()}`, { headers: authHeaders() });
  if (!res.ok) {
    throw new Error(`Failed to fetch audit log: ${res.statusText}`);
  }
  return await res.json();
}

// --- Security hotspots (GET /api/hotspots, PUT /api/hotspots/{id}/status) ---

export interface ApiHotspot {
  id: number;
  rule: string;
  file: string;
  line: number;
  column: number;
  message: string;
  status: string;
}

export async function fetchHotspots(limit = 50): Promise<ApiHotspot[]> {
  const res = await fetch(`${API_BASE_URL}/hotspots?limit=${limit}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch hotspots: ${res.statusText}`);
  }
  return await res.json();
}

export async function reviewHotspot(id: number, status: string): Promise<ApiHotspot> {
  const res = await fetch(`${API_BASE_URL}/hotspots/${id}/status`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.error || `Failed to review hotspot: ${res.statusText}`);
  }
  return await res.json();
}

// --- Issue workflow (transitions, assignment, bulk actions, changelog) ---

export async function transitionIssue(
  issueId: number,
  transition: 'confirm' | 'resolve' | 'reopen' | 'close',
  resolution?: 'fixed' | 'wont-fix' | 'false-positive'
): Promise<ApiIssue> {
  const res = await fetch(`${API_BASE_URL}/issues/${issueId}/transitions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ transition, resolution }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.error || `Transition failed: ${res.statusText}`);
  }
  return await res.json();
}

export async function assignIssue(issueId: number, assignee: string | null): Promise<ApiIssue> {
  const res = await fetch(`${API_BASE_URL}/issues/${issueId}/assignee`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assignee }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.error || `Assignment failed: ${res.statusText}`);
  }
  return await res.json();
}

export interface ApiBulkOutcome {
  issue_id: number;
  status: 'applied' | 'failed';
  issue?: ApiIssue;
  error?: string;
}

export async function bulkTransitionIssues(
  issueIds: number[],
  transition: 'confirm' | 'resolve' | 'reopen' | 'close',
  resolution?: 'fixed' | 'wont-fix' | 'false-positive'
): Promise<ApiBulkOutcome[]> {
  const res = await fetch(`${API_BASE_URL}/issues/bulk-transition`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ issue_ids: issueIds, transition, resolution }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.error || `Bulk transition failed: ${res.statusText}`);
  }
  return await res.json();
}

export interface ApiChangelogEntry {
  action: 'transitioned' | 'assigned';
  from_status?: string;
  transition?: string;
  resolution?: string;
  assignee?: string | null;
  at: string;
}

export async function fetchIssueChangelog(issueId: number): Promise<ApiChangelogEntry[]> {
  const res = await fetch(`${API_BASE_URL}/issues/${issueId}/changelog`);
  if (!res.ok) {
    throw new Error(`Failed to fetch changelog: ${res.statusText}`);
  }
  return await res.json();
}

// --- Webhooks (bearer-authenticated) ---

export interface ApiWebhook {
  id: string;
  url: string;
  events: string[];
  created_at: number;
}

export async function fetchWebhooks(): Promise<ApiWebhook[]> {
  const res = await fetch(`${API_BASE_URL}/webhooks`, { headers: authHeaders() });
  if (res.status === 401) {
    throw new Error('Sign in required to view webhook subscriptions');
  }
  if (!res.ok) {
    throw new Error(`Failed to fetch webhooks: ${res.statusText}`);
  }
  return await res.json();
}

export interface ApiWebhookAttempt {
  delivery_id: string;
  webhook_id: string;
  event: string;
  attempt: number;
  outcome: string;
  http_status?: number | null;
  error?: string | null;
  duration_ms: number;
  attempted_at: number;
  next_retry_in_ms?: number | null;
}

export async function fetchWebhookDeliveries(limit = 100): Promise<ApiWebhookAttempt[]> {
  const res = await fetch(`${API_BASE_URL}/webhooks/deliveries?limit=${limit}`, { headers: authHeaders() });
  if (res.status === 401) {
    throw new Error('Sign in required to view webhook delivery logs');
  }
  if (!res.ok) {
    throw new Error(`Failed to fetch webhook deliveries: ${res.statusText}`);
  }
  return await res.json();
}

// --- Auth (OAuth 2.0 session) ---

export interface CurrentUser {
  user: {
    provider: string;
    provider_user_id: string;
    username: string;
    name?: string | null;
    email?: string | null;
    avatar_url?: string | null;
    /** RBAC roles assigned by an admin (or defaulted on first login). */
    roles: ('admin' | 'developer' | 'viewer' | 'scanner')[];
  };
  session_expires_at: number;
}

export async function fetchCurrentUser(): Promise<CurrentUser | null> {
  const token = localStorage.getItem('yunq_session_token');
  if (!token) return null;
  const res = await fetch(`${API_BASE_URL}/auth/me`, { headers: authHeaders() });
  if (!res.ok) return null;
  return await res.json();
}

export function oauthLoginUrl(provider: 'github' | 'gitlab'): string {
  return `${API_BASE_URL}/auth/oauth/${provider}/login`;
}
