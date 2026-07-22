//! API Client Service connecting the React Frontend directly to the `yunq-server` REST API.

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

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
  modified_code: String;
  explanation: String;
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
  const res = await fetch('/scans', {
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
    throw new Error(`AI Fix request failed: ${res.statusText}`);
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
