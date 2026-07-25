import React from 'react';
import { describe, it, expect, beforeEach } from 'vitest';
import { render, waitFor, screen } from '@testing-library/react';
import { usePermission } from '../usePermission';
import { AuthProvider } from '../AuthProvider';
import type { Role } from '../roles';

// Capture hook results inside a tiny harness that renders a span with the
// boolean answer for each permission.
function Probe({ permissions }: { permissions: string[] }) {
  const results = permissions.map((p) => ({
    perm: p,
    ok: usePermission(p as any),
  }));
  return (
    <>
      {results.map((r) => (
        <span key={r.perm} data-perm={r.perm} data-ok={String(r.ok)}>
          {r.perm}={String(r.ok)}
        </span>
      ))}
    </>
  );
}

function read(perm: string): string | null {
  return document.querySelector(`[data-perm="${perm}"]`)?.getAttribute('data-ok') ?? null;
}

function renderWithAuth(user: { roles: Role[]; username: string } | null) {
  if (user) {
    globalThis.fetch = (async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({
          user: {
            provider: 'github',
            provider_user_id: '1',
            username: user.username,
            name: user.username,
            email: null,
            avatar_url: null,
            roles: user.roles,
          },
          session_expires_at: Math.floor(Date.now() / 1000) + 3600,
        }),
      } as Response)) as typeof fetch;
    localStorage.setItem('yunq_session_token', 'test-token');
  } else {
    localStorage.removeItem('yunq_session_token');
  }
  return render(
    <AuthProvider>
      <Probe permissions={['adminAccess', 'browseIssues', 'submitAnalyses', 'transitionIssues']} />
    </AuthProvider>
  );
}

beforeEach(() => {
  localStorage.clear();
  // Reset to a stub that 401s so any leftover state is cleared.
  globalThis.fetch = (async () =>
    ({ ok: false, status: 401, json: async () => ({}) } as Response)) as typeof fetch;
});

describe('usePermission', () => {
  it('returns false for every permission when user is unauthenticated', async () => {
    localStorage.removeItem('yunq_session_token');
    render(
      <AuthProvider>
        <Probe permissions={['adminAccess', 'browseIssues']} />
      </AuthProvider>
    );
    // AuthProvider hits /api/auth/me and clears token on 401.
    await waitFor(() => expect(read('adminAccess')).toBe('false'));
    expect(read('browseIssues')).toBe('false');
  });

  it('returns true for adminAccess when user has admin role', async () => {
    renderWithAuth({ username: 'alice', roles: ['admin'] });
    await waitFor(() => expect(read('adminAccess')).toBe('true'));
  });

  it('returns false for adminAccess when user is a developer', async () => {
    renderWithAuth({ username: 'bob', roles: ['developer'] });
    await waitFor(() => expect(read('adminAccess')).toBe('false'));
  });

  it('developer can browse + transition but not adminAccess', async () => {
    renderWithAuth({ username: 'dev1', roles: ['developer'] });
    await waitFor(() => expect(read('browseIssues')).toBe('true'));
    expect(read('transitionIssues')).toBe('true');
    expect(read('adminAccess')).toBe('false');
  });

  it('viewer can browse but CANNOT submit or transition', async () => {
    renderWithAuth({ username: 'v', roles: ['viewer'] });
    await waitFor(() => expect(read('browseIssues')).toBe('true'));
    expect(read('submitAnalyses')).toBe('false');
    expect(read('transitionIssues')).toBe('false');
  });

  it('scanner can submit but cannot browse or transition', async () => {
    renderWithAuth({ username: 'ci', roles: ['scanner'] });
    await waitFor(() => expect(read('submitAnalyses')).toBe('true'));
    expect(read('browseIssues')).toBe('false');
    expect(read('transitionIssues')).toBe('false');
  });
});
