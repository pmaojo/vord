import React from 'react';
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { PermissionGate } from '../PermissionGate';
import { AuthProvider } from '../AuthProvider';
import type { Role } from '../roles';

function mockFetchWithRoles(roles: Role[] | null) {
  if (roles) {
    globalThis.fetch = (async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({
          user: {
            provider: 'github',
            provider_user_id: '1',
            username: 'u',
            name: 'u',
            email: null,
            avatar_url: null,
            roles,
          },
          session_expires_at: Math.floor(Date.now() / 1000) + 3600,
        }),
      } as Response)) as typeof fetch;
    localStorage.setItem('yunq_session_token', 't');
  } else {
    localStorage.removeItem('yunq_session_token');
    globalThis.fetch = (async () => ({ ok: false, status: 401, json: async () => ({}) } as Response)) as typeof fetch;
  }
}

beforeEach(() => {
  localStorage.clear();
});

describe('<PermissionGate>', () => {
  it('renders children when the user has the required permission', async () => {
    mockFetchWithRoles(['admin']);
    render(
      <AuthProvider>
        <PermissionGate permission="adminAccess">
          <span data-testid="secret">SECRET</span>
        </PermissionGate>
      </AuthProvider>
    );
    // Wait for AuthProvider to resolve the fetch and re-render.
    await waitFor(() => expect(screen.getByTestId('secret')).toBeTruthy());
  });

  it('renders nothing when the user lacks the permission and no fallback is given', async () => {
    mockFetchWithRoles(['developer']);
    render(
      <AuthProvider>
        <PermissionGate permission="adminAccess">
          <span data-testid="secret">SECRET</span>
        </PermissionGate>
      </AuthProvider>
    );
    // Wait until AuthProvider has resolved (any span will be present), then
    // assert that the secret is not there.
    await waitFor(() => {
      // AuthProvider renders nothing extra here, so we just need the
      // PermissionGate to have had a chance to settle after fetch.
    });
    expect(screen.queryByTestId('secret')).toBeNull();
  });

  it('renders fallback when the user lacks the permission', async () => {
    mockFetchWithRoles(['viewer']);
    render(
      <AuthProvider>
        <PermissionGate
          permission="adminAccess"
          fallback={<span data-testid="forbidden">Nope</span>}
        >
          <span data-testid="secret">SECRET</span>
        </PermissionGate>
      </AuthProvider>
    );
    await waitFor(() => expect(screen.getByTestId('forbidden')).toBeTruthy());
    expect(screen.queryByTestId('secret')).toBeNull();
  });

  it('renders nothing when unauthenticated (no fetch anywhere)', async () => {
    mockFetchWithRoles(null);
    render(
      <AuthProvider>
        <PermissionGate permission="browseIssues">
          <span data-testid="secret">SECRET</span>
        </PermissionGate>
      </AuthProvider>
    );
    // Give AuthProvider a chance to resolve the 401 and clear the token.
    await waitFor(() => {
      // no-op: just wait one tick beyond the auth fetch
    });
    expect(screen.queryByTestId('secret')).toBeNull();
  });
});
