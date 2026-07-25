import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthProvider, useAuth } from '../AuthProvider';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithProviders(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

/** A test component that reads from useAuth and renders the state */
function TestConsumer() {
  const auth = useAuth();
  return (
    <div>
      <span data-testid="is-authenticated">{String(auth.isAuthenticated)}</span>
      <span data-testid="username">{auth.user?.username ?? '(none)'}</span>
      <span data-testid="avatar">{auth.user?.avatar_url ?? '(none)'}</span>
      <button data-testid="logout-btn" onClick={auth.logout}>
        Logout
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AuthProvider', () => {
  beforeEach(() => {
    localStorage.clear();
    // Mock fetch so no real network calls happen during tests
    globalThis.fetch = vi.fn();
  });

  // --- RED test 1: unauthenticated by default ---
  it('starts unauthenticated when no token is stored', () => {
    renderWithProviders(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>,
    );

    expect(screen.getByTestId('is-authenticated').textContent).toBe('false');
    expect(screen.getByTestId('username').textContent).toBe('(none)');
  });

  // --- RED test 2: reads token from localStorage on mount and fetches user ---
  it('calls /api/auth/me when a token is found in localStorage', async () => {
    localStorage.setItem('yunq_session_token', 'test-token-123');

    const fakeUser = {
      user: {
        provider: 'github',
        provider_user_id: '42',
        username: 'testuser',
        name: 'Test User',
        email: 'test@example.com',
        avatar_url: 'https://example.com/avatar.png',
      },
      session_expires_at: 9999999999,
    };

    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => fakeUser,
    });

    renderWithProviders(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-authenticated').textContent).toBe('true');
    });

    expect(screen.getByTestId('username').textContent).toBe('testuser');
    expect(screen.getByTestId('avatar').textContent).toBe('https://example.com/avatar.png');
  });

  // --- RED test 3: handles 401 from /api/auth/me gracefully ---
  it('stays unauthenticated when /api/auth/me returns 401', async () => {
    localStorage.setItem('yunq_session_token', 'expired-token');

    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
      status: 401,
    });

    renderWithProviders(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-authenticated').textContent).toBe('false');
    });

    // Expired token should be removed from localStorage
    expect(localStorage.getItem('yunq_session_token')).toBeNull();
  });

  // --- RED test 4: logout clears token and state ---
  it('logout clears the token and resets state', async () => {
    localStorage.setItem('yunq_session_token', 'test-token-456');

    const fakeUser = {
      user: {
        provider: 'github',
        provider_user_id: '99',
        username: 'logout-user',
        name: 'Logout User',
        email: null,
        avatar_url: null,
      },
      session_expires_at: 9999999999,
    };

    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => fakeUser,
    });

    renderWithProviders(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-authenticated').textContent).toBe('true');
    });

    // Click logout
    const user = userEvent.setup();
    await user.click(screen.getByTestId('logout-btn'));

    expect(screen.getByTestId('is-authenticated').textContent).toBe('false');
    expect(localStorage.getItem('yunq_session_token')).toBeNull();
  });

  // --- RED test 5: useAuth throws outside AuthProvider ---
  it('throws an error when useAuth is used outside of AuthProvider', () => {
    // Suppress console.error for the expected error boundary
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => render(<TestConsumer />)).toThrow('useAuth must be used within an AuthProvider');

    spy.mockRestore();
  });
});
