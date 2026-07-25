import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../AuthProvider';
import { ProtectedRoute } from '../ProtectedRoute';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithAuth(
  ui: React.ReactElement,
  initialEntries = ['/protected'],
) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <MemoryRouter initialEntries={initialEntries}>
          <Routes>
            <Route path="/login" element={<div data-testid="login-page">Login Page</div>} />
            <Route path="/protected" element={ui} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ProtectedRoute', () => {
  beforeEach(() => {
    localStorage.clear();
    globalThis.fetch = vi.fn();
  });

  // --- test 1: redirects to /login when unauthenticated ---
  it('redirects to /login when user is not authenticated', () => {
    renderWithAuth(
      <ProtectedRoute>
        <div data-testid="protected-content">Secret Dashboard</div>
      </ProtectedRoute>,
    );

    // Should NOT render the protected content
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
    // The Navigate should have redirected to /login — login page should render
    expect(screen.getByTestId('login-page')).toBeInTheDocument();
  });

  // --- test 2: renders children when authenticated ---
  it('renders protected content when user is authenticated', async () => {
    localStorage.setItem('yunq_session_token', 'valid-token');

    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        user: {
          provider: 'github',
          provider_user_id: '1',
          username: 'dev',
          name: 'Developer',
          email: null,
          avatar_url: null,
        },
        session_expires_at: 9999999999,
      }),
    });

    renderWithAuth(
      <ProtectedRoute>
        <div data-testid="protected-content">Secret Dashboard</div>
      </ProtectedRoute>,
    );

    const content = await screen.findByTestId('protected-content');
    expect(content).toBeInTheDocument();
    expect(content.textContent).toBe('Secret Dashboard');
  });
});
