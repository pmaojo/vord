import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../AuthProvider';
import { LoginPage } from '../LoginPage';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithProviders(ui: React.ReactElement, initialEntries = ['/login']) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <MemoryRouter initialEntries={initialEntries}>
          {ui}
          {/* Route the LoginPage's <Navigate> can redirect to */}
          <div data-testid="projects-page" />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('LoginPage', () => {
  beforeEach(() => {
    localStorage.clear();
    globalThis.fetch = vi.fn();
  });

  // --- test 1: renders the login page heading ---
  it('renders a heading and sign-in prompt', () => {
    renderWithProviders(<LoginPage />);
    expect(screen.getByText(/sign in/i)).toBeTruthy();
  });

  // --- test 2: shows GitHub OAuth link ---
  it('renders a GitHub OAuth login link', () => {
    renderWithProviders(<LoginPage />);
    const githubLink = screen.getByRole('link', { name: /continue with github/i });
    expect(githubLink).toBeInTheDocument();
  });

  // --- test 3: shows GitLab OAuth link ---
  it('renders a GitLab OAuth login link', () => {
    renderWithProviders(<LoginPage />);
    const gitlabLink = screen.getByRole('link', { name: /continue with gitlab/i });
    expect(gitlabLink).toBeInTheDocument();
  });

  // --- test 4: GitHub button links to correct OAuth URL ---
  it('GitHub button redirects to /api/auth/oauth/github/login', () => {
    renderWithProviders(<LoginPage />);
    const githubLink = screen.getByRole('link', { name: /github/i });
    expect(githubLink).toHaveAttribute('href', '/api/auth/oauth/github/login');
  });

  // --- test 5: GitLab button links to correct OAuth URL ---
  it('GitLab button redirects to /api/auth/oauth/gitlab/login', () => {
    renderWithProviders(<LoginPage />);
    const gitlabLink = screen.getByRole('link', { name: /gitlab/i });
    expect(gitlabLink).toHaveAttribute('href', '/api/auth/oauth/gitlab/login');
  });

  // --- test 6: already-authenticated users get redirected ---
  it('redirects to /projects when user is already authenticated', async () => {
    localStorage.setItem('yunq_session_token', 'has-token');

    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        user: { provider: 'github', provider_user_id: '1', username: 'existing', name: null, email: null, avatar_url: null },
        session_expires_at: 9999999999,
      }),
    });

    renderWithProviders(<LoginPage />);

    // Wait for auth to resolve — LoginPage should redirect away from login
    await waitFor(() => {
      expect(screen.queryByRole('link', { name: /github/i })).not.toBeInTheDocument();
    });
  });
});
