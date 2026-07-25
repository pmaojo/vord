import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { OAuthCallbackPage } from '../OAuthCallbackPage';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithRouter(
  initialEntries: string[],
) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route
            path="/auth/callback"
            element={
              <>
                <OAuthCallbackPage />
                <div data-testid="destination">landed</div>
              </>
            }
          />
          <Route path="/projects" element={<div data-testid="landing-projects">Projects</div>} />
          <Route path="/admin" element={<div data-testid="landing-admin">Admin</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('OAuthCallbackPage', () => {
  beforeEach(() => {
    localStorage.clear();
    globalThis.fetch = vi.fn();
  });

  // --- test 1: extracts token from URL hash and stores it in localStorage ---
  it('stores the token from URL hash into localStorage', async () => {
    renderWithRouter(['/auth/callback#token=my-bearer-token']);

    await waitFor(() => {
      expect(localStorage.getItem('yunq_session_token')).toBe('my-bearer-token');
    });
  });

  // --- test 2: redirects to the returnTo destination after storing token ---
  it('redirects to returnTo destination when present', async () => {
    renderWithRouter([
      '/auth/callback#token=valid-token&returnTo=' + encodeURIComponent('/admin'),
    ]);

    await waitFor(() => {
      expect(screen.getByTestId('landing-admin')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('destination')).not.toBeInTheDocument();
    expect(localStorage.getItem('yunq_session_token')).toBe('valid-token');
  });

  // --- test 3: falls back to /projects when no returnTo ---
  it('redirects to /projects when no returnTo is present', async () => {
    renderWithRouter(['/auth/callback#token=token-without-return']);

    await waitFor(() => {
      expect(screen.getByTestId('landing-projects')).toBeInTheDocument();
    });
    expect(localStorage.getItem('yunq_session_token')).toBe('token-without-return');
  });

  // --- test 4: rejects returnTo paths that are not same-origin absolute paths (open-redirect protection) ---
  it('ignores external returnTo URLs and falls back to /projects', async () => {
    renderWithRouter([
      '/auth/callback#token=token&returnTo=' + encodeURIComponent('https://evil.example.com/steal'),
    ]);

    await waitFor(() => {
      expect(screen.getByTestId('landing-projects')).toBeInTheDocument();
    });
  });

  // --- test 5: rejects returnTo paths with protocol-relative URLs ---
  it('ignores protocol-relative returnTo URLs', async () => {
    renderWithRouter([
      '/auth/callback#token=token&returnTo=' + encodeURIComponent('//evil.example.com/steal'),
    ]);

    await waitFor(() => {
      expect(screen.getByTestId('landing-projects')).toBeInTheDocument();
    });
  });

  // --- test 6: shows an error UI when no token is in the hash ---
  it('renders an error state when the hash has no token', async () => {
    renderWithRouter(['/auth/callback#returnTo=/projects']);

    // No token stored
    expect(localStorage.getItem('yunq_session_token')).toBeNull();

    // Should show the error UI heading (specific selector avoids ambiguity)
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /sign-in failed/i })).toBeInTheDocument();
    });
  });
});
