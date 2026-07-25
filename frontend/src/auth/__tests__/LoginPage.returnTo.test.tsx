import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
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
        <MemoryRouter initialEntries={initialEntries}>{ui}</MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('LoginPage returnTo propagation', () => {
  beforeEach(() => {
    localStorage.clear();
    globalThis.fetch = vi.fn();
  });

  // --- test: when the URL has ?returnTo=/scans/123, both OAuth links include it ---
  it('appends returnTo query param to the GitHub OAuth URL when present', () => {
    renderWithProviders(<LoginPage />, ['/login?returnTo=' + encodeURIComponent('/scans/123')]);

    const githubLink = screen.getByRole('link', { name: /continue with github/i });
    const href = githubLink.getAttribute('href') ?? '';
    expect(href).toContain('returnTo=');
    // Assert URL-encoded form, since the component encodes the param before appending.
    expect(href).toContain(encodeURIComponent('/scans/123'));
  });

  it('appends returnTo query param to the GitLab OAuth URL when present', () => {
    renderWithProviders(<LoginPage />, ['/login?returnTo=' + encodeURIComponent('/admin')]);

    const gitlabLink = screen.getByRole('link', { name: /continue with gitlab/i });
    const href = gitlabLink.getAttribute('href') ?? '';
    expect(href).toContain('returnTo=');
    expect(href).toContain(encodeURIComponent('/admin'));
  });

  it('does not append returnTo when no returnTo is present', () => {
    renderWithProviders(<LoginPage />, ['/login']);

    const githubLink = screen.getByRole('link', { name: /continue with github/i });
    const href = githubLink.getAttribute('href') ?? '';
    expect(href).not.toContain('returnTo');
  });
});
