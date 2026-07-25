import React, { useEffect, useState, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Loader2 } from 'lucide-react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type CallbackStatus = 'processing' | 'success' | 'error';

interface TokenizeResult {
  /** Decoded URL fragment as key-value pairs. */
  params: URLSearchParams;
  /** Bearer token or null if absent. */
  token: string | null;
}

// ---------------------------------------------------------------------------
// Helpers (pure, unit-testable)
// ---------------------------------------------------------------------------

/** Parse a hash string (with or without leading `#`) into URLSearchParams. */
export function parseHash(hash: string): URLSearchParams {
  const stripped = hash.startsWith('#') ? hash.slice(1) : hash;
  return new URLSearchParams(stripped);
}

/** Read the bearer token out of a hash fragment. */
export function tokenizeHash(rawHash: string): TokenizeResult {
  const params = parseHash(rawHash);
  const token = params.get('token');
  return { params, token: token && token.trim() ? token : null };
}

/**
 * Decide where to send the user after a successful OAuth exchange.
 *
 * Rejects (returns `/projects`):
 *  - missing or empty paths
 *  - paths not starting with a single `/` (avoids `//evil.example.com` confusing some routers)
 *  - absolute URLs (anything with `://` in it)
 */
export function sanitizeReturnTo(raw: string | null): string {
  if (!raw) return '/projects';
  const trimmed = raw.trim();
  if (!trimmed.startsWith('/')) return '/projects';
  if (trimmed.startsWith('//')) return '/projects';
  if (trimmed.includes('://')) return '/projects';
  return trimmed;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const OAuthCallbackPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [status, setStatus] = useState<CallbackStatus>('processing');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const handled = useRef(false);

  useEffect(() => {
    if (handled.current) return; // strict-mode double-invoke guard
    handled.current = true;

    const { params, token } = tokenizeHash(location.hash);
    if (!token) {
      setStatus('error');
      setErrorMsg('No session token was provided. Please sign in again.');
      return;
    }

    const returnTo = sanitizeReturnTo(params.get('returnTo'));
    localStorage.setItem('yunq_session_token', token);
    // Clear the hash from history so the token doesn't sit in the back stack.
    window.history.replaceState(null, '', window.location.pathname);
    setStatus('success');
    navigate(returnTo, { replace: true });
  }, [navigate, location.hash]);

  // --- Error UI ---
  if (status === 'error') {
    return (
      <div className="min-h-screen bg-[#f3f6f9] flex items-center justify-center px-4">
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8 max-w-sm text-center">
          <h1 className="text-lg font-semibold text-[#233445] mb-2">
            Sign-in failed
          </h1>
          <p className="text-sm text-gray-500 mb-2">
            {errorMsg ?? 'The OAuth response was missing a session token.'}
          </p>
          <p className="text-xs text-gray-400 mb-6">
            You can go back and try a different provider, or
            contact an administrator if this persists.
          </p>
          <a
            href="/login"
            className="inline-flex items-center justify-center px-6 py-2.5 bg-[#4b9fd5] hover:bg-[#3b8dc0] text-white rounded-lg text-sm font-medium transition-all"
          >
            Back to sign in
          </a>
        </div>
      </div>
    );
  }

  // --- Processing UI (only seen when the page is mounted; usually invisible due to navigate) ---
  return (
    <div className="min-h-screen bg-[#f3f6f9] flex items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="w-8 h-8 text-[#4b9fd5] animate-spin" />
        <p className="text-sm text-gray-500">Completing sign-in…</p>
      </div>
    </div>
  );
};
