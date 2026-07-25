import React, { useMemo } from 'react';
import { Navigate, useSearchParams } from 'react-router-dom';
import { Github, Gitlab, Shield } from 'lucide-react';
import { useAuth } from './AuthProvider';
import { oauthLoginUrl } from '../lib/api';
import { sanitizeReturnTo } from './OAuthCallbackPage';

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const LoginPage: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();
  const [searchParams] = useSearchParams();

  // Hooks must run unconditionally on every render. Read returnTo first,
  // then compute the redirect URLs, then early-return for already-authed users.
  const rawReturnTo = searchParams.get('returnTo');
  const returnTo = useMemo(() => sanitizeReturnTo(rawReturnTo), [rawReturnTo]);

  const githubHref = useMemo(() => {
    const base = oauthLoginUrl('github');
    return returnTo === '/projects' ? base : `${base}?returnTo=${encodeURIComponent(returnTo)}`;
  }, [returnTo]);

  const gitlabHref = useMemo(() => {
    const base = oauthLoginUrl('gitlab');
    return returnTo === '/projects' ? base : `${base}?returnTo=${encodeURIComponent(returnTo)}`;
  }, [returnTo]);

  // Already logged in — redirect to the page they intended to visit (or /projects).
  if (!isLoading && isAuthenticated) {
    return <Navigate to={returnTo} replace />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-[#f0f4f8] to-[#e2e8f0] flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Brand header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 bg-[#233445] rounded-xl shadow-lg mb-4">
            <span className="text-2xl font-bold text-white">Y</span>
          </div>
          <h1 className="text-2xl font-bold text-[#233445] tracking-tight">yunq</h1>
          <p className="text-sm text-gray-500 mt-1">Static Analysis Platform</p>
        </div>

        {/* Login card */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
          <h2 className="text-lg font-semibold text-[#233445] mb-1">Sign in</h2>
          <p className="text-sm text-gray-500 mb-6">
            Choose your OAuth provider to continue
          </p>

          <div className="space-y-3">
            {/* GitHub OAuth */}
            <a
              href={githubHref}
              className="flex items-center justify-center gap-3 w-full px-4 py-3 bg-[#24292f] hover:bg-[#1b1f23] text-white rounded-lg text-sm font-medium transition-all active:scale-[0.98]"
            >
              <Github className="w-5 h-5" />
              <span>Continue with GitHub</span>
            </a>

            {/* GitLab OAuth */}
            <a
              href={gitlabHref}
              className="flex items-center justify-center gap-3 w-full px-4 py-3 bg-[#fc6d26] hover:bg-[#e05d11] text-white rounded-lg text-sm font-medium transition-all active:scale-[0.98]"
            >
              <Gitlab className="w-5 h-5" />
              <span>Continue with GitLab</span>
            </a>
          </div>

          <div className="mt-6 pt-4 border-t border-gray-100">
            <div className="flex items-center justify-center gap-2 text-xs text-gray-400">
              <Shield className="w-3.5 h-3.5" />
              <span>Authentication is handled by your OAuth provider</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-400 mt-6">
          yunq v0.1.1 &mdash; Enterprise Edition
        </p>
      </div>
    </div>
  );
};
