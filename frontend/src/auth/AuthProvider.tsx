import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { fetchCurrentUser, type CurrentUser } from '../lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuthState {
  /** Whether the user has a valid, unexpired bearer session. */
  isAuthenticated: boolean;
  /** The current user's profile, or null when not authenticated. */
  user: CurrentUser['user'] | null;
  /** Session expiry unix timestamp, or null. */
  sessionExpiresAt: number | null;
  /** Whether the initial /api/auth/me call is still in flight. */
  isLoading: boolean;
  /** Log out: clears the stored token, resets state, and reloads. */
  logout: () => void;
}

// Default role assigned to a brand-new OAuth login so the UI is usable
// before any admin grants anything. The backend is the source of truth
// and applies the same default in `oauth_callback` on first login.
const DEFAULT_NEW_USER_ROLES: CurrentUser['user']['roles'] = ['developer'];

const AuthContext = createContext<AuthState | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<CurrentUser['user'] | null>(null);
  const [sessionExpiresAt, setSessionExpiresAt] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Attempt to restore a session from localStorage on mount
  useEffect(() => {
    const token = localStorage.getItem('yunq_session_token');
    if (!token) {
      setIsLoading(false);
      return;
    }

    let cancelled = false;

    (async () => {
      try {
        const current = await fetchCurrentUser();
        if (cancelled) return;

        if (current) {
          setIsAuthenticated(true);
          // Backend always sends roles — the `??` covers rooms where the
          // server hasn't shipped the field yet (pre-RBAC deployment).
          setUser({
            ...current.user,
            roles: current.user.roles ?? DEFAULT_NEW_USER_ROLES,
          });
          setSessionExpiresAt(current.session_expires_at);
        } else {
          // Token is invalid or expired — clean up
          localStorage.removeItem('yunq_session_token');
        }
      } catch {
        if (!cancelled) {
          localStorage.removeItem('yunq_session_token');
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('yunq_session_token');
    setIsAuthenticated(false);
    setUser(null);
    setSessionExpiresAt(null);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, sessionExpiresAt, isLoading, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
