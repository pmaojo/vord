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
          setUser(current.user);
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
