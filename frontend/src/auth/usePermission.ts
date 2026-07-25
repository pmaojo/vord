import { useAuth } from './AuthProvider';
import { roleHas, type Permission, type Role } from './roles';

/**
 * Returns true if the currently authed user has the named permission.
 * Returns false when unauthenticated or while session is loading.
 *
 * The permission set is recomputed from `useAuth().user.roles` on every
 * render — cheap (O(roles × permissions-per-role)) and always reflects the
 * current state. The backend mirrors the same map and remains the source
 * of truth for any actual API access.
 */
export function usePermission(permission: Permission): boolean {
  const { isAuthenticated, user } = useAuth();
  if (!isAuthenticated || !user) return false;
  const roles: Role[] = Array.isArray((user as { roles?: Role[] }).roles)
    ? ((user as { roles?: Role[] }).roles as Role[])
    : [];
  return roleHas(roles, permission);
}
