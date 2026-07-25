import React from 'react';
import { usePermission } from './usePermission';
import type { Permission } from './roles';

export interface PermissionGateProps {
  /** Permission required to render `children`. */
  permission: Permission;
  /** What to render instead when the user lacks the permission. Defaults to `null`. */
  fallback?: React.ReactNode;
  children: React.ReactNode;
}

/**
 * Declarative UI gate. Renders `children` if the user has `permission`,
 * otherwise renders `fallback` (which defaults to nothing).
 *
 * Use this for nav items, action buttons, and entire page bodies that
 * must only be visible/usable to roles with the named permission.
 *
 * NOTE: this is a UX affordance, NOT an enforcement boundary. The
 * backend MUST also reject API calls from users without the role;
 * a determined attacker can always flip a div to display: block.
 */
export const PermissionGate: React.FC<PermissionGateProps> = ({ permission, fallback = null, children }) => {
  const allowed = usePermission(permission);
  return <>{allowed ? children : fallback}</>;
};
